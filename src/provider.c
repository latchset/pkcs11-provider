/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "decoder.h"
#include <pthread.h>
#include <string.h>

struct p11prov_interface;
struct quirk;

struct p11prov_ctx {

    enum {
        P11PROV_UNINITIALIZED = 0,
        P11PROV_INITIALIZED,
        P11PROV_NEEDS_REINIT,
        P11PROV_NO_DEINIT,
        P11PROV_IN_ERROR,
    } status;

    /* Provider handles */
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;

    /* Configuration */
    char *pin;
    int allow_export;
    int login_behavior;
    bool cache_pins;
    int cache_keys;
    int cache_sessions;
    bool encode_pkey_as_pk11_uri;
    /* TODO: ui_method */
    /* TODO: fork id */

    /* cfg quirks */
    bool no_deinit;
    bool no_allowed_mechanisms;
    bool no_session_callbacks;
    uint64_t blocked_calls;
    bool blocked_ops[OSSL_OP__HIGHEST + 1];

    /* module handles and data */
    P11PROV_MODULE *module;

    P11PROV_SLOTS_CTX *slots;

    OSSL_ALGORITHM *op_digest;
    OSSL_ALGORITHM *op_kdf;
    OSSL_ALGORITHM *op_random;
    OSSL_ALGORITHM *op_exchange;
    OSSL_ALGORITHM *op_signature;
    OSSL_ALGORITHM *op_asym_cipher;
    OSSL_ALGORITHM *op_encoder;

    pthread_rwlock_t quirk_lock;
    struct quirk *quirks;
    int nquirks;
};

static struct p11prov_context_pool {
    struct p11prov_ctx **contexts;
    int num;

    pthread_rwlock_t rwlock;
} ctx_pool = {
    .contexts = NULL,
    .num = 0,
    .rwlock = PTHREAD_RWLOCK_INITIALIZER,
};

static void fork_prepare(void)
{
    int err;

    err = pthread_rwlock_rdlock(&ctx_pool.rwlock);
    if (err != 0) {
        err = errno;
        P11PROV_debug("Can't lock contexts pool (error=%d)", err);
    }

    for (int i = 0; i < ctx_pool.num; i++) {
        if (ctx_pool.contexts[i]->status == P11PROV_INITIALIZED) {
            p11prov_slot_fork_prepare(ctx_pool.contexts[i]->slots);
        }
    }
}

static void fork_parent(void)
{
    int err;

    for (int i = 0; i < ctx_pool.num; i++) {
        if (ctx_pool.contexts[i]->status == P11PROV_INITIALIZED) {
            p11prov_slot_fork_release(ctx_pool.contexts[i]->slots);
        }
    }
    err = pthread_rwlock_unlock(&ctx_pool.rwlock);
    if (err != 0) {
        err = errno;
        P11PROV_debug("Failed to release context pool (errno:%d)", err);
    }
}

static void fork_child(void)
{
    int err;

    /* rwlock, saves TID internally, so we need to reset
     * after fork in the child */
    p11prov_force_rwlock_reinit(&ctx_pool.rwlock);

    /* This is running in the fork handler, so there should be no
     * way to have other threads running, but just in case some
     * crazy library creates threads in their child handler */
    err = pthread_rwlock_wrlock(&ctx_pool.rwlock);
    if (err != 0) {
        err = errno;
        P11PROV_debug("Failed to get slots lock (errno:%d)", err);
        return;
    }

    for (int i = 0; i < ctx_pool.num; i++) {
        if (ctx_pool.contexts[i]->status == P11PROV_INITIALIZED) {
            /* can't re-init in the fork handler, mark it */
            ctx_pool.contexts[i]->status = P11PROV_NEEDS_REINIT;
            p11prov_module_mark_reinit(ctx_pool.contexts[i]->module);
            p11prov_slot_fork_reset(ctx_pool.contexts[i]->slots);
        }
    }

    err = pthread_rwlock_unlock(&ctx_pool.rwlock);
    if (err != 0) {
        err = errno;
        P11PROV_debug("Failed to release context pool (errno:%d)", err);
    }
}

#define CTX_POOL_ALLOC 4
static void context_add_pool(struct p11prov_ctx *ctx)
{
    int err;
    /* init static pool for atfork/atexit handling */
    err = pthread_rwlock_wrlock(&ctx_pool.rwlock);
    if (err != 0) {
        /* just warn */
        err = errno;
        P11PROV_raise(ctx, CKR_CANT_LOCK, "Failed to lock ctx pool (error:%d)",
                      err);
        return;
    }

    /* WRLOCKED ------------------------------------------------- */
    if (ctx_pool.contexts == NULL) {
        ctx_pool.contexts =
            OPENSSL_zalloc(CTX_POOL_ALLOC * sizeof(P11PROV_CTX *));
        if (!ctx_pool.contexts) {
            P11PROV_raise(ctx, CKR_HOST_MEMORY, "Failed to alloc ctx pool");
            goto done;
        }
        err = pthread_atfork(fork_prepare, fork_parent, fork_child);
        if (err != 0) {
            /* just warn, nothing much we can do */
            P11PROV_raise(ctx, CKR_GENERAL_ERROR,
                          "Failed to register fork handlers (error:%d)", err);
        }
    } else {
        if (ctx_pool.num % CTX_POOL_ALLOC == 0) {
            P11PROV_CTX **tmp;
            tmp = OPENSSL_realloc(ctx_pool.contexts,
                                  (ctx_pool.num + CTX_POOL_ALLOC)
                                      * sizeof(P11PROV_CTX *));
            if (!tmp) {
                P11PROV_raise(ctx, CKR_HOST_MEMORY,
                              "Failed to realloc ctx pool");
                goto done;
            }
            ctx_pool.contexts = tmp;
        }
    }
    ctx_pool.contexts[ctx_pool.num] = ctx;
    ctx_pool.num++;

done:
    /* ------------------------------------------------- WRLOCKED */
    (void)pthread_rwlock_unlock(&ctx_pool.rwlock);
    return;
}

static void context_rm_pool(struct p11prov_ctx *ctx)
{
    int found = false;
    int err;

    /* init static pool for atfork/atexit handling */
    err = pthread_rwlock_wrlock(&ctx_pool.rwlock);
    if (err != 0) {
        /* just warn */
        err = errno;
        P11PROV_raise(ctx, CKR_CANT_LOCK, "Failed to lock ctx pool (error:%d)",
                      err);
        return;
    }

    /* WRLOCKED ------------------------------------------------- */
    for (int i = 0; i < ctx_pool.num; i++) {
        if (!found) {
            if (ctx_pool.contexts[i] == ctx) {
                ctx_pool.contexts[i] = NULL;
                found = true;
            }
        } else {
            ctx_pool.contexts[i - 1] = ctx_pool.contexts[i];
            if (i == ctx_pool.num - 1) {
                ctx_pool.contexts[i] = NULL;
            }
        }
    }
    if (found) {
        ctx_pool.num--;
    } else {
        P11PROV_debug("Context not found in pool ?!");
    }

    /* ------------------------------------------------- WRLOCKED */
    (void)pthread_rwlock_unlock(&ctx_pool.rwlock);
    return;
}

struct quirk {
    CK_SLOT_ID id;
    char *name;
    union {
        void *ptr;
        CK_ULONG ulong;
    } data;
    CK_ULONG size;
};

CK_RV p11prov_ctx_get_quirk(P11PROV_CTX *ctx, CK_SLOT_ID id, const char *name,
                            void **data, CK_ULONG *size)
{
    int lock;
    CK_RV ret;

    lock = pthread_rwlock_rdlock(&ctx->quirk_lock);
    if (lock != 0) {
        ret = CKR_CANT_LOCK;
        P11PROV_raise(ctx, ret, "Failure to rdlock! (%d)", errno);
        return ret;
    }

    for (int i = 0; i < ctx->nquirks; i++) {
        if (id != ctx->quirks[i].id) {
            continue;
        }
        if (strcmp(name, ctx->quirks[i].name) != 0) {
            continue;
        }
        /* return only if requested and if ancillary data exists */
        if (data && ctx->quirks[i].size > 0) {
            if (*size == 0) {
                *data = OPENSSL_malloc(ctx->quirks[i].size);
                if (!*data) {
                    ret = CKR_HOST_MEMORY;
                    goto done;
                }
            } else {
                if (*size < ctx->quirks[i].size) {
                    ret = CKR_BUFFER_TOO_SMALL;
                    goto done;
                }
            }
            if (ctx->quirks[i].size > sizeof(CK_ULONG)) {
                memcpy(*data, ctx->quirks[i].data.ptr, ctx->quirks[i].size);
            } else {
                memcpy(*data, &ctx->quirks[i].data.ulong, ctx->quirks[i].size);
            }
            *size = ctx->quirks[i].size;
        }
        break;
    }

    ret = CKR_OK;

done:
    lock = pthread_rwlock_unlock(&ctx->quirk_lock);
    if (lock != 0) {
        P11PROV_raise(ctx, CKR_CANT_LOCK, "Failure to unlock! (%d)", errno);
        /* we do not return an error in this case, as we got the info */
    }
    return ret;
}

#define DATA_SWAP(t, d, s) \
    do { \
        t _tmp = d; \
        d = s; \
        s = _tmp; \
    } while (0)
#define QUIRK_ALLOC 4
CK_RV p11prov_ctx_set_quirk(P11PROV_CTX *ctx, CK_SLOT_ID id, const char *name,
                            void *data, CK_ULONG size)
{
    char *_name = NULL;
    void *_data = NULL;
    CK_ULONG _ulong = 0;
    CK_ULONG _size = size;
    int lock;
    CK_RV ret;
    bool found = false;
    int i;

    /* do potentially costly memory allocation operations before locking */
    _name = OPENSSL_strdup(name);
    if (!_name) {
        ret = CKR_HOST_MEMORY;
        P11PROV_raise(ctx, ret, "Failure to copy name");
        return ret;
    }
    if (_size > 0) {
        if (_size > sizeof(CK_ULONG)) {
            _data = OPENSSL_malloc(_size);
            if (!_data) {
                ret = CKR_HOST_MEMORY;
                P11PROV_raise(ctx, ret, "Failure to allocate for data");
                goto failed;
            }
        } else {
            _data = &_ulong;
        }
        memcpy(_data, data, _size);
    }

    lock = pthread_rwlock_wrlock(&ctx->quirk_lock);
    if (lock != 0) {
        ret = CKR_CANT_LOCK;
        P11PROV_raise(ctx, ret, "Failure to wrlock! (%d)", errno);
        goto failed;
    }

    /* first see if we are replacing quirk data */
    for (i = 0; i < ctx->nquirks; i++) {
        if (id != ctx->quirks[i].id) {
            continue;
        }
        if (strcmp(_name, ctx->quirks[i].name) != 0) {
            continue;
        }

        found = true;
        /* free previous data */
        break;
    }

    if (!found) {
        if ((ctx->nquirks % QUIRK_ALLOC) == 0) {
            size_t asize = sizeof(struct quirk) * (ctx->nquirks + QUIRK_ALLOC);
            struct quirk *q = OPENSSL_realloc(ctx->quirks, asize);
            if (!q) {
                ret = CKR_HOST_MEMORY;
                goto done;
            }
            ctx->quirks = q;
            memset(&ctx->quirks[ctx->nquirks], 0, asize);
            i = ctx->nquirks;
            ctx->nquirks++;
        }
    }

    ctx->quirks[i].id = id;
    /* swap so that we free the old data at fn exit, where
     * precopied data is also freed in case of error */
    DATA_SWAP(char *, ctx->quirks[i].name, _name);
    if (_size > sizeof(CK_ULONG)) {
        DATA_SWAP(void *, ctx->quirks[i].data.ptr, _data);
    } else {
        ctx->quirks[i].data.ulong = _ulong;
        _data = NULL;
    }
    DATA_SWAP(CK_ULONG, ctx->quirks[i].size, _size);
    ret = CKR_OK;

done:
    P11PROV_debug("Set quirk '%s' of size %lu", name, size);
    lock = pthread_rwlock_unlock(&ctx->quirk_lock);
    if (lock != 0) {
        P11PROV_raise(ctx, CKR_CANT_LOCK, "Failure to unlock! (%d)", errno);
        /* we do not return an error in this case, as we got the info */
    }
failed:
    OPENSSL_free(_name);
    if (_data != &_ulong) {
        OPENSSL_clear_free(_data, _size);
    }
    return ret;
}

CK_RV p11prov_token_sup_attr(P11PROV_CTX *ctx, CK_SLOT_ID id, int action,
                             CK_ATTRIBUTE_TYPE attr, CK_BBOOL *data)
{
    CK_ULONG data_size = sizeof(CK_BBOOL);
    void *data_ptr = &data;
    char alloc_name[32];
    const char *name;
    int err;

    switch (attr) {
    case CKA_ALLOWED_MECHANISMS:
        if (ctx->no_allowed_mechanisms) {
            if (action == GET_ATTR) {
                *data = false;
            }
            return CKR_OK;
        }
        name = "sup_attr_CKA_ALLOWED_MECHANISMS";
        break;
    default:
        err = snprintf(alloc_name, 32, "sup_attr_%016lx", attr);
        if (err < 0 || err >= 32) {
            return CKR_HOST_MEMORY;
        }
        name = alloc_name;
    }

    switch (action) {
    case GET_ATTR:
        return p11prov_ctx_get_quirk(ctx, id, name, data_ptr, &data_size);
    case SET_ATTR:
        return p11prov_ctx_set_quirk(ctx, id, name, data, data_size);
    default:
        return CKR_ARGUMENTS_BAD;
    }
}

P11PROV_INTERFACE *p11prov_ctx_get_interface(P11PROV_CTX *ctx)
{
    if (ctx->status == P11PROV_NO_DEINIT) {
        /* This is a quirk to handle modules that do funny things
         * with openssl and have issues when called in the openssl
         * destructors. Prevent any call to finalize or otherwise
         * use the module. */
        return NULL;
    }
    return p11prov_module_get_interface(ctx->module);
}

P11PROV_SLOTS_CTX *p11prov_ctx_get_slots(P11PROV_CTX *ctx)
{
    return ctx->slots;
}

void p11prov_ctx_set_slots(P11PROV_CTX *ctx, P11PROV_SLOTS_CTX *slots)
{
    if (ctx->slots) {
        p11prov_free_slots(ctx->slots);
    }
    ctx->slots = slots;
}

OSSL_LIB_CTX *p11prov_ctx_get_libctx(P11PROV_CTX *ctx)
{
    return ctx->libctx;
}

static CK_RV operations_init(P11PROV_CTX *ctx);

CK_RV p11prov_ctx_status(P11PROV_CTX *ctx)
{
    CK_RV ret;

    switch (ctx->status) {
    case P11PROV_UNINITIALIZED:
        ret = p11prov_module_init(ctx->module);
        if (ret != CKR_OK) {
            P11PROV_raise(ctx, ret, "Module initialization failed!");
            ctx->status = P11PROV_IN_ERROR;
            break;
        }
        ret = operations_init(ctx);
        if (ret != CKR_OK) {
            P11PROV_raise(ctx, ret, "Operations initialization failed!");
            ctx->status = P11PROV_IN_ERROR;
            break;
        }
        ctx->status = P11PROV_INITIALIZED;
        break;
    case P11PROV_INITIALIZED:
    case P11PROV_NO_DEINIT:
        ret = CKR_OK;
        break;
    case P11PROV_NEEDS_REINIT:
        ret = p11prov_module_reinit(ctx->module);
        if (ret != CKR_OK) {
            P11PROV_raise(ctx, ret, "Module re-initialization failed!");
            ctx->status = P11PROV_IN_ERROR;
            break;
        }
        ctx->status = P11PROV_INITIALIZED;
        break;
    case P11PROV_IN_ERROR:
        P11PROV_raise(ctx, CKR_GENERAL_ERROR, "Module in error state!");
        ret = CKR_GENERAL_ERROR;
        break;
    default:
        ret = CKR_GENERAL_ERROR;
    }

    return ret;
}

CK_UTF8CHAR_PTR p11prov_ctx_pin(P11PROV_CTX *ctx)
{
    return (CK_UTF8CHAR_PTR)ctx->pin;
}

static void p11prov_ctx_free(P11PROV_CTX *ctx)
{
    int ret;

    if (ctx->no_deinit) {
        ctx->status = P11PROV_NO_DEINIT;
    }

    OPENSSL_free(ctx->op_digest);
    OPENSSL_free(ctx->op_kdf);
    OPENSSL_free(ctx->op_random);
    /* keymgmt is static */
    OPENSSL_free(ctx->op_exchange);
    OPENSSL_free(ctx->op_signature);
    OPENSSL_free(ctx->op_asym_cipher);
    OPENSSL_free(ctx->op_encoder);
    /* store is static */

    OSSL_LIB_CTX_free(ctx->libctx);
    ctx->libctx = NULL;

    p11prov_free_slots(ctx->slots);
    ctx->slots = NULL;

    if (ctx->pin) {
        OPENSSL_clear_free(ctx->pin, strlen(ctx->pin));
    }

    p11prov_module_free(ctx->module);
    ctx->module = NULL;

    ret = pthread_rwlock_wrlock(&ctx->quirk_lock);
    if (ret != 0) {
        P11PROV_raise(ctx, CKR_CANT_LOCK,
                      "Failure to wrlock! Data corruption may happen (%d)",
                      errno);
    }

    if (ctx->quirks) {
        for (int i = 0; i < ctx->nquirks; i++) {
            OPENSSL_free(ctx->quirks[i].name);
            if (ctx->quirks[i].size > sizeof(CK_ULONG)) {
                OPENSSL_clear_free(ctx->quirks[i].data.ptr,
                                   ctx->quirks[i].size);
            }
        }
        OPENSSL_free(ctx->quirks);
    }

    ret = pthread_rwlock_unlock(&ctx->quirk_lock);
    if (ret != 0) {
        P11PROV_raise(ctx, CKR_CANT_LOCK,
                      "Failure to unlock! Data corruption may happen (%d)",
                      errno);
    }

    ret = pthread_rwlock_destroy(&ctx->quirk_lock);
    if (ret != 0) {
        P11PROV_raise(ctx, CKR_CANT_LOCK,
                      "Failure to free lock! Data corruption may happen (%d)",
                      errno);
    }

    /* remove from pool */
    context_rm_pool(ctx);

    OPENSSL_clear_free(ctx, sizeof(P11PROV_CTX));
}

int p11prov_ctx_allow_export(P11PROV_CTX *ctx)
{
    P11PROV_debug("allow_export = %d", ctx->allow_export);
    return ctx->allow_export;
}

int p11prov_ctx_login_behavior(P11PROV_CTX *ctx)
{
    P11PROV_debug("login_behavior = %d", ctx->login_behavior);
    return ctx->login_behavior;
}

bool p11prov_ctx_cache_pins(P11PROV_CTX *ctx)
{
    P11PROV_debug("cache_pins = %s", ctx->cache_pins ? "true" : "false");
    return ctx->cache_pins;
}

int p11prov_ctx_cache_keys(P11PROV_CTX *ctx)
{
    P11PROV_debug("cache_keys = %d", ctx->cache_keys);
    return ctx->cache_keys;
}

int p11prov_ctx_cache_sessions(P11PROV_CTX *ctx)
{
    P11PROV_debug("cache_sessions = %d", ctx->cache_sessions);
    return ctx->cache_sessions;
}

bool p11prov_ctx_is_call_blocked(P11PROV_CTX *ctx, uint64_t mask)
{
    return (ctx->blocked_calls & mask) != 0;
}

bool p11prov_ctx_no_session_callbacks(P11PROV_CTX *ctx)
{
    return ctx->no_session_callbacks;
}

CK_INFO p11prov_ctx_get_ck_info(P11PROV_CTX *ctx)
{
    if (!ctx->module) {
        CK_INFO info = { 0 };
        return info;
    }
    return p11prov_module_ck_info(ctx->module);
}

static void p11prov_teardown(void *ctx)
{
    p11prov_ctx_free((P11PROV_CTX *)ctx);
}

static OSSL_FUNC_core_get_params_fn *core_get_params = NULL;
static OSSL_FUNC_core_new_error_fn *core_new_error = NULL;
static OSSL_FUNC_core_set_error_debug_fn *core_set_error_debug = NULL;
static OSSL_FUNC_core_vset_error_fn *core_vset_error = NULL;
static OSSL_FUNC_core_set_error_mark_fn *core_set_error_mark = NULL;
static OSSL_FUNC_core_clear_last_error_mark_fn *core_clear_last_error_mark =
    NULL;
static OSSL_FUNC_core_pop_error_to_mark_fn *core_pop_error_to_mark = NULL;

static void p11prov_get_core_dispatch_funcs(const OSSL_DISPATCH *in)
{
    const OSSL_DISPATCH *iter_in;

    for (iter_in = in; iter_in->function_id != 0; iter_in++) {
        switch (iter_in->function_id) {
        case OSSL_FUNC_CORE_GET_PARAMS:
            core_get_params = OSSL_FUNC_core_get_params(iter_in);
            break;
        case OSSL_FUNC_CORE_NEW_ERROR:
            core_new_error = OSSL_FUNC_core_new_error(iter_in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            core_set_error_debug = OSSL_FUNC_core_set_error_debug(iter_in);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            core_vset_error = OSSL_FUNC_core_vset_error(iter_in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_MARK:
            core_set_error_mark = OSSL_FUNC_core_set_error_mark(iter_in);
            break;
        case OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK:
            core_clear_last_error_mark =
                OSSL_FUNC_core_clear_last_error_mark(iter_in);
            break;
        case OSSL_FUNC_CORE_POP_ERROR_TO_MARK:
            core_pop_error_to_mark = OSSL_FUNC_core_pop_error_to_mark(iter_in);
            break;
        default:
            /* Just ignore anything we don't understand */
            continue;
        }
    }
}

void p11prov_raise(P11PROV_CTX *ctx, const char *file, int line,
                   const char *func, int errnum, const char *fmt, ...)
{
    va_list args;

    if (!core_new_error || !core_vset_error) {
        return;
    }

    va_start(args, fmt);
    core_new_error(ctx->handle);
    core_set_error_debug(ctx->handle, file, line, func);
    core_vset_error(ctx->handle, errnum, fmt, args);
    va_end(args);
}

int p11prov_set_error_mark(P11PROV_CTX *ctx)
{
    return core_set_error_mark(ctx->handle);
}

int p11prov_clear_last_error_mark(P11PROV_CTX *ctx)
{
    return core_clear_last_error_mark(ctx->handle);
}

int p11prov_pop_error_to_mark(P11PROV_CTX *ctx)
{
    return core_pop_error_to_mark(ctx->handle);
}

/* Parameters we provide to the core */
static const OSSL_PARAM p11prov_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END,
};

static const OSSL_PARAM *p11prov_gettable_params(void *provctx)
{
    return p11prov_param_types;
}

static int p11prov_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ret;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL) {
        ret = OSSL_PARAM_set_utf8_ptr(p, "PKCS#11 Provider");
        if (ret == 0) {
            return RET_OSSL_ERR;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL) {
        /* temporarily return the OpenSSL build version */
        ret = OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR);
        if (ret == 0) {
            return RET_OSSL_ERR;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL) {
        /* temporarily return the OpenSSL build version */
        ret = OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR);
        if (ret == 0) {
            return RET_OSSL_ERR;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL) {
        /* return 1 for now,
         * return 0 in future if there are module issues? */
        ret = OSSL_PARAM_set_int(p, 1);
        if (ret == 0) {
            return RET_OSSL_ERR;
        }
    }
    return RET_OSSL_OK;
}

/* TODO: this needs to be made dynamic,
 * based on what the pkcs11 module supports */
#define ALGOS_ALLOC 4
static CK_RV alg_set_op(OSSL_ALGORITHM **op, int idx, OSSL_ALGORITHM *alg)
{
    if (idx % ALGOS_ALLOC == 0) {
        OSSL_ALGORITHM *tmp =
            OPENSSL_realloc(*op, sizeof(OSSL_ALGORITHM) * (idx + ALGOS_ALLOC));
        if (!tmp) {
            return CKR_HOST_MEMORY;
        }
        *op = tmp;
    }
    (*op)[idx] = *alg;
    return CKR_OK;
}

#define ADD_ALGO_EXT(NAME, operation, prop, func) \
    do { \
        CK_RV alg_ret; \
        OSSL_ALGORITHM alg = { P11PROV_NAMES_##NAME, prop, func, \
                               P11PROV_DESCS_##NAME }; \
        alg_ret = alg_set_op(&ctx->op_##operation, operation##_idx, &alg); \
        if (alg_ret != CKR_OK) { \
            P11PROV_raise(ctx, alg_ret, "Failed to store mech algo"); \
            return RET_OSSL_ERR; \
        } \
        operation##_idx++; \
    } while (0)

#define ADD_ALGO(NAME, name, operation) \
    ADD_ALGO_EXT(NAME, operation, P11PROV_DEFAULT_PROPERTIES, \
                 p11prov_##name##_##operation##_functions)

#define TERM_ALGO(operation) \
    if (operation##_idx > 0) { \
        CK_RV alg_ret; \
        OSSL_ALGORITHM alg = { NULL, NULL, NULL, NULL }; \
        alg_ret = alg_set_op(&ctx->op_##operation, operation##_idx, &alg); \
        if (alg_ret != CKR_OK) { \
            P11PROV_raise(ctx, alg_ret, "Failed to terminate mech algo"); \
            return RET_OSSL_ERR; \
        } \
    } \
    operation##_idx = 0

#define DIGEST_MECHS \
    CKM_SHA_1, CKM_SHA224, CKM_SHA256, CKM_SHA384, CKM_SHA512, CKM_SHA512_224, \
        CKM_SHA512_256, CKM_SHA3_224, CKM_SHA3_256, CKM_SHA3_384, CKM_SHA3_512

#define RSA_SIG_MECHS \
    CKM_RSA_PKCS, CKM_SHA1_RSA_PKCS, CKM_SHA224_RSA_PKCS, CKM_SHA256_RSA_PKCS, \
        CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS, CKM_SHA3_224_RSA_PKCS, \
        CKM_SHA3_256_RSA_PKCS, CKM_SHA3_384_RSA_PKCS, CKM_SHA3_512_RSA_PKCS

#define RSAPSS_SIG_MECHS \
    CKM_RSA_PKCS_PSS, CKM_SHA1_RSA_PKCS_PSS, CKM_SHA224_RSA_PKCS_PSS, \
        CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, \
        CKM_SHA512_RSA_PKCS_PSS, CKM_SHA3_224_RSA_PKCS_PSS, \
        CKM_SHA3_256_RSA_PKCS_PSS, CKM_SHA3_384_RSA_PKCS_PSS, \
        CKM_SHA3_512_RSA_PKCS_PSS

#define RSA_ENC_MECHS \
    CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_RSA_X_509, CKM_RSA_X9_31

#define ECDSA_SIG_MECHS \
    CKM_ECDSA, CKM_ECDSA_SHA1, CKM_ECDSA_SHA224, CKM_ECDSA_SHA256, \
        CKM_ECDSA_SHA384, CKM_ECDSA_SHA512, CKM_ECDSA_SHA3_224, \
        CKM_ECDSA_SHA3_256, CKM_ECDSA_SHA3_384, CKM_ECDSA_SHA3_512

static void alg_rm_mechs(CK_ULONG *checklist, CK_ULONG *rmlist, int *clsize,
                         int rmsize)
{
    CK_ULONG tmplist[*clsize];
    int t = 0;

    for (int i = 0; i < *clsize; i++) {
        tmplist[t] = checklist[i];
        for (int j = 0; j < rmsize; j++) {
            if (tmplist[t] == rmlist[j]) {
                tmplist[t] = CK_UNAVAILABLE_INFORMATION;
                break;
            }
        }
        if (tmplist[t] != CK_UNAVAILABLE_INFORMATION) {
            t++;
        }
    }
    memcpy(checklist, tmplist, t * sizeof(CK_ULONG));
    *clsize = t;
}

#define UNCHECK_MECHS(...) \
    do { \
        CK_ULONG rmlist[] = { __VA_ARGS__ }; \
        int rmsize = sizeof(rmlist) / sizeof(CK_ULONG); \
        alg_rm_mechs(checklist, rmlist, &cl_size, rmsize); \
    } while (0);

static CK_RV operations_init(P11PROV_CTX *ctx)
{
    P11PROV_SLOTS_CTX *slots;
    P11PROV_SLOT *slot;
    CK_ULONG checklist[] = { CKM_RSA_PKCS_KEY_PAIR_GEN,
                             RSA_SIG_MECHS,
                             RSAPSS_SIG_MECHS,
                             RSA_ENC_MECHS,
                             CKM_EC_KEY_PAIR_GEN,
                             ECDSA_SIG_MECHS,
                             CKM_ECDH1_DERIVE,
                             CKM_ECDH1_COFACTOR_DERIVE,
                             CKM_HKDF_DERIVE,
                             DIGEST_MECHS,
                             CKM_EDDSA };
    bool add_rsasig = false;
    bool add_rsaenc = false;
    int cl_size = sizeof(checklist) / sizeof(CK_ULONG);
    int digest_idx = 0;
    int kdf_idx = 0;
    int random_idx = 0;
    int exchange_idx = 0;
    int signature_idx = 0;
    int asym_cipher_idx = 0;
    int encoder_idx = 0;
    int slot_idx = 0;
    CK_RV ret;

    ret = p11prov_take_slots(ctx, &slots);
    if (ret != CKR_OK) {
        return ret;
    }

    for (slot = p11prov_fetch_slot(slots, &slot_idx); slot != NULL;
         slot = p11prov_fetch_slot(slots, &slot_idx)) {

        CK_MECHANISM_TYPE *mechs;
        int nmechs;
        nmechs = p11prov_slot_get_mechanisms(slot, &mechs);
        for (int ms = 0; ms < nmechs; ms++) {
            CK_ULONG mech = CK_UNAVAILABLE_INFORMATION;
            if (cl_size == 0) {
                /* we are done*/
                break;
            }
            for (int cl = 0; cl < cl_size; cl++) {
                if (mechs[ms] == checklist[cl]) {
                    mech = mechs[ms];
                    /* found */
                    break;
                }
            }
            switch (mech) {
            case CK_UNAVAILABLE_INFORMATION:
                continue;
            case CKM_RSA_PKCS_KEY_PAIR_GEN:
                UNCHECK_MECHS(CKM_RSA_PKCS_KEY_PAIR_GEN);
                break;
            case CKM_RSA_PKCS:
                add_rsasig = true;
                add_rsaenc = true;
                UNCHECK_MECHS(CKM_RSA_PKCS_KEY_PAIR_GEN, RSA_SIG_MECHS);
                UNCHECK_MECHS(CKM_RSA_PKCS_KEY_PAIR_GEN, RSA_ENC_MECHS);
                break;
            case CKM_SHA1_RSA_PKCS:
            case CKM_SHA224_RSA_PKCS:
            case CKM_SHA256_RSA_PKCS:
            case CKM_SHA384_RSA_PKCS:
            case CKM_SHA512_RSA_PKCS:
            case CKM_SHA3_224_RSA_PKCS:
            case CKM_SHA3_256_RSA_PKCS:
            case CKM_SHA3_384_RSA_PKCS:
            case CKM_SHA3_512_RSA_PKCS:
                add_rsasig = true;
                UNCHECK_MECHS(CKM_RSA_PKCS_KEY_PAIR_GEN, RSA_SIG_MECHS);
                break;
            case CKM_RSA_PKCS_PSS:
            case CKM_SHA1_RSA_PKCS_PSS:
            case CKM_SHA224_RSA_PKCS_PSS:
            case CKM_SHA256_RSA_PKCS_PSS:
            case CKM_SHA384_RSA_PKCS_PSS:
            case CKM_SHA512_RSA_PKCS_PSS:
            case CKM_SHA3_224_RSA_PKCS_PSS:
            case CKM_SHA3_256_RSA_PKCS_PSS:
            case CKM_SHA3_384_RSA_PKCS_PSS:
            case CKM_SHA3_512_RSA_PKCS_PSS:
                add_rsasig = true;
                UNCHECK_MECHS(CKM_RSA_PKCS_KEY_PAIR_GEN, RSAPSS_SIG_MECHS);
                break;
            case CKM_RSA_PKCS_OAEP:
            case CKM_RSA_X_509:
            case CKM_RSA_X9_31:
                add_rsaenc = true;
                UNCHECK_MECHS(CKM_RSA_PKCS_KEY_PAIR_GEN, RSA_ENC_MECHS);
                break;
            case CKM_EC_KEY_PAIR_GEN:
                UNCHECK_MECHS(CKM_EC_KEY_PAIR_GEN);
                break;
            case CKM_ECDSA:
            case CKM_ECDSA_SHA1:
            case CKM_ECDSA_SHA224:
            case CKM_ECDSA_SHA256:
            case CKM_ECDSA_SHA384:
            case CKM_ECDSA_SHA512:
            case CKM_ECDSA_SHA3_224:
            case CKM_ECDSA_SHA3_256:
            case CKM_ECDSA_SHA3_384:
            case CKM_ECDSA_SHA3_512:
                ADD_ALGO(ECDSA, ecdsa, signature);
                UNCHECK_MECHS(CKM_EC_KEY_PAIR_GEN, ECDSA_SIG_MECHS);
                break;
            case CKM_ECDH1_DERIVE:
            case CKM_ECDH1_COFACTOR_DERIVE:
                ADD_ALGO(ECDH, ecdh, exchange);
                UNCHECK_MECHS(CKM_EC_KEY_PAIR_GEN, CKM_ECDH1_DERIVE,
                              CKM_ECDH1_COFACTOR_DERIVE);
                break;
            case CKM_HKDF_DERIVE:
                ADD_ALGO(HKDF, hkdf, kdf);
                ADD_ALGO(TLS13_KDF, tls13, kdf);
                ADD_ALGO(HKDF, hkdf, exchange);
                UNCHECK_MECHS(CKM_HKDF_DERIVE);
                break;
            case CKM_SHA_1:
                ADD_ALGO(SHA1, sha1, digest);
                UNCHECK_MECHS(CKM_SHA_1);
                break;
            case CKM_SHA224:
                ADD_ALGO(SHA2_224, sha224, digest);
                UNCHECK_MECHS(CKM_SHA224);
                break;
            case CKM_SHA256:
                ADD_ALGO(SHA2_256, sha256, digest);
                UNCHECK_MECHS(CKM_SHA256);
                break;
            case CKM_SHA384:
                ADD_ALGO(SHA2_384, sha384, digest);
                UNCHECK_MECHS(CKM_SHA384);
                break;
            case CKM_SHA512:
                ADD_ALGO(SHA2_512, sha512, digest);
                UNCHECK_MECHS(CKM_SHA512);
                break;
            case CKM_SHA512_224:
                ADD_ALGO(SHA2_512_224, sha512_224, digest);
                UNCHECK_MECHS(CKM_SHA512_224);
                break;
            case CKM_SHA512_256:
                ADD_ALGO(SHA2_512_256, sha512_256, digest);
                UNCHECK_MECHS(CKM_SHA512_256);
                break;
            case CKM_SHA3_224:
                ADD_ALGO(SHA3_224, sha3_224, digest);
                UNCHECK_MECHS(CKM_SHA3_224);
                break;
            case CKM_SHA3_256:
                ADD_ALGO(SHA3_256, sha3_256, digest);
                UNCHECK_MECHS(CKM_SHA3_256);
                break;
            case CKM_SHA3_384:
                ADD_ALGO(SHA3_384, sha3_384, digest);
                UNCHECK_MECHS(CKM_SHA3_384);
                break;
            case CKM_SHA3_512:
                ADD_ALGO(SHA3_512, sha3_512, digest);
                UNCHECK_MECHS(CKM_SHA3_512);
                break;
            case CKM_EDDSA:
                ADD_ALGO_EXT(ED25519, signature, P11PROV_DEFAULT_PROPERTIES,
                             p11prov_eddsa_signature_functions);
                ADD_ALGO_EXT(ED448, signature, P11PROV_DEFAULT_PROPERTIES,
                             p11prov_eddsa_signature_functions);
                UNCHECK_MECHS(CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EDDSA);
                break;
            default:
                P11PROV_raise(ctx, CKR_GENERAL_ERROR,
                              "Unhandled mechianism %lu", mech);
                break;
            }
        }
    }

    p11prov_return_slots(slots);

    if (add_rsasig) {
        ADD_ALGO(RSA, rsa, signature);
    }
    if (add_rsaenc) {
        ADD_ALGO(RSA, rsa, asym_cipher);
    }
    /* terminations */
    TERM_ALGO(digest);
    TERM_ALGO(kdf);
    TERM_ALGO(exchange);
    TERM_ALGO(signature);
    TERM_ALGO(asym_cipher);

    /* encoder/decoder */
    ADD_ALGO_EXT(RSA, encoder, "provider=pkcs11,output=text",
                 p11prov_rsa_encoder_text_functions);
    ADD_ALGO_EXT(RSA, encoder, "provider=pkcs11,output=der,structure=pkcs1",
                 p11prov_rsa_encoder_pkcs1_der_functions);
    ADD_ALGO_EXT(RSA, encoder, "provider=pkcs11,output=pem,structure=pkcs1",
                 p11prov_rsa_encoder_pkcs1_pem_functions);
    ADD_ALGO_EXT(RSA, encoder,
                 "provider=pkcs11,output=der,structure=SubjectPublicKeyInfo",
                 p11prov_rsa_encoder_spki_der_functions);
    ADD_ALGO_EXT(RSA, encoder,
                 "provider=pkcs11,output=pem,structure=SubjectPublicKeyInfo",
                 p11prov_rsa_encoder_spki_pem_functions);
    ADD_ALGO_EXT(RSAPSS, encoder, "provider=pkcs11,output=text",
                 p11prov_rsa_encoder_text_functions);
    ADD_ALGO_EXT(RSAPSS, encoder, "provider=pkcs11,output=der,structure=pkcs1",
                 p11prov_rsa_encoder_pkcs1_der_functions);
    ADD_ALGO_EXT(RSAPSS, encoder, "provider=pkcs11,output=pem,structure=pkcs1",
                 p11prov_rsa_encoder_pkcs1_pem_functions);
    ADD_ALGO_EXT(RSAPSS, encoder,
                 "provider=pkcs11,output=der,structure=SubjectPublicKeyInfo",
                 p11prov_rsa_encoder_spki_der_functions);
    ADD_ALGO_EXT(RSAPSS, encoder,
                 "provider=pkcs11,output=pem,structure=SubjectPublicKeyInfo",
                 p11prov_rsa_encoder_spki_pem_functions);
    ADD_ALGO_EXT(EC, encoder, "provider=pkcs11,output=text",
                 p11prov_ec_encoder_text_functions);
    ADD_ALGO_EXT(EC, encoder, "provider=pkcs11,output=der,structure=pkcs1",
                 p11prov_ec_encoder_pkcs1_der_functions);
    ADD_ALGO_EXT(EC, encoder, "provider=pkcs11,output=pem,structure=pkcs1",
                 p11prov_ec_encoder_pkcs1_pem_functions);
    ADD_ALGO_EXT(EC, encoder,
                 "provider=pkcs11,output=der,structure=SubjectPublicKeyInfo",
                 p11prov_ec_encoder_spki_der_functions);
    ADD_ALGO_EXT(ED25519, encoder, "provider=pkcs11,output=text",
                 p11prov_ec_edwards_encoder_text_functions);
    ADD_ALGO_EXT(ED448, encoder, "provider=pkcs11,output=text",
                 p11prov_ec_edwards_encoder_text_functions);
    if (ctx->encode_pkey_as_pk11_uri) {
        ADD_ALGO_EXT(RSA, encoder,
                     "provider=pkcs11,output=pem,structure=PrivateKeyInfo",
                     p11prov_rsa_encoder_priv_key_info_pem_functions);
        ADD_ALGO_EXT(RSAPSS, encoder,
                     "provider=pkcs11,output=pem,structure=PrivateKeyInfo",
                     p11prov_rsa_encoder_priv_key_info_pem_functions);
        ADD_ALGO_EXT(EC, encoder,
                     "provider=pkcs11,output=pem,structure=PrivateKeyInfo",
                     p11prov_ec_encoder_priv_key_info_pem_functions);
        ADD_ALGO_EXT(ED25519, encoder,
                     "provider=pkcs11,output=pem,structure=PrivateKeyInfo",
                     p11prov_ec_edwards_encoder_priv_key_info_pem_functions);
        ADD_ALGO_EXT(ED448, encoder,
                     "provider=pkcs11,output=pem,structure=PrivateKeyInfo",
                     p11prov_ec_edwards_encoder_priv_key_info_pem_functions);
    }

    TERM_ALGO(encoder);

    /* handle random */
    ret = p11prov_check_random(ctx);
    if (ret == CKR_OK) {
        ADD_ALGO_EXT(RAND, random, "provider=pkcs11", p11prov_rand_functions);
        TERM_ALGO(random);
    }

    return CKR_OK;
}

static const OSSL_ALGORITHM p11prov_keymgmt[] = {
    { P11PROV_NAMES_RSA, P11PROV_DEFAULT_PROPERTIES,
      p11prov_rsa_keymgmt_functions, P11PROV_DESCS_RSA },
    { P11PROV_NAMES_RSAPSS, P11PROV_DEFAULT_PROPERTIES,
      p11prov_rsapss_keymgmt_functions, P11PROV_DESCS_RSAPSS },
    { P11PROV_NAMES_EC, P11PROV_DEFAULT_PROPERTIES,
      p11prov_ec_keymgmt_functions, P11PROV_DESCS_EC },
    { P11PROV_NAMES_HKDF, P11PROV_DEFAULT_PROPERTIES,
      p11prov_hkdf_keymgmt_functions, P11PROV_DESCS_HKDF },
    { P11PROV_NAMES_ED25519, P11PROV_DEFAULT_PROPERTIES,
      p11prov_ed25519_keymgmt_functions, P11PROV_DESCS_ED25519 },
    { P11PROV_NAMES_ED448, P11PROV_DEFAULT_PROPERTIES,
      p11prov_ed448_keymgmt_functions, P11PROV_DESCS_ED448 },
    { NULL, NULL, NULL, NULL },
};

static const OSSL_ALGORITHM p11prov_store[] = {
    {
        "pkcs11",
        P11PROV_DEFAULT_PROPERTIES,
        p11prov_store_functions,
        P11PROV_DESCS_URI,
    },
    { NULL, NULL, NULL, NULL },
};

static const OSSL_ALGORITHM p11prov_decoders[] = {
    { "DER", "provider=pkcs11,input=pem",
      p11prov_pem_decoder_p11prov_der_functions },
    { P11PROV_NAMES_RSA,
      "provider=pkcs11,input=der,structure=" P11PROV_DER_STRUCTURE,
      p11prov_der_decoder_p11prov_rsa_functions },
    { P11PROV_NAMES_RSAPSS,
      "provider=pkcs11,input=der,structure=" P11PROV_DER_STRUCTURE,
      p11prov_der_decoder_p11prov_rsa_functions },
    { P11PROV_NAMES_EC,
      "provider=pkcs11,input=der,structure=" P11PROV_DER_STRUCTURE,
      p11prov_der_decoder_p11prov_ec_functions },
    { P11PROV_NAMES_ED25519,
      "provider=pkcs11,input=der,structure=" P11PROV_DER_STRUCTURE,
      p11prov_der_decoder_p11prov_ed25519_functions },
    { P11PROV_NAMES_ED448,
      "provider=pkcs11,input=der,structure=" P11PROV_DER_STRUCTURE,
      p11prov_der_decoder_p11prov_ed448_functions },
    { NULL, NULL, NULL }
};

static const char *p11prov_block_ops_names[OSSL_OP__HIGHEST + 1] = {
    [OSSL_OP_DIGEST] = "digest",
    [OSSL_OP_CIPHER] = "cipher",
    [OSSL_OP_MAC] = "mac",
    [OSSL_OP_KDF] = "kdf",
    [OSSL_OP_RAND] = "rand",
    [OSSL_OP_KEYMGMT] = "keymgmt",
    [OSSL_OP_KEYEXCH] = "keyexch",
    [OSSL_OP_SIGNATURE] = "signature",
    [OSSL_OP_ASYM_CIPHER] = "asym-cipher",
    [OSSL_OP_KEM] = "kem",
    [OSSL_OP_ENCODER] = "encoder",
    [OSSL_OP_DECODER] = "decoder",
    [OSSL_OP_STORE] = "store",
};

static const OSSL_ALGORITHM *
p11prov_query_operation(void *provctx, int operation_id, int *no_cache)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;

    if (operation_id > OSSL_OP__HIGHEST) {
        P11PROV_debug("Invalid op id %d > OSSL_OP__HIGHEST", operation_id);
        *no_cache = 0;
        return NULL;
    }
    if (ctx->blocked_ops[operation_id]) {
        P11PROV_debug("Blocked operation: %s (%d)",
                      p11prov_block_ops_names[operation_id], operation_id);
        *no_cache = 0;
        return NULL;
    }

    switch (operation_id) {
    case OSSL_OP_DIGEST:
        *no_cache = ctx->status == P11PROV_UNINITIALIZED ? 1 : 0;
        return ctx->op_digest;
    case OSSL_OP_KDF:
        *no_cache = ctx->status == P11PROV_UNINITIALIZED ? 1 : 0;
        return ctx->op_kdf;
    case OSSL_OP_RAND:
        *no_cache = ctx->status == P11PROV_UNINITIALIZED ? 1 : 0;
        return ctx->op_random;
    case OSSL_OP_KEYMGMT:
        *no_cache = 0;
        return p11prov_keymgmt;
    case OSSL_OP_KEYEXCH:
        *no_cache = ctx->status == P11PROV_UNINITIALIZED ? 1 : 0;
        return ctx->op_exchange;
    case OSSL_OP_SIGNATURE:
        *no_cache = ctx->status == P11PROV_UNINITIALIZED ? 1 : 0;
        return ctx->op_signature;
    case OSSL_OP_ASYM_CIPHER:
        *no_cache = ctx->status == P11PROV_UNINITIALIZED ? 1 : 0;
        return ctx->op_asym_cipher;
    case OSSL_OP_ENCODER:
        *no_cache = ctx->status == P11PROV_UNINITIALIZED ? 1 : 0;
        return ctx->op_encoder;
    case OSSL_OP_DECODER:
        *no_cache = 0;
        return p11prov_decoders;
    case OSSL_OP_STORE:
        *no_cache = 0;
        return p11prov_store;
    }
    *no_cache = 0;
    return NULL;
}

static int p11prov_get_capabilities(void *provctx, const char *capability,
                                    OSSL_CALLBACK *cb, void *arg)
{
    int ret = RET_OSSL_OK;

    if (OPENSSL_strcasecmp(capability, "TLS-GROUP") == 0) {
        ret = tls_group_capabilities(cb, arg);
    }

    return ret;
}

static const OSSL_ITEM *p11prov_get_reason_strings(void *provctx)
{
#define C(str) (void *)(str)
    static const OSSL_ITEM reason_strings[] = {
        { CKR_HOST_MEMORY, C("Host out of memory error") },
        { CKR_SLOT_ID_INVALID, C("The specified slot ID is not valid") },
        { CKR_GENERAL_ERROR, C("General Error") },
        { CKR_FUNCTION_FAILED,
          C("The requested function could not be performed") },
        { CKR_ARGUMENTS_BAD,
          C("Invalid or improper arguments were provided to the "
            "invoked function") },
        { CKR_CANT_LOCK, C("Internal locking failure") },
        { CKR_ATTRIBUTE_READ_ONLY,
          C("Attempted to set or modify an attribute that is Read "
            "Only for applications") },
        { CKR_ATTRIBUTE_TYPE_INVALID,
          C("Invalid attribute type specified in a template") },
        { CKR_ATTRIBUTE_VALUE_INVALID,
          C("Invalid value specified for attribute in a template") },
        { CKR_DATA_INVALID, C("The plaintext input data to a cryptographic "
                              "operation is invalid") },
        { CKR_DATA_LEN_RANGE,
          C("The size of plaintext input data to a cryptographic "
            "operation is invalid (Out of range)") },
        { CKR_DEVICE_ERROR,
          C("Some problem has occurred with the token and/or slot") },
        { CKR_DEVICE_MEMORY,
          C("The token does not have sufficient memory to perform "
            "the requested function") },
        { CKR_DEVICE_REMOVED,
          C("The token was removed from its slot during the "
            "execution of the function") },
        { CKR_FUNCTION_CANCELED,
          C("The function was canceled in mid-execution") },
        { CKR_KEY_HANDLE_INVALID, C("The specified key handle is not valid") },
        { CKR_KEY_SIZE_RANGE,
          C("Unable to handle the specified key size (Out of range)") },
        { CKR_KEY_NEEDED, C("This operation requires a key (missing)") },
        { CKR_KEY_TYPE_INCONSISTENT,
          C("The specified key is not the correct type of key to "
            "use with the specified mechanism") },
        { CKR_KEY_FUNCTION_NOT_PERMITTED,
          C("The key attributes do not allow this operation to "
            "be executed") },
        { CKR_MECHANISM_INVALID, C("An invalid mechanism was specified to the "
                                   "cryptographic operation") },
        { CKR_MECHANISM_PARAM_INVALID,
          C("Invalid mechanism parameters were supplied") },
        { CKR_OPERATION_ACTIVE,
          C("There is already an active operation that prevents "
            "executing the requested function") },
        { CKR_OPERATION_NOT_INITIALIZED,
          C("There is no active operation of appropriate type "
            "in the specified session") },
        { CKR_PIN_INCORRECT, C("The specified PIN is incorrect") },
        { CKR_PIN_INVALID, C("The specified PIN is invalid") },
        { CKR_PIN_EXPIRED, C("The specified PIN has expired") },
        { CKR_PIN_LOCKED,
          C("The specified PIN is locked, and cannot be used") },
        { CKR_SESSION_CLOSED, C("Session is already closed") },
        { CKR_SESSION_COUNT, C("Too many sessions open") },
        { CKR_SESSION_HANDLE_INVALID, C("Invalid Session Handle") },
        { CKR_SESSION_PARALLEL_NOT_SUPPORTED,
          C("Parallel sessions not supported") },
        { CKR_SESSION_READ_ONLY, C("Session is Read Only") },
        { CKR_SESSION_EXISTS, C("Session already exists") },
        { CKR_SESSION_READ_ONLY_EXISTS,
          C("A read-only session already exists") },
        { CKR_SESSION_READ_WRITE_SO_EXISTS,
          C("A read/write SO session already exists") },
        { CKR_TEMPLATE_INCOMPLETE,
          C("The template to create an object is incomplete") },
        { CKR_TEMPLATE_INCONSISTENT,
          C("The template to create an object has conflicting attributes") },
        { CKR_TOKEN_NOT_PRESENT,
          C("The token was not present in its slot when the "
            "function was invoked") },
        { CKR_TOKEN_NOT_RECOGNIZED,
          C("The token in the slot is not recognized") },
        { CKR_TOKEN_WRITE_PROTECTED,
          C("Action denied because the token is write-protected") },
        { CKR_TOKEN_WRITE_PROTECTED,
          C("Can't perform action because the token is write-protected") },
        { CKR_USER_NOT_LOGGED_IN,
          C("The desired action cannot be performed because an "
            "appropriate user is not logged in") },
        { CKR_USER_PIN_NOT_INITIALIZED, C("The user PIN is not initialized") },
        { CKR_USER_TYPE_INVALID, C("An invalid user type was specified") },
        { CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
          C("Another user is already logged in") },
        { CKR_USER_TOO_MANY_TYPES,
          C("Attempted to log in more users than the token can support") },
        { CKR_OPERATION_CANCEL_FAILED, C("The operation cannot be cancelled") },
        { CKR_DOMAIN_PARAMS_INVALID,
          C("Invalid or unsupported domain parameters were "
            "supplied to the function") },
        { CKR_CURVE_NOT_SUPPORTED,
          C("The specified curve is not supported by this token") },
        { CKR_BUFFER_TOO_SMALL,
          C("The output of the function is too large to fit in "
            "the supplied buffer") },
        { CKR_SAVED_STATE_INVALID,
          C("The supplied saved cryptographic operations state is invalid") },
        { CKR_STATE_UNSAVEABLE,
          C("The cryptographic operations state of the specified "
            "session cannot be saved") },
        { CKR_CRYPTOKI_NOT_INITIALIZED,
          C("PKCS11 Module has not been initialized yet") },
        { 0, NULL },
    };

    return reason_strings;
#undef C
}

/* Functions we provide to the core */
static const OSSL_DISPATCH p11prov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))p11prov_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
      (void (*)(void))p11prov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))p11prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,
      (void (*)(void))p11prov_query_operation },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
      (void (*)(void))p11prov_get_capabilities },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
      (void (*)(void))p11prov_get_reason_strings },
    { 0, NULL },
};

enum p11prov_cfg_enum {
    P11PROV_CFG_PATH = 0,
    P11PROV_CFG_INIT_ARGS,
    P11PROV_CFG_TOKEN_PIN,
    P11PROV_CFG_ALLOW_EXPORT,
    P11PROV_CFG_LOGIN_BEHAVIOR,
    P11PROV_CFG_LOAD_BEHAVIOR,
    P11PROV_CFG_CACHE_PINS,
    P11PROV_CFG_CACHE_KEYS,
    P11PROV_CFG_QUIRKS,
    P11PROV_CFG_CACHE_SESSIONS,
    P11PROV_CFG_ENCODE_PROVIDER_URI_TO_PEM,
    P11PROV_CFG_BLOCK_OPS,
    P11PROV_CFG_SIZE,
};

static struct p11prov_cfg_names {
    const char *name;
} p11prov_cfg_names[P11PROV_CFG_SIZE] = {
    { "pkcs11-module-path" },
    { "pkcs11-module-init-args" },
    { "pkcs11-module-token-pin" },
    { "pkcs11-module-allow-export" },
    { "pkcs11-module-login-behavior" },
    { "pkcs11-module-load-behavior" },
    { "pkcs11-module-cache-pins" },
    { "pkcs11-module-cache-keys" },
    { "pkcs11-module-quirks" },
    { "pkcs11-module-cache-sessions" },
    { "pkcs11-module-encode-provider-uri-to-pem" },
    { "pkcs11-module-block-operations" },
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx)
{
    const char *cfg[P11PROV_CFG_SIZE] = { 0 };
    OSSL_PARAM core_params[P11PROV_CFG_SIZE + 1];
    P11PROV_CTX *ctx;
    bool show_quirks = false;
    int ret;

    *provctx = NULL;

    p11prov_get_core_dispatch_funcs(in);

    ctx = OPENSSL_zalloc(sizeof(P11PROV_CTX));
    if (ctx == NULL) {
        return RET_OSSL_ERR;
    }
    ctx->handle = handle;

    ret = pthread_rwlock_init(&ctx->quirk_lock, NULL);
    if (ret != 0) {
        ret = errno;
        P11PROV_debug("rwlock init failed (%d)", ret);
        OPENSSL_free(ctx);
        return RET_OSSL_ERR;
    }

    ctx->libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);
    if (ctx->libctx == NULL) {
        OPENSSL_free(ctx);
        return RET_OSSL_ERR;
    }

    for (int i = 0; i < P11PROV_CFG_SIZE; i++) {
        core_params[i] = OSSL_PARAM_construct_utf8_ptr(
            p11prov_cfg_names[i].name, (char **)&cfg[i], sizeof(void *));
    }
    core_params[P11PROV_CFG_SIZE] = OSSL_PARAM_construct_end();

    ret = core_get_params(handle, core_params);
    if (ret != RET_OSSL_OK) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        p11prov_ctx_free(ctx);
        return ret;
    }

    P11PROV_debug("Provided config params:");
    for (int i = 0; i < P11PROV_CFG_SIZE; i++) {
        const char none[] = "[none]";
        const char pin[] = "[****]";
        const char *val = none;
        if (i == P11PROV_CFG_TOKEN_PIN) {
            val = pin;
        } else if (cfg[i]) {
            val = cfg[i];
        }
        P11PROV_debug("  %s: %s", p11prov_cfg_names[i].name, val);
    }

    ret = p11prov_module_new(ctx, cfg[P11PROV_CFG_PATH],
                             cfg[P11PROV_CFG_INIT_ARGS], &ctx->module);
    if (ret != CKR_OK) {
        ERR_raise(ERR_LIB_PROV, PROV_R_IN_ERROR_STATE);
        p11prov_ctx_free(ctx);
        return RET_OSSL_ERR;
    }

    if (cfg[P11PROV_CFG_TOKEN_PIN] != NULL) {
        ret = p11prov_get_pin(ctx, cfg[P11PROV_CFG_TOKEN_PIN], &ctx->pin);
        if (ret != 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_IN_ERROR_STATE);
            p11prov_ctx_free(ctx);
            return RET_OSSL_ERR;
        }
    }
    P11PROV_debug("PIN %savailable", ctx->pin ? "" : "not ");

    if (cfg[P11PROV_CFG_ALLOW_EXPORT] != NULL) {
        char *end = NULL;
        errno = 0;
        ctx->allow_export = (int)strtol(cfg[P11PROV_CFG_ALLOW_EXPORT], &end, 0);
        if (errno != 0 || *end != '\0') {
            P11PROV_raise(ctx, CKR_GENERAL_ERROR, "Invalid value for %s: (%s)",
                          p11prov_cfg_names[P11PROV_CFG_ALLOW_EXPORT].name,
                          cfg[P11PROV_CFG_ALLOW_EXPORT]);
            p11prov_ctx_free(ctx);
            return RET_OSSL_ERR;
        }
    }
    P11PROV_debug("Export %sallowed", ctx->allow_export == 1 ? "not " : "");

    if (cfg[P11PROV_CFG_LOGIN_BEHAVIOR] != NULL) {
        if (strcmp(cfg[P11PROV_CFG_LOGIN_BEHAVIOR], "auto") == 0) {
            ctx->login_behavior = PUBKEY_LOGIN_AUTO;
        } else if (strcmp(cfg[P11PROV_CFG_LOGIN_BEHAVIOR], "always") == 0) {
            ctx->login_behavior = PUBKEY_LOGIN_ALWAYS;
        } else if (strcmp(cfg[P11PROV_CFG_LOGIN_BEHAVIOR], "never") == 0) {
            ctx->login_behavior = PUBKEY_LOGIN_NEVER;
        } else {
            P11PROV_raise(ctx, CKR_GENERAL_ERROR, "Invalid value for %s: (%s)",
                          p11prov_cfg_names[P11PROV_CFG_LOGIN_BEHAVIOR].name,
                          cfg[P11PROV_CFG_LOGIN_BEHAVIOR]);
            p11prov_ctx_free(ctx);
            return RET_OSSL_ERR;
        }
    }
    switch (ctx->login_behavior) {
    case PUBKEY_LOGIN_AUTO:
        P11PROV_debug("Login behavior: auto");
        break;
    case PUBKEY_LOGIN_ALWAYS:
        P11PROV_debug("Login behavior: always");
        break;
    case PUBKEY_LOGIN_NEVER:
        P11PROV_debug("Login behavior: never");
        break;
    default:
        P11PROV_debug("Login behavior: <invalid>");
        break;
    }

    if (cfg[P11PROV_CFG_CACHE_PINS] != NULL
        && strcmp(cfg[P11PROV_CFG_CACHE_PINS], "cache") == 0) {
        ctx->cache_pins = true;
    }
    P11PROV_debug("PINs will %sbe cached", ctx->cache_pins ? "" : "not ");

    if (cfg[P11PROV_CFG_CACHE_KEYS] != NULL) {
        if (strcmp(cfg[P11PROV_CFG_CACHE_KEYS], "true") == 0) {
            ctx->cache_keys = P11PROV_CACHE_KEYS_IN_SESSION;
        } else if (strcmp(cfg[P11PROV_CFG_CACHE_KEYS], "false") == 0) {
            ctx->cache_keys = P11PROV_CACHE_KEYS_NEVER;
        }
    } else {
        /* defaults to session */
        ctx->cache_keys = P11PROV_CACHE_KEYS_IN_SESSION;
    }
    switch (ctx->cache_keys) {
    case P11PROV_CACHE_KEYS_NEVER:
        P11PROV_debug("Key caching: never");
        break;
    case P11PROV_CACHE_KEYS_IN_SESSION:
        P11PROV_debug("Key caching: in session object");
        break;
    }

    if (cfg[P11PROV_CFG_QUIRKS] != NULL) {
        const char *str;
        const char *sep;
        size_t len = strlen(cfg[P11PROV_CFG_QUIRKS]);
        size_t toklen;

        str = cfg[P11PROV_CFG_QUIRKS];
        while (str) {
            sep = strchr(str, ' ');
            if (sep) {
                toklen = sep - str;
            } else {
                toklen = len;
            }
            if (strncmp(str, "no-deinit", toklen) == 0) {
                show_quirks = true;
                ctx->no_deinit = true;
            } else if (strncmp(str, "no-allowed-mechanisms", toklen) == 0) {
                show_quirks = true;
                ctx->no_allowed_mechanisms = true;
            } else if (strncmp(str, "no-operation-state", toklen) == 0) {
                show_quirks = true;
                ctx->blocked_calls |= P11PROV_BLOCK_GetOperationState;
            } else if (strncmp(str, "no-session-callbacks", toklen) == 0) {
                show_quirks = true;
                ctx->no_session_callbacks = true;
            }
            len -= toklen;
            if (sep) {
                str = sep + 1;
                len--;
            } else {
                str = NULL;
            }
        }
    }
    if (show_quirks) {
        P11PROV_debug("Quirks:");
        if (ctx->no_deinit) {
            P11PROV_debug(" No finalization on de-initialization");
        }
        if (ctx->no_allowed_mechanisms) {
            P11PROV_debug(" No CKA_ALLOWED_MECHANISM use");
        }
        if (ctx->no_session_callbacks) {
            P11PROV_debug(" No session callbacks");
        }
        if (ctx->blocked_calls) {
            P11PROV_debug(" Blocked calls: [%08lx]", ctx->blocked_calls);
        }
    } else {
        P11PROV_debug("No quirks");
    }

    if (cfg[P11PROV_CFG_CACHE_SESSIONS] != NULL) {
        CK_ULONG val;
        ret =
            parse_ulong(ctx, cfg[P11PROV_CFG_CACHE_SESSIONS],
                        strlen(cfg[P11PROV_CFG_CACHE_SESSIONS]), (void **)&val);
        if (ret != 0 || val > MAX_CONCURRENT_SESSIONS) {
            P11PROV_raise(ctx, CKR_GENERAL_ERROR, "Invalid value for %s: (%s)",
                          p11prov_cfg_names[P11PROV_CFG_CACHE_SESSIONS].name,
                          cfg[P11PROV_CFG_CACHE_SESSIONS]);
            p11prov_ctx_free(ctx);
            return RET_OSSL_ERR;
        }
        ctx->cache_sessions = val;
    } else {
        ctx->cache_sessions = MAX_CACHE_SESSIONS;
    }
    P11PROV_debug("Cache Sessions: %d", ctx->cache_sessions);

    if (cfg[P11PROV_CFG_ENCODE_PROVIDER_URI_TO_PEM] != NULL
        && strcmp(cfg[P11PROV_CFG_ENCODE_PROVIDER_URI_TO_PEM], "true") == 0) {
        ctx->encode_pkey_as_pk11_uri = true;
    } else {
        ctx->encode_pkey_as_pk11_uri = false;
    }
    P11PROV_debug("PK11-URI will %sbe written instead of PrivateKeyInfo",
                  ctx->encode_pkey_as_pk11_uri ? "" : "not ");

    if (cfg[P11PROV_CFG_BLOCK_OPS] != NULL) {
        const char *str;
        const char *sep;
        size_t len = strlen(cfg[P11PROV_CFG_BLOCK_OPS]);
        size_t tokl;
        bool match = false;

        P11PROV_debug("Blocked Operations:");

        str = cfg[P11PROV_CFG_BLOCK_OPS];
        while (str) {
            sep = strchr(str, ' ');
            if (sep) {
                tokl = sep - str;
            } else {
                tokl = len;
            }
            match = false;
            for (int i = 0; i < OSSL_OP__HIGHEST; i++) {
                if (p11prov_block_ops_names[i]
                    && strncmp(str, p11prov_block_ops_names[i], tokl) == 0) {
                    match = true;
                    P11PROV_debug("  %s", p11prov_block_ops_names[i]);
                    ctx->blocked_ops[i] = true;
                    break;
                }
            }
            if (!match) {
                P11PROV_debug("  **invalid token: [%.*s]", (int)tokl, str);
            }
            len -= tokl;
            if (sep) {
                str = sep + 1;
                len--;
            } else {
                str = NULL;
            }
        }
    } else {
        P11PROV_debug("Blocked Operations: None");
    }

    /* PAY ATTENTION: do this as the last thing */
    if (cfg[P11PROV_CFG_LOAD_BEHAVIOR] != NULL
        && strcmp(cfg[P11PROV_CFG_LOAD_BEHAVIOR], "early") == 0) {
        /* this triggers early module loading */
        ret = p11prov_ctx_status(ctx);
        if (ret != CKR_OK) {
            p11prov_ctx_free(ctx);
            return RET_OSSL_ERR;
        }
    }
    P11PROV_debug("Load behavior: %s",
                  ctx->status == P11PROV_UNINITIALIZED ? "default" : "early");

    /* done */
    ret = RET_OSSL_OK;
    context_add_pool(ctx);
    *out = p11prov_dispatch_table;
    *provctx = ctx;
    return ret;
}
