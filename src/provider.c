/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

#include "provider.h"
#include <dlfcn.h>

struct st_provider_ctx {

    bool initialized;
    pthread_mutex_t lock;

    /* Provider handles */
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;

    /* Configuration */
    /* TODO: pin */
    const char *module;
    const char *init_args;
    /* TODO: ui_method */
    /* TODO: fork id */

    /* module handles and data */
    void *dlhandle;
    CK_FUNCTION_LIST *fns;

    int nslots;
    struct p11prov_slot *slots;
};

int provider_ctx_lock_slots(PROVIDER_CTX *ctx, struct p11prov_slot **slots)
{
    if (!ctx->initialized) return RET_OSSL_ERR;

    pthread_mutex_lock(&ctx->lock);

    *slots = ctx->slots;
    return ctx->nslots;
}

void provider_ctx_unlock_slots(PROVIDER_CTX *ctx, struct p11prov_slot **slots)
{
    if (!ctx->initialized) return;

    *slots = NULL;

    pthread_mutex_unlock(&ctx->lock);
}

CK_FUNCTION_LIST *provider_ctx_fns(PROVIDER_CTX *ctx)
{
    if (!ctx->initialized) return NULL;
    return ctx->fns;
}

static void provider_ctx_free(PROVIDER_CTX *ctx)
{
    if (ctx->initialized) {
        pthread_mutex_lock(&ctx->lock);
    }

    OSSL_LIB_CTX_free(ctx->libctx);

    /* TODO: C_CloseAllSessions ? */
    if (ctx->dlhandle) {
        ctx->fns->C_Finalize(NULL);
        dlclose(ctx->dlhandle);

        if (ctx->slots) {
            OPENSSL_free(ctx->slots);
            ctx->slots = NULL;
            ctx->nslots = 0;
        }
    }

    if (ctx->initialized) {
        pthread_mutex_unlock(&ctx->lock);
    }
    pthread_mutex_destroy(&ctx->lock);
    OPENSSL_clear_free(ctx, sizeof(PROVIDER_CTX));
}

static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

static void p11prov_teardown(void *ctx)
{
    provider_ctx_free((PROVIDER_CTX *)ctx);
}

/* Parameters we provide to the core */
static const OSSL_PARAM p11prov_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
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
        if (ret == 0) return RET_OSSL_ERR;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL) {
        /* temporarily return the OpenSSL build version */
        ret = OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR);
        if (ret == 0) return RET_OSSL_ERR;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL) {
        /* temporarily return the OpenSSL build version */
        ret = OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR);
        if (ret == 0) return RET_OSSL_ERR;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL) {
        /* return 1 for now,
         * return 0 in future if there are module issues? */
        ret = OSSL_PARAM_set_int(p, 1);
        if (ret == 0) return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

/* TODO: this needs to be made dynamic,
 * based on what the pkcs11 module supports */
static const OSSL_ALGORITHM p11prov_keymgmt[] = {
    { P11PROV_NAMES_RSA, P11PROV_DEFAULT_PROPERTIES,
      p11prov_rsa_keymgmt_functions, P11PROV_DESCS_RSA, },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM p11prov_store[] = {
    { "pkcs11", P11PROV_DEFAULT_PROPERTIES,
      p11prov_store_functions, P11PROV_DESCS_URI, },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM p11prov_signature[] = {
    { P11PROV_NAMES_RSA, P11PROV_DEFAULT_PROPERTIES,
      p11prov_rsa_signature_functions, P11PROV_DESCS_RSA, },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *p11prov_query_operation(void *provctx,
                                                     int operation_id,
                                                     int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return p11prov_keymgmt;
    case OSSL_OP_STORE:
        return p11prov_store;
    case OSSL_OP_SIGNATURE:
        return p11prov_signature;
    }
    return NULL;
}

static int p11prov_get_capabilities(void *provctx, const char *capability,
                                    OSSL_CALLBACK *cb, void *arg)
{
    /* TODO: deal with TLS-GROUP */

    return RET_OSSL_ERR;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH p11prov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN,
      (void (*)(void))p11prov_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
      (void (*)(void))p11prov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,
      (void (*)(void))p11prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,
      (void (*)(void))p11prov_query_operation },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
      (void (*)(void))p11prov_get_capabilities },
    { 0, NULL }
};

static int refresh_slot_profiles(PROVIDER_CTX *ctx, struct p11prov_slot *slot)
{
    CK_SESSION_HANDLE session;
    CK_BBOOL token = CK_TRUE;
    CK_OBJECT_CLASS class = CKO_PROFILE;

    CK_ATTRIBUTE template[2] = {
        { CKA_TOKEN, &token, sizeof(token) },
        { CKA_CLASS, &class, sizeof(class) },
    };
    CK_OBJECT_HANDLE object[5];
    CK_ULONG objcount;
    int index = 0;
    int ret;

    ret = ctx->fns->C_OpenSession(slot->id, CKF_SERIAL_SESSION, NULL, NULL,
                                  &session);
    if (ret != CKR_OK) {
        p11prov_debug("OpenSession failed %d\n", ret);
        return ret;
    }

    ret = ctx->fns->C_FindObjectsInit(session, template, 2);
    if (ret != CKR_OK) {
        p11prov_debug("C_FindObjectsInit failed %d\n", ret);
        (void)ctx->fns->C_CloseSession(session);
        return ret;
    }

    /* at most 5 objects as there are 5 profiles for now */
    ret = ctx->fns->C_FindObjects(session, object, 5, &objcount);
    if (ret != CKR_OK) {
        p11prov_debug("C_FindObjects failed %d\n", ret);
        goto done;
    }

    if (objcount == 0) {
        p11prov_debug("No profiles for slot %lu\n", slot->id);
        goto done;
    }

    for (int i = 0; i < objcount; i++) {
        CK_ULONG value = CK_UNAVAILABLE_INFORMATION;
        CK_ATTRIBUTE profileid = { CKA_PROFILE_ID, &value, sizeof(value) };

        ret = ctx->fns->C_GetAttributeValue(session, object[i],
                                            &profileid, 1);
        if (ret != CKR_OK || value == CK_UNAVAILABLE_INFORMATION) {
            p11prov_debug("C_GetAttributeValue failed %d\n", ret);
            continue;
        }

        slot->profiles[index] = value;
        index++;
    }

done:
    (void)ctx->fns->C_FindObjectsFinal(session);
    (void)ctx->fns->C_CloseSession(session);
    return ret;
}

static int refresh_slots(PROVIDER_CTX *ctx)
{
    CK_ULONG nslots;
    CK_SLOT_ID *slotid;
    struct p11prov_slot *slots;
    int ret;

    if (ctx->initialized) {
        pthread_mutex_lock(&ctx->lock);
    }

    ret = ctx->fns->C_GetSlotList(CK_FALSE, NULL, &nslots);
    if (ret) {
        goto done;
    }

    /* arbitrary number from libp11 */
    if (nslots > 0x10000) {
        ret = -E2BIG;
        goto done;
    }

    slotid = OPENSSL_malloc(nslots * sizeof(CK_SLOT_ID));
    if (slotid == NULL) {
        ret = -ENOMEM;
        goto done;
    }


    ret = ctx->fns->C_GetSlotList(CK_FALSE, slotid, &nslots);
    if (ret) {
        OPENSSL_free(slotid);
        goto done;
    }

    slots = OPENSSL_malloc(nslots * sizeof(struct p11prov_slot));
    if (slots == NULL) {
        OPENSSL_free(slotid);
        ret = -ENOMEM;
        goto done;
    }

    for (int i = 0; i < nslots; i++) {
        slots[i].id = slotid[i];
        ret = ctx->fns->C_GetSlotInfo(slotid[i], &slots[i].slot);
        if (ret == CKR_OK && slots[i].slot.flags & CKF_TOKEN_PRESENT) {
            ret = ctx->fns->C_GetTokenInfo(slotid[i], &slots[i].token);
        }
        if (ret) {
            OPENSSL_free(slotid);
            OPENSSL_free(slots);
            goto done;
        }
        (void)refresh_slot_profiles(ctx, &slots[i]);

        p11prov_debug_slot(&slots[i]);
    }

    OPENSSL_free(slotid);
    OPENSSL_free(ctx->slots);
    ctx->slots = slots;
    ctx->nslots = nslots;

done:
    if (ctx->initialized) {
        pthread_mutex_unlock(&ctx->lock);
    }

    return ret;
}

static int p11prov_module_init(PROVIDER_CTX *ctx)
{
    CK_RV (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);
    CK_C_INITIALIZE_ARGS args = {
        .flags = CKF_OS_LOCKING_OK,
        .pReserved = (void *)ctx->init_args,
    };
    CK_INFO ck_info = { 0 };
    int ret;

    if (ctx->initialized) return 0;

    pthread_mutex_init(&ctx->lock, 0);

    p11prov_debug("PKCS#11: Initializing the module: %s\n", ctx->module);

    dlerror();
    ctx->dlhandle = dlopen(ctx->module,
                           RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND);
    if (ctx->dlhandle == NULL) {
        char *err = dlerror();
        p11prov_debug("dlopen() failed: %s\n", err);
        return -ENOENT;
    }

    c_get_function_list = dlsym(ctx->dlhandle, "C_GetFunctionList");
    if (c_get_function_list) {
        ret = c_get_function_list(&ctx->fns);
    } else ret = CKR_GENERAL_ERROR;
    if (ret != CKR_OK) {
        char *err = dlerror();
        p11prov_debug("dlsym() failed: %s\n", err);
        dlclose(ctx->dlhandle);
        ctx->dlhandle = NULL;
        return -ENOENT;
    }

    ret = ctx->fns->C_Initialize(&args);
    if (ret && ret != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        p11prov_debug("init failed: %d (%s:%s)\n", ret, __FILE__, __LINE__);
        return -EFAULT;
    }

    ret = ctx->fns->C_GetInfo(&ck_info);
    if (ret) {
        return -EFAULT;
    }
    p11prov_debug("Module Info: ck_ver:%d.%d lib: '%s' '%s' ver:%d.%d\n",
                  (int)ck_info.cryptokiVersion.major,
                  (int)ck_info.cryptokiVersion.minor,
                  ck_info.manufacturerID,
                  ck_info.libraryDescription,
                  (int)ck_info.libraryVersion.major,
                  (int)ck_info.libraryVersion.minor);

    ret = refresh_slots(ctx);
    if (ret) {
        return -EFAULT;
    }

    ctx->initialized = true;
    return 0;
}

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    const OSSL_DISPATCH *iter_in;
    OSSL_PARAM core_params[3] = { 0 };
    PROVIDER_CTX *ctx;
    int ret;

    *provctx = NULL;

    for (iter_in = in; iter_in->function_id != 0; iter_in++) {
        switch (iter_in->function_id) {
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(iter_in);
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    ctx = OPENSSL_zalloc(sizeof(PROVIDER_CTX));
    if (ctx == NULL) {
        return RET_OSSL_ERR;
    }
    ctx->handle = handle;

    ctx->libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);
    if (ctx->libctx == NULL) {
        OPENSSL_free(ctx);
        return RET_OSSL_ERR;
    }

    /* get module path */
    core_params[0] = OSSL_PARAM_construct_utf8_ptr(
                        P11PROV_PKCS11_MODULE_PATH,
                        (char **)&ctx->module,
                        sizeof(ctx->module));
    core_params[1] = OSSL_PARAM_construct_utf8_ptr(
                        P11PROV_PKCS11_MODULE_INIT_ARGS,
                        (char **)&ctx->init_args,
                        sizeof(ctx->init_args));
    core_params[2] = OSSL_PARAM_construct_end();
    ret = c_get_params(handle, core_params);
    if (ret != RET_OSSL_OK) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        provider_ctx_free(ctx);
        return ret;
    }

    ret = p11prov_module_init(ctx);
    if (ret != CKR_OK) {
        ERR_raise(ERR_LIB_PROV, PROV_R_IN_ERROR_STATE);
        provider_ctx_free(ctx);
        return RET_OSSL_ERR;
    }

    *out = p11prov_dispatch_table;
    *provctx = ctx;
    return RET_OSSL_OK;
}
