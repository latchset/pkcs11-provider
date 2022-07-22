/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <dlfcn.h>

struct p11prov_ctx {

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

int p11prov_ctx_lock_slots(P11PROV_CTX *ctx, struct p11prov_slot **slots)
{
    if (!ctx->initialized) return RET_OSSL_ERR;

    pthread_mutex_lock(&ctx->lock);

    *slots = ctx->slots;
    return ctx->nslots;
}

void p11prov_ctx_unlock_slots(P11PROV_CTX *ctx, struct p11prov_slot **slots)
{
    if (!ctx->initialized) return;

    *slots = NULL;

    pthread_mutex_unlock(&ctx->lock);
}

OSSL_LIB_CTX *p11prov_ctx_get_libctx(P11PROV_CTX *ctx)
{
    if (!ctx->initialized) return NULL;
    return ctx->libctx;
}

CK_FUNCTION_LIST *p11prov_ctx_fns(P11PROV_CTX *ctx)
{
    if (!ctx->initialized) {
        P11PROV_raise(ctx, CKR_GENERAL_ERROR,
                      "Failed to fetch PKCS#11 Function List");
        return NULL;
    }
    return ctx->fns;
}

static void p11prov_ctx_free(P11PROV_CTX *ctx)
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
    OPENSSL_clear_free(ctx, sizeof(P11PROV_CTX));
}

static void p11prov_teardown(void *ctx)
{
    p11prov_ctx_free((P11PROV_CTX *)ctx);
}

static OSSL_FUNC_core_get_params_fn *core_get_params = NULL;
static OSSL_FUNC_core_new_error_fn *core_new_error = NULL;
static OSSL_FUNC_core_set_error_debug_fn *core_set_error_debug = NULL;
static OSSL_FUNC_core_vset_error_fn *core_vset_error = NULL;

void p11prov_get_core_dispatch_funcs(const OSSL_DISPATCH *in)
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
        default:
            /* Just ignore anything we don't understand */
            continue;
        }
    }
}

void p11prov_raise(P11PROV_CTX *ctx,
                   const char *file, int line, const char *func,
                   int errnum, const char *fmt, ...)
{
    va_list args;

    if (!core_new_error || !core_vset_error) return;

    va_start(args, fmt);
    core_new_error(ctx->handle);
    core_set_error_debug(ctx->handle, file, line, func);
    core_vset_error(ctx->handle, errnum, fmt, args);
    va_end(args);
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
    { P11PROV_NAMES_ECDSA, P11PROV_DEFAULT_PROPERTIES,
      p11prov_ecdsa_keymgmt_functions, P11PROV_DESCS_ECDSA, },
    { P11PROV_NAMES_HKDF, P11PROV_DEFAULT_PROPERTIES,
      p11prov_hkdf_keymgmt_functions, P11PROV_DESCS_HKDF, },
    { "HKDF", P11PROV_DEFAULT_PROPERTIES,
      p11prov_hkdf_keymgmt_functions, P11PROV_DESCS_HKDF, },
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
    { P11PROV_NAMES_ECDSA, P11PROV_DEFAULT_PROPERTIES,
      p11prov_ecdsa_signature_functions, P11PROV_DESCS_ECDSA, },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM p11prov_asym_cipher[] = {
    { P11PROV_NAMES_RSA, P11PROV_DEFAULT_PROPERTIES,
      p11prov_rsa_asym_cipher_functions, P11PROV_DESCS_RSA, },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM p11prov_exchange[] = {
    { P11PROV_NAMES_ECDH, P11PROV_DEFAULT_PROPERTIES,
      p11prov_ecdh_exchange_functions, P11PROV_DESCS_ECDH, },
    { P11PROV_NAMES_HKDF, P11PROV_DEFAULT_PROPERTIES,
      p11prov_hkdf_exchange_functions, P11PROV_DESCS_HKDF, },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM p11prov_kdf[] = {
    { P11PROV_NAMES_HKDF, P11PROV_DEFAULT_PROPERTIES,
      p11prov_hkdf_kdf_functions, P11PROV_DESCS_HKDF, },
    { "HKDF", P11PROV_DEFAULT_PROPERTIES,
      p11prov_hkdf_kdf_functions, P11PROV_DESCS_HKDF, },
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
    case OSSL_OP_ASYM_CIPHER:
        return p11prov_asym_cipher;
    case OSSL_OP_KEYEXCH:
        return p11prov_exchange;
    case OSSL_OP_KDF:
        return p11prov_kdf;
    }
    return NULL;
}

static int p11prov_get_capabilities(void *provctx, const char *capability,
                                    OSSL_CALLBACK *cb, void *arg)
{
    /* TODO: deal with TLS-GROUP */

    return RET_OSSL_ERR;
}

static const OSSL_ITEM *p11prov_get_reason_strings(void *provctx)
{
    static const OSSL_ITEM reason_strings[] = {
        { CKR_HOST_MEMORY, "Host out of memory error" },
        { CKR_SLOT_ID_INVALID, "The specified slot ID is not valid" },
        { CKR_GENERAL_ERROR, "General Error" },
        { CKR_FUNCTION_FAILED,
            "The requested function could not be performed" },
        { CKR_ARGUMENTS_BAD,
            "Invalid or improper arguments were provided to the "
            "invoked function" },
        { CKR_ATTRIBUTE_READ_ONLY,
            "Attempted to set or modify an attribute that is Read "
            "Only for applications" },
        { CKR_ATTRIBUTE_TYPE_INVALID,
            "Invalid attribute type specified in a template" },
        { CKR_ATTRIBUTE_VALUE_INVALID,
            "Invalid value specified for attribute in a template" },
        { CKR_DATA_INVALID,
            "The plaintext input data to a cryptographic "
            "operation is invalid" },
        { CKR_DATA_LEN_RANGE,
            "The size of plaintext input data to a cryptographic "
            "operation is invalid (Out of range)" },
        { CKR_DEVICE_ERROR,
            "Some problem has occurred with the token and/or slot" },
        { CKR_DEVICE_MEMORY,
            "The token does not have sufficient memory to perform "
            "the requested function" },
        { CKR_DEVICE_REMOVED,
            "The token was removed from its slot during the "
            "execution of the function" },
        { CKR_FUNCTION_CANCELED,
            "The function was canceled in mid-execution" },
        { CKR_KEY_HANDLE_INVALID, "The specified key handle is not valid" },
        { CKR_KEY_SIZE_RANGE,
            "Unable to handle the specified key size (Out of range)" },
        { CKR_KEY_TYPE_INCONSISTENT,
            "The specified key is not the correct type of key to "
            "use with the specified mechanism" },
        { CKR_KEY_FUNCTION_NOT_PERMITTED,
            "The key attributes do not allow this operation to be executed" },
        { CKR_MECHANISM_INVALID,
            "An invalid mechanism was specified to the "
            "cryptographic operation" },
        { CKR_MECHANISM_PARAM_INVALID,
            "Invalid mechanism parameters were supplied" },
        { CKR_OPERATION_ACTIVE,
            "There is already an active operation that prevents "
            "executing the requested function" },
        { CKR_OPERATION_NOT_INITIALIZED,
            "There is no active operation of appropriate type "
            "in the specified session" },
        { CKR_PIN_INCORRECT, "The specified PIN is incorrect" },
        { CKR_PIN_EXPIRED, "The specified PIN has expired" },
        { CKR_PIN_LOCKED, "The specified PIN is locked, and cannot be used" },
        { CKR_SESSION_CLOSED, "Session is already closed" },
        { CKR_SESSION_COUNT, "Too many sessions open" },
        { CKR_SESSION_HANDLE_INVALID, "Invalid Session Handle" },
        { CKR_SESSION_PARALLEL_NOT_SUPPORTED,
            "Parallel sessions not supported" },
        { CKR_SESSION_READ_ONLY, "Session is Read Only" },
        { CKR_SESSION_EXISTS, "Session already exists" },
        { CKR_SESSION_READ_ONLY_EXISTS,
            "A read-only session already exists" },
        { CKR_SESSION_READ_WRITE_SO_EXISTS,
            "A read/write SO session already exists" },
        { CKR_TEMPLATE_INCOMPLETE,
            "The template to create an object is incomplete" },
        { CKR_TEMPLATE_INCONSISTENT,
            "The template to create an object has conflicting attributes" },
        { CKR_TOKEN_NOT_PRESENT,
            "The token was not present in its slot when the "
            "function was invoked" },
        { CKR_TOKEN_NOT_RECOGNIZED,
            "The token in the slot is not recognized" },
        { CKR_TOKEN_WRITE_PROTECTED,
            "Action denied because the token is write-protected" },
        { CKR_TOKEN_WRITE_PROTECTED,
            "Can't perform action because the token is write-protected" },
        { CKR_USER_NOT_LOGGED_IN,
            "The desired action cannot be performed because an "
            "appropriate user is not logged in" },
        { CKR_USER_PIN_NOT_INITIALIZED, "The user PIN is not initialized" },
        { CKR_USER_TYPE_INVALID, "An invalid user type was specified" },
        { CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
            "Another user is already logged in" },
        { CKR_USER_TOO_MANY_TYPES,
            "Attempted to log in more users than the token can support" },
        { CKR_OPERATION_CANCEL_FAILED, "The operation cannot be cancelled" },
        { CKR_DOMAIN_PARAMS_INVALID,
            "Invalid or unsupported domain parameters were "
            "supplied to the function" },
        { CKR_CURVE_NOT_SUPPORTED,
            "The specified curve is not supported by this token" },
        { CKR_BUFFER_TOO_SMALL,
            "The output of the function is too large to fit in "
            "the supplied buffer" },
        { CKR_SAVED_STATE_INVALID,
            "The supplied saved cryptographic operations state is invalid" },
        { CKR_STATE_UNSAVEABLE,
            "The cryptographic operations state of the specified "
            "session cannot be saved" },
        { CKR_CRYPTOKI_NOT_INITIALIZED,
            "PKCS11 Module has not been intialized yet" },
        { 0, NULL }
    };

    return reason_strings;
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
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
      (void (*)(void))p11prov_get_reason_strings },
    { 0, NULL }
};

static int refresh_slot_profiles(P11PROV_CTX *ctx, struct p11prov_slot *slot)
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

static int refresh_slots(P11PROV_CTX *ctx)
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

#if !defined(RTLD_DEEPBIND)
#define RTLD_DEEPBIND 0
#endif

static int p11prov_module_init(P11PROV_CTX *ctx)
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
    OSSL_PARAM core_params[3] = { 0 };
    P11PROV_CTX *ctx;
    int ret;

    *provctx = NULL;

    p11prov_get_core_dispatch_funcs(in);

    ctx = OPENSSL_zalloc(sizeof(P11PROV_CTX));
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
    ret = core_get_params(handle, core_params);
    if (ret != RET_OSSL_OK) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        p11prov_ctx_free(ctx);
        return ret;
    }

    ret = p11prov_module_init(ctx);
    if (ret != CKR_OK) {
        ERR_raise(ERR_LIB_PROV, PROV_R_IN_ERROR_STATE);
        p11prov_ctx_free(ctx);
        return RET_OSSL_ERR;
    }

    *out = p11prov_dispatch_table;
    *provctx = ctx;
    return RET_OSSL_OK;
}
