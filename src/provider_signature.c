/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

#include "provider.h"
#include <string.h>
#include "openssl/rsa.h"

static OSSL_FUNC_signature_newctx_fn p11prov_sig_newctx;
static OSSL_FUNC_signature_freectx_fn p11prov_sig_freectx;
static OSSL_FUNC_signature_sign_init_fn p11prov_sig_sign_init;
static OSSL_FUNC_signature_sign_fn p11prov_sig_sign;
static OSSL_FUNC_signature_verify_init_fn p11prov_sig_verify_init;
static OSSL_FUNC_signature_verify_fn p11prov_sig_verify;
static OSSL_FUNC_signature_get_ctx_params_fn p11prov_sig_get_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn p11prov_sig_set_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn p11prov_sig_gettable_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn p11prov_sig_settable_ctx_params;

struct p11prov_sig_ctx {
    PROVIDER_CTX *provctx;
    char *properties;

    P11PROV_KEY *key;

    int pad_mode;
};

static void *p11prov_sig_newctx(void *provctx, const char *properties)
{
    PROVIDER_CTX *ctx = (PROVIDER_CTX *)provctx;
    struct p11prov_sig_ctx *sigctx;

    sigctx = OPENSSL_zalloc(sizeof(struct p11prov_sig_ctx));
    if (sigctx == NULL) return NULL;

    sigctx->provctx = ctx;

    if (properties) {
        sigctx->properties = OPENSSL_strdup(properties);
        if (sigctx->properties == NULL) {
            OPENSSL_free(sigctx);
            return NULL;
        }
    }

    return sigctx;
}

static void p11prov_sig_freectx(void *ctx)
{
    struct p11prov_sig_ctx *sigctx = (struct p11prov_sig_ctx *)ctx;

    p11prov_key_free(sigctx->key);
    OPENSSL_free(sigctx->properties);
    OPENSSL_free(sigctx);
}

static int p11prov_sig_sign_init(void *ctx, void *provkey,
                                 const OSSL_PARAM params[])
{
    struct p11prov_sig_ctx *sigctx = (struct p11prov_sig_ctx *)ctx;
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)provkey;

    p11prov_debug("sign init (ctx=%p, key=%p, params=%p)\n",
                  ctx, provkey, params);

    if (!p11prov_object_check_key(obj, true)) return RET_OSSL_ERR;

    sigctx->key = p11prov_object_get_key(obj);

    return p11prov_sig_set_ctx_params(ctx, params);
}

static int p11prov_sig_sign(void *ctx, unsigned char *sig,
                            size_t *siglen, size_t sigsize,
                            const unsigned char *tbs, size_t tbslen)
{
    struct p11prov_sig_ctx *sigctx = (struct p11prov_sig_ctx *)ctx;
    CK_FUNCTION_LIST *f;
    CK_MECHANISM mechanism;
    CK_SESSION_HANDLE session;
    CK_ATTRIBUTE *modulus;
    CK_SLOT_ID slotid;
    CK_OBJECT_HANDLE handle;
    CK_ULONG sig_size = sigsize;
    int result = RET_OSSL_ERR;
    int ret;

    p11prov_debug("sign (ctx=%p)\n", ctx);

    modulus = p11prov_key_attr(sigctx->key, CKA_MODULUS);
    if (modulus == NULL) return RET_OSSL_ERR;

    if (sig == NULL) {
        *siglen = modulus->ulValueLen;
        return RET_OSSL_OK;
    }

    if (sigsize < modulus->ulValueLen) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_SIGNATURE_SIZE,
                       "is %zu, should be at least %lu", sigsize,
                       modulus->ulValueLen);
        return RET_OSSL_ERR;
    }

    f = provider_ctx_fns(sigctx->provctx);
    if (f == NULL) return RET_OSSL_ERR;
    slotid = p11prov_key_slotid(sigctx->key);
    if (slotid == CK_UNAVAILABLE_INFORMATION) return RET_OSSL_ERR;
    handle = p11prov_key_hanlde(sigctx->key);
    if (handle == CK_UNAVAILABLE_INFORMATION) return RET_OSSL_ERR;

    mechanism.mechanism = CKM_RSA_PKCS;
    mechanism.pParameter = NULL;
    mechanism.ulParameterLen  = 0;

    ret = f->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (ret != CKR_OK) {
        p11prov_debug("OpenSession failed %d\n", ret);
        return RET_OSSL_ERR;
    }

    ret = f->C_SignInit(session, &mechanism, handle);
    if (ret != CKR_OK) {
        p11prov_debug("SignInit failed %d\n", ret);
        goto endsess;
    }

    ret = f->C_Sign(session, (void *)tbs, tbslen, sig, &sig_size);
    if (ret != CKR_OK) {
        p11prov_debug("Sign failed %d\n", ret);
        goto endsess;
    }

    *siglen = sig_size;
    result = RET_OSSL_OK;

endsess:
    ret = f->C_CloseSession(session);
    if (ret != CKR_OK) {
        p11prov_debug("Failed to close session (%d)\n", ret);
    }

    return result;
}

static int p11prov_sig_verify_init(void *ctx, void *provkey,
                                   const OSSL_PARAM params[])
{
    struct p11prov_sig_ctx *sigctx = (struct p11prov_sig_ctx *)ctx;
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)provkey;

    p11prov_debug("verify init (ctx=%p, key=%p, params=%p)\n",
                  ctx, provkey, params);

    if (!p11prov_object_check_key(obj, false)) return RET_OSSL_ERR;

    sigctx->key = p11prov_object_get_key(obj);

    return p11prov_sig_set_ctx_params(ctx, params);
}

static int p11prov_sig_verify(void *ctx, const unsigned char *sig,
                              size_t siglen, const unsigned char *tbs,
                              size_t tbslen)
{
    struct p11prov_sig_ctx *sigctx = (struct p11prov_sig_ctx *)ctx;
    CK_FUNCTION_LIST *f;
    CK_MECHANISM mechanism;
    CK_SESSION_HANDLE session;
    CK_SLOT_ID slotid;
    CK_OBJECT_HANDLE handle;
    int result = RET_OSSL_ERR;
    int ret;

    p11prov_debug("verify (ctx=%p)\n", ctx);

    f = provider_ctx_fns(sigctx->provctx);
    if (f == NULL) return RET_OSSL_ERR;
    slotid = p11prov_key_slotid(sigctx->key);
    if (slotid == CK_UNAVAILABLE_INFORMATION) return RET_OSSL_ERR;
    handle = p11prov_key_hanlde(sigctx->key);
    if (handle == CK_UNAVAILABLE_INFORMATION) return RET_OSSL_ERR;

    mechanism.mechanism = CKM_RSA_PKCS;
    mechanism.pParameter = NULL;
    mechanism.ulParameterLen  = 0;

    ret = f->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (ret != CKR_OK) {
        p11prov_debug("OpenSession failed %d\n", ret);
        return RET_OSSL_ERR;
    }

    ret = f->C_VerifyInit(session, &mechanism, handle);
    if (ret != CKR_OK) {
        p11prov_debug("VerifyInit failed %d\n", ret);
        goto endsess;
    }

    ret = f->C_Verify(session, (void *)tbs, tbslen, (void *)sig, siglen);
    if (ret != CKR_OK) {
        p11prov_debug("Verify failed %d\n", ret);
        goto endsess;
    }

    result = RET_OSSL_OK;

endsess:
    ret = f->C_CloseSession(session);
    if (ret != CKR_OK) {
        p11prov_debug("Failed to close session (%d)\n", ret);
    }

    return result;
}

static OSSL_ITEM padding_map[] = {
    { RSA_PKCS1_PADDING,        OSSL_PKEY_RSA_PAD_MODE_PKCSV15 },
    { RSA_NO_PADDING,           OSSL_PKEY_RSA_PAD_MODE_NONE },
    { RSA_X931_PADDING,         OSSL_PKEY_RSA_PAD_MODE_X931 },
    { RSA_PKCS1_PSS_PADDING,    OSSL_PKEY_RSA_PAD_MODE_PSS },
    { 0,                        NULL     }
};

static int p11prov_sig_get_ctx_params(void *vprsactx, OSSL_PARAM *params)
{
    return RET_OSSL_ERR;
}

static int p11prov_sig_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    struct p11prov_sig_ctx *sigctx = (struct p11prov_sig_ctx *)ctx;
    const OSSL_PARAM *p;

    p11prov_debug("sign set ctx params (ctx=%p, params=%p)\n",
                  ctx, params);

    if (params == NULL) return RET_OSSL_OK;

    /* possible sig params:
        OSSL_SIGNATURE_PARAM_ALGORITHM_ID
        OSSL_SIGNATURE_PARAM_PAD_MODE
        OSSL_SIGNATURE_PARAM_DIGEST
        OSSL_SIGNATURE_PARAM_PROPERTIES
        OSSL_SIGNATURE_PARAM_PSS_SALTLEN
        OSSL_SIGNATURE_PARAM_MGF1_DIGEST
        OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES
        OSSL_SIGNATURE_PARAM_DIGEST_SIZE
     */

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p) {
        int pad_mode;

        if (p->data_type == OSSL_PARAM_INTEGER) {
            /* legacy pad mode number */
            if (!OSSL_PARAM_get_int(p, &pad_mode)) return 0;
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            if (p->data == NULL) return 0;
            for (int i = 0; padding_map[i].id != 0; i++) {
                if (strcmp(p->data, padding_map[i].ptr) == 0) {
                    pad_mode = padding_map[i].id;
                    break;
                }
            }
        } else {
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_sig_gettable_ctx_params(void *ctx, void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static const OSSL_PARAM *p11prov_sig_settable_ctx_params(void *ctx, void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        /* TODO: support rsa_padding_mode */
        OSSL_PARAM_END
    };
    return params;
}



const OSSL_DISPATCH p11prov_rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,
        (void (*)(void))p11prov_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX,
        (void (*)(void))p11prov_sig_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,
        (void (*)(void))p11prov_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN,
        (void (*)(void))p11prov_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        (void (*)(void))p11prov_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY,
        (void (*)(void))p11prov_sig_verify },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        (void (*)(void))p11prov_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        (void (*)(void))p11prov_sig_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        (void (*)(void))p11prov_sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        (void (*)(void))p11prov_sig_settable_ctx_params },
    { 0, NULL }
};

