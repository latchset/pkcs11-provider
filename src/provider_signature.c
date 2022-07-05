/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

#include "provider.h"
#include <string.h>
#include "openssl/rsa.h"

DISPATCH_RSASIG_FN(newctx);
DISPATCH_RSASIG_FN(freectx);
DISPATCH_RSASIG_FN(sign_init);
DISPATCH_RSASIG_FN(sign);
DISPATCH_RSASIG_FN(verify_init);
DISPATCH_RSASIG_FN(verify);
DISPATCH_RSASIG_FN(get_ctx_params);
DISPATCH_RSASIG_FN(set_ctx_params);
DISPATCH_RSASIG_FN(gettable_ctx_params);
DISPATCH_RSASIG_FN(settable_ctx_params);

struct p11prov_rsasig_ctx {
    PROVIDER_CTX *provctx;
    char *properties;

    P11PROV_KEY *priv_key;
    P11PROV_KEY *pub_key;

    char *digest_name;

    CK_MECHANISM_TYPE mechtype;
};

static void *p11prov_rsasig_newctx(void *provctx, const char *properties)
{
    PROVIDER_CTX *ctx = (PROVIDER_CTX *)provctx;
    struct p11prov_rsasig_ctx *sigctx;

    sigctx = OPENSSL_zalloc(sizeof(struct p11prov_rsasig_ctx));
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

static void p11prov_rsasig_freectx(void *ctx)
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;

    p11prov_key_free(sigctx->priv_key);
    p11prov_key_free(sigctx->pub_key);
    OPENSSL_free(sigctx->properties);
    OPENSSL_free(sigctx->digest_name);
    OPENSSL_free(sigctx);
}

static int p11prov_rsasig_sign_init(void *ctx, void *provkey,
                                    const OSSL_PARAM params[])
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)provkey;

    p11prov_debug("sign init (ctx=%p, key=%p, params=%p)\n",
                  ctx, provkey, params);

    sigctx->priv_key = p11prov_object_get_key(obj, true);
    if (sigctx->priv_key == NULL) return RET_OSSL_ERR;
    sigctx->pub_key = p11prov_object_get_key(obj, false);

    /* PKCS1.5 is the defautl */
    sigctx->mechtype = CKM_RSA_PKCS;

    return p11prov_rsasig_set_ctx_params(ctx, params);
}

static int p11prov_rsasig_sign(void *ctx, unsigned char *sig,
                               size_t *siglen, size_t sigsize,
                               const unsigned char *tbs, size_t tbslen)
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;
    CK_FUNCTION_LIST *f;
    CK_MECHANISM mechanism;
    CK_SESSION_HANDLE session;
    CK_ATTRIBUTE *modulus;
    CK_SLOT_ID slotid;
    CK_OBJECT_HANDLE handle;
    CK_ULONG sig_size = sigsize;
    P11PROV_KEY *mod_key;
    int result = RET_OSSL_ERR;
    int ret;

    p11prov_debug("sign (ctx=%p)\n", ctx);

    if (sigctx->pub_key) mod_key = sigctx->pub_key;
    else mod_key = sigctx->priv_key;

    modulus = p11prov_key_attr(mod_key, CKA_MODULUS);
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
    slotid = p11prov_key_slotid(sigctx->priv_key);
    if (slotid == CK_UNAVAILABLE_INFORMATION) return RET_OSSL_ERR;
    handle = p11prov_key_handle(sigctx->priv_key);
    if (handle == CK_UNAVAILABLE_INFORMATION) return RET_OSSL_ERR;

    mechanism.mechanism = sigctx->mechtype;
    mechanism.pParameter = NULL;
    mechanism.ulParameterLen  = 0;

    ret = f->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (ret != CKR_OK) {
        p11prov_debug("OpenSession failed %d\n", ret);
        return RET_OSSL_ERR;
    }

    ret = f->C_SignInit(session, &mechanism, handle);
    if (ret != CKR_OK) {
        if (ret == CKR_MECHANISM_INVALID ||
            ret == CKR_MECHANISM_PARAM_INVALID) {
            ERR_raise(ERR_LIB_PROV,
                      PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
        }
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

static int p11prov_rsasig_verify_init(void *ctx, void *provkey,
                                      const OSSL_PARAM params[])
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)provkey;

    p11prov_debug("verify init (ctx=%p, key=%p, params=%p)\n",
                  ctx, provkey, params);

    sigctx->pub_key = p11prov_object_get_key(obj, false);
    if (sigctx->pub_key == NULL) return RET_OSSL_ERR;

    /* PKCS1.5 is the defautl */
    sigctx->mechtype = CKM_RSA_PKCS;

    return p11prov_rsasig_set_ctx_params(ctx, params);
}

static int p11prov_rsasig_verify(void *ctx, const unsigned char *sig,
                                 size_t siglen, const unsigned char *tbs,
                                 size_t tbslen)
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;
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
    slotid = p11prov_key_slotid(sigctx->pub_key);
    if (slotid == CK_UNAVAILABLE_INFORMATION) return RET_OSSL_ERR;
    handle = p11prov_key_handle(sigctx->pub_key);
    if (handle == CK_UNAVAILABLE_INFORMATION) return RET_OSSL_ERR;

    mechanism.mechanism = sigctx->mechtype;
    mechanism.pParameter = NULL;
    mechanism.ulParameterLen  = 0;

    ret = f->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (ret != CKR_OK) {
        p11prov_debug("OpenSession failed %d\n", ret);
        return RET_OSSL_ERR;
    }

    ret = f->C_VerifyInit(session, &mechanism, handle);
    if (ret != CKR_OK) {
        if (ret == CKR_MECHANISM_INVALID ||
            ret == CKR_MECHANISM_PARAM_INVALID) {
            ERR_raise(ERR_LIB_PROV,
                      PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
        }
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

static struct {
    CK_MECHANISM_TYPE type;
    unsigned int ossl_id;
    const char *string;
} padding_map[] = {
    { CKM_RSA_X_509, RSA_NO_PADDING, OSSL_PKEY_RSA_PAD_MODE_NONE },
    { CKM_RSA_PKCS, RSA_PKCS1_PADDING, OSSL_PKEY_RSA_PAD_MODE_PKCSV15 },
    { CKM_RSA_PKCS_OAEP, RSA_PKCS1_OAEP_PADDING, OSSL_PKEY_RSA_PAD_MODE_OAEP },
    { CKM_RSA_X9_31, RSA_X931_PADDING, OSSL_PKEY_RSA_PAD_MODE_X931 },
    { CKM_RSA_PKCS_PSS, RSA_PKCS1_PSS_PADDING, OSSL_PKEY_RSA_PAD_MODE_PSS },
    { CK_UNAVAILABLE_INFORMATION, 0, NULL }
};

static int p11prov_rsasig_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;
    OSSL_PARAM *p;
    int ret;

    p11prov_debug("sign get ctx params (ctx=%p, params=%p)\n",
                  ctx, params);

    if (params == NULL) return RET_OSSL_OK;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p) {
        ret = RET_OSSL_ERR;
        for (int i = 0; padding_map[i].string != NULL; i++) {
            if (padding_map[i].type == sigctx->mechtype) {
                switch (p->data_type) {
                case OSSL_PARAM_INTEGER:
                    ret = OSSL_PARAM_set_int(p, padding_map[i].ossl_id);
                    break;
                case OSSL_PARAM_UTF8_STRING:
                    ret = OSSL_PARAM_set_utf8_string(p, padding_map[i].string);
                    break;
                }
                break;
            }
        }
        if (ret != RET_OSSL_OK) return ret;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p && sigctx->digest_name) {
        ret = OSSL_PARAM_set_utf8_string(p, sigctx->digest_name);
        if (ret != RET_OSSL_OK) return ret;
    }

    return RET_OSSL_OK;
}

static int p11prov_rsasig_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;
    const OSSL_PARAM *p;
    int ret;

    p11prov_debug("sign set ctx params (ctx=%p, params=%p)\n",
                  ctx, params);

    if (params == NULL) return RET_OSSL_OK;

    /* possible sig params:
        OSSL_SIGNATURE_PARAM_ALGORITHM_ID
        OSSL_SIGNATURE_PARAM_PROPERTIES
        OSSL_SIGNATURE_PARAM_PSS_SALTLEN
        OSSL_SIGNATURE_PARAM_MGF1_DIGEST
        OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES
        OSSL_SIGNATURE_PARAM_DIGEST_SIZE
     */

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p) {
        ret = OSSL_PARAM_get_utf8_string(p, &sigctx->digest_name, 0);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p) {
        CK_MECHANISM_TYPE mechtype = CK_UNAVAILABLE_INFORMATION;
        if (p->data_type == OSSL_PARAM_INTEGER) {
            int pad_mode;
            /* legacy pad mode number */
            ret = OSSL_PARAM_get_int(p, &pad_mode);
            if (ret != RET_OSSL_OK) return ret;
            for (int i = 0; padding_map[i].string != NULL; i++) {
                if (padding_map[i].ossl_id == pad_mode) {
                    mechtype = padding_map[i].type;
                    break;
                }
            }
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            if (p->data) {
                for (int i = 0; padding_map[i].string != NULL; i++) {
                    if (strcmp(p->data, padding_map[i].string) == 0) {
                        mechtype = padding_map[i].type;
                        break;
                    }
                }
            }
        } else {
            return RET_OSSL_ERR;
        }
        if (mechtype == CK_UNAVAILABLE_INFORMATION) {
            ERR_raise(ERR_LIB_PROV,
                      PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
            return RET_OSSL_ERR;
        }
        sigctx->mechtype = mechtype;

        p11prov_debug_mechanism(sigctx->provctx,
                                p11prov_key_slotid(sigctx->pub_key),
                                sigctx->mechtype);
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_rsasig_gettable_ctx_params(void *ctx,
                                                            void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static const OSSL_PARAM *p11prov_rsasig_settable_ctx_params(void *ctx,
                                                            void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        /* TODO: support rsa_padding_mode */
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

const OSSL_DISPATCH p11prov_rsa_signature_functions[] = {
    DISPATCH_RSASIG_ELEM(NEWCTX, newctx),
    DISPATCH_RSASIG_ELEM(FREECTX, freectx),
    DISPATCH_RSASIG_ELEM(SIGN_INIT, sign_init),
    DISPATCH_RSASIG_ELEM(SIGN, sign),
    DISPATCH_RSASIG_ELEM(VERIFY_INIT, verify_init),
    DISPATCH_RSASIG_ELEM(VERIFY, verify),
    DISPATCH_RSASIG_ELEM(GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_RSASIG_ELEM(GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_RSASIG_ELEM(SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_RSASIG_ELEM(SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL }
};

