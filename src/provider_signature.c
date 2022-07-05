/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

#include "provider.h"
#include <string.h>
#include "openssl/rsa.h"

DISPATCH_RSASIG_FN(newctx);
DISPATCH_RSASIG_FN(freectx);
DISPATCH_RSASIG_FN(dupctx);
DISPATCH_RSASIG_FN(sign_init);
DISPATCH_RSASIG_FN(sign);
DISPATCH_RSASIG_FN(verify_init);
DISPATCH_RSASIG_FN(verify);
DISPATCH_RSASIG_FN(digest_sign_init);
DISPATCH_RSASIG_FN(digest_sign_update);
DISPATCH_RSASIG_FN(digest_sign_final);
DISPATCH_RSASIG_FN(digest_verify_init);
DISPATCH_RSASIG_FN(digest_verify_update);
DISPATCH_RSASIG_FN(digest_verify_final);
DISPATCH_RSASIG_FN(get_ctx_params);
DISPATCH_RSASIG_FN(set_ctx_params);
DISPATCH_RSASIG_FN(gettable_ctx_params);
DISPATCH_RSASIG_FN(settable_ctx_params);

struct p11prov_rsasig_ctx {
    PROVIDER_CTX *provctx;
    char *properties;

    P11PROV_KEY *priv_key;
    P11PROV_KEY *pub_key;
    bool pss;

    CK_MECHANISM_TYPE mechtype;
    CK_MECHANISM_TYPE digest;

    CK_FLAGS operation;
    CK_SESSION_HANDLE session;
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

    /* PKCS1.5 is the default */
    sigctx->mechtype = CKM_RSA_PKCS;
    sigctx->session = CK_INVALID_HANDLE;

    return sigctx;
}

static void *p11prov_rsasig_dupctx(void *ctx)
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;
    struct p11prov_rsasig_ctx *newctx;
    CK_FUNCTION_LIST *f;
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    CK_BYTE_PTR state = NULL;
    CK_ULONG state_len;
    int ret;

    if (sigctx == NULL) return NULL;

    f = provider_ctx_fns(sigctx->provctx);
    if (f == NULL) return NULL;

    newctx = p11prov_rsasig_newctx(sigctx->provctx, sigctx->properties);
    if (newctx == NULL) return NULL;

    newctx->priv_key = p11prov_key_ref(sigctx->priv_key);
    newctx->pub_key = p11prov_key_ref(sigctx->pub_key);
    newctx->pss = sigctx->pss;
    newctx->mechtype = sigctx->mechtype;
    newctx->digest = sigctx->digest;

    /* This is not really funny. OpenSSL by dfault asume contexts with
     * operations in flight can be easily duplicated, with all the
     * cryptographic status and then both context can keep going
     * independently. We'll try here, but on failure we just 'move' the
     * to the new token and hope for the best */

    switch (sigctx->operation) {
    case 0:
        return newctx;
    case CKF_SIGN:
        slotid = p11prov_key_slotid(sigctx->priv_key);
        handle = p11prov_key_handle(newctx->priv_key);
        break;
    case CKF_VERIFY:
        slotid = p11prov_key_slotid(sigctx->pub_key);
        handle = p11prov_key_handle(newctx->pub_key);
        break;
    default:
        p11prov_rsasig_freectx(newctx);
        return NULL;
    }

    if (slotid != CK_UNAVAILABLE_INFORMATION &&
        handle != CK_INVALID_HANDLE) {

        ret = f->C_GetOperationState(sigctx->session, NULL_PTR, &state_len);
        if (ret != CKR_OK) {
            p11prov_debug("C_GetOperationState failed %d\n", ret);
            goto done;
        }
        state = OPENSSL_malloc(state_len);
        if (state == NULL) {
            goto done;
        }

        ret = f->C_GetOperationState(sigctx->session, state, &state_len);
        if (ret != CKR_OK) {
            p11prov_debug("C_GetOperationState failed %d\n", ret);
            goto done;
        }

        ret = f->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL,
                               &newctx->session);
        if (ret != CKR_OK) {
            p11prov_debug("OpenSession failed %d\n", ret);
            goto done;
        }
        ret = f->C_SetOperationState(newctx->session, state, state_len,
                                     CK_INVALID_HANDLE, handle);
        if (ret != CKR_OK) {
            p11prov_debug("C_GetOperationState failed %d\n", ret);
            (void)f->C_CloseSession(newctx->session);
            newctx->session = CK_INVALID_HANDLE;
        }
    }

done:
    OPENSSL_free(state);

    if (newctx->session == CK_INVALID_HANDLE) {
        newctx->session = sigctx->session;
        sigctx->session = CK_INVALID_HANDLE;
    }
    newctx->operation = sigctx->operation;

    return newctx;
}

static void p11prov_rsasig_freectx(void *ctx)
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;

    if (sigctx == NULL) return;

    if (sigctx->session != CK_INVALID_HANDLE) {
        CK_FUNCTION_LIST *f = provider_ctx_fns(sigctx->provctx);
        if (f) f->C_CloseSession(sigctx->session);
    }

    p11prov_key_free(sigctx->priv_key);
    p11prov_key_free(sigctx->pub_key);
    OPENSSL_free(sigctx->properties);
    OPENSSL_clear_free(sigctx, sizeof(struct p11prov_rsasig_ctx));
}

/* only the ones we can support */
struct {
    const char *name;
    CK_MECHANISM_TYPE digest;
    CK_MECHANISM_TYPE pkcs_mech;
    CK_MECHANISM_TYPE pkcs_pss;
} digest_map[] = {
    { "SHA3-512", CKM_SHA3_512, CKM_SHA3_512_RSA_PKCS, CKM_SHA3_512_RSA_PKCS_PSS },
    { "SHA3-384", CKM_SHA3_384, CKM_SHA3_384_RSA_PKCS, CKM_SHA3_384_RSA_PKCS_PSS },
    { "SHA3-256", CKM_SHA3_256, CKM_SHA3_256_RSA_PKCS, CKM_SHA3_256_RSA_PKCS_PSS },
    { "SHA3-224", CKM_SHA3_224, CKM_SHA3_224_RSA_PKCS, CKM_SHA3_224_RSA_PKCS_PSS },
    { "SHA512", CKM_SHA512, CKM_SHA512_RSA_PKCS, CKM_SHA512_RSA_PKCS_PSS },
    { "SHA384", CKM_SHA384, CKM_SHA384_RSA_PKCS, CKM_SHA384_RSA_PKCS_PSS },
    { "SHA256", CKM_SHA256, CKM_SHA256_RSA_PKCS, CKM_SHA256_RSA_PKCS_PSS },
    { "SHA224", CKM_SHA224, CKM_SHA224_RSA_PKCS, CKM_SHA224_RSA_PKCS_PSS },
    { "SHA1", CKM_SHA_1, CKM_SHA1_RSA_PKCS, CKM_SHA1_RSA_PKCS_PSS },
    { NULL, 0, 0 }
};

static int p11prov_rsasig_set_digest(void *ctx, const char *name)
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;

    for (int i = 0; digest_map[i].name != NULL; i++) {
        /* hate to strcasecmp but openssl forces us to */
        if (strcasecmp(name, digest_map[i].name) == 0) {
            sigctx->digest = digest_map[i].digest;
            return CKR_OK;
        }
    }
    return CKR_DATA_INVALID;
}

static int p11prov_rsasig_get_digest(void *ctx, const char **name)
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;

    for (int i = 0; digest_map[i].name != NULL; i++) {
        if (sigctx->digest == digest_map[i].digest) {
            *name = digest_map[i].name;
            return CKR_OK;
        }
    }
    return CKR_DATA_INVALID;
}

static int p11prov_rsasig_set_mechanism(void *ctx, bool digest_sign,
                                        CK_MECHANISM *mechanism)
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;
    int result;

    /* not supported yet */
    if (sigctx->pss) return CKR_FUNCTION_NOT_SUPPORTED;

    if (!digest_sign || sigctx->digest == 0) {
        mechanism->mechanism = sigctx->mechtype;
        mechanism->pParameter = NULL;
        mechanism->ulParameterLen  = 0;
        result = CKR_OK;
        goto done;
    }

    mechanism->pParameter = NULL;
    mechanism->ulParameterLen  = 0;

    switch (sigctx->mechtype) {
    case CKM_RSA_PKCS:
        for (int i = 0; digest_map[i].name != NULL; i++) {
            if (sigctx->digest == digest_map[i].digest) {
                mechanism->mechanism = digest_map[i].pkcs_mech;
                result = CKR_OK;
                goto done;
            }
        }
        break;
    case CKM_RSA_X_509:
        break;
    case CKM_RSA_X9_31:
        if (sigctx->digest == CKM_SHA_1) {
            mechanism->mechanism = CKM_SHA1_RSA_X9_31;
            result = CKR_OK;
            goto done;
        }
        break;
    case CKM_RSA_PKCS_PSS:
        for (int i = 0; digest_map[i].name != NULL; i++) {
            if (sigctx->digest == digest_map[i].digest) {
                mechanism->mechanism = digest_map[i].pkcs_pss;
                result = CKR_OK;
                goto done;
            }
        }
        break;
    }

    result =  CKR_DATA_INVALID;

done:
    if (result == CKR_OK) {
        p11prov_debug_mechanism(sigctx->provctx,
                                p11prov_key_slotid(sigctx->pub_key),
                                mechanism->mechanism);
    }
    return result;
}

static int p11prov_rsasig_get_siglen(void *ctx, size_t *siglen)
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;
    CK_ATTRIBUTE *modulus;

    modulus = p11prov_key_attr(sigctx->pub_key, CKA_MODULUS);
    if (modulus == NULL) {
        /* try again with private key just in case */
        modulus = p11prov_key_attr(sigctx->priv_key, CKA_MODULUS);
    }
    if (modulus == NULL) return RET_OSSL_ERR;

    *siglen = modulus->ulValueLen;
    return RET_OSSL_OK;
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
    CK_SLOT_ID slotid;
    CK_OBJECT_HANDLE handle;
    CK_ULONG sig_size = sigsize;
    int result = RET_OSSL_ERR;
    int ret;

    p11prov_debug("sign (ctx=%p)\n", ctx);

    if (sig == NULL) {
        return p11prov_rsasig_get_siglen(sigctx, siglen);
    }

    f = provider_ctx_fns(sigctx->provctx);
    if (f == NULL) return RET_OSSL_ERR;
    slotid = p11prov_key_slotid(sigctx->priv_key);
    if (slotid == CK_UNAVAILABLE_INFORMATION) return RET_OSSL_ERR;
    handle = p11prov_key_handle(sigctx->priv_key);
    if (handle == CK_INVALID_HANDLE) return RET_OSSL_ERR;

    ret = p11prov_rsasig_set_mechanism(sigctx, false, &mechanism);
    if (ret != CKR_OK) return RET_OSSL_ERR;

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
    if (handle == CK_INVALID_HANDLE) return RET_OSSL_ERR;

    ret = p11prov_rsasig_set_mechanism(sigctx, false, &mechanism);
    if (ret != CKR_OK) return RET_OSSL_ERR;

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

static int p11prov_rsasig_digest_sign_init(void *ctx,
                                           const char *mdname,
                                           void *provkey,
                                           const OSSL_PARAM params[])
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)provkey;
    int ret;

    p11prov_debug("digest sign init (ctx=%p, mdname=%s, key=%p, params=%p)\n",
                  ctx, mdname, provkey, params);

    if (sigctx == NULL) return RET_OSSL_ERR;

    sigctx->priv_key = p11prov_object_get_key(obj, true);
    if (sigctx->priv_key == NULL) return RET_OSSL_ERR;
    sigctx->pub_key = p11prov_object_get_key(obj, false);

    if (mdname) {
        ret = p11prov_rsasig_set_digest(sigctx, mdname);
        if (ret != CKR_OK) return RET_OSSL_ERR;
    }

    return p11prov_rsasig_set_ctx_params(ctx, params);
}

static int p11prov_rsasig_digest_sign_update(void *ctx,
                                             const unsigned char *data,
                                             size_t datalen)
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;
    CK_FUNCTION_LIST *f;
    int ret;

    p11prov_debug("digest sign update (ctx=%p, data=%p, datalen=%zu)\n",
                  ctx, data, datalen);

    if (sigctx == NULL) return RET_OSSL_ERR;

    f = provider_ctx_fns(sigctx->provctx);
    if (f == NULL) return RET_OSSL_ERR;

    if (sigctx->operation == 0) {
        CK_SLOT_ID slotid = p11prov_key_slotid(sigctx->priv_key);
        CK_OBJECT_HANDLE handle = p11prov_key_handle(sigctx->priv_key);
        CK_MECHANISM mechanism = { 0 };
        if (slotid == CK_UNAVAILABLE_INFORMATION ||
            handle == CK_INVALID_HANDLE) {
            return RET_OSSL_ERR;
        }

        ret = p11prov_rsasig_set_mechanism(sigctx, true, &mechanism);
        if (ret != CKR_OK) return RET_OSSL_ERR;

        ret = f->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL,
                               &sigctx->session);
        if (ret != CKR_OK) {
            p11prov_debug("OpenSession failed %d\n", ret);
            return RET_OSSL_ERR;
        }

        ret = f->C_SignInit(sigctx->session, &mechanism, handle);
        if (ret != CKR_OK) {
            if (ret == CKR_MECHANISM_INVALID ||
                ret == CKR_MECHANISM_PARAM_INVALID) {
                ERR_raise(ERR_LIB_PROV,
                          PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
            }
            p11prov_debug("SignInit failed %d\n", ret);
            (void)f->C_CloseSession(sigctx->session);
            sigctx->session = CK_INVALID_HANDLE;
            return RET_OSSL_ERR;
        }

        sigctx->operation = CKF_SIGN;
    }

    /* we have an initialized session */
    ret = f->C_SignUpdate(sigctx->session, (void *)data, datalen);
    if (ret != CKR_OK) {
        p11prov_debug("SignUpdate failed %d\n", ret);
        (void)f->C_CloseSession(sigctx->session);
        sigctx->session = CK_INVALID_HANDLE;
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_rsasig_digest_sign_final(void *ctx, unsigned char *sig,
                                            size_t *siglen, size_t sigsize)
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;
    CK_ULONG sig_size = sigsize;
    CK_FUNCTION_LIST *f;
    int ret;

    p11prov_debug("digest sign final (ctx=%p, sig=%p, siglen=%zu, "
                  "sigsize=%zu)\n", ctx, sig, *siglen, sigsize);

    if (sigctx == NULL) return RET_OSSL_ERR;
    if (!(sigctx->operation & CKF_SIGN)) return RET_OSSL_ERR;

    if (sig == NULL) {
        return p11prov_rsasig_get_siglen(sigctx, siglen);
    }

    f = provider_ctx_fns(sigctx->provctx);
    if (f == NULL) return RET_OSSL_ERR;

    ret = f->C_SignFinal(sigctx->session, sig, &sig_size);
    if (ret != CKR_OK) {
        p11prov_debug("SignFinal failed %d\n", ret);
    }

    (void)f->C_CloseSession(sigctx->session);
    sigctx->session = CK_INVALID_HANDLE;
    sigctx->operation = 0;

    if (ret == CKR_OK) {
        *siglen = sig_size;
        return RET_OSSL_OK;
    }
    return RET_OSSL_ERR;
}

static int p11prov_rsasig_digest_verify_init(void *ctx,
                                             const char *mdname,
                                             void *provkey,
                                             const OSSL_PARAM params[])
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)provkey;
    int ret;

    p11prov_debug("digest verify init (ctx=%p, mdname=%s, key=%p, "
                  "params=%p)\n", ctx, mdname, provkey, params);

    if (sigctx == NULL) return RET_OSSL_ERR;

    sigctx->pub_key = p11prov_object_get_key(obj, false);
    if (sigctx->pub_key == NULL) return RET_OSSL_ERR;

    if (mdname) {
        ret = p11prov_rsasig_set_digest(sigctx, mdname);
        if (ret != CKR_OK) return RET_OSSL_ERR;
    }

    return p11prov_rsasig_set_ctx_params(ctx, params);
}

static int p11prov_rsasig_digest_verify_update(void *ctx,
                                               const unsigned char *data,
                                               size_t datalen)
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;
    CK_FUNCTION_LIST *f;
    int ret;

    p11prov_debug("digest verify update (ctx=%p, data=%p, datalen=%zu)\n",
                  ctx, data, datalen);

    if (sigctx == NULL) return RET_OSSL_ERR;

    f = provider_ctx_fns(sigctx->provctx);
    if (f == NULL) return RET_OSSL_ERR;

    if (sigctx->operation == 0) {
        CK_SLOT_ID slotid = p11prov_key_slotid(sigctx->pub_key);
        CK_OBJECT_HANDLE handle = p11prov_key_handle(sigctx->pub_key);
        CK_MECHANISM mechanism = { 0 };
        if (slotid == CK_UNAVAILABLE_INFORMATION ||
            handle == CK_INVALID_HANDLE) {
            return RET_OSSL_ERR;
        }

        ret = p11prov_rsasig_set_mechanism(sigctx, true, &mechanism);
        if (ret != CKR_OK) return RET_OSSL_ERR;

        ret = f->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL,
                               &sigctx->session);
        if (ret != CKR_OK) {
            p11prov_debug("OpenSession failed %d\n", ret);
            return RET_OSSL_ERR;
        }

        ret = f->C_VerifyInit(sigctx->session, &mechanism, handle);
        if (ret != CKR_OK) {
            if (ret == CKR_MECHANISM_INVALID ||
                ret == CKR_MECHANISM_PARAM_INVALID) {
                ERR_raise(ERR_LIB_PROV,
                          PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
            }
            p11prov_debug("VerifyInit failed %d\n", ret);
            (void)f->C_CloseSession(sigctx->session);
            sigctx->session = CK_INVALID_HANDLE;
            return RET_OSSL_ERR;
        }

        sigctx->operation = CKF_VERIFY;
    }

    /* we have an initialized session */
    ret = f->C_VerifyUpdate(sigctx->session, (void *)data, datalen);
    if (ret != CKR_OK) {
        p11prov_debug("SignUpdate failed %d\n", ret);
        (void)f->C_CloseSession(sigctx->session);
        sigctx->session = CK_INVALID_HANDLE;
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_rsasig_digest_verify_final(void *ctx, const unsigned char *sig,
                                              size_t siglen)
{
    struct p11prov_rsasig_ctx *sigctx = (struct p11prov_rsasig_ctx *)ctx;
    CK_FUNCTION_LIST *f;
    int ret;

    p11prov_debug("digest verify final (ctx=%p, sig=%p, siglen=%zu)\n",
                  ctx, sig, siglen);

    if (sigctx == NULL || sig == NULL) return RET_OSSL_ERR;
    if (!(sigctx->operation & CKF_VERIFY)) return RET_OSSL_ERR;

    f = provider_ctx_fns(sigctx->provctx);
    if (f == NULL) return RET_OSSL_ERR;

    ret = f->C_VerifyFinal(sigctx->session, (void *)sig, siglen);
    if (ret != CKR_OK) {
        p11prov_debug("VerifyFinal failed %d\n", ret);
    }

    (void)f->C_CloseSession(sigctx->session);
    sigctx->session = CK_INVALID_HANDLE;
    sigctx->operation = 0;

    if (ret == CKR_OK) {
        return RET_OSSL_OK;
    }
    return RET_OSSL_ERR;
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
    if (p) {
        const char *digest_name;
        ret = p11prov_rsasig_get_digest(sigctx, &digest_name);
        if (ret != CKR_OK) {
            ret = OSSL_PARAM_set_utf8_string(p, digest_name);
            if (ret != RET_OSSL_OK) return ret;
        }
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
        char digest_name[256];
        ret = OSSL_PARAM_get_utf8_string(p, (char **)&digest_name, 256);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        ret = p11prov_rsasig_set_digest(sigctx, digest_name);
        if (ret != CKR_OK) return RET_OSSL_ERR;
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
    DISPATCH_RSASIG_ELEM(DUPCTX, dupctx),
    DISPATCH_RSASIG_ELEM(SIGN_INIT, sign_init),
    DISPATCH_RSASIG_ELEM(SIGN, sign),
    DISPATCH_RSASIG_ELEM(VERIFY_INIT, verify_init),
    DISPATCH_RSASIG_ELEM(VERIFY, verify),
    DISPATCH_RSASIG_ELEM(DIGEST_SIGN_INIT, digest_sign_init),
    DISPATCH_RSASIG_ELEM(DIGEST_SIGN_UPDATE, digest_sign_update),
    DISPATCH_RSASIG_ELEM(DIGEST_SIGN_FINAL, digest_sign_final),
    DISPATCH_RSASIG_ELEM(DIGEST_VERIFY_INIT, digest_verify_init),
    DISPATCH_RSASIG_ELEM(DIGEST_VERIFY_UPDATE, digest_verify_update),
    DISPATCH_RSASIG_ELEM(DIGEST_VERIFY_FINAL, digest_verify_final),
    DISPATCH_RSASIG_ELEM(GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_RSASIG_ELEM(GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_RSASIG_ELEM(SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_RSASIG_ELEM(SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL }
};

