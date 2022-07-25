/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>
#include "openssl/rsa.h"
#include "openssl/sha.h"

struct p11prov_sig_ctx {
    P11PROV_CTX *provctx;
    char *properties;

    P11PROV_KEY *priv_key;
    P11PROV_KEY *pub_key;

    CK_MECHANISM_TYPE mechtype;
    CK_MECHANISM_TYPE digest;

    CK_FLAGS operation;
    CK_SESSION_HANDLE session;

    CK_RSA_PKCS_PSS_PARAMS pss_params;
};
typedef struct p11prov_sig_ctx P11PROV_SIG_CTX;

DISPATCH_SIG_FN(freectx);
DISPATCH_SIG_FN(dupctx);

static P11PROV_SIG_CTX *p11prov_sig_newctx(P11PROV_CTX *ctx,
                                           CK_MECHANISM_TYPE type,
                                           const char *properties)
{
    P11PROV_SIG_CTX *sigctx;

    sigctx = OPENSSL_zalloc(sizeof(P11PROV_SIG_CTX));
    if (sigctx == NULL) {
        return NULL;
    }

    sigctx->provctx = ctx;

    if (properties) {
        sigctx->properties = OPENSSL_strdup(properties);
        if (sigctx->properties == NULL) {
            OPENSSL_free(sigctx);
            return NULL;
        }
    }

    sigctx->mechtype = type;
    sigctx->session = CK_INVALID_HANDLE;

    return sigctx;
}

static void *p11prov_sig_dupctx(void *ctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    P11PROV_SIG_CTX *newctx;
    CK_FUNCTION_LIST *f;
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    CK_BYTE_PTR state = NULL;
    CK_ULONG state_len;
    int ret;

    if (sigctx == NULL) {
        return NULL;
    }

    f = p11prov_ctx_fns(sigctx->provctx);
    if (f == NULL) {
        return NULL;
    }

    newctx = p11prov_sig_newctx(sigctx->provctx, sigctx->mechtype,
                                sigctx->properties);
    if (newctx == NULL) {
        return NULL;
    }

    newctx->priv_key = p11prov_key_ref(sigctx->priv_key);
    newctx->pub_key = p11prov_key_ref(sigctx->pub_key);
    newctx->mechtype = sigctx->mechtype;
    newctx->digest = sigctx->digest;
    newctx->pss_params = sigctx->pss_params;

    if (sigctx->session == CK_INVALID_HANDLE) {
        goto done;
    }

    /* This is not really funny. OpenSSL by dfault asume contexts with
     * operations in flight can be easily duplicated, with all the
     * cryptographic status and then both context can keep going
     * independently. We'll try here, but on failure we just 'move' the
     * to the new token and hope for the best */

    newctx->session = sigctx->session;
    sigctx->session = CK_INVALID_HANDLE;

    switch (sigctx->operation) {
    case CKF_SIGN:
        slotid = p11prov_key_slotid(sigctx->priv_key);
        handle = p11prov_key_handle(newctx->priv_key);
        break;
    case CKF_VERIFY:
        slotid = p11prov_key_slotid(sigctx->pub_key);
        handle = p11prov_key_handle(newctx->pub_key);
        break;
    default:
        p11prov_sig_freectx(newctx);
        return NULL;
    }

    if (slotid != CK_UNAVAILABLE_INFORMATION && handle != CK_INVALID_HANDLE) {

        ret = f->C_GetOperationState(newctx->session, NULL_PTR, &state_len);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret,
                          "Error returned by C_GetOperationState");
            goto done;
        }
        state = OPENSSL_malloc(state_len);
        if (state == NULL) {
            goto done;
        }

        ret = f->C_GetOperationState(newctx->session, state, &state_len);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret,
                          "Error returned by C_GetOperationState");
            goto done;
        }

        ret = f->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL,
                               &sigctx->session);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret,
                          "Failed to open session on slot %lu", slotid);
            goto done;
        }
        ret = f->C_SetOperationState(sigctx->session, state, state_len,
                                     CK_INVALID_HANDLE, handle);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret,
                          "Error returned by C_SetOperationState");
            ret = f->C_CloseSession(sigctx->session);
            if (ret != CKR_OK) {
                P11PROV_raise(sigctx->provctx, ret,
                              "Failed to close session %lu", sigctx->session);
            }
            sigctx->session = CK_INVALID_HANDLE;
        }
    }

done:
    OPENSSL_free(state);
    newctx->operation = sigctx->operation;
    return newctx;
}

static void p11prov_sig_freectx(void *ctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    if (sigctx == NULL) {
        return;
    }

    if (sigctx->session != CK_INVALID_HANDLE) {
        CK_FUNCTION_LIST *f = p11prov_ctx_fns(sigctx->provctx);
        if (f) {
            f->C_CloseSession(sigctx->session);
        }
    }

    p11prov_key_free(sigctx->priv_key);
    p11prov_key_free(sigctx->pub_key);
    OPENSSL_free(sigctx->properties);
    OPENSSL_clear_free(sigctx, sizeof(P11PROV_SIG_CTX));
}

#define DM_ELEM_SHA(bits) \
    { \
        .name = "SHA" #bits, .digest = CKM_SHA##bits, \
        .pkcs_mech = CKM_SHA##bits##_RSA_PKCS, \
        .pkcs_pss = CKM_SHA##bits##_RSA_PKCS_PSS, \
        .ecdsa_mech = CKM_ECDSA_SHA##bits, .mgf = CKG_MGF1_SHA##bits, \
        .digest_size = bits / 8 \
    }
#define DM_ELEM_SHA3(bits) \
    { \
        .name = "SHA3-" #bits, .digest = CKM_SHA3_##bits, \
        .pkcs_mech = CKM_SHA3_##bits##_RSA_PKCS, \
        .pkcs_pss = CKM_SHA3_##bits##_RSA_PKCS_PSS, \
        .ecdsa_mech = CKM_ECDSA_SHA3_##bits, .mgf = CKG_MGF1_SHA3_##bits, \
        .digest_size = bits / 8 \
    }
/* only the ones we can support */
static struct {
    const char *name;
    CK_MECHANISM_TYPE digest;
    CK_MECHANISM_TYPE pkcs_mech;
    CK_MECHANISM_TYPE pkcs_pss;
    CK_MECHANISM_TYPE ecdsa_mech;
    CK_RSA_PKCS_MGF_TYPE mgf;
    int digest_size;
} digest_map[] = {
    DM_ELEM_SHA3(256),
    DM_ELEM_SHA3(512),
    DM_ELEM_SHA3(384),
    DM_ELEM_SHA3(224),
    DM_ELEM_SHA(256),
    DM_ELEM_SHA(512),
    DM_ELEM_SHA(384),
    DM_ELEM_SHA(224),
    { "SHA1", CKM_SHA_1, CKM_SHA1_RSA_PKCS, CKM_SHA1_RSA_PKCS_PSS,
      CKM_ECDSA_SHA1, CKG_MGF1_SHA1, 20 },
    { NULL, 0, 0, 0, 0, 0, 0 },
};

static const char *p11prov_sig_digest_name(CK_MECHANISM_TYPE digest)
{
    for (int i = 0; digest_map[i].name != NULL; i++) {
        if (digest_map[i].digest == digest) {
            return digest_map[i].name;
        }
    }
    return "";
}

static const char *p11prov_sig_mgf_name(CK_RSA_PKCS_MGF_TYPE mgf)
{
    for (int i = 0; digest_map[i].name != NULL; i++) {
        if (digest_map[i].mgf == mgf) {
            return digest_map[i].name;
        }
    }
    return "";
}

static CK_RSA_PKCS_MGF_TYPE p11prov_sig_map_mgf(const char *digest)
{
    for (int i = 0; digest_map[i].name != NULL; i++) {
        /* hate to strcasecmp but openssl forces us to */
        if (strcasecmp(digest, digest_map[i].name) == 0) {
            return digest_map[i].mgf;
        }
    }
    return CK_UNAVAILABLE_INFORMATION;
}

static CK_MECHANISM_TYPE p11prov_sig_map_digest(const char *digest)
{
    for (int i = 0; digest_map[i].name != NULL; i++) {
        /* hate to strcasecmp but openssl forces us to */
        if (strcasecmp(digest, digest_map[i].name) == 0) {
            return digest_map[i].digest;
        }
    }
    return CK_UNAVAILABLE_INFORMATION;
}

static int p11prov_sig_set_mechanism(void *ctx, bool digest_sign,
                                     CK_MECHANISM *mechanism)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    int result = CKR_DATA_INVALID;

    mechanism->mechanism = sigctx->mechtype;
    mechanism->pParameter = NULL;
    mechanism->ulParameterLen = 0;

    if (sigctx->mechtype == CKM_RSA_PKCS_PSS) {
        mechanism->pParameter = &sigctx->pss_params;
        mechanism->ulParameterLen = sizeof(sigctx->pss_params);
        if (sigctx->digest) {
            sigctx->pss_params.hashAlg = sigctx->digest;
        }
    }

    if (!digest_sign) {
        return CKR_OK;
    }

    switch (sigctx->mechtype) {
    case CKM_RSA_PKCS:
        for (int i = 0; digest_map[i].name != NULL; i++) {
            if (sigctx->digest == digest_map[i].digest) {
                mechanism->mechanism = digest_map[i].pkcs_mech;
                result = CKR_OK;
                break;
            }
        }
        break;
    case CKM_RSA_X_509:
        break;
    case CKM_RSA_PKCS_PSS:
        mechanism->pParameter = &sigctx->pss_params;
        mechanism->ulParameterLen = sizeof(sigctx->pss_params);
        for (int i = 0; digest_map[i].name != NULL; i++) {
            if (sigctx->digest == digest_map[i].digest) {
                mechanism->mechanism = digest_map[i].pkcs_pss;
                result = CKR_OK;
                break;
            }
        }
        break;
    case CKM_ECDSA:
        for (int i = 0; digest_map[i].name != NULL; i++) {
            if (sigctx->digest == digest_map[i].digest) {
                mechanism->mechanism = digest_map[i].ecdsa_mech;
                result = CKR_OK;
                break;
            }
        }
        break;
    }

    if (result == CKR_OK) {
        p11prov_debug_mechanism(sigctx->provctx,
                                p11prov_key_slotid(sigctx->pub_key),
                                mechanism->mechanism);
    }
    return result;
}

#define ANYKEY(ctx) (ctx->pub_key ? ctx->pub_key : ctx->priv_key)

static int p11prov_sig_get_sig_size(void *ctx, size_t *siglen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_KEY_TYPE type = p11prov_key_type(ANYKEY(sigctx));
    CK_ULONG size = p11prov_key_size(ANYKEY(sigctx));

    if (type == CK_UNAVAILABLE_INFORMATION) {
        return RET_OSSL_ERR;
    }
    if (size == CK_UNAVAILABLE_INFORMATION) {
        return RET_OSSL_ERR;
    }

    switch (type) {
    case CKK_RSA:
        *siglen = size;
        break;
    case CKK_EC:
        *siglen = size * 2;
        break;
    default:
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_rsasig_set_pss_saltlen_from_digest(void *ctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    if (sigctx->digest == 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "Can only be set if Digest was set first.");
        return RET_OSSL_ERR;
    }
    for (int i = 0; digest_map[i].name != NULL; i++) {
        if (sigctx->digest == digest_map[i].digest) {
            sigctx->pss_params.sLen = digest_map[i].digest_size;
            return RET_OSSL_OK;
        }
    }
    return RET_OSSL_ERR;
}

static int p11prov_sig_op_init(void *ctx, void *provkey, CK_FLAGS operation,
                               const char *digest, const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)provkey;

    sigctx->priv_key = p11prov_object_get_key(obj, true);
    if (sigctx->priv_key == NULL) {
        return RET_OSSL_ERR;
    }
    sigctx->pub_key = p11prov_object_get_key(obj, false);

    sigctx->operation = operation;

    if (digest) {
        sigctx->digest = p11prov_sig_map_digest(digest);
        if (sigctx->digest == CK_UNAVAILABLE_INFORMATION) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_OK;
}

static int p11prov_sig_operate_init(P11PROV_SIG_CTX *sigctx, bool digest_op,
                                    CK_SESSION_HANDLE *_session)
{
    CK_FUNCTION_LIST *f;
    CK_MECHANISM mechanism;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE handle;
    CK_SLOT_ID slotid;
    P11PROV_KEY *key;
    int ret;

    f = p11prov_ctx_fns(sigctx->provctx);
    if (f == NULL) {
        return CKR_GENERAL_ERROR;
    }

    switch (sigctx->operation) {
    case CKF_SIGN:
        key = sigctx->priv_key;
        break;
    case CKF_VERIFY:
        key = sigctx->pub_key;
        break;
    default:
        return CKR_FUNCTION_REJECTED;
    }

    handle = p11prov_key_handle(key);
    if (handle == CK_INVALID_HANDLE) {
        P11PROV_raise(sigctx->provctx, CKR_KEY_HANDLE_INVALID,
                      "Provided key has invalid handle");
        return CKR_KEY_HANDLE_INVALID;
    }
    slotid = p11prov_key_slotid(key);
    if (slotid == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(sigctx->provctx, CKR_SLOT_ID_INVALID,
                      "Provided key has invalid slot");
        return CKR_SLOT_ID_INVALID;
    }

    ret = p11prov_sig_set_mechanism(sigctx, digest_op, &mechanism);
    if (ret != CKR_OK) {
        return ret;
    }

    ret = f->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (ret != CKR_OK) {
        P11PROV_raise(sigctx->provctx, ret,
                      "Failed to open session on slot %lu", slotid);
        return ret;
    }

    if (sigctx->operation == CKF_SIGN) {
        ret = f->C_SignInit(session, &mechanism, handle);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret, "Error returned by C_SignInit");
        }
    } else {
        ret = f->C_VerifyInit(session, &mechanism, handle);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret,
                          "Error returned by C_VerifyInit");
        }
    }
    if (ret != CKR_OK) {
        int result = ret;
        if (ret == CKR_MECHANISM_INVALID
            || ret == CKR_MECHANISM_PARAM_INVALID) {
            ERR_raise(ERR_LIB_PROV, PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
        }
        ret = f->C_CloseSession(session);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret, "Failed to close session %lu",
                          session);
        }
        return result;
    }

    *_session = session;
    return CKR_OK;
}

static int p11prov_sig_operate(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                               size_t *siglen, size_t sigsize,
                               unsigned char *tbs, size_t tbslen)
{
    CK_FUNCTION_LIST *f;
    CK_SESSION_HANDLE session;
    CK_ULONG sig_size = sigsize;
    int result = RET_OSSL_ERR;
    int ret;

    if (sig == NULL) {
        if (sigctx->operation == CKF_VERIFY) {
            return RET_OSSL_ERR;
        }
        return p11prov_sig_get_sig_size(sigctx, siglen);
    }

    if (sigctx->operation == CKF_SIGN && sigctx->mechtype == CKM_RSA_X_509) {
        /* some tokens allow raw signatures on any data size.
         * Enforce data size is the same as modulus as that is
         * what OpenSSL expects and does internally in rsa_sign
         * when there is no padding. */
        if (tbslen < sigsize) {
            ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE);
            return RET_OSSL_ERR;
        }
    }

    ret = p11prov_sig_operate_init(sigctx, false, &session);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    f = p11prov_ctx_fns(sigctx->provctx);
    if (f == NULL) {
        return RET_OSSL_ERR;
    }

    if (sigctx->operation == CKF_SIGN) {
        ret = f->C_Sign(session, tbs, tbslen, sig, &sig_size);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret, "Error returned by C_Sign");
        }
    } else {
        ret = f->C_Verify(session, tbs, tbslen, sig, sigsize);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret, "Error returned by C_Verify");
        }
    }
    if (ret != CKR_OK) {
        goto endsess;
    }

    if (siglen) {
        *siglen = sig_size;
    }
    result = RET_OSSL_OK;

endsess:
    ret = f->C_CloseSession(session);
    if (ret != CKR_OK) {
        P11PROV_raise(sigctx->provctx, ret, "Failed to close session %lu",
                      session);
    }

    return result;
}

static int p11prov_sig_digest_update(P11PROV_SIG_CTX *sigctx,
                                     unsigned char *data, size_t datalen)
{
    CK_FUNCTION_LIST *f;
    int ret;

    f = p11prov_ctx_fns(sigctx->provctx);
    if (f == NULL) {
        return RET_OSSL_ERR;
    }

    if (sigctx->session == CK_INVALID_HANDLE) {
        ret = p11prov_sig_operate_init(sigctx, true, &sigctx->session);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    /* we have an initialized session */
    if (sigctx->operation == CKF_SIGN) {
        ret = f->C_SignUpdate(sigctx->session, data, datalen);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret,
                          "Error returned by C_SignUpdate");
        }
    } else {
        ret = f->C_VerifyUpdate(sigctx->session, data, datalen);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret,
                          "Error returned by C_VerifyUpdate");
        }
    }
    if (ret != CKR_OK) {
        ret = f->C_CloseSession(sigctx->session);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret, "Failed to close session %lu",
                          sigctx->session);
        }
        sigctx->session = CK_INVALID_HANDLE;
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_sig_digest_final(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                                    size_t *siglen, size_t sigsize)
{
    CK_ULONG sig_size = sigsize;
    CK_FUNCTION_LIST *f;
    int result = RET_OSSL_ERR;
    int ret;

    if (sigctx->session == CK_INVALID_HANDLE) {
        return RET_OSSL_ERR;
    }

    if (sig == NULL) {
        if (sigctx->operation == CKF_VERIFY) {
            return RET_OSSL_ERR;
        }
        return p11prov_sig_get_sig_size(sigctx, siglen);
    }

    f = p11prov_ctx_fns(sigctx->provctx);
    if (f == NULL) {
        return RET_OSSL_ERR;
    }

    if (sigctx->operation == CKF_SIGN) {
        ret = f->C_SignFinal(sigctx->session, sig, &sig_size);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret,
                          "Error returned by C_SignFinal");
        }
    } else {
        ret = f->C_VerifyFinal(sigctx->session, sig, sigsize);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret,
                          "Error returned by C_VerifyFinal");
        }
    }

    if (ret == CKR_OK) {
        if (siglen) {
            *siglen = sig_size;
        }
        result = RET_OSSL_OK;
    }

    ret = f->C_CloseSession(sigctx->session);
    if (ret != CKR_OK) {
        P11PROV_raise(sigctx->provctx, ret, "Failed to close session %lu",
                      sigctx->session);
    }
    sigctx->session = CK_INVALID_HANDLE;

    return result;
}

DISPATCH_RSASIG_FN(newctx);
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

static void *p11prov_rsasig_newctx(void *provctx, const char *properties)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_SIG_CTX *sigctx;

    /* PKCS1.5 is the default, PSS set via padding params */
    sigctx = p11prov_sig_newctx(ctx, CKM_RSA_PKCS, properties);
    if (sigctx == NULL) {
        return NULL;
    }

    /* default PSS Params */
    sigctx->pss_params.hashAlg = CKM_SHA_1;
    sigctx->pss_params.mgf = CKG_MGF1_SHA1;
    sigctx->pss_params.sLen = 20;

    return sigctx;
}

static int p11prov_rsasig_sign_init(void *ctx, void *provkey,
                                    const OSSL_PARAM params[])
{
    int ret;

    p11prov_debug("rsa sign init (ctx=%p, key=%p, params=%p)\n", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, NULL, params);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    return p11prov_rsasig_set_ctx_params(ctx, params);
}

static int p11prov_rsasig_sign(void *ctx, unsigned char *sig, size_t *siglen,
                               size_t sigsize, const unsigned char *tbs,
                               size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    p11prov_debug("rsa sign (ctx=%p)\n", ctx);

    return p11prov_sig_operate(sigctx, sig, siglen, sigsize, (void *)tbs,
                               tbslen);
}

static int p11prov_rsasig_verify_init(void *ctx, void *provkey,
                                      const OSSL_PARAM params[])
{
    int ret;

    p11prov_debug("rsa verify init (ctx=%p, key=%p, params=%p)\n", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, NULL, params);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    return p11prov_rsasig_set_ctx_params(ctx, params);
}

static int p11prov_rsasig_verify(void *ctx, const unsigned char *sig,
                                 size_t siglen, const unsigned char *tbs,
                                 size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    p11prov_debug("rsa verify (ctx=%p)\n", ctx);

    return p11prov_sig_operate(sigctx, (void *)sig, NULL, siglen, (void *)tbs,
                               tbslen);
}

static int p11prov_rsasig_digest_sign_init(void *ctx, const char *digest,
                                           void *provkey,
                                           const OSSL_PARAM params[])
{
    int ret;

    p11prov_debug("rsa digest sign init (ctx=%p, key=%p, params=%p)\n", ctx,
                  provkey, params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, digest, params);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    return p11prov_rsasig_set_ctx_params(ctx, params);
}

static int p11prov_rsasig_digest_sign_update(void *ctx,
                                             const unsigned char *data,
                                             size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    p11prov_debug("rsa digest sign update (ctx=%p, data=%p, datalen=%zu)\n",
                  ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_rsasig_digest_sign_final(void *ctx, unsigned char *sig,
                                            size_t *siglen, size_t sigsize)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    p11prov_debug(
        "rsa digest sign final (ctx=%p, sig=%p, siglen=%zu, "
        "sigsize=%zu)\n",
        ctx, sig, *siglen, sigsize);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_final(sigctx, sig, siglen, sigsize);
}

static int p11prov_rsasig_digest_verify_init(void *ctx, const char *digest,
                                             void *provkey,
                                             const OSSL_PARAM params[])
{
    int ret;

    p11prov_debug("rsa digest verify init (ctx=%p, key=%p, params=%p)\n", ctx,
                  provkey, params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, digest, params);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    return p11prov_rsasig_set_ctx_params(ctx, params);
}

static int p11prov_rsasig_digest_verify_update(void *ctx,
                                               const unsigned char *data,
                                               size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    p11prov_debug("rsa digest verify update (ctx=%p, data=%p, datalen=%zu)\n",
                  ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_rsasig_digest_verify_final(void *ctx,
                                              const unsigned char *sig,
                                              size_t siglen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    p11prov_debug("rsa digest verify final (ctx=%p, sig=%p, siglen=%zu)\n", ctx,
                  sig, siglen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_final(sigctx, (void *)sig, NULL, siglen);
}

static struct {
    CK_MECHANISM_TYPE type;
    unsigned int ossl_id;
    const char *string;
} padding_map[] = {
    { CKM_RSA_X_509, RSA_NO_PADDING, OSSL_PKEY_RSA_PAD_MODE_NONE },
    { CKM_RSA_PKCS, RSA_PKCS1_PADDING, OSSL_PKEY_RSA_PAD_MODE_PKCSV15 },
    { CKM_RSA_X9_31, RSA_X931_PADDING, OSSL_PKEY_RSA_PAD_MODE_X931 },
    { CKM_RSA_PKCS_PSS, RSA_PKCS1_PSS_PADDING, OSSL_PKEY_RSA_PAD_MODE_PSS },
    { CK_UNAVAILABLE_INFORMATION, 0, NULL },
};

static int p11prov_rsasig_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    OSSL_PARAM *p;
    int ret;

    /* todo sig params:
        OSSL_SIGNATURE_PARAM_ALGORITHM_ID
     */

    p11prov_debug("rsasig get ctx params (ctx=%p, params=%p)\n", ctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p) {
        const char *digest = p11prov_sig_digest_name(sigctx->digest);
        ret = OSSL_PARAM_set_utf8_string(p, digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

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
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p) {
        const char *digest = p11prov_sig_mgf_name(sigctx->pss_params.mgf);
        ret = OSSL_PARAM_set_utf8_string(p, digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

static int p11prov_rsasig_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    p11prov_debug("rsasig set ctx params (ctx=%p, params=%p)\n", sigctx,
                  params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p) {
        char digest[256];
        char *ptr = digest;
        ret = OSSL_PARAM_get_utf8_string(p, &ptr, 256);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        sigctx->digest = p11prov_sig_map_digest(digest);
        if (sigctx->digest == CK_UNAVAILABLE_INFORMATION) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p) {
        CK_MECHANISM_TYPE mechtype = CK_UNAVAILABLE_INFORMATION;
        if (p->data_type == OSSL_PARAM_INTEGER) {
            int pad_mode;
            /* legacy pad mode number */
            ret = OSSL_PARAM_get_int(p, &pad_mode);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
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
            ERR_raise(ERR_LIB_PROV, PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
            return RET_OSSL_ERR;
        }
        sigctx->mechtype = mechtype;

        p11prov_debug_mechanism(sigctx->provctx,
                                p11prov_key_slotid(sigctx->pub_key),
                                sigctx->mechtype);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p) {
        int saltlen;
        if (sigctx->mechtype != CKM_RSA_PKCS_PSS) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "Can only be set if PSS Padding was first set.");
            return RET_OSSL_ERR;
        }

        if (p->data_type == OSSL_PARAM_INTEGER) {
            /* legacy saltlen number */
            ret = OSSL_PARAM_get_int(p, &saltlen);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
            sigctx->pss_params.sLen = saltlen;
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0) {
                ret = p11prov_rsasig_set_pss_saltlen_from_digest(sigctx);
                if (ret != RET_OSSL_OK) {
                    return ret;
                }
            } else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0) {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                               "saltlen=max is unsupported.");
                return RET_OSSL_ERR;
            } else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0) {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                               "saltlen=auto is unsupported.");
                return RET_OSSL_ERR;
            } else {
                saltlen = atoi(p->data);
                if (saltlen == 0) {
                    return RET_OSSL_ERR;
                }
                sigctx->pss_params.sLen = saltlen;
            }
        } else {
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p) {
        char digest[256];
        char *ptr = digest;
        ret = OSSL_PARAM_get_utf8_string(p, &ptr, 256);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        sigctx->pss_params.mgf = p11prov_sig_map_mgf(digest);
        if (sigctx->pss_params.mgf == CK_UNAVAILABLE_INFORMATION) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MGF1_MD);
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_rsasig_gettable_ctx_params(void *ctx,
                                                            void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_END,
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
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_rsa_signature_functions[] = {
    DISPATCH_SIG_ELEM(rsasig, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(rsasig, SIGN_INIT, sign_init),
    DISPATCH_SIG_ELEM(rsasig, SIGN, sign),
    DISPATCH_SIG_ELEM(rsasig, VERIFY_INIT, verify_init),
    DISPATCH_SIG_ELEM(rsasig, VERIFY, verify),
    DISPATCH_SIG_ELEM(rsasig, DIGEST_SIGN_INIT, digest_sign_init),
    DISPATCH_SIG_ELEM(rsasig, DIGEST_SIGN_UPDATE, digest_sign_update),
    DISPATCH_SIG_ELEM(rsasig, DIGEST_SIGN_FINAL, digest_sign_final),
    DISPATCH_SIG_ELEM(rsasig, DIGEST_VERIFY_INIT, digest_verify_init),
    DISPATCH_SIG_ELEM(rsasig, DIGEST_VERIFY_UPDATE, digest_verify_update),
    DISPATCH_SIG_ELEM(rsasig, DIGEST_VERIFY_FINAL, digest_verify_final),
    DISPATCH_SIG_ELEM(rsasig, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(rsasig, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(rsasig, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(rsasig, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};

DISPATCH_ECDSA_FN(newctx);
DISPATCH_ECDSA_FN(sign_init);
DISPATCH_ECDSA_FN(sign);
DISPATCH_ECDSA_FN(verify_init);
DISPATCH_ECDSA_FN(verify);
DISPATCH_ECDSA_FN(digest_sign_init);
DISPATCH_ECDSA_FN(digest_sign_update);
DISPATCH_ECDSA_FN(digest_sign_final);
DISPATCH_ECDSA_FN(digest_verify_init);
DISPATCH_ECDSA_FN(digest_verify_update);
DISPATCH_ECDSA_FN(digest_verify_final);
DISPATCH_ECDSA_FN(get_ctx_params);
DISPATCH_ECDSA_FN(set_ctx_params);
DISPATCH_ECDSA_FN(gettable_ctx_params);
DISPATCH_ECDSA_FN(settable_ctx_params);

static void *p11prov_ecdsa_newctx(void *provctx, const char *properties)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_SIG_CTX *sigctx;

    sigctx = p11prov_sig_newctx(ctx, CKM_ECDSA, properties);
    if (sigctx == NULL) {
        return NULL;
    }

    return sigctx;
}

static int p11prov_ecdsa_sign_init(void *ctx, void *provkey,
                                   const OSSL_PARAM params[])
{
    int ret;

    p11prov_debug("rsa sign init (ctx=%p, key=%p, params=%p)\n", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, NULL, params);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    return p11prov_ecdsa_set_ctx_params(ctx, params);
}

static int p11prov_ecdsa_sign(void *ctx, unsigned char *sig, size_t *siglen,
                              size_t sigsize, const unsigned char *tbs,
                              size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    p11prov_debug("ecdsa sign (ctx=%p)\n", ctx);

    return p11prov_sig_operate(sigctx, sig, siglen, sigsize, (void *)tbs,
                               tbslen);
}

static int p11prov_ecdsa_verify_init(void *ctx, void *provkey,
                                     const OSSL_PARAM params[])
{
    int ret;

    p11prov_debug("ecdsa verify init (ctx=%p, key=%p, params=%p)\n", ctx,
                  provkey, params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, NULL, params);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    return p11prov_ecdsa_set_ctx_params(ctx, params);
}

static int p11prov_ecdsa_verify(void *ctx, const unsigned char *sig,
                                size_t siglen, const unsigned char *tbs,
                                size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    p11prov_debug("rsa verify (ctx=%p)\n", ctx);

    return p11prov_sig_operate(sigctx, (void *)sig, NULL, siglen, (void *)tbs,
                               tbslen);
}

static int p11prov_ecdsa_digest_sign_init(void *ctx, const char *digest,
                                          void *provkey,
                                          const OSSL_PARAM params[])
{
    int ret;

    p11prov_debug("ecdsa digest sign init (ctx=%p, key=%p, params=%p)\n", ctx,
                  provkey, params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, digest, params);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    return p11prov_ecdsa_set_ctx_params(ctx, params);
}

static int p11prov_ecdsa_digest_sign_update(void *ctx,
                                            const unsigned char *data,
                                            size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    p11prov_debug("ecdsa digest sign update (ctx=%p, data=%p, datalen=%zu)\n",
                  ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_ecdsa_digest_sign_final(void *ctx, unsigned char *sig,
                                           size_t *siglen, size_t sigsize)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    p11prov_debug(
        "ecdsa digest sign final (ctx=%p, sig=%p, siglen=%zu, "
        "sigsize=%zu)\n",
        ctx, sig, *siglen, sigsize);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_final(sigctx, sig, siglen, sigsize);
}

static int p11prov_ecdsa_digest_verify_init(void *ctx, const char *digest,
                                            void *provkey,
                                            const OSSL_PARAM params[])
{
    int ret;

    p11prov_debug("ecdsa digest verify init (ctx=%p, key=%p, params=%p)\n", ctx,
                  provkey, params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, digest, params);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    return p11prov_ecdsa_set_ctx_params(ctx, params);
}

static int p11prov_ecdsa_digest_verify_update(void *ctx,
                                              const unsigned char *data,
                                              size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    p11prov_debug(
        "ecdsa digest verify update (ctx=%p, data=%p, "
        "datalen=%zu)\n",
        ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_ecdsa_digest_verify_final(void *ctx,
                                             const unsigned char *sig,
                                             size_t siglen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    p11prov_debug("ecdsa digest verify final (ctx=%p, sig=%p, siglen=%zu)\n",
                  ctx, sig, siglen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_final(sigctx, (void *)sig, NULL, siglen);
}

static int p11prov_ecdsa_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    OSSL_PARAM *p;
    int ret;

    /* todo sig params:
        OSSL_SIGNATURE_PARAM_ALGORITHM_ID
     */

    p11prov_debug("ecdsa get ctx params (ctx=%p, params=%p)\n", ctx, params);

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p) {
        const char *digest = p11prov_sig_digest_name(sigctx->digest);
        ret = OSSL_PARAM_set_utf8_string(p, digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_ERR;
}

static int p11prov_ecdsa_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    p11prov_debug("ecdsa set ctx params (ctx=%p, params=%p)\n", sigctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p) {
        char digest[256];
        char *ptr = digest;
        ret = OSSL_PARAM_get_utf8_string(p, &ptr, 256);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        sigctx->digest = p11prov_sig_map_digest(digest);
        if (sigctx->digest == CK_UNAVAILABLE_INFORMATION) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_ERR;
}

static const OSSL_PARAM *p11prov_ecdsa_gettable_ctx_params(void *ctx,
                                                           void *prov)
{
    static const OSSL_PARAM params[] = {
        /*
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
         */
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *p11prov_ecdsa_settable_ctx_params(void *ctx,
                                                           void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_ecdsa_signature_functions[] = {
    DISPATCH_SIG_ELEM(ecdsa, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(ecdsa, SIGN_INIT, sign_init),
    DISPATCH_SIG_ELEM(ecdsa, SIGN, sign),
    DISPATCH_SIG_ELEM(ecdsa, VERIFY_INIT, verify_init),
    DISPATCH_SIG_ELEM(ecdsa, VERIFY, verify),
    DISPATCH_SIG_ELEM(ecdsa, DIGEST_SIGN_INIT, digest_sign_init),
    DISPATCH_SIG_ELEM(ecdsa, DIGEST_SIGN_UPDATE, digest_sign_update),
    DISPATCH_SIG_ELEM(ecdsa, DIGEST_SIGN_FINAL, digest_sign_final),
    DISPATCH_SIG_ELEM(ecdsa, DIGEST_VERIFY_INIT, digest_verify_init),
    DISPATCH_SIG_ELEM(ecdsa, DIGEST_VERIFY_UPDATE, digest_verify_update),
    DISPATCH_SIG_ELEM(ecdsa, DIGEST_VERIFY_FINAL, digest_verify_final),
    DISPATCH_SIG_ELEM(ecdsa, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(ecdsa, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(ecdsa, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(ecdsa, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};
