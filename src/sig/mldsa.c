/* Copyright (C) 2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "sig/internal.h"
#include <string.h>
#include "openssl/evp.h"
#include "openssl/err.h"

DISPATCH_MLDSA_FN(sign_init);
DISPATCH_MLDSA_FN(sign);
DISPATCH_MLDSA_FN(verify_init);
DISPATCH_MLDSA_FN(verify);
DISPATCH_MLDSA_FN(digest_sign_init);
DISPATCH_MLDSA_FN(digest_sign_update);
DISPATCH_MLDSA_FN(digest_sign_final);
DISPATCH_MLDSA_FN(digest_verify_init);
DISPATCH_MLDSA_FN(digest_verify_update);
DISPATCH_MLDSA_FN(digest_verify_final);
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
DISPATCH_MLDSA_FN(sign_message_update);
DISPATCH_MLDSA_FN(sign_message_final);
DISPATCH_MLDSA_FN(verify_message_update);
DISPATCH_MLDSA_FN(verify_message_final);
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */
DISPATCH_MLDSA_FN(get_ctx_params);
DISPATCH_MLDSA_FN(set_ctx_params);
DISPATCH_MLDSA_FN(gettable_ctx_params);
DISPATCH_MLDSA_FN(settable_ctx_params);

static CK_RV p11prov_mldsa_set_mechanism(P11PROV_SIG_CTX *sigctx)
{
    sigctx->mechanism.mechanism = CKM_ML_DSA;
    sigctx->mechanism.pParameter = NULL;
    sigctx->mechanism.ulParameterLen = 0;
    return CKR_OK;
}

static CK_RV p11prov_mldsa_sig_size(P11PROV_SIG_CTX *sigctx, size_t *siglen)
{
    switch (sigctx->mldsa_paramset) {
    case CKP_ML_DSA_44:
        *siglen = ML_DSA_44_SIG_SIZE;
        return CKR_OK;
    case CKP_ML_DSA_65:
        *siglen = ML_DSA_65_SIG_SIZE;
        return CKR_OK;
    case CKP_ML_DSA_87:
        *siglen = ML_DSA_87_SIG_SIZE;
        return CKR_OK;
    default:
        return CKR_GENERAL_ERROR;
    }
}

static CK_RV p11prov_mldsa_operate(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                                   size_t *siglen, size_t sigsize,
                                   unsigned char *tbs, size_t tbslen)
{
    CK_RV rv;

    rv = p11prov_mldsa_set_mechanism(sigctx);
    if (rv != CKR_OK) {
        return rv;
    }

    return p11prov_sig_operate(sigctx, sig, siglen, sigsize, (void *)tbs,
                               tbslen);
}

static void *p11prov_mldsa_newctx(void *provctx, const char *properties,
                                  CK_ML_DSA_PARAMETER_SET_TYPE paramset)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_SIG_CTX *sigctx;

    sigctx = p11prov_sig_newctx(ctx, CKM_ML_DSA, properties);
    if (sigctx == NULL) {
        return NULL;
    }

    sigctx->mldsa_paramset = paramset;
    sigctx->fallback_operate = &p11prov_mldsa_operate;

    return sigctx;
}

static void *p11prov_mldsa_44_newctx(void *provctx, const char *properties)
{
    return p11prov_mldsa_newctx(provctx, properties, CKP_ML_DSA_44);
}

static void *p11prov_mldsa_65_newctx(void *provctx, const char *properties)
{
    return p11prov_mldsa_newctx(provctx, properties, CKP_ML_DSA_65);
}

static void *p11prov_mldsa_87_newctx(void *provctx, const char *properties)
{
    return p11prov_mldsa_newctx(provctx, properties, CKP_ML_DSA_87);
}

static int p11prov_mldsa_sign_init(void *ctx, void *provkey,
                                   const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("mldsa sign init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_mldsa_set_ctx_params(ctx, params);
}

static int p11prov_mldsa_sign(void *ctx, unsigned char *sig, size_t *siglen,
                              size_t sigsize, const unsigned char *tbs,
                              size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("mldsa sign (ctx=%p)", ctx);

    if (sig == NULL) {
        if (siglen == 0) {
            return RET_OSSL_ERR;
        }
        ret = p11prov_mldsa_sig_size(sigctx, siglen);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        return RET_OSSL_OK;
    }

    ret = p11prov_mldsa_operate(sigctx, sig, siglen, sigsize, (void *)tbs,
                                tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_mldsa_verify_init(void *ctx, void *provkey,
                                     const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("mldsa verify init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_mldsa_set_ctx_params(ctx, params);
}

static int p11prov_mldsa_verify(void *ctx, const unsigned char *sig,
                                size_t siglen, const unsigned char *tbs,
                                size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("mldsa verify (ctx=%p)", ctx);

    ret = p11prov_mldsa_operate(sigctx, (unsigned char *)sig, NULL, siglen,
                                (void *)tbs, tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_mldsa_digest_sign_init(void *ctx, const char *digest,
                                          void *provkey,
                                          const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug(
        "mldsa digest sign init (ctx=%p, digest=%s, key=%p, params=%p)", ctx,
        digest ? digest : "<NULL>", provkey, params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, digest);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    sigctx->digest_op = true;

    return p11prov_mldsa_set_ctx_params(ctx, params);
}

static int p11prov_mldsa_digest_sign_update(void *ctx,
                                            const unsigned char *data,
                                            size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("mldsa digest sign update (ctx=%p, data=%p, datalen=%zu)",
                  ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    if (sigctx->mechanism.mechanism == CK_UNAVAILABLE_INFORMATION) {
        int rv = p11prov_mldsa_set_mechanism(sigctx);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_mldsa_digest_sign_final(void *ctx, unsigned char *sig,
                                           size_t *siglen, size_t sigsize)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV rv;
    int ret;

    if (siglen == NULL) {
        return RET_OSSL_ERR;
    }
    *siglen = 0;

    P11PROV_debug("mldsa digest sign final (ctx=%p, sig=%p, siglen=%zu, "
                  "sigsize=%zu)",
                  ctx, sig, *siglen, sigsize);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (sig == NULL) {
        rv = p11prov_mldsa_sig_size(sigctx, siglen);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
        return RET_OSSL_OK;
    }
    if (sigsize == 0) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_sig_digest_final(sigctx, sig, siglen, sigsize);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    return RET_OSSL_OK;
}

static int p11prov_mldsa_digest_verify_init(void *ctx, const char *digest,
                                            void *provkey,
                                            const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("mldsa digest verify init (ctx=%p, key=%p, params=%p)", ctx,
                  provkey, params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, digest);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    sigctx->digest_op = true;

    return p11prov_mldsa_set_ctx_params(ctx, params);
}

static int p11prov_mldsa_digest_verify_update(void *ctx,
                                              const unsigned char *data,
                                              size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("mldsa digest verify update (ctx=%p, data=%p, datalen=%zu)",
                  ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    if (sigctx->mechanism.mechanism == CK_UNAVAILABLE_INFORMATION) {
        int rv = p11prov_mldsa_set_mechanism(sigctx);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_mldsa_digest_verify_final(void *ctx,
                                             const unsigned char *sig,
                                             size_t siglen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    int ret;

    P11PROV_debug("mldsa digest verify final (ctx=%p, sig=%p, siglen=%zu)", ctx,
                  sig, siglen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_sig_digest_final(sigctx, (void *)sig, NULL, siglen);
    return ret;
}

#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
static int p11prov_mldsa_sign_message_update(void *ctx,
                                             const unsigned char *data,
                                             size_t datalen)
{
    return p11prov_mldsa_digest_sign_update(ctx, data, datalen);
}

static int p11prov_mldsa_sign_message_final(void *ctx, unsigned char *sig,
                                            size_t *siglen, size_t sigsize)
{
    return p11prov_mldsa_digest_sign_final(ctx, sig, siglen, sigsize);
}

static int p11prov_mldsa_verify_message_update(void *ctx,
                                               const unsigned char *data,
                                               size_t datalen)
{
    return p11prov_mldsa_digest_verify_update(ctx, data, datalen);
}

static int p11prov_mldsa_verify_message_final(void *ctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("mldsa message verify final (ctx=%p)", ctx);

    if (sigctx == NULL || sigctx->signature == NULL) {
        P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                      "Signature not available on context");
        return RET_OSSL_ERR;
    }

    return p11prov_mldsa_digest_verify_final(sigctx, sigctx->signature,
                                             sigctx->signature_len);
}
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */

static const unsigned char der_ml_dsa_44_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x11
};

static const unsigned char der_ml_dsa_65_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x12
};

static const unsigned char der_ml_dsa_87_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x13
};

static int p11prov_mldsa_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    OSSL_PARAM *p;
    int ret;

    P11PROV_debug("mldsa get ctx params (ctx=%p, params=%p)", ctx, params);

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p) {
        CK_ULONG size = p11prov_obj_get_key_size(sigctx->key);
        switch (size) {
        case ML_DSA_44_SK_SIZE:
        case ML_DSA_44_PK_SIZE:
            ret = OSSL_PARAM_set_octet_string(p, der_ml_dsa_44_alg_id,
                                              sizeof(der_ml_dsa_44_alg_id));
            break;
        case ML_DSA_65_SK_SIZE:
        case ML_DSA_65_PK_SIZE:
            ret = OSSL_PARAM_set_octet_string(p, der_ml_dsa_65_alg_id,
                                              sizeof(der_ml_dsa_65_alg_id));
            break;
        case ML_DSA_87_SK_SIZE:
        case ML_DSA_87_PK_SIZE:
            ret = OSSL_PARAM_set_octet_string(p, der_ml_dsa_87_alg_id,
                                              sizeof(der_ml_dsa_87_alg_id));
            break;
        default:
            ret = RET_OSSL_ERR;
        }
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

#ifndef OSSL_SIGNATURE_PARAM_DETERMINISTIC
#define OSSL_SIGNATURE_PARAM_DETERMINISTIC "deterministic"
#endif
#ifndef OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING
#define OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING "message-encoding"
#endif
#ifndef OSSL_SIGNATURE_PARAM_MU
#define OSSL_SIGNATURE_PARAM_MU "mu"
#endif
#ifndef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
#define OSSL_SIGNATURE_PARAM_CONTEXT_STRING "context-string"
#endif

static int p11prov_mldsa_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("mldsa set ctx params (ctx=%p, params=%p)", sigctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p) {
        size_t datalen;
        OPENSSL_clear_free(sigctx->mldsa_params.pContext,
                           sigctx->mldsa_params.ulContextLen);
        sigctx->mldsa_params.pContext = NULL;
        ret = OSSL_PARAM_get_octet_string(
            p, (void **)&sigctx->mldsa_params.pContext, 0, &datalen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        sigctx->mldsa_params.ulContextLen = datalen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC);
    if (p) {
        CK_HEDGE_TYPE hedge = CKH_HEDGE_PREFERRED;
        int deterministic;
        ret = OSSL_PARAM_get_int(p, &deterministic);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        if (deterministic == 0) {
            hedge = CKH_HEDGE_REQUIRED;
        } else if (deterministic == 1) {
            hedge = CKH_DETERMINISTIC_REQUIRED;
        } else {
            P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                          "Unsupported 'deterministic' value");
            return RET_OSSL_ERR;
        }
        sigctx->mldsa_params.hedgeVariant = hedge;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING);
    if (p) {
        int encode;
        ret = OSSL_PARAM_get_int(p, &encode);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        if (encode != 1) {
            P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                          "Unsupported 'message-encoding' parameter");
            return RET_OSSL_ERR;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MU);
    if (p) {
        int mu;
        ret = OSSL_PARAM_get_int(p, &mu);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        if (mu != 0) {
            P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                          "Unsupported 'mu' parameter");
            return RET_OSSL_ERR;
        }
    }

#if defined(OSSL_SIGNATURE_PARAM_SIGNATURE)
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_SIGNATURE);
    if (p) {
        OPENSSL_free(sigctx->signature);
        sigctx->signature = NULL;
        ret = OSSL_PARAM_get_octet_string(p, (void **)&sigctx->signature, 0,
                                          &sigctx->signature_len);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
#endif

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_mldsa_gettable_ctx_params(void *ctx,
                                                           void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *p11prov_mldsa_settable_ctx_params(void *ctx,
                                                           void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MU, 0),
#if defined(OSSL_SIGNATURE_PARAM_SIGNATURE)
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0),
#endif
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_mldsa_44_signature_functions[] = {
    DISPATCH_SIG_ELEM(mldsa_44, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(mldsa, SIGN_INIT, sign_init),
    DISPATCH_SIG_ELEM(mldsa, SIGN, sign),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_INIT, verify_init),
    DISPATCH_SIG_ELEM(mldsa, VERIFY, verify),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_INIT, digest_sign_init),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_UPDATE, digest_sign_update),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_FINAL, digest_sign_final),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_INIT, digest_verify_init),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_UPDATE, digest_verify_update),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_FINAL, digest_verify_final),
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_INIT, sign_init),
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_UPDATE, sign_message_update),
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_FINAL, sign_message_final),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_INIT, verify_init),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_UPDATE, verify_message_update),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_FINAL, verify_message_final),
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */
    DISPATCH_SIG_ELEM(mldsa, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mldsa_65_signature_functions[] = {
    DISPATCH_SIG_ELEM(mldsa_65, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(mldsa, SIGN_INIT, sign_init),
    DISPATCH_SIG_ELEM(mldsa, SIGN, sign),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_INIT, verify_init),
    DISPATCH_SIG_ELEM(mldsa, VERIFY, verify),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_INIT, digest_sign_init),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_UPDATE, digest_sign_update),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_FINAL, digest_sign_final),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_INIT, digest_verify_init),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_UPDATE, digest_verify_update),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_FINAL, digest_verify_final),
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_INIT, sign_init),
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_UPDATE, sign_message_update),
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_FINAL, sign_message_final),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_INIT, verify_init),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_UPDATE, verify_message_update),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_FINAL, verify_message_final),
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */
    DISPATCH_SIG_ELEM(mldsa, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mldsa_87_signature_functions[] = {
    DISPATCH_SIG_ELEM(mldsa_87, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(mldsa, SIGN_INIT, sign_init),
    DISPATCH_SIG_ELEM(mldsa, SIGN, sign),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_INIT, verify_init),
    DISPATCH_SIG_ELEM(mldsa, VERIFY, verify),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_INIT, digest_sign_init),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_UPDATE, digest_sign_update),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_SIGN_FINAL, digest_sign_final),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_INIT, digest_verify_init),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_UPDATE, digest_verify_update),
    DISPATCH_SIG_ELEM(mldsa, DIGEST_VERIFY_FINAL, digest_verify_final),
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_INIT, sign_init),
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_UPDATE, sign_message_update),
    DISPATCH_SIG_ELEM(mldsa, SIGN_MESSAGE_FINAL, sign_message_final),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_INIT, verify_init),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_UPDATE, verify_message_update),
    DISPATCH_SIG_ELEM(mldsa, VERIFY_MESSAGE_FINAL, verify_message_final),
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */
    DISPATCH_SIG_ELEM(mldsa, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(mldsa, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};
