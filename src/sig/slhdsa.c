/* Copyright (C) 2026 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "sig/internal.h"
#include <string.h>
#include "openssl/evp.h"
#include "openssl/err.h"

#define DISPATCH_SLHDSA_FN(name) \
    DECL_DISPATCH_FUNC(signature, p11prov_slhdsa, name)

DISPATCH_SLHDSA_FN(sign_init);
DISPATCH_SLHDSA_FN(sign);
DISPATCH_SLHDSA_FN(verify_init);
DISPATCH_SLHDSA_FN(verify);
DISPATCH_SLHDSA_FN(digest_sign_init);
DISPATCH_SLHDSA_FN(digest_sign_update);
DISPATCH_SLHDSA_FN(digest_sign_final);
DISPATCH_SLHDSA_FN(digest_verify_init);
DISPATCH_SLHDSA_FN(digest_verify_update);
DISPATCH_SLHDSA_FN(digest_verify_final);
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
DISPATCH_SLHDSA_FN(sign_message_update);
DISPATCH_SLHDSA_FN(sign_message_final);
DISPATCH_SLHDSA_FN(verify_message_update);
DISPATCH_SLHDSA_FN(verify_message_final);
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */
DISPATCH_SLHDSA_FN(get_ctx_params);
DISPATCH_SLHDSA_FN(set_ctx_params);
DISPATCH_SLHDSA_FN(gettable_ctx_params);
DISPATCH_SLHDSA_FN(settable_ctx_params);

static CK_RV p11prov_slhdsa_set_mechanism(P11PROV_SIG_CTX *sigctx)
{
    sigctx->mechanism.mechanism = CKM_SLH_DSA;
    /* we set the optional additional context only if non-default parameters
     * need to be passed in */
    if (sigctx->additional_context.pContext
        || sigctx->additional_context.hedgeVariant != CKH_HEDGE_PREFERRED) {
        sigctx->mechanism.pParameter = &sigctx->additional_context;
        sigctx->mechanism.ulParameterLen = sizeof(CK_SIGN_ADDITIONAL_CONTEXT);
    } else {
        sigctx->mechanism.pParameter = NULL;
        sigctx->mechanism.ulParameterLen = 0;
    }
    return CKR_OK;
}

static CK_RV p11prov_slhdsa_sig_size(P11PROV_SIG_CTX *sigctx, size_t *siglen)
{
    switch (sigctx->slhdsa_paramset) {
    case CKP_SLH_DSA_SHA2_128S:
        *siglen = SLH_DSA_SHA2_128S_SIG_SIZE;
        return CKR_OK;
    case CKP_SLH_DSA_SHAKE_128S:
        *siglen = SLH_DSA_SHAKE_128S_SIG_SIZE;
        return CKR_OK;
    case CKP_SLH_DSA_SHA2_128F:
        *siglen = SLH_DSA_SHA2_128F_SIG_SIZE;
        return CKR_OK;
    case CKP_SLH_DSA_SHAKE_128F:
        *siglen = SLH_DSA_SHAKE_128F_SIG_SIZE;
        return CKR_OK;
    case CKP_SLH_DSA_SHA2_192S:
        *siglen = SLH_DSA_SHA2_192S_SIG_SIZE;
        return CKR_OK;
    case CKP_SLH_DSA_SHAKE_192S:
        *siglen = SLH_DSA_SHAKE_192S_SIG_SIZE;
        return CKR_OK;
    case CKP_SLH_DSA_SHA2_192F:
        *siglen = SLH_DSA_SHA2_192F_SIG_SIZE;
        return CKR_OK;
    case CKP_SLH_DSA_SHAKE_192F:
        *siglen = SLH_DSA_SHAKE_192F_SIG_SIZE;
        return CKR_OK;
    case CKP_SLH_DSA_SHA2_256S:
        *siglen = SLH_DSA_SHA2_256S_SIG_SIZE;
        return CKR_OK;
    case CKP_SLH_DSA_SHAKE_256S:
        *siglen = SLH_DSA_SHAKE_256S_SIG_SIZE;
        return CKR_OK;
    case CKP_SLH_DSA_SHA2_256F:
        *siglen = SLH_DSA_SHA2_256F_SIG_SIZE;
        return CKR_OK;
    case CKP_SLH_DSA_SHAKE_256F:
        *siglen = SLH_DSA_SHAKE_256F_SIG_SIZE;
        return CKR_OK;
    default:
        return CKR_GENERAL_ERROR;
    }
}

static CK_RV p11prov_slhdsa_operate(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                                    size_t *siglen, size_t sigsize,
                                    unsigned char *tbs, size_t tbslen)
{
    CK_RV rv;

    rv = p11prov_slhdsa_set_mechanism(sigctx);
    if (rv != CKR_OK) {
        return rv;
    }

    if (!sigctx->signature) {
        if (sig && sigsize > 0) {
            sigctx->signature = OPENSSL_memdup(sig, sigsize);
            if (!sigctx->signature) {
                return CKR_HOST_MEMORY;
            }
            sigctx->signature_len = sigsize;
        } else {
            rv = CKR_SIGNATURE_LEN_RANGE;
            P11PROV_raise(sigctx->provctx, rv, "Invalid signature length");
            return rv;
        }
    }

    return p11prov_sig_operate(sigctx, sig, siglen, sigsize, (void *)tbs,
                               tbslen);
}

static void *p11prov_slhdsa_newctx(void *provctx, const char *properties,
                                   CK_SLH_DSA_PARAMETER_SET_TYPE paramset)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_SIG_CTX *sigctx;

    sigctx = p11prov_sig_newctx(ctx, CKM_SLH_DSA, properties);
    if (sigctx == NULL) {
        return NULL;
    }

    sigctx->slhdsa_paramset = paramset;
    sigctx->additional_context.hedgeVariant = CKH_HEDGE_PREFERRED;

    return sigctx;
}

#define SLHDSA_NEWCTX(name, param_set) \
    static void *p11prov_slhdsa_##name##_newctx(void *provctx, \
                                                const char *properties) \
    { \
        return p11prov_slhdsa_newctx(provctx, properties, param_set); \
    }

SLHDSA_NEWCTX(sha2_128s, CKP_SLH_DSA_SHA2_128S)
SLHDSA_NEWCTX(shake_128s, CKP_SLH_DSA_SHAKE_128S)
SLHDSA_NEWCTX(sha2_128f, CKP_SLH_DSA_SHA2_128F)
SLHDSA_NEWCTX(shake_128f, CKP_SLH_DSA_SHAKE_128F)
SLHDSA_NEWCTX(sha2_192s, CKP_SLH_DSA_SHA2_192S)
SLHDSA_NEWCTX(shake_192s, CKP_SLH_DSA_SHAKE_192S)
SLHDSA_NEWCTX(sha2_192f, CKP_SLH_DSA_SHA2_192F)
SLHDSA_NEWCTX(shake_192f, CKP_SLH_DSA_SHAKE_192F)
SLHDSA_NEWCTX(sha2_256s, CKP_SLH_DSA_SHA2_256S)
SLHDSA_NEWCTX(shake_256s, CKP_SLH_DSA_SHAKE_256S)
SLHDSA_NEWCTX(sha2_256f, CKP_SLH_DSA_SHA2_256F)
SLHDSA_NEWCTX(shake_256f, CKP_SLH_DSA_SHAKE_256F)

static int p11prov_slhdsa_sign_init(void *ctx, void *provkey,
                                    const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("slhdsa sign init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_slhdsa_set_ctx_params(ctx, params);
}

static int p11prov_slhdsa_sign(void *ctx, unsigned char *sig, size_t *siglen,
                               size_t sigsize, const unsigned char *tbs,
                               size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("slhdsa sign (ctx=%p)", ctx);

    if (sig == NULL) {
        if (siglen == NULL) {
            return RET_OSSL_ERR;
        }
        ret = p11prov_slhdsa_sig_size(sigctx, siglen);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        return RET_OSSL_OK;
    }

    ret = p11prov_slhdsa_operate(sigctx, sig, siglen, sigsize, (void *)tbs,
                                 tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_slhdsa_verify_init(void *ctx, void *provkey,
                                      const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("slhdsa verify init (ctx=%p, key=%p, params=%p)", ctx,
                  provkey, params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_slhdsa_set_ctx_params(ctx, params);
}

static int p11prov_slhdsa_verify(void *ctx, const unsigned char *sig,
                                 size_t siglen, const unsigned char *tbs,
                                 size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("slhdsa verify (ctx=%p)", ctx);

    ret = p11prov_slhdsa_operate(sigctx, (unsigned char *)sig, NULL, siglen,
                                 (void *)tbs, tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_slhdsa_digest_sign_init(void *ctx, const char *digest,
                                           void *provkey,
                                           const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug(
        "slhdsa digest sign init (ctx=%p, digest=%s, key=%p, params=%p)", ctx,
        digest ? digest : "<NULL>", provkey, params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, digest);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    sigctx->digest_op = true;

    return p11prov_slhdsa_set_ctx_params(ctx, params);
}

static int p11prov_slhdsa_digest_sign_update(void *ctx,
                                             const unsigned char *data,
                                             size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("slhdsa digest sign update (ctx=%p, data=%p, datalen=%zu)",
                  ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    if (sigctx->mechanism.mechanism == CK_UNAVAILABLE_INFORMATION) {
        int rv = p11prov_slhdsa_set_mechanism(sigctx);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_slhdsa_digest_sign_final(void *ctx, unsigned char *sig,
                                            size_t *siglen, size_t sigsize)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV rv;
    int ret;

    if (siglen == NULL) {
        return RET_OSSL_ERR;
    }
    *siglen = 0;

    P11PROV_debug("slhdsa digest sign final (ctx=%p, sig=%p, siglen=%zu, "
                  "sigsize=%zu)",
                  ctx, sig, *siglen, sigsize);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (sig == NULL) {
        rv = p11prov_slhdsa_sig_size(sigctx, siglen);
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

static int p11prov_slhdsa_digest_verify_init(void *ctx, const char *digest,
                                             void *provkey,
                                             const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("slhdsa digest verify init (ctx=%p, key=%p, params=%p)", ctx,
                  provkey, params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, digest);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    sigctx->digest_op = true;

    return p11prov_slhdsa_set_ctx_params(ctx, params);
}

static int p11prov_slhdsa_digest_verify_update(void *ctx,
                                               const unsigned char *data,
                                               size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("slhdsa digest verify update (ctx=%p, data=%p, datalen=%zu)",
                  ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    if (sigctx->mechanism.mechanism == CK_UNAVAILABLE_INFORMATION) {
        int rv = p11prov_slhdsa_set_mechanism(sigctx);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_slhdsa_digest_verify_final(void *ctx,
                                              const unsigned char *sig,
                                              size_t siglen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    int ret;

    P11PROV_debug("slhdsa digest verify final (ctx=%p, sig=%p, siglen=%zu)",
                  ctx, sig, siglen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_sig_digest_final(sigctx, (void *)sig, NULL, siglen);
    return ret;
}

#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
static int p11prov_slhdsa_sign_message_update(void *ctx,
                                              const unsigned char *data,
                                              size_t datalen)
{
    return p11prov_slhdsa_digest_sign_update(ctx, data, datalen);
}

static int p11prov_slhdsa_sign_message_final(void *ctx, unsigned char *sig,
                                             size_t *siglen, size_t sigsize)
{
    return p11prov_slhdsa_digest_sign_final(ctx, sig, siglen, sigsize);
}

static int p11prov_slhdsa_verify_message_update(void *ctx,
                                                const unsigned char *data,
                                                size_t datalen)
{
    return p11prov_slhdsa_digest_verify_update(ctx, data, datalen);
}

static int p11prov_slhdsa_verify_message_final(void *ctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("slhdsa message verify final (ctx=%p)", ctx);

    if (!sigctx) {
        return RET_OSSL_ERR;
    }
    if (sigctx->signature == NULL) {
        P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                      "Signature not available on context");
        return RET_OSSL_ERR;
    }

    return p11prov_slhdsa_digest_verify_final(sigctx, sigctx->signature,
                                              sigctx->signature_len);
}
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */

static const unsigned char der_slh_dsa_sha2_128s_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x14
};
static const unsigned char der_slh_dsa_sha2_128f_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x15
};
static const unsigned char der_slh_dsa_sha2_192s_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x16
};
static const unsigned char der_slh_dsa_sha2_192f_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x17
};
static const unsigned char der_slh_dsa_sha2_256s_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x18
};
static const unsigned char der_slh_dsa_sha2_256f_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x19
};
static const unsigned char der_slh_dsa_shake_128s_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x1A
};
static const unsigned char der_slh_dsa_shake_128f_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x1B
};
static const unsigned char der_slh_dsa_shake_192s_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x1C
};
static const unsigned char der_slh_dsa_shake_192f_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x1D
};
static const unsigned char der_slh_dsa_shake_256s_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x1E
};
static const unsigned char der_slh_dsa_shake_256f_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x1F
};

static int p11prov_slhdsa_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    OSSL_PARAM *p;
    int ret;

    P11PROV_debug("slhdsa get ctx params (ctx=%p, params=%p)", ctx, params);

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p) {
        switch (sigctx->slhdsa_paramset) {
        case CKP_SLH_DSA_SHA2_128S:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_sha2_128s_alg_id,
                sizeof(der_slh_dsa_sha2_128s_alg_id));
            break;
        case CKP_SLH_DSA_SHAKE_128S:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_shake_128s_alg_id,
                sizeof(der_slh_dsa_shake_128s_alg_id));
            break;
        case CKP_SLH_DSA_SHA2_128F:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_sha2_128f_alg_id,
                sizeof(der_slh_dsa_sha2_128f_alg_id));
            break;
        case CKP_SLH_DSA_SHAKE_128F:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_shake_128f_alg_id,
                sizeof(der_slh_dsa_shake_128f_alg_id));
            break;
        case CKP_SLH_DSA_SHA2_192S:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_sha2_192s_alg_id,
                sizeof(der_slh_dsa_sha2_192s_alg_id));
            break;
        case CKP_SLH_DSA_SHAKE_192S:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_shake_192s_alg_id,
                sizeof(der_slh_dsa_shake_192s_alg_id));
            break;
        case CKP_SLH_DSA_SHA2_192F:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_sha2_192f_alg_id,
                sizeof(der_slh_dsa_sha2_192f_alg_id));
            break;
        case CKP_SLH_DSA_SHAKE_192F:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_shake_192f_alg_id,
                sizeof(der_slh_dsa_shake_192f_alg_id));
            break;
        case CKP_SLH_DSA_SHA2_256S:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_sha2_256s_alg_id,
                sizeof(der_slh_dsa_sha2_256s_alg_id));
            break;
        case CKP_SLH_DSA_SHAKE_256S:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_shake_256s_alg_id,
                sizeof(der_slh_dsa_shake_256s_alg_id));
            break;
        case CKP_SLH_DSA_SHA2_256F:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_sha2_256f_alg_id,
                sizeof(der_slh_dsa_sha2_256f_alg_id));
            break;
        case CKP_SLH_DSA_SHAKE_256F:
            ret = OSSL_PARAM_set_octet_string(
                p, der_slh_dsa_shake_256f_alg_id,
                sizeof(der_slh_dsa_shake_256f_alg_id));
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
#ifndef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
#define OSSL_SIGNATURE_PARAM_CONTEXT_STRING "context-string"
#endif

static int p11prov_slhdsa_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("slhdsa set ctx params (ctx=%p, params=%p)", sigctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p) {
        size_t datalen;
        OPENSSL_clear_free(sigctx->additional_context.pContext,
                           sigctx->additional_context.ulContextLen);
        sigctx->additional_context.pContext = NULL;
        ret = OSSL_PARAM_get_octet_string(
            p, (void **)&sigctx->additional_context.pContext, 0, &datalen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        sigctx->additional_context.ulContextLen = datalen;
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
        sigctx->additional_context.hedgeVariant = hedge;
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

static const OSSL_PARAM *p11prov_slhdsa_gettable_ctx_params(void *ctx,
                                                            void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *p11prov_slhdsa_settable_ctx_params(void *ctx,
                                                            void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, 0),
#if defined(OSSL_SIGNATURE_PARAM_SIGNATURE)
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0),
#endif
        OSSL_PARAM_END,
    };
    return params;
}

#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
#define DISPATCH_MESSAGE_FUNCTIONS \
    DISPATCH_SIG_ELEM(slhdsa, SIGN_MESSAGE_INIT, sign_init), \
        DISPATCH_SIG_ELEM(slhdsa, SIGN_MESSAGE_UPDATE, sign_message_update), \
        DISPATCH_SIG_ELEM(slhdsa, SIGN_MESSAGE_FINAL, sign_message_final), \
        DISPATCH_SIG_ELEM(slhdsa, VERIFY_MESSAGE_INIT, verify_init), \
        DISPATCH_SIG_ELEM(slhdsa, VERIFY_MESSAGE_UPDATE, \
                          verify_message_update), \
        DISPATCH_SIG_ELEM(slhdsa, VERIFY_MESSAGE_FINAL, verify_message_final),
#else
#define DISPATCH_MESSAGE_FUNCTIONS
#endif

#define SLHDSA_SIGNATURE_FUNCTIONS(variant) \
    const OSSL_DISPATCH p11prov_slhdsa_##variant##_functions[] = { \
        DISPATCH_SIG_ELEM(slhdsa_##variant, NEWCTX, newctx), \
        DISPATCH_SIG_ELEM(sig, FREECTX, freectx), \
        DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx), \
        DISPATCH_SIG_ELEM(slhdsa, SIGN_INIT, sign_init), \
        DISPATCH_SIG_ELEM(slhdsa, SIGN, sign), \
        DISPATCH_SIG_ELEM(slhdsa, VERIFY_INIT, verify_init), \
        DISPATCH_SIG_ELEM(slhdsa, VERIFY, verify), \
        DISPATCH_SIG_ELEM(slhdsa, DIGEST_SIGN_INIT, digest_sign_init), \
        DISPATCH_SIG_ELEM(slhdsa, DIGEST_SIGN_UPDATE, digest_sign_update), \
        DISPATCH_SIG_ELEM(slhdsa, DIGEST_SIGN_FINAL, digest_sign_final), \
        DISPATCH_SIG_ELEM(slhdsa, DIGEST_VERIFY_INIT, digest_verify_init), \
        DISPATCH_SIG_ELEM(slhdsa, DIGEST_VERIFY_UPDATE, digest_verify_update), \
        DISPATCH_SIG_ELEM(slhdsa, DIGEST_VERIFY_FINAL, digest_verify_final), \
        DISPATCH_MESSAGE_FUNCTIONS DISPATCH_SIG_ELEM(slhdsa, GET_CTX_PARAMS, \
                                                     get_ctx_params), \
        DISPATCH_SIG_ELEM(slhdsa, GETTABLE_CTX_PARAMS, gettable_ctx_params), \
        DISPATCH_SIG_ELEM(slhdsa, SET_CTX_PARAMS, set_ctx_params), \
        DISPATCH_SIG_ELEM(slhdsa, SETTABLE_CTX_PARAMS, settable_ctx_params), \
        { 0, NULL }, \
    }

SLHDSA_SIGNATURE_FUNCTIONS(sha2_128s);
SLHDSA_SIGNATURE_FUNCTIONS(shake_128s);
SLHDSA_SIGNATURE_FUNCTIONS(sha2_128f);
SLHDSA_SIGNATURE_FUNCTIONS(shake_128f);
SLHDSA_SIGNATURE_FUNCTIONS(sha2_192s);
SLHDSA_SIGNATURE_FUNCTIONS(shake_192s);
SLHDSA_SIGNATURE_FUNCTIONS(sha2_192f);
SLHDSA_SIGNATURE_FUNCTIONS(shake_192f);
SLHDSA_SIGNATURE_FUNCTIONS(sha2_256s);
SLHDSA_SIGNATURE_FUNCTIONS(shake_256s);
SLHDSA_SIGNATURE_FUNCTIONS(sha2_256f);
SLHDSA_SIGNATURE_FUNCTIONS(shake_256f);
