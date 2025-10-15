/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "sig/internal.h"
#include <string.h>
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/err.h"

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
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
DISPATCH_ECDSA_FN(sign_message_update);
DISPATCH_ECDSA_FN(sign_message_final);
DISPATCH_ECDSA_FN(verify_message_update);
DISPATCH_ECDSA_FN(verify_message_final);
DISPATCH_ECDSA_FN(query_key_types);
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */
DISPATCH_ECDSA_FN(get_ctx_params);
DISPATCH_ECDSA_FN(set_ctx_params);
DISPATCH_ECDSA_FN(gettable_ctx_params);
DISPATCH_ECDSA_FN(settable_ctx_params);

/* clang-format off */
static const unsigned char der_ecdsa_sha1[] = {
    DER_SEQUENCE, DER_ANSIX962_SIG_LEN+3,
        DER_OBJECT, DER_ANSIX962_SIG_LEN+1,
            DER_ANSIX962_SIG, 0x01
};

#define DER_ECDSA_DEFS(bits, sha2_id, sha3_id) \
    static const unsigned char der_ecdsa_sha2_##bits[] = { \
        DER_SEQUENCE, DER_ANSIX962_SHA2_SIG_LEN + 3, \
            DER_OBJECT, DER_ANSIX962_SHA2_SIG_LEN + 1, \
                DER_ANSIX962_SHA2_SIG, sha2_id, \
    }; \
    static const unsigned char der_ecdsa_sha3_##bits[] = { \
        DER_SEQUENCE, DER_NIST_SIGALGS_LEN + 3, \
            DER_OBJECT, DER_NIST_SIGALGS_LEN + 1, \
                DER_NIST_SIGALGS, sha3_id, \
    };
/* clang-format on */

DER_ECDSA_DEFS(224, 0x01, 0x09);
DER_ECDSA_DEFS(256, 0x02, 0x0A);
DER_ECDSA_DEFS(384, 0x03, 0x0B);
DER_ECDSA_DEFS(512, 0x04, 0x0C);

struct ecdsa_data {
    CK_MECHANISM_TYPE digest;
    CK_MECHANISM_TYPE mech;
    const void *der;
    size_t derlen;
} ecdsa_mech_map[] = {
    { CKM_SHA_1, CKM_ECDSA_SHA1, der_ecdsa_sha1, sizeof(der_ecdsa_sha1) },
    { CKM_SHA224, CKM_ECDSA_SHA224, der_ecdsa_sha2_224,
      sizeof(der_ecdsa_sha2_224) },
    { CKM_SHA256, CKM_ECDSA_SHA256, der_ecdsa_sha2_256,
      sizeof(der_ecdsa_sha2_256) },
    { CKM_SHA384, CKM_ECDSA_SHA384, der_ecdsa_sha2_384,
      sizeof(der_ecdsa_sha2_384) },
    { CKM_SHA512, CKM_ECDSA_SHA512, der_ecdsa_sha2_512,
      sizeof(der_ecdsa_sha2_512) },
    { CKM_SHA3_224, CKM_ECDSA_SHA3_224, der_ecdsa_sha3_224,
      sizeof(der_ecdsa_sha3_224) },
    { CKM_SHA3_256, CKM_ECDSA_SHA3_256, der_ecdsa_sha3_256,
      sizeof(der_ecdsa_sha3_256) },
    { CKM_SHA3_384, CKM_ECDSA_SHA3_384, der_ecdsa_sha3_384,
      sizeof(der_ecdsa_sha3_384) },
    { CKM_SHA3_512, CKM_ECDSA_SHA3_512, der_ecdsa_sha3_512,
      sizeof(der_ecdsa_sha3_512) },
    { CK_UNAVAILABLE_INFORMATION, 0, NULL, 0 },
};

static struct ecdsa_data *ecdsa_digest_map(CK_MECHANISM_TYPE digest)
{
    for (int i = 0; ecdsa_mech_map[i].digest != CK_UNAVAILABLE_INFORMATION;
         i++) {
        if (ecdsa_mech_map[i].digest == digest) {
            return &ecdsa_mech_map[i];
        }
    }
    return NULL;
}

static CK_RV p11prov_ecdsa_set_mechanism(P11PROV_SIG_CTX *sigctx)
{
    sigctx->mechanism.mechanism = sigctx->mechtype;
    sigctx->mechanism.pParameter = NULL;
    sigctx->mechanism.ulParameterLen = 0;

    switch (sigctx->mechtype) {
    case CKM_ECDSA:
        if (sigctx->digest_op) {
            struct ecdsa_data *data;
            data = ecdsa_digest_map(sigctx->digest);
            if (!data) {
                return CKR_MECHANISM_INVALID;
            }
            sigctx->mechanism.mechanism = data->mech;
        }
        break;
    default:
        return CKR_DATA_INVALID;
    }

    return CKR_OK;
}

static CK_RV p11prov_ecdsa_sig_size(P11PROV_SIG_CTX *sigctx, size_t *siglen)
{
    CK_KEY_TYPE type = p11prov_obj_get_key_type(sigctx->key);
    if (type == CKK_EC) {
        CK_ULONG size = p11prov_obj_get_key_size(sigctx->key);
        if (size != CK_UNAVAILABLE_INFORMATION) {
            *siglen = 3 + (size + 4) * 2;
            return CKR_OK;
        }
    }
    return CKR_KEY_INDIGESTIBLE;
}

static CK_RV p11prov_ecdsa_operate(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                                   size_t *siglen, size_t sigsize,
                                   unsigned char *tbs, size_t tbslen)
{
    CK_RV rv;

    rv = p11prov_ecdsa_set_mechanism(sigctx);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_operate(sigctx, sig, siglen, sigsize, (void *)tbs,
                               tbslen);
}

static void *p11prov_ecdsa_newctx(void *provctx, const char *properties)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_SIG_CTX *sigctx;

    sigctx = p11prov_sig_newctx(ctx, CKM_ECDSA, properties);
    if (sigctx == NULL) {
        return NULL;
    }

    /* In case we need to fall back */
    sigctx->fallback_operate = &p11prov_ecdsa_operate;

    return sigctx;
}

static int p11prov_ecdsa_sign_init(void *ctx, void *provkey,
                                   const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("ecdsa sign init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_ecdsa_set_ctx_params(ctx, params);
}

/* The raw signature is concatenated r | s padded to the field sizes */
#define P11PROV_MAX_RAW_ECC_SIG_SIZE (2 * (OPENSSL_ECC_MAX_FIELD_BITS + 7) / 8)

static int convert_ecdsa_raw_to_der(const unsigned char *raw, size_t rawlen,
                                    unsigned char *der, size_t *derlen,
                                    size_t dersize)
{
    const CK_ULONG fieldlen = rawlen / 2;
    ECDSA_SIG *ecdsasig;
    BIGNUM *r, *s;
    int ret = RET_OSSL_ERR;

    ecdsasig = ECDSA_SIG_new();
    if (ecdsasig == NULL) {
        return RET_OSSL_ERR;
    }

    r = BN_bin2bn(&raw[0], fieldlen, NULL);
    s = BN_bin2bn(&raw[fieldlen], fieldlen, NULL);
    ret = ECDSA_SIG_set0(ecdsasig, r, s);
    if (ret == RET_OSSL_OK) {
        *derlen = i2d_ECDSA_SIG(ecdsasig, NULL);
        if (*derlen <= dersize) {
            i2d_ECDSA_SIG(ecdsasig, &der);
        } else {
            ret = RET_OSSL_ERR;
        }
    } else {
        BN_clear_free(r);
        BN_clear_free(s);
    }

    ECDSA_SIG_free(ecdsasig);
    return ret;
}

static int convert_ecdsa_der_to_raw(const unsigned char *der, size_t derlen,
                                    unsigned char *raw, size_t rawlen,
                                    CK_ULONG fieldlen)
{
    ECDSA_SIG *ecdsasig;
    const BIGNUM *r, *s;

    if (fieldlen == CK_UNAVAILABLE_INFORMATION) {
        return RET_OSSL_ERR;
    }
    if (rawlen < 2 * fieldlen) {
        return RET_OSSL_ERR;
    }

    ecdsasig = d2i_ECDSA_SIG(NULL, &der, derlen);
    if (ecdsasig == NULL) {
        return RET_OSSL_ERR;
    }

    ECDSA_SIG_get0(ecdsasig, &r, &s);
    BN_bn2binpad(r, &raw[0], fieldlen);
    BN_bn2binpad(s, &raw[fieldlen], fieldlen);
    ECDSA_SIG_free(ecdsasig);
    return RET_OSSL_OK;
}

static int p11prov_ecdsa_sign(void *ctx, unsigned char *sig, size_t *siglen,
                              size_t sigsize, const unsigned char *tbs,
                              size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    unsigned char raw[P11PROV_MAX_RAW_ECC_SIG_SIZE];
    size_t rawlen = 0;
    CK_RV ret;
    int err;

    P11PROV_debug("ecdsa sign (ctx=%p)", ctx);

    if (sig == NULL) {
        if (siglen == 0) {
            return RET_OSSL_ERR;
        }
        ret = p11prov_ecdsa_sig_size(sigctx, siglen);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        return RET_OSSL_OK;
    }

    ret = p11prov_ecdsa_operate(sigctx, raw, &rawlen, sizeof(raw), (void *)tbs,
                                tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    err = convert_ecdsa_raw_to_der(raw, rawlen, sig, siglen, sigsize);
    OPENSSL_cleanse(raw, rawlen);
    return err;
}

static int p11prov_ecdsa_verify_init(void *ctx, void *provkey,
                                     const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("ecdsa verify init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_ecdsa_set_ctx_params(ctx, params);
}

static int p11prov_ecdsa_verify(void *ctx, const unsigned char *sig,
                                size_t siglen, const unsigned char *tbs,
                                size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    unsigned char raw[P11PROV_MAX_RAW_ECC_SIG_SIZE];
    CK_ULONG flen = p11prov_obj_get_key_size(sigctx->key);
    CK_RV ret;
    int err;

    P11PROV_debug("ecdsa verify (ctx=%p)", ctx);

    err = convert_ecdsa_der_to_raw(sig, siglen, raw, sizeof(raw), flen);
    if (err != RET_OSSL_OK) {
        return err;
    }

    ret = p11prov_ecdsa_operate(sigctx, (void *)raw, NULL, 2 * flen,
                                (void *)tbs, tbslen);
    OPENSSL_cleanse(raw, 2 * flen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_ecdsa_digest_sign_init(void *ctx, const char *digest,
                                          void *provkey,
                                          const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug(
        "ecdsa digest sign init (ctx=%p, digest=%s, key=%p, params=%p)", ctx,
        digest ? digest : "<NULL>", provkey, params);

    /* use a default of sha2 256 if not provided */
    if (!digest) {
        digest = "sha256";
    }

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, digest);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    sigctx->digest_op = true;

    return p11prov_ecdsa_set_ctx_params(ctx, params);
}

static int p11prov_ecdsa_digest_sign_update(void *ctx,
                                            const unsigned char *data,
                                            size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("ecdsa digest sign update (ctx=%p, data=%p, datalen=%zu)",
                  ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    if (sigctx->mechanism.mechanism == CK_UNAVAILABLE_INFORMATION) {
        int rv = p11prov_ecdsa_set_mechanism(sigctx);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_ecdsa_digest_sign_final(void *ctx, unsigned char *sig,
                                           size_t *siglen, size_t sigsize)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    unsigned char raw[P11PROV_MAX_RAW_ECC_SIG_SIZE];
    size_t rawlen = 0;
    int ret;

    if (siglen == NULL) {
        return RET_OSSL_ERR;
    }

    /* the siglen might be uninitialized when called from openssl */
    *siglen = 0;

    P11PROV_debug("ecdsa digest sign final (ctx=%p, sig=%p, siglen=%zu, "
                  "sigsize=%zu)",
                  ctx, sig, *siglen, sigsize);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (sig == NULL) {
        ret = p11prov_ecdsa_sig_size(sigctx, siglen);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        return RET_OSSL_OK;
    }
    if (sigsize == 0) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_sig_digest_final(sigctx, raw, &rawlen, sizeof(raw));
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    ret = convert_ecdsa_raw_to_der(raw, rawlen, sig, siglen, sigsize);
    OPENSSL_cleanse(raw, rawlen);
    return ret;
}

static int p11prov_ecdsa_digest_verify_init(void *ctx, const char *digest,
                                            void *provkey,
                                            const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("ecdsa digest verify init (ctx=%p, key=%p, params=%p)", ctx,
                  provkey, params);

    /* use a default of sha2 256 if not provided */
    if (!digest) {
        digest = "sha256";
    }

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, digest);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    sigctx->digest_op = true;

    return p11prov_ecdsa_set_ctx_params(ctx, params);
}

static int p11prov_ecdsa_digest_verify_update(void *ctx,
                                              const unsigned char *data,
                                              size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("ecdsa digest verify update (ctx=%p, data=%p, datalen=%zu)",
                  ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    if (sigctx->mechanism.mechanism == CK_UNAVAILABLE_INFORMATION) {
        int rv = p11prov_ecdsa_set_mechanism(sigctx);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_ecdsa_digest_verify_final(void *ctx,
                                             const unsigned char *sig,
                                             size_t siglen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    unsigned char raw[P11PROV_MAX_RAW_ECC_SIG_SIZE];
    CK_ULONG flen;
    int ret;

    P11PROV_debug("ecdsa digest verify final (ctx=%p, sig=%p, siglen=%zu)", ctx,
                  sig, siglen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    flen = p11prov_obj_get_key_size(sigctx->key);

    ret = convert_ecdsa_der_to_raw(sig, siglen, raw, sizeof(raw), flen);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    ret = p11prov_sig_digest_final(sigctx, (void *)raw, NULL, 2 * flen);
    OPENSSL_cleanse(raw, 2 * flen);
    return ret;
}

#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
static const char **p11prov_ecdsa_query_key_types(void)
{
    static const char *keytypes[] = { "EC", NULL };

    return keytypes;
}

static int p11prov_ecdsa_sign_message_update(void *ctx,
                                             const unsigned char *data,
                                             size_t datalen)
{
    return p11prov_ecdsa_digest_sign_update(ctx, data, datalen);
}

static int p11prov_ecdsa_sign_message_final(void *ctx, unsigned char *sig,
                                            size_t *siglen, size_t sigsize)
{
    return p11prov_ecdsa_digest_sign_final(ctx, sig, siglen, sigsize);
}

static int p11prov_ecdsa_verify_message_update(void *ctx,
                                               const unsigned char *data,
                                               size_t datalen)
{
    return p11prov_ecdsa_digest_verify_update(ctx, data, datalen);
}

static int p11prov_ecdsa_verify_message_final(void *ctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("ecdsa message verify final (ctx=%p)", ctx);

    if (sigctx == NULL || sigctx->signature == NULL) {
        P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                      "Signature not available on context");
        return RET_OSSL_ERR;
    }

    return p11prov_ecdsa_digest_verify_final(sigctx, sigctx->signature,
                                             sigctx->signature_len);
}
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */

static int p11prov_ecdsa_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    OSSL_PARAM *p;
    int ret;

    /* todo sig params:
        OSSL_SIGNATURE_PARAM_ALGORITHM_ID
     */

    P11PROV_debug("ecdsa get ctx params (ctx=%p, params=%p)", ctx, params);

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p) {
        struct ecdsa_data *data;
        data = ecdsa_digest_map(sigctx->digest);
        if (!data) {
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_octet_string(p, data->der, data->derlen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p) {
        size_t digest_size;
        CK_RV rv;

        rv = p11prov_digest_get_digest_size(sigctx->digest, &digest_size);
        if (rv != CKR_OK) {
            P11PROV_raise(sigctx->provctx, rv, "Unavailable digest size");
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_size_t(p, digest_size);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p) {
        const char *digest;
        CK_RV rv;

        rv = p11prov_digest_get_name(sigctx->digest, &digest);
        if (rv != CKR_OK) {
            P11PROV_raise(sigctx->provctx, rv, "Unavailable digest name");
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_utf8_string(p, digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

static int p11prov_ecdsa_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("ecdsa set ctx params (ctx=%p, params=%p)", sigctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p) {
        const char *digest = NULL;
        CK_RV rv;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        P11PROV_debug("Set OSSL_SIGNATURE_PARAM_DIGEST to %s", digest);

        rv = p11prov_digest_get_by_name(digest, &sigctx->digest);
        if (rv != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
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

static const OSSL_PARAM *p11prov_ecdsa_gettable_ctx_params(void *ctx,
                                                           void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
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
#if defined(OSSL_SIGNATURE_PARAM_SIGNATURE)
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0),
#endif
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

#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
#define DEFINE_ECDSA_SHA_SIG(alg, digest) \
    static int p11prov_ecdsa_##alg##_sign_message_init( \
        void *ctx, void *provkey, const OSSL_PARAM params[]) \
    { \
        return p11prov_ecdsa_digest_sign_init(ctx, digest, provkey, params); \
    } \
    static int p11prov_ecdsa_##alg##_verify_message_init( \
        void *ctx, void *provkey, const OSSL_PARAM params[]) \
    { \
        return p11prov_ecdsa_digest_verify_init(ctx, digest, provkey, params); \
    } \
    const OSSL_DISPATCH p11prov_ecdsa_##alg##_signature_functions[] = { \
        DISPATCH_SIG_ELEM(ecdsa, NEWCTX, newctx), \
        DISPATCH_SIG_ELEM(sig, FREECTX, freectx), \
        DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx), \
        DISPATCH_SIG_ELEM(ecdsa, SIGN_INIT, sign_init), \
        DISPATCH_SIG_ELEM(ecdsa, SIGN, sign), \
        DISPATCH_SIG_ELEM(ecdsa, VERIFY_INIT, verify_init), \
        DISPATCH_SIG_ELEM(ecdsa, VERIFY, verify), \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, \
          (void (*)(void))p11prov_ecdsa_##alg##_sign_message_init }, \
        DISPATCH_SIG_ELEM(ecdsa, SIGN_MESSAGE_UPDATE, sign_message_update), \
        DISPATCH_SIG_ELEM(ecdsa, SIGN_MESSAGE_FINAL, sign_message_final), \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, \
          (void (*)(void))p11prov_ecdsa_##alg##_verify_message_init }, \
        DISPATCH_SIG_ELEM(ecdsa, VERIFY_MESSAGE_UPDATE, \
                          verify_message_update), \
        DISPATCH_SIG_ELEM(ecdsa, VERIFY_MESSAGE_FINAL, verify_message_final), \
        DISPATCH_SIG_ELEM(ecdsa, QUERY_KEY_TYPES, query_key_types), \
        DISPATCH_SIG_ELEM(ecdsa, GET_CTX_PARAMS, get_ctx_params), \
        DISPATCH_SIG_ELEM(ecdsa, GETTABLE_CTX_PARAMS, gettable_ctx_params), \
        DISPATCH_SIG_ELEM(ecdsa, SET_CTX_PARAMS, set_ctx_params), \
        DISPATCH_SIG_ELEM(ecdsa, SETTABLE_CTX_PARAMS, settable_ctx_params), \
        { 0, NULL }, \
    }

DEFINE_ECDSA_SHA_SIG(sha1, "SHA1");
DEFINE_ECDSA_SHA_SIG(sha224, "SHA224");
DEFINE_ECDSA_SHA_SIG(sha256, "SHA256");
DEFINE_ECDSA_SHA_SIG(sha384, "SHA384");
DEFINE_ECDSA_SHA_SIG(sha512, "SHA512");
DEFINE_ECDSA_SHA_SIG(sha3_224, "SHA3-224");
DEFINE_ECDSA_SHA_SIG(sha3_256, "SHA3-256");
DEFINE_ECDSA_SHA_SIG(sha3_384, "SHA3-384");
DEFINE_ECDSA_SHA_SIG(sha3_512, "SHA3-512");
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */
