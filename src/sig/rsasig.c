/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "sig/internal.h"
#include <string.h>
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"
#include "openssl/err.h"

/* clang-format off */
#define DEFINE_DER_DIGESTINFO(name, alg_id, digest_size) \
    static const unsigned char der_digestinfo_##name[] = { \
        DER_SEQUENCE, DER_NIST_HASHALGS_LEN + 9 + digest_size, \
          DER_SEQUENCE, DER_NIST_HASHALGS_LEN + 5, \
            DER_OBJECT, DER_NIST_HASHALGS_LEN + 1, DER_NIST_HASHALGS, alg_id, \
            DER_NULL, 0, \
          DER_OCTET_STRING, digest_size \
    };

#define DEFINE_DER_RSA_PSS_PARAMS(name, obj_base, obj_alg, obj_len, digest_len) \
    static const unsigned char der_rsa_pss_params_##name[] = { \
        DER_SEQUENCE, 25 + DER_RSASSA_PSS_LEN + DER_MGF1_LEN + obj_len + obj_len, \
            DER_OBJECT, DER_RSASSA_PSS_LEN, DER_RSASSA_PSS, \
            DER_SEQUENCE, 21 + DER_MGF1_LEN + obj_len + obj_len, \
                0xA0, 4 + obj_len, \
                    DER_SEQUENCE, 2 + obj_len, \
                        DER_OBJECT, obj_len, obj_base, obj_alg, \
                0xA1, 8 + DER_MGF1_LEN + obj_len, \
                    DER_SEQUENCE, 6 + DER_MGF1_LEN + obj_len, \
                        DER_OBJECT, DER_MGF1_LEN, DER_MGF1, \
                        DER_SEQUENCE, 2 + obj_len, \
                            DER_OBJECT, obj_len, obj_base, obj_alg, \
                0xA2, 3, \
                    DER_INTEGER, 1, digest_len, \
    };

#define DEFINE_DER_SEQ_SHA(bits, rsa_algid, digestinfo_algid) \
    static const unsigned char der_rsa_sha##bits[] = { \
        DER_SEQUENCE, DER_RSADSI_PKCS1_LEN + 5, \
            DER_OBJECT, DER_RSADSI_PKCS1_LEN + 1, DER_RSADSI_PKCS1, rsa_algid, \
            DER_NULL, 0, \
    }; \
    DEFINE_DER_DIGESTINFO(sha##bits, digestinfo_algid, bits/8) \
    DEFINE_DER_RSA_PSS_PARAMS(sha##bits, DER_NIST_HASHALGS, digestinfo_algid, \
        DER_NIST_HASHALGS_LEN+1, SHA##bits##_DIGEST_LENGTH)

#define DEFINE_DER_SEQ_SHA3(bits, rsa_algid, digestinfo_algid) \
    static const unsigned char der_rsa_sha3_##bits[] = { \
        DER_SEQUENCE, DER_NIST_SIGALGS_LEN + 5, \
            DER_OBJECT, DER_NIST_SIGALGS_LEN + 1, DER_NIST_SIGALGS, rsa_algid, \
            DER_NULL, 0 \
    }; \
    DEFINE_DER_DIGESTINFO(sha3_##bits, digestinfo_algid, bits/8) \
    DEFINE_DER_RSA_PSS_PARAMS(sha3_##bits, DER_NIST_HASHALGS, digestinfo_algid, \
        DER_NIST_HASHALGS_LEN + 1, SHA##bits##_DIGEST_LENGTH)

/* ... pkcs(1) 10 (id-RSASSA-PSS) */
#define DER_RSASSA_PSS DER_RSADSI_PKCS1, 0x0A
#define DER_RSASSA_PSS_LEN (DER_RSADSI_PKCS1_LEN + 1)

/* ... pkcs(1) 8 (id-RSASSA-PSS) */
#define DER_MGF1 DER_RSADSI_PKCS1, 0x08
#define DER_MGF1_LEN (DER_RSADSI_PKCS1_LEN + 1)

static const unsigned char der_rsa_sha1[] = {
    DER_SEQUENCE, DER_RSADSI_PKCS1_LEN + 5,
        DER_OBJECT, DER_RSADSI_PKCS1_LEN + 1, DER_RSADSI_PKCS1, 0x05,
        DER_NULL, 0
};

/* iso(1) org(3) oiw(14) secsig(3) algorithms(2) */
#define DER_SECSIG_ALGO 1 * 40 + 3, 14, 3, 2
#define DER_SECSIG_ALGO_LEN 4
/* iso(1) org(3) oiw(14) secsig(3) algorithms(2) hashAlgorithmIdentifier(26) */
#define ID_SHA1 DER_SECSIG_ALGO, 26
#define ID_SHA1_LEN DER_SECSIG_ALGO_LEN + 1
static const unsigned char der_digestinfo_sha1[] = {
    DER_SEQUENCE, 0x0d + SHA_DIGEST_LENGTH,
        DER_SEQUENCE, 0x09,
        DER_OBJECT, ID_SHA1_LEN, ID_SHA1,
        DER_NULL, 0x00,
    DER_OCTET_STRING, SHA_DIGEST_LENGTH
};

DEFINE_DER_RSA_PSS_PARAMS(sha1, DER_SECSIG_ALGO, 26, DER_SECSIG_ALGO_LEN, SHA_DIGEST_LENGTH);
/* clang-format on */

DEFINE_DER_SEQ_SHA(512, 0x0D, 0x03);
DEFINE_DER_SEQ_SHA(384, 0x0C, 0x02);
DEFINE_DER_SEQ_SHA(256, 0x0B, 0x01);
DEFINE_DER_SEQ_SHA(224, 0x0E, 0x04);

DEFINE_DER_SEQ_SHA3(512, 0x10, 0x0A);
DEFINE_DER_SEQ_SHA3(384, 0x0F, 0x09);
DEFINE_DER_SEQ_SHA3(256, 0x0E, 0x08);
DEFINE_DER_SEQ_SHA3(224, 0x0D, 0x07);

#define DM_ELEM_SHA(bits) \
    { \
        .digest = CKM_SHA##bits, \
        .pkcs_mech = CKM_SHA##bits##_RSA_PKCS, \
        .pkcs_pss = CKM_SHA##bits##_RSA_PKCS_PSS, \
        .mgf = CKG_MGF1_SHA##bits, \
        .der_rsa_algorithm_id = der_rsa_sha##bits, \
        .der_rsa_algorithm_id_len = sizeof(der_rsa_sha##bits), \
        .der_digestinfo = der_digestinfo_sha##bits, \
        .der_digestinfo_len = sizeof(der_digestinfo_sha##bits), \
        .der_rsa_pss_params = der_rsa_pss_params_sha##bits, \
        .der_rsa_pss_params_len = sizeof(der_rsa_pss_params_sha##bits), \
    }
#define DM_ELEM_SHA3(bits) \
    { \
        .digest = CKM_SHA3_##bits, \
        .pkcs_mech = CKM_SHA3_##bits##_RSA_PKCS, \
        .pkcs_pss = CKM_SHA3_##bits##_RSA_PKCS_PSS, \
        .mgf = CKG_MGF1_SHA3_##bits, \
        .der_rsa_algorithm_id = der_rsa_sha3_##bits, \
        .der_rsa_algorithm_id_len = sizeof(der_rsa_sha3_##bits), \
        .der_digestinfo = der_digestinfo_sha3_##bits, \
        .der_digestinfo_len = sizeof(der_digestinfo_sha3_##bits), \
        .der_rsa_pss_params = der_rsa_pss_params_sha3_##bits, \
        .der_rsa_pss_params_len = sizeof(der_rsa_pss_params_sha3_##bits), \
    }

struct rsasig_data {
    CK_MECHANISM_TYPE digest;
    CK_MECHANISM_TYPE pkcs_mech;
    CK_MECHANISM_TYPE pkcs_pss;
    CK_RSA_PKCS_MGF_TYPE mgf;
    const void *der_rsa_algorithm_id;
    size_t der_rsa_algorithm_id_len;
    const void *der_digestinfo;
    size_t der_digestinfo_len;
    const void *der_rsa_pss_params;
    size_t der_rsa_pss_params_len;
} rsasig_mech_map[] = {
    {
        CKM_SHA_1,
        CKM_SHA1_RSA_PKCS,
        CKM_SHA1_RSA_PKCS_PSS,
        CKG_MGF1_SHA1,
        der_rsa_sha1,
        sizeof(der_rsa_sha1),
        der_digestinfo_sha1,
        sizeof(der_digestinfo_sha1),
        der_rsa_pss_params_sha1,
        sizeof(der_rsa_pss_params_sha1),
    },
    DM_ELEM_SHA(224),
    DM_ELEM_SHA(256),
    DM_ELEM_SHA(384),
    DM_ELEM_SHA(512),
    DM_ELEM_SHA3(224),
    DM_ELEM_SHA3(256),
    DM_ELEM_SHA3(384),
    DM_ELEM_SHA3(512),
    { CK_UNAVAILABLE_INFORMATION, 0, 0, 0, NULL, 0, NULL, 0, NULL, 0 },
};

static struct rsasig_data *rsasig_digest_map(CK_MECHANISM_TYPE digest)
{
    for (int i = 0; rsasig_mech_map[i].digest != CK_UNAVAILABLE_INFORMATION;
         i++) {
        if (rsasig_mech_map[i].digest == digest) {
            return &rsasig_mech_map[i];
        }
    }
    return NULL;
}

static struct rsasig_data *rsasig_mgf_map(CK_MECHANISM_TYPE mgf)
{
    for (int i = 0; rsasig_mech_map[i].digest != CK_UNAVAILABLE_INFORMATION;
         i++) {
        if (rsasig_mech_map[i].mgf == mgf) {
            return &rsasig_mech_map[i];
        }
    }
    return NULL;
}

static struct rsasig_data *rsasig_pss_map(CK_MECHANISM_TYPE pssmech)
{
    for (int i = 0; rsasig_mech_map[i].digest != CK_UNAVAILABLE_INFORMATION;
         i++) {
        if (rsasig_mech_map[i].pkcs_pss == pssmech) {
            return &rsasig_mech_map[i];
        }
    }
    return NULL;
}

static const char *p11prov_sig_mgf_name(CK_RSA_PKCS_MGF_TYPE mgf)
{
    struct rsasig_data *data;
    const char *digest_name;
    CK_RV rv;

    data = rsasig_mgf_map(mgf);
    if (!data) {
        return NULL;
    }

    rv = p11prov_digest_get_name(data->digest, &digest_name);
    if (rv != CKR_OK) {
        return NULL;
    }

    return digest_name;
}

static CK_RSA_PKCS_MGF_TYPE p11prov_sig_map_mgf(const char *digest_name)
{
    CK_MECHANISM_TYPE digest;
    struct rsasig_data *data;
    CK_RV rv;

    rv = p11prov_digest_get_by_name(digest_name, &digest);
    if (rv != CKR_OK) {
        return CK_UNAVAILABLE_INFORMATION;
    }

    data = rsasig_digest_map(digest);
    if (!data) {
        return CK_UNAVAILABLE_INFORMATION;
    }

    return data->mgf;
}

static CK_RV p11prov_sig_pss_restrictions(P11PROV_SIG_CTX *sigctx,
                                          CK_MECHANISM_TYPE mechanism)
{
    CK_BBOOL token_supports_allowed_mechs = CK_TRUE;
    CK_ATTRIBUTE *allowed_mechs = NULL;
    CK_RV ret;

    /* check if token supports CKA_ALLOWED_MECHANISMS at all */
    ret = p11prov_token_sup_attr(
        sigctx->provctx, p11prov_obj_get_slotid(sigctx->key), GET_ATTR,
        CKA_ALLOWED_MECHANISMS, &token_supports_allowed_mechs);
    if (ret != CKR_OK) {
        P11PROV_raise(sigctx->provctx, ret,
                      "Failed to probe CKA_ALLOWED_MECHANISMS quirk");
        return ret;
    }
    if (token_supports_allowed_mechs == CK_FALSE) {
        /* Token does not support CKA_ALLOWED_MECHANISMS so there are no restrictions */
        return CKR_OK;
    }

    allowed_mechs = p11prov_obj_get_attr(sigctx->key, CKA_ALLOWED_MECHANISMS);
    if (allowed_mechs) {
        CK_ATTRIBUTE_TYPE *mechs = (CK_ATTRIBUTE_TYPE *)allowed_mechs->pValue;
        int num_mechs = allowed_mechs->ulValueLen / sizeof(CK_MECHANISM_TYPE);
        bool allowed = false;

        if (num_mechs == 0) {
            /* It makes no sense to return 0 allowed mechanisms for a key,
             * this just means the token is bogus, let's ignore the check
             * and try the operation and see what happens */
            P11PROV_debug("Buggy CKA_ALLOWED_MECHANISMS implementation");
            return CKR_OK;
        }

        for (int i = 0; i < num_mechs; i++) {
            if (mechs[i] == mechanism) {
                allowed = true;
                break;
            }
        }

        if (allowed) {
            return CKR_OK;
        }

        P11PROV_raise(sigctx->provctx, CKR_ACTION_PROHIBITED,
                      "mechanism not allowed with this key");
        return CKR_ACTION_PROHIBITED;
    }

    /* there are no restrictions on this key */
    return CKR_OK;
}

/* fixates pss_params based on defaults if values are not set */
static CK_RV pss_defaults(P11PROV_SIG_CTX *sigctx)
{
    struct rsasig_data *data;

    data = rsasig_digest_map(sigctx->digest);
    if (!data) {
        return CKR_MECHANISM_INVALID;
    }
    sigctx->pss_params.hashAlg = data->digest;
    if (sigctx->pss_params.mgf == 0) {
        sigctx->pss_params.mgf = data->mgf;
    }
    if (sigctx->pss_params.sLen == 0) {
        /* default to digest size if not set */
        size_t size;
        CK_RV ret;

        ret = p11prov_digest_get_digest_size(data->digest, &size);
        if (ret != CKR_OK) {
            return ret;
        }
        sigctx->pss_params.sLen = size;
    }

    return CKR_OK;
}

static int p11prov_rsasig_set_pss_saltlen_from_digest(void *ctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    size_t digest_size;
    CK_RV rv;

    if (sigctx->digest == 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "Can only be set if Digest was set first.");
        return RET_OSSL_ERR;
    }

    rv = p11prov_digest_get_digest_size(sigctx->digest, &digest_size);
    if (rv != CKR_OK) {
        P11PROV_raise(sigctx->provctx, rv, "Unavailable digest");
        return RET_OSSL_ERR;
    }

    sigctx->pss_params.sLen = digest_size;
    return RET_OSSL_OK;
}

static int p11prov_rsasig_set_pss_saltlen_max(void *ctx, bool max_to_digest)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    size_t digest_size;
    CK_ULONG key_size;
    CK_ULONG key_bit_size;
    CK_RV rv;

    if (sigctx->digest == 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "Can only be set if Digest was set first.");
        return RET_OSSL_ERR;
    }

    rv = p11prov_digest_get_digest_size(sigctx->digest, &digest_size);
    if (rv != CKR_OK) {
        P11PROV_raise(sigctx->provctx, rv, "Unavailable digest");
        return RET_OSSL_ERR;
    }

    key_size = p11prov_obj_get_key_size(sigctx->key);
    if (key_size == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(sigctx->provctx, rv, "Unavailable key");
        return RET_OSSL_ERR;
    }
    key_bit_size = p11prov_obj_get_key_bit_size(sigctx->key);
    if (key_bit_size == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(sigctx->provctx, rv, "Unavailable key");
        return RET_OSSL_ERR;
    }

    /* from openssl */
    sigctx->pss_params.sLen = key_size - digest_size - 2;
    if ((key_bit_size & 0x07) == 1) {
        sigctx->pss_params.sLen -= 1;
    }
    if (max_to_digest && sigctx->pss_params.sLen > digest_size) {
        sigctx->pss_params.sLen = digest_size;
    }
    return RET_OSSL_OK;
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
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
DISPATCH_RSASIG_FN(sign_message_update);
DISPATCH_RSASIG_FN(sign_message_final);
DISPATCH_RSASIG_FN(verify_message_update);
DISPATCH_RSASIG_FN(verify_message_final);
DISPATCH_RSASIG_FN(query_key_types);
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */
DISPATCH_RSASIG_FN(get_ctx_params);
DISPATCH_RSASIG_FN(set_ctx_params);
DISPATCH_RSASIG_FN(gettable_ctx_params);
DISPATCH_RSASIG_FN(settable_ctx_params);

static CK_RV p11prov_rsasig_set_mechanism(P11PROV_SIG_CTX *sigctx)
{
    struct rsasig_data *data = NULL;
    int rv;

    sigctx->mechanism.mechanism = sigctx->mechtype;
    sigctx->mechanism.pParameter = NULL;
    sigctx->mechanism.ulParameterLen = 0;

    if (sigctx->digest_op) {
        data = rsasig_digest_map(sigctx->digest);
        if (!data) {
            return CKR_MECHANISM_INVALID;
        }
    }

    switch (sigctx->mechtype) {
    case CKM_RSA_PKCS:
        if (sigctx->digest_op) {
            sigctx->mechanism.mechanism = data->pkcs_mech;
        }
        break;
    case CKM_RSA_X_509:
        break;
    case CKM_RSA_PKCS_PSS:
        rv = pss_defaults(sigctx);
        if (rv != CKR_OK) {
            return rv;
        }
        sigctx->mechanism.pParameter = &sigctx->pss_params;
        sigctx->mechanism.ulParameterLen = sizeof(sigctx->pss_params);
        if (sigctx->digest_op) {
            sigctx->mechanism.mechanism = data->pkcs_pss;
            rv = p11prov_sig_pss_restrictions(sigctx, data->pkcs_pss);
            if (rv != CKR_OK) {
                return rv;
            }
        }
        break;
    default:
        return CKR_DATA_INVALID;
    }

    return CKR_OK;
}

static CK_RV p11prov_rsa_sig_size(P11PROV_SIG_CTX *sigctx, size_t *siglen)
{
    CK_KEY_TYPE type = p11prov_obj_get_key_type(sigctx->key);
    if (type == CKK_RSA) {
        CK_ULONG size = p11prov_obj_get_key_size(sigctx->key);
        if (size != CK_UNAVAILABLE_INFORMATION) {
            *siglen = size;
            return CKR_OK;
        }
    }
    return CKR_KEY_INDIGESTIBLE;
}

static CK_RV p11prov_rsasig_encode_data(P11PROV_SIG_CTX *sigctx,
                                        unsigned char *data, size_t *datalen,
                                        unsigned char *tbs, size_t tbslen)
{
    struct rsasig_data *rsa_data;
    size_t digest_size = 0;
    CK_RV rv;

    rsa_data = rsasig_digest_map(sigctx->digest);
    if (!rsa_data) {
        ERR_raise(ERR_LIB_RSA, PROV_R_INVALID_DIGEST);
        return CKR_MECHANISM_INVALID;
    }
    rv = p11prov_digest_get_digest_size(sigctx->digest, &digest_size);
    if (rv != CKR_OK) {
        ERR_raise(ERR_LIB_RSA, PROV_R_INVALID_DIGEST);
        return rv;
    }
    if (tbslen != digest_size
        || tbslen + rsa_data->der_digestinfo_len >= *datalen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
        return CKR_SIGNATURE_LEN_RANGE;
    }
    memcpy(data, rsa_data->der_digestinfo, rsa_data->der_digestinfo_len);
    memcpy(data + rsa_data->der_digestinfo_len, tbs, tbslen);
    *datalen = tbslen + rsa_data->der_digestinfo_len;
    return CKR_OK;
}

static CK_RV p11prov_rsasig_operate(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                                    size_t *siglen, size_t sigsize,
                                    unsigned char *tbs, size_t tbslen)
{
    /* The 64 is the largest possible der_digestinfo prefix encoding */
    unsigned char data[EVP_MAX_MD_SIZE + 64];
    size_t datalen = sizeof(data);
    CK_RV rv;

    if (sigctx->operation == CKF_SIGN && sigctx->mechtype == CKM_RSA_X_509) {
        /* some tokens allow raw signatures on any data size.
         * Enforce data size is the same as modulus as that is
         * what OpenSSL expects and does internally in rsa_sign
         * when there is no padding. */
        if (tbslen < sigsize) {
            ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE);
            return CKR_DATA_LEN_RANGE;
        }
    }

    if (sigctx->mechtype == CKM_RSA_PKCS && sigctx->digest != 0) {
        rv = p11prov_rsasig_encode_data(sigctx, data, &datalen, tbs, tbslen);
        if (rv != CKR_OK) {
            return rv;
        }
        tbs = data;
        tbslen = datalen;
    }

    rv = p11prov_rsasig_set_mechanism(sigctx);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }

    rv = p11prov_sig_operate(sigctx, sig, siglen, sigsize, (void *)tbs, tbslen);
    if (tbs == data) {
        OPENSSL_cleanse(data, datalen);
    }

    return rv;
}

static void *p11prov_rsasig_newctx(void *provctx, const char *properties)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_SIG_CTX *sigctx;

    /* PKCS1.5 is the default, PSS set via padding params */
    sigctx = p11prov_sig_newctx(ctx, CKM_RSA_PKCS, properties);
    if (sigctx == NULL) {
        return NULL;
    }

    /* In case we need to fall back */
    sigctx->fallback_operate = &p11prov_rsasig_operate;

    return sigctx;
}

static int p11prov_rsasig_sign_init(void *ctx, void *provkey,
                                    const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("rsa sign init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_rsasig_set_ctx_params(ctx, params);
}

static int p11prov_rsasig_sign(void *ctx, unsigned char *sig, size_t *siglen,
                               size_t sigsize, const unsigned char *tbs,
                               size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("rsa sign (ctx=%p)", ctx);

    if (sig == NULL) {
        if (siglen == 0) {
            return RET_OSSL_ERR;
        }
        ret = p11prov_rsa_sig_size(sigctx, siglen);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        return RET_OSSL_OK;
    }

    ret = p11prov_rsasig_operate(sigctx, sig, siglen, sigsize, (void *)tbs,
                                 tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_rsasig_verify_init(void *ctx, void *provkey,
                                      const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("rsa verify init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_rsasig_set_ctx_params(ctx, params);
}

static int p11prov_rsasig_verify(void *ctx, const unsigned char *sig,
                                 size_t siglen, const unsigned char *tbs,
                                 size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("rsa verify (ctx=%p)", ctx);

    ret = p11prov_rsasig_operate(sigctx, (void *)sig, NULL, siglen, (void *)tbs,
                                 tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_rsasig_digest_sign_init(void *ctx, const char *digest,
                                           void *provkey,
                                           const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("rsa digest sign init (ctx=%p, digest=%s, key=%p, params=%p)",
                  ctx, digest ? digest : "<NULL>", provkey, params);

    /* use a default of sha2 256 if not provided */
    if (!digest) {
        digest = "sha256";
    }

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, digest);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    sigctx->digest_op = true;

    return p11prov_rsasig_set_ctx_params(ctx, params);
}

static int p11prov_rsasig_digest_sign_update(void *ctx,
                                             const unsigned char *data,
                                             size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("rsa digest sign update (ctx=%p, data=%p, datalen=%zu)", ctx,
                  data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    if (sigctx->mechanism.mechanism == CK_UNAVAILABLE_INFORMATION) {
        int rv = p11prov_rsasig_set_mechanism(sigctx);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_rsasig_digest_sign_final(void *ctx, unsigned char *sig,
                                            size_t *siglen, size_t sigsize)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    if (siglen == NULL) {
        return RET_OSSL_ERR;
    }

    /* the siglen might be uninitialized when called from openssl */
    *siglen = 0;

    P11PROV_debug("rsa digest sign final (ctx=%p, sig=%p, siglen=%zu, "
                  "sigsize=%zu)",
                  ctx, sig, *siglen, sigsize);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (sig == NULL) {
        ret = p11prov_rsa_sig_size(sigctx, siglen);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        return RET_OSSL_OK;
    }
    if (sigsize == 0) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_final(sigctx, sig, siglen, sigsize);
}

static int p11prov_rsasig_digest_verify_init(void *ctx, const char *digest,
                                             void *provkey,
                                             const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("rsa digest verify init (ctx=%p, key=%p, params=%p)", ctx,
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

    return p11prov_rsasig_set_ctx_params(ctx, params);
}

static int p11prov_rsasig_digest_verify_update(void *ctx,
                                               const unsigned char *data,
                                               size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("rsa digest verify update (ctx=%p, data=%p, datalen=%zu)",
                  ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    if (sigctx->mechanism.mechanism == CK_UNAVAILABLE_INFORMATION) {
        int rv = p11prov_rsasig_set_mechanism(sigctx);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_rsasig_digest_verify_final(void *ctx,
                                              const unsigned char *sig,
                                              size_t siglen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("rsa digest verify final (ctx=%p, sig=%p, siglen=%zu)", ctx,
                  sig, siglen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_final(sigctx, (void *)sig, NULL, siglen);
}

#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
static const char **p11prov_rsasig_query_key_types(void)
{
    static const char *keytypes[] = { "RSA", NULL };

    return keytypes;
}

static int p11prov_rsasig_sign_message_update(void *ctx,
                                              const unsigned char *data,
                                              size_t datalen)
{
    return p11prov_rsasig_digest_sign_update(ctx, data, datalen);
}

static int p11prov_rsasig_sign_message_final(void *ctx, unsigned char *sig,
                                             size_t *siglen, size_t sigsize)
{
    return p11prov_rsasig_digest_sign_final(ctx, sig, siglen, sigsize);
}

static int p11prov_rsasig_verify_message_update(void *ctx,
                                                const unsigned char *data,
                                                size_t datalen)
{
    return p11prov_rsasig_digest_verify_update(ctx, data, datalen);
}

static int p11prov_rsasig_verify_message_final(void *ctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("rsa message verify final (ctx=%p)", ctx);

    if (sigctx == NULL || sigctx->signature == NULL) {
        P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                      "Signature not available on context");
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_final(sigctx, sigctx->signature, NULL,
                                    sigctx->signature_len);
}
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */

static struct {
    CK_MECHANISM_TYPE type;
    int ossl_id;
    const char *string;
} padding_map[] = {
    { CKM_RSA_X_509, RSA_NO_PADDING, OSSL_PKEY_RSA_PAD_MODE_NONE },
    { CKM_RSA_PKCS, RSA_PKCS1_PADDING, OSSL_PKEY_RSA_PAD_MODE_PKCSV15 },
    { CKM_RSA_X9_31, RSA_X931_PADDING, OSSL_PKEY_RSA_PAD_MODE_X931 },
    { CKM_RSA_PKCS_PSS, RSA_PKCS1_PSS_PADDING, OSSL_PKEY_RSA_PAD_MODE_PSS },
    { CK_UNAVAILABLE_INFORMATION, 0, NULL },
};

static unsigned char *
p11prov_encode_rsa_pss_algorithm_id(CK_MECHANISM_TYPE digest, int saltlen,
                                    size_t *outlen)
{
    unsigned char *buffer = NULL;
    struct rsasig_data *data;

    data = rsasig_digest_map(digest);
    if (!data) {
        return NULL;
    }

    buffer = OPENSSL_malloc(data->der_rsa_pss_params_len);
    if (buffer == NULL) {
        return NULL;
    }

    memcpy(buffer, data->der_rsa_pss_params, data->der_rsa_pss_params_len);
    *outlen = data->der_rsa_pss_params_len;
    /* The last byte of Algorithm Identifier is the salt length, which is
     * not hardcoded and needs to be fitted here */
    buffer[data->der_rsa_pss_params_len - 1] = saltlen;
    return buffer;
}

static unsigned char *
p11prov_rsapss_encode_algorithm_id(P11PROV_SIG_CTX *sigctx, size_t *outlen)
{
    struct rsasig_data *data, *mgf_data;
    int ret;

    /* when OpenSSL calls this before it makes the signature, we still might not
     * have the defaults set so do it now */
    ret = pss_defaults(sigctx);
    if (ret != CKR_OK) {
        P11PROV_raise(sigctx->provctx, ret, "Failed to set PSS defaults");
        goto err;
    }

    data = rsasig_digest_map(sigctx->pss_params.hashAlg);
    if (!data) {
        P11PROV_raise(sigctx->provctx, CKR_MECHANISM_PARAM_INVALID,
                      "Failed to get mech for digest %lx",
                      sigctx->pss_params.hashAlg);
        goto err;
    }

    mgf_data = rsasig_mgf_map(sigctx->pss_params.mgf);
    if (!mgf_data) {
        P11PROV_raise(sigctx->provctx, CKR_MECHANISM_PARAM_INVALID,
                      "Failed to get mech for mgf %lx", sigctx->pss_params.mgf);
        goto err;
    }
    /* Here we assume that the hashAlg and mgf1 hash algorithms are the same.
     * If not, it will need some more love */
    if (data != mgf_data) {
        P11PROV_raise(sigctx->provctx, CKR_GENERAL_ERROR,
                      "Inconsistent digest (%lx) and mgf1 (%lx) combination",
                      sigctx->pss_params.hashAlg, sigctx->pss_params.mgf);
        goto err;
    }

    return p11prov_encode_rsa_pss_algorithm_id(sigctx->pss_params.hashAlg,
                                               sigctx->pss_params.sLen, outlen);

err:
    return NULL;
}

static int p11prov_rsasig_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    OSSL_PARAM *p;
    int ret;

    P11PROV_debug("rsasig get ctx params (ctx=%p, params=%p)", ctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p) {
        unsigned char *algorithm_id = NULL;
        struct rsasig_data *data;
        size_t len;

        switch (sigctx->mechtype) {
        case CKM_RSA_PKCS:
            data = rsasig_digest_map(sigctx->digest);
            if (!data) {
                P11PROV_raise(
                    sigctx->provctx, CKR_MECHANISM_INVALID,
                    "Failed to get digest for signature algorithm ID");
                return RET_OSSL_ERR;
            }
            ret = OSSL_PARAM_set_octet_string(p, data->der_rsa_algorithm_id,
                                              data->der_rsa_algorithm_id_len);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
            break;
        case CKM_RSA_X_509:
            return RET_OSSL_ERR;
        case CKM_RSA_PKCS_PSS:
            /* The AlgorithmIdentifier here needs to contain also the
             * information about the RSA-PSS parameters as defined in
             * https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.2.3 */
            algorithm_id = p11prov_rsapss_encode_algorithm_id(sigctx, &len);
            if (algorithm_id == NULL) {
                P11PROV_raise(sigctx->provctx, CKR_GENERAL_ERROR,
                              "Failed to encode algorithm ID for RSA-PSS");
                return RET_OSSL_ERR;
            }
            ret = OSSL_PARAM_set_octet_string(p, algorithm_id, len);
            OPENSSL_free(algorithm_id);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
            break;
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
        const char *digest = NULL;
        CK_RV rv = CKR_GENERAL_ERROR;

        if (sigctx->pss_params.mgf != 0) {
            digest = p11prov_sig_mgf_name(sigctx->pss_params.mgf);
        } else {
            struct rsasig_data *data;
            data = rsasig_pss_map(sigctx->mechtype);
            if (data) {
                rv = p11prov_digest_get_name(data->digest, &digest);
                if (rv != CKR_OK) {
                    digest = NULL;
                }
            }
        }
        if (!digest) {
            P11PROV_raise(sigctx->provctx, rv, "Failed to get digest for MGF1");
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_utf8_string(p, digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

/* only available in recent OpenSSL 3.0.x headers */
#ifndef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
#define RSA_PSS_SALTLEN_AUTO_DIGEST_MAX -4
#endif
#ifndef OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX
#define OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX "auto-digestmax"
#endif

static int rsasig_set_saltlen(P11PROV_SIG_CTX *sigctx, int saltlen)
{
    if (saltlen >= 0) {
        sigctx->pss_params.sLen = saltlen;
        return RET_OSSL_OK;
    }
    if (saltlen == RSA_PSS_SALTLEN_DIGEST) {
        return p11prov_rsasig_set_pss_saltlen_from_digest(sigctx);
    }
    if (saltlen == RSA_PSS_SALTLEN_AUTO || saltlen == RSA_PSS_SALTLEN_MAX) {
        return p11prov_rsasig_set_pss_saltlen_max(sigctx, false);
    }
    if (saltlen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX) {
        return p11prov_rsasig_set_pss_saltlen_max(sigctx, true);
    }
    return RET_OSSL_ERR;
}

static int p11prov_rsasig_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("rsasig set ctx params (ctx=%p, params=%p)", sigctx, params);

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

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p) {
        CK_MECHANISM_TYPE mechtype = CK_UNAVAILABLE_INFORMATION;
        CK_SLOT_ID slotid = p11prov_obj_get_slotid(sigctx->key);

        /* If the object is imported, use the default slot */
        if (slotid == CK_UNAVAILABLE_INFORMATION) {
            P11PROV_SLOTS_CTX *slots = p11prov_ctx_get_slots(sigctx->provctx);
            if (!slots) {
                return RET_OSSL_ERR;
            }
            slotid = p11prov_get_default_slot(slots);
        }
        if (p->data_type == OSSL_PARAM_INTEGER) {
            int pad_mode;
            /* legacy pad mode number */
            ret = OSSL_PARAM_get_int(p, &pad_mode);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
            P11PROV_debug("Set OSSL_SIGNATURE_PARAM_PAD_MODE to %d", pad_mode);
            for (int i = 0; padding_map[i].string != NULL; i++) {
                if (padding_map[i].ossl_id == pad_mode) {
                    mechtype = padding_map[i].type;
                    break;
                }
            }
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            P11PROV_debug("Set OSSL_SIGNATURE_PARAM_PAD_MODE to %s",
                          p->data ? (const char *)p->data : "<NULL>");
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

        if (mechtype == CKM_RSA_PKCS_PSS) {
            /* some modules do not support PSS so we need to return
             * an error early if we try to select this. Unfortunately
             * although openssl has separate keymgmt for PKCS vs PSS
             * padding, it consider RSA always capable to be performed
             * regardless, and this is not the case in PKCS#11 */
            CK_RV rv;

            rv = p11prov_check_mechanism(sigctx->provctx, slotid,
                                         CKM_RSA_PKCS_PSS);
            if (rv != CKR_OK) {
                P11PROV_raise(sigctx->provctx, rv,
                              "CKM_RSA_PKCS_PSS unavailable");
                return RET_OSSL_ERR;
            }
        }

        sigctx->mechtype = mechtype;

        P11PROV_debug_mechanism(sigctx->provctx, slotid, sigctx->mechtype);
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
            P11PROV_debug("Set OSSL_SIGNATURE_PARAM_PSS_SALTLEN to %d",
                          saltlen);
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            P11PROV_debug("Set OSSL_SIGNATURE_PARAM_PSS_SALTLEN to %s",
                          p->data ? (const char *)p->data : "<NULL>");
            if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0) {
                saltlen = RSA_PSS_SALTLEN_DIGEST;
            } else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0) {
                saltlen = RSA_PSS_SALTLEN_MAX;
            } else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0) {
                saltlen = RSA_PSS_SALTLEN_AUTO;
            } else if (strcmp(p->data,
                              OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX)
                       == 0) {
                saltlen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
            } else {
                saltlen = atoi(p->data);
            }
        } else {
            return RET_OSSL_ERR;
        }
        ret = rsasig_set_saltlen(sigctx, saltlen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p) {
        const char *digest = NULL;
        ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        P11PROV_debug("Set OSSL_SIGNATURE_PARAM_MGF1_DIGEST to %s", digest);

        sigctx->pss_params.mgf = p11prov_sig_map_mgf(digest);
        if (sigctx->pss_params.mgf == CK_UNAVAILABLE_INFORMATION) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MGF1_MD);
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

static const OSSL_PARAM *p11prov_rsasig_gettable_ctx_params(void *ctx,
                                                            void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
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
#if defined(OSSL_SIGNATURE_PARAM_SIGNATURE)
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0),
#endif
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

#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
#define DEFINE_RSA_SHA_SIG(alg, digest) \
    static int p11prov_rsasig_##alg##_sign_message_init( \
        void *ctx, void *provkey, const OSSL_PARAM params[]) \
    { \
        return p11prov_rsasig_digest_sign_init(ctx, digest, provkey, params); \
    } \
    static int p11prov_rsasig_##alg##_verify_message_init( \
        void *ctx, void *provkey, const OSSL_PARAM params[]) \
    { \
        return p11prov_rsasig_digest_verify_init(ctx, digest, provkey, \
                                                 params); \
    } \
    const OSSL_DISPATCH p11prov_rsa_##alg##_signature_functions[] = { \
        DISPATCH_SIG_ELEM(rsasig, NEWCTX, newctx), \
        DISPATCH_SIG_ELEM(sig, FREECTX, freectx), \
        DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx), \
        DISPATCH_SIG_ELEM(rsasig, SIGN_INIT, sign_init), \
        DISPATCH_SIG_ELEM(rsasig, SIGN, sign), \
        DISPATCH_SIG_ELEM(rsasig, VERIFY_INIT, verify_init), \
        DISPATCH_SIG_ELEM(rsasig, VERIFY, verify), \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, \
          (void (*)(void))p11prov_rsasig_##alg##_sign_message_init }, \
        DISPATCH_SIG_ELEM(rsasig, SIGN_MESSAGE_UPDATE, sign_message_update), \
        DISPATCH_SIG_ELEM(rsasig, SIGN_MESSAGE_FINAL, sign_message_final), \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, \
          (void (*)(void))p11prov_rsasig_##alg##_verify_message_init }, \
        DISPATCH_SIG_ELEM(rsasig, VERIFY_MESSAGE_UPDATE, \
                          verify_message_update), \
        DISPATCH_SIG_ELEM(rsasig, VERIFY_MESSAGE_FINAL, verify_message_final), \
        DISPATCH_SIG_ELEM(rsasig, QUERY_KEY_TYPES, query_key_types), \
        DISPATCH_SIG_ELEM(rsasig, GET_CTX_PARAMS, get_ctx_params), \
        DISPATCH_SIG_ELEM(rsasig, GETTABLE_CTX_PARAMS, gettable_ctx_params), \
        DISPATCH_SIG_ELEM(rsasig, SET_CTX_PARAMS, set_ctx_params), \
        DISPATCH_SIG_ELEM(rsasig, SETTABLE_CTX_PARAMS, settable_ctx_params), \
        { 0, NULL }, \
    }

DEFINE_RSA_SHA_SIG(sha1, "SHA1");
DEFINE_RSA_SHA_SIG(sha224, "SHA224");
DEFINE_RSA_SHA_SIG(sha256, "SHA256");
DEFINE_RSA_SHA_SIG(sha384, "SHA384");
DEFINE_RSA_SHA_SIG(sha512, "SHA512");
DEFINE_RSA_SHA_SIG(sha3_224, "SHA3-224");
DEFINE_RSA_SHA_SIG(sha3_256, "SHA3-256");
DEFINE_RSA_SHA_SIG(sha3_384, "SHA3-384");
DEFINE_RSA_SHA_SIG(sha3_512, "SHA3-512");
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */

CK_MECHANISM_TYPE p11prov_digest_to_rsapss_mech(CK_MECHANISM_TYPE digest)
{
    struct rsasig_data *data;

    data = rsasig_digest_map(digest);
    if (!data) {
        return CK_UNAVAILABLE_INFORMATION;
    }

    return data->pkcs_pss;
}
