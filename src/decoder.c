/* Copyright (C) 2023 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0
*/

#include "provider.h"
#include "decoder.h"
#include "store.h"
#include "util.h"
#include "pk11_uri.h"
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/core.h>

#define RET_OSSL_CARRY_ON_DECODING 1

typedef struct p11prov_decoder_ctx {
    P11PROV_CTX *provctx;
} P11PROV_DECODER_CTX;

static void *p11prov_decoder_newctx(void *provctx)
{
    P11PROV_DECODER_CTX *dctx;
    dctx = OPENSSL_zalloc(sizeof(P11PROV_DECODER_CTX));
    if (!dctx) {
        return NULL;
    }

    dctx->provctx = provctx;
    return dctx;
}

static void p11prov_decoder_freectx(void *ctx)
{
    OPENSSL_clear_free(ctx, sizeof(P11PROV_DECODER_CTX));
}

static int obj_desc_verify(P11PROV_PK11_URI *obj)
{
    const char *desc = NULL;
    int desc_len;
    desc = (const char *)ASN1_STRING_get0_data(obj->desc);
    desc_len = ASN1_STRING_length(obj->desc);
    if (!desc || desc_len <= 0) {
        P11PROV_debug("Failed to get description");
        return RET_OSSL_ERR;
    }

    if (desc_len != (sizeof(P11PROV_DESCS_URI_FILE) - 1)
        || 0 != strncmp(desc, P11PROV_DESCS_URI_FILE, desc_len)) {
        P11PROV_debug("Description string does not match");
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static char *obj_uri_get1(P11PROV_PK11_URI *obj)
{
    unsigned char *uri = NULL;
    char *ret = NULL;

    if (obj->uri == NULL) {
        return NULL;
    }
    int uri_len = ASN1_STRING_length(obj->uri);
    if (uri_len <= 0) {
        goto done;
    }
    uri = OPENSSL_malloc(uri_len + 1);
    if (uri == NULL) {
        goto done;
    }
    memcpy(uri, ASN1_STRING_get0_data(obj->uri), uri_len);
    uri[uri_len] = '\0';
    ret = p11prov_alloc_sprintf(uri_len, "%s", uri);
done:
    if (ret == NULL) {
        P11PROV_debug("Failed to extract URI");
    }
    OPENSSL_free(uri);
    return ret;
}

struct desired_data_type_cbdata {
    const char *desired_data_type;
    OSSL_CALLBACK *cb;
    void *cbarg;
};

static int filter_for_desired_data_type(const OSSL_PARAM params[], void *arg)
{
    struct desired_data_type_cbdata *cbdata = arg;
    const OSSL_PARAM *p =
        OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_TYPE);
    const char *data_type = NULL;

    if (p && OSSL_PARAM_get_utf8_string_ptr(p, &data_type)
        && 0 == strcmp(cbdata->desired_data_type, data_type)) {
        return cbdata->cb(params, cbdata->cbarg);
    }

    return RET_OSSL_CARRY_ON_DECODING;
}

static int load_obj(const P11PROV_DECODER_CTX *ctx, const unsigned char *der,
                    long der_len, struct desired_data_type_cbdata *cbdata,
                    OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    P11PROV_PK11_URI *obj = NULL;
    char *uri = NULL;

    obj = d2i_P11PROV_PK11_URI(NULL, &der, der_len);
    if (!obj) {
        P11PROV_debug("P11 KEY DECODER d2i_P11PROV_PK11_URI failed");
        goto done;
    }

    if (!obj_desc_verify(obj)) {
        goto done;
    }

    uri = obj_uri_get1(obj);
    if (!uri) {
        goto done;
    }

    p11prov_store_direct_fetch(ctx->provctx, uri, filter_for_desired_data_type,
                               cbdata, pw_cb, pw_cbarg);
done:
    OPENSSL_free(uri);
    P11PROV_PK11_URI_free(obj);
    return RET_OSSL_CARRY_ON_DECODING;
}

static int p11prov_der_decoder_p11prov_obj_decode(
    const char *desired_data_type, void *inctx, OSSL_CORE_BIO *cin,
    int selection, OSSL_CALLBACK *object_cb, void *object_cbarg,
    OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    const P11PROV_DECODER_CTX *ctx = inctx;
    BIO *bin;
    unsigned char *der = NULL;
    long der_len;
    int ret = RET_OSSL_CARRY_ON_DECODING;

    bin = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cin);
    if (!bin) {
        P11PROV_debug("P11 DECODER BIO_new_from_core_bio failed");
        goto done;
    }

    der_len = BIO_get_mem_data(bin, &der);
    if (der_len <= 0) {
        P11PROV_debug("P11 DECODER BIO_get_mem_data failed");
        goto done;
    }

    struct desired_data_type_cbdata cbdata = {
        .desired_data_type = desired_data_type,
        .cb = object_cb,
        .cbarg = object_cbarg,
    };

    ret = load_obj(ctx, der, der_len, &cbdata, pw_cb, pw_cbarg);

done:
    BIO_free(bin);
    P11PROV_debug("der decoder (carry on:%d)", ret);
    return ret;
}

static int p11prov_pem_decoder_p11prov_der_decode(
    void *inctx, OSSL_CORE_BIO *cin, int selection, OSSL_CALLBACK *object_cb,
    void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{

    BIO *bin;
    char *pem_label;
    char *pem_header;
    unsigned char *der_data;
    long der_len;
    OSSL_PARAM params[3];
    int ret = RET_OSSL_CARRY_ON_DECODING;
    P11PROV_DECODER_CTX *ctx = inctx;

    bin = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cin);
    if (!bin) {
        P11PROV_debug("BIO_new_from_core_bio failed");
        return RET_OSSL_CARRY_ON_DECODING;
    }

    P11PROV_debug("PEM_read_bio (fpos:%u)", BIO_tell(bin));

    if (PEM_read_bio(bin, &pem_label, &pem_header, &der_data, &der_len) > 0
        && strcmp(pem_label, P11PROV_PEM_LABEL) == 0) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                      der_data, der_len);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_STRUCTURE, (char *)P11PROV_DER_STRUCTURE, 0);
        params[2] = OSSL_PARAM_construct_end();
        ret = object_cb(params, object_cbarg);
    }

    OPENSSL_free(pem_label);
    OPENSSL_free(pem_header);
    OPENSSL_free(der_data);
    BIO_free(bin);

    P11PROV_debug("pem decoder (carry on:%d)", ret);
    return ret;
}

#define P11PROV_DER_COMMON_DECODE_FN(FORMAT_NAME, format) \
    static int p11prov_der_decoder_p11prov_##format##_decode( \
        void *inctx, OSSL_CORE_BIO *cin, int selection, \
        OSSL_CALLBACK *object_cb, void *object_cbarg, \
        OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg) \
    { \
        return p11prov_der_decoder_p11prov_obj_decode( \
            FORMAT_NAME, inctx, cin, selection, object_cb, object_cbarg, \
            pw_cb, pw_cbarg); \
    }

P11PROV_DER_COMMON_DECODE_FN(P11PROV_NAME_RSA, rsa)
P11PROV_DER_COMMON_DECODE_FN(P11PROV_NAME_EC, ec)
P11PROV_DER_COMMON_DECODE_FN(P11PROV_NAME_ED25519, ed25519)
P11PROV_DER_COMMON_DECODE_FN(P11PROV_NAME_ED448, ed448)
P11PROV_DER_COMMON_DECODE_FN(P11PROV_NAME_X25519, x25519)
P11PROV_DER_COMMON_DECODE_FN(P11PROV_NAME_X448, x448)

P11PROV_DER_COMMON_DECODE_FN("ML-DSA-44", ml_dsa_44)
P11PROV_DER_COMMON_DECODE_FN("ML-DSA-65", ml_dsa_65)
P11PROV_DER_COMMON_DECODE_FN("ML-DSA-87", ml_dsa_87)
P11PROV_DER_COMMON_DECODE_FN("ML-KEM-512", ml_kem_512)
P11PROV_DER_COMMON_DECODE_FN("ML-KEM-768", ml_kem_768)
P11PROV_DER_COMMON_DECODE_FN("ML-KEM-1024", ml_kem_1024)
P11PROV_DER_COMMON_DECODE_FN("SLH-DSA-SHA2-128s", slh_dsa_sha2_128s)
P11PROV_DER_COMMON_DECODE_FN("SLH-DSA-SHA2-128f", slh_dsa_sha2_128f)
P11PROV_DER_COMMON_DECODE_FN("SLH-DSA-SHA2-192s", slh_dsa_sha2_192s)
P11PROV_DER_COMMON_DECODE_FN("SLH-DSA-SHA2-192f", slh_dsa_sha2_192f)
P11PROV_DER_COMMON_DECODE_FN("SLH-DSA-SHA2-256s", slh_dsa_sha2_256s)
P11PROV_DER_COMMON_DECODE_FN("SLH-DSA-SHA2-256f", slh_dsa_sha2_256f)
P11PROV_DER_COMMON_DECODE_FN("SLH-DSA-SHAKE-128s", slh_dsa_shake_128s)
P11PROV_DER_COMMON_DECODE_FN("SLH-DSA-SHAKE-128f", slh_dsa_shake_128f)
P11PROV_DER_COMMON_DECODE_FN("SLH-DSA-SHAKE-192s", slh_dsa_shake_192s)
P11PROV_DER_COMMON_DECODE_FN("SLH-DSA-SHAKE-192f", slh_dsa_shake_192f)
P11PROV_DER_COMMON_DECODE_FN("SLH-DSA-SHAKE-256s", slh_dsa_shake_256s)
P11PROV_DER_COMMON_DECODE_FN("SLH-DSA-SHAKE-256f", slh_dsa_shake_256f)

#define DISPATCH_BASE_DECODER_ELEM(NAME, name) \
    { OSSL_FUNC_DECODER_##NAME, (void (*)(void))p11prov_decoder_##name }
#define DISPATCH_DECODER_ELEM(NAME, type, structure, format, name) \
    { OSSL_FUNC_DECODER_##NAME, \
      (void (*)( \
          void))p11prov_##type##_decoder_##structure##_##format##_##name }
#define DISPATCH_DECODER_FN_LIST(type, structure, format) \
    const OSSL_DISPATCH \
        p11prov_##type##_decoder_##structure##_##format##_functions[] = { \
            DISPATCH_BASE_DECODER_ELEM(NEWCTX, newctx), \
            DISPATCH_BASE_DECODER_ELEM(FREECTX, freectx), \
            DISPATCH_DECODER_ELEM(DECODE, type, structure, format, decode), \
            { 0, NULL } \
        };

DISPATCH_DECODER_FN_LIST(pem, p11prov, der);
DISPATCH_DECODER_FN_LIST(der, p11prov, rsa);
DISPATCH_DECODER_FN_LIST(der, p11prov, ec);
DISPATCH_DECODER_FN_LIST(der, p11prov, ed25519);
DISPATCH_DECODER_FN_LIST(der, p11prov, ed448);
DISPATCH_DECODER_FN_LIST(der, p11prov, x25519);
DISPATCH_DECODER_FN_LIST(der, p11prov, x448);
DISPATCH_DECODER_FN_LIST(der, p11prov, ml_dsa_44);
DISPATCH_DECODER_FN_LIST(der, p11prov, ml_dsa_65);
DISPATCH_DECODER_FN_LIST(der, p11prov, ml_dsa_87);
DISPATCH_DECODER_FN_LIST(der, p11prov, ml_kem_512);
DISPATCH_DECODER_FN_LIST(der, p11prov, ml_kem_768);
DISPATCH_DECODER_FN_LIST(der, p11prov, ml_kem_1024);
DISPATCH_DECODER_FN_LIST(der, p11prov, slh_dsa_sha2_128s);
DISPATCH_DECODER_FN_LIST(der, p11prov, slh_dsa_sha2_128f);
DISPATCH_DECODER_FN_LIST(der, p11prov, slh_dsa_sha2_192s);
DISPATCH_DECODER_FN_LIST(der, p11prov, slh_dsa_sha2_192f);
DISPATCH_DECODER_FN_LIST(der, p11prov, slh_dsa_sha2_256s);
DISPATCH_DECODER_FN_LIST(der, p11prov, slh_dsa_sha2_256f);
DISPATCH_DECODER_FN_LIST(der, p11prov, slh_dsa_shake_128s);
DISPATCH_DECODER_FN_LIST(der, p11prov, slh_dsa_shake_128f);
DISPATCH_DECODER_FN_LIST(der, p11prov, slh_dsa_shake_192s);
DISPATCH_DECODER_FN_LIST(der, p11prov, slh_dsa_shake_192f);
DISPATCH_DECODER_FN_LIST(der, p11prov, slh_dsa_shake_256s);
DISPATCH_DECODER_FN_LIST(der, p11prov, slh_dsa_shake_256f);

enum p11prov_decoder_algorithms {
    P11PROV_DECODER_DER,
    P11PROV_DECODER_RSA,
    P11PROV_DECODER_RSAPSS,
    P11PROV_DECODER_EC,
    P11PROV_DECODER_ED25519,
    P11PROV_DECODER_ED448,
    P11PROV_DECODER_X25519,
    P11PROV_DECODER_X448,
    P11PROV_DECODER_ML_DSA_44,
    P11PROV_DECODER_ML_DSA_65,
    P11PROV_DECODER_ML_DSA_87,
    P11PROV_DECODER_ML_KEM_512,
    P11PROV_DECODER_ML_KEM_768,
    P11PROV_DECODER_ML_KEM_1024,
    P11PROV_DECODER_SLH_DSA_SHA2_128S,
    P11PROV_DECODER_SLH_DSA_SHA2_128F,
    P11PROV_DECODER_SLH_DSA_SHA2_192S,
    P11PROV_DECODER_SLH_DSA_SHA2_192F,
    P11PROV_DECODER_SLH_DSA_SHA2_256S,
    P11PROV_DECODER_SLH_DSA_SHA2_256F,
    P11PROV_DECODER_SLH_DSA_SHAKE_128S,
    P11PROV_DECODER_SLH_DSA_SHAKE_128F,
    P11PROV_DECODER_SLH_DSA_SHAKE_192S,
    P11PROV_DECODER_SLH_DSA_SHAKE_192F,
    P11PROV_DECODER_SLH_DSA_SHAKE_256S,
    P11PROV_DECODER_SLH_DSA_SHAKE_256F,
    P11PROV_DECODER_NUM_ALGS
};

#define P11PROV_NAMES_DER "DER"
#define P11PROV_DESCS_DER "DER decoder implementation in PKCS11 provider"

#define PEM_DECODER_PROP P11PROV_DEFAULT_PROPERTIES ",input=pem"
#define DER_DECODER_PROP \
    P11PROV_DEFAULT_PROPERTIES ",input=der,structure=" P11PROV_DER_STRUCTURE

#define PEM_DECODER_FIPS P11PROV_FIPS_PROPERTIES ",input=pem"
#define DER_DECODER_FIPS \
    P11PROV_FIPS_PROPERTIES ",input=der,structure=" P11PROV_DER_STRUCTURE

const OSSL_ALGORITHM decoder_algorithms[P11PROV_DECODER_NUM_ALGS] = {
    [P11PROV_DECODER_DER] = {
        P11PROV_NAMES_DER,
        PEM_DECODER_PROP,
        p11prov_pem_decoder_p11prov_der_functions,
        P11PROV_DESCS_DER,
    },
    [P11PROV_DECODER_RSA] = {
        P11PROV_NAME_RSA,
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_rsa_functions,
        "RSA decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_RSAPSS] = {
        P11PROV_NAME_RSAPSS,
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_rsa_functions,
        "RSA-PSS decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_EC] = {
        P11PROV_NAME_EC,
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_ec_functions,
        "EC decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_ED25519] = {
        P11PROV_NAME_ED25519,
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_ed25519_functions,
        "ED25519 decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_ED448] = {
        P11PROV_NAME_ED448,
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_ed448_functions,
        "ED448 decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_X25519] = {
        P11PROV_NAME_X25519,
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_x25519_functions,
        "X25519 decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_X448] = {
        P11PROV_NAME_X448,
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_x448_functions,
        "X448 decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_ML_DSA_44] = {
        "ML-DSA-44",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_ml_dsa_44_functions,
        "ML-DSA-44 decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_ML_DSA_65] = {
        "ML-DSA-65",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_ml_dsa_65_functions,
        "ML-DSA-65 decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_ML_DSA_87] = {
        "ML-DSA-87",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_ml_dsa_87_functions,
        "ML-DSA-87 decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_ML_KEM_512] = {
        "ML-KEM-512",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_ml_kem_512_functions,
        "ML-KEM-512 decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_ML_KEM_768] = {
        "ML-KEM-768",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_ml_kem_768_functions,
        "ML-KEM-768 decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_ML_KEM_1024] = {
        "ML-KEM-1024",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_ml_kem_1024_functions,
        "ML-KEM-1024 decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_SLH_DSA_SHA2_128S] = {
        "SLH-DSA-SHA2-128s",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_slh_dsa_sha2_128s_functions,
        "SLH-DSA-SHA2-128s decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_SLH_DSA_SHA2_128F] = {
        "SLH-DSA-SHA2-128f",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_slh_dsa_sha2_128f_functions,
        "SLH-DSA-SHA2-128f decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_SLH_DSA_SHA2_192S] = {
        "SLH-DSA-SHA2-192s",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_slh_dsa_sha2_192s_functions,
        "SLH-DSA-SHA2-192s decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_SLH_DSA_SHA2_192F] = {
        "SLH-DSA-SHA2-192f",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_slh_dsa_sha2_192f_functions,
        "SLH-DSA-SHA2-192f decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_SLH_DSA_SHA2_256S] = {
        "SLH-DSA-SHA2-256s",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_slh_dsa_sha2_256s_functions,
        "SLH-DSA-SHA2-256s decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_SLH_DSA_SHA2_256F] = {
        "SLH-DSA-SHA2-256f",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_slh_dsa_sha2_256f_functions,
        "SLH-DSA-SHA2-256f decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_SLH_DSA_SHAKE_128S] = {
        "SLH-DSA-SHAKE-128s",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_slh_dsa_shake_128s_functions,
        "SLH-DSA-SHAKE-128s decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_SLH_DSA_SHAKE_128F] = {
        "SLH-DSA-SHAKE-128f",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_slh_dsa_shake_128f_functions,
        "SLH-DSA-SHAKE-128f decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_SLH_DSA_SHAKE_192S] = {
        "SLH-DSA-SHAKE-192s",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_slh_dsa_shake_192s_functions,
        "SLH-DSA-SHAKE-192s decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_SLH_DSA_SHAKE_192F] = {
        "SLH-DSA-SHAKE-192f",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_slh_dsa_shake_192f_functions,
        "SLH-DSA-SHAKE-192f decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_SLH_DSA_SHAKE_256S] = {
        "SLH-DSA-SHAKE-256s",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_slh_dsa_shake_256s_functions,
        "SLH-DSA-SHAKE-256s decoder implementation in PKCS11 provider",
    },
    [P11PROV_DECODER_SLH_DSA_SHAKE_256F] = {
        "SLH-DSA-SHAKE-256f",
        DER_DECODER_PROP,
        p11prov_der_decoder_p11prov_slh_dsa_shake_256f_functions,
        "SLH-DSA-SHAKE-256f decoder implementation in PKCS11 provider",
    },
};

CK_RV p11prov_register_decoders(P11PROV_CTX *ctx, bool fips_property)
{
    const char *property = NULL;
    OSSL_ALGORITHM *algs =
        OPENSSL_zalloc(sizeof(OSSL_ALGORITHM) * (P11PROV_DECODER_NUM_ALGS + 1));
    int i = 0;

    if (algs == NULL) {
        return CKR_HOST_MEMORY;
    }

    if (fips_property) {
        property = PEM_DECODER_FIPS;
    }
    p11prov_assign_alg(&algs[i++], decoder_algorithms, P11PROV_DECODER_DER,
                       property);

    if (fips_property) {
        property = DER_DECODER_FIPS;
    }
    p11prov_assign_alg(&algs[i++], decoder_algorithms, P11PROV_DECODER_RSA,
                       property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms, P11PROV_DECODER_RSAPSS,
                       property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms, P11PROV_DECODER_EC,
                       property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms, P11PROV_DECODER_ED25519,
                       property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms, P11PROV_DECODER_ED448,
                       property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms, P11PROV_DECODER_X25519,
                       property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms, P11PROV_DECODER_X448,
                       property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_ML_DSA_44, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_ML_DSA_65, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_ML_DSA_87, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_ML_KEM_512, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_ML_KEM_768, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_ML_KEM_1024, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_SLH_DSA_SHA2_128S, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_SLH_DSA_SHA2_128F, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_SLH_DSA_SHA2_192S, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_SLH_DSA_SHA2_192F, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_SLH_DSA_SHA2_256S, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_SLH_DSA_SHA2_256F, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_SLH_DSA_SHAKE_128S, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_SLH_DSA_SHAKE_128F, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_SLH_DSA_SHAKE_192S, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_SLH_DSA_SHAKE_192F, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_SLH_DSA_SHAKE_256S, property);
    p11prov_assign_alg(&algs[i++], decoder_algorithms,
                       P11PROV_DECODER_SLH_DSA_SHAKE_256F, property);

    return p11prov_ctx_add_algs(ctx, OSSL_OP_DECODER, algs);
}
