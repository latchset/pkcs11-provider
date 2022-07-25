/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>
#include <strings.h>
#include <openssl/kdf.h>

struct p11prov_exch_ctx {
    P11PROV_CTX *provctx;

    P11PROV_KEY *key;
    P11PROV_KEY *peer_key;

    CK_MECHANISM_TYPE mechtype;
    CK_MECHANISM_TYPE digest;

    CK_ECDH1_DERIVE_PARAMS ecdh_params;
    CK_ULONG kdf_outlen;

    void *kdfctx;
};
typedef struct p11prov_exch_ctx P11PROV_EXCH_CTX;

#define DM_ELEM_SHA(bits) \
    { \
        .name = "SHA" #bits, .digest = CKM_SHA##bits, \
        .kdf = CKD_SHA##bits##_KDF, .digest_size = bits / 8 \
    }
#define DM_ELEM_SHA3(bits) \
    { \
        .name = "SHA3-" #bits, .digest = CKM_SHA3_##bits, \
        .kdf = CKD_SHA3_##bits##_KDF, .digest_size = bits / 8 \
    }
/* only the ones we can support */
static struct {
    const char *name;
    CK_MECHANISM_TYPE digest;
    CK_RSA_PKCS_MGF_TYPE kdf;
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
    { "SHA1", CKM_SHA_1, CKD_SHA1_KDF, 20 },
    { NULL, 0, 0, 0 },
};

static CK_ULONG p11prov_ecdh_digest_to_kdf(CK_MECHANISM_TYPE digest)
{
    for (int i = 0; digest_map[i].name != NULL; i++) {
        if (digest == digest_map[i].digest) {
            return digest_map[i].kdf;
        }
    }
    return CK_UNAVAILABLE_INFORMATION;
}

static CK_MECHANISM_TYPE p11prov_ecdh_map_digest(const char *digest)
{
    for (int i = 0; digest_map[i].name != NULL; i++) {
        /* hate to strcasecmp but openssl forces us to */
        if (strcasecmp(digest, digest_map[i].name) == 0) {
            return digest_map[i].digest;
        }
    }
    return CK_UNAVAILABLE_INFORMATION;
}

static const char *p11prov_ecdh_digest_name(CK_MECHANISM_TYPE digest)
{
    for (int i = 0; digest_map[i].name != NULL; i++) {
        if (digest_map[i].digest == digest) {
            return digest_map[i].name;
        }
    }
    return "";
}

DISPATCH_ECDH_FN(newctx);
DISPATCH_ECDH_FN(dupctx);
DISPATCH_ECDH_FN(freectx);
DISPATCH_ECDH_FN(init);
DISPATCH_ECDH_FN(set_peer);
DISPATCH_ECDH_FN(derive);
DISPATCH_ECDH_FN(set_ctx_params);
DISPATCH_ECDH_FN(settable_ctx_params);
DISPATCH_ECDH_FN(get_ctx_params);
DISPATCH_ECDH_FN(gettable_ctx_params);

static void *p11prov_ecdh_newctx(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_EXCH_CTX *ecdhctx;

    ecdhctx = OPENSSL_zalloc(sizeof(P11PROV_EXCH_CTX));
    if (ecdhctx == NULL) return NULL;

    ecdhctx->provctx = ctx;

    /* default mechanism */
    ecdhctx->mechtype = CKM_ECDH1_DERIVE;

    /* default KDF */
    ecdhctx->ecdh_params.kdf = CKD_NULL;

    return ecdhctx;
}

static void *p11prov_ecdh_dupctx(void *ctx)
{
    P11PROV_EXCH_CTX *ecdhctx = (P11PROV_EXCH_CTX *)ctx;
    P11PROV_EXCH_CTX *newctx;
    int ret;

    if (ecdhctx == NULL) return NULL;

    newctx = p11prov_ecdh_newctx(ecdhctx->provctx);
    if (newctx == NULL) return NULL;

    newctx->key = p11prov_key_ref(ecdhctx->key);
    newctx->peer_key = p11prov_key_ref(ecdhctx->peer_key);

    newctx->mechtype = ecdhctx->mechtype;

    /* copy ecdh params */
    newctx->ecdh_params.kdf = ecdhctx->ecdh_params.kdf;
    if (ecdhctx->ecdh_params.ulSharedDataLen > 0) {
        newctx->ecdh_params.ulSharedDataLen =
            ecdhctx->ecdh_params.ulSharedDataLen;
        newctx->ecdh_params.pSharedData =
            OPENSSL_memdup(ecdhctx->ecdh_params.pSharedData,
                           ecdhctx->ecdh_params.ulSharedDataLen);
        if (newctx->ecdh_params.pSharedData == NULL) {
            p11prov_ecdh_freectx(newctx);
            return NULL;
        }
    }
    if (ecdhctx->ecdh_params.ulPublicDataLen > 0) {
        newctx->ecdh_params.ulPublicDataLen =
            ecdhctx->ecdh_params.ulPublicDataLen;
        newctx->ecdh_params.pPublicData =
            OPENSSL_memdup(ecdhctx->ecdh_params.pPublicData,
                           ecdhctx->ecdh_params.ulPublicDataLen);
        if (newctx->ecdh_params.pPublicData == NULL) {
            p11prov_ecdh_freectx(newctx);
            return NULL;
        }
    }

    return newctx;
}

static void p11prov_ecdh_freectx(void *ctx)
{
    P11PROV_EXCH_CTX *ecdhctx = (P11PROV_EXCH_CTX *)ctx;

    if (ecdhctx == NULL) return;

    p11prov_key_free(ecdhctx->key);
    p11prov_key_free(ecdhctx->peer_key);
    OPENSSL_clear_free(ecdhctx->ecdh_params.pSharedData,
                       ecdhctx->ecdh_params.ulSharedDataLen);
    OPENSSL_clear_free(ecdhctx, sizeof(P11PROV_EXCH_CTX));
}

static int p11prov_ecdh_init(void *ctx, void *provkey,
                             const OSSL_PARAM params[])
{
    P11PROV_EXCH_CTX *ecdhctx = (P11PROV_EXCH_CTX *)ctx;
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)provkey;

    if (ctx == NULL || provkey == NULL) return RET_OSSL_ERR;

    p11prov_key_free(ecdhctx->key);
    ecdhctx->key = p11prov_object_get_key(obj, true);
    if (ecdhctx->key == NULL) return RET_OSSL_ERR;

    return p11prov_ecdh_set_ctx_params(ctx, params);
}

static int p11prov_ecdh_set_peer(void *ctx, void *provkey)
{
    P11PROV_EXCH_CTX *ecdhctx = (P11PROV_EXCH_CTX *)ctx;
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)provkey;

    if (ctx == NULL || provkey == NULL) return RET_OSSL_ERR;

    p11prov_key_free(ecdhctx->peer_key);
    ecdhctx->peer_key = p11prov_object_get_key(obj, false);
    if (ecdhctx->peer_key == NULL) return RET_OSSL_ERR;

    return RET_OSSL_OK;
}

static int p11prov_ecdh_derive(void *ctx, unsigned char *secret,
                               size_t *psecretlen, size_t outlen)
{
    P11PROV_EXCH_CTX *ecdhctx = (P11PROV_EXCH_CTX *)ctx;
    CK_ATTRIBUTE *ec_point;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_false = CK_FALSE;
    CK_ULONG key_size = 0;
    CK_ATTRIBUTE key_template[5] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_SENSITIVE, &val_false, sizeof(val_false) },
        { CKA_EXTRACTABLE, &val_true, sizeof(val_true) },
        { CKA_VALUE_LEN, &key_size, sizeof(key_size) },
    };
    CK_FUNCTION_LIST *f;
    CK_MECHANISM mechanism;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE handle;
    CK_OBJECT_HANDLE secret_handle;
    CK_SLOT_ID slotid;
    int result = RET_OSSL_ERR;
    int ret;

    if (ecdhctx->key == NULL || ecdhctx->peer_key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return RET_OSSL_ERR;
    }

    if (secret == NULL) {
        *psecretlen = p11prov_key_size(ecdhctx->key);
        return RET_OSSL_OK;
    }

    if (ecdhctx->kdf_outlen > outlen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    /* set up mechanism */
    if (ecdhctx->ecdh_params.kdf == CKF_DIGEST) {
        ecdhctx->ecdh_params.kdf = p11prov_ecdh_digest_to_kdf(ecdhctx->digest);
        if (ecdhctx->ecdh_params.kdf == CK_UNAVAILABLE_INFORMATION) {
            return RET_OSSL_ERR;
        }
    }

    ec_point = p11prov_key_attr(ecdhctx->peer_key, CKA_EC_POINT);
    if (ec_point == NULL) return RET_OSSL_ERR;
    ecdhctx->ecdh_params.pPublicData = ec_point->pValue;
    ecdhctx->ecdh_params.ulPublicDataLen = ec_point->ulValueLen;

    mechanism.mechanism = ecdhctx->mechtype;
    mechanism.pParameter = &ecdhctx->ecdh_params;
    mechanism.ulParameterLen = sizeof(ecdhctx->ecdh_params);

    /* complete key template */
    if (ecdhctx->kdf_outlen) {
        key_size = ecdhctx->kdf_outlen;
    } else {
        key_size = p11prov_key_size(ecdhctx->key);
    }

    handle = p11prov_key_handle(ecdhctx->key);
    if (handle == CK_INVALID_HANDLE) {
        P11PROV_raise(ecdhctx->provctx, CKR_KEY_HANDLE_INVALID,
                      "Provided key has invalid handle");
        return RET_OSSL_ERR;
    }

    slotid = p11prov_key_slotid(ecdhctx->key);
    if (slotid == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(ecdhctx->provctx, CKR_SLOT_ID_INVALID,
                      "Provided key has invalid slot");
        return RET_OSSL_ERR;
    }

    f = p11prov_ctx_fns(ecdhctx->provctx);
    if (f == NULL) return CKR_GENERAL_ERROR;

    ret = f->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (ret != CKR_OK) {
        P11PROV_raise(ecdhctx->provctx, ret,
                      "Failed to open session on slot %lu", slotid);
        return ret;
    }

    ret = f->C_DeriveKey(session, &mechanism, handle, key_template, 5,
                         &secret_handle);
    if (ret == CKR_OK) {
        unsigned long secret_len;
        p11prov_debug("ECDH derived hey handle: %lu\n", secret_handle);
        struct fetch_attrs attrs[1] = {
            { CKA_VALUE, &secret, &secret_len, false, true },
        };
        ret = p11prov_fetch_attributes(f, session, secret_handle, attrs, 1);
        if (ret != CKR_OK) {
            p11prov_debug("ecdh failed to retrieve secret %d\n", ret);
        }
        *psecretlen = secret_len;
        result = RET_OSSL_OK;
    } else {
        P11PROV_raise(ecdhctx->provctx, ret, "Error returned by C_DeriveKey");
        result = RET_OSSL_ERR;
    }

    ret = f->C_CloseSession(session);
    if (ret != CKR_OK) {
        P11PROV_raise(ecdhctx->provctx, ret, "Failed to close session %lu",
                      session);
    }

    return result;
}

static int p11prov_ecdh_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_EXCH_CTX *ecdhctx = (P11PROV_EXCH_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    p11prov_debug("ecdh set ctx params (ctx=%p, params=%p)\n", ecdhctx, params);

    if (params == NULL) return RET_OSSL_OK;

    p = OSSL_PARAM_locate_const(params,
                                OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE);
    if (p) {
        int mode;

        ret = OSSL_PARAM_get_int(p, &mode);
        if (ret != RET_OSSL_OK) return ret;

        if (mode < -1 || mode > 1) return RET_OSSL_ERR;

        if (mode == 0)
            ecdhctx->mechtype = CKM_ECDH1_DERIVE;
        else
            ecdhctx->mechtype = CKM_ECDH1_COFACTOR_DERIVE;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p) {
        char name[128] = { 0 };
        char *str = name;

        ret = OSSL_PARAM_get_utf8_string(p, &str, sizeof(name));
        if (ret != RET_OSSL_OK) return ret;

        if (name[0] == '\0') {
            ecdhctx->ecdh_params.kdf = CKD_NULL;
        } else if (strcmp(name, OSSL_KDF_NAME_X963KDF) == 0) {
            /* not really a KDF, but signals that a digest
             * KDF will need to be used. Need to set a signal
             * because openssl allows digest to set in any order
             * so we need to know that an actual KDF is wanted
             * as opposed to a malformed case where a digest was
             * set, but ultimately KDF_NULL was chosen
             *
             * CKF_DIGEST works here as it is a much higher value
             * than any CKD so it won't conflict, and just error
             * if mistakenly passed into a token.
             * */
            ecdhctx->ecdh_params.kdf = CKF_DIGEST;
        } else {
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if (p) {
        char digest[256];
        char *ptr = digest;
        ret = OSSL_PARAM_get_utf8_string(p, &ptr, 256);
        if (ret != RET_OSSL_OK) return ret;

        ecdhctx->digest = p11prov_ecdh_map_digest(digest);
        if (ecdhctx->digest == CK_UNAVAILABLE_INFORMATION) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p) {
        size_t outlen;

        ret = OSSL_PARAM_get_size_t(p, &outlen);
        if (ret != RET_OSSL_OK) return ret;

        ecdhctx->kdf_outlen = outlen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p) {
        void *ukm = NULL;
        size_t ukm_len;

        ret = OSSL_PARAM_get_octet_string(p, &ukm, 0, &ukm_len);
        if (ret != RET_OSSL_OK) return ret;

        OPENSSL_free(ecdhctx->ecdh_params.pSharedData);
        ecdhctx->ecdh_params.pSharedData = ukm;
        ecdhctx->ecdh_params.ulSharedDataLen = ukm_len;
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_ecdh_settable_ctx_params(void *ctx, void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
        OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static int p11prov_ecdh_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_EXCH_CTX *ecdhctx = (P11PROV_EXCH_CTX *)ctx;
    OSSL_PARAM *p;
    int ret;

    p11prov_debug("ecdh get ctx params (ctx=%p, params=%p)\n", ctx, params);

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE);
    if (p) {
        int mode = (ecdhctx->mechtype == CKM_ECDH1_DERIVE) ? 0 : 1;
        ret = OSSL_PARAM_set_int(p, mode);
        if (ret != RET_OSSL_OK) return ret;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p) {
        if (ecdhctx->ecdh_params.kdf == CKD_NULL) {
            ret = OSSL_PARAM_set_utf8_string(p, "");
        } else {
            ret = OSSL_PARAM_set_utf8_string(p, OSSL_KDF_NAME_X963KDF);
        }
        if (ret != RET_OSSL_OK) return ret;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if (p) {
        const char *digest = p11prov_ecdh_digest_name(ecdhctx->digest);
        ret = OSSL_PARAM_set_utf8_string(p, digest);
        if (ret != RET_OSSL_OK) return ret;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p) {
        ret = OSSL_PARAM_set_size_t(p, ecdhctx->kdf_outlen);
        if (ret != RET_OSSL_OK) return ret;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p) {
        ret = OSSL_PARAM_set_octet_ptr(p, ecdhctx->ecdh_params.pSharedData,
                                       ecdhctx->ecdh_params.ulSharedDataLen);
        if (ret != RET_OSSL_OK) return ret;
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_ecdh_gettable_ctx_params(void *ctx, void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
        OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_ecdh_exchange_functions[] = {
    DISPATCH_ECDH_ELEM(ecdh, NEWCTX, newctx),
    DISPATCH_ECDH_ELEM(ecdh, DUPCTX, dupctx),
    DISPATCH_ECDH_ELEM(ecdh, FREECTX, freectx),
    DISPATCH_ECDH_ELEM(ecdh, INIT, init),
    DISPATCH_ECDH_ELEM(ecdh, DERIVE, derive),
    DISPATCH_ECDH_ELEM(ecdh, SET_PEER, set_peer),
    DISPATCH_ECDH_ELEM(ecdh, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_ECDH_ELEM(ecdh, SETTABLE_CTX_PARAMS, settable_ctx_params),
    DISPATCH_ECDH_ELEM(ecdh, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_ECDH_ELEM(ecdh, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    { 0, NULL },
};

/* unclear why OpenSSL makes KDFs go through a middle "exchange" layer
 * when there is a direct KDF facility. I can only assume this is
 * because for some reason they want the command line -derive comamnd
 * to be able to handle both key exchanges like ECDH and symmetric key
 * derivation done by KDFs via the -kdf <type> selector */
DISPATCH_EXCHHKDF_FN(newctx);
DISPATCH_EXCHHKDF_FN(freectx);
DISPATCH_EXCHHKDF_FN(init);
DISPATCH_EXCHHKDF_FN(derive);
DISPATCH_EXCHHKDF_FN(set_ctx_params);
DISPATCH_EXCHHKDF_FN(settable_ctx_params);

static void *p11prov_exch_hkdf_newctx(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_EXCH_CTX *hkdfctx;
    EVP_KDF *kdf = NULL;

    p11prov_debug("hkdf exchange newctx\n");

    hkdfctx = OPENSSL_zalloc(sizeof(P11PROV_EXCH_CTX));
    if (hkdfctx == NULL) return NULL;

    hkdfctx->provctx = ctx;

    /* mark with mechanism type */
    hkdfctx->mechtype = CKM_HKDF_DERIVE;

    kdf = EVP_KDF_fetch(NULL, "HKDF", P11PROV_DEFAULT_PROPERTIES);
    if (kdf == NULL) {
        OPENSSL_free(hkdfctx);
        return NULL;
    }
    hkdfctx->kdfctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    if (hkdfctx->kdfctx == NULL) {
        OPENSSL_free(hkdfctx);
        return NULL;
    }

    return hkdfctx;
}

static void p11prov_exch_hkdf_freectx(void *ctx)
{
    P11PROV_EXCH_CTX *hkdfctx = (P11PROV_EXCH_CTX *)ctx;

    p11prov_debug("hkdf exchange freectx\n");

    if (hkdfctx == NULL) return;

    EVP_KDF_CTX_free(hkdfctx->kdfctx);
    p11prov_key_free(hkdfctx->key);
    OPENSSL_clear_free(hkdfctx, sizeof(P11PROV_EXCH_CTX));
}

static int p11prov_exch_hkdf_init(void *ctx, void *provobj,
                                  const OSSL_PARAM params[])
{
    P11PROV_EXCH_CTX *hkdfctx = (P11PROV_EXCH_CTX *)ctx;
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)provobj;

    p11prov_debug("hkdf exchange init (ctx:%p obj:%p params:%p)\n", ctx, obj,
                  params);

    if (ctx == NULL || provobj == NULL) return RET_OSSL_ERR;

    if (provobj != &p11prov_hkdfkm_static_ctx) {
        p11prov_key_free(hkdfctx->key);
        hkdfctx->key = p11prov_object_get_key(obj, true);
        if (hkdfctx->key == NULL) return RET_OSSL_ERR;
    }

    return p11prov_exch_hkdf_set_ctx_params(ctx, params);
}

static int p11prov_exch_hkdf_derive(void *ctx, unsigned char *secret,
                                    size_t *secretlen, size_t outlen)
{
    P11PROV_EXCH_CTX *hkdfctx = (P11PROV_EXCH_CTX *)ctx;

    p11prov_debug("hkdf exchange derive (ctx:%p)\n", ctx);

    if (secret == NULL) {
        *secretlen = EVP_KDF_CTX_get_kdf_size(hkdfctx->kdfctx);
        return 1;
    }

    return EVP_KDF_derive(hkdfctx->kdfctx, secret, outlen, NULL);
}

static int p11prov_exch_hkdf_set_ctx_params(void *ctx,
                                            const OSSL_PARAM params[])
{
    P11PROV_EXCH_CTX *hkdfctx = (P11PROV_EXCH_CTX *)ctx;

    p11prov_debug("hkdf exchange set ctx params (ctx:%p, params:%p)\n", ctx,
                  params);

    return EVP_KDF_CTX_set_params(hkdfctx->kdfctx, params);
}

static const OSSL_PARAM *p11prov_exch_hkdf_settable_ctx_params(void *ctx,
                                                               void *provctx)
{
    const OSSL_PARAM *params;
    EVP_KDF *kdf;

    kdf = EVP_KDF_fetch(NULL, "HKDF", P11PROV_DEFAULT_PROPERTIES);
    if (kdf == NULL) return NULL;

    params = EVP_KDF_settable_ctx_params(kdf);
    EVP_KDF_free(kdf);

    return params;
}

const OSSL_DISPATCH p11prov_hkdf_exchange_functions[] = {
    DISPATCH_EXCHHKDF_ELEM(exch_hkdf, NEWCTX, newctx),
    DISPATCH_EXCHHKDF_ELEM(exch_hkdf, FREECTX, freectx),
    DISPATCH_EXCHHKDF_ELEM(exch_hkdf, INIT, init),
    DISPATCH_EXCHHKDF_ELEM(exch_hkdf, DERIVE, derive),
    DISPATCH_EXCHHKDF_ELEM(exch_hkdf, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_EXCHHKDF_ELEM(exch_hkdf, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};
