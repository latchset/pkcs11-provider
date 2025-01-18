/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>
#include <openssl/kdf.h>

struct p11prov_exch_ctx {
    P11PROV_CTX *provctx;

    P11PROV_OBJ *key;
    P11PROV_OBJ *peer_key;

    CK_MECHANISM_TYPE mechtype;
    CK_MECHANISM_TYPE digest;

    CK_ECDH1_DERIVE_PARAMS ecdh_params;
    CK_ULONG kdf_outlen;

    void *kdfctx;
};
typedef struct p11prov_exch_ctx P11PROV_EXCH_CTX;

#define DM_ELEM_SHA(bits) \
    { \
        .digest = CKM_SHA##bits, .kdf = CKD_SHA##bits##_KDF \
    }
#define DM_ELEM_SHA3(bits) \
    { \
        .digest = CKM_SHA3_##bits, .kdf = CKD_SHA3_##bits##_KDF \
    }
/* only the ones we can support */
static struct {
    CK_MECHANISM_TYPE digest;
    CK_RSA_PKCS_MGF_TYPE kdf;
} kdf_map[] = {
    DM_ELEM_SHA3(256),
    DM_ELEM_SHA3(512),
    DM_ELEM_SHA3(384),
    DM_ELEM_SHA3(224),
    DM_ELEM_SHA(256),
    DM_ELEM_SHA(512),
    DM_ELEM_SHA(384),
    DM_ELEM_SHA(224),
    { CKM_SHA_1, CKD_SHA1_KDF },
    { CK_UNAVAILABLE_INFORMATION, 0 },
};

static CK_ULONG p11prov_ecdh_digest_to_kdf(CK_MECHANISM_TYPE digest)
{
    for (int i = 0; kdf_map[i].digest != CK_UNAVAILABLE_INFORMATION; i++) {
        if (digest == kdf_map[i].digest) {
            return kdf_map[i].kdf;
        }
    }
    return CK_UNAVAILABLE_INFORMATION;
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
    if (ecdhctx == NULL) {
        return NULL;
    }

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

    if (ecdhctx == NULL) {
        return NULL;
    }

    newctx = p11prov_ecdh_newctx(ecdhctx->provctx);
    if (newctx == NULL) {
        return NULL;
    }

    newctx->key = p11prov_obj_ref(ecdhctx->key);
    newctx->peer_key = p11prov_obj_ref(ecdhctx->peer_key);

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

    if (ecdhctx == NULL) {
        return;
    }

    p11prov_obj_free(ecdhctx->key);
    p11prov_obj_free(ecdhctx->peer_key);
    OPENSSL_clear_free(ecdhctx->ecdh_params.pSharedData,
                       ecdhctx->ecdh_params.ulSharedDataLen);
    OPENSSL_clear_free(ecdhctx, sizeof(P11PROV_EXCH_CTX));
}

static int p11prov_ecdh_init(void *ctx, void *provkey,
                             const OSSL_PARAM params[])
{
    P11PROV_EXCH_CTX *ecdhctx = (P11PROV_EXCH_CTX *)ctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)provkey;
    CK_RV ret;

    if (ctx == NULL || provkey == NULL) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_ctx_status(ecdhctx->provctx);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    p11prov_obj_free(ecdhctx->key);
    ecdhctx->key = p11prov_obj_ref(key);
    if (ecdhctx->key == NULL) {
        P11PROV_raise(ecdhctx->provctx, CKR_ARGUMENTS_BAD, "Invalid object");
        return RET_OSSL_ERR;
    }
    if (p11prov_obj_get_class(ecdhctx->key) != CKO_PRIVATE_KEY) {
        P11PROV_raise(ecdhctx->provctx, CKR_ARGUMENTS_BAD, "Invalid key class");
        return RET_OSSL_ERR;
    }

    return p11prov_ecdh_set_ctx_params(ctx, params);
}

static int p11prov_ecdh_set_peer(void *ctx, void *provkey)
{
    P11PROV_EXCH_CTX *ecdhctx = (P11PROV_EXCH_CTX *)ctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)provkey;

    if (ctx == NULL || provkey == NULL) {
        return RET_OSSL_ERR;
    }

    p11prov_obj_free(ecdhctx->peer_key);
    ecdhctx->peer_key = p11prov_obj_ref(key);
    if (ecdhctx->peer_key == NULL) {
        P11PROV_raise(ecdhctx->provctx, CKR_ARGUMENTS_BAD, "Invalid object");
        return RET_OSSL_ERR;
    }
    if (p11prov_obj_get_class(ecdhctx->peer_key) != CKO_PUBLIC_KEY) {
        P11PROV_raise(ecdhctx->provctx, CKR_ARGUMENTS_BAD, "Invalid key class");
        return RET_OSSL_ERR;
    }

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
    CK_ULONG key_size = outlen;
    CK_ATTRIBUTE key_template[6] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_SENSITIVE, &val_false, sizeof(val_false) },
        { CKA_EXTRACTABLE, &val_true, sizeof(val_true) },
        { CKA_VALUE_LEN, &key_size, sizeof(key_size) },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
    };
    CK_MECHANISM mechanism;
    P11PROV_SESSION *session = NULL;
    CK_OBJECT_HANDLE handle;
    CK_OBJECT_HANDLE secret_handle;
    CK_SLOT_ID slotid;
    struct fetch_attrs attrs[1];
    int num = 0;
    CK_RV ret;

    if (ecdhctx->key == NULL || ecdhctx->peer_key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return RET_OSSL_ERR;
    }

    if (secret == NULL) {
        *psecretlen = p11prov_obj_get_key_size(ecdhctx->key);
        return RET_OSSL_OK;
    }

    /* set up mechanism */
    if (ecdhctx->ecdh_params.kdf == CKF_DIGEST) {
        ecdhctx->ecdh_params.kdf = p11prov_ecdh_digest_to_kdf(ecdhctx->digest);
        if (ecdhctx->ecdh_params.kdf == CK_UNAVAILABLE_INFORMATION) {
            return RET_OSSL_ERR;
        }
    }

    ec_point = p11prov_obj_get_ec_public_raw(ecdhctx->peer_key);
    if (ec_point == NULL) {
        return RET_OSSL_ERR;
    }
    ecdhctx->ecdh_params.pPublicData = ec_point->pValue;
    ecdhctx->ecdh_params.ulPublicDataLen = ec_point->ulValueLen;

    mechanism.mechanism = ecdhctx->mechtype;
    mechanism.pParameter = &ecdhctx->ecdh_params;
    mechanism.ulParameterLen = sizeof(ecdhctx->ecdh_params);

    /* complete key template */
    if (ecdhctx->kdf_outlen) {
        if (ecdhctx->kdf_outlen < outlen) {
            key_size = ecdhctx->kdf_outlen;
        }
    }

    handle = p11prov_obj_get_handle(ecdhctx->key);
    if (handle == CK_INVALID_HANDLE) {
        P11PROV_raise(ecdhctx->provctx, CKR_KEY_HANDLE_INVALID,
                      "Provided key has invalid handle");
        return RET_OSSL_ERR;
    }

    slotid = p11prov_obj_get_slotid(ecdhctx->key);
    if (slotid == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(ecdhctx->provctx, CKR_SLOT_ID_INVALID,
                      "Provided key has invalid slot");
        return RET_OSSL_ERR;
    }

    ret = p11prov_derive_key(ecdhctx->provctx, slotid, &mechanism, handle,
                             key_template, 6, &session, &secret_handle);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    P11PROV_debug("ECDH derived hey handle: %lu", secret_handle);
    FA_SET_BUF_VAL(attrs, num, CKA_VALUE, secret, key_size, true);
    ret = p11prov_fetch_attributes(ecdhctx->provctx, session, secret_handle,
                                   attrs, num);
    p11prov_return_session(session);
    if (ret != CKR_OK) {
        P11PROV_debug("ecdh failed to retrieve secret %lu", ret);
        return RET_OSSL_ERR;
    }
    FA_GET_LEN(attrs, 0, *psecretlen);
    return RET_OSSL_OK;
}

static int p11prov_ecdh_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_EXCH_CTX *ecdhctx = (P11PROV_EXCH_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("ecdh set ctx params (ctx=%p, params=%p)", ecdhctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params,
                                OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE);
    if (p) {
        int mode;

        ret = OSSL_PARAM_get_int(p, &mode);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        if (mode < -1 || mode > 1) {
            return RET_OSSL_ERR;
        }

        if (mode == 0) {
            ecdhctx->mechtype = CKM_ECDH1_DERIVE;
        } else {
            ecdhctx->mechtype = CKM_ECDH1_COFACTOR_DERIVE;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p) {
        const char *name = NULL;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &name);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

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
        const char *digest = NULL;
        CK_RV rv;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        rv = p11prov_digest_get_by_name(digest, &ecdhctx->digest);
        if (rv != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p) {
        size_t outlen;

        ret = OSSL_PARAM_get_size_t(p, &outlen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        ecdhctx->kdf_outlen = outlen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p) {
        void *ukm = NULL;
        size_t ukm_len;

        ret = OSSL_PARAM_get_octet_string(p, &ukm, 0, &ukm_len);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

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

    P11PROV_debug("ecdh get ctx params (ctx=%p, params=%p)", ctx, params);

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE);
    if (p) {
        int mode = (ecdhctx->mechtype == CKM_ECDH1_DERIVE) ? 0 : 1;
        ret = OSSL_PARAM_set_int(p, mode);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p) {
        if (ecdhctx->ecdh_params.kdf == CKD_NULL) {
            ret = OSSL_PARAM_set_utf8_string(p, "");
        } else {
            ret = OSSL_PARAM_set_utf8_string(p, OSSL_KDF_NAME_X963KDF);
        }
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if (p) {
        const char *digest;
        CK_RV rv;

        rv = p11prov_digest_get_name(ecdhctx->digest, &digest);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_utf8_string(p, digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p) {
        ret = OSSL_PARAM_set_size_t(p, ecdhctx->kdf_outlen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p) {
        ret = OSSL_PARAM_set_octet_ptr(p, ecdhctx->ecdh_params.pSharedData,
                                       ecdhctx->ecdh_params.ulSharedDataLen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
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
 * because for some reason they want the command line -derive command
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

    P11PROV_debug("hkdf exchange newctx");

    hkdfctx = OPENSSL_zalloc(sizeof(P11PROV_EXCH_CTX));
    if (hkdfctx == NULL) {
        return NULL;
    }

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

    P11PROV_debug("hkdf exchange freectx");

    if (hkdfctx == NULL) {
        return;
    }

    EVP_KDF_CTX_free(hkdfctx->kdfctx);
    p11prov_obj_free(hkdfctx->key);
    OPENSSL_clear_free(hkdfctx, sizeof(P11PROV_EXCH_CTX));
}

static int p11prov_exch_hkdf_init(void *ctx, void *provkey,
                                  const OSSL_PARAM params[])
{
    P11PROV_EXCH_CTX *hkdfctx = (P11PROV_EXCH_CTX *)ctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)provkey;
    CK_RV ret;

    P11PROV_debug("hkdf exchange init (ctx:%p key:%p params:%p)", ctx, key,
                  params);

    if (ctx == NULL || provkey == NULL) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_ctx_status(hkdfctx->provctx);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    if (provkey != &p11prov_hkdf_static_ctx) {
        p11prov_obj_free(hkdfctx->key);
        hkdfctx->key = p11prov_obj_ref(key);
        if (hkdfctx->key == NULL) {
            P11PROV_raise(hkdfctx->provctx, CKR_ARGUMENTS_BAD,
                          "Invalid object");
            return RET_OSSL_ERR;
        }
        if (p11prov_obj_get_class(hkdfctx->key) != CKO_PRIVATE_KEY) {
            P11PROV_raise(hkdfctx->provctx, CKR_ARGUMENTS_BAD,
                          "Invalid key class");
            return RET_OSSL_ERR;
        }
    }

    return p11prov_exch_hkdf_set_ctx_params(ctx, params);
}

static int p11prov_exch_hkdf_derive(void *ctx, unsigned char *secret,
                                    size_t *secretlen, size_t outlen)
{
    P11PROV_EXCH_CTX *hkdfctx = (P11PROV_EXCH_CTX *)ctx;

    P11PROV_debug("hkdf exchange derive (ctx:%p)", ctx);

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

    P11PROV_debug("hkdf exchange set ctx params (ctx:%p, params:%p)", ctx,
                  params);

    return EVP_KDF_CTX_set_params(hkdfctx->kdfctx, params);
}

static const OSSL_PARAM *p11prov_exch_hkdf_settable_ctx_params(void *ctx,
                                                               void *provctx)
{
    const OSSL_PARAM *params;
    EVP_KDF *kdf;

    kdf = EVP_KDF_fetch(NULL, "HKDF", P11PROV_DEFAULT_PROPERTIES);
    if (kdf == NULL) {
        return NULL;
    }

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
