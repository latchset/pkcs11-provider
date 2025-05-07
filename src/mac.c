// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2025 NXP
 */

#include "provider.h"
#include <string.h>

struct p11prov_mac_ctx {
    P11PROV_CTX *provctx;

    P11PROV_OBJ *key;
    P11PROV_SESSION *session;

    CK_MECHANISM_TYPE hmac;
};

typedef struct p11prov_mac_ctx P11PROV_MAC_CTX;

#define HMAC_MECHANISM(digest) \
    { .hash = CKM_##digest, .hmac = CKM_##digest##_HMAC }, \
    { \
        .hash = CKM_##digest, .hmac = CKM_##digest##_HMAC_GENERAL \
    }

static const struct {
    CK_MECHANISM_TYPE hmac;
    CK_MECHANISM_TYPE hash;
} hmac_mechanisms[] = { HMAC_MECHANISM(SHA_1),
                        HMAC_MECHANISM(SHA224),
                        HMAC_MECHANISM(SHA256),
                        HMAC_MECHANISM(SHA384),
                        HMAC_MECHANISM(SHA512),

                        HMAC_MECHANISM(BLAKE2B_160),
                        HMAC_MECHANISM(BLAKE2B_256),
                        HMAC_MECHANISM(BLAKE2B_384),
                        HMAC_MECHANISM(BLAKE2B_512),

                        HMAC_MECHANISM(SHA3_224),
                        HMAC_MECHANISM(SHA3_256),
                        HMAC_MECHANISM(SHA3_384),
                        HMAC_MECHANISM(SHA3_512),

                        HMAC_MECHANISM(SHA512_224),
                        HMAC_MECHANISM(SHA512_256),
                        HMAC_MECHANISM(SHA512_T),

                        { .hash = CK_UNAVAILABLE_INFORMATION,
                          .hmac = CK_UNAVAILABLE_INFORMATION } };

static CK_ULONG hash_mech(CK_ULONG hmac)
{
    switch (hmac) {
    case CKM_SHA_1_HMAC:
    case CKM_SHA_1_HMAC_GENERAL:
        return CKM_SHA_1;

    case CKM_SHA224_HMAC:
    case CKM_SHA224_HMAC_GENERAL:
        return CKM_SHA224;

    case CKM_SHA256_HMAC:
    case CKM_SHA256_HMAC_GENERAL:
        return CKM_SHA256;

    case CKM_SHA384_HMAC:
    case CKM_SHA384_HMAC_GENERAL:
        return CKM_SHA384;

    case CKM_SHA512_HMAC:
    case CKM_SHA512_HMAC_GENERAL:
        return CKM_SHA512;

    case CKM_BLAKE2B_160_HMAC:
    case CKM_BLAKE2B_160_HMAC_GENERAL:
        return CKM_BLAKE2B_160;

    case CKM_BLAKE2B_256_HMAC:
    case CKM_BLAKE2B_256_HMAC_GENERAL:
        return CKM_BLAKE2B_256;

    case CKM_BLAKE2B_384_HMAC:
    case CKM_BLAKE2B_384_HMAC_GENERAL:
        return CKM_BLAKE2B_384;

    case CKM_BLAKE2B_512_HMAC:
    case CKM_BLAKE2B_512_HMAC_GENERAL:
        return CKM_BLAKE2B_512;

    case CKM_SHA3_224_HMAC:
    case CKM_SHA3_224_HMAC_GENERAL:
        return CKM_SHA3_224;

    case CKM_SHA3_256_HMAC:
    case CKM_SHA3_256_HMAC_GENERAL:
        return CKM_SHA3_256;

    case CKM_SHA3_384_HMAC:
    case CKM_SHA3_384_HMAC_GENERAL:
        return CKM_SHA3_384;

    case CKM_SHA3_512_HMAC:
    case CKM_SHA3_512_HMAC_GENERAL:
        return CKM_SHA3_512;

    case CKM_SHA512_224_HMAC:
    case CKM_SHA512_224_HMAC_GENERAL:
        return CKM_SHA512_224;

    case CKM_SHA512_256_HMAC:
    case CKM_SHA512_256_HMAC_GENERAL:
        return CKM_SHA512_256;

    case CKM_SHA512_T_HMAC:
    case CKM_SHA512_T_HMAC_GENERAL:
        return CKM_SHA512_T;

    default:
        P11PROV_debug("unknown hmmac %lu", hmac);
        break;
    }

    return CK_UNAVAILABLE_INFORMATION;
}

static void *p11prov_mac_newctx(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_MAC_CTX *macctx;

    P11PROV_debug("mac newctx");

    macctx = OPENSSL_zalloc(sizeof(*macctx));
    if (macctx == NULL) {
        return NULL;
    }

    macctx->provctx = ctx;

    /* default mechanism */
    macctx->hmac = CKM_SHA_1_HMAC;

    return macctx;
}

static void p11prov_mac_freectx(void *ctx)
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)ctx;

    P11PROV_debug("mac freectx (ctx:%p)", ctx);

    p11prov_obj_free(macctx->key);

    if (macctx->session) p11prov_return_session(macctx->session);

    OPENSSL_clear_free(macctx, sizeof(*macctx));
}

static int p11prov_hmac_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)ctx;
    OSSL_PARAM *p;
    CK_RV ret;
    size_t digest_size = 0;
    size_t block_size = 0;

    P11PROV_debug("mac get ctx params (ctx=%p, params=%p)", macctx, params);

    if (params == NULL) return RET_OSSL_OK;

    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p) {
        ret = p11prov_digest_get_digest_size(hash_mech(macctx->hmac),
                                             &digest_size);
        if (ret != CKR_OK || digest_size == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }

        OSSL_PARAM_set_size_t(p, digest_size);
    }

    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
    if (p) {
        ret =
            p11prov_digest_get_block_size(hash_mech(macctx->hmac), &block_size);
        if (ret != CKR_OK || block_size == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }

        OSSL_PARAM_set_size_t(p, block_size);
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_hmac_gettable_ctx_params(void *ctx,
                                                          void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL), OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

static CK_RV inner_mac_key(P11PROV_MAC_CTX *macctx, const uint8_t *key,
                           size_t keylen, P11PROV_OBJ **keyobj)
{
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_RV ret;

    if (macctx->session == NULL) {
        ret = p11prov_get_session(macctx->provctx, &slotid, NULL, NULL,
                                  macctx->hmac, NULL, NULL, false, false,
                                  &macctx->session);
        if (ret != CKR_OK) {
            return ret;
        }
    }
    if (macctx->session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    *keyobj = p11prov_create_mac_key(macctx->provctx, macctx->session, true,
                                     (unsigned char *)key, keylen);
    if (*keyobj == NULL) {
        return CKR_KEY_HANDLE_INVALID;
    }
    return CKR_OK;
}

static int p11prov_hmac_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("mac set ctx params (ctx=%p, params=%p)", macctx, params);

    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_TLS_DATA_SIZE);
    if (p) {
        /*
         * TLS_DATA_SIZE parameter should activate some special handling
         * for TLS records that are mac-then-encrypt and have variable length
         * padding (i.e. CBC ciphersuites).
         *
         * For now, just raise "not supported" error.
         */
        P11PROV_raise(ctx, CKR_ARGUMENTS_BAD,
                      "TLS_DATA_SIZE is not supported!");
        return RET_OSSL_ERR;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_DIGEST);
    if (p) {
        const char *digest = NULL;
        CK_ULONG hash = CK_UNAVAILABLE_INFORMATION;
        CK_RV rv;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        rv = p11prov_digest_get_by_name(digest, &hash);
        if (rv != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
        P11PROV_debug("set digest to %lu", hash);

        macctx->hmac = CK_UNAVAILABLE_INFORMATION;
        for (int i = 0; hmac_mechanisms[i].hash != CK_UNAVAILABLE_INFORMATION;
             i++) {
            if (hash == hmac_mechanisms[i].hash) {
                macctx->hmac = hmac_mechanisms[i].hmac;
                break;
            }
        }

        if (macctx->hmac == CK_UNAVAILABLE_INFORMATION) {
            P11PROV_debug("No associated HMAC mechanism");
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }

        P11PROV_debug("set MAC to %lu", macctx->hmac);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
    if (p) {
        const void *key = NULL;
        size_t key_len;
        CK_RV rv;

        ret = OSSL_PARAM_get_octet_string_ptr(p, &key, &key_len);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        /* Create Session and key from key material */
        p11prov_obj_free(macctx->key);
        rv = inner_mac_key(macctx, key, key_len, &macctx->key);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
        P11PROV_debug("set key (len:%lu)", key_len);
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_hmac_settable_ctx_params(void *ctx,
                                                          void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE, NULL), OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int p11prov_hmac_init(void *ctx, const unsigned char *key, size_t keylen,
                             const OSSL_PARAM params[])
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)ctx;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pkey_handle = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { 0 };

    P11PROV_debug("hmac init (ctx:%p, key:%p[%zu], params:%p)", ctx, key,
                  keylen, params);

    ret = p11prov_ctx_status(macctx->provctx);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_hmac_set_ctx_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        P11PROV_raise(macctx->provctx, ret, "Invalid params");
        return RET_OSSL_ERR;
    }

    if (key) {
        p11prov_obj_free(macctx->key);
        ret = inner_mac_key(macctx, key, keylen, &macctx->key);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        P11PROV_debug("set key (len:%lu)", keylen);
    }

    if (macctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return RET_OSSL_ERR;
    }

    pkey_handle = p11prov_obj_get_handle(macctx->key);
    if (pkey_handle == CK_INVALID_HANDLE) {
        P11PROV_raise(ctx, CKR_KEY_HANDLE_INVALID, "Invalid key handle");
        return RET_OSSL_ERR;
    }

    mech.mechanism = macctx->hmac;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    ret = p11prov_SignInit(macctx->provctx,
                           p11prov_session_handle(macctx->session), &mech,
                           pkey_handle);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_hmac_update(void *ctx, const unsigned char *in, size_t inl)
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)ctx;
    CK_RV ret = CKR_OK;

    ret = p11prov_SignUpdate(macctx->provctx,
                             p11prov_session_handle(macctx->session),
                             (CK_BYTE_PTR)in, inl);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_hmac_final(void *ctx, unsigned char *out, size_t *outl,
                              size_t outsize)
{
    P11PROV_MAC_CTX *macctx = (P11PROV_MAC_CTX *)ctx;
    CK_RV ret = CKR_OK;
    CK_ULONG siglen = outsize;

    ret = p11prov_SignFinal(
        macctx->provctx, p11prov_session_handle(macctx->session), out, &siglen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    *outl = siglen;
    return RET_OSSL_OK;
}

const OSSL_DISPATCH p11prov_hmac_mac_functions[] = {
    DISPATCH_MAC_ELEM(mac, NEWCTX, newctx),
    DISPATCH_MAC_ELEM(mac, FREECTX, freectx),
    DISPATCH_MAC_ELEM(hmac, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_MAC_ELEM(hmac, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_MAC_ELEM(hmac, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_MAC_ELEM(hmac, SETTABLE_CTX_PARAMS, settable_ctx_params),
    DISPATCH_MAC_ELEM(hmac, INIT, init),
    DISPATCH_MAC_ELEM(hmac, UPDATE, update),
    DISPATCH_MAC_ELEM(hmac, FINAL, final),
    { 0, NULL },
};
