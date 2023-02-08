/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>
#include <openssl/kdf.h>

struct p11prov_kdf_ctx {
    P11PROV_CTX *provctx;

    P11PROV_OBJ *key;

    CK_MECHANISM_TYPE mechtype;

    CK_HKDF_PARAMS params;

    P11PROV_SESSION *session;
};
typedef struct p11prov_kdf_ctx P11PROV_KDF_CTX;

DISPATCH_HKDF_FN(newctx);
DISPATCH_HKDF_FN(freectx);
DISPATCH_HKDF_FN(reset);
DISPATCH_HKDF_FN(derive);
DISPATCH_HKDF_FN(set_ctx_params);
DISPATCH_HKDF_FN(settable_ctx_params);
DISPATCH_HKDF_FN(get_ctx_params);
DISPATCH_HKDF_FN(gettable_ctx_params);

static void *p11prov_hkdf_newctx(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_KDF_CTX *hkdfctx;
    CK_RV ret;

    P11PROV_debug("hkdf newctx");

    ret = p11prov_ctx_status(ctx);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    hkdfctx = OPENSSL_zalloc(sizeof(P11PROV_KDF_CTX));
    if (hkdfctx == NULL) {
        return NULL;
    }

    hkdfctx->provctx = ctx;

    /* default mechanism */
    hkdfctx->mechtype = CKM_HKDF_DERIVE;

    return hkdfctx;
}

static void p11prov_hkdf_freectx(void *ctx)
{
    P11PROV_debug("hkdf freectx (ctx:%p)", ctx);

    p11prov_hkdf_reset(ctx);
    OPENSSL_free(ctx);
}

static void p11prov_hkdf_reset(void *ctx)
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    /* save provider context */
    void *provctx = hkdfctx->provctx;

    P11PROV_debug("hkdf reset (ctx:%p)", ctx);

    /* free all allocated resources */
    p11prov_obj_free(hkdfctx->key);
    if (hkdfctx->session) {
        p11prov_return_session(hkdfctx->session);
        hkdfctx->session = NULL;
    }

    OPENSSL_cleanse(hkdfctx->params.pSalt, hkdfctx->params.ulSaltLen);
    OPENSSL_cleanse(hkdfctx->params.pInfo, hkdfctx->params.ulInfoLen);

    /* zero all */
    memset(hkdfctx, 0, sizeof(*hkdfctx));

    /* restore defaults */
    hkdfctx->provctx = provctx;
    hkdfctx->mechtype = CKM_HKDF_DERIVE;
}

static int p11prov_hkdf_derive(void *ctx, unsigned char *key, size_t keylen,
                               const OSSL_PARAM params[])
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_false = CK_FALSE;
    CK_ULONG key_size = keylen;
    CK_ATTRIBUTE key_template[5] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_SENSITIVE, &val_false, sizeof(val_false) },
        { CKA_EXTRACTABLE, &val_true, sizeof(val_true) },
        { CKA_VALUE_LEN, &key_size, sizeof(key_size) },
    };
    CK_MECHANISM mechanism;
    CK_OBJECT_HANDLE pkey_handle;
    CK_OBJECT_HANDLE dkey_handle;
    CK_SLOT_ID slotid;
    struct fetch_attrs attrs[1];
    int num = 0;
    CK_RV ret;

    P11PROV_debug("hkdf derive (ctx:%p, key:%p[%zu], params:%p)", ctx, key,
                  keylen, params);

    if (hkdfctx->key == NULL || key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return RET_OSSL_ERR;
    }

    if (keylen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return RET_OSSL_ERR;
    }

    mechanism.mechanism = hkdfctx->mechtype;
    mechanism.pParameter = &hkdfctx->params;
    mechanism.ulParameterLen = sizeof(hkdfctx->params);

    pkey_handle = p11prov_obj_get_handle(hkdfctx->key);
    if (pkey_handle == CK_INVALID_HANDLE) {
        P11PROV_raise(hkdfctx->provctx, CKR_KEY_HANDLE_INVALID,
                      "Provided key has invalid handle");
        return RET_OSSL_ERR;
    }

    /* no salt ? */
    if (hkdfctx->params.ulSaltType == 0) {
        hkdfctx->params.ulSaltType = CKF_HKDF_SALT_NULL;
    }

    slotid = p11prov_obj_get_slotid(hkdfctx->key);
    if (slotid == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(hkdfctx->provctx, CKR_SLOT_ID_INVALID,
                      "Provided key has invalid slot");
        return RET_OSSL_ERR;
    }

    ret = p11prov_derive_key(hkdfctx->provctx, slotid, &mechanism, pkey_handle,
                             key_template, 5, &hkdfctx->session, &dkey_handle);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    P11PROV_debug("HKDF derived hey handle: %lu", dkey_handle);
    FA_SET_BUF_VAL(attrs, num, CKA_VALUE, key, keylen, true);
    ret = p11prov_fetch_attributes(hkdfctx->provctx, hkdfctx->session,
                                   dkey_handle, attrs, num);
    if (ret != CKR_OK) {
        P11PROV_raise(hkdfctx->provctx, ret, "Failed to retrieve derived key");
        return RET_OSSL_ERR;
    }
    FA_GET_LEN(attrs, 0, key_size);
    if (key_size != keylen) {
        ret = CKR_GENERAL_ERROR;
        P11PROV_raise(hkdfctx->provctx, ret,
                      "Expected derived key of len %zu, but got %lu", keylen,
                      key_size);
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_hkdf_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("hkdf set ctx params (ctx=%p, params=%p)", hkdfctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
    if (p) {
        const char *digest = NULL;
        CK_RV rv;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        rv = p11prov_digest_get_by_name(digest,
                                        &hkdfctx->params.prfHashMechanism);
        if (rv != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
        P11PROV_debug("set digest to %lu", hkdfctx->params.prfHashMechanism);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE);
    if (p) {
        int mode;
        if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            if (OPENSSL_strcasecmp(p->data, "EXTRACT_AND_EXPAND") == 0) {
                mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
            } else if (OPENSSL_strcasecmp(p->data, "EXTRACT_ONLY") == 0) {
                mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
            } else if (OPENSSL_strcasecmp(p->data, "EXPAND_ONLY") == 0) {
                mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
            } else {
                mode = 1;
            }
        } else {
            ret = OSSL_PARAM_get_int(p, &mode);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
        }

        switch (mode) {
        case EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND:
            hkdfctx->params.bExtract = CK_TRUE;
            hkdfctx->params.bExpand = CK_TRUE;
            break;
        case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
            hkdfctx->params.bExtract = CK_TRUE;
            hkdfctx->params.bExpand = CK_FALSE;
            break;
        case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
            hkdfctx->params.bExtract = CK_FALSE;
            hkdfctx->params.bExpand = CK_TRUE;
            break;
        default:
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            return RET_OSSL_ERR;
        }
        P11PROV_debug("set mode to extract:%d expand:%d",
                      (int)hkdfctx->params.bExtract,
                      (int)hkdfctx->params.bExpand);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    if (p) {
        CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
        void *secret = NULL;
        size_t secret_len;
        /* TODO: import into a pkcs11 key? */
        ret = OSSL_PARAM_get_octet_string(p, &secret, 0, &secret_len);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        /* Create Session  and key from key material */
        if (hkdfctx->session == NULL) {
            ret = p11prov_get_session(hkdfctx->provctx, &slotid, NULL, NULL,
                                      hkdfctx->mechtype, NULL, NULL, false,
                                      false, &hkdfctx->session);
            if (ret != CKR_OK) {
                return RET_OSSL_ERR;
            }
        }
        if (hkdfctx->session == NULL) {
            return RET_OSSL_ERR;
        }

        hkdfctx->key = p11prov_create_secret_key(
            hkdfctx->provctx, hkdfctx->session, true, secret, secret_len);
        if (hkdfctx->key == NULL) {
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    if (p) {
        void *ptr = NULL;
        size_t len;
        OPENSSL_cleanse(hkdfctx->params.pSalt, hkdfctx->params.ulSaltLen);
        hkdfctx->params.pSalt = NULL;
        ret = OSSL_PARAM_get_octet_string(p, &ptr, 0, &len);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        hkdfctx->params.ulSaltType = CKF_HKDF_SALT_DATA;
        hkdfctx->params.pSalt = ptr;
        hkdfctx->params.ulSaltLen = len;
        P11PROV_debug("set salt (len:%lu)", hkdfctx->params.ulSaltLen);
    }

    /* can be multiple parameters, which will be all concatenated */
    for (p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO); p != NULL;
         p = OSSL_PARAM_locate_const(p + 1, OSSL_KDF_PARAM_INFO)) {
        uint8_t *ptr;
        size_t len;

        if (p->data_size == 0 || p->data == NULL) {
            return RET_OSSL_ERR;
        }

        len = hkdfctx->params.ulInfoLen + p->data_size;
        ptr = OPENSSL_realloc(hkdfctx->params.pInfo, len);
        if (ptr == NULL) {
            OPENSSL_cleanse(hkdfctx->params.pInfo, hkdfctx->params.ulInfoLen);
            return RET_OSSL_ERR;
        }
        memcpy(ptr + hkdfctx->params.ulInfoLen, p->data, p->data_size);
        hkdfctx->params.pInfo = ptr;
        hkdfctx->params.ulInfoLen = len;
        P11PROV_debug("set info (len:%lu)", hkdfctx->params.ulInfoLen);
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_hkdf_settable_ctx_params(void *ctx, void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),
        OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static int p11prov_hkdf_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    OSSL_PARAM *p;

    P11PROV_debug("hkdf get ctx params (ctx=%p, params=%p)", hkdfctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (p) {
        size_t ret_size = 0;
        if (hkdfctx->params.bExpand != CK_FALSE) {
            ret_size = SIZE_MAX;
        } else {
            CK_RV rv;

            rv = p11prov_digest_get_digest_size(
                hkdfctx->params.prfHashMechanism, &ret_size);
            if (rv != CKR_OK) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
                return RET_OSSL_ERR;
            }
        }
        if (ret_size != 0) {
            return OSSL_PARAM_set_size_t(p, ret_size);
        }
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_hkdf_gettable_ctx_params(void *ctx, void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_hkdf_kdf_functions[] = {
    DISPATCH_HKDF_ELEM(hkdf, NEWCTX, newctx),
    DISPATCH_HKDF_ELEM(hkdf, FREECTX, freectx),
    DISPATCH_HKDF_ELEM(hkdf, RESET, reset),
    DISPATCH_HKDF_ELEM(hkdf, DERIVE, derive),
    DISPATCH_HKDF_ELEM(hkdf, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_HKDF_ELEM(hkdf, SETTABLE_CTX_PARAMS, settable_ctx_params),
    DISPATCH_HKDF_ELEM(hkdf, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_HKDF_ELEM(hkdf, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    { 0, NULL },
};
