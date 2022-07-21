/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

#include "provider.h"
#include <string.h>
#include <openssl/kdf.h>

struct p11prov_kdf_ctx {
    P11PROV_CTX *provctx;

    P11PROV_KEY *key;

    CK_MECHANISM_TYPE mechtype;

    CK_HKDF_PARAMS params;

    CK_SESSION_HANDLE session;
};
typedef struct p11prov_kdf_ctx P11PROV_KDF_CTX;

#define DM_ELEM_SHA(bits) \
  { .name = "SHA"#bits, \
    .digest = CKM_SHA##bits, \
    .digest_size = bits / 8 }
#define DM_ELEM_SHA3(bits) \
  { .name = "SHA3-"#bits, \
    .digest = CKM_SHA3_##bits, \
    .digest_size = bits / 8 }
/* only the ones we can support */
static struct {
    const char *name;
    CK_MECHANISM_TYPE digest;
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
    { "SHA1", CKM_SHA_1, 20 },
    { NULL, 0, 0 }
};

static CK_MECHANISM_TYPE p11prov_hkdf_map_digest(const char *digest)
{
    for (int i = 0; digest_map[i].name != NULL; i++) {
        /* hate to strcasecmp but openssl forces us to */
        if (OPENSSL_strcasecmp(digest, digest_map[i].name) == 0) {
            return digest_map[i].digest;
        }
    }
    return CK_UNAVAILABLE_INFORMATION;
}

static int p11prov_hkdf_map_digest_size(CK_MECHANISM_TYPE digest)
{
    for (int i = 0; digest_map[i].name != NULL; i++) {
        if (digest == digest_map[i].digest) {
            return digest_map[i].digest_size;
        }
    }
    return 0;
}

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

    p11prov_debug("hkdf newctx\n");

    hkdfctx = OPENSSL_zalloc(sizeof(P11PROV_KDF_CTX));
    if (hkdfctx == NULL) return NULL;

    hkdfctx->provctx = ctx;

    /* default mechanism */
    hkdfctx->mechtype = CKM_HKDF_DERIVE;

    return hkdfctx;
}

static void p11prov_hkdf_freectx(void *ctx)
{
    p11prov_debug("hkdf freectx (ctx:%p)\n", ctx);

    p11prov_hkdf_reset(ctx);
    OPENSSL_free(ctx);
}

static void p11prov_hkdf_reset(void *ctx)
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    /* save provider context */
    void *provctx = hkdfctx->provctx;

    p11prov_debug("hkdf reset (ctx:%p)\n", ctx);

    /* free all allocated resources */
    p11prov_key_free(hkdfctx->key);
    if (hkdfctx->session != CK_INVALID_HANDLE) {
        p11prov_put_session(hkdfctx->provctx, hkdfctx->session);
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
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_SENSITIVE, &val_false, sizeof(val_false)},
        {CKA_EXTRACTABLE, &val_true, sizeof(val_true)},
        {CKA_VALUE_LEN, &key_size, sizeof(key_size)}
    };
    CK_FUNCTION_LIST *f;
    CK_MECHANISM mechanism;
    CK_OBJECT_HANDLE pkey_handle;
    CK_OBJECT_HANDLE dkey_handle;
    int ret = RET_OSSL_ERR;

    p11prov_debug("hkdf derive (ctx:%p, key:%p[%zu], params:%p)\n",
                  ctx, key, keylen, params);

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

    pkey_handle = p11prov_key_handle(hkdfctx->key);
    if (pkey_handle == CK_INVALID_HANDLE) {
        P11PROV_raise(hkdfctx->provctx, CKR_KEY_HANDLE_INVALID,
                      "Provided key has invalid handle");
        return RET_OSSL_ERR;
    }

    /* no salt ? */
    if (hkdfctx->params.ulSaltType == 0) {
        hkdfctx->params.ulSaltType = CKF_HKDF_SALT_NULL;
    }

    f = p11prov_ctx_fns(hkdfctx->provctx);
    if (f == NULL) return RET_OSSL_ERR;

    ret = f->C_DeriveKey(hkdfctx->session, &mechanism, pkey_handle,
                         key_template, 5, &dkey_handle);
    if (ret == CKR_OK) {
        unsigned long dkey_len;
        p11prov_debug("HKDF derived hey handle: %lu\n", dkey_handle);
        struct fetch_attrs attrs[1] = {
            { CKA_VALUE, &key, &dkey_len, false, true },
        };
        ret = p11prov_fetch_attributes(f, hkdfctx->session, dkey_handle,
                                       attrs, 1);
        if (ret != CKR_OK) {
            p11prov_debug("hkdf failed to retrieve secret %d\n", ret);
        }
    } else {
        P11PROV_raise(hkdfctx->provctx, ret,
                      "Error returned by C_DeriveKey");
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_hkdf_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    p11prov_debug("hkdf set ctx params (ctx=%p, params=%p)\n",
                  hkdfctx, params);

    if (params == NULL) return RET_OSSL_OK;

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
    if (p) {
        char digest[256];
        char *ptr = digest;
        ret = OSSL_PARAM_get_utf8_string(p, &ptr, 256);
        if (ret != RET_OSSL_OK) return ret;

        hkdfctx->params.prfHashMechanism = p11prov_hkdf_map_digest(digest);
        if (hkdfctx->params.prfHashMechanism == CK_UNAVAILABLE_INFORMATION) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
        p11prov_debug("set digest to %lu\n", hkdfctx->params.prfHashMechanism);
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
            if (ret != RET_OSSL_OK) return ret;
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
        p11prov_debug("set mode to extract:%d expand:%d\n",
                      (int)hkdfctx->params.bExtract,
                      (int)hkdfctx->params.bExpand);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    if (p) {
        void *secret = NULL;
        size_t secret_len;
        /* TODO: import into a pkcs11 key? */
        ret = OSSL_PARAM_get_octet_string(p, &secret, 0, &secret_len);
        if (ret != RET_OSSL_OK) return ret;

        /* Create Session  and key from key material */

        if (hkdfctx->session == CK_INVALID_HANDLE) {
            hkdfctx->session = p11prov_get_session(hkdfctx->provctx,
                                                   CK_UNAVAILABLE_INFORMATION);
        }
        if (hkdfctx->session == CK_INVALID_HANDLE) return RET_OSSL_ERR;

        hkdfctx->key = p11prov_create_secret_key(hkdfctx->provctx,
                                                 hkdfctx->session, true,
                                                 secret, secret_len);
        if (hkdfctx->key == NULL) return RET_OSSL_ERR;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    if (p) {
        void *ptr = NULL;
        size_t len;
        OPENSSL_cleanse(hkdfctx->params.pSalt, hkdfctx->params.ulSaltLen);
        hkdfctx->params.pSalt = NULL;
        ret = OSSL_PARAM_get_octet_string(p, &ptr, 0, &len);
        if (ret != RET_OSSL_OK) return ret;
        hkdfctx->params.ulSaltType = CKF_HKDF_SALT_DATA;
        hkdfctx->params.pSalt = ptr;
        hkdfctx->params.ulSaltLen = len;
        p11prov_debug("set salt (len:%lu)\n", hkdfctx->params.ulSaltLen);
    }

    /* can be multiple paramaters, which wil be all concatenated */
    for (p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO);
         p != NULL;
         p = OSSL_PARAM_locate_const(p + 1, OSSL_KDF_PARAM_INFO)) {
        void *ptr;
        size_t len;

        if (p->data_size == 0 || p->data == NULL) return RET_OSSL_ERR;

        len = hkdfctx->params.ulInfoLen + p->data_size;
        ptr = OPENSSL_realloc(hkdfctx->params.pInfo, len);
        if (ptr == NULL) {
            OPENSSL_cleanse(hkdfctx->params.pInfo, hkdfctx->params.ulInfoLen);
            return RET_OSSL_ERR;
        }
        memcpy(ptr + hkdfctx->params.ulInfoLen, p->data, p->data_size);
        hkdfctx->params.pInfo = ptr;
        hkdfctx->params.ulInfoLen = len;
        p11prov_debug("set info (len:%lu)\n", hkdfctx->params.ulInfoLen);
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_hkdf_settable_ctx_params(void *ctx,
                                                          void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),
        OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static int p11prov_hkdf_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    OSSL_PARAM *p;
    int ret;

    p11prov_debug("hkdf get ctx params (ctx=%p, params=%p)\n",
                  hkdfctx, params);

    if (params == NULL) return RET_OSSL_OK;

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (p) {
        size_t ret_size = 0;
        if (hkdfctx->params.bExpand != CK_FALSE) {
            ret_size = SIZE_MAX;
        } else {
            ret_size = p11prov_hkdf_map_digest_size(
                            hkdfctx->params.prfHashMechanism);
        }
        if (ret_size != 0) {
            return OSSL_PARAM_set_size_t(p, ret_size);
        }
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_hkdf_gettable_ctx_params(void *ctx,
                                                          void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
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
    { 0, NULL }
};
