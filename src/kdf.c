/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "platform/endian.h"
#include <string.h>
#include <openssl/kdf.h>

struct p11prov_kdf_ctx {
    P11PROV_CTX *provctx;

    P11PROV_OBJ *key;

    CK_MECHANISM_TYPE mechtype;

    int mode;
    CK_MECHANISM_TYPE hash_mech;
    CK_ULONG salt_type;
    uint8_t *salt;
    size_t saltlen;
    uint8_t *info;
    size_t infolen;
    uint8_t *prefix;
    uint8_t *label;
    uint8_t *data;
    size_t prefixlen;
    size_t labellen;
    size_t datalen;

    P11PROV_SESSION *session;

    bool is_tls13_kdf;
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
    hkdfctx->mechtype = CKM_HKDF_DATA;

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

    OPENSSL_clear_free(hkdfctx->salt, hkdfctx->saltlen);
    OPENSSL_clear_free(hkdfctx->info, hkdfctx->infolen);
    OPENSSL_clear_free(hkdfctx->prefix, hkdfctx->prefixlen);
    OPENSSL_clear_free(hkdfctx->label, hkdfctx->labellen);
    OPENSSL_clear_free(hkdfctx->data, hkdfctx->datalen);

    /* zero all */
    memset(hkdfctx, 0, sizeof(*hkdfctx));

    /* restore defaults */
    hkdfctx->provctx = provctx;
    hkdfctx->mechtype = CKM_HKDF_DATA;
}

static CK_RV inner_pkcs11_key(P11PROV_KDF_CTX *hkdfctx, const uint8_t *key,
                              size_t keylen, P11PROV_OBJ **keyobj)
{
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_RV ret;

    if (hkdfctx->session == NULL) {
        ret = p11prov_get_session(hkdfctx->provctx, &slotid, NULL, NULL,
                                  hkdfctx->mechtype, NULL, NULL, false, false,
                                  &hkdfctx->session);
        if (ret != CKR_OK) {
            return ret;
        }
    }
    if (hkdfctx->session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    *keyobj = p11prov_create_secret_key(hkdfctx->provctx, hkdfctx->session,
                                        true, (void *)key, keylen);
    if (*keyobj == NULL) {
        return CKR_KEY_HANDLE_INVALID;
    }
    return CKR_OK;
}

static int inner_extract_key_value(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                                   CK_OBJECT_HANDLE dkey_handle,
                                   unsigned char *key, size_t keylen)
{
    CK_ULONG key_size;
    struct fetch_attrs attrs[1];
    int num = 0;
    CK_RV ret;

    P11PROV_debug("HKDF derived key handle: %lu", dkey_handle);
    FA_SET_BUF_VAL(attrs, num, CKA_VALUE, key, keylen, true);
    ret = p11prov_fetch_attributes(ctx, session, dkey_handle, attrs, num);
    if (ret != CKR_OK) {
        P11PROV_raise(ctx, ret, "Failed to retrieve derived key");
        return ret;
    }
    FA_GET_LEN(attrs, 0, key_size);
    if (key_size != keylen) {
        ret = CKR_GENERAL_ERROR;
        P11PROV_raise(ctx, ret, "Expected derived key of len %zu, but got %lu",
                      keylen, key_size);
        return ret;
    }

    return CKR_OK;
}

static int inner_derive_key(P11PROV_CTX *ctx, P11PROV_OBJ *key,
                            P11PROV_SESSION **session, CK_MECHANISM *mechanism,
                            size_t keylen, CK_OBJECT_HANDLE *dkey_handle)
{
    CK_OBJECT_CLASS class = CKO_DATA;
    CK_BBOOL val_false = CK_FALSE;
    CK_ULONG key_size = keylen;
    CK_ATTRIBUTE key_template[3] = {
        { CKA_CLASS, &class, sizeof(class) },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
        { CKA_VALUE_LEN, &key_size, sizeof(key_size) },
    };
    CK_OBJECT_HANDLE pkey_handle;
    CK_SLOT_ID slotid;
    CK_RV ret;

    pkey_handle = p11prov_obj_get_handle(key);
    if (pkey_handle == CK_INVALID_HANDLE) {
        ret = CKR_KEY_HANDLE_INVALID;
        P11PROV_raise(ctx, ret, "Invalid key handle");
        return ret;
    }

    slotid = p11prov_obj_get_slotid(key);
    if (slotid == CK_UNAVAILABLE_INFORMATION) {
        ret = CKR_SLOT_ID_INVALID;
        P11PROV_raise(ctx, ret, "Invalid key slotid");
        return ret;
    }

    return p11prov_derive_key(ctx, slotid, mechanism, pkey_handle, key_template,
                              3, session, dkey_handle);
}

static int p11prov_hkdf_derive(void *ctx, unsigned char *key, size_t keylen,
                               const OSSL_PARAM params[])
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    CK_HKDF_PARAMS ck_params = {
        .bExtract = (hkdfctx->mode == EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
                     || hkdfctx->mode == EVP_KDF_HKDF_MODE_EXTRACT_ONLY)
                        ? CK_TRUE
                        : CK_FALSE,
        .bExpand = (hkdfctx->mode == EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
                    || hkdfctx->mode == EVP_KDF_HKDF_MODE_EXPAND_ONLY)
                       ? CK_TRUE
                       : CK_FALSE,
        .prfHashMechanism = hkdfctx->hash_mech,
        .ulSaltType = hkdfctx->salt_type,
        .pSalt = hkdfctx->salt,
        .ulSaltLen = hkdfctx->saltlen,
        .hSaltKey = CK_INVALID_HANDLE,
        .pInfo = hkdfctx->info,
        .ulInfoLen = hkdfctx->infolen,
    };
    CK_MECHANISM mechanism = {
        .mechanism = hkdfctx->mechtype,
        .pParameter = &ck_params,
        .ulParameterLen = sizeof(ck_params),
    };

    CK_OBJECT_HANDLE dkey_handle;
    CK_RV ret;

    P11PROV_debug("hkdf derive (ctx:%p, key:%p[%zu], params:%p)", ctx, key,
                  keylen, params);

    ret = p11prov_hkdf_set_ctx_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        P11PROV_raise(hkdfctx->provctx, ret, "Invalid params");
        return RET_OSSL_ERR;
    }

    if (hkdfctx->key == NULL || key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return RET_OSSL_ERR;
    }

    if (keylen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return RET_OSSL_ERR;
    }

    /* no salt ? */
    if (hkdfctx->salt_type == 0) {
        ck_params.ulSaltType = CKF_HKDF_SALT_NULL;
    }

    ret = inner_derive_key(hkdfctx->provctx, hkdfctx->key, &hkdfctx->session,
                           &mechanism, keylen, &dkey_handle);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    ret = inner_extract_key_value(hkdfctx->provctx, hkdfctx->session,
                                  dkey_handle, key, keylen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

/* ref: RFC 8446 - 7.1 Key Schedule
 * Citation:
 *   HKDF-Expand-Label(Secret, Label, Context, Length) =
            HKDF-Expand(Secret, HkdfLabel, Length)
 *
 *   Where HkdfLabel is specified as:
 *
 *     struct {
 *         uint16 length = Length;
 *         opaque label<7..255> = "tls13 " + Label;
 *         opaque context<0..255> = Context;
 *     } HkdfLabel;
 */
#define TLS13_HL_KEY_SIZE 2
#define TLS13_HL_KEY_MAX_LENGTH 65535
#define TLS13_HL_LABEL_SIZE 1
#define TLS13_HL_LABEL_MAX_LENGTH 255
#define TLS13_HL_CONTEXT_SIZE 1
#define TLS13_HL_CONTEXT_MAX_LENGTH 255
#define TLS13_HKDF_LABEL_MAX_SIZE \
    (TLS13_HL_KEY_SIZE + TLS13_HL_LABEL_SIZE + TLS13_HL_LABEL_MAX_LENGTH \
     + TLS13_HL_CONTEXT_SIZE + TLS13_HL_CONTEXT_MAX_LENGTH)

static CK_RV p11prov_tls13_expand_label(P11PROV_KDF_CTX *hkdfctx,
                                        P11PROV_OBJ *keyobj, uint8_t *prefix,
                                        size_t prefixlen, uint8_t *label,
                                        size_t labellen, uint8_t *data,
                                        size_t datalen, size_t keylen,
                                        CK_OBJECT_HANDLE *dkey_handle)
{
    CK_HKDF_PARAMS params = {
        .bExtract = CK_FALSE,
        .bExpand = CK_TRUE,
        .prfHashMechanism = hkdfctx->hash_mech,
        .ulSaltType = 0,
        .pSalt = NULL,
        .ulSaltLen = 0,
        .hSaltKey = CK_INVALID_HANDLE,
    };
    CK_MECHANISM mechanism = {
        .mechanism = hkdfctx->mechtype,
        .pParameter = &params,
        .ulParameterLen = sizeof(params),
    };
    uint8_t info[TLS13_HKDF_LABEL_MAX_SIZE];
    size_t i;
    uint16_t keysize;
    CK_RV ret;

    P11PROV_debug(
        "tls13 expand label (prefix:%p[%zu], label:%p[%zu], data:%p[%zu])",
        prefix, prefixlen, label, labellen, data, datalen);

    if (prefix == NULL || prefixlen == 0 || label == NULL || labellen == 0
        || (prefixlen + labellen > TLS13_HL_LABEL_MAX_LENGTH)
        || (datalen > 0 && data == NULL) || (datalen == 0 && data != NULL)
        || (datalen > TLS13_HL_CONTEXT_MAX_LENGTH)
        || (keylen > TLS13_HL_KEY_MAX_LENGTH)) {
        return CKR_ARGUMENTS_BAD;
    }

    params.pInfo = info;
    params.ulInfoLen = 2 + 1 + prefixlen + labellen + 1 + datalen;
    if (params.ulInfoLen > TLS13_HKDF_LABEL_MAX_SIZE) {
        return CKR_ARGUMENTS_BAD;
    }
    i = 0;
    keysize = htobe16(keylen);
    memcpy(&info[i], &keysize, sizeof(keysize));
    i += sizeof(keysize);
    info[i] = prefixlen + labellen;
    i += 1;
    memcpy(&info[i], prefix, prefixlen);
    i += prefixlen;
    memcpy(&info[i], label, labellen);
    i += labellen;
    info[i] = datalen;
    i += 1;
    if (datalen > 0) {
        memcpy(&info[i], data, datalen);
        i += datalen;
    }
    if (params.ulInfoLen != i) {
        OPENSSL_cleanse(params.pInfo, TLS13_HKDF_LABEL_MAX_SIZE);
        return CKR_HOST_MEMORY;
    }

    ret = inner_derive_key(hkdfctx->provctx, keyobj, &hkdfctx->session,
                           &mechanism, keylen, dkey_handle);

    OPENSSL_cleanse(params.pInfo, params.ulInfoLen);
    return ret;
}

static CK_RV p11prov_tls13_derive_secret(P11PROV_KDF_CTX *hkdfctx,
                                         P11PROV_OBJ *keyobj, size_t keylen,
                                         CK_OBJECT_HANDLE *dkey_handle)
{
    P11PROV_OBJ *zerokey = NULL;
    CK_HKDF_PARAMS params = {
        .bExtract = CK_TRUE,
        .bExpand = CK_FALSE,
        .prfHashMechanism = hkdfctx->hash_mech,
        .ulSaltType = CKF_HKDF_SALT_DATA,
        .hSaltKey = CK_INVALID_HANDLE,
        .pInfo = NULL,
        .ulInfoLen = 0,
    };
    CK_MECHANISM mechanism = {
        .mechanism = CKM_HKDF_DATA,
        .pParameter = &params,
        .ulParameterLen = sizeof(params),
    };
    uint8_t saltbuf[EVP_MAX_MD_SIZE] = { 0 };
    uint8_t zerobuf[EVP_MAX_MD_SIZE] = { 0 };
    size_t saltlen;
    size_t hashlen;
    CK_RV ret;

    ret = p11prov_digest_get_digest_size(hkdfctx->hash_mech, &hashlen);
    if (ret != CKR_OK) {
        return ret;
    }
    saltlen = hashlen;

    if (hkdfctx->salt) {
        P11PROV_OBJ *ek = NULL;
        unsigned char info[hashlen];
        const char *mdname;
        data_buffer digest_data[1] = { 0 }; /* intentionally empty */
        data_buffer digest = { .data = info, .length = hashlen };
        CK_OBJECT_HANDLE skey_handle;

        /* OpenSSL special cases this in an odd way and regenerates a hash as
         * if an empty message was received. */
        ret = p11prov_digest_get_name(hkdfctx->hash_mech, &mdname);
        if (ret != CKR_OK) {
            return ret;
        }

        ret = p11prov_digest_util(hkdfctx->provctx, mdname, NULL, digest_data,
                                  &digest);
        if (ret != CKR_OK) {
            return ret;
        }

        /* In OpenSSL the salt is used as the derivation key */
        ret = inner_pkcs11_key(hkdfctx, hkdfctx->salt, hkdfctx->saltlen, &ek);
        if (ret != CKR_OK) {
            return ret;
        }

        ret = p11prov_tls13_expand_label(
            hkdfctx, ek, hkdfctx->prefix, hkdfctx->prefixlen, hkdfctx->label,
            hkdfctx->labellen, info, hashlen, hashlen, &skey_handle);
        p11prov_obj_free(ek);
        if (ret != CKR_OK) {
            return ret;
        }

        ret = inner_extract_key_value(hkdfctx->provctx, hkdfctx->session,
                                      skey_handle, saltbuf, saltlen);
        if (ret != CKR_OK) {
            return ret;
        }
    }

    params.pSalt = saltbuf;
    params.ulSaltLen = saltlen;

    if (!keyobj) {
        ret = inner_pkcs11_key(hkdfctx, zerobuf, hashlen, &zerokey);
        if (ret != CKR_OK) {
            return ret;
        }
        keyobj = zerokey;
    }

    ret = inner_derive_key(hkdfctx->provctx, keyobj, &hkdfctx->session,
                           &mechanism, keylen, dkey_handle);

    p11prov_obj_free(zerokey);
    return ret;
}

static int p11prov_tls13_kdf_derive(void *ctx, unsigned char *key,
                                    size_t keylen, const OSSL_PARAM params[])
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    CK_OBJECT_HANDLE dkey_handle;
    CK_RV ret;

    P11PROV_debug("tls13 hkdf derive (ctx:%p, key:%p[%zu], params:%p)", ctx,
                  key, keylen, params);

    ret = p11prov_hkdf_set_ctx_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        P11PROV_raise(hkdfctx->provctx, ret, "Invalid params");
        return RET_OSSL_ERR;
    }

    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return RET_OSSL_ERR;
    }

    if (keylen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return RET_OSSL_ERR;
    }

    switch (hkdfctx->mode) {
    case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
        if (hkdfctx->key == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            return RET_OSSL_ERR;
        }
        ret = p11prov_tls13_expand_label(
            hkdfctx, hkdfctx->key, hkdfctx->prefix, hkdfctx->prefixlen,
            hkdfctx->label, hkdfctx->labellen, hkdfctx->data, hkdfctx->datalen,
            keylen, &dkey_handle);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        break;
    case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
        /* key can be null here */
        ret = p11prov_tls13_derive_secret(hkdfctx, hkdfctx->key, keylen,
                                          &dkey_handle);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        break;
    default:
        return RET_OSSL_ERR;
    }

    ret = inner_extract_key_value(hkdfctx->provctx, hkdfctx->session,
                                  dkey_handle, key, keylen);
    if (ret != CKR_OK) {
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

    /* params common to HKDF and TLS13_KDF first */

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
    if (p) {
        const char *digest = NULL;
        CK_RV rv;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        rv = p11prov_digest_get_by_name(digest, &hkdfctx->hash_mech);
        if (rv != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
        P11PROV_debug("set digest to %lu", hkdfctx->hash_mech);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE);
    if (p) {
        if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            if (OPENSSL_strcasecmp(p->data, "EXTRACT_AND_EXPAND") == 0) {
                hkdfctx->mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
            } else if (OPENSSL_strcasecmp(p->data, "EXTRACT_ONLY") == 0) {
                hkdfctx->mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
            } else if (OPENSSL_strcasecmp(p->data, "EXPAND_ONLY") == 0) {
                hkdfctx->mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
            } else {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
                return RET_OSSL_ERR;
            }
        } else {
            ret = OSSL_PARAM_get_int(p, &hkdfctx->mode);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
        }

        switch (hkdfctx->mode) {
        case EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND:
            break;
        case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
            break;
        case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
            break;
        default:
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            return RET_OSSL_ERR;
        }
        P11PROV_debug("set mode to mode:%d", hkdfctx->mode);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    if (p) {
        const void *secret = NULL;
        size_t secret_len;

        ret = OSSL_PARAM_get_octet_string_ptr(p, &secret, &secret_len);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        /* Create Session and key from key material */
        p11prov_obj_free(hkdfctx->key);
        ret = inner_pkcs11_key(hkdfctx, secret, secret_len, &hkdfctx->key);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    if (p) {
        OPENSSL_clear_free(hkdfctx->salt, hkdfctx->saltlen);
        hkdfctx->salt = NULL;
        ret = OSSL_PARAM_get_octet_string(p, (void **)&hkdfctx->salt, 0,
                                          &hkdfctx->saltlen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        hkdfctx->salt_type = CKF_HKDF_SALT_DATA;
        P11PROV_debug("set salt (len:%lu)", hkdfctx->saltlen);
    }

    if (hkdfctx->is_tls13_kdf) {

        if (hkdfctx->mode == EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            return RET_OSSL_ERR;
        }

        OPENSSL_clear_free(hkdfctx->info, hkdfctx->infolen);
        hkdfctx->info = NULL;
        hkdfctx->infolen = 0;

        p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PREFIX);
        if (p) {
            OPENSSL_clear_free(hkdfctx->prefix, hkdfctx->prefixlen);
            hkdfctx->prefix = NULL;
            hkdfctx->prefixlen = 0;
            ret = OSSL_PARAM_get_octet_string(p, (void **)&hkdfctx->prefix, 0,
                                              &hkdfctx->prefixlen);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
        }

        p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_LABEL);
        if (p) {
            OPENSSL_clear_free(hkdfctx->label, hkdfctx->labellen);
            hkdfctx->label = NULL;
            hkdfctx->labellen = 0;
            ret = OSSL_PARAM_get_octet_string(p, (void **)&hkdfctx->label, 0,
                                              &hkdfctx->labellen);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
        }

        p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DATA);
        if (p) {
            OPENSSL_clear_free(hkdfctx->data, hkdfctx->datalen);
            hkdfctx->data = NULL;
            hkdfctx->datalen = 0;
            ret = OSSL_PARAM_get_octet_string(p, (void **)&hkdfctx->data, 0,
                                              &hkdfctx->datalen);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
        }

        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO);
    if (p) {
        OPENSSL_clear_free(hkdfctx->info, hkdfctx->infolen);
        hkdfctx->info = NULL;
        hkdfctx->infolen = 0;
    }
    /* can be multiple parameters, which will be all concatenated */
    for (; p; p = OSSL_PARAM_locate_const(p + 1, OSSL_KDF_PARAM_INFO)) {
        uint8_t *ptr;
        size_t len;

        if (p->data_size == 0 || p->data == NULL) {
            return RET_OSSL_ERR;
        }

        len = hkdfctx->infolen + p->data_size;
        ptr = OPENSSL_realloc(hkdfctx->info, len);
        if (ptr == NULL) {
            OPENSSL_clear_free(hkdfctx->info, hkdfctx->infolen);
            hkdfctx->info = NULL;
            hkdfctx->infolen = 0;
            return RET_OSSL_ERR;
        }
        memcpy(ptr + hkdfctx->infolen, p->data, p->data_size);
        hkdfctx->info = ptr;
        hkdfctx->infolen = len;
        P11PROV_debug("set info (len:%lu)", hkdfctx->infolen);
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
        if (hkdfctx->mode != EVP_KDF_HKDF_MODE_EXTRACT_ONLY) {
            ret_size = SIZE_MAX;
        } else {
            CK_RV rv;

            rv = p11prov_digest_get_digest_size(hkdfctx->hash_mech, &ret_size);
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

static void *p11prov_tls13_kdf_newctx(void *provctx)
{
    P11PROV_KDF_CTX *ctx = (P11PROV_KDF_CTX *)p11prov_hkdf_newctx(provctx);
    ctx->is_tls13_kdf = true;
    return ctx;
}

static const OSSL_PARAM *p11prov_tls13_kdf_settable_ctx_params(void *ctx,
                                                               void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),
        OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PREFIX, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_LABEL, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_DATA, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_tls13_kdf_functions[] = {
    DISPATCH_HKDF_ELEM(tls13_kdf, NEWCTX, newctx),
    DISPATCH_HKDF_ELEM(hkdf, FREECTX, freectx),
    DISPATCH_HKDF_ELEM(hkdf, RESET, reset),
    DISPATCH_HKDF_ELEM(tls13_kdf, DERIVE, derive),
    DISPATCH_HKDF_ELEM(hkdf, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_HKDF_ELEM(tls13_kdf, SETTABLE_CTX_PARAMS, settable_ctx_params),
    DISPATCH_HKDF_ELEM(hkdf, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_HKDF_ELEM(hkdf, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    { 0, NULL },
};
