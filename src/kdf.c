/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   Copyright 2026 NXP
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "platform/endian.h"
#include <string.h>
#include <openssl/kdf.h>
#include <openssl/ssl3.h>
#include <openssl/tls1.h>

struct p11prov_kdf_ctx {
    P11PROV_CTX *provctx;

    P11PROV_OBJ *key;

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

static struct {
    CK_ULONG keytype;
    CK_MECHANISM_TYPE cipher;
    CK_ULONG keylen;
    CK_ULONG maclen;
    CK_ULONG ivlen;
} tls12_cipher_map[] = {
    { .keytype = CKK_AES,
      .cipher = CKM_AES_CBC,
      .keylen = 32,
      .maclen = 48,
      .ivlen = 16 },
    { .keytype = CKK_AES,
      .cipher = CKM_AES_CBC,
      .keylen = 16,
      .maclen = 32,
      .ivlen = 16 },
    { .keytype = CKK_AES,
      .cipher = CKM_AES_GCM,
      .keylen = 32,
      .maclen = 0,
      .ivlen = 4 },
    { .keytype = CKK_AES,
      .cipher = CKM_AES_GCM,
      .keylen = 16,
      .maclen = 0,
      .ivlen = 4 },
};

DISPATCH_HKDF_FN(newctx);
DISPATCH_HKDF_FN(freectx);
DISPATCH_HKDF_FN(reset);
DISPATCH_HKDF_FN(derive);
DISPATCH_HKDF_FN(set_ctx_params);
DISPATCH_HKDF_FN(settable_ctx_params);
DISPATCH_HKDF_FN(get_ctx_params);
DISPATCH_HKDF_FN(gettable_ctx_params);
#if defined(OSSL_FUNC_KDF_DERIVE_SKEY)
DISPATCH_HKDF_FN(set_skey);
DISPATCH_HKDF_FN(derive_skey);
#endif

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
}

/* The mechanism is used only to ensure the token can perform the request
 * operation, for the HKDF case it doesn't really matter whether the
 * CKM_HKDF_DERIVE or the CKM_HKDF_DATA mechanisms are requested, any token
 * that supports one SHOULD support the other too */
static CK_RV inner_pkcs11_key(P11PROV_KDF_CTX *hkdfctx,
                              CK_MECHANISM_TYPE mech_type, const uint8_t *key,
                              size_t keylen, P11PROV_OBJ **keyobj)
{
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_RV ret;

    if (hkdfctx->session == NULL) {
        ret = p11prov_get_session(hkdfctx->provctx, &slotid, NULL, NULL,
                                  mech_type, NULL, NULL, false, false,
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
                            CK_KEY_TYPE key_type, size_t keylen,
                            CK_OBJECT_HANDLE *dkey_handle)
{
    CK_OBJECT_CLASS class = CK_UNAVAILABLE_INFORMATION;
    CK_BBOOL val_false = CK_FALSE;
    CK_BBOOL val_true = CK_TRUE;
    CK_ULONG key_size = keylen;
    CK_ATTRIBUTE key_template[6] = {
        { CKA_CLASS, &class, sizeof(class) },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
        { CKA_VALUE_LEN, &key_size, sizeof(key_size) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_SENSITIVE, &val_false, sizeof(val_false) },
        { CKA_EXTRACTABLE, &val_true, sizeof(val_true) },
    };
    CK_ULONG key_tmpl_len = 0;
    CK_RV ret;

    if (mechanism->mechanism == CKM_HKDF_DERIVE) {
        class = CKO_SECRET_KEY;
        key_tmpl_len = 6;
    } else if (mechanism->mechanism == CKM_HKDF_DATA) {
        class = CKO_DATA;
        key_tmpl_len = 3;
    } else {
        ret = CKR_ARGUMENTS_BAD;
        P11PROV_raise(ctx, ret, "Invalid mechanism type: %lu",
                      mechanism->mechanism);
        return ret;
    }

    return p11prov_derive_key(key, mechanism, key_template, key_tmpl_len,
                              session, dkey_handle);
}

static int p11prov_hkdf_format_params(P11PROV_KDF_CTX *hkdfctx,
                                      CK_HKDF_PARAMS *params)
{
    if (hkdfctx->mode == EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
        || hkdfctx->mode == EVP_KDF_HKDF_MODE_EXTRACT_ONLY) {
        params->bExtract = CK_TRUE;
    } else {
        params->bExtract = CK_FALSE;
    }
    if (hkdfctx->mode == EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
        || hkdfctx->mode == EVP_KDF_HKDF_MODE_EXPAND_ONLY) {
        params->bExpand = CK_TRUE;
    } else {
        params->bExpand = CK_FALSE;
    }
    if (hkdfctx->hash_mech) {
        params->prfHashMechanism = hkdfctx->hash_mech;
    } else {
        return CKR_ARGUMENTS_BAD;
    }
    if (hkdfctx->salt_type == 0) {
        params->ulSaltType = CKF_HKDF_SALT_NULL;
    } else if (hkdfctx->salt_type == CKF_HKDF_SALT_DATA) {
        params->ulSaltType = CKF_HKDF_SALT_DATA;
        params->pSalt = hkdfctx->salt;
        params->ulSaltLen = hkdfctx->saltlen;
    }
    if (hkdfctx->info) {
        params->pInfo = hkdfctx->info;
        params->ulInfoLen = hkdfctx->infolen;
    }

    return CKR_OK;
}

static int p11prov_hkdf_derive(void *ctx, unsigned char *key, size_t keylen,
                               const OSSL_PARAM params[])
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    CK_HKDF_PARAMS ck_params = { 0 };
    CK_MECHANISM mechanism = {
        .mechanism = CKM_HKDF_DATA,
        .pParameter = &ck_params,
        .ulParameterLen = sizeof(ck_params),
    };
    CK_OBJECT_HANDLE dkey_handle;
    CK_RV ret;
    int err;

    P11PROV_debug("hkdf derive (ctx:%p, key:%p[%zu], params:%p)", ctx, key,
                  keylen, params);

    err = p11prov_hkdf_set_ctx_params(ctx, params);
    if (err != RET_OSSL_OK) {
        ret = CKR_ARGUMENTS_BAD;
        P11PROV_raise(hkdfctx->provctx, ret, "Invalid params");
        return err;
    }

    if (hkdfctx->key == NULL || key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return RET_OSSL_ERR;
    }

    if (keylen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return RET_OSSL_ERR;
    }

    ret = p11prov_hkdf_format_params(hkdfctx, &ck_params);
    if (ret != CKR_OK) {
        P11PROV_raise(hkdfctx->provctx, ret, "Invalid params");
        return RET_OSSL_ERR;
    }

    ret = inner_derive_key(hkdfctx->provctx, hkdfctx->key, &hkdfctx->session,
                           &mechanism, CK_UNAVAILABLE_INFORMATION, keylen,
                           &dkey_handle);
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

#if defined(OSSL_FUNC_KDF_DERIVE_SKEY)
static int p11prov_hkdf_set_skey(void *ctx, void *skeydata,
                                 const char *paramname)
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)skeydata;

    if (strcmp(paramname, OSSL_KDF_PARAM_KEY)) {
        /* ignore anything but a "key" param */
        return RET_OSSL_OK;
    }

    p11prov_obj_free(hkdfctx->key);
    hkdfctx->key = p11prov_obj_ref(key);

    return RET_OSSL_OK;
}

static void *p11prov_hkdf_derive_skey(void *ctx, const char *key_type,
                                      void *provctx,
                                      OSSL_FUNC_skeymgmt_import_fn *import,
                                      size_t keylen, const OSSL_PARAM params[])
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    CK_HKDF_PARAMS ck_params = { 0 };
    CK_MECHANISM mechanism = {
        .mechanism = CKM_HKDF_DERIVE,
        .pParameter = &ck_params,
        .ulParameterLen = sizeof(ck_params),
    };
    CK_KEY_TYPE keytype;
    CK_OBJECT_HANDLE dkey_handle;
    P11PROV_OBJ *dkey_object = NULL;
    CK_RV ret;
    int err;

    P11PROV_debug("hkdf derive (ctx:%p, key_type:%s, params:%p)", ctx, key_type,
                  params);

    err = p11prov_hkdf_set_ctx_params(ctx, params);
    if (err != RET_OSSL_OK) {
        ret = CKR_ARGUMENTS_BAD;
        P11PROV_raise(hkdfctx->provctx, ret, "Invalid params");
        return NULL;
    }

    if (hkdfctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return NULL;
    }

    if (keylen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return NULL;
    }

    ret = p11prov_hkdf_format_params(hkdfctx, &ck_params);
    if (ret != CKR_OK) {
        P11PROV_raise(hkdfctx->provctx, ret, "Invalid params");
        return RET_OSSL_ERR;
    }

    keytype = p11prov_get_key_type_from_string(key_type);
    if (keytype == CK_UNAVAILABLE_INFORMATION) {
        ret = CKR_ARGUMENTS_BAD;
        P11PROV_raise(hkdfctx->provctx, ret, "Unknown key type: %s", key_type);
        return NULL;
    }

    ret = inner_derive_key(hkdfctx->provctx, hkdfctx->key, &hkdfctx->session,
                           &mechanism, keytype, keylen, &dkey_handle);
    if (ret != CKR_OK) {
        return NULL;
    }

    ret = p11prov_obj_from_handle(hkdfctx->provctx, hkdfctx->session,
                                  dkey_handle, &dkey_object);
    if (ret != CKR_OK) {
        return NULL;
    }

    return dkey_object;
}
#endif

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

static CK_RV
p11prov_tls13_expand_label(P11PROV_KDF_CTX *hkdfctx, P11PROV_OBJ *keyobj,
                           uint8_t *prefix, size_t prefixlen, uint8_t *label,
                           size_t labellen, uint8_t *data, size_t datalen,
                           size_t keylen, CK_MECHANISM_TYPE mech_type,
                           CK_KEY_TYPE key_type, CK_OBJECT_HANDLE *dkey_handle)
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
        .mechanism = mech_type,
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
                           &mechanism, key_type, keylen, dkey_handle);

    OPENSSL_cleanse(params.pInfo, params.ulInfoLen);
    return ret;
}

static CK_RV p11prov_tls13_derive_secret(P11PROV_KDF_CTX *hkdfctx,
                                         P11PROV_OBJ *keyobj, size_t keylen,
                                         CK_MECHANISM_TYPE mech_type,
                                         CK_KEY_TYPE key_type,
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
        .mechanism = mech_type,
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
        ret = inner_pkcs11_key(hkdfctx, CKM_HKDF_DATA, hkdfctx->salt,
                               hkdfctx->saltlen, &ek);
        if (ret != CKR_OK) {
            return ret;
        }

        ret = p11prov_tls13_expand_label(
            hkdfctx, ek, hkdfctx->prefix, hkdfctx->prefixlen, hkdfctx->label,
            hkdfctx->labellen, info, hashlen, hashlen, CKM_HKDF_DATA,
            CK_UNAVAILABLE_INFORMATION, &skey_handle);
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
        ret = inner_pkcs11_key(hkdfctx, mech_type, zerobuf, hashlen, &zerokey);
        if (ret != CKR_OK) {
            return ret;
        }
        keyobj = zerokey;
    }

    ret = inner_derive_key(hkdfctx->provctx, keyobj, &hkdfctx->session,
                           &mechanism, key_type, keylen, dkey_handle);

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
            keylen, CKM_HKDF_DATA, CK_UNAVAILABLE_INFORMATION, &dkey_handle);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        break;
    case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
        /* key can be null here */
        ret = p11prov_tls13_derive_secret(
            hkdfctx, hkdfctx->key, keylen, CKM_HKDF_DATA,
            CK_UNAVAILABLE_INFORMATION, &dkey_handle);
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

#if defined(OSSL_FUNC_KDF_DERIVE_SKEY)
static void *p11prov_tls13_kdf_derive_skey(void *ctx, const char *key_type,
                                           void *provctx,
                                           OSSL_FUNC_skeymgmt_import_fn *import,
                                           size_t keylen,
                                           const OSSL_PARAM params[])
{
    P11PROV_KDF_CTX *hkdfctx = (P11PROV_KDF_CTX *)ctx;
    CK_KEY_TYPE keytype;
    CK_OBJECT_HANDLE dkey_handle;
    P11PROV_OBJ *dkey_object = NULL;
    CK_RV ret;
    int err;

    P11PROV_debug("tls13 kdf derive_skey (ctx:%p, key_type:%s, params:%p)", ctx,
                  key_type, params);

    err = p11prov_hkdf_set_ctx_params(ctx, params);
    if (err != RET_OSSL_OK) {
        ret = CKR_ARGUMENTS_BAD;
        P11PROV_raise(hkdfctx->provctx, ret, "Invalid params");
        return NULL;
    }

    if (keylen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return NULL;
    }

    keytype = p11prov_get_key_type_from_string(key_type);
    if (keytype == CK_UNAVAILABLE_INFORMATION) {
        ret = CKR_ARGUMENTS_BAD;
        P11PROV_raise(hkdfctx->provctx, ret, "Unknown key type");
        return NULL;
    }

    switch (hkdfctx->mode) {
    case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
        if (hkdfctx->key == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            goto done;
        }
        ret = p11prov_tls13_expand_label(
            hkdfctx, hkdfctx->key, hkdfctx->prefix, hkdfctx->prefixlen,
            hkdfctx->label, hkdfctx->labellen, hkdfctx->data, hkdfctx->datalen,
            keylen, CKM_HKDF_DERIVE, keytype, &dkey_handle);
        if (ret != CKR_OK) {
            goto done;
        }
        break;
    case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
        /* key can be null here */
        ret =
            p11prov_tls13_derive_secret(hkdfctx, hkdfctx->key, keylen,
                                        CKM_HKDF_DERIVE, keytype, &dkey_handle);
        if (ret != CKR_OK) {
            goto done;
        }
        break;
    default:
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
        goto done;
    }

    ret = p11prov_obj_from_handle(hkdfctx->provctx, hkdfctx->session,
                                  dkey_handle, &dkey_object);
    if (ret != CKR_OK) {
        /* dkey_object will be NULL */
    }

done:
    return dkey_object;
}
#endif

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
        ret = inner_pkcs11_key(hkdfctx, CKM_HKDF_DERIVE, secret, secret_len,
                               &hkdfctx->key);
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
#if defined(OSSL_FUNC_KDF_DERIVE_SKEY)
    DISPATCH_HKDF_ELEM(hkdf, SET_SKEY, set_skey),
    DISPATCH_HKDF_ELEM(hkdf, DERIVE_SKEY, derive_skey),
#endif
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
#if defined(OSSL_FUNC_KDF_DERIVE_SKEY)
    DISPATCH_HKDF_ELEM(hkdf, SET_SKEY, set_skey),
    DISPATCH_HKDF_ELEM(tls13_kdf, DERIVE_SKEY, derive_skey),
#endif
    { 0, NULL },
};

static int inner_derive_master_key(P11PROV_CTX *ctx, P11PROV_OBJ *key,
                                   P11PROV_SESSION **session,
                                   CK_MECHANISM *mechanism, size_t keylen,
                                   CK_OBJECT_HANDLE *dkey_handle)
{
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_BBOOL val_false = CK_FALSE;
    CK_BBOOL val_true = CK_TRUE;
    CK_ULONG key_size = keylen;
    CK_ATTRIBUTE key_template[] = {
        { CKA_CLASS, &class, sizeof(class) },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
        { CKA_VALUE_LEN, &key_size, sizeof(key_size) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_SIGN, &val_true, sizeof(val_true) },
        { CKA_VERIFY, &val_true, sizeof(val_true) },
        { CKA_DERIVE, &val_true, sizeof(val_true) },
        { CKA_SENSITIVE, &val_false, sizeof(val_false) },
        { CKA_EXTRACTABLE, &val_true, sizeof(val_true) }
    };

    return p11prov_derive_key(key, mechanism, key_template,
                              sizeof(key_template) / sizeof(CK_ATTRIBUTE),
                              session, dkey_handle);
}

static int inner_derive_key_expansion(P11PROV_CTX *ctx, P11PROV_OBJ *key,
                                      P11PROV_SESSION **session,
                                      CK_KEY_TYPE key_type,
                                      CK_MECHANISM *mechanism, size_t keylen,
                                      CK_OBJECT_HANDLE *dkey_handle)
{
    CK_BBOOL val_false = CK_FALSE;
    CK_BBOOL val_true = CK_TRUE;
    CK_ULONG key_size = keylen;
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_ATTRIBUTE key_template[] = {
        { CKA_CLASS, &class, sizeof(class) },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
        { CKA_VALUE_LEN, &key_size, sizeof(key_size) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_SENSITIVE, &val_false, sizeof(val_false) },
        { CKA_EXTRACTABLE, &val_true, sizeof(val_true) },
        { CKA_ENCRYPT, &val_true, sizeof(val_true) },
        { CKA_DECRYPT, &val_true, sizeof(val_true) },
    };

    return p11prov_derive_key(key, mechanism, key_template,
                              sizeof(key_template) / sizeof(CK_ATTRIBUTE),
                              session, dkey_handle);
}

static CK_RV inner_tls_sign(P11PROV_KDF_CTX *tls12ctx, CK_MECHANISM *mechanism,
                            CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR sig,
                            CK_ULONG siglen)
{
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_RV rv;

    if (tls12ctx->session == NULL) {
        rv = p11prov_get_session(tls12ctx->provctx, &slotid, NULL, NULL,
                                 mechanism->mechanism, NULL, NULL, false, false,
                                 &tls12ctx->session);
        if (rv != CKR_OK) {
            return rv;
        }
    }
    if (tls12ctx->session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    rv = p11prov_SignInit(tls12ctx->provctx,
                          p11prov_session_handle(tls12ctx->session), mechanism,
                          p11prov_obj_get_handle(tls12ctx->key));
    if (rv != CKR_OK) {
        return rv;
    }

    return p11prov_Sign(tls12ctx->provctx,
                        p11prov_session_handle(tls12ctx->session), data,
                        datalen, sig, &siglen);
}

static const OSSL_PARAM *p11prov_tls1_prf_kdf_settable_ctx_params(void *ctx,
                                                                  void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SEED, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static int p11prov_tls1_prf_kdf_set_ctx_params(void *ctx,
                                               const OSSL_PARAM params[])
{
    P11PROV_KDF_CTX *kdfctx = (P11PROV_KDF_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("tls1_prf set ctx params (ctx=%p, params=%p)", kdfctx,
                  params);

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
    if (p) {
        const char *digest = NULL;
        CK_RV rv;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        rv = p11prov_digest_get_by_name(digest, &kdfctx->hash_mech);
        if (rv != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
        P11PROV_debug("set digest to %lu", kdfctx->hash_mech);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SECRET);
    if (p) {
        const void *secret = NULL;
        size_t secret_len;

        ret = OSSL_PARAM_get_octet_string_ptr(p, &secret, &secret_len);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        /* Create Session and key from key material */
        p11prov_obj_free(kdfctx->key);
        ret = inner_pkcs11_key(kdfctx, CKM_TLS12_MASTER_KEY_DERIVE_DH, secret,
                               secret_len, &kdfctx->key);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        P11PROV_debug("set secret (len:%lu)", secret_len);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SEED);
    if (p) {
        OPENSSL_clear_free(kdfctx->data, kdfctx->datalen);
        kdfctx->data = NULL;
        kdfctx->datalen = 0;
    }

    /* can be multiple parameters, which will be all concatenated */
    for (; p; p = OSSL_PARAM_locate_const(p + 1, OSSL_KDF_PARAM_SEED)) {
        uint8_t *ptr;
        size_t len;

        if (p->data_size == 0 || p->data == NULL) {
            continue;
        }

        len = kdfctx->datalen + p->data_size;
        ptr = OPENSSL_realloc(kdfctx->data, len);
        if (ptr == NULL) {
            OPENSSL_clear_free(kdfctx->data, kdfctx->datalen);
            kdfctx->data = NULL;
            kdfctx->datalen = 0;
            return RET_OSSL_ERR;
        }
        memcpy(ptr + kdfctx->datalen, p->data, p->data_size);
        kdfctx->data = ptr;
        kdfctx->datalen = len;
        P11PROV_debug("set seed (len:%lu)", kdfctx->datalen);
    }

    return RET_OSSL_OK;
}

#define HAS_TLS12_LABEL(data, datalen, label) \
    (datalen >= TLS_MD_##label##_CONST_SIZE \
     && !CRYPTO_memcmp(data, TLS_MD_##label##_CONST, \
                       TLS_MD_##label##_CONST_SIZE))

static CK_RV p11prov_tls1_prf_derive_generic(P11PROV_KDF_CTX *tls12ctx,
                                             unsigned char *key, size_t keylen)
{
    CK_RV rv;

    if (!HAS_TLS12_LABEL(tls12ctx->data, tls12ctx->datalen, MASTER_SECRET)
        && !HAS_TLS12_LABEL(tls12ctx->data, tls12ctx->datalen, KEY_EXPANSION)) {
        return CKR_DATA_INVALID;
    }

    CK_TLS_KDF_PARAMS mechparams;
    mechparams.prfMechanism = tls12ctx->hash_mech;
    mechparams.pContextData = NULL_PTR;
    mechparams.ulContextDataLength = 0;
    mechparams.pLabel = tls12ctx->data;
    mechparams.ulLabelLength = TLS_MD_MASTER_SECRET_CONST_SIZE;
    mechparams.RandomInfo.ulClientRandomLen = SSL3_RANDOM_SIZE;
    mechparams.RandomInfo.ulServerRandomLen = SSL3_RANDOM_SIZE;
    mechparams.RandomInfo.pClientRandom =
        tls12ctx->data + TLS_MD_MASTER_SECRET_CONST_SIZE;
    mechparams.RandomInfo.pServerRandom =
        tls12ctx->data + TLS_MD_MASTER_SECRET_CONST_SIZE + SSL3_RANDOM_SIZE;

    CK_MECHANISM mech = { .mechanism = CKM_TLS_KDF,
                          .pParameter = &mechparams,
                          .ulParameterLen = sizeof(mechparams) };

    CK_OBJECT_HANDLE dkey_handle = CK_INVALID_HANDLE;
    rv = inner_derive_key_expansion(tls12ctx->provctx, tls12ctx->key,
                                    &tls12ctx->session, CKK_GENERIC_SECRET,
                                    &mech, keylen, &dkey_handle);
    if (rv != CKR_OK) {
        return rv;
    }

    return inner_extract_key_value(tls12ctx->provctx, tls12ctx->session,
                                   dkey_handle, key, keylen);
}

static CK_RV p11prov_tls1_prf_derive_master_secret(P11PROV_KDF_CTX *tls12ctx,
                                                   unsigned char *key,
                                                   size_t keylen)
{
    CK_RV rv;

    if (keylen != SSL3_MASTER_SECRET_SIZE) {
        P11PROV_raise(tls12ctx->provctx, CKR_ARGUMENTS_BAD,
                      "Invalid length for master secret");
        return CKR_ARGUMENTS_BAD;
    }

    if (tls12ctx->datalen
        != TLS_MD_MASTER_SECRET_CONST_SIZE + 2 * SSL3_RANDOM_SIZE) {
        P11PROV_raise(tls12ctx->provctx, CKR_ARGUMENTS_BAD,
                      "Invalid seed length for master secret");
        return CKR_ARGUMENTS_BAD;
    }

    CK_TLS12_MASTER_KEY_DERIVE_PARAMS mechparams;
    mechparams.pVersion = NULL_PTR;
    mechparams.prfHashMechanism = tls12ctx->hash_mech;
    mechparams.RandomInfo.ulClientRandomLen = SSL3_RANDOM_SIZE;
    mechparams.RandomInfo.ulServerRandomLen = SSL3_RANDOM_SIZE;
    mechparams.RandomInfo.pClientRandom =
        tls12ctx->data + TLS_MD_MASTER_SECRET_CONST_SIZE;
    mechparams.RandomInfo.pServerRandom =
        tls12ctx->data + TLS_MD_MASTER_SECRET_CONST_SIZE + SSL3_RANDOM_SIZE;

    CK_MECHANISM mech = { .mechanism = CKM_TLS12_MASTER_KEY_DERIVE_DH,
                          .pParameter = &mechparams,
                          .ulParameterLen = sizeof(mechparams) };

    CK_OBJECT_HANDLE dkey_handle = CK_INVALID_HANDLE;
    rv = inner_derive_master_key(tls12ctx->provctx, tls12ctx->key,
                                 &tls12ctx->session, &mech, keylen,
                                 &dkey_handle);
    if (rv != CKR_OK) {
        return rv;
    }

    return inner_extract_key_value(tls12ctx->provctx, tls12ctx->session,
                                   dkey_handle, key, keylen);
}

static CK_RV
p11prov_tls1_prf_derive_ext_master_secret(P11PROV_KDF_CTX *tls12ctx,
                                          unsigned char *key, size_t keylen)
{
    CK_RV rv;
    size_t digest_size = 0;

    if (keylen != SSL3_MASTER_SECRET_SIZE) {
        P11PROV_raise(tls12ctx->provctx, CKR_ARGUMENTS_BAD,
                      "Invalid length for extended master secret");
        return CKR_ARGUMENTS_BAD;
    }

    rv = p11prov_digest_get_digest_size(tls12ctx->hash_mech, &digest_size);
    if (rv != CKR_OK) {
        return rv;
    }

    if (tls12ctx->datalen
        != TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE + digest_size) {
        P11PROV_raise(tls12ctx->provctx, CKR_ARGUMENTS_BAD,
                      "Invalid seed length for extended master secret");
        return CKR_ARGUMENTS_BAD;
    }

    CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS mechparams;
    mechparams.pVersion = NULL_PTR;
    mechparams.prfHashMechanism = tls12ctx->hash_mech;
    mechparams.pSessionHash =
        tls12ctx->data + TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE;
    mechparams.ulSessionHashLen =
        tls12ctx->datalen - TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE;

    CK_MECHANISM mech = { .mechanism = CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
                          .pParameter = &mechparams,
                          .ulParameterLen = sizeof(mechparams) };

    CK_OBJECT_HANDLE dkey_handle = CK_INVALID_HANDLE;
    rv = inner_derive_master_key(tls12ctx->provctx, tls12ctx->key,
                                 &tls12ctx->session, &mech, keylen,
                                 &dkey_handle);
    if (rv != CKR_OK) {
        return rv;
    }

    return inner_extract_key_value(tls12ctx->provctx, tls12ctx->session,
                                   dkey_handle, key, keylen);
}

static CK_RV p11prov_tls1_prf_derive_key_expansion(P11PROV_KDF_CTX *tls12ctx,
                                                   unsigned char *key,
                                                   size_t keylen)
{
    CK_RV rv;

    if (tls12ctx->datalen
        != TLS_MD_KEY_EXPANSION_CONST_SIZE + 2 * SSL3_RANDOM_SIZE) {
        P11PROV_raise(tls12ctx->provctx, CKR_ARGUMENTS_BAD,
                      "Invalid seed length for key expansion");
        return CKR_ARGUMENTS_BAD;
    }

    /*
     * OpenSSL does not give any hints about which ciphersuite is being used,
     * it expects the provider to fill `keylen` bytes of output.
     *
     * If the generic CKM_TLS_KDF mechanism is not available and we have to
     * use CKM_TLS12_KEY_AND_MAC_DERIVE, we need to know more information about
     * the selected ciphersuite: the mac key size, the enc key size and the IV
     * size.
     *
     * We can use the size of the requested key block to "guess" the ciphersuite.
     */
    CK_ULONG macsz = 0, keysz = 0, ivsz = 0;
    for (size_t i = 0;
         i < sizeof(tls12_cipher_map) / sizeof(tls12_cipher_map[0]); i++) {
        CK_ULONG keyblocklen = tls12_cipher_map[i].maclen
                               + tls12_cipher_map[i].keylen
                               + tls12_cipher_map[i].ivlen;
        keyblocklen *= 2;

        if (keyblocklen == keylen) {
            macsz = tls12_cipher_map[i].maclen;
            keysz = tls12_cipher_map[i].keylen;
            ivsz = tls12_cipher_map[i].ivlen;
            break;
        }
    }

    /* Couldn't find a corresponding cipher for this length; macsz can be 0 */
    if (!keysz || !ivsz) {
        P11PROV_raise(tls12ctx->provctx, CKR_GENERAL_ERROR,
                      "Cannot determine ciphersuite");
        return CKR_GENERAL_ERROR;
    }

    CK_BYTE iv[EVP_MAX_IV_LENGTH * 2] = { 0 };
    CK_SSL3_KEY_MAT_OUT keymaterial = { 0 };
    keymaterial.pIVClient = iv;
    keymaterial.pIVServer = iv + ivsz;

    CK_TLS12_KEY_MAT_PARAMS mechparams;
    mechparams.bIsExport = CK_FALSE;
    mechparams.prfHashMechanism = tls12ctx->hash_mech;
    mechparams.pReturnedKeyMaterial = &keymaterial;
    mechparams.RandomInfo.ulClientRandomLen = SSL3_RANDOM_SIZE;
    mechparams.RandomInfo.ulServerRandomLen = SSL3_RANDOM_SIZE;
    mechparams.RandomInfo.pServerRandom =
        tls12ctx->data + TLS_MD_KEY_EXPANSION_CONST_SIZE;
    mechparams.RandomInfo.pClientRandom =
        tls12ctx->data + TLS_MD_KEY_EXPANSION_CONST_SIZE + SSL3_RANDOM_SIZE;
    mechparams.ulMacSizeInBits = macsz * 8;
    mechparams.ulKeySizeInBits = keysz * 8;
    mechparams.ulIVSizeInBits = ivsz * 8;

    CK_MECHANISM mech = { .mechanism = CKM_TLS12_KEY_AND_MAC_DERIVE,
                          .pParameter = &mechparams,
                          .ulParameterLen = sizeof(mechparams) };

    rv = inner_derive_key_expansion(tls12ctx->provctx, tls12ctx->key,
                                    &tls12ctx->session, CKK_AES, &mech, keysz,
                                    NULL_PTR);
    if (rv != CKR_OK) {
        P11PROV_raise(tls12ctx->provctx, rv, "Key expansion failed");
        return rv;
    }

    unsigned char keyval[EVP_MAX_KEY_LENGTH] = { 0 };
    size_t offset = 0;

    if (mechparams.ulMacSizeInBits) {
        rv = inner_extract_key_value(
            tls12ctx->provctx, tls12ctx->session,
            mechparams.pReturnedKeyMaterial->hClientMacSecret, keyval, macsz);
        if (rv != CKR_OK) {
            return rv;
        }
        memcpy(key + offset, keyval, macsz);
        offset += macsz;

        rv = inner_extract_key_value(
            tls12ctx->provctx, tls12ctx->session,
            mechparams.pReturnedKeyMaterial->hServerMacSecret, keyval, macsz);
        if (rv != CKR_OK) {
            return rv;
        }
        memcpy(key + offset, keyval, macsz);
        offset += macsz;
    }

    rv = inner_extract_key_value(tls12ctx->provctx, tls12ctx->session,
                                 mechparams.pReturnedKeyMaterial->hClientKey,
                                 keyval, keysz);
    if (rv != CKR_OK) {
        return rv;
    }
    memcpy(key + offset, keyval, keysz);
    offset += keysz;

    rv = inner_extract_key_value(tls12ctx->provctx, tls12ctx->session,
                                 mechparams.pReturnedKeyMaterial->hServerKey,
                                 keyval, keysz);
    if (rv != CKR_OK) {
        return rv;
    }
    memcpy(key + offset, keyval, keysz);
    offset += keysz;

    memcpy(key + offset, mechparams.pReturnedKeyMaterial->pIVClient, ivsz);
    offset += ivsz;

    memcpy(key + offset, mechparams.pReturnedKeyMaterial->pIVServer, ivsz);
    offset += ivsz;

    /* At this point, offset should be equal to keylen */
    if (offset != keylen) {
        P11PROV_raise(tls12ctx->provctx, CKR_GENERAL_ERROR,
                      "Key material size mismatch");
        return CKR_GENERAL_ERROR;
    }

    return rv;
}

static CK_RV p11prov_tls1_prf_derive_finished(P11PROV_KDF_CTX *tls12ctx,
                                              unsigned char *key, size_t keylen,
                                              CK_ULONG flag)
{
    if (flag != 1 && flag != 2) {
        P11PROV_raise(tls12ctx->provctx, CKR_GENERAL_ERROR,
                      "Invalid server or client flag");
        return CKR_GENERAL_ERROR;
    }

    CK_TLS_MAC_PARAMS mechparams;
    mechparams.prfHashMechanism = tls12ctx->hash_mech;
    mechparams.ulMacLength = TLS1_FINISH_MAC_LENGTH;
    mechparams.ulServerOrClient = flag;

    CK_MECHANISM mech = { .mechanism = CKM_TLS_MAC,
                          .pParameter = &mechparams,
                          .ulParameterLen = sizeof(mechparams) };

    /* The data passed to CKM_TLS_MAC must not include the "client" or "server"
     * label, so we must skip over the first few bytes. TLS_MD_CLIENT_FINISH_CONST_SIZE
     * and TLS_MD_SERVER_FINISH_CONST_SIZE have the same value, so use the first one. */
    return inner_tls_sign(
        tls12ctx, &mech, tls12ctx->data + TLS_MD_CLIENT_FINISH_CONST_SIZE,
        tls12ctx->datalen - TLS_MD_CLIENT_FINISH_CONST_SIZE, key, keylen);
}

static int p11prov_tls1_prf_kdf_derive(void *ctx, unsigned char *key,
                                       size_t keylen, const OSSL_PARAM params[])
{
    P11PROV_KDF_CTX *tls12ctx = (P11PROV_KDF_CTX *)ctx;
    CK_RV rv = CKR_OK;

    P11PROV_debug("tls1_prf derive (ctx:%p, key:%p[%zu], params:%p)", ctx, key,
                  keylen, params);

    rv = p11prov_tls1_prf_kdf_set_ctx_params(ctx, params);
    if (rv != RET_OSSL_OK) {
        P11PROV_raise(tls12ctx->provctx, rv, "Invalid params");
        return RET_OSSL_ERR;
    }

    if (tls12ctx->key == NULL || key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return RET_OSSL_ERR;
    }

    if (keylen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return RET_OSSL_ERR;
    }

    if (tls12ctx->datalen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        return RET_OSSL_ERR;
    }

    /* Try the generic TLS1-PRF derivation mechanism if possible */
    CK_SLOT_ID slotid = p11prov_session_slotid(tls12ctx->session);
    if (slotid != CK_UNAVAILABLE_INFORMATION) {
        rv = p11prov_check_mechanism(tls12ctx->provctx, slotid, CKM_TLS_KDF);
        if (rv == CKR_OK) {
            rv = p11prov_tls1_prf_derive_generic(tls12ctx, key, keylen);
            if (rv == CKR_OK) {
                return RET_OSSL_OK;
            }
        }
    }

    if (HAS_TLS12_LABEL(tls12ctx->data, tls12ctx->datalen, MASTER_SECRET)) {
        rv = p11prov_tls1_prf_derive_master_secret(tls12ctx, key, keylen);
    } else if (HAS_TLS12_LABEL(tls12ctx->data, tls12ctx->datalen,
                               EXTENDED_MASTER_SECRET)) {
        rv = p11prov_tls1_prf_derive_ext_master_secret(tls12ctx, key, keylen);
    } else if (HAS_TLS12_LABEL(tls12ctx->data, tls12ctx->datalen,
                               KEY_EXPANSION)) {
        rv = p11prov_tls1_prf_derive_key_expansion(tls12ctx, key, keylen);
    } else if (HAS_TLS12_LABEL(tls12ctx->data, tls12ctx->datalen,
                               SERVER_FINISH)) {
        rv = p11prov_tls1_prf_derive_finished(tls12ctx, key, keylen, 1);
    } else if (HAS_TLS12_LABEL(tls12ctx->data, tls12ctx->datalen,
                               CLIENT_FINISH)) {
        rv = p11prov_tls1_prf_derive_finished(tls12ctx, key, keylen, 2);
    } else {
        P11PROV_raise(tls12ctx->provctx, CKR_ARGUMENTS_BAD,
                      "Unknown seed for TLS1.2 derivation");
        return RET_OSSL_ERR;
    }

    if (rv == CKR_OK) {
        return RET_OSSL_OK;
    }

    return RET_OSSL_ERR;
}

const OSSL_DISPATCH p11prov_tls1_prf_kdf_functions[] = {
    DISPATCH_HKDF_ELEM(hkdf, NEWCTX, newctx),
    DISPATCH_HKDF_ELEM(hkdf, FREECTX, freectx),
    DISPATCH_HKDF_ELEM(hkdf, RESET, reset),
    DISPATCH_HKDF_ELEM(tls1_prf_kdf, DERIVE, derive),
    DISPATCH_HKDF_ELEM(tls1_prf_kdf, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_HKDF_ELEM(tls1_prf_kdf, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};
