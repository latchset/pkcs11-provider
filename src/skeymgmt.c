/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"

#if SKEY_SUPPORT == 1

#include "platform/endian.h"
#include <string.h>

DISPATCH_SKEYMGMT_FN(aes, free);
DISPATCH_SKEYMGMT_FN(aes, import);
DISPATCH_SKEYMGMT_FN(aes, export);
DISPATCH_SKEYMGMT_FN(aes, generate);
DISPATCH_SKEYMGMT_FN(aes, get_key_id);
DISPATCH_SKEYMGMT_FN(aes, gen_settable_params);
DISPATCH_SKEYMGMT_FN(aes, imp_settable_params);

static void p11prov_aes_free(void *key)
{
    P11PROV_debug("aes free %p", key);
    p11prov_obj_free((P11PROV_OBJ *)key);
}

static void *p11prov_aes_import(void *provctx, int selection,
                                const OSSL_PARAM params[])
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    const OSSL_PARAM *p;

    P11PROV_debug("aes import");

    if (!ctx) {
        return NULL;
    }

    if (!(selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY)) {
        /* TODO: check for hack import uri */
        return NULL;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES);
    if (p) {
        unsigned char *key = NULL;
        size_t keylen = 0;
        int ret =
            OSSL_PARAM_get_octet_string_ptr(p, (const void **)&key, &keylen);

        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Invalid data");
            return NULL;
        }
        return p11prov_obj_import_secret_key(ctx, CKK_AES, key, keylen);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_REFERENCE);
    if (p) {
        const void *reference = NULL;
        size_t reference_sz = 0;
        int ret = OSSL_PARAM_get_octet_string_ptr(p, &reference, &reference_sz);

        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Invalid data");
            return NULL;
        }
        return p11prov_obj_from_typed_reference(reference, reference_sz,
                                                CKK_AES);
    }

    /* Not a digestible secret key */
    P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Raw Bytes param unavailable");
    return NULL;
}

static int p11prov_aes_export(void *keydata, int selection,
                              OSSL_CALLBACK *param_cb, void *cbarg)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;

    P11PROV_raise(p11prov_obj_get_prov_ctx(key), CKR_KEY_FUNCTION_NOT_PERMITTED,
                  "Not exportable");

    return RET_OSSL_ERR;
}

static int p11prov_cipher_usage_to_flags(const char *usage, CK_FLAGS *flags)
{
    const char *str = usage;
    size_t slen;

    if (usage == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    *flags = 0;

    slen = strlen(str);
    while (slen > 0) {
        const char *p = strchr(str, ' ');
        const char *tok = str;
        int tlen;
        if (p) {
            tlen = p - str;
            slen -= tlen + 1;
            str = p + 1;
        } else {
            tlen = slen;
            slen = 0;
            str = NULL;
        }
        if ((tlen == 7) && (strncmp(tok, "encrypt", tlen) == 0)) {
            *flags |= CKF_ENCRYPT | CKF_DECRYPT;
        } else if ((tlen == 3) && (strncmp(tok, "mac", tlen) == 0)) {
            *flags |= CKF_SIGN | CKF_VERIFY;
        } else if ((tlen == 4) && (strncmp(tok, "wrap", tlen) == 0)) {
            *flags |= CKF_WRAP | CKF_UNWRAP;
        } else if ((tlen == 6) && (strncmp(tok, "derive", tlen) == 0)) {
            *flags |= CKF_DERIVE;
        } else {
            return CKR_ARGUMENTS_BAD;
        }
    }

    return CKR_OK;
}

static void *p11prov_aes_generate(void *provctx, const OSSL_PARAM params[])
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    CK_MECHANISM mech = {
        .mechanism = CKM_AES_KEY_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0,
    };
    CK_BBOOL tokenobj = false;
    CK_ULONG keylen = 32; /* default to 256 bit */
    CK_ATTRIBUTE tmpl[12] = {
        { CKA_TOKEN, &tokenobj, sizeof(tokenobj) },
        { CKA_VALUE_LEN, &keylen, sizeof(keylen) },
        { 0 },
    };
    size_t tmax = sizeof(tmpl) / sizeof(CK_ATTRIBUTE);
    size_t tsize = 2;
    P11PROV_URI *uri = NULL;
    int ephemeral = 1; /* by default we create session keys */
    /* all flags by default */
    CK_FLAGS usage = CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY
                     | CKF_WRAP | CKF_UNWRAP | CKF_DERIVE;
    const OSSL_PARAM *p;
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_RV rv = CKR_MECHANISM_PARAM_INVALID;
    P11PROV_SESSION *session = NULL;
    CK_OBJECT_HANDLE key_handle = CK_INVALID_HANDLE;
    P11PROV_OBJ *key = NULL;
    int ret;

    P11PROV_debug("aes generate");

    if (!ctx) {
        return NULL;
    }

    /* CKA_ID and CKA_LABEL from template URI */
    p = OSSL_PARAM_locate_const(params, P11PROV_PARAM_URI);
    if (p) {
        const char *puri = NULL;
        ret = OSSL_PARAM_get_utf8_string_ptr(p, &puri);
        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx, rv, "Invalid uri parameter type");
            goto done;
        }
        uri = p11prov_parse_uri(ctx, puri);
        if (!uri) {
            goto done;
        }

        /* Id */
        tmpl[tsize] = p11prov_uri_get_id(uri);
        if (tmpl[tsize].ulValueLen != 0) tsize++;
        /* Label */
        tmpl[tsize] = p11prov_uri_get_label(uri);
        if (tmpl[tsize].ulValueLen != 0) tsize++;
    }

    /* Key length */
    p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_KEY_LENGTH);
    if (p) {
        size_t len;
        ret = OSSL_PARAM_get_size_t(p, &len);
        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx, rv, "Invalid key length parameter type");
            goto done;
        }
        if (len != 16 && len != 24 && len != 32) {
            P11PROV_raise(ctx, rv, "Invalid key length parameter value");
            goto done;
        }
        keylen = len;
    }

    /* Session or Token key ? */
    p = OSSL_PARAM_locate_const(params, P11PROV_PARAM_EPHEMERAL);
    if (p) {
        ret = OSSL_PARAM_get_int(p, &ephemeral);
        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx, rv, "Invalid ephemeral parameter type");
            goto done;
        }
        if (ephemeral != 0 && ephemeral != 1) {
            P11PROV_raise(ctx, rv, "Invalid ephemeral parameter value");
            goto done;
        }
    }

    if (!ephemeral) {
        tokenobj = true;
    }

    /* Key Usage */
    p = OSSL_PARAM_locate_const(params, P11PROV_PARAM_KEY_USAGE);
    if (p) {
        const char *key_usage = NULL;
        ret = OSSL_PARAM_get_utf8_string_ptr(p, &key_usage);
        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx, rv, "Invalid key usage parameter type");
            goto done;
        }
        rv = p11prov_cipher_usage_to_flags(key_usage, &usage);
        if (rv != CKR_OK) {
            P11PROV_raise(ctx, rv, "Invalid key usage parameter value");
            goto done;
        }
    }

    rv = p11prov_usage_to_template(tmpl, &tsize, tmax, usage);
    if (rv != CKR_OK) {
        P11PROV_raise(ctx, rv, "Failed to set key usage parameters");
        goto done;
    }

    rv = p11prov_get_session(ctx, &slotid, NULL, uri, mech.mechanism, NULL,
                             NULL, true, true, &session);
    if (rv != CKR_OK) {
        P11PROV_raise(ctx, rv, "Failed to get PKCS#11 session");
        goto done;
    }

    rv = p11prov_GenerateKey(ctx, p11prov_session_handle(session), &mech, tmpl,
                             tsize, &key_handle);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_obj_from_handle(ctx, session, key_handle, &key);
    if (rv != CKR_OK) {
        goto done;
    }

done:
    p11prov_return_session(session);
    p11prov_uri_free(uri);
    return key;
}

static const char *p11prov_aes_get_key_id(void *keydata)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;

    return p11prov_obj_get_public_uri(key);
}

static const OSSL_PARAM aes_import_params[] = {
    OSSL_PARAM_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, NULL, 0),
    OSSL_PARAM_octet_ptr(OSSL_OBJECT_PARAM_REFERENCE, NULL, 0), OSSL_PARAM_END
};

static const OSSL_PARAM *p11prov_aes_imp_settable_params(void *provctx)
{
    return aes_import_params;
}

static const OSSL_PARAM aes_generate_params[] = {
    OSSL_PARAM_size_t(OSSL_SKEY_PARAM_KEY_LENGTH, NULL),
    OSSL_PARAM_utf8_string(P11PROV_PARAM_URI, NULL, 0),
    OSSL_PARAM_octet_string(P11PROV_PARAM_KEY_USAGE, NULL, 0),
    OSSL_PARAM_int(P11PROV_PARAM_EPHEMERAL, NULL), OSSL_PARAM_END
};

static const OSSL_PARAM *p11prov_aes_gen_settable_params(void *provctx)
{
    return aes_generate_params;
}

const OSSL_DISPATCH p11prov_aes_skeymgmt_functions[] = {
    DISPATCH_SKEYMGMT_ELEM(aes, FREE, free),
    DISPATCH_SKEYMGMT_ELEM(aes, IMPORT, import),
    DISPATCH_SKEYMGMT_ELEM(aes, EXPORT, export),
    DISPATCH_SKEYMGMT_ELEM(aes, GENERATE, generate),
    DISPATCH_SKEYMGMT_ELEM(aes, GET_KEY_ID, get_key_id),
    DISPATCH_SKEYMGMT_ELEM(aes, IMP_SETTABLE_PARAMS, imp_settable_params),
    DISPATCH_SKEYMGMT_ELEM(aes, GEN_SETTABLE_PARAMS, gen_settable_params),
    { 0, NULL },
};

DISPATCH_SKEYMGMT_FN(generic_secret, free);
DISPATCH_SKEYMGMT_FN(generic_secret, import);
DISPATCH_SKEYMGMT_FN(generic_secret, export);
DISPATCH_SKEYMGMT_FN(generic_secret, generate);
DISPATCH_SKEYMGMT_FN(generic_secret, get_key_id);
DISPATCH_SKEYMGMT_FN(generic_secret, gen_settable_params);
DISPATCH_SKEYMGMT_FN(generic_secret, imp_settable_params);

static void p11prov_generic_secret_free(void *key)
{
    P11PROV_debug("generic_secret free %p", key);
    p11prov_obj_free((P11PROV_OBJ *)key);
}

static void *p11prov_generic_secret_import(void *provctx, int selection,
                                           const OSSL_PARAM params[])
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    const OSSL_PARAM *p;

    P11PROV_debug("generic_secret import");

    if (!ctx) {
        return NULL;
    }

    if (!(selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY)) {
        /* TODO: check for hack import uri */
        return NULL;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES);
    if (p) {
        unsigned char *key = NULL;
        size_t keylen = 0;
        int ret =
            OSSL_PARAM_get_octet_string_ptr(p, (const void **)&key, &keylen);

        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Invalid data");
            return NULL;
        }
        return p11prov_obj_import_secret_key(ctx, CKK_GENERIC_SECRET, key,
                                             keylen);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_REFERENCE);
    if (p) {
        const void *reference = NULL;
        size_t reference_sz = 0;
        int ret = OSSL_PARAM_get_octet_string_ptr(p, &reference, &reference_sz);

        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Invalid data");
            return NULL;
        }
        return p11prov_obj_from_typed_reference(reference, reference_sz,
                                                CKK_GENERIC_SECRET);
    }

    /* Not a digestible secret key */
    P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Required params are missing");
    return NULL;
}

static int p11prov_generic_secret_export(void *keydata, int selection,
                                         OSSL_CALLBACK *param_cb, void *cbarg)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    P11PROV_CTX *ctx = p11prov_obj_get_prov_ctx(key);
    CK_ATTRIBUTE *cached_value_attr;
    CK_ATTRIBUTE *extractable_attr;
    CK_ATTRIBUTE *sensitive_attr;
    CK_BBOOL extractable = CK_FALSE;
    CK_BBOOL sensitive = CK_TRUE;

    cached_value_attr = p11prov_obj_get_attr(key, CKA_VALUE);
    if (cached_value_attr) {
        OSSL_PARAM params[2];

        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SKEY_PARAM_RAW_BYTES, cached_value_attr->pValue,
            cached_value_attr->ulValueLen);
        params[1] = OSSL_PARAM_construct_end();

        if (param_cb(params, cbarg)) {
            return RET_OSSL_OK;
        }
        return RET_OSSL_ERR;
    }

    extractable_attr = p11prov_obj_get_attr(key, CKA_EXTRACTABLE);
    if (extractable_attr && extractable_attr->ulValueLen == sizeof(CK_BBOOL)) {
        extractable = *(CK_BBOOL *)extractable_attr->pValue;
    }

    sensitive_attr = p11prov_obj_get_attr(key, CKA_SENSITIVE);
    if (sensitive_attr && sensitive_attr->ulValueLen == sizeof(CK_BBOOL)) {
        sensitive = *(CK_BBOOL *)sensitive_attr->pValue;
    }

    if (extractable == CK_TRUE && sensitive == CK_FALSE) {
        P11PROV_SESSION *session = NULL;
        CK_SLOT_ID slotid = p11prov_obj_get_slotid(key);
        CK_ATTRIBUTE value_attr = { CKA_VALUE, NULL_PTR, 0 };
        OSSL_PARAM params[2];
        CK_RV rv;
        int ret = RET_OSSL_ERR;
        CK_ULONG key_size;

        rv = p11prov_get_session(ctx, &slotid, NULL, NULL,
                                 CK_UNAVAILABLE_INFORMATION, NULL, NULL, false,
                                 false, &session);
        if (rv != CKR_OK) {
            P11PROV_raise(ctx, rv, "Failed to get session for export");
            return RET_OSSL_ERR;
        }

        key_size = p11prov_obj_get_key_size(key);
        if (key_size > 0 && key_size != CK_UNAVAILABLE_INFORMATION) {
            value_attr.ulValueLen = key_size;
        } else {
            /* Get length of CKA_VALUE */
            rv = p11prov_GetAttributeValue(ctx, p11prov_session_handle(session),
                                           p11prov_obj_get_handle(key),
                                           &value_attr, 1);
            if (rv != CKR_OK
                || value_attr.ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                P11PROV_raise(ctx, rv, "Failed to get key value length");
                goto done;
            }
        }

        value_attr.pValue = OPENSSL_malloc(value_attr.ulValueLen);
        if (value_attr.pValue == NULL && value_attr.ulValueLen > 0) {
            P11PROV_raise(ctx, CKR_HOST_MEMORY,
                          "Failed to allocate for key value");
            goto done;
        }

        /* Get CKA_VALUE */
        rv = p11prov_GetAttributeValue(ctx, p11prov_session_handle(session),
                                       p11prov_obj_get_handle(key), &value_attr,
                                       1);
        if (rv != CKR_OK) {
            P11PROV_raise(ctx, rv, "Failed to get key value");
            OPENSSL_clear_free(value_attr.pValue, value_attr.ulValueLen);
            goto done;
        }

        params[0] = OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES,
                                                      value_attr.pValue,
                                                      value_attr.ulValueLen);
        params[1] = OSSL_PARAM_construct_end();

        if (param_cb(params, cbarg)) {
            ret = RET_OSSL_OK;
        }

        /* Note: we MUST cache the attribute here, because the callback
         * OpenSSL use expect the value to valid for the life of the key
         * object and will just store the provided pointer. Therefore we
         * need * to keep value_attr.pValue alive as it will be used after
         * this * function returns. This mechanism works also as cache to
         * avoid * re-fecthing from the token multiple times. As multiple
         * import/export * cycles may happen when a mix of legacy and
         * SKEY functions are used.
         */
        rv = p11prov_obj_add_attr(key, &value_attr);
        if (rv != CKR_OK) {
            /* Failed to cache, free the memory to avoid a leak */
            OPENSSL_clear_free(value_attr.pValue, value_attr.ulValueLen);
            ret = RET_OSSL_ERR;
        }

    done:
        p11prov_return_session(session);
        return ret;
    }

    P11PROV_raise(p11prov_obj_get_prov_ctx(key), CKR_KEY_FUNCTION_NOT_PERMITTED,
                  "Not exportable");

    return RET_OSSL_ERR;
}

static void *p11prov_generic_secret_generate(void *provctx,
                                             const OSSL_PARAM params[])
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    CK_MECHANISM mech = {
        .mechanism = CKM_GENERIC_SECRET_KEY_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0,
    };
    CK_BBOOL tokenobj = false;
    CK_ULONG keylen = 32; /* default to 256 bit */
    CK_ATTRIBUTE tmpl[12] = {
        { CKA_TOKEN, &tokenobj, sizeof(tokenobj) },
        { CKA_VALUE_LEN, &keylen, sizeof(keylen) },
        { 0 },
    };
    size_t tmax = sizeof(tmpl) / sizeof(CK_ATTRIBUTE);
    size_t tsize = 2;
    P11PROV_URI *uri = NULL;
    int ephemeral = 1; /* by default we create session keys */
    /* Generally Generic Secrets can only be used in derive-like functions */
    CK_FLAGS usage = CKF_DERIVE;
    const OSSL_PARAM *p;
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_RV rv = CKR_MECHANISM_PARAM_INVALID;
    P11PROV_SESSION *session = NULL;
    CK_OBJECT_HANDLE key_handle = CK_INVALID_HANDLE;
    P11PROV_OBJ *key = NULL;
    int ret;

    P11PROV_debug("generic_secret generate");

    if (!ctx) {
        return NULL;
    }

    /* CKA_ID and CKA_LABEL from template URI */
    p = OSSL_PARAM_locate_const(params, P11PROV_PARAM_URI);
    if (p) {
        const char *puri = NULL;
        ret = OSSL_PARAM_get_utf8_string_ptr(p, &puri);
        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx, rv, "Invalid uri parameter type");
            goto done;
        }
        uri = p11prov_parse_uri(ctx, puri);
        if (!uri) {
            goto done;
        }

        /* Id */
        tmpl[tsize] = p11prov_uri_get_id(uri);
        if (tmpl[tsize].ulValueLen != 0) tsize++;
        /* Label */
        tmpl[tsize] = p11prov_uri_get_label(uri);
        if (tmpl[tsize].ulValueLen != 0) tsize++;
    }

    /* Key length */
    p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_KEY_LENGTH);
    if (p) {
        size_t len;
        ret = OSSL_PARAM_get_size_t(p, &len);
        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx, rv, "Invalid key length parameter type");
            goto done;
        }
        keylen = len;
    }

    /* Session or Token key ? */
    p = OSSL_PARAM_locate_const(params, P11PROV_PARAM_EPHEMERAL);
    if (p) {
        ret = OSSL_PARAM_get_int(p, &ephemeral);
        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx, rv, "Invalid ephemeral parameter type");
            goto done;
        }
        if (ephemeral != 0 && ephemeral != 1) {
            P11PROV_raise(ctx, rv, "Invalid ephemeral parameter value");
            goto done;
        }
    }

    if (!ephemeral) {
        tokenobj = true;
    }

    /* Key Usage */
    p = OSSL_PARAM_locate_const(params, P11PROV_PARAM_KEY_USAGE);
    if (p) {
        const char *key_usage = NULL;
        ret = OSSL_PARAM_get_utf8_string_ptr(p, &key_usage);
        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx, rv, "Invalid key usage parameter type");
            goto done;
        }
        rv = p11prov_cipher_usage_to_flags(key_usage, &usage);
        if (rv != CKR_OK) {
            P11PROV_raise(ctx, rv, "Invalid key usage parameter value");
            goto done;
        }
    }

    rv = p11prov_usage_to_template(tmpl, &tsize, tmax, usage);
    if (rv != CKR_OK) {
        P11PROV_raise(ctx, rv, "Failed to set key usage parameters");
        goto done;
    }

    rv = p11prov_get_session(ctx, &slotid, NULL, uri, mech.mechanism, NULL,
                             NULL, true, true, &session);
    if (rv != CKR_OK) {
        P11PROV_raise(ctx, rv, "Failed to get PKCS#11 session");
        goto done;
    }

    rv = p11prov_GenerateKey(ctx, p11prov_session_handle(session), &mech, tmpl,
                             tsize, &key_handle);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_obj_from_handle(ctx, session, key_handle, &key);
    if (rv != CKR_OK) {
        goto done;
    }

done:
    p11prov_return_session(session);
    p11prov_uri_free(uri);
    return key;
}

static const char *p11prov_generic_secret_get_key_id(void *keydata)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;

    return p11prov_obj_get_public_uri(key);
}

static const OSSL_PARAM generic_secret_import_params[] = {
    OSSL_PARAM_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, NULL, 0),
    OSSL_PARAM_octet_ptr(OSSL_OBJECT_PARAM_REFERENCE, NULL, 0), OSSL_PARAM_END
};

static const OSSL_PARAM *
p11prov_generic_secret_imp_settable_params(void *provctx)
{
    return generic_secret_import_params;
}

static const OSSL_PARAM generic_secret_generate_params[] = {
    OSSL_PARAM_size_t(OSSL_SKEY_PARAM_KEY_LENGTH, NULL),
    OSSL_PARAM_utf8_string(P11PROV_PARAM_URI, NULL, 0),
    OSSL_PARAM_octet_string(P11PROV_PARAM_KEY_USAGE, NULL, 0),
    OSSL_PARAM_int(P11PROV_PARAM_EPHEMERAL, NULL), OSSL_PARAM_END
};

static const OSSL_PARAM *
p11prov_generic_secret_gen_settable_params(void *provctx)
{
    return generic_secret_generate_params;
}

const OSSL_DISPATCH p11prov_generic_secret_skeymgmt_functions[] = {
    DISPATCH_SKEYMGMT_ELEM(generic_secret, FREE, free),
    DISPATCH_SKEYMGMT_ELEM(generic_secret, IMPORT, import),
    DISPATCH_SKEYMGMT_ELEM(generic_secret, EXPORT, export),
    DISPATCH_SKEYMGMT_ELEM(generic_secret, GENERATE, generate),
    DISPATCH_SKEYMGMT_ELEM(generic_secret, GET_KEY_ID, get_key_id),
    DISPATCH_SKEYMGMT_ELEM(generic_secret, IMP_SETTABLE_PARAMS,
                           imp_settable_params),
    DISPATCH_SKEYMGMT_ELEM(generic_secret, GEN_SETTABLE_PARAMS,
                           gen_settable_params),
    { 0, NULL },
};

#endif
