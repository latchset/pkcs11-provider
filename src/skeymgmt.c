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
    unsigned char *key;
    size_t keylen;

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
        int ret =
            OSSL_PARAM_get_octet_string_ptr(p, (const void **)&key, &keylen);
        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Invalid data");
            return NULL;
        }
    } else {
        /* Not a digestible secret key */
        P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Raw Bytes param unavailable");
        return NULL;
    }

    return p11prov_obj_import_secret_key(ctx, CKK_AES, key, keylen);
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
    OSSL_PARAM_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, NULL, 0), OSSL_PARAM_END
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

#endif
