/* Copyright (C) 2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "kem.h"
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/evp.h>

struct p11prov_kem_ctx {
    P11PROV_CTX *provctx;
    P11PROV_OBJ *key;
    int op;
};
typedef struct p11prov_kem_ctx P11PROV_KEM_CTX;

DISPATCH_MLKEM_FN(newctx);
DISPATCH_MLKEM_FN(freectx);
DISPATCH_MLKEM_FN(encapsulate_init);
DISPATCH_MLKEM_FN(encapsulate);
DISPATCH_MLKEM_FN(decapsulate_init);
DISPATCH_MLKEM_FN(decapsulate);
DISPATCH_MLKEM_FN(set_ctx_params);
DISPATCH_MLKEM_FN(settable_ctx_params);
static int p11prov_mlkem_init(void *vctx, int op, void *vkey,
                              const OSSL_PARAM params[]);

static void *p11prov_mlkem_newctx(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_KEM_CTX *kemctx;

    kemctx = OPENSSL_zalloc(sizeof(P11PROV_KEM_CTX));
    if (kemctx == NULL) {
        return NULL;
    }

    kemctx->provctx = ctx;
    return kemctx;
}

static void p11prov_mlkem_freectx(void *vctx)
{
    P11PROV_KEM_CTX *ctx = vctx;

    if (ctx == NULL) {
        return;
    }

    p11prov_obj_free(ctx->key);
    OPENSSL_clear_free(ctx, sizeof(P11PROV_KEM_CTX));
}

static int p11prov_mlkem_init(void *vctx, int op, void *vkey,
                              const OSSL_PARAM params[])
{
    P11PROV_KEM_CTX *ctx = vctx;
    P11PROV_OBJ *key = vkey;
    CK_RV ret;

    if (vctx == NULL || vkey == NULL) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_ctx_status(ctx->provctx);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    p11prov_obj_free(ctx->key);
    ctx->key = p11prov_obj_ref(key);
    if (ctx->key == NULL) {
        P11PROV_raise(ctx->provctx, CKR_ARGUMENTS_BAD, "Invalid object");
        return RET_OSSL_ERR;
    }

    if (p11prov_obj_get_key_type(ctx->key) != CKK_ML_KEM) {
        P11PROV_raise(ctx->provctx, CKR_KEY_TYPE_INCONSISTENT,
                      "Not an ML-KEM key");
        return RET_OSSL_ERR;
    }

    ctx->op = op;
    return p11prov_mlkem_set_ctx_params(vctx, params);
}

static int p11prov_mlkem_encapsulate_init(void *vctx, void *vkey,
                                          const OSSL_PARAM params[])
{
    P11PROV_OBJ *key = vkey;

    if (p11prov_obj_get_class(key) != CKO_PUBLIC_KEY) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
        return RET_OSSL_ERR;
    }
    return p11prov_mlkem_init(vctx, EVP_PKEY_OP_ENCAPSULATE, key, params);
}

static int p11prov_mlkem_decapsulate_init(void *vctx, void *vkey,
                                          const OSSL_PARAM params[])
{
    P11PROV_OBJ *key = vkey;

    if (p11prov_obj_get_class(key) != CKO_PRIVATE_KEY) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return RET_OSSL_ERR;
    }
    return p11prov_mlkem_init(vctx, EVP_PKEY_OP_DECAPSULATE, key, params);
}

static CK_RV p11prov_mlkem_get_lengths(P11PROV_OBJ *key, size_t *ct_len,
                                       size_t *ss_len)
{
    CK_ULONG key_size;

    key_size = p11prov_obj_get_key_size(key);
    switch (key_size) {
    case ML_KEM_512_PK_SIZE:
        *ct_len = ML_KEM_512_CIPHERTEXT_BYTES;
        break;
    case ML_KEM_768_PK_SIZE:
        *ct_len = ML_KEM_768_CIPHERTEXT_BYTES;
        break;
    case ML_KEM_1024_PK_SIZE:
        *ct_len = ML_KEM_1024_CIPHERTEXT_BYTES;
        break;
    default:
        return CKR_KEY_SIZE_RANGE;
    }

    *ss_len = 32;

    return CKR_OK;
}

static int p11prov_mlkem_encapsulate(void *vctx, unsigned char *ct,
                                     size_t *ct_len, unsigned char *ss,
                                     size_t *ss_len)
{
    P11PROV_KEM_CTX *ctx = vctx;
    size_t mlkem_ct_len, mlkem_ss_len;
    CK_OBJECT_HANDLE key_handle;
    P11PROV_SESSION *session = NULL;
    CK_RV rv;
    CK_SLOT_ID slot_id;

    if (ctx == NULL || ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return RET_OSSL_ERR;
    }

    rv = p11prov_mlkem_get_lengths(ctx->key, &mlkem_ct_len, &mlkem_ss_len);
    if (rv != CKR_OK) {
        P11PROV_raise(ctx->provctx, rv, "Failed to get ML-KEM lengths");
        return RET_OSSL_ERR;
    }

    if (ct == NULL || ss == NULL) {
        if (ct_len) {
            *ct_len = mlkem_ct_len;
        }
        if (ss_len) {
            *ss_len = mlkem_ss_len;
        }
        return RET_OSSL_OK;
    }

    if (*ct_len < mlkem_ct_len) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                       "ciphertext buffer too small");
        return RET_OSSL_ERR;
    }
    if (*ss_len < mlkem_ss_len) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                       "shared-secret buffer too small");
        return RET_OSSL_ERR;
    }

    CK_MECHANISM mech = {
        .mechanism = CKM_ML_KEM,
        .pParameter = NULL,
        .ulParameterLen = 0,
    };

    slot_id = p11prov_obj_get_slotid(ctx->key);
    if (slot_id == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR,
                      "Could not determine slot for key");
        return RET_OSSL_ERR;
    }

    rv = p11prov_get_session(ctx->provctx, &slot_id, NULL, NULL, mech.mechanism,
                             NULL, NULL, NULL, NULL, &session);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }

    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_ULONG value_len = mlkem_ss_len;
    CK_BBOOL val_false = CK_FALSE;
    CK_BBOOL val_true = CK_TRUE;
    CK_ATTRIBUTE key_template[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_VALUE_LEN, &value_len, sizeof(value_len) },
        { CKA_SENSITIVE, &val_false, sizeof(val_false) },
        { CKA_EXTRACTABLE, &val_true, sizeof(val_true) },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
    };
    CK_ULONG key_template_len = sizeof(key_template) / sizeof(CK_ATTRIBUTE);
    CK_OBJECT_HANDLE secret_key_handle = CK_INVALID_HANDLE;
    CK_ULONG ct_len_pkcs = *ct_len;

    key_handle = p11prov_obj_get_handle(ctx->key);

    rv = p11prov_EncapsulateKey(
        ctx->provctx, p11prov_session_handle(session), &mech, key_handle,
        key_template, key_template_len, ct, &ct_len_pkcs, &secret_key_handle);
    if (rv == CKR_OK) {
        *ct_len = ct_len_pkcs;

        CK_ATTRIBUTE value_attr = { CKA_VALUE, ss, *ss_len };
        rv = p11prov_GetAttributeValue(ctx->provctx,
                                       p11prov_session_handle(session),
                                       secret_key_handle, &value_attr, 1);
        if (rv == CKR_OK) {
            *ss_len = value_attr.ulValueLen;
        }
    }

    if (secret_key_handle != CK_INVALID_HANDLE) {
        p11prov_DestroyObject(ctx->provctx, p11prov_session_handle(session),
                              secret_key_handle);
    }

    p11prov_return_session(session);

    if (rv != CKR_OK) {
        P11PROV_raise(ctx->provctx, rv, "Encapsulation failed");
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_mlkem_decapsulate(void *vctx, unsigned char *ss,
                                     size_t *ss_len, const uint8_t *ct,
                                     size_t ct_len)
{
    P11PROV_KEM_CTX *ctx = vctx;
    size_t mlkem_ct_len, mlkem_ss_len;
    CK_OBJECT_HANDLE key_handle;
    P11PROV_SESSION *session = NULL;
    CK_RV rv;
    CK_SLOT_ID slot_id;

    if (ctx == NULL || ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return RET_OSSL_ERR;
    }

    rv = p11prov_mlkem_get_lengths(ctx->key, &mlkem_ct_len, &mlkem_ss_len);
    if (rv != CKR_OK) {
        P11PROV_raise(ctx->provctx, rv, "Failed to get ML-KEM lengths");
        return RET_OSSL_ERR;
    }

    if (ss == NULL) {
        if (ss_len) {
            *ss_len = mlkem_ss_len;
        }
        return RET_OSSL_OK;
    }

    if (*ss_len < mlkem_ss_len) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                       "shared-secret buffer too small");
        return RET_OSSL_ERR;
    }

    CK_MECHANISM mech = {
        .mechanism = CKM_ML_KEM,
        .pParameter = NULL,
        .ulParameterLen = 0,
    };

    slot_id = p11prov_obj_get_slotid(ctx->key);
    if (slot_id == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR,
                      "Could not determine slot for key");
        return RET_OSSL_ERR;
    }

    rv = p11prov_get_session(ctx->provctx, &slot_id, NULL, NULL, mech.mechanism,
                             NULL, NULL, NULL, NULL, &session);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }

    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_ULONG value_len = mlkem_ss_len;
    CK_BBOOL val_false = CK_FALSE;
    CK_BBOOL val_true = CK_TRUE;
    CK_ATTRIBUTE key_template[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_VALUE_LEN, &value_len, sizeof(value_len) },
        { CKA_SENSITIVE, &val_false, sizeof(val_false) },
        { CKA_EXTRACTABLE, &val_true, sizeof(val_true) },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
    };
    CK_ULONG key_template_len = sizeof(key_template) / sizeof(CK_ATTRIBUTE);
    CK_OBJECT_HANDLE secret_key_handle = CK_INVALID_HANDLE;

    key_handle = p11prov_obj_get_handle(ctx->key);

    rv = p11prov_DecapsulateKey(ctx->provctx, p11prov_session_handle(session),
                                &mech, key_handle, key_template,
                                key_template_len, (CK_BYTE_PTR)ct, ct_len,
                                &secret_key_handle);

    if (rv == CKR_OK) {
        CK_ATTRIBUTE value_attr = { CKA_VALUE, ss, *ss_len };
        rv = p11prov_GetAttributeValue(ctx->provctx,
                                       p11prov_session_handle(session),
                                       secret_key_handle, &value_attr, 1);
        if (rv == CKR_OK) {
            *ss_len = value_attr.ulValueLen;
        }
    }

    if (secret_key_handle != CK_INVALID_HANDLE) {
        p11prov_DestroyObject(ctx->provctx, p11prov_session_handle(session),
                              secret_key_handle);
    }

    p11prov_return_session(session);

    if (rv != CKR_OK) {
        P11PROV_raise(ctx->provctx, rv, "Decapsulation failed");
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_mlkem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    P11PROV_KEM_CTX *ctx = vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL || params == NULL) {
        return RET_OSSL_OK;
    }
#ifdef OSSL_KEM_PARAM_IKME
    p = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_IKME);
    if (p) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        return RET_OSSL_ERR;
    }
#endif
    return RET_OSSL_OK;
}

static const OSSL_PARAM *
p11prov_mlkem_settable_ctx_params(ossl_unused void *vctx,
                                  ossl_unused void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_END,
    };
    return settable;
}

const OSSL_DISPATCH p11prov_mlkem_kem_functions[] = {
    DISPATCH_MLKEM_ELEM(mlkem, NEWCTX, newctx),
    DISPATCH_MLKEM_ELEM(mlkem, FREECTX, freectx),
    DISPATCH_MLKEM_ELEM(mlkem, ENCAPSULATE_INIT, encapsulate_init),
    DISPATCH_MLKEM_ELEM(mlkem, ENCAPSULATE, encapsulate),
    DISPATCH_MLKEM_ELEM(mlkem, DECAPSULATE_INIT, decapsulate_init),
    DISPATCH_MLKEM_ELEM(mlkem, DECAPSULATE, decapsulate),
    DISPATCH_MLKEM_ELEM(mlkem, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_MLKEM_ELEM(mlkem, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};
