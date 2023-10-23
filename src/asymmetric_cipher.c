/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>
#include "openssl/rsa.h"

DISPATCH_RSAENC_FN(newctx);
DISPATCH_RSAENC_FN(freectx);
DISPATCH_RSAENC_FN(dupctx);
DISPATCH_RSAENC_FN(encrypt_init);
DISPATCH_RSAENC_FN(encrypt);
DISPATCH_RSAENC_FN(decrypt_init);
DISPATCH_RSAENC_FN(decrypt);
DISPATCH_RSAENC_FN(get_ctx_params);
DISPATCH_RSAENC_FN(set_ctx_params);
DISPATCH_RSAENC_FN(gettable_ctx_params);
DISPATCH_RSAENC_FN(settable_ctx_params);

struct p11prov_rsaenc_ctx {
    P11PROV_CTX *provctx;

    P11PROV_OBJ *key;

    CK_MECHANISM_TYPE mechtype;
    CK_RSA_PKCS_OAEP_PARAMS oaep_params;
};

static void *p11prov_rsaenc_newctx(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    struct p11prov_rsaenc_ctx *encctx;

    encctx = OPENSSL_zalloc(sizeof(struct p11prov_rsaenc_ctx));
    if (encctx == NULL) {
        return NULL;
    }

    encctx->provctx = ctx;

    /* PKCS1.5 is the default */
    encctx->mechtype = CKM_RSA_PKCS;

    return encctx;
}

static void p11prov_rsaenc_freectx(void *ctx)
{
    struct p11prov_rsaenc_ctx *encctx = (struct p11prov_rsaenc_ctx *)ctx;

    if (encctx == NULL) {
        return;
    }

    p11prov_obj_free(encctx->key);
    OPENSSL_free(encctx->oaep_params.pSourceData);
    OPENSSL_clear_free(encctx, sizeof(struct p11prov_rsaenc_ctx));
}

static void *p11prov_rsaenc_dupctx(void *ctx)
{
    struct p11prov_rsaenc_ctx *encctx = (struct p11prov_rsaenc_ctx *)ctx;
    struct p11prov_rsaenc_ctx *newctx;

    if (encctx == NULL) {
        return NULL;
    }

    newctx = p11prov_rsaenc_newctx(encctx->provctx);
    if (newctx == NULL) {
        return NULL;
    }

    newctx->key = p11prov_obj_ref(encctx->key);
    newctx->mechtype = encctx->mechtype;
    newctx->oaep_params = encctx->oaep_params;
    if (encctx->oaep_params.pSourceData) {
        CK_RSA_PKCS_OAEP_PARAMS_PTR src = &encctx->oaep_params;
        CK_RSA_PKCS_OAEP_PARAMS_PTR dst = &newctx->oaep_params;
        dst->pSourceData =
            OPENSSL_memdup(src->pSourceData, src->ulSourceDataLen);
        if (dst->pSourceData == NULL) {
            p11prov_rsaenc_freectx(newctx);
            return NULL;
        }
        dst->ulSourceDataLen = src->ulSourceDataLen;
    }

    return newctx;
}

static int p11prov_rsaenc_set_mechanism(void *ctx, CK_MECHANISM *mechanism)
{
    struct p11prov_rsaenc_ctx *encctx = (struct p11prov_rsaenc_ctx *)ctx;

    mechanism->mechanism = encctx->mechtype;
    mechanism->pParameter = NULL;
    mechanism->ulParameterLen = 0;

    if (mechanism->mechanism == CKM_RSA_PKCS_OAEP) {
        encctx->oaep_params.source = CKZ_DATA_SPECIFIED;
        mechanism->pParameter = &encctx->oaep_params;
        mechanism->ulParameterLen = sizeof(encctx->oaep_params);
    }

    return CKR_OK;
}

static int p11prov_rsaenc_encrypt_init(void *ctx, void *provkey,
                                       const OSSL_PARAM params[])
{
    struct p11prov_rsaenc_ctx *encctx = (struct p11prov_rsaenc_ctx *)ctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)provkey;
    CK_RV ret;

    P11PROV_debug("encrypt init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_ctx_status(encctx->provctx);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    encctx->key = p11prov_obj_ref(key);
    if (encctx->key == NULL) {
        return RET_OSSL_ERR;
    }

    return p11prov_rsaenc_set_ctx_params(ctx, params);
}

static int p11prov_rsaenc_encrypt(void *ctx, unsigned char *out, size_t *outlen,
                                  size_t outsize, const unsigned char *in,
                                  size_t inlen)
{
    struct p11prov_rsaenc_ctx *encctx = (struct p11prov_rsaenc_ctx *)ctx;
    CK_MECHANISM mechanism;
    P11PROV_SESSION *session;
    CK_SESSION_HANDLE sess;
    CK_SLOT_ID slotid;
    CK_OBJECT_HANDLE handle;
    CK_ULONG out_size = *outlen;
    int result = RET_OSSL_ERR;
    CK_RV ret;

    P11PROV_debug("encrypt (ctx=%p)", ctx);

    if (out == NULL) {
        CK_ULONG size = p11prov_obj_get_key_size(encctx->key);
        if (size == CK_UNAVAILABLE_INFORMATION) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            return RET_OSSL_ERR;
        }
        *outlen = size;
        return RET_OSSL_OK;
    }

    slotid = p11prov_obj_get_slotid(encctx->key);
    if (slotid == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(encctx->provctx, CKR_SLOT_ID_INVALID,
                      "Provided key has invalid slot");
        return RET_OSSL_ERR;
    }
    handle = p11prov_obj_get_handle(encctx->key);
    if (handle == CK_INVALID_HANDLE) {
        P11PROV_raise(encctx->provctx, CKR_KEY_HANDLE_INVALID,
                      "Provided key has invalid handle");
        return RET_OSSL_ERR;
    }

    ret = p11prov_rsaenc_set_mechanism(encctx, &mechanism);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_get_session(encctx->provctx, &slotid, NULL, NULL,
                              mechanism.mechanism, NULL, NULL, false, false,
                              &session);
    if (ret != CKR_OK) {
        P11PROV_raise(encctx->provctx, ret,
                      "Failed to open session on slot %lu", slotid);
        return RET_OSSL_ERR;
    }
    sess = p11prov_session_handle(session);

    ret = p11prov_EncryptInit(encctx->provctx, sess, &mechanism, handle);
    if (ret != CKR_OK) {
        if (ret == CKR_MECHANISM_INVALID
            || ret == CKR_MECHANISM_PARAM_INVALID) {
            ERR_raise(ERR_LIB_PROV, PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
        }
        goto endsess;
    }

    ret = p11prov_Encrypt(encctx->provctx, sess, (void *)in, inlen, out,
                          &out_size);
    if (ret != CKR_OK) {
        goto endsess;
    }

    *outlen = out_size;
    result = RET_OSSL_OK;

endsess:
    p11prov_return_session(session);
    return result;
}

static int p11prov_rsaenc_decrypt_init(void *ctx, void *provkey,
                                       const OSSL_PARAM params[])
{
    struct p11prov_rsaenc_ctx *encctx = (struct p11prov_rsaenc_ctx *)ctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)provkey;
    CK_RV ret;

    P11PROV_debug("encrypt init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_ctx_status(encctx->provctx);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    encctx->key = p11prov_obj_ref(key);
    if (encctx->key == NULL) {
        return RET_OSSL_ERR;
    }
    if (p11prov_obj_get_class(encctx->key) != CKO_PRIVATE_KEY) {
        P11PROV_raise(encctx->provctx, CKR_ARGUMENTS_BAD, "Invalid key class");
        return RET_OSSL_ERR;
    }

    return p11prov_rsaenc_set_ctx_params(ctx, params);
}

static int p11prov_rsaenc_decrypt(void *ctx, unsigned char *out, size_t *outlen,
                                  size_t outsize, const unsigned char *in,
                                  size_t inlen)
{
    struct p11prov_rsaenc_ctx *encctx = (struct p11prov_rsaenc_ctx *)ctx;
    CK_MECHANISM mechanism;
    P11PROV_SESSION *session;
    CK_SESSION_HANDLE sess;
    CK_SLOT_ID slotid;
    CK_OBJECT_HANDLE handle;
    CK_ULONG out_size = *outlen;
    int result = RET_OSSL_ERR;
    bool always_auth = false;
    CK_RV ret;

    P11PROV_debug("decrypt (ctx=%p)", ctx);

    if (out == NULL) {
        CK_ULONG size = p11prov_obj_get_key_size(encctx->key);
        if (size == CK_UNAVAILABLE_INFORMATION) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            return RET_OSSL_ERR;
        }
        *outlen = size;
        return RET_OSSL_OK;
    }

    slotid = p11prov_obj_get_slotid(encctx->key);
    if (slotid == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(encctx->provctx, CKR_SLOT_ID_INVALID,
                      "Provided key has invalid slot");
        return RET_OSSL_ERR;
    }
    handle = p11prov_obj_get_handle(encctx->key);
    if (handle == CK_INVALID_HANDLE) {
        P11PROV_raise(encctx->provctx, CKR_KEY_HANDLE_INVALID,
                      "Provided key has invalid handle");
        return RET_OSSL_ERR;
    }

    ret = p11prov_rsaenc_set_mechanism(encctx, &mechanism);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_get_session(encctx->provctx, &slotid, NULL, NULL,
                              mechanism.mechanism, NULL, NULL, true, false,
                              &session);
    if (ret != CKR_OK) {
        P11PROV_raise(encctx->provctx, ret,
                      "Failed to open session on slot %lu", slotid);
        return RET_OSSL_ERR;
    }
    sess = p11prov_session_handle(session);

    ret = p11prov_DecryptInit(encctx->provctx, sess, &mechanism, handle);
    if (ret != CKR_OK) {
        if (ret == CKR_MECHANISM_INVALID
            || ret == CKR_MECHANISM_PARAM_INVALID) {
            ERR_raise(ERR_LIB_PROV, PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
        }
        goto endsess;
    }

    always_auth =
        p11prov_obj_get_bool(encctx->key, CKA_ALWAYS_AUTHENTICATE, false);
    if (always_auth) {
        ret = p11prov_context_specific_login(session, NULL, NULL, NULL);
        if (ret != CKR_OK) {
            goto endsess;
        }
    }

    /* Special handling against PKCS#1 1.5 side channel leaking */
    if (mechanism.mechanism == CKM_RSA_PKCS) {
        CK_ULONG cond;
        ret = side_channel_free_Decrypt(encctx->provctx, sess, (void *)in,
                                        inlen, out, &out_size);
        /* the error case need to be handled in a side-channel free way, so
         * conditionals need to be constant time. Always setting outlen is
         * fine because out_size is initialized to the value of outlen
         * and the value should not matter in an error condition anyway */
        *outlen = out_size;
        cond = constant_equal(ret, CKR_OK);
        result = constant_select_int(cond, RET_OSSL_OK, RET_OSSL_ERR);
        goto endsess;
    }

    ret = p11prov_Decrypt(encctx->provctx, sess, (void *)in, inlen, out,
                          &out_size);
    if (ret != CKR_OK) {
        goto endsess;
    }
    *outlen = out_size;
    result = RET_OSSL_OK;

endsess:
    p11prov_return_session(session);
    return result;
}

static struct {
    CK_MECHANISM_TYPE type;
    int ossl_id;
    const char *string;
} padding_map[] = {
    { CKM_RSA_X_509, RSA_NO_PADDING, OSSL_PKEY_RSA_PAD_MODE_NONE },
    { CKM_RSA_PKCS, RSA_PKCS1_PADDING, OSSL_PKEY_RSA_PAD_MODE_PKCSV15 },
    { CKM_RSA_PKCS_OAEP, RSA_PKCS1_OAEP_PADDING, OSSL_PKEY_RSA_PAD_MODE_OAEP },
    { CKM_RSA_X9_31, RSA_X931_PADDING, OSSL_PKEY_RSA_PAD_MODE_X931 },
    { CK_UNAVAILABLE_INFORMATION, 0, NULL },
};

/* only the ones we can support */
static struct {
    CK_MECHANISM_TYPE digest;
    CK_RSA_PKCS_MGF_TYPE mgf;
} mfg_map[] = {
    { CKM_SHA3_512, CKG_MGF1_SHA3_512 }, { CKM_SHA3_384, CKG_MGF1_SHA3_384 },
    { CKM_SHA3_256, CKG_MGF1_SHA3_256 }, { CKM_SHA3_224, CKG_MGF1_SHA3_224 },
    { CKM_SHA512, CKG_MGF1_SHA512 },     { CKM_SHA384, CKG_MGF1_SHA384 },
    { CKM_SHA256, CKG_MGF1_SHA256 },     { CKM_SHA224, CKG_MGF1_SHA224 },
    { CKM_SHA_1, CKG_MGF1_SHA1 },        { CK_UNAVAILABLE_INFORMATION, 0 },
};

static const char *p11prov_rsaenc_mgf_name(CK_RSA_PKCS_MGF_TYPE mgf)
{
    for (int i = 0; mfg_map[i].digest != CK_UNAVAILABLE_INFORMATION; i++) {
        if (mfg_map[i].mgf == mgf) {
            const char *name;
            CK_RV rv;

            rv = p11prov_digest_get_name(mfg_map[i].digest, &name);
            if (rv != CKR_OK) {
                return NULL;
            }
            return name;
        }
    }
    return NULL;
}

static CK_RSA_PKCS_MGF_TYPE p11prov_rsaenc_map_mgf(const char *digest_name)
{
    CK_MECHANISM_TYPE digest;
    CK_RV rv;

    rv = p11prov_digest_get_by_name(digest_name, &digest);
    if (rv != CKR_OK) {
        return CK_UNAVAILABLE_INFORMATION;
    }

    for (int i = 0; mfg_map[i].digest != CK_UNAVAILABLE_INFORMATION; i++) {
        if (mfg_map[i].digest == digest) {
            return mfg_map[i].mgf;
        }
    }
    return CK_UNAVAILABLE_INFORMATION;
}

static int p11prov_rsaenc_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    struct p11prov_rsaenc_ctx *encctx = (struct p11prov_rsaenc_ctx *)ctx;
    OSSL_PARAM *p;
    int ret;

    P11PROV_debug("rsaenc get ctx params (ctx=%p, params=%p)", ctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p) {
        ret = RET_OSSL_ERR;
        for (int i = 0; padding_map[i].string != NULL; i++) {
            if (padding_map[i].type == encctx->mechtype) {
                switch (p->data_type) {
                case OSSL_PARAM_INTEGER:
                    ret = OSSL_PARAM_set_int(p, padding_map[i].ossl_id);
                    break;
                case OSSL_PARAM_UTF8_STRING:
                    ret = OSSL_PARAM_set_utf8_string(p, padding_map[i].string);
                    break;
                }
                break;
            }
        }
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p) {
        const char *digest;
        CK_RV rv;

        rv = p11prov_digest_get_name(encctx->oaep_params.hashAlg, &digest);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_utf8_string(p, digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p) {
        const char *name;

        name = p11prov_rsaenc_mgf_name(encctx->oaep_params.mgf);
        if (!name) {
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_utf8_string(p, name);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (p) {
        ret = OSSL_PARAM_set_octet_ptr(p, encctx->oaep_params.pSourceData,
                                       encctx->oaep_params.ulSourceDataLen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

static int p11prov_rsaenc_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    struct p11prov_rsaenc_ctx *encctx = (struct p11prov_rsaenc_ctx *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("rsaenc set ctx params (ctx=%p, params=%p)", ctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p) {
        CK_MECHANISM_TYPE mechtype = CK_UNAVAILABLE_INFORMATION;
        if (p->data_type == OSSL_PARAM_INTEGER) {
            int pad_mode;
            /* legacy pad mode number */
            ret = OSSL_PARAM_get_int(p, &pad_mode);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
            for (int i = 0; padding_map[i].string != NULL; i++) {
                if (padding_map[i].ossl_id == pad_mode) {
                    mechtype = padding_map[i].type;
                    break;
                }
            }
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            if (p->data) {
                for (int i = 0; padding_map[i].string != NULL; i++) {
                    if (strcmp(p->data, padding_map[i].string) == 0) {
                        mechtype = padding_map[i].type;
                        break;
                    }
                }
            }
        } else {
            return RET_OSSL_ERR;
        }
        if (mechtype == CK_UNAVAILABLE_INFORMATION) {
            ERR_raise(ERR_LIB_PROV, PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
            return RET_OSSL_ERR;
        }
        encctx->mechtype = mechtype;

        P11PROV_debug_mechanism(encctx->provctx,
                                p11prov_obj_get_slotid(encctx->key),
                                encctx->mechtype);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p) {
        const char *digest = NULL;
        CK_RV rv;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        rv = p11prov_digest_get_by_name(digest, &encctx->oaep_params.hashAlg);
        if (rv != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p) {
        const char *digest = NULL;
        ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        encctx->oaep_params.mgf = p11prov_rsaenc_map_mgf(digest);
        if (encctx->oaep_params.mgf == CK_UNAVAILABLE_INFORMATION) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MGF1_MD);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (p) {
        void *label = NULL;
        size_t len;

        ret = OSSL_PARAM_get_octet_string(p, &label, 0, &len);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        /* just in case it was previously set */
        OPENSSL_free(encctx->oaep_params.pSourceData);

        encctx->oaep_params.pSourceData = label;
        encctx->oaep_params.ulSourceDataLen = len;
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_rsaenc_gettable_ctx_params(void *ctx,
                                                            void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
        /*
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
        */
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *p11prov_rsaenc_settable_ctx_params(void *ctx,
                                                            void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS, NULL,
                               0),
        OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
        /*
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
        */
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_rsa_asym_cipher_functions[] = {
    DISPATCH_RSAENC_ELEM(NEWCTX, newctx),
    DISPATCH_RSAENC_ELEM(FREECTX, freectx),
    DISPATCH_RSAENC_ELEM(DUPCTX, dupctx),
    DISPATCH_RSAENC_ELEM(ENCRYPT_INIT, encrypt_init),
    DISPATCH_RSAENC_ELEM(ENCRYPT, encrypt),
    DISPATCH_RSAENC_ELEM(DECRYPT_INIT, decrypt_init),
    DISPATCH_RSAENC_ELEM(DECRYPT, decrypt),
    DISPATCH_RSAENC_ELEM(GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_RSAENC_ELEM(GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_RSAENC_ELEM(SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_RSAENC_ELEM(SETTABLE_CTX_PARAMS, settable_ctx_params),
};
