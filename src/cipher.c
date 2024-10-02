/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"

#if SKEY_SUPPORT == 1

#include "cipher.h"
#include <string.h>
#include "openssl/prov_ssl.h"

DISPATCH_CIPHER_FN(cipher, freectx);
DISPATCH_CIPHER_FN(aes, dupctx);
DISPATCH_CIPHER_FN(cipher, encrypt_init);
DISPATCH_CIPHER_FN(cipher, decrypt_init);
DISPATCH_CIPHER_FN(cipher, update);
DISPATCH_CIPHER_FN(cipher, final);
DISPATCH_CIPHER_FN(aes, cipher);
DISPATCH_CIPHER_FN(aes, get_ctx_params);
DISPATCH_CIPHER_FN(aes, set_ctx_params);
DISPATCH_CIPHER_FN(aes, gettable_ctx_params);
DISPATCH_CIPHER_FN(aes, settable_ctx_params);
DISPATCH_CIPHER_FN(cipher, encrypt_skey_init);
DISPATCH_CIPHER_FN(cipher, decrypt_skey_init);

struct p11prov_cipher_ctx {
    P11PROV_CTX *provctx;

    P11PROV_OBJ *key;
    int keysize;

    bool pad;

    CK_MECHANISM mech;
    CK_FLAGS operation;

    P11PROV_SESSION *session;
};

static void *p11prov_cipher_newctx(void *provctx, int size, CK_ULONG mechanism)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    struct p11prov_cipher_ctx *cctx;

    P11PROV_debug("New Cipher context for mechanism %ld (key size: %d)",
                  mechanism, size);

    cctx = OPENSSL_zalloc(sizeof(struct p11prov_cipher_ctx));
    if (cctx == NULL) {
        return NULL;
    }

    cctx->provctx = ctx;
    cctx->mech.mechanism = mechanism;
    cctx->keysize = size / 8;

    /* OpenSSL Pads by default */
    cctx->pad = true;

    return cctx;
}

static const OSSL_PARAM cipher_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *p11prov_cipher_gettable_params(void *provctx)
{
    return cipher_gettable_params;
}

static struct {
    const char *name;
    int flag;
} param_to_flag[] = {
    { OSSL_CIPHER_PARAM_AEAD, MODE_flag_aead },
    { OSSL_CIPHER_PARAM_CUSTOM_IV, MODE_flag_custom_iv },
    { OSSL_CIPHER_PARAM_CTS, MODE_flag_cts },
    { OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, MODE_flag_tls1_mb },
    { OSSL_CIPHER_PARAM_HAS_RAND_KEY, MODE_flag_rand_key },
    { NULL, 0 },
};

static int p11prov_cipher_get_params(OSSL_PARAM params[], unsigned int mode,
                                     int flags, size_t keysize,
                                     size_t blocksize, size_t ivsize)
{
    OSSL_PARAM *p;
    int ret;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p) {
        ret = OSSL_PARAM_set_uint(p, mode);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    for (int i = 0; param_to_flag[i].name != NULL; i++) {
        p = OSSL_PARAM_locate(params, param_to_flag[i].name);
        if (p) {
            int flag = 0;
            if ((flags & param_to_flag[i].flag) != 0) {
                flag = 1;
            }
            ret = OSSL_PARAM_set_int(p, flag);
            if (ret != RET_OSSL_OK) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return RET_OSSL_ERR;
            }
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p) {
        ret = OSSL_PARAM_set_size_t(p, keysize);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p) {
        ret = OSSL_PARAM_set_size_t(p, blocksize);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p) {
        ret = OSSL_PARAM_set_size_t(p, ivsize);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_OK;
}

static int p11prov_aes_get_params(OSSL_PARAM params[], int size, int mode,
                                  CK_ULONG mechanism)
{
    int ciph_mode = 0;
    int flags = mode & MODE_flags_mask;
    size_t keysize = size / 8;
    size_t blocksize = 16; /* 128 bits for all AES modes */
    size_t ivsize = 16; /* 128 bits for all modes but ECB */

    switch (mode & MODE_modes_mask) {
    case MODE_ecb:
        ciph_mode = EVP_CIPH_ECB_MODE;
        break;
    case MODE_cbc:
        ciph_mode = EVP_CIPH_CBC_MODE;
        break;
    case MODE_ofb:
        ciph_mode = EVP_CIPH_OFB_MODE;
        break;
    case MODE_cfb:
        ciph_mode = EVP_CIPH_CFB_MODE;
        break;
    case MODE_ctr:
        ciph_mode = EVP_CIPH_CTR_MODE;
        break;
    default:
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return RET_OSSL_ERR;
    }

    if (ciph_mode == EVP_CIPH_ECB_MODE) {
        ivsize = 0;
    }

    return p11prov_cipher_get_params(params, ciph_mode, flags, keysize,
                                     blocksize, ivsize);
};

static void p11prov_cipher_freectx(void *ctx)
{
    struct p11prov_cipher_ctx *cctx = (struct p11prov_cipher_ctx *)ctx;

    if (!cctx) {
        return;
    }

    p11prov_obj_free(cctx->key);
    p11prov_return_session(cctx->session);
    OPENSSL_clear_free(cctx->mech.pParameter, cctx->mech.ulParameterLen);
    OPENSSL_clear_free(cctx, sizeof(struct p11prov_cipher_ctx));
}

static void *p11prov_aes_dupctx(void *ctx)
{
    return NULL;
}

static int set_iv(struct p11prov_cipher_ctx *ctx, const unsigned char *iv,
                  size_t ivlen)
{
    /* Free parameter first, as OpenSSL apparently can "init" without
     * keys and just set the IV, and then re-init again with the IV
     * or even set the IV again via parameters ... */
    if (ctx->mech.pParameter) {
        OPENSSL_clear_free(ctx->mech.pParameter, ctx->mech.ulParameterLen);
        ctx->mech.pParameter = NULL;
        ctx->mech.ulParameterLen = 0;
    }
    /* If IV is null it means the app is either trying to clear a context
     * for reuse or did the initialization w/o IV and intends to init again
     * or pass the IV via params, ether way just bail out, the mech will
     * fail to initialize later if the application forgets to set the IV
     * and the mechanism requires it */
    if (iv != NULL && ivlen != 0) {
        ctx->mech.pParameter = OPENSSL_memdup(iv, ivlen);
        if (!ctx->mech.pParameter) {
            return CKR_HOST_MEMORY;
        }
        ctx->mech.ulParameterLen = ivlen;
    }
    return CKR_OK;
}

static CK_RV p11prov_cipher_prep_mech(struct p11prov_cipher_ctx *ctx,
                                      const unsigned char *iv, size_t ivlen,
                                      const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    bool param_as_iv = false;
    CK_RV rv = CKR_OK;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p) {
        unsigned int pad;
        int ret = OSSL_PARAM_get_uint(p, &pad);
        if (ret != RET_OSSL_OK) {
            rv = CKR_MECHANISM_PARAM_INVALID;
            P11PROV_raise(ctx->provctx, rv, "Invalid padding parameter");
            return rv;
        }
        ctx->pad = pad == 1;
    }

    switch (ctx->mech.mechanism) {
    case CKM_AES_ECB:
        if (ctx->pad) {
            /* FIXME: we need to do our padding as there is no _PAD mode
             * for ECB in PKCS#11 */
            return CKR_MECHANISM_PARAM_INVALID;
        }
        /* ECB has no ck params */
        break;

    case CKM_AES_CBC:
        if (ctx->pad) {
            ctx->mech.mechanism = CKM_AES_CBC_PAD;
        }
        param_as_iv = true;
        break;

    case CKM_AES_CBC_PAD:
        if (!ctx->pad) {
            ctx->mech.mechanism = CKM_AES_CBC;
        }
        param_as_iv = true;
        break;

    case CKM_AES_OFB:
    case CKM_AES_CFB128:
    case CKM_AES_CFB1:
    case CKM_AES_CFB8:
    case CKM_AES_CTR:
        /* TODO */
        return CKR_MECHANISM_INVALID;

    case CKM_AES_CTS:
        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_CTS_MODE);
        if (p) {
            const char *mode;
            int ret = OSSL_PARAM_get_utf8_ptr(p, &mode);
            if (ret != RET_OSSL_OK) {
                rv = CKR_MECHANISM_PARAM_INVALID;
                P11PROV_raise(ctx->provctx, rv, "Invalid mode parameter");
                return ret;
            }
            /* Currently only CS1 is supported */
            if (strcmp(mode, OSSL_CIPHER_CTS_MODE_CS1) != 0) {
                rv = CKR_MECHANISM_PARAM_INVALID;
                P11PROV_raise(ctx->provctx, rv, "Unsupported mode: %s", mode);
                return RET_OSSL_ERR;
            }
        }
        param_as_iv = true;
        break;

    default:
        return CKR_MECHANISM_INVALID;
    }

    if (param_as_iv) {
        rv = set_iv(ctx, iv, ivlen);
    }

    return rv;
}

static CK_RV p11prov_cipher_op_init(void *ctx, void *keydata, CK_FLAGS op,
                                    const unsigned char *iv, size_t ivlen,
                                    const OSSL_PARAM params[])
{
    struct p11prov_cipher_ctx *cctx = (struct p11prov_cipher_ctx *)ctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    CK_RV rv;

    rv = p11prov_ctx_status(cctx->provctx);
    if (rv != CKR_OK) {
        return rv;
    }

    cctx->operation = op;

    rv = p11prov_cipher_prep_mech(cctx, iv, ivlen, params);
    if (rv != CKR_OK) {
        return rv;
    }

    /* If keydata is NULL, it means the application will pass the key later,
     * this is allowed in legacy initialization, so skip full init until we
     * have all the pieces. */
    if (key) {
        cctx->key = p11prov_obj_ref(key);
        if (cctx->key == NULL) {
            return CKR_KEY_NEEDED;
        }
    }

    return CKR_OK;
}

static CK_RV p11prov_cipher_session_init(struct p11prov_cipher_ctx *cctx)
{
    CK_SLOT_ID slotid;
    CK_RV rv;

    slotid = p11prov_obj_get_slotid(cctx->key);
    if (slotid == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(cctx->provctx, CKR_SLOT_ID_INVALID,
                      "Provided key has invalid slot");
        return CKR_SLOT_ID_INVALID;
    }

    rv = p11prov_get_session(cctx->provctx, &slotid, NULL, NULL,
                             cctx->mech.mechanism, NULL, NULL, true, false,
                             &cctx->session);
    if (rv != CKR_OK) {
        return rv;
    }

    switch (cctx->operation) {
    case CKF_ENCRYPT:
        rv = p11prov_EncryptInit(
            cctx->provctx, p11prov_session_handle(cctx->session), &cctx->mech,
            p11prov_obj_get_handle(cctx->key));
        break;
    case CKF_DECRYPT:
        rv = p11prov_DecryptInit(
            cctx->provctx, p11prov_session_handle(cctx->session), &cctx->mech,
            p11prov_obj_get_handle(cctx->key));
        break;
    default:
        rv = CKR_GENERAL_ERROR;
    }

    return rv;
}

static int p11prov_cipher_legacy_init(void *ctx, CK_FLAGS op,
                                      const unsigned char *key, size_t keylen,
                                      const unsigned char *iv, size_t ivlen,
                                      const OSSL_PARAM params[])
{
    struct p11prov_cipher_ctx *cctx = (struct p11prov_cipher_ctx *)ctx;
    P11PROV_OBJ *skey = NULL;
    CK_RV rv;

    rv = p11prov_ctx_status(cctx->provctx);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }

    if (key != NULL && keylen > 0) {
        /* The only way to fulfill this request is by importing the AES key
         * in the token as a session object */
        skey =
            p11prov_obj_import_secret_key(cctx->provctx, CKK_AES, key, keylen);
        if (!skey) {
            return RET_OSSL_ERR;
        }
    }

    rv = p11prov_cipher_op_init(ctx, skey, op, iv, ivlen, params);

    p11prov_obj_free(skey);

    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_cipher_encrypt_init(void *ctx, const unsigned char *key,
                                       size_t keylen, const unsigned char *iv,
                                       size_t ivlen, const OSSL_PARAM params[])
{
    P11PROV_debug("encrypt init (ctx=%p, key=%p, iv=%p, params=%p)", ctx, key,
                  iv, params);

    return p11prov_cipher_legacy_init(ctx, CKF_ENCRYPT, key, keylen, iv, ivlen,
                                      params);
}

static int p11prov_cipher_decrypt_init(void *ctx, const unsigned char *key,
                                       size_t keylen, const unsigned char *iv,
                                       size_t ivlen, const OSSL_PARAM params[])
{
    P11PROV_debug("decrypt init (ctx=%p, key=%p, iv=%p, params=%p)", ctx, key,
                  iv, params);

    return p11prov_cipher_legacy_init(ctx, CKF_DECRYPT, key, keylen, iv, ivlen,
                                      params);
}

static int p11prov_cipher_encrypt_skey_init(void *ctx, void *keydata,
                                            const unsigned char *iv,
                                            size_t ivlen,
                                            const OSSL_PARAM params[])
{
    CK_RV rv;

    P11PROV_debug("encrypt skey init (ctx=%p, key=%p, params=%p)", ctx, keydata,
                  params);

    rv = p11prov_cipher_op_init(ctx, keydata, CKF_ENCRYPT, iv, ivlen, params);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_cipher_decrypt_skey_init(void *ctx, void *keydata,
                                            const unsigned char *iv,
                                            size_t ivlen,
                                            const OSSL_PARAM params[])
{
    CK_RV rv;

    P11PROV_debug("decrypt skey init (ctx=%p, key=%p, params=%p)", ctx, keydata,
                  params);

    rv = p11prov_cipher_op_init(ctx, keydata, CKF_DECRYPT, iv, ivlen, params);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_cipher_update(void *ctx, unsigned char *out, size_t *outl,
                                 size_t outsize, const unsigned char *in,
                                 size_t inl)
{
    struct p11prov_cipher_ctx *cctx = (struct p11prov_cipher_ctx *)ctx;
    CK_ULONG outlen = outsize;
    CK_ULONG inlen = inl;
    CK_RV rv;

    if (!cctx->session) {
        rv = p11prov_cipher_session_init(cctx);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    switch (cctx->operation) {
    case CKF_ENCRYPT:
        rv = p11prov_EncryptUpdate(cctx->provctx,
                                   p11prov_session_handle(cctx->session),
                                   (void *)in, inlen, out, &outlen);
        break;
    case CKF_DECRYPT:
        rv = p11prov_DecryptUpdate(cctx->provctx,
                                   p11prov_session_handle(cctx->session),
                                   (void *)in, inlen, out, &outlen);
        break;
    default:
        rv = CKR_GENERAL_ERROR;
    }

    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }

    *outl = outlen;
    return RET_OSSL_OK;
}

static int p11prov_cipher_final(void *ctx, unsigned char *out, size_t *outl,
                                size_t outsize)
{
    struct p11prov_cipher_ctx *cctx = (struct p11prov_cipher_ctx *)ctx;
    CK_ULONG outlen = outsize;
    CK_RV rv;

    if (!cctx->session) {
        return RET_OSSL_ERR;
    }

    switch (cctx->operation) {
    case CKF_ENCRYPT:
        rv = p11prov_EncryptFinal(
            cctx->provctx, p11prov_session_handle(cctx->session), out, &outlen);
        break;
    case CKF_DECRYPT:
        rv = p11prov_DecryptFinal(
            cctx->provctx, p11prov_session_handle(cctx->session), out, &outlen);
        break;
    default:
        rv = CKR_GENERAL_ERROR;
    }

    /* unconditionally return session here as well */
    p11prov_return_session(cctx->session);
    cctx->session = NULL;

    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }

    *outl = outlen;
    return RET_OSSL_OK;
}

static int p11prov_aes_cipher(void *ctx, unsigned char *out, size_t *outl,
                              size_t outsize, const unsigned char *in,
                              size_t inl)
{
    return RET_OSSL_ERR;
}

static int p11prov_aes_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    struct p11prov_cipher_ctx *cctx = (struct p11prov_cipher_ctx *)ctx;
    size_t ivsize = 16; /* 128 bits for all modes but ECB */
    OSSL_PARAM *p;
    int ret;

    if (cctx->mech.mechanism == CKM_AES_ECB) {
        ivsize = 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p) {
        ret = OSSL_PARAM_set_size_t(p, ivsize);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p) {
        int pad = 0;
        if (cctx->pad) {
            pad = 1;
        }
        ret = OSSL_PARAM_set_uint(p, pad);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p) {
        ret = OSSL_PARAM_set_octet_string(p, cctx->mech.pParameter,
                                          cctx->mech.ulParameterLen);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p) {
        ret = OSSL_PARAM_set_octet_string(p, cctx->mech.pParameter,
                                          cctx->mech.ulParameterLen);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p) {
        /* TODO: ? (uint) */
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return RET_OSSL_ERR;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p) {
        size_t keylen = cctx->keysize;
        ret = OSSL_PARAM_set_size_t(p, keylen);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
    if (p) {
        /* TODO: ? (octet_ptr) */
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_aes_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    return RET_OSSL_ERR;
}

static const OSSL_PARAM *p11prov_aes_gettable_ctx_params(void *ctx,
                                                         void *provctx)
{
    return NULL;
}

static const OSSL_PARAM *p11prov_aes_settable_ctx_params(void *ctx,
                                                         void *provctx)
{
    return NULL;
}

DISPATCH_TABLE_CIPHER_FN(aes, 128, ecb, CKM_AES_ECB);
DISPATCH_TABLE_CIPHER_FN(aes, 192, ecb, CKM_AES_ECB);
DISPATCH_TABLE_CIPHER_FN(aes, 256, ecb, CKM_AES_ECB);
DISPATCH_TABLE_CIPHER_FN(aes, 128, cbc, CKM_AES_CBC_PAD);
DISPATCH_TABLE_CIPHER_FN(aes, 192, cbc, CKM_AES_CBC_PAD);
DISPATCH_TABLE_CIPHER_FN(aes, 256, cbc, CKM_AES_CBC_PAD);
DISPATCH_TABLE_CIPHER_FN(aes, 128, ofb, CKM_AES_OFB);
DISPATCH_TABLE_CIPHER_FN(aes, 192, ofb, CKM_AES_OFB);
DISPATCH_TABLE_CIPHER_FN(aes, 256, ofb, CKM_AES_OFB);
DISPATCH_TABLE_CIPHER_FN(aes, 128, cfb, CKM_AES_CFB128);
DISPATCH_TABLE_CIPHER_FN(aes, 192, cfb, CKM_AES_CFB128);
DISPATCH_TABLE_CIPHER_FN(aes, 256, cfb, CKM_AES_CFB128);
DISPATCH_TABLE_CIPHER_FN(aes, 128, cfb1, CKM_AES_CFB1);
DISPATCH_TABLE_CIPHER_FN(aes, 192, cfb1, CKM_AES_CFB1);
DISPATCH_TABLE_CIPHER_FN(aes, 256, cfb1, CKM_AES_CFB1);
DISPATCH_TABLE_CIPHER_FN(aes, 128, cfb8, CKM_AES_CFB8);
DISPATCH_TABLE_CIPHER_FN(aes, 192, cfb8, CKM_AES_CFB8);
DISPATCH_TABLE_CIPHER_FN(aes, 256, cfb8, CKM_AES_CFB8);
DISPATCH_TABLE_CIPHER_FN(aes, 128, ctr, CKM_AES_CTR);
DISPATCH_TABLE_CIPHER_FN(aes, 192, ctr, CKM_AES_CTR);
DISPATCH_TABLE_CIPHER_FN(aes, 256, ctr, CKM_AES_CTR);
DISPATCH_TABLE_CIPHER_FN(aes, 128, cts, CKM_AES_CTS);
DISPATCH_TABLE_CIPHER_FN(aes, 192, cts, CKM_AES_CTS);
DISPATCH_TABLE_CIPHER_FN(aes, 256, cts, CKM_AES_CTS);

#endif
