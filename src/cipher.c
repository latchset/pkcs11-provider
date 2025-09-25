/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"

#if SKEY_SUPPORT == 1

#include "cipher.h"
#include "openssl/prov_ssl.h"
#include "openssl/rand.h"
#include <string.h>

#define MAX_PADDING 256;
#define AESBLOCK 16 /* 128 bits for all AES modes */

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
    enum {
        SESS_UNUSED,
        SESS_INITIALIZED,
        SESS_FINALIZED,
    } session_state;

    /* OpenSSL violates layering separation and decided
     * to process AES CBC MAC/padding handling in TLS 1.x < 1.3
     * in the lower cipher layer, so we have to do it here as well
     * for compatibility ... */
    unsigned int tlsver;
    size_t tlsmacsize;
    unsigned char *tlsmac;
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
    size_t blocksize = AESBLOCK;
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

    if (cctx->session) {
        if (cctx->session_state == SESS_INITIALIZED) {
            /* Finalize any operation to avoid leaving a hanging
             * operation on this session. Ignore return errors here
             * intentionally as errors can be returned if the operation was
             * internally finalized because of a previous internal token
             * error state and, in any case, not much to be done. */
            CK_RV ret;
            CK_SESSION_HANDLE sess = p11prov_session_handle(cctx->session);
            if (cctx->operation == CKF_ENCRYPT) {
                ret = p11prov_EncryptInit(cctx->provctx, sess, NULL,
                                          CK_INVALID_HANDLE);
            } else {
                ret = p11prov_DecryptInit(cctx->provctx, sess, NULL,
                                          CK_INVALID_HANDLE);
            }
            if (ret != CKR_OK) {
                /* NSS softokn has a broken interface and is incapable of
                 * dropping operations on sessions returning a generic
                 * CKR_MECHANISM_PARAM_INVALID when the mechanism is set to
                 * NULL. Attempt to force cancellation via C_SessionCancel. */
                ret =
                    p11prov_SessionCancel(cctx->provctx, sess, cctx->operation);
            }
            if (ret != CKR_OK) {
                /* When this happens the session becomes broken as
                 * we can't initialize operations on it anymore */
                p11prov_session_mark_broken(cctx->session);
            }
            cctx->session_state = SESS_FINALIZED;
        }
        p11prov_return_session(cctx->session);
    }

    p11prov_obj_free(cctx->key);
    OPENSSL_clear_free(cctx->mech.pParameter, cctx->mech.ulParameterLen);
    OPENSSL_clear_free(cctx->tlsmac, cctx->tlsmacsize);
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

static int p11prov_aes_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static CK_RV p11prov_cipher_prep_mech(struct p11prov_cipher_ctx *ctx,
                                      const unsigned char *iv, size_t ivlen,
                                      const OSSL_PARAM params[])
{
    bool param_as_iv = false;
    CK_RV rv = CKR_OK;
    int ret;

    switch (ctx->mech.mechanism) {
    case CKM_AES_ECB:
        /* ECB has no ck params */
        break;

    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
    case CKM_AES_CTS:
        param_as_iv = true;
        break;

    case CKM_AES_OFB:
    case CKM_AES_CFB128:
    case CKM_AES_CFB1:
    case CKM_AES_CFB8:
    case CKM_AES_CTR:
        /* TODO */
        return CKR_MECHANISM_INVALID;

        param_as_iv = true;
        break;

    default:
        return CKR_MECHANISM_INVALID;
    }

    if (param_as_iv) {
        rv = set_iv(ctx, iv, ivlen);
        if (rv != CKR_OK) {
            return rv;
        }
    }

    ret = p11prov_aes_set_ctx_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    return CKR_OK;
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
    CK_RV rv;

    if (cctx->tlsver != 0 && cctx->mech.mechanism == CKM_AES_CBC_PAD) {
        /* In the special TLS mode we handle de-padding and mac extraction
         * outside the pkcs11 module to conform to what OpenSSL does */
        cctx->mech.mechanism = CKM_AES_CBC;
    }

    rv = p11prov_try_session_ref(cctx->key, cctx->mech.mechanism, true, false,
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

    if (rv == CKR_OK) {
        cctx->session_state = SESS_INITIALIZED;
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

/* This function needs to be executed in constant time */
static CK_RV tlsunpad(struct p11prov_cipher_ctx *cctx, unsigned char *out,
                      CK_ULONG inlen, CK_ULONG *outlen)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_ULONG overhead = cctx->tlsmacsize + 1; /* mac size + padlen byte */
    CK_ULONG maxcheck = MAX_PADDING;
    CK_ULONG padsize = out[inlen - 1];
    CK_ULONG olen = inlen;
    CK_ULONG pass;

    /* Remove explicit IV for TLS 1.1 and 1.2 */
    if (cctx->tlsver != 0x301) {
        /* This is a bad interface as it make it seem that
         * the returned output buffer is incorrectly pointing
         * at the IV and not the data, but OpenSSL will in turn
         * offset the buffer later, based on knowledge that this
         * cipher return a length that excludes the IV from the
         * count. */
        out += AESBLOCK;
        olen = inlen - AESBLOCK;
    }

    /* olen is public known so can be checked normally */
    if (olen < overhead) {
        return CKR_BUFFER_TOO_SMALL;
    }

    if (olen < cctx->tlsmacsize) {
        return CKR_BUFFER_TOO_SMALL;
    }

    if (maxcheck > olen) {
        maxcheck = olen;
    }

    /* olen must not be smaller than padsize + overhead */
    pass = ~constant_smaller_mask(olen, overhead + padsize);

    /* creates a mask so that we check only the padding bytes
     * without revealing the padding length in a conditional.
     * mask is 0xff when i < padsize, and 0 otherwise, allowing
     * us to scan the whole buffer while really only testing for
     * equality only the padding part, as the xoring with non-pad
     * data is ignored my the empty mask. We skip checking the
     * last value itself as that is always == padsize */
    for (int i = 0; i < maxcheck - 1; i++) {
        unsigned char mask = constant_smaller_mask(i, padsize);
        unsigned char data = out[olen - i - 2];

        pass &= ~(mask & (padsize ^ data));
    }

    /* renormalize to a CK_ULONG */
    pass = constant_equal_mask(pass, 0xff);

    if (cctx->tlsmacsize > 0) {
        unsigned char randmac[EVP_MAX_MD_SIZE];
        size_t mac_pos = olen - cctx->tlsmacsize - (pass & (padsize + 1));
        size_t mac_area = 0;
        int err = RET_OSSL_ERR;

        /* allocate space for the mac */
        cctx->tlsmac = OPENSSL_zalloc(cctx->tlsmacsize);
        if (!cctx->tlsmac) {
            return CKR_GENERAL_ERROR;
        }

        /* random mac we return if something is wrong */
        err = RAND_bytes_ex(p11prov_ctx_get_libctx(cctx->provctx), randmac,
                            sizeof(randmac), 0);
        if (err != RET_OSSL_OK) {
            return CKR_GENERAL_ERROR;
        }

        /* olen and mac size are public data, so we can do this
         * assignment without bothering with constant time */
        if (olen > cctx->tlsmacsize + 256) {
            mac_area = olen - cctx->tlsmacsize - 256;
        }

        for (size_t i = mac_area; i < olen; i++) {
            for (int j = 0; j < cctx->tlsmacsize; j++) {
                unsigned char mask =
                    ~constant_smaller_mask(i, mac_pos)
                    & constant_smaller_mask(i, mac_pos + cctx->tlsmacsize)
                    & constant_equal_mask(i, j + mac_pos);
                cctx->tlsmac[j] |= out[i] & mask;
            }
        }

        /* on depadding failure overwrite with random data */
        for (int j = 0; j < cctx->tlsmacsize; j++) {
            cctx->tlsmac[j] =
                constant_select_byte_mask(cctx->tlsmac[j], randmac[j], pass);
        }

        rv = CKR_OK;
    } else {
        /* no MAC to check just return the result */
        if (pass + 1 == 0) {
            rv = CKR_OK;
        }
    }

    *outlen = olen - cctx->tlsmacsize - (pass & (padsize + 1));
    return rv;
}

static int p11prov_cipher_update(void *ctx, unsigned char *out, size_t *outl,
                                 size_t outsize, const unsigned char *in,
                                 size_t inl)
{
    struct p11prov_cipher_ctx *cctx = (struct p11prov_cipher_ctx *)ctx;
    CK_SESSION_HANDLE session_handle;
    CK_ULONG outlen = outsize;
    CK_ULONG inlen = inl;
    CK_RV rv;

    if (cctx->tlsver != 0) {
        /* Special OpenSSL layering violating mode.
         * A single update is a full record.
         * Inputs need to be consistent with stricter requirements */
        if (!in || in != out || outsize < inl || !cctx->pad) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
    }

    if (!cctx->session) {
        rv = p11prov_cipher_session_init(cctx);
        if (rv != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }
    session_handle = p11prov_session_handle(cctx->session);

    switch (cctx->operation) {
    case CKF_ENCRYPT:
        if (cctx->tlsver != 0) {
            size_t padsize = AESBLOCK - (inl % AESBLOCK);
            unsigned char padval = (unsigned char)(padsize - 1);

            if (outsize < inl + padsize) {
                rv = CKR_BUFFER_TOO_SMALL;
                P11PROV_raise(cctx->provctx, rv, "Output buffer too small");
                return RET_OSSL_ERR;
            }
            inlen += padsize;
            if ((inlen % AESBLOCK) != 0) {
                rv = CKR_ARGUMENTS_BAD;
                P11PROV_raise(cctx->provctx, rv, "Invalid input buffer size");
                return RET_OSSL_ERR;
            }
            /* add the padding, relies on in == out and therefore enough
             * space available in the buffer */
            memset(&out[inl], padval, padsize);

            /* in TLS mode we must use single shot encryption to properly
             * auto-finalize the session as OpenSSL won't */
            rv = p11prov_Encrypt(cctx->provctx, session_handle, (void *)in,
                                 inlen, out, &outlen);

            cctx->session_state = SESS_FINALIZED;
            /* unconditionally return the session */
            p11prov_return_session(cctx->session);
            cctx->session = NULL;
        } else {
            rv = p11prov_EncryptUpdate(cctx->provctx, session_handle,
                                       (void *)in, inlen, out, &outlen);
        }
        break;
    case CKF_DECRYPT:
        if (cctx->tlsver != 0) {
            if ((inlen % AESBLOCK) != 0) {
                rv = CKR_ARGUMENTS_BAD;
                P11PROV_raise(cctx->provctx, rv, "Invalid input buffer size");
                return RET_OSSL_ERR;
            }
            /* in TLS mode we must use single shot decryption to properly
             * auto-finalize the session as OpenSSL won't */
            rv = p11prov_Decrypt(cctx->provctx, session_handle, (void *)in,
                                 inlen, out, &outlen);

            cctx->session_state = SESS_FINALIZED;
            /* unconditionally return the session */
            p11prov_return_session(cctx->session);
            cctx->session = NULL;

            if (rv != CKR_OK) {
                P11PROV_raise(cctx->provctx, rv, "Decryption failure");
                return RET_OSSL_ERR;
            }
            /* remove padding and fill in tlsmac as needed */
            if (cctx->tlsmac) {
                OPENSSL_clear_free(cctx->tlsmac, cctx->tlsmacsize);
                cctx->tlsmac = NULL;
            }

            /* Assumes inlen = outlen on correct decryption */
            rv = tlsunpad(cctx, out, inlen, &outlen);
        } else {
            rv = p11prov_DecryptUpdate(cctx->provctx, session_handle,
                                       (void *)in, inlen, out, &outlen);
        }
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

    cctx->session_state = SESS_FINALIZED;
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
        int num = 0;
        ret = OSSL_PARAM_set_uint(p, num);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
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
        ret = OSSL_PARAM_set_octet_ptr(p, cctx->tlsmac, cctx->tlsmacsize);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_OK;
}

static int p11prov_aes_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct p11prov_cipher_ctx *ctx = (struct p11prov_cipher_ctx *)vctx;
    const OSSL_PARAM *p;

    if (ctx->session != NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_ALREADY_INSTANTIATED);
        return RET_OSSL_ERR;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p) {
        unsigned int pad;
        int ret = OSSL_PARAM_get_uint(p, &pad);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return RET_OSSL_ERR;
        }
        if (pad > 1) {
            ERR_raise(ERR_LIB_PROV, PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
            return RET_OSSL_ERR;
        }
        ctx->pad = pad == 1;

        switch (ctx->mech.mechanism) {
        case CKM_AES_CBC:
            if (ctx->pad) {
                ctx->mech.mechanism = CKM_AES_CBC_PAD;
            }
            break;

        case CKM_AES_CBC_PAD:
            if (!ctx->pad) {
                ctx->mech.mechanism = CKM_AES_CBC;
            }
            break;

        default:
            if (ctx->pad) {
                /* FIXME: we need to do our padding as there is no _PAD mode
                 * for non CBC modes in PKCS#11 */
                ERR_raise(ERR_LIB_PROV,
                          PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
                return RET_OSSL_ERR;
            }
        }
    }

    if (ctx->mech.mechanism == CKM_AES_CTS) {
        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_CTS_MODE);
        if (p) {
            const char *mode;
            int ret = OSSL_PARAM_get_utf8_ptr(p, &mode);
            if (ret != RET_OSSL_OK) {
                CK_RV rv = CKR_MECHANISM_PARAM_INVALID;
                P11PROV_raise(ctx->provctx, rv, "Invalid mode parameter");
                return RET_OSSL_ERR;
            }
            /* Currently only CS1 is supported */
            if (strcmp(mode, OSSL_CIPHER_CTS_MODE_CS1) != 0) {
                CK_RV rv = CKR_MECHANISM_PARAM_INVALID;
                P11PROV_raise(ctx->provctx, rv, "Unsupported mode: %s", mode);
                return RET_OSSL_ERR;
            }
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_VERSION);
    if (p) {
        CK_RV rv = CKR_MECHANISM_PARAM_INVALID;
        unsigned int version;
        int ret = OSSL_PARAM_get_uint(p, &version);
        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx->provctx, rv, "Invalid TLS Version parameter");
            return RET_OSSL_ERR;
        }
        switch (version) {
        case 0x301: /* TLS 1.0 */
        case 0x302: /* TLS 1.1 */
        case 0x303: /* TLS 1.2 */
            ctx->tlsver = version;
            break;
        default:
            P11PROV_raise(ctx->provctx, rv, "Unsupported TLS Version");
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE);
    if (p) {
        CK_RV rv = CKR_MECHANISM_PARAM_INVALID;
        size_t macsize;
        int ret = OSSL_PARAM_get_size_t(p, &macsize);
        if (ret != RET_OSSL_OK) {
            P11PROV_raise(ctx->provctx, rv, "Invalid TLS MAC Size parameter");
            return RET_OSSL_ERR;
        }
        if (macsize > EVP_MAX_MD_SIZE) {
            P11PROV_raise(ctx->provctx, rv, "Invalid TLS Mac Size");
            return RET_OSSL_ERR;
        }
        ctx->tlsmacsize = macsize;
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM p11prov_aes_generic_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_TLS_MAC, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *p11prov_aes_gettable_ctx_params(void *vctx,
                                                         void *provctx)
{
    struct p11prov_cipher_ctx *ctx = (struct p11prov_cipher_ctx *)vctx;

    if (!ctx) {
        /* There are some cases where openssl will ask for context
         * parameters but will pass NULL for the context, for now
         * we return the generic parameters, but in future we may
         * need to allocate shim functions for each cipher in their
         * dispatch table if it becomes important to return different
         * results for each cipher */
        return p11prov_aes_generic_gettable_ctx_params;
    }

    switch (ctx->mech.mechanism) {
    case CKM_AES_ECB:
    case CKM_AES_CBC_PAD:
    case CKM_AES_OFB:
    case CKM_AES_CFB128:
    case CKM_AES_CFB1:
    case CKM_AES_CFB8:
    case CKM_AES_CTR:
    case CKM_AES_CTS:
        return p11prov_aes_generic_gettable_ctx_params;
    }
    return NULL;
}

#define GENERIC_SETTABLE_CTX_PARAMS() \
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL)
/* Supported by OpenSSL but not here:
 * OSSL_CIPHER_PARAM_NUM (uint)
 * OSSL_CIPHER_PARAM_USE_BITS (uint)
 */

static const OSSL_PARAM p11prov_aes_generic_settable_ctx_params[] = {
    GENERIC_SETTABLE_CTX_PARAMS(),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_TLS_VERSION, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, NULL), OSSL_PARAM_END
};

static const OSSL_PARAM p11prov_aes_cts_settable_ctx_params[] = {
    GENERIC_SETTABLE_CTX_PARAMS(),
    OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, NULL, 0), OSSL_PARAM_END
};

static const OSSL_PARAM *p11prov_aes_settable_ctx_params(void *vctx,
                                                         void *provctx)
{
    struct p11prov_cipher_ctx *ctx = (struct p11prov_cipher_ctx *)vctx;
    if (!ctx) {
        /* See the explanation in p11prov_aes_gettable_ctx_params() for
         * why we handle this case this way */
        return p11prov_aes_generic_settable_ctx_params;
    }
    switch (ctx->mech.mechanism) {
    case CKM_AES_ECB:
    case CKM_AES_CBC_PAD:
    case CKM_AES_OFB:
    case CKM_AES_CFB128:
    case CKM_AES_CFB1:
    case CKM_AES_CFB8:
    case CKM_AES_CTR:
        return p11prov_aes_generic_settable_ctx_params;
    case CKM_AES_CTS:
        return p11prov_aes_cts_settable_ctx_params;
    }
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
