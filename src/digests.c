/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>

/* General Digest Mapping functions */
static struct {
    CK_MECHANISM_TYPE digest;
    size_t block_size;
    size_t digest_size;
    const char *names[5]; /* must give a size for initialization ... */
} digest_map[] = {
    { CKM_SHA_1,
      64,
      20,
      { "SHA1", "SHA-1", "SSL3-SHA1", "1.3.14.3.2.26", NULL } },
    { CKM_SHA224,
      64,
      28,
      { "SHA2-224", "SHA-224", "SHA224", "2.16.840.1.101.3.4.2.4", NULL } },
    { CKM_SHA256,
      64,
      32,
      { "SHA2-256", "SHA-256", "SHA256", "2.16.840.1.101.3.4.2.1", NULL } },
    { CKM_SHA384,
      128,
      48,
      { "SHA2-384", "SHA-384", "SHA384", "2.16.840.1.101.3.4.2.2", NULL } },
    { CKM_SHA512,
      128,
      64,
      { "SHA2-512", "SHA-512", "SHA512", "2.16.840.1.101.3.4.2.3", NULL } },
    { CKM_SHA512_224,
      128,
      28,
      { "SHA2-512/224", "SHA-512/224", "SHA512-224", "2.16.840.1.101.3.4.2.5",
        NULL } },
    { CKM_SHA512_256,
      128,
      32,
      { "SHA2-512/256", "SHA-512/256", "SHA512-256", "2.16.840.1.101.3.4.2.6",
        NULL } },
    { CKM_SHA3_224,
      (1600 - 224 * 2) / 8,
      28,
      { "SHA3-224", "2.16.840.1.101.3.4.2.7", NULL } },
    { CKM_SHA3_256,
      (1600 - 256 * 2) / 8,
      32,
      { "SHA3-256", "2.16.840.1.101.3.4.2.8", NULL } },
    { CKM_SHA3_384,
      (1600 - 384 * 2) / 8,
      48,
      { "SHA3-384", "2.16.840.1.101.3.4.2.9", NULL } },
    { CKM_SHA3_512,
      (1600 - 512 * 2) / 8,
      64,
      { "SHA3-512", "2.16.840.1.101.3.4.2.10", NULL } },
    { CK_UNAVAILABLE_INFORMATION, 0, 0, { NULL } },
};

CK_RV p11prov_digest_get_block_size(CK_MECHANISM_TYPE digest,
                                    size_t *block_size)
{
    for (int i = 0; digest_map[i].digest != CK_UNAVAILABLE_INFORMATION; i++) {
        if (digest_map[i].digest == digest) {
            *block_size = digest_map[i].block_size;
            return CKR_OK;
        }
    }
    return CKR_MECHANISM_INVALID;
}

CK_RV p11prov_digest_get_digest_size(CK_MECHANISM_TYPE digest,
                                     size_t *digest_size)
{
    for (int i = 0; digest_map[i].digest != CK_UNAVAILABLE_INFORMATION; i++) {
        if (digest_map[i].digest == digest) {
            *digest_size = digest_map[i].digest_size;
            return CKR_OK;
        }
    }
    return CKR_MECHANISM_INVALID;
}

CK_RV p11prov_digest_get_name(CK_MECHANISM_TYPE digest, const char **name)
{
    for (int i = 0; digest_map[i].digest != CK_UNAVAILABLE_INFORMATION; i++) {
        if (digest_map[i].digest == digest) {
            *name = digest_map[i].names[0];
            return CKR_OK;
        }
    }
    return CKR_MECHANISM_INVALID;
}

CK_RV p11prov_digest_get_by_name(const char *name, CK_MECHANISM_TYPE *digest)
{
    for (int i = 0; digest_map[i].digest != CK_UNAVAILABLE_INFORMATION; i++) {
        for (int j = 0; digest_map[i].names[j] != NULL; j++) {
            if (OPENSSL_strcasecmp(name, digest_map[i].names[j]) == 0) {
                *digest = digest_map[i].digest;
                return CKR_OK;
            }
        }
    }
    return CKR_MECHANISM_INVALID;
}

struct p11prov_digest_ctx {
    P11PROV_CTX *provctx;
    CK_MECHANISM_TYPE mechtype;

    P11PROV_SESSION *session;
};

typedef struct p11prov_digest_ctx P11PROV_DIGEST_CTX;

#define DISPATCH_DIGEST_NEWCTX_FN(mech, digest) \
    static void *p11prov_##digest##_newctx(void *provctx) \
    { \
        P11PROV_DIGEST_CTX *dctx = OPENSSL_zalloc(sizeof(P11PROV_DIGEST_CTX)); \
        if (dctx == NULL) { \
            return NULL; \
        } \
        dctx->provctx = provctx; \
        dctx->mechtype = mech; \
        dctx->session = CK_INVALID_HANDLE; \
        return dctx; \
    }

DISPATCH_DIGEST_NEWCTX_FN(CKM_SHA_1, sha1);
DISPATCH_DIGEST_NEWCTX_FN(CKM_SHA224, sha224);
DISPATCH_DIGEST_NEWCTX_FN(CKM_SHA256, sha256);
DISPATCH_DIGEST_NEWCTX_FN(CKM_SHA384, sha384);
DISPATCH_DIGEST_NEWCTX_FN(CKM_SHA512, sha512);
DISPATCH_DIGEST_NEWCTX_FN(CKM_SHA512_224, sha512_224);
DISPATCH_DIGEST_NEWCTX_FN(CKM_SHA512_256, sha512_256);
DISPATCH_DIGEST_NEWCTX_FN(CKM_SHA3_224, sha3_224);
DISPATCH_DIGEST_NEWCTX_FN(CKM_SHA3_256, sha3_256);
DISPATCH_DIGEST_NEWCTX_FN(CKM_SHA3_384, sha3_384);
DISPATCH_DIGEST_NEWCTX_FN(CKM_SHA3_512, sha3_512);
DISPATCH_DIGEST_COMMON_FN(dupctx);
DISPATCH_DIGEST_COMMON_FN(freectx);
DISPATCH_DIGEST_COMMON_FN(init);
DISPATCH_DIGEST_COMMON_FN(update);
DISPATCH_DIGEST_COMMON_FN(final);
DISPATCH_DIGEST_COMMON_FN(gettable_params);

static void *p11prov_digest_dupctx(void *ctx)
{
    P11PROV_DIGEST_CTX *dctx = (P11PROV_DIGEST_CTX *)ctx;
    P11PROV_DIGEST_CTX *newctx;
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_BYTE_PTR state = NULL;
    CK_ULONG state_len;
    CK_RV ret;

    P11PROV_debug("digest dupctx, ctx=%p", ctx);

    if (dctx == NULL) {
        return NULL;
    }

    newctx = OPENSSL_zalloc(sizeof(P11PROV_DIGEST_CTX));
    if (newctx == NULL) {
        return NULL;
    }
    newctx->provctx = dctx->provctx;
    newctx->mechtype = dctx->mechtype;

    if (dctx->session == NULL) {
        return newctx;
    }

    /* This is not really funny. OpenSSL by default assumes contexts with
     * operations in flight can be easily duplicated, with all the
     * cryptographic status and then both context can keep going
     * independently. We'll try to save/restore state here, but on failure
     * we just 'move' the the session to the new context and hope there is no
     * need for the old context which will have no session and just return
     * errors if an update is attempted. */

    sess = p11prov_session_handle(dctx->session);

    /* move old session to new context, we swap because often openssl continues
     * on the duplicated context by default */
    newctx->session = dctx->session;
    dctx->session = NULL;

    /* NOTE: most tokens will probably return errors trying to do this on digest
     * sessions. If the configuration indicates that GetOperationState will fail
     * we don't even try to duplicate the context. */

    if (p11prov_ctx_no_operation_state(dctx->provctx)) {
        goto done;
    }

    ret = p11prov_GetOperationState(dctx->provctx, sess, NULL_PTR, &state_len);
    if (ret != CKR_OK) {
        goto done;
    }
    state = OPENSSL_malloc(state_len);
    if (state == NULL) {
        goto done;
    }

    ret = p11prov_GetOperationState(dctx->provctx, sess, state, &state_len);
    if (ret != CKR_OK) {
        goto done;
    }

    ret =
        p11prov_get_session(dctx->provctx, &slotid, NULL, NULL, dctx->mechtype,
                            NULL, NULL, false, false, &dctx->session);
    if (ret != CKR_OK) {
        P11PROV_raise(dctx->provctx, ret, "Failed to open new session");
        goto done;
    }
    sess = p11prov_session_handle(dctx->session);

    ret = p11prov_SetOperationState(dctx->provctx, sess, state, state_len,
                                    CK_INVALID_HANDLE, CK_INVALID_HANDLE);
    if (ret != CKR_OK) {
        p11prov_return_session(dctx->session);
        dctx->session = NULL;
    }

done:
    OPENSSL_free(state);
    return newctx;
}

static void p11prov_digest_freectx(void *ctx)
{
    P11PROV_DIGEST_CTX *dctx = (P11PROV_DIGEST_CTX *)ctx;

    P11PROV_debug("digest freectx, ctx=%p", ctx);

    if (!ctx) {
        return;
    }
    p11prov_return_session(dctx->session);
    OPENSSL_clear_free(dctx, sizeof(P11PROV_DIGEST_CTX));
}

static int p11prov_digest_init(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_DIGEST_CTX *dctx = (P11PROV_DIGEST_CTX *)ctx;
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_MECHANISM mechanism = { 0 };
    CK_RV ret;

    P11PROV_debug("digest init, ctx=%p", ctx);

    if (ctx == NULL) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_ctx_status(dctx->provctx);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    if (params != NULL) {
        const OSSL_PARAM *p;
        int err;

        p = OSSL_PARAM_locate_const(params, P11PROV_PARAM_SLOT_ID);
        if (p) {
            err = OSSL_PARAM_get_ulong(p, &slotid);
            if (err != RET_OSSL_OK) {
                P11PROV_raise(dctx->provctx, CKR_GENERAL_ERROR,
                              "Invalid PARAM_SLOT_ID");
                return err;
            }
            P11PROV_debug("Set PARAM_SLOT_ID to %lu", slotid);
        }
    }

    ret =
        p11prov_get_session(dctx->provctx, &slotid, NULL, NULL, dctx->mechtype,
                            NULL, NULL, false, false, &dctx->session);
    if (ret != CKR_OK) {
        P11PROV_raise(dctx->provctx, ret, "Failed to open new session");
        return RET_OSSL_ERR;
    }
    sess = p11prov_session_handle(dctx->session);

    mechanism.mechanism = dctx->mechtype;

    ret = p11prov_DigestInit(dctx->provctx, sess, &mechanism);
    if (ret != CKR_OK) {
        p11prov_return_session(dctx->session);
        dctx->session = NULL;
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_digest_update(void *ctx, const unsigned char *data,
                                 size_t len)
{
    P11PROV_DIGEST_CTX *dctx = (P11PROV_DIGEST_CTX *)ctx;
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_RV ret;

    P11PROV_debug("digest update, ctx=%p", ctx);

    if (ctx == NULL) {
        return RET_OSSL_ERR;
    }

    if (len == 0) {
        return RET_OSSL_OK;
    }

    sess = p11prov_session_handle(dctx->session);

    ret = p11prov_DigestUpdate(dctx->provctx, sess, (void *)data, len);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_digest_final(void *ctx, unsigned char *out, size_t *size,
                                size_t buf_size)
{
    P11PROV_DIGEST_CTX *dctx = (P11PROV_DIGEST_CTX *)ctx;
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    size_t digest_size;
    CK_ULONG digest_len;
    CK_RV ret;

    P11PROV_debug("digest update, ctx=%p", ctx);

    if (ctx == NULL) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_digest_get_digest_size(dctx->mechtype, &digest_size);
    if (ret != CKR_OK) {
        P11PROV_raise(dctx->provctx, ret, "Unexpected get_digest_size error");
        return RET_OSSL_ERR;
    }

    /* probing for buffer size to alloc */
    if (buf_size == 0) {
        *size = digest_size;
        return RET_OSSL_OK;
    } else if (buf_size < digest_size) {
        P11PROV_raise(dctx->provctx, CKR_ARGUMENTS_BAD,
                      "Digest output buffer too small %zd < %zd", buf_size,
                      digest_size);
        return RET_OSSL_OK;
    }

    digest_len = digest_size;

    sess = p11prov_session_handle(dctx->session);

    ret = p11prov_DigestFinal(dctx->provctx, sess, out, &digest_len);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    *size = digest_len;
    return RET_OSSL_OK;
}

static int p11prov_digest_get_params(CK_MECHANISM_TYPE digest,
                                     OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;
    CK_RV ret;

    P11PROV_debug("digest get params: digest=%lX, params=%p", digest, params);

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p) {
        size_t block_size;
        ret = p11prov_digest_get_block_size(digest, &block_size);
        if (ret != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_size_t(p, block_size);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
        P11PROV_debug("block_size = %zd", block_size);
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p) {
        size_t digest_size;
        ret = p11prov_digest_get_digest_size(digest, &digest_size);
        if (ret != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_size_t(p, digest_size);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
        P11PROV_debug("digest_size = %zd", digest_size);
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
    if (p) {
        ret = OSSL_PARAM_set_int(p, 0);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT);
    if (p) {
        ret = OSSL_PARAM_set_int(p, 1);
        if (ret != RET_OSSL_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
    }
    return RET_OSSL_OK;
}

#define DISPATCH_DIGEST_GET_PARAMS_FN(mech, digest) \
    static int p11prov_##digest##_get_params(OSSL_PARAM params[]) \
    { \
        return p11prov_digest_get_params(mech, params); \
    }

DISPATCH_DIGEST_GET_PARAMS_FN(CKM_SHA_1, sha1);
DISPATCH_DIGEST_GET_PARAMS_FN(CKM_SHA224, sha224);
DISPATCH_DIGEST_GET_PARAMS_FN(CKM_SHA256, sha256);
DISPATCH_DIGEST_GET_PARAMS_FN(CKM_SHA384, sha384);
DISPATCH_DIGEST_GET_PARAMS_FN(CKM_SHA512, sha512);
DISPATCH_DIGEST_GET_PARAMS_FN(CKM_SHA512_224, sha512_224);
DISPATCH_DIGEST_GET_PARAMS_FN(CKM_SHA512_256, sha512_256);
DISPATCH_DIGEST_GET_PARAMS_FN(CKM_SHA3_224, sha3_224);
DISPATCH_DIGEST_GET_PARAMS_FN(CKM_SHA3_256, sha3_256);
DISPATCH_DIGEST_GET_PARAMS_FN(CKM_SHA3_384, sha3_384);
DISPATCH_DIGEST_GET_PARAMS_FN(CKM_SHA3_512, sha3_512);

static const OSSL_PARAM *p11prov_digest_gettable_params(void *provctx)
{
    P11PROV_debug("digest gettable params, ctx=%p", provctx);

    static const OSSL_PARAM digest_params[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
        OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL),
        OSSL_PARAM_END,
    };
    return digest_params;
}

#define DISPATCH_FUNCTION_TABLE(digest) \
    const OSSL_DISPATCH p11prov_##digest##_digest_functions[] = { \
        DISPATCH_DIGEST_ELEM(digest, NEWCTX, newctx), \
        DISPATCH_DIGEST_COMMON(DUPCTX, dupctx), \
        DISPATCH_DIGEST_COMMON(FREECTX, freectx), \
        DISPATCH_DIGEST_COMMON(INIT, init), \
        DISPATCH_DIGEST_COMMON(UPDATE, update), \
        DISPATCH_DIGEST_COMMON(FINAL, final), \
        DISPATCH_DIGEST_ELEM(digest, GET_PARAMS, get_params), \
        DISPATCH_DIGEST_COMMON(GETTABLE_PARAMS, gettable_params), \
        { 0, NULL }, \
    }

DISPATCH_FUNCTION_TABLE(sha1);
DISPATCH_FUNCTION_TABLE(sha224);
DISPATCH_FUNCTION_TABLE(sha256);
DISPATCH_FUNCTION_TABLE(sha384);
DISPATCH_FUNCTION_TABLE(sha512);
DISPATCH_FUNCTION_TABLE(sha512_224);
DISPATCH_FUNCTION_TABLE(sha512_256);
DISPATCH_FUNCTION_TABLE(sha3_224);
DISPATCH_FUNCTION_TABLE(sha3_256);
DISPATCH_FUNCTION_TABLE(sha3_384);
DISPATCH_FUNCTION_TABLE(sha3_512);
