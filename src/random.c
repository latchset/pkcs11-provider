/* Copyright (C) 2023 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"

DISPATCH_RAND_FN(newctx); /* required */
DISPATCH_RAND_FN(freectx); /* required */
DISPATCH_RAND_FN(instantiate); /* required */
DISPATCH_RAND_FN(uninstantiate); /* required */
DISPATCH_RAND_FN(generate); /* required */
DISPATCH_RAND_FN(reseed);
DISPATCH_RAND_FN(get_ctx_params); /* required */

/* following functions are optional only in theory,
 * openssl depends on them */
DISPATCH_RAND_FN(enable_locking);
DISPATCH_RAND_FN(lock);
DISPATCH_RAND_FN(unlock);

struct p11prov_rand_ctx {
    P11PROV_CTX *provctx;
    CK_SLOT_ID slotid;
};

static void *p11prov_rand_newctx(void *provctx, void *parent,
                                 const OSSL_DISPATCH *parent_dispatch)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    struct p11prov_rand_ctx *rctx;

    P11PROV_debug("rand newctx");

    rctx = OPENSSL_zalloc(sizeof(struct p11prov_rand_ctx));
    if (!rctx) {
        return NULL;
    }

    rctx->provctx = ctx;
    rctx->slotid = CK_UNAVAILABLE_INFORMATION;
    return rctx;
}

static void p11prov_rand_freectx(void *pctx)
{
    P11PROV_debug("rand: freectx");

    OPENSSL_free(pctx);
}

static int p11prov_rand_instantiate(void *pctx, unsigned int strength,
                                    int prediction_resistance,
                                    const unsigned char *pstr, size_t pstr_len,
                                    const OSSL_PARAM params[])
{
    struct p11prov_rand_ctx *ctx = (struct p11prov_rand_ctx *)pctx;
    CK_RV ret;

    P11PROV_debug("rand: instantiate");

    ret = p11prov_ctx_status(ctx->provctx);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_rand_uninstantiate(void *pctx)
{
    P11PROV_debug("rand: uninstantiate");

    return RET_OSSL_OK;
}

static int p11prov_rand_generate(void *pctx, unsigned char *out, size_t outlen,
                                 unsigned int strength,
                                 int prediction_resistance,
                                 const unsigned char *adin, size_t adin_len)
{
    struct p11prov_rand_ctx *ctx = (struct p11prov_rand_ctx *)pctx;
    P11PROV_SESSION *session = NULL;
    CK_RV ret;
    int res = RET_OSSL_ERR;

    P11PROV_debug("rand: generate (add bytes: %zu)", adin_len);

    ret = p11prov_get_session(ctx->provctx, &ctx->slotid, NULL, NULL,
                              CK_UNAVAILABLE_INFORMATION, NULL, NULL, false,
                              false, &session);
    if (ret != CKR_OK) {
        return res;
    }

    if (adin && adin_len > 0) {
        /* we ignore the result, as this is optional */
        (void)p11prov_SeedRandom(ctx->provctx, p11prov_session_handle(session),
                                 (CK_BYTE *)adin, adin_len);
    }

    ret = p11prov_GenerateRandom(ctx->provctx, p11prov_session_handle(session),
                                 (CK_BYTE *)out, outlen);
    if (ret == CKR_OK) {
        res = RET_OSSL_OK;
    }

    p11prov_return_session(session);
    return res;
}

static int p11prov_rand_reseed(void *pctx, int prediction_resistance,
                               const unsigned char *entropy, size_t ent_len,
                               const unsigned char *adin, size_t adin_len)
{
    struct p11prov_rand_ctx *ctx = (struct p11prov_rand_ctx *)pctx;
    P11PROV_SESSION *session = NULL;
    CK_RV ret;
    int res = RET_OSSL_ERR;

    P11PROV_debug("rand: reseed (ent bytes: %zu, add bytes: %zu)", ent_len,
                  adin_len);

    ret = p11prov_get_session(ctx->provctx, &ctx->slotid, NULL, NULL,
                              CK_UNAVAILABLE_INFORMATION, NULL, NULL, false,
                              false, &session);
    if (ret != CKR_OK) {
        return res;
    }

    if (entropy && ent_len > 0) {
        /* we ignore the result, as this is optional */
        (void)p11prov_SeedRandom(ctx->provctx, p11prov_session_handle(session),
                                 (CK_BYTE *)entropy, ent_len);
    }

    if (adin && adin_len > 0) {
        /* we ignore the result, as this is optional */
        (void)p11prov_SeedRandom(ctx->provctx, p11prov_session_handle(session),
                                 (CK_BYTE *)adin, adin_len);
    }

    p11prov_return_session(session);
    return res;
}

#define MAX_RAND_REQUEST INT_MAX

static int p11prov_rand_get_ctx_params(void *pctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ret;

    P11PROV_debug("rand: get_ctx_params");

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p) {
        ret = OSSL_PARAM_set_size_t(p, MAX_RAND_REQUEST);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

static int p11prov_rand_enable_locking(void *pctx)
{
    return RET_OSSL_OK;
}

static int p11prov_rand_lock(void *pctx)
{
    return RET_OSSL_OK;
}

static void p11prov_rand_unlock(void *pctx)
{
    /* nothing to do */
}

const OSSL_DISPATCH p11prov_rand_functions[] = {
    DISPATCH_RAND_ELEM(rand, NEWCTX, newctx),
    DISPATCH_RAND_ELEM(rand, FREECTX, freectx),
    DISPATCH_RAND_ELEM(rand, INSTANTIATE, instantiate),
    DISPATCH_RAND_ELEM(rand, UNINSTANTIATE, uninstantiate),
    DISPATCH_RAND_ELEM(rand, GENERATE, generate),
    DISPATCH_RAND_ELEM(rand, RESEED, reseed),
    DISPATCH_RAND_ELEM(rand, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_RAND_ELEM(rand, ENABLE_LOCKING, enable_locking),
    DISPATCH_RAND_ELEM(rand, LOCK, lock),
    DISPATCH_RAND_ELEM(rand, UNLOCK, unlock),
    { 0, NULL },
};

CK_RV p11prov_check_random(P11PROV_CTX *ctx)
{
    struct p11prov_rand_ctx rctx = {
        .provctx = ctx,
        .slotid = CK_UNAVAILABLE_INFORMATION,
    };
    unsigned char test[8];
    int ret;

    ret = p11prov_rand_generate(&rctx, test, 8, 0, 0, NULL, 0);
    if (ret != RET_OSSL_OK) {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    return CKR_OK;
}
