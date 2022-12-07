/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <openssl/store.h>

struct p11prov_store_ctx {
    P11PROV_CTX *provctx;
    P11PROV_URI *parsed_uri;

    /* search filters set via params */
    int expect;
    CK_ATTRIBUTE subject;
    CK_ATTRIBUTE issuer;
    BIGNUM *serial;
    char *digest;
    CK_ATTRIBUTE fingerprint;
    char *alias;
    char *properties;
    char *input_type;

    P11PROV_SESSION *session;

    int loaded;

    /* objects found */
    P11PROV_OBJ **objects;
    int num_objs;
    int fetched;
};

static void p11prov_store_ctx_free(struct p11prov_store_ctx *ctx)
{
    P11PROV_debug("store ctx free (%p)", ctx);

    if (ctx == NULL) {
        return;
    }

    if (ctx->session != NULL) {
        p11prov_session_free(ctx->session);
    }

    p11prov_uri_free(ctx->parsed_uri);
    OPENSSL_free(ctx->subject.pValue);
    OPENSSL_free(ctx->issuer.pValue);
    OPENSSL_free(ctx->digest);
    OPENSSL_free(ctx->fingerprint.pValue);
    OPENSSL_free(ctx->alias);
    OPENSSL_free(ctx->properties);
    OPENSSL_free(ctx->input_type);

    for (int i = 0; i < ctx->num_objs; i++) {
        p11prov_obj_free(ctx->objects[i]);
    }
    OPENSSL_free(ctx->objects);

    OPENSSL_clear_free(ctx, sizeof(struct p11prov_store_ctx));
}

#define OBJS_ALLOC_SIZE 8
static CK_RV p11prov_store_ctx_add_obj(void *pctx, P11PROV_OBJ *obj)
{
    struct p11prov_store_ctx *ctx = (struct p11prov_store_ctx *)pctx;

    if ((ctx->num_objs % OBJS_ALLOC_SIZE) == 0) {
        P11PROV_OBJ **tmp =
            OPENSSL_realloc(ctx->objects, (ctx->num_objs + OBJS_ALLOC_SIZE)
                                              * sizeof(P11PROV_OBJ *));
        if (tmp == NULL) {
            P11PROV_raise(ctx->provctx, CKR_HOST_MEMORY,
                          "Failed to allocate store objects");
            p11prov_obj_free(obj);
            return CKR_HOST_MEMORY;
        }
        ctx->objects = tmp;
    }
    ctx->objects[ctx->num_objs] = obj;
    ctx->num_objs += 1;

    return CKR_OK;
}

static void store_fetch(struct p11prov_store_ctx *ctx,
                        OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_SLOT_ID nextid = CK_UNAVAILABLE_INFORMATION;
    CK_RV ret;

    /* cycle through all available slots,
     * only stack errors, but not block on any of them */
    do {
        nextid = CK_UNAVAILABLE_INFORMATION;

        if (ctx->session != NULL) {
            p11prov_session_free(ctx->session);
            ctx->session = CK_INVALID_HANDLE;
        }

        ret = p11prov_get_session(ctx->provctx, &slotid, &nextid,
                                  ctx->parsed_uri, CK_UNAVAILABLE_INFORMATION,
                                  pw_cb, pw_cbarg, false, false, &ctx->session);
        if (ret != CKR_OK || ctx->session == CK_INVALID_HANDLE) {
            P11PROV_raise(ctx->provctx, ret,
                          "Failed to get session to load keys");

            /* some cases may be recoverable in store_load if we get a pin
             * prompter, but if we already had one, this is it */
            if (pw_cb != NULL && ctx->loaded == 0) {
                ctx->loaded = -1;
            }
            return;
        }

        ret = p11prov_obj_find(ctx->provctx, ctx->session, slotid,
                               ctx->parsed_uri, p11prov_store_ctx_add_obj, ctx);
        if (ret != CKR_OK) {
            P11PROV_raise(ctx->provctx, ret,
                          "Failed to load keys from slot (%ld)", slotid);
        } else {
            /* if we got here w/o error at least once, consider it a success */
            ctx->loaded = 1;
        }
        slotid = nextid;

    } while (nextid != CK_UNAVAILABLE_INFORMATION);
}

DISPATCH_STORE_FN(open);
DISPATCH_STORE_FN(attach);
DISPATCH_STORE_FN(load);
DISPATCH_STORE_FN(eof);
DISPATCH_STORE_FN(close);
DISPATCH_STORE_FN(export_object);
DISPATCH_STORE_FN(set_ctx_params);
DISPATCH_STORE_FN(settable_ctx_params);

static void *p11prov_store_open(void *pctx, const char *uri)
{
    struct p11prov_store_ctx *ctx = NULL;
    CK_RV result = CKR_CANCEL;

    P11PROV_debug("object open (%p, %s)", pctx, uri);

    ctx = OPENSSL_zalloc(sizeof(struct p11prov_store_ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->provctx = (P11PROV_CTX *)pctx;

    ctx->parsed_uri = p11prov_parse_uri(ctx->provctx, uri);
    if (ctx->parsed_uri == NULL) {
        goto done;
    }

    store_fetch(ctx, NULL, NULL);

    result = CKR_OK;

done:
    if (result != CKR_OK) {
        p11prov_store_ctx_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

static void *p11prov_store_attach(void *pctx, OSSL_CORE_BIO *in)
{
    struct p11prov_store_ctx *ctx = (struct p11prov_store_ctx *)pctx;

    P11PROV_debug("object attach (%p, %p)", ctx, in);

    return NULL;
}

static int p11prov_store_load(void *pctx, OSSL_CALLBACK *object_cb,
                              void *object_cbarg,
                              OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct p11prov_store_ctx *ctx = (struct p11prov_store_ctx *)pctx;
    void *reference = NULL;
    size_t reference_sz;
    CK_ATTRIBUTE *cert = NULL;
    P11PROV_OBJ *obj = NULL;
    OSSL_PARAM params[4];
    int object_type;
    CK_KEY_TYPE type;
    char *data_type;
    bool found = false;

    P11PROV_debug("store load (%p)", ctx);

    if (ctx->loaded == 0) {
        store_fetch(ctx, pw_cb, pw_cbarg);
    }

    if (ctx->loaded != 1) {
        return RET_OSSL_ERR;
    }

    while (ctx->fetched < ctx->num_objs) {
        obj = ctx->objects[ctx->fetched];
        ctx->fetched++;

        /* Supported search types in OSSL_STORE_SEARCH(3) */
        switch (p11prov_obj_get_class(obj)) {
        case CKO_CERTIFICATE:
            /* ctx->subject */
            /* ctx->issuer */
            /* ctx->serial */
            break;
        case CKO_PUBLIC_KEY:
        case CKO_PRIVATE_KEY:
            /* ctx->digest */
            /* ctx->fingerprint */
            if (ctx->alias) {
                CK_ATTRIBUTE *label;
                label = p11prov_obj_get_attr(obj, CKA_LABEL);
                if (!label || strcmp(ctx->alias, label->pValue) != 0) {
                    /* no match, try next */
                    continue;
                }
            }
            break;
        }

        /* if we get here it means the object matched */
        found = true;
        break;
    }

    if (!found) {
        return RET_OSSL_ERR;
    }

    switch (p11prov_obj_get_class(obj)) {
    case CKO_PUBLIC_KEY:
    case CKO_PRIVATE_KEY:
        object_type = OSSL_OBJECT_PKEY;
        type = p11prov_obj_get_key_type(obj);
        switch (type) {
        case CKK_RSA:
            data_type = (char *)P11PROV_NAMES_RSA;
            break;
        case CKK_EC:
            data_type = (char *)P11PROV_NAMES_EC;
            break;
        default:
            return RET_OSSL_ERR;
        }
        p11prov_obj_to_reference(obj, &reference, &reference_sz);
        break;
    case CKO_CERTIFICATE:
        object_type = OSSL_OBJECT_CERT;
        data_type = (char *)"CERTIFICATE";
        cert = p11prov_obj_get_attr(obj, CKA_VALUE);
        if (cert == NULL) {
            return RET_OSSL_ERR;
        }
        break;
    default:
        return RET_OSSL_ERR;
    }

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 data_type, 0);
    if (reference) {
        /* giving away the object by reference */
        params[2] = OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_REFERENCE, reference, reference_sz);
    } else if (cert) {
        params[2] = OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_DATA, cert->pValue, cert->ulValueLen);
    } else {
        return RET_OSSL_ERR;
    }
    params[3] = OSSL_PARAM_construct_end();

    return object_cb(params, object_cbarg);
}

static int p11prov_store_eof(void *pctx)
{
    struct p11prov_store_ctx *ctx = (struct p11prov_store_ctx *)pctx;

    P11PROV_debug("store eof (%p)", ctx);

    if (ctx->loaded == -1) {
        /* error condition nothing more to return */
        return 1;
    } else if (ctx->loaded && ctx->fetched >= ctx->num_objs) {
        return 1;
    }
    return 0;
}

static int p11prov_store_close(void *pctx)
{
    struct p11prov_store_ctx *ctx = (struct p11prov_store_ctx *)pctx;

    P11PROV_debug("store close (%p)", ctx);

    if (ctx == NULL) {
        return 0;
    }

    p11prov_store_ctx_free(ctx);
    return 1;
}

static int p11prov_store_export_object(void *loaderctx, const void *reference,
                                       size_t reference_sz,
                                       OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    P11PROV_OBJ *obj = NULL;

    P11PROV_debug("store (%p) export object %p, %zu", loaderctx, reference,
                  reference_sz);

    /* the contents of the reference is the address to our object */
    obj = p11prov_obj_from_reference(reference, reference_sz);
    if (!obj) {
        return RET_OSSL_ERR;
    }

    /* we can only export public bits, so that's all we do */
    if (p11prov_obj_get_class(obj) != CKO_PUBLIC_KEY) {
        return RET_OSSL_ERR;
    }

    return p11prov_obj_export_public_rsa_key(obj, cb_fn, cb_arg);
}

static const OSSL_PARAM *p11prov_store_settable_ctx_params(void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL),
        OSSL_PARAM_octet_string(OSSL_STORE_PARAM_SUBJECT, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_STORE_PARAM_ISSUER, NULL, 0),
        OSSL_PARAM_BN(OSSL_STORE_PARAM_SERIAL, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_STORE_PARAM_FINGERPRINT, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_ALIAS, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_INPUT_TYPE, NULL, 0),
        OSSL_PARAM_END,
    };
    return known_settable_ctx_params;
}

static int p11prov_store_set_ctx_params(void *pctx, const OSSL_PARAM params[])
{
    struct p11prov_store_ctx *ctx = (struct p11prov_store_ctx *)pctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("set ctx params (%p, %p)", ctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_EXPECT);
    if (p) {
        ret = OSSL_PARAM_get_int(p, &ctx->expect);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_SUBJECT);
    if (p) {
        size_t len = 0;
        OPENSSL_free(ctx->subject.pValue);
        ctx->subject.type = CKA_SUBJECT;
        ctx->subject.pValue = NULL;
        ret = OSSL_PARAM_get_octet_string(p, &ctx->subject.pValue, 0, &len);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        ctx->subject.ulValueLen = len;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_ISSUER);
    if (p) {
        size_t len = 0;
        OPENSSL_free(ctx->issuer.pValue);
        ctx->issuer.type = CKA_ISSUER;
        ctx->issuer.pValue = NULL;
        ret = OSSL_PARAM_get_octet_string(p, &ctx->issuer.pValue, 0, &len);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        ctx->issuer.ulValueLen = len;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_DIGEST);
    if (p) {
        OPENSSL_free(ctx->digest);
        ctx->digest = NULL;
        ret = OSSL_PARAM_get_utf8_string(p, &ctx->digest, 0);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_FINGERPRINT);
    if (p) {
        size_t len = 0;
        OPENSSL_free(ctx->fingerprint.pValue);
        ctx->fingerprint.type = CKA_VALUE;
        ctx->fingerprint.pValue = NULL;
        ret = OSSL_PARAM_get_octet_string(p, &ctx->fingerprint.pValue, 0, &len);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        ctx->fingerprint.ulValueLen = len;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_ALIAS);
    if (p) {
        OPENSSL_free(ctx->alias);
        ctx->alias = NULL;
        ret = OSSL_PARAM_get_utf8_string(p, &ctx->alias, 0);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_PROPERTIES);
    if (p) {
        OPENSSL_free(ctx->properties);
        ctx->properties = NULL;
        ret = OSSL_PARAM_get_utf8_string(p, &ctx->properties, 0);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_INPUT_TYPE);
    if (p) {
        OPENSSL_free(ctx->input_type);
        ctx->input_type = NULL;
        ret = OSSL_PARAM_get_utf8_string(p, &ctx->input_type, 0);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

const OSSL_DISPATCH p11prov_store_functions[] = {
    DISPATCH_STORE_ELEM(OPEN, open),
    DISPATCH_STORE_ELEM(ATTACH, attach),
    DISPATCH_STORE_ELEM(LOAD, load),
    DISPATCH_STORE_ELEM(EOF, eof),
    DISPATCH_STORE_ELEM(CLOSE, close),
    DISPATCH_STORE_ELEM(SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_STORE_ELEM(SETTABLE_CTX_PARAMS, settable_ctx_params),
    DISPATCH_STORE_ELEM(EXPORT_OBJECT, export_object),
    { 0, NULL },
};
