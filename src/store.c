/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <openssl/store.h>
#include "platform/endian.h"

struct p11prov_obj {
    CK_OBJECT_CLASS class;
    union {
        struct p11prov_key *key;
    } data;

    int refcnt;
};

static CK_RV p11prov_object_new(P11PROV_CTX *ctx, CK_OBJECT_CLASS class,
                                P11PROV_KEY *key, P11PROV_OBJ **object)
{
    P11PROV_OBJ *obj;

    obj = OPENSSL_zalloc(sizeof(P11PROV_OBJ));
    if (obj == NULL) {
        return CKR_HOST_MEMORY;
    }
    obj->class = class;
    switch (class) {
    case CKO_PUBLIC_KEY:
    case CKO_PRIVATE_KEY:
        obj->data.key = p11prov_key_ref(key);
        break;
    default:
        P11PROV_raise(ctx, CKR_ARGUMENTS_BAD, "Unsupported object type");
        OPENSSL_free(obj);
        return CKR_ARGUMENTS_BAD;
    }

    obj->refcnt = 1;

    *object = obj;
    return CKR_OK;
}

static P11PROV_OBJ *p11prov_object_ref(P11PROV_OBJ *obj)
{
    if (obj && __atomic_fetch_add(&obj->refcnt, 1, __ATOMIC_ACQ_REL) > 0) {
        return obj;
    }

    return NULL;
}

void p11prov_object_free(P11PROV_OBJ *obj)
{
    p11prov_debug("object free (%p)\n", obj);

    if (obj == NULL) {
        return;
    }
    if (__atomic_sub_fetch(&obj->refcnt, 1, __ATOMIC_ACQ_REL) != 0) {
        p11prov_debug("object free: reference held\n");
        return;
    }

    switch (obj->class) {
    case CKO_PUBLIC_KEY:
    case CKO_PRIVATE_KEY:
        p11prov_key_free(obj->data.key);
        break;
    default:
        p11prov_debug("object_free: invalid class: %lu", obj->class);
    }

    OPENSSL_clear_free(obj, sizeof(P11PROV_OBJ));
}

bool p11prov_object_check_key(P11PROV_OBJ *obj, bool priv)
{
    if (priv) {
        return obj->class == CKO_PRIVATE_KEY;
    }
    return obj->class == CKO_PRIVATE_KEY;
}

P11PROV_KEY *p11prov_object_get_key(P11PROV_OBJ *obj, CK_OBJECT_CLASS class)
{
    if (class == CKO_PRIVATE_KEY && obj->class != CKO_PRIVATE_KEY) {
        return NULL;
    }
    if (class == CKO_PUBLIC_KEY && obj->class != CKO_PUBLIC_KEY) {
        return NULL;
    }
    return p11prov_key_ref(obj->data.key);
}

/* Tokens return data in bigendian order, while openssl
 * wants it in host order, so we may need to fix the
 * endianess of the buffer.
 * Src and Dest, can be the same area, but not partially
 * overlapping memory areas */
static void endianfix(unsigned char *src, unsigned char *dest, size_t len)
{
    int s = 0;
    int e = len - 1;
    unsigned char sb;
    unsigned char eb;

    while (e >= s) {
        sb = src[s];
        eb = src[e];
        dest[s] = eb;
        dest[e] = sb;
        s++;
        e--;
    }
}

#if BYTE_ORDER == LITTLE_ENDIAN
#define WITH_FIXED_BUFFER(src, ptr) \
    unsigned char fix_##src[src->ulValueLen]; \
    endianfix(src->pValue, fix_##src, src->ulValueLen); \
    ptr = fix_##src;
#else
#define WITH_FIXED_BUFFER(src, ptr) ptr = src->pValue;
#endif
int p11prov_object_export_public_rsa_key(P11PROV_OBJ *obj, OSSL_CALLBACK *cb_fn,
                                         void *cb_arg)
{
    OSSL_PARAM params[3];
    CK_ATTRIBUTE *n, *e;
    unsigned char *val;

    switch (obj->class) {
    case CKO_PUBLIC_KEY:
    case CKO_PRIVATE_KEY:
        break;
    default:
        return RET_OSSL_ERR;
    }

    if (p11prov_key_type(obj->data.key) != CKK_RSA) {
        return RET_OSSL_ERR;
    }

    n = p11prov_key_attr(obj->data.key, CKA_MODULUS);
    if (n == NULL) {
        return RET_OSSL_ERR;
    }

    WITH_FIXED_BUFFER(n, val);
    params[0] =
        OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, val, n->ulValueLen);

    e = p11prov_key_attr(obj->data.key, CKA_PUBLIC_EXPONENT);
    if (e == NULL) {
        return RET_OSSL_ERR;
    }

    WITH_FIXED_BUFFER(e, val);
    params[1] =
        OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, val, e->ulValueLen);

    params[2] = OSSL_PARAM_construct_end();

    return cb_fn(params, cb_arg);
}

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

    CK_SESSION_HANDLE session;

    int loaded;

    /* objects found */
    P11PROV_OBJ **objects;
    int num_objs;
    int fetched;
};

static void p11prov_store_ctx_free(struct p11prov_store_ctx *ctx)
{
    p11prov_debug("store ctx free (%p)\n", ctx);

    if (ctx == NULL) {
        return;
    }

    if (ctx->session != CK_INVALID_HANDLE) {
        CK_FUNCTION_LIST_PTR f = p11prov_ctx_fns(ctx->provctx);
        if (f) {
            (void)f->C_CloseSession(ctx->session);
        }
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
        p11prov_object_free(ctx->objects[i]);
    }
    OPENSSL_free(ctx->objects);

    OPENSSL_clear_free(ctx, sizeof(struct p11prov_store_ctx));
}

#define OBJS_ALLOC_SIZE 8
static CK_RV p11prov_store_ctx_add_key(void *pctx, CK_OBJECT_CLASS class,
                                       P11PROV_KEY *key)
{
    struct p11prov_store_ctx *ctx = (struct p11prov_store_ctx *)pctx;
    P11PROV_OBJ *obj;
    CK_RV ret;

    ret = p11prov_object_new(ctx->provctx, class, key, &obj);
    if (ret != CKR_OK) {
        return ret;
    }

    if ((ctx->num_objs % OBJS_ALLOC_SIZE) == 0) {
        P11PROV_OBJ **tmp =
            OPENSSL_realloc(ctx->objects, ctx->num_objs + OBJS_ALLOC_SIZE);
        if (tmp == NULL) {
            P11PROV_raise(ctx->provctx, CKR_HOST_MEMORY,
                          "Failed to allocate store objects");
            p11prov_object_free(obj);
            return CKR_HOST_MEMORY;
        }
        ctx->objects = tmp;
    }
    ctx->objects[ctx->num_objs] = obj;
    ctx->num_objs += 1;

    return CKR_OK;
}

static void store_load(struct p11prov_store_ctx *ctx,
                       OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_SLOT_ID nextid = CK_UNAVAILABLE_INFORMATION;
    CK_RV ret;

    do {
        nextid = CK_UNAVAILABLE_INFORMATION;

        if (ctx->session != CK_INVALID_HANDLE) {
            p11prov_put_session(ctx->provctx, ctx->session);
        }

        ret =
            p11prov_get_session(ctx->provctx, &slotid, &nextid, ctx->parsed_uri,
                                pw_cb, pw_cbarg, &ctx->session);
        switch (ret) {
        case CKR_OK:
            break;
        case CKR_PIN_INCORRECT:
        case CKR_PIN_INVALID:
        case CKR_PIN_LEN_RANGE:
            if (pw_cb == NULL) {
                /* potentially recoverable error */
                return;
            }
            /* fallthrough */
        default:
            /* mark unrecoverable error */
            ctx->loaded = -1;
            return;
        }
        if (ctx->session == CK_INVALID_HANDLE) {
            return;
        }

        ret = find_keys(ctx->provctx, ctx->session, slotid, ctx->parsed_uri,
                        p11prov_store_ctx_add_key, ctx);
        if (ret != CKR_OK) {
            ctx->loaded = -1;
            return;
        }
        slotid = nextid;

    } while (nextid != CK_UNAVAILABLE_INFORMATION);

    ctx->loaded = 1;
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

    p11prov_debug("object open (%p, %s)\n", pctx, uri);

    ctx = OPENSSL_zalloc(sizeof(struct p11prov_store_ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->provctx = (P11PROV_CTX *)pctx;

    ctx->parsed_uri = p11prov_parse_uri(uri);
    if (ctx->parsed_uri == NULL) {
        goto done;
    }

    store_load(ctx, NULL, NULL);

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

    p11prov_debug("object attach (%p, %p)\n", ctx, in);

    return NULL;
}

static int p11prov_store_load(void *pctx, OSSL_CALLBACK *object_cb,
                              void *object_cbarg,
                              OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct p11prov_store_ctx *ctx = (struct p11prov_store_ctx *)pctx;
    P11PROV_OBJ *obj = NULL;
    OSSL_PARAM params[4];
    int object_type;
    CK_KEY_TYPE type;
    char *data_type;

    p11prov_debug("store load (%p)\n", ctx);

    if (ctx->loaded == 0) {
        store_load(ctx, pw_cb, pw_cbarg);
    }

    if (ctx->loaded != 1 || ctx->fetched >= ctx->num_objs) {
        return RET_OSSL_ERR;
    }

    /* FIXME: fetch next object with filters as set by openssl */
    obj = ctx->objects[ctx->fetched];
    ctx->fetched++;

    switch (obj->class) {
    case CKO_PUBLIC_KEY:
    case CKO_PRIVATE_KEY:
        object_type = OSSL_OBJECT_PKEY;
        type = p11prov_key_type(obj->data.key);
        switch (type) {
        case CKK_RSA:
            /* REMOVE once we have encoders to export pub keys.
             *  we have to handle private keys as our own type,
             * while we can let openssl import public keys and
             * deal with them in the default provider */
            switch (ctx->expect) {
            case OSSL_STORE_INFO_PKEY:
                data_type = (char *)P11PROV_NAMES_RSA;
                break;
            case OSSL_STORE_INFO_PUBKEY:
                data_type = (char *)"RSA";
                break;
            default:
                if (obj->class == CKO_PRIVATE_KEY) {
                    data_type = (char *)P11PROV_NAMES_RSA;
                } else {
                    data_type = (char *)"RSA";
                }
                break;
            }
            break;
        case CKK_EC:
            data_type = (char *)P11PROV_NAMES_ECDSA;
            break;
        default:
            return RET_OSSL_ERR;
        }
        break;
    default:
        return RET_OSSL_ERR;
    }

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 data_type, 0);

    /* giving away the object by reference */
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  p11prov_object_ref(obj),
                                                  sizeof(P11PROV_OBJ));
    params[3] = OSSL_PARAM_construct_end();

    return object_cb(params, object_cbarg);
}

static int p11prov_store_eof(void *pctx)
{
    struct p11prov_store_ctx *ctx = (struct p11prov_store_ctx *)pctx;

    p11prov_debug("store eof (%p)\n", ctx);

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

    p11prov_debug("store close (%p)\n", ctx);

    if (ctx == NULL) {
        return 0;
    }

    p11prov_store_ctx_free(ctx);
    return 1;
}

P11PROV_OBJ *p11prov_obj_from_reference(const void *reference,
                                        size_t reference_sz)
{
    if (!reference || reference_sz != sizeof(P11PROV_OBJ)) {
        return NULL;
    }

    return (P11PROV_OBJ *)reference;
}

static int p11prov_store_export_object(void *loaderctx, const void *reference,
                                       size_t reference_sz,
                                       OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    P11PROV_OBJ *obj = NULL;

    p11prov_debug("store (%p) export object %p, %zu\n", loaderctx, reference,
                  reference_sz);

    /* the contents of the reference is the address to our object */
    obj = p11prov_obj_from_reference(reference, reference_sz);
    if (!obj) {
        return RET_OSSL_ERR;
    }

    /* we can only export public bits, so that's all we do */
    return p11prov_object_export_public_rsa_key(obj, cb_fn, cb_arg);
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

    p11prov_debug("set ctx params (%p, %p)\n", ctx, params);

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
