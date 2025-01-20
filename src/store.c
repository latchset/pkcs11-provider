/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <openssl/store.h>
#include "store.h"

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

    p11prov_return_session(ctx->session);

    p11prov_uri_free(ctx->parsed_uri);
    OPENSSL_free(ctx->subject.pValue);
    OPENSSL_free(ctx->issuer.pValue);
    OPENSSL_free(ctx->digest);
    OPENSSL_free(ctx->fingerprint.pValue);
    OPENSSL_free(ctx->alias);
    OPENSSL_free(ctx->properties);
    OPENSSL_free(ctx->input_type);
    BN_free(ctx->serial);

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
    int login_behavior;
    bool login = false;
    CK_RV ret;

    P11PROV_debug("called (store_ctx=%p)", ctx);
    login_behavior = p11prov_ctx_login_behavior(ctx->provctx);

    if (ctx->expect == 0 || ctx->expect == OSSL_STORE_INFO_PKEY
        || login_behavior == PUBKEY_LOGIN_ALWAYS) {
        login = true;
    }
    if (p11prov_uri_get_class(ctx->parsed_uri) == CKO_PUBLIC_KEY
        && login_behavior != PUBKEY_LOGIN_ALWAYS) {
        login = false;
    }

    /* error stack mark so we can unwind in case of repeat to avoid
     * returning bogus errors */
    p11prov_set_error_mark(ctx->provctx);

again:
    /* cycle through all available slots,
     * only stack errors, but not block on any of them */
    do {
        nextid = CK_UNAVAILABLE_INFORMATION;

        /* mark internal loops as well */
        p11prov_set_error_mark(ctx->provctx);

        if (ctx->session != NULL) {
            p11prov_return_session(ctx->session);
            ctx->session = NULL;
        }

        ret = p11prov_get_session(ctx->provctx, &slotid, &nextid,
                                  ctx->parsed_uri, CK_UNAVAILABLE_INFORMATION,
                                  pw_cb, pw_cbarg, login, false, &ctx->session);
        if (ret != CKR_OK) {
            P11PROV_debug(
                "Failed to get session to load keys (slotid=%lx, ret=%lx)",
                slotid, ret);

            /* some cases may be recoverable in store_load if we get a pin
             * prompter, but if we already had one, this is it */
            if (pw_cb != NULL && ctx->loaded == 0) {
                ctx->loaded = -1;
            }
            p11prov_pop_error_to_mark(ctx->provctx);
            continue;
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

        /* unset the mark, leaving errors on the stack */
        p11prov_clear_last_error_mark(ctx->provctx);

    } while (nextid != CK_UNAVAILABLE_INFORMATION);

    /* Given the variety of tokens, if we found no object at all, and we did
     * *not* set login required, we retry again, after setting login required.
     * This accounts for HW that requires a login even for public objects */
    if (login == false && ctx->num_objs == 0
        && login_behavior != PUBKEY_LOGIN_NEVER) {
        P11PROV_debug("No object found. Retrying with login (store_ctx=%p)",
                      ctx);
        slotid = CK_UNAVAILABLE_INFORMATION;
        ctx->loaded = 0;
        login = true;
        goto again;
    }

    if (ctx->loaded == 0) {
        /* if we get here it means we tried all */
        ctx->loaded = -1;
    }

    if (ctx->num_objs > 0) {
        /* if there was any error, remove it, as we got success */
        p11prov_pop_error_to_mark(ctx->provctx);
    } else {
        /* otherwise clear the mark and leave errors on the stack */
        p11prov_clear_last_error_mark(ctx->provctx);
    }
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
    P11PROV_CTX *provctx = (P11PROV_CTX *)pctx;
    CK_RV ret = CKR_CANCEL;

    P11PROV_debug("object open (%p, %s)", pctx, uri);

    ret = p11prov_ctx_status(provctx);
    if (ret != CKR_OK) {
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(struct p11prov_store_ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->provctx = provctx;

    ctx->parsed_uri = p11prov_parse_uri(ctx->provctx, uri);
    if (ctx->parsed_uri == NULL) {
        ret = CKR_HOST_MEMORY;
        goto done;
    }

    ret = CKR_OK;

done:
    if (ret != CKR_OK) {
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
            if (ctx->subject.type == CKA_SUBJECT) {
                CK_ATTRIBUTE *subject;
                /* unfortunately different but equivalent encodings may be
                 * used for the same attributes by different certificate
                 * generation tools, so a simple memcmp is not possible
                 * for the DER encoding of a DN, for example NSs tools use
                 * PRINTABLESTRING for CN while moder openssl use UTF8STRING
                 * ANS1 tags for the encoding of the same attribute */

                subject = p11prov_obj_get_attr(obj, CKA_SUBJECT);
                if (!subject) {
                    /* no match, try next */
                    continue;
                }
                /* TODO: X509_NAME caching for ctx->subject ? */
                if (!p11prov_x509_names_are_equal(&ctx->subject, subject)) {
                    /* no match, try next */
                    continue;
                }
            }
            if (ctx->issuer.type == CKA_ISSUER) {
                CK_ATTRIBUTE *issuer;

                issuer = p11prov_obj_get_attr(obj, CKA_ISSUER);
                if (!issuer) {
                    /* no match, try next */
                    continue;
                }
                /* TODO: X509_NAME caching for ctx->issuer ? */
                if (!p11prov_x509_names_are_equal(&ctx->issuer, issuer)) {
                    /* no match, try next */
                    continue;
                }
            }
            if (ctx->serial) {
                const unsigned char *val;
                CK_ATTRIBUTE *serial;
                ASN1_INTEGER *asn1_serial;
                BIGNUM *bn_serial;
                int cmp;

                serial = p11prov_obj_get_attr(obj, CKA_SERIAL_NUMBER);
                if (!serial) {
                    continue;
                }
                val = serial->pValue;
                asn1_serial = d2i_ASN1_INTEGER(NULL, &val, serial->ulValueLen);
                if (!asn1_serial) {
                    continue;
                }
                bn_serial = ASN1_INTEGER_to_BN(asn1_serial, NULL);
                if (!bn_serial) {
                    ASN1_INTEGER_free(asn1_serial);
                    continue;
                }
                cmp = BN_ucmp(ctx->serial, bn_serial);
                ASN1_INTEGER_free(asn1_serial);
                BN_free(bn_serial);
                if (cmp != 0) {
                    /* no match, try next */
                    continue;
                }
            }
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
            if (p11prov_obj_is_rsa_pss(obj)) {
                data_type = (char *)P11PROV_NAME_RSAPSS;
            } else {
                data_type = (char *)P11PROV_NAME_RSA;
            }
            break;
        case CKK_EC:
            data_type = (char *)P11PROV_NAME_EC;
            break;
        case CKK_EC_EDWARDS:
            switch (p11prov_obj_get_key_bit_size(obj)) {
            case ED448_BIT_SIZE:
                data_type = (char *)ED448;
                break;
            case ED25519_BIT_SIZE:
                data_type = (char *)ED25519;
                break;
            default:
                return RET_OSSL_ERR;
            }
            break;
        default:
            return RET_OSSL_ERR;
        }
        p11prov_obj_to_store_reference(obj, &reference, &reference_sz);
        break;
    case CKO_CERTIFICATE:
        object_type = OSSL_OBJECT_CERT;
        data_type = (char *)P11PROV_NAME_CERTIFICATE;
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
    P11PROV_CTX *ctx = NULL;
    P11PROV_OBJ *obj = NULL;

    P11PROV_debug("store (%p) export object %p, %zu", loaderctx, reference,
                  reference_sz);

    obj = p11prov_obj_from_reference(reference, reference_sz);
    if (!obj) {
        return RET_OSSL_ERR;
    }
    ctx = p11prov_obj_get_prov_ctx(obj);
    if (!ctx) {
        return RET_OSSL_ERR;
    }

    if (p11prov_ctx_allow_export(ctx) & DISALLOW_EXPORT_PUBLIC) {
        return RET_OSSL_ERR;
    }

    /* we can only export public bits, so that's all we do */
    return p11prov_obj_export_public_key(obj, CK_UNAVAILABLE_INFORMATION, false,
                                         cb_fn, cb_arg);
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
    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_SERIAL);
    if (p) {
        BN_free(ctx->serial);
        ctx->serial = NULL;
        ret = OSSL_PARAM_get_BN(p, &ctx->serial);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

int p11prov_store_direct_fetch(void *provctx, const char *uri,
                               OSSL_CALLBACK *object_cb, void *object_cbarg,
                               OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    int ret = RET_OSSL_OK;
    p11prov_set_error_mark(provctx);

    struct p11prov_store_ctx *ctx = NULL;
    ctx = p11prov_store_open(provctx, uri);
    if (!ctx) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    do {
        int load_ret =
            p11prov_store_load(ctx, object_cb, object_cbarg, pw_cb, pw_cbarg);
        if (load_ret != RET_OSSL_OK) {
            ret = RET_OSSL_ERR;
        }
    } while (!p11prov_store_eof(ctx));

done:
    p11prov_store_ctx_free(ctx);

    if (ret == RET_OSSL_OK) {
        p11prov_pop_error_to_mark(provctx);
    } else {
        p11prov_clear_last_error_mark(provctx);
    }
    return ret;
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
