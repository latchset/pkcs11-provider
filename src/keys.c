/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>
#include <openssl/ec.h>

struct p11prov_key {
    CK_SLOT_ID slotid;
    CK_OBJECT_HANDLE handle;
    CK_OBJECT_CLASS class;
    CK_KEY_TYPE type;

    unsigned char *id;
    unsigned long id_len;
    char *label;
    CK_BBOOL always_auth;

    CK_ULONG key_size;

    CK_ATTRIBUTE *attrs;
    unsigned long numattrs;

    int refcnt;
};

static P11PROV_KEY *p11prov_key_new(void)
{
    P11PROV_KEY *key;

    key = OPENSSL_zalloc(sizeof(P11PROV_KEY));
    if (!key) {
        return NULL;
    }

    key->refcnt = 1;

    return key;
}

P11PROV_KEY *p11prov_key_ref(P11PROV_KEY *key)
{
    if (key && __atomic_fetch_add(&key->refcnt, 1, __ATOMIC_SEQ_CST) > 0) {
        return key;
    }

    return NULL;
}

void p11prov_key_free(P11PROV_KEY *key)
{
    P11PROV_debug("key free (%p)", key);

    if (key == NULL) {
        return;
    }
    if (__atomic_sub_fetch(&key->refcnt, 1, __ATOMIC_SEQ_CST) != 0) {
        P11PROV_debug("key free: reference held");
        return;
    }

    OPENSSL_free(key->id);
    OPENSSL_free(key->label);

    for (size_t i = 0; i < key->numattrs; i++) {
        OPENSSL_free(key->attrs[i].pValue);
    }
    OPENSSL_free(key->attrs);

    OPENSSL_clear_free(key, sizeof(P11PROV_KEY));
}

CK_ATTRIBUTE *p11prov_key_attr(P11PROV_KEY *key, CK_ATTRIBUTE_TYPE type)
{
    if (!key) {
        return NULL;
    }

    for (size_t i = 0; i < key->numattrs; i++) {
        if (key->attrs[i].type == type) {
            return &key->attrs[i];
        }
    }

    return NULL;
}

CK_KEY_TYPE p11prov_key_type(P11PROV_KEY *key)
{
    if (key) {
        return key->type;
    }
    return CK_UNAVAILABLE_INFORMATION;
}

CK_SLOT_ID p11prov_key_slotid(P11PROV_KEY *key)
{
    if (key) {
        return key->slotid;
    }
    return CK_UNAVAILABLE_INFORMATION;
}

CK_OBJECT_HANDLE p11prov_key_handle(P11PROV_KEY *key)
{
    if (key) {
        return key->handle;
    }
    return CK_INVALID_HANDLE;
}

CK_ULONG p11prov_key_size(P11PROV_KEY *key)
{
    if (key == NULL) {
        return CK_UNAVAILABLE_INFORMATION;
    }
    return key->key_size;
}

static int fetch_rsa_key(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                         CK_OBJECT_HANDLE object, P11PROV_KEY *key)
{
    struct fetch_attrs attrs[2];
    unsigned long n_len = 0, e_len = 0;
    CK_BYTE *n = NULL, *e = NULL;
    int ret;

    key->attrs = OPENSSL_zalloc(2 * sizeof(CK_ATTRIBUTE));
    if (key->attrs == NULL) {
        return CKR_HOST_MEMORY;
    }
    FA_ASSIGN_ALL(attrs[0], CKA_MODULUS, &n, &n_len, true, true);
    FA_ASSIGN_ALL(attrs[1], CKA_PUBLIC_EXPONENT, &e, &e_len, true, true);
    ret = p11prov_fetch_attributes(ctx, session, object, attrs, 2);
    if (ret != CKR_OK) {
        /* free any allocated memory */
        OPENSSL_free(n);
        OPENSSL_free(e);

        if (key->class == CKO_PRIVATE_KEY) {
            /* A private key may not always return these */
            return CKR_OK;
        }
        return ret;
    }

    key->key_size = n_len;
    CKATTR_ASSIGN_ALL(key->attrs[0], CKA_MODULUS, n, n_len);
    CKATTR_ASSIGN_ALL(key->attrs[1], CKA_PUBLIC_EXPONENT, e, e_len);
    key->numattrs = 2;
    return CKR_OK;
}

static int fetch_ec_key(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                        CK_OBJECT_HANDLE object, P11PROV_KEY *key)
{
    struct fetch_attrs attrs[2];
    unsigned long params_len = 0, point_len = 0;
    CK_BYTE *params = NULL, *point = NULL;
    size_t n_bytes = 0;
    int n;
    int ret;

    key->attrs = OPENSSL_zalloc(2 * sizeof(CK_ATTRIBUTE));
    if (key->attrs == NULL) {
        return CKR_HOST_MEMORY;
    }

    n = 0;
    FA_ASSIGN_ALL(attrs[n], CKA_EC_PARAMS, &params, &params_len, true, true);
    n++;
    if (key->class == CKO_PUBLIC_KEY) {
        FA_ASSIGN_ALL(attrs[n], CKA_EC_POINT, &point, &point_len, true, true);
        n++;
    }
    ret = p11prov_fetch_attributes(ctx, session, object, attrs, n);
    if (ret != CKR_OK) {
        /* free any allocated memory */
        OPENSSL_free(params);
        OPENSSL_free(point);
        return ret;
    }

    /* decode CKA_EC_PARAMS and store some extra attrs for
     * convenience */
    if (params != NULL) {
        const unsigned char *der = params;
        EC_GROUP *group = NULL;
        const BIGNUM *bn;

        (void)d2i_ECPKParameters(&group, &der, params_len);
        if (group == NULL) {
            /* free any allocated memory */
            OPENSSL_free(params);
            OPENSSL_free(point);
            return CKR_KEY_INDIGESTIBLE;
        }

        bn = EC_GROUP_get0_order(group);
        if (bn == NULL) {
            /* free any allocated memory */
            EC_GROUP_free(group);
            OPENSSL_free(params);
            OPENSSL_free(point);
            return CKR_KEY_INDIGESTIBLE;
        }

        n_bytes = BN_num_bytes(bn);

        EC_GROUP_free(group);
    }

    key->key_size = n_bytes;
    CKATTR_ASSIGN_ALL(key->attrs[0], CKA_EC_PARAMS, params, params_len);
    if (n > 1) {
        CKATTR_ASSIGN_ALL(key->attrs[1], CKA_EC_POINT, point, point_len);
    }
    key->numattrs = n;
    return CKR_OK;
}

/* TODO: may want to have a hashmap with cached keys */
static P11PROV_KEY *object_handle_to_key(P11PROV_CTX *ctx, CK_SLOT_ID slotid,
                                         P11PROV_SESSION *session,
                                         CK_OBJECT_HANDLE object)
{
    P11PROV_KEY *key;
    CK_OBJECT_CLASS *key_class;
    CK_ULONG key_class_len = sizeof(CK_OBJECT_CLASS);
    CK_KEY_TYPE *key_type;
    CK_ULONG key_type_len = sizeof(CK_KEY_TYPE);
    CK_ULONG label_len;
    struct fetch_attrs attrs[4];
    int ret;

    key = p11prov_key_new();
    if (key == NULL) {
        return NULL;
    }

    key_class = &key->class;
    FA_ASSIGN_ALL(attrs[0], CKA_CLASS, &key_class, &key_class_len, false, true);
    key_type = &key->type;
    FA_ASSIGN_ALL(attrs[1], CKA_KEY_TYPE, &key_type, &key_type_len, false,
                  true);
    FA_ASSIGN_ALL(attrs[2], CKA_ID, &key->id, &key->id_len, true, false);
    FA_ASSIGN_ALL(attrs[3], CKA_LABEL, &key->label, &label_len, true, false);
    /* TODO: fetch also other attributes as specified in
     * Spev v3 - 4.9 Private key objects  ?? */

    ret = p11prov_fetch_attributes(ctx, session, object, attrs, 4);
    if (ret != CKR_OK) {
        P11PROV_debug("Failed to query object attributes (%d)", ret);
        p11prov_key_free(key);
        return NULL;
    }

    key->slotid = slotid;
    key->handle = object;

    switch (key->type) {
    case CKK_RSA:
        ret = fetch_rsa_key(ctx, session, object, key);
        if (ret != CKR_OK) {
            p11prov_key_free(key);
            return NULL;
        }
        break;
    case CKK_EC:
        ret = fetch_ec_key(ctx, session, object, key);
        if (ret != CKR_OK) {
            p11prov_key_free(key);
            return NULL;
        }
        break;
    default:
        /* unknown key type, we can't handle it */
        P11PROV_debug("Unsupported key type (%lu)", key->type);
        p11prov_key_free(key);
        return NULL;
    }

    return key;
}

#define MAX_OBJS_IN_STORE 1024

CK_RV find_keys(P11PROV_CTX *provctx, P11PROV_SESSION *session,
                CK_SLOT_ID slotid, P11PROV_URI *uri, store_key_callback cb,
                void *cb_ctx)
{
    CK_FUNCTION_LIST *f;
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS class = p11prov_uri_get_class(uri);
    CK_ATTRIBUTE id = p11prov_uri_get_id(uri);
    char *label = p11prov_uri_get_object(uri);
    CK_ATTRIBUTE template[3] = { 0 };
    CK_ULONG tsize = 0;
    CK_ULONG objcount = 0;
    P11PROV_KEY *key = NULL;
    CK_RV result = CKR_GENERAL_ERROR;
    CK_RV ret;

    P11PROV_debug("Find keys");

    ret = p11prov_ctx_status(provctx, &f);
    if (ret != CKR_OK) {
        return ret;
    }

    if (class != CK_UNAVAILABLE_INFORMATION) {
        if (class != CKO_PUBLIC_KEY && class != CKO_PRIVATE_KEY) {
            /* nothing to find for us */
            return CKR_OK;
        }
        CKATTR_ASSIGN_ALL(template[tsize], CKA_CLASS, &class, sizeof(class));
        tsize++;
    }
    if (id.type == CKA_ID) {
        template[tsize] = id;
        tsize++;
    }
    if (label) {
        CKATTR_ASSIGN_ALL(template[tsize], CKA_LABEL, label, strlen(label));
        tsize++;
    }

    sess = p11prov_session_handle(session);

    ret = f->C_FindObjectsInit(sess, template, tsize);
    if (ret != CKR_OK) {
        P11PROV_raise(provctx, ret, "Error returned by C_FindObjectsInit");
        return ret;
    }
    for (int idx = 0; idx < MAX_OBJS_IN_STORE; idx += objcount) {
        CK_OBJECT_HANDLE object[64];
        ret = f->C_FindObjects(sess, object, 64, &objcount);
        if (ret != CKR_OK || objcount == 0) {
            result = ret;
            break;
        }

        for (CK_ULONG k = 0; k < objcount; k++) {
            key = object_handle_to_key(provctx, slotid, session, object[k]);
            if (key) {
                ret = cb(cb_ctx, key->class, key);
                if (ret != CKR_OK) {
                    result = ret;
                    break;
                }
            }
        }
    }

    ret = f->C_FindObjectsFinal(sess);
    if (ret != CKR_OK) {
        /* this is not fatal */
        P11PROV_raise(provctx, ret, "Failed to terminate object search");
    }

    return result;
}

P11PROV_KEY *p11prov_create_secret_key(P11PROV_CTX *provctx,
                                       P11PROV_SESSION *session,
                                       bool session_key, unsigned char *secret,
                                       size_t secretlen)
{
    CK_FUNCTION_LIST *f;
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_SESSION_INFO session_info;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_token = session_key ? CK_FALSE : CK_TRUE;
    CK_ATTRIBUTE key_template[5] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_TOKEN, &val_token, sizeof(val_token) },
        { CKA_DERIVE, &val_true, sizeof(val_true) },
        { CKA_VALUE, (void *)secret, secretlen },
    };
    CK_OBJECT_HANDLE key_handle;
    P11PROV_KEY *key;
    struct fetch_attrs attrs[2];
    unsigned long label_len;
    CK_RV ret;

    sess = p11prov_session_handle(session);

    P11PROV_debug("keys: create secret key (session:%lu secret:%p[%zu])", sess,
                  secret, secretlen);

    ret = p11prov_ctx_status(provctx, &f);
    if (ret != CKR_OK) {
        return NULL;
    }

    ret = f->C_GetSessionInfo(sess, &session_info);
    if (ret != CKR_OK) {
        P11PROV_raise(provctx, ret, "Error returned by C_GetSessionInfo");
        return NULL;
    }
    if (((session_info.flags & CKF_RW_SESSION) == 0) && val_token == CK_TRUE) {
        P11PROV_debug("Invalid read only session for token key request");
        return NULL;
    }

    ret = f->C_CreateObject(sess, key_template, 5, &key_handle);
    if (ret != CKR_OK) {
        P11PROV_raise(provctx, ret,
                      "Error returned by C_CreateObject while creating key");
        return NULL;
    }

    key = p11prov_key_new();
    if (key == NULL) {
        return NULL;
    }

    key->type = key_type;
    key->slotid = session_info.slotID;
    key->handle = key_handle;
    key->class = key_class;
    key->key_size = secretlen;
    key->numattrs = 0;

    FA_ASSIGN_ALL(attrs[0], CKA_ID, &key->id, &key->id_len, true, false);
    FA_ASSIGN_ALL(attrs[1], CKA_LABEL, &key->label, &label_len, true, false);
    ret = p11prov_fetch_attributes(provctx, session, key_handle, attrs, 2);
    if (ret != CKR_OK) {
        P11PROV_debug("Failed to query object attributes (%lu)", ret);
    }

    if (ret != CKR_OK) {
        p11prov_key_free(key);
        key = NULL;
    }
    return key;
}

CK_RV p11prov_derive_key(P11PROV_CTX *ctx, CK_SLOT_ID slotid,
                         CK_MECHANISM *mechanism, CK_OBJECT_HANDLE handle,
                         CK_ATTRIBUTE *template, CK_ULONG nattrs,
                         P11PROV_SESSION **session, CK_OBJECT_HANDLE *key)
{
    bool first_pass = true;
    P11PROV_SESSION *s = *session;
    CK_FUNCTION_LIST *f;
    CK_RV ret;

    ret = p11prov_ctx_status(ctx, &f);
    if (ret != CKR_OK) {
        return ret;
    }

again:
    if (!s) {
        ret = p11prov_get_session(ctx, &slotid, NULL, NULL, NULL, NULL, false,
                                  false, &s);
        if (ret != CKR_OK) {
            P11PROV_raise(ctx, ret, "Failed to open session on slot %lu",
                          slotid);
            return ret;
        }
    }

    ret = f->C_DeriveKey(p11prov_session_handle(s), mechanism, handle, template,
                         nattrs, key);
    switch (ret) {
    case CKR_OK:
        *session = s;
        return CKR_OK;
    case CKR_SESSION_CLOSED:
    case CKR_SESSION_HANDLE_INVALID:
        if (first_pass) {
            first_pass = false;
            /* TODO: Explicilty mark handle invalid */
            p11prov_session_free(s);
            s = *session = NULL;
            goto again;
        }
        /* fallthrough */
    default:
        if (*session == NULL) {
            p11prov_session_free(s);
        }
        P11PROV_raise(ctx, ret, "Error returned by C_DeriveKey");
        return ret;
    }
}
