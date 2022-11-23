/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include "platform/endian.h"

struct p11prov_key {
    CK_KEY_TYPE type;
    CK_BBOOL always_auth;
    CK_ULONG size;
};

struct p11prov_obj {
    P11PROV_CTX *ctx;

    CK_SLOT_ID slotid;
    CK_OBJECT_HANDLE handle;
    CK_OBJECT_CLASS class;

    union {
        struct p11prov_key key;
    } data;

    CK_ATTRIBUTE *attrs;
    unsigned long numattrs;

    int refcnt;
};

P11PROV_OBJ *p11prov_obj_new(P11PROV_CTX *ctx, CK_SLOT_ID slotid,
                             CK_OBJECT_HANDLE handle, CK_OBJECT_CLASS class)
{
    P11PROV_OBJ *obj;

    obj = OPENSSL_zalloc(sizeof(P11PROV_OBJ));
    if (obj == NULL) {
        return NULL;
    }
    obj->ctx = ctx;
    obj->slotid = slotid;
    obj->handle = handle;
    obj->class = class;

    obj->refcnt = 1;

    return obj;
}

P11PROV_OBJ *p11prov_obj_ref(P11PROV_OBJ *obj)
{
    if (obj && __atomic_fetch_add(&obj->refcnt, 1, __ATOMIC_SEQ_CST) > 0) {
        return obj;
    }

    return NULL;
}

void p11prov_obj_free(P11PROV_OBJ *obj)
{
    P11PROV_debug("object free (%p)", obj);

    if (obj == NULL) {
        return;
    }
    if (__atomic_sub_fetch(&obj->refcnt, 1, __ATOMIC_SEQ_CST) != 0) {
        P11PROV_debug("object free: reference held");
        return;
    }

    for (size_t i = 0; i < obj->numattrs; i++) {
        OPENSSL_free(obj->attrs[i].pValue);
    }
    OPENSSL_free(obj->attrs);

    OPENSSL_clear_free(obj, sizeof(P11PROV_OBJ));
}

CK_SLOT_ID p11prov_obj_get_slotid(P11PROV_OBJ *obj)
{
    if (obj) {
        return obj->slotid;
    }
    return CK_UNAVAILABLE_INFORMATION;
}

CK_OBJECT_HANDLE p11prov_obj_get_handle(P11PROV_OBJ *obj)
{
    if (obj) {
        return obj->handle;
    }
    return CK_INVALID_HANDLE;
}

CK_OBJECT_CLASS p11prov_obj_get_class(P11PROV_OBJ *obj)
{
    if (obj) {
        return obj->class;
    }
    return CK_UNAVAILABLE_INFORMATION;
}

CK_ATTRIBUTE *p11prov_obj_get_attr(P11PROV_OBJ *obj, CK_ATTRIBUTE_TYPE type)
{
    if (!obj) {
        return NULL;
    }

    for (size_t i = 0; i < obj->numattrs; i++) {
        if (obj->attrs[i].type == type) {
            return &obj->attrs[i];
        }
    }

    return NULL;
}

CK_KEY_TYPE p11prov_obj_get_key_type(P11PROV_OBJ *obj)
{
    if (obj) {
        switch (obj->class) {
        case CKO_PRIVATE_KEY:
        case CKO_PUBLIC_KEY:
            return obj->data.key.type;
        }
    }
    return CK_UNAVAILABLE_INFORMATION;
}

CK_ULONG p11prov_obj_get_key_size(P11PROV_OBJ *obj)
{
    if (obj) {
        switch (obj->class) {
        case CKO_PRIVATE_KEY:
        case CKO_PUBLIC_KEY:
            return obj->data.key.size;
        }
    }
    return CK_UNAVAILABLE_INFORMATION;
}

void p11prov_obj_to_reference(P11PROV_OBJ *obj, void **reference,
                              size_t *reference_sz)
{
    *reference = p11prov_obj_ref(obj);
    *reference_sz = sizeof(P11PROV_OBJ);
}

P11PROV_OBJ *p11prov_obj_from_reference(const void *reference,
                                        size_t reference_sz)
{
    if (!reference || reference_sz != sizeof(P11PROV_OBJ)) {
        return NULL;
    }

    return (P11PROV_OBJ *)reference;
}

#define BASE_KEY_ATTRS_NUM 3

#define RSA_ATTRS_NUM (BASE_KEY_ATTRS_NUM + 2)
static int fetch_rsa_key(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                         CK_OBJECT_HANDLE object, P11PROV_OBJ *key)
{
    struct fetch_attrs attrs[RSA_ATTRS_NUM];
    CK_ULONG n_len = 0, e_len = 0, id_len = 0, label_len = 0;
    CK_BYTE *n = NULL, *e = NULL, *id = NULL;
    CK_UTF8CHAR *label = NULL;
    int ret;

    key->attrs = OPENSSL_zalloc(RSA_ATTRS_NUM * sizeof(CK_ATTRIBUTE));
    if (key->attrs == NULL) {
        return CKR_HOST_MEMORY;
    }
    FA_ASSIGN_ALL(attrs[0], CKA_MODULUS, &n, &n_len, true, true);
    FA_ASSIGN_ALL(attrs[1], CKA_PUBLIC_EXPONENT, &e, &e_len, true, true);
    FA_ASSIGN_ALL(attrs[2], CKA_ID, &id, &id_len, true, false);
    FA_ASSIGN_ALL(attrs[3], CKA_LABEL, &label, &label_len, true, false);
    ret = p11prov_fetch_attributes(ctx, session, object, attrs, 4);
    if (ret != CKR_OK) {
        /* free any allocated memory */
        OPENSSL_free(n);
        OPENSSL_free(e);
        OPENSSL_free(label);
        OPENSSL_free(id);

        if (key->class == CKO_PRIVATE_KEY) {
            /* A private key may not always return these */
            return CKR_OK;
        }
        return ret;
    }

    key->data.key.size = n_len;
    CKATTR_ASSIGN_ALL(key->attrs[0], CKA_MODULUS, n, n_len);
    CKATTR_ASSIGN_ALL(key->attrs[1], CKA_PUBLIC_EXPONENT, e, e_len);
    key->numattrs = 2;
    if (id_len > 0) {
        CKATTR_ASSIGN_ALL(key->attrs[key->numattrs], CKA_ID, id, id_len);
        key->numattrs++;
    }
    if (label_len > 0) {
        CKATTR_ASSIGN_ALL(key->attrs[key->numattrs], CKA_LABEL, label,
                          label_len);
        key->numattrs++;
    }
    return CKR_OK;
}

#define EC_ATTRS_NUM (BASE_KEY_ATTRS_NUM + 2)
static int fetch_ec_key(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                        CK_OBJECT_HANDLE object, P11PROV_OBJ *key)
{
    struct fetch_attrs attrs[EC_ATTRS_NUM];
    CK_ULONG params_len = 0, point_len = 0, id_len = 0, label_len = 0;
    CK_BYTE *params = NULL, *point = NULL, *id = NULL;
    CK_UTF8CHAR *label = NULL;
    size_t n_bytes = 0;
    int n;
    int ret;

    key->attrs = OPENSSL_zalloc(EC_ATTRS_NUM * sizeof(CK_ATTRIBUTE));
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
    FA_ASSIGN_ALL(attrs[n], CKA_ID, &id, &id_len, true, false);
    n++;
    FA_ASSIGN_ALL(attrs[n], CKA_LABEL, &label, &label_len, true, false);
    n++;
    ret = p11prov_fetch_attributes(ctx, session, object, attrs, n);
    if (ret != CKR_OK) {
        /* free any allocated memory */
        OPENSSL_free(params);
        OPENSSL_free(point);
        OPENSSL_free(label);
        OPENSSL_free(id);
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
            OPENSSL_free(label);
            OPENSSL_free(id);
            return CKR_KEY_INDIGESTIBLE;
        }

        bn = EC_GROUP_get0_order(group);
        if (bn == NULL) {
            /* free any allocated memory */
            EC_GROUP_free(group);
            OPENSSL_free(params);
            OPENSSL_free(point);
            OPENSSL_free(label);
            OPENSSL_free(id);
            return CKR_KEY_INDIGESTIBLE;
        }

        n_bytes = BN_num_bytes(bn);

        EC_GROUP_free(group);
    }

    key->data.key.size = n_bytes;
    CKATTR_ASSIGN_ALL(key->attrs[0], CKA_EC_PARAMS, params, params_len);
    key->numattrs = 1;
    if (point_len > 0) {
        CKATTR_ASSIGN_ALL(key->attrs[1], CKA_EC_POINT, point, point_len);
        key->numattrs++;
    }
    if (id_len > 0) {
        CKATTR_ASSIGN_ALL(key->attrs[key->numattrs], CKA_ID, id, id_len);
        key->numattrs++;
    }
    if (label_len > 0) {
        CKATTR_ASSIGN_ALL(key->attrs[key->numattrs], CKA_LABEL, label,
                          label_len);
        key->numattrs++;
    }
    return CKR_OK;
}

/* TODO: may want to have a hashmap with cached objects */
CK_RV p11prov_obj_from_handle(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                              CK_OBJECT_HANDLE handle, P11PROV_OBJ **object)
{
    P11PROV_OBJ *obj;
    CK_OBJECT_CLASS *class;
    CK_ULONG class_len = sizeof(CK_OBJECT_CLASS);
    CK_KEY_TYPE *key_type;
    CK_ULONG key_type_len = sizeof(CK_KEY_TYPE);
    struct fetch_attrs attrs[2];
    CK_BBOOL token_supports_allowed_mechs = CK_TRUE;
    CK_RV ret;

    obj = p11prov_obj_new(ctx, p11prov_session_slotid(session), handle,
                          CK_UNAVAILABLE_INFORMATION);
    if (obj == NULL) {
        return CKR_HOST_MEMORY;
    }
    obj->handle = handle;
    obj->slotid = p11prov_session_slotid(session);

    class = &obj->class;
    FA_ASSIGN_ALL(attrs[0], CKA_CLASS, &class, &class_len, false, true);
    key_type = &obj->data.key.type;
    FA_ASSIGN_ALL(attrs[1], CKA_KEY_TYPE, &key_type, &key_type_len, false,
                  true);

    ret = p11prov_fetch_attributes(ctx, session, handle, attrs, 2);
    if (ret != CKR_OK) {
        P11PROV_debug("Failed to query object attributes (%lu)", ret);
        p11prov_obj_free(obj);
        return ret;
    }

    switch (obj->data.key.type) {
    case CKK_RSA:
        ret = fetch_rsa_key(ctx, session, handle, obj);
        if (ret != CKR_OK) {
            p11prov_obj_free(obj);
            return ret;
        }
        break;
    case CKK_EC:
        ret = fetch_ec_key(ctx, session, handle, obj);
        if (ret != CKR_OK) {
            p11prov_obj_free(obj);
            return ret;
        }
        break;
    default:
        /* unknown key type, we can't handle it */
        P11PROV_debug("Unsupported key type (%lu)", obj->data.key.type);
        p11prov_obj_free(obj);
        return CKR_ARGUMENTS_BAD;
    }

    /* do this at the end as it often won't be a supported attributed */
    ret = p11prov_token_sup_attr(ctx, obj->slotid, GET_ATTR,
                                 CKA_ALLOWED_MECHANISMS,
                                 &token_supports_allowed_mechs);
    if (ret != CKR_OK) {
        P11PROV_raise(ctx, ret, "Failed to probe quirk");
    } else if (token_supports_allowed_mechs == CK_TRUE) {
        CK_BYTE *value;
        CK_ULONG value_len;
        FA_ASSIGN_ALL(attrs[0], CKA_ALLOWED_MECHANISMS, &value, &value_len,
                      true, false);
        ret = p11prov_fetch_attributes(ctx, session, handle, attrs, 1);
        if (ret == CKR_OK) {
            CKATTR_ASSIGN_ALL(obj->attrs[obj->numattrs], CKA_ALLOWED_MECHANISMS,
                              value, value_len);
            obj->numattrs++;
        } else if (ret == CKR_ATTRIBUTE_TYPE_INVALID) {
            token_supports_allowed_mechs = CK_FALSE;
            (void)p11prov_token_sup_attr(ctx, obj->slotid, SET_ATTR,
                                         CKA_ALLOWED_MECHANISMS,
                                         &token_supports_allowed_mechs);
        }
    }

    *object = obj;
    return CKR_OK;
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
    CK_ATTRIBUTE label = p11prov_uri_get_label(uri);
    CK_ATTRIBUTE template[3] = { 0 };
    CK_ULONG tsize = 0;
    CK_ULONG objcount = 0;
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
    if (label.type == CKA_LABEL) {
        template[tsize] = label;
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
            P11PROV_OBJ *obj = NULL;
            ret = p11prov_obj_from_handle(provctx, session, object[k], &obj);
            if (ret == CKR_OK) {
                ret = cb(cb_ctx, obj);
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

P11PROV_OBJ *find_associated_key(P11PROV_CTX *provctx, P11PROV_OBJ *key,
                                 CK_OBJECT_CLASS class)
{
    CK_FUNCTION_LIST *f;
    CK_ATTRIBUTE template[2] = { 0 };
    CK_ATTRIBUTE *id;
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SESSION *session = NULL;
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE handle;
    CK_ULONG objcount = 0;
    P11PROV_OBJ *akey = NULL;
    CK_RV ret;

    P11PROV_debug("Find associated key");

    ret = p11prov_ctx_status(provctx, &f);
    if (ret != CKR_OK) {
        goto done;
    }

    if (class != CKO_PUBLIC_KEY && class != CKO_PRIVATE_KEY) {
        P11PROV_raise(provctx, CKR_GENERAL_ERROR, "Invalid class");
        goto done;
    }

    id = p11prov_obj_get_attr(key, CKA_ID);
    if (!id) {
        P11PROV_raise(provctx, CKR_GENERAL_ERROR, "Source key missing CKA_ID");
        goto done;
    }

    CKATTR_ASSIGN_ALL(template[0], CKA_CLASS, &class, sizeof(class));
    template[1] = *id;

    slotid = p11prov_obj_get_slotid(key);

    ret = p11prov_get_session(provctx, &slotid, NULL, NULL, NULL, NULL, false,
                              false, &session);
    if (ret != CKR_OK) {
        goto done;
    }

    sess = p11prov_session_handle(session);

    ret = f->C_FindObjectsInit(sess, template, 2);
    if (ret != CKR_OK) {
        P11PROV_raise(provctx, ret, "Error returned by C_FindObjectsInit");
        goto done;
    }

    /* we expect a single entry */
    ret = f->C_FindObjects(sess, &handle, 1, &objcount);
    if (ret != CKR_OK || objcount != 1) {
        P11PROV_raise(provctx, ret, "Error in C_FindObjects (count=%ld)",
                      objcount);
        goto done;
    }

    ret = p11prov_obj_from_handle(provctx, session, handle, &akey);
    if (ret != CKR_OK) {
        P11PROV_raise(provctx, ret, "Failed to get key from handle");
    }

done:
    p11prov_session_free(session);
    return akey;
}

P11PROV_OBJ *p11prov_create_secret_key(P11PROV_CTX *provctx,
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
    P11PROV_OBJ *obj;
    struct fetch_attrs attrs[2];
    CK_ULONG id_len = 0, label_len = 0;
    CK_BYTE *id = NULL;
    CK_UTF8CHAR *label = NULL;
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

    obj = p11prov_obj_new(provctx, session_info.slotID, key_handle, key_class);
    if (obj == NULL) {
        return NULL;
    }
    obj->data.key.type = key_type;
    obj->data.key.size = secretlen;

    obj->attrs = OPENSSL_zalloc(2 * sizeof(CK_ATTRIBUTE));
    if (obj->attrs == NULL) {
        P11PROV_raise(provctx, CKR_HOST_MEMORY, "Allocation failure");
        p11prov_obj_free(obj);
        return NULL;
    }
    obj->numattrs = 0;

    FA_ASSIGN_ALL(attrs[0], CKA_ID, &id, &id_len, true, false);
    FA_ASSIGN_ALL(attrs[1], CKA_LABEL, &label, &label_len, true, false);
    ret = p11prov_fetch_attributes(provctx, session, key_handle, attrs, 2);
    if (ret == CKR_OK) {
        if (id_len > 0) {
            CKATTR_ASSIGN_ALL(obj->attrs[obj->numattrs], CKA_ID, id, id_len);
            obj->numattrs++;
        }
        if (label_len > 0) {
            CKATTR_ASSIGN_ALL(obj->attrs[obj->numattrs], CKA_LABEL, label,
                              label_len);
            obj->numattrs++;
        }
    } else {
        P11PROV_debug("Failed to query object attributes (%lu)", ret);
        OPENSSL_free(label);
        OPENSSL_free(id);
        p11prov_obj_free(obj);
        obj = NULL;
    }
    return obj;
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
            /* TODO: Explicitly mark handle invalid */
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

CK_RV p11prov_obj_set_attributes(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                                 P11PROV_OBJ *obj, CK_ATTRIBUTE *template,
                                 CK_ULONG tsize)
{
    P11PROV_SESSION *s = session;
    CK_SLOT_ID slotid = obj->slotid;
    CK_FUNCTION_LIST *f;
    CK_RV ret;

    if (!s) {
        ret = p11prov_get_session(ctx, &slotid, NULL, NULL, NULL, NULL, false,
                                  true, &s);
        if (ret != CKR_OK) {
            P11PROV_raise(ctx, ret, "Failed to open session on slot %lu",
                          slotid);
            return ret;
        }
    }

    ret = p11prov_ctx_status(ctx, &f);
    if (ret != CKR_OK) {
        goto done;
    }

    ret = f->C_SetAttributeValue(p11prov_session_handle(s), obj->handle,
                                 template, tsize);

    /* TODO: should we retry iterating value by value on each element of
     * template to be able to set as much as we can and return which attribute
     * exactly the token is refusing ? */

done:
    if (s != session) {
        p11prov_session_free(s);
    }
    return ret;
}

/* Tokens return data in bigendian order, while openssl
 * wants it in host order, so we may need to fix the
 * endianness of the buffer.
 * Src and Dest, can be the same area, but not partially
 * overlapping memory areas */

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define WITH_FIXED_BUFFER(src, ptr) \
    unsigned char fix_##src[src->ulValueLen]; \
    byteswap_buf(src->pValue, fix_##src, src->ulValueLen); \
    ptr = fix_##src;
#else
#define WITH_FIXED_BUFFER(src, ptr) ptr = src->pValue;
#endif
int p11prov_obj_export_public_rsa_key(P11PROV_OBJ *obj, OSSL_CALLBACK *cb_fn,
                                      void *cb_arg)
{
    P11PROV_OBJ *pubkey = NULL;
    OSSL_PARAM params[3];
    CK_ATTRIBUTE *n, *e;
    unsigned char *val;
    int ret;

    if (p11prov_obj_get_key_type(obj) != CKK_RSA) {
        return RET_OSSL_ERR;
    }

    if (p11prov_ctx_allow_export(obj->ctx) & DISALLOW_EXPORT_PUBLIC) {
        return RET_OSSL_ERR;
    }

    n = p11prov_obj_get_attr(obj, CKA_MODULUS);
    e = p11prov_obj_get_attr(obj, CKA_PUBLIC_EXPONENT);
    if (!n || !e) {
        if (obj->class == CKO_PRIVATE_KEY) {
            /* try to find the associated public key */
            pubkey = find_associated_key(obj->ctx, obj, CKO_PUBLIC_KEY);
            if (!pubkey) {
                return RET_OSSL_ERR;
            }
            n = p11prov_obj_get_attr(pubkey, CKA_MODULUS);
            e = p11prov_obj_get_attr(pubkey, CKA_PUBLIC_EXPONENT);
            if (!n || !e) {
                p11prov_obj_free(pubkey);
                return RET_OSSL_ERR;
            }
        } else {
            return RET_OSSL_ERR;
        }
    }

    WITH_FIXED_BUFFER(n, val);
    params[0] =
        OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, val, n->ulValueLen);

    WITH_FIXED_BUFFER(e, val);
    params[1] =
        OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, val, e->ulValueLen);

    params[2] = OSSL_PARAM_construct_end();

    ret = cb_fn(params, cb_arg);

    p11prov_obj_free(pubkey);
    return ret;
}

int p11prov_obj_export_public_ec_key(P11PROV_OBJ *obj, OSSL_CALLBACK *cb_fn,
                                     void *cb_arg)
{
    P11PROV_OBJ *pubkey = NULL;
    OSSL_PARAM params[3];
    CK_ATTRIBUTE *ec_params, *ec_point;
    ASN1_OCTET_STRING *octet = NULL;
    EC_GROUP *group = NULL;
    const unsigned char *val;
    const char *curve_name;
    int curve_nid;
    int ret;

    if (p11prov_obj_get_key_type(obj) != CKK_EC) {
        return RET_OSSL_ERR;
    }

    if (p11prov_ctx_allow_export(obj->ctx) & DISALLOW_EXPORT_PUBLIC) {
        return RET_OSSL_ERR;
    }

    ec_params = p11prov_obj_get_attr(obj, CKA_EC_PARAMS);
    ec_point = p11prov_obj_get_attr(obj, CKA_EC_POINT);
    if (!ec_params || !ec_point) {
        if (obj->class == CKO_PRIVATE_KEY) {
            /* try to find the associated public key */
            pubkey = find_associated_key(obj->ctx, obj, CKO_PUBLIC_KEY);
            if (!pubkey) {
                return RET_OSSL_ERR;
            }
            ec_params = p11prov_obj_get_attr(pubkey, CKA_EC_PARAMS);
            ec_point = p11prov_obj_get_attr(pubkey, CKA_EC_POINT);
            if (!ec_params || !ec_point) {
                p11prov_obj_free(pubkey);
                return RET_OSSL_ERR;
            }
        } else {
            return RET_OSSL_ERR;
        }
    }

    /* in d2i functions 'in' is overwritten to return the remainder of the
     * buffer after parsing, so we always need to avoid passing in our pointer
     * folders, to avoid having them clobbered */
    val = ec_params->pValue;
    group = d2i_ECPKParameters(NULL, (const unsigned char **)&val,
                               ec_params->ulValueLen);
    if (group == NULL) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    curve_nid = EC_GROUP_get_curve_name(group);
    if (curve_nid == NID_undef) {
        EC_GROUP_free(group);
        return RET_OSSL_ERR;
    }
    curve_name = OSSL_EC_curve_nid2name(curve_nid);
    if (curve_name == NULL) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)curve_name, 0);

    val = ec_point->pValue;
    octet = d2i_ASN1_OCTET_STRING(NULL, (const unsigned char **)&val,
                                  ec_point->ulValueLen);
    if (octet == NULL) {
        return RET_OSSL_ERR;
    }
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  octet->data, octet->length);

    params[2] = OSSL_PARAM_construct_end();

    ret = cb_fn(params, cb_arg);

done:
    /* must be freed after callback */
    ASN1_OCTET_STRING_free(octet);
    p11prov_obj_free(pubkey);
    EC_GROUP_free(group);
    return ret;
}
