/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/obj_mac.h>
#include "platform/endian.h"

struct p11prov_key {
    CK_KEY_TYPE type;
    CK_BBOOL always_auth;
    CK_ULONG size;
};

struct p11prov_crt {
    CK_CERTIFICATE_TYPE type;
    CK_CERTIFICATE_CATEGORY category;
    CK_BBOOL trusted;
};

struct p11prov_obj {
    P11PROV_CTX *ctx;

    CK_SLOT_ID slotid;
    CK_OBJECT_HANDLE handle;
    CK_OBJECT_CLASS class;

    union {
        struct p11prov_key key;
        struct p11prov_crt crt;
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

P11PROV_CTX *p11prov_obj_get_prov_ctx(P11PROV_OBJ *obj)
{
    if (!obj) {
        return NULL;
    }
    return obj->ctx;
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

#define CERT_ATTRS_NUM 9
static int fetch_certificate(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                             CK_OBJECT_HANDLE object, P11PROV_OBJ *crt)
{
    struct fetch_attrs attrs[CERT_ATTRS_NUM];
    CK_ULONG crt_type_len = sizeof(CK_CERTIFICATE_TYPE);
    CK_CERTIFICATE_TYPE *crt_type;
    CK_ULONG subject_len = 0, id_len = 0, issuer_len = 0, serial_len = 0;
    CK_BYTE *subject = NULL, *id = NULL, *issuer = NULL, *serial = NULL;
    CK_ULONG value_len = 0, pubkey_len = 0;
    CK_BYTE *value = NULL, *pubkey = NULL;
    CK_BBOOL *trusted;
    CK_ULONG trusted_len = sizeof(CK_BBOOL);
    CK_CERTIFICATE_CATEGORY *category;
    CK_ULONG category_len = sizeof(CK_CERTIFICATE_CATEGORY);
    CK_RV ret;
    int n;

    crt->attrs = OPENSSL_zalloc(CERT_ATTRS_NUM * sizeof(CK_ATTRIBUTE));
    if (crt->attrs == NULL) {
        P11PROV_raise(ctx, CKR_HOST_MEMORY, "failed to allocate cert attrs");
        return CKR_HOST_MEMORY;
    }

    n = 0;

    crt_type = &crt->data.crt.type;
    FA_ASSIGN_ALL(attrs[n], CKA_CERTIFICATE_TYPE, &crt_type, &crt_type_len,
                  false, true);
    n++;
    trusted = &crt->data.crt.trusted;
    FA_ASSIGN_ALL(attrs[n], CKA_TRUSTED, &trusted, &trusted_len, false, false);
    n++;
    category = &crt->data.crt.category;
    FA_ASSIGN_ALL(attrs[n], CKA_CERTIFICATE_CATEGORY, &category, &category_len,
                  false, false);
    n++;
    FA_ASSIGN_ALL(attrs[n], CKA_SUBJECT, &subject, &subject_len, true, true);
    n++;
    FA_ASSIGN_ALL(attrs[n], CKA_ID, &id, &id_len, true, false);
    n++;
    FA_ASSIGN_ALL(attrs[n], CKA_ISSUER, &issuer, &issuer_len, true, false);
    n++;
    FA_ASSIGN_ALL(attrs[n], CKA_SERIAL_NUMBER, &serial, &serial_len, true,
                  false);
    n++;
    FA_ASSIGN_ALL(attrs[n], CKA_VALUE, &value, &value_len, true, false);
    n++;
    FA_ASSIGN_ALL(attrs[n], CKA_PUBLIC_KEY_INFO, &pubkey, &pubkey_len, true,
                  false);
    n++;

    ret = p11prov_fetch_attributes(ctx, session, object, attrs, n);
    if (ret != CKR_OK) {
        P11PROV_debug("Failed to query certificate attributes (%lu)", ret);
        return ret;
    }

    CKATTR_ASSIGN_ALL(crt->attrs[0], CKA_SUBJECT, subject, subject_len);
    crt->numattrs = 1;
    if (id_len > 0) {
        CKATTR_ASSIGN_ALL(crt->attrs[crt->numattrs], CKA_ID, id, id_len);
        crt->numattrs++;
    }
    if (issuer_len > 0) {
        CKATTR_ASSIGN_ALL(crt->attrs[crt->numattrs], CKA_ISSUER, issuer,
                          issuer_len);
        crt->numattrs++;
    }
    if (serial_len > 0) {
        CKATTR_ASSIGN_ALL(crt->attrs[crt->numattrs], CKA_SERIAL_NUMBER, serial,
                          serial_len);
        crt->numattrs++;
    }
    if (value_len > 0) {
        CKATTR_ASSIGN_ALL(crt->attrs[crt->numattrs], CKA_VALUE, value,
                          value_len);
        crt->numattrs++;
    }
    if (pubkey_len > 0) {
        CKATTR_ASSIGN_ALL(crt->attrs[crt->numattrs], CKA_PUBLIC_KEY_INFO,
                          pubkey, pubkey_len);
        crt->numattrs++;
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

    if (object) {
        *object = NULL;
    } else {
        return CKR_ARGUMENTS_BAD;
    }

    obj = p11prov_obj_new(ctx, p11prov_session_slotid(session), handle,
                          CK_UNAVAILABLE_INFORMATION);
    if (obj == NULL) {
        return CKR_HOST_MEMORY;
    }
    obj->handle = handle;
    obj->slotid = p11prov_session_slotid(session);

    class = &obj->class;
    FA_ASSIGN_ALL(attrs[0], CKA_CLASS, &class, &class_len, false, true);

    obj->data.key.type = CK_UNAVAILABLE_INFORMATION;
    key_type = &obj->data.key.type;
    FA_ASSIGN_ALL(attrs[1], CKA_KEY_TYPE, &key_type, &key_type_len, false,
                  false);

    ret = p11prov_fetch_attributes(ctx, session, handle, attrs, 2);
    if (ret != CKR_OK) {
        P11PROV_debug("Failed to query object attributes (%lu)", ret);
        p11prov_obj_free(obj);
        return ret;
    }

    switch (obj->class) {
    case CKO_CERTIFICATE:
        ret = fetch_certificate(ctx, session, handle, obj);
        if (ret != CKR_OK) {
            p11prov_obj_free(obj);
            return ret;
        }
        break;

    case CKO_PUBLIC_KEY:
    case CKO_PRIVATE_KEY:
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
                CKATTR_ASSIGN_ALL(obj->attrs[obj->numattrs],
                                  CKA_ALLOWED_MECHANISMS, value, value_len);
                obj->numattrs++;
            } else if (ret == CKR_ATTRIBUTE_TYPE_INVALID) {
                token_supports_allowed_mechs = CK_FALSE;
                (void)p11prov_token_sup_attr(ctx, obj->slotid, SET_ATTR,
                                             CKA_ALLOWED_MECHANISMS,
                                             &token_supports_allowed_mechs);
            }
        }
        break;

    default:
        if (obj->class & CKO_VENDOR_DEFINED) {
            P11PROV_debug("Vendor defined object %ld", obj->class);
        } else {
            P11PROV_debug("Unknown object class %ld", obj->class);
        }
        p11prov_obj_free(obj);
        return CKR_CANCEL;
    }

    *object = obj;
    return CKR_OK;
}

#define OBJS_PER_SEARCH 64
#define MAX_OBJS_IN_STORE OBJS_PER_SEARCH * 16 /* 1024 */
CK_RV p11prov_obj_find(P11PROV_CTX *provctx, P11PROV_SESSION *session,
                       CK_SLOT_ID slotid, P11PROV_URI *uri,
                       store_obj_callback cb, void *cb_ctx)
{
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS class = p11prov_uri_get_class(uri);
    CK_ATTRIBUTE id = p11prov_uri_get_id(uri);
    CK_ATTRIBUTE label = p11prov_uri_get_label(uri);
    CK_ATTRIBUTE template[3] = { 0 };
    CK_OBJECT_HANDLE *objects = NULL;
    CK_ULONG tsize = 0;
    CK_ULONG objcount = 0;
    CK_ULONG total = 0;
    CK_RV result = CKR_GENERAL_ERROR;
    CK_RV ret;

    P11PROV_debug("Find objects [class=%lu, id-len=%lu, label=%s]", class,
                  id.ulValueLen,
                  label.type == CKA_LABEL ? (char *)label.pValue : "None");

    switch (class) {
    case CKO_CERTIFICATE:
    case CKO_PUBLIC_KEY:
    case CKO_PRIVATE_KEY:
        CKATTR_ASSIGN_ALL(template[tsize], CKA_CLASS, &class, sizeof(class));
        tsize++;
        break;
    case CK_UNAVAILABLE_INFORMATION:
        break;
    default:
        /* nothing to find for us */
        return CKR_OK;
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

    ret = p11prov_FindObjectsInit(provctx, sess, template, tsize);
    if (ret != CKR_OK) {
        return ret;
    }
    do {
        CK_OBJECT_HANDLE *tmp;

        objcount = 0;
        tmp = OPENSSL_realloc(objects, (total + OBJS_PER_SEARCH)
                                           * sizeof(CK_OBJECT_HANDLE));
        if (tmp == NULL) {
            OPENSSL_free(objects);
            (void)p11prov_FindObjectsFinal(provctx, sess);
            return CKR_HOST_MEMORY;
        }
        objects = tmp;

        ret = p11prov_FindObjects(provctx, sess, &objects[total],
                                  OBJS_PER_SEARCH, &objcount);
        if (ret != CKR_OK || objcount == 0) {
            result = ret;
            break;
        }
        total += objcount;
    } while (total < MAX_OBJS_IN_STORE);

    if (objcount != 0 && total >= MAX_OBJS_IN_STORE) {
        P11PROV_debug("Too many objects in store, results truncated to %d",
                      MAX_OBJS_IN_STORE);
    }

    ret = p11prov_FindObjectsFinal(provctx, sess);
    if (ret != CKR_OK) {
        /* this is not fatal */
        P11PROV_raise(provctx, ret, "Failed to terminate object search");
    }

    for (CK_ULONG k = 0; k < total; k++) {
        P11PROV_OBJ *obj = NULL;
        ret = p11prov_obj_from_handle(provctx, session, objects[k], &obj);
        if (ret == CKR_CANCEL) {
            /* unknown object or other recoverable error to ignore */
            continue;
        } else if (ret == CKR_OK) {
            ret = cb(cb_ctx, obj);
        }
        if (ret != CKR_OK) {
            P11PROV_raise(provctx, ret, "Failed to store object");
            result = ret;
            break;
        }
    }

    P11PROV_debug("Find objects: found %lu objects", total);
    OPENSSL_free(objects);
    return result;
}

static P11PROV_OBJ *find_associated_obj(P11PROV_CTX *provctx, P11PROV_OBJ *obj,
                                        CK_OBJECT_CLASS class)
{
    CK_ATTRIBUTE template[2] = { 0 };
    CK_ATTRIBUTE *id;
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SESSION *session = NULL;
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE handle;
    CK_ULONG objcount = 0;
    P11PROV_OBJ *retobj = NULL;
    CK_RV ret, fret;

    P11PROV_debug("Find associated object");

    id = p11prov_obj_get_attr(obj, CKA_ID);
    if (!id) {
        P11PROV_raise(provctx, CKR_GENERAL_ERROR, "No CKA_ID in source object");
        goto done;
    }

    CKATTR_ASSIGN_ALL(template[0], CKA_CLASS, &class, sizeof(class));
    template[1] = *id;

    slotid = p11prov_obj_get_slotid(obj);

    ret = p11prov_get_session(provctx, &slotid, NULL, NULL,
                              CK_UNAVAILABLE_INFORMATION, NULL, NULL, false,
                              false, &session);
    if (ret != CKR_OK) {
        goto done;
    }

    sess = p11prov_session_handle(session);

    ret = p11prov_FindObjectsInit(provctx, sess, template, 2);
    if (ret != CKR_OK) {
        goto done;
    }

    /* we expect a single entry */
    ret = p11prov_FindObjects(provctx, sess, &handle, 1, &objcount);

    fret = p11prov_FindObjectsFinal(provctx, sess);
    if (fret != CKR_OK) {
        /* this is not fatal */
        P11PROV_raise(provctx, fret, "Failed to terminate object search");
    }

    if (ret != CKR_OK) {
        goto done;
    }
    if (objcount != 1) {
        P11PROV_raise(provctx, ret, "Error in C_FindObjects (count=%ld)",
                      objcount);
        goto done;
    }

    ret = p11prov_obj_from_handle(provctx, session, handle, &retobj);
    if (ret != CKR_OK) {
        P11PROV_raise(provctx, ret, "Failed to get object from handle");
    }

done:
    p11prov_session_free(session);
    return retobj;
}

P11PROV_OBJ *p11prov_create_secret_key(P11PROV_CTX *provctx,
                                       P11PROV_SESSION *session,
                                       bool session_key, unsigned char *secret,
                                       size_t secretlen)
{
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

    ret = p11prov_GetSessionInfo(provctx, sess, &session_info);
    if (ret != CKR_OK) {
        return NULL;
    }
    if (((session_info.flags & CKF_RW_SESSION) == 0) && val_token == CK_TRUE) {
        P11PROV_debug("Invalid read only session for token key request");
        return NULL;
    }

    ret = p11prov_CreateObject(provctx, sess, key_template, 5, &key_handle);
    if (ret != CKR_OK) {
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
    CK_RV ret;

again:
    if (!s) {
        ret =
            p11prov_get_session(ctx, &slotid, NULL, NULL, mechanism->mechanism,
                                NULL, NULL, false, false, &s);
        if (ret != CKR_OK) {
            P11PROV_raise(ctx, ret, "Failed to open session on slot %lu",
                          slotid);
            return ret;
        }
    }

    ret = p11prov_DeriveKey(ctx, p11prov_session_handle(s), mechanism, handle,
                            template, nattrs, key);
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
        return ret;
    }
}

CK_RV p11prov_obj_set_attributes(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                                 P11PROV_OBJ *obj, CK_ATTRIBUTE *template,
                                 CK_ULONG tsize)
{
    P11PROV_SESSION *s = session;
    CK_SLOT_ID slotid = obj->slotid;
    CK_RV ret;

    if (!s) {
        ret = p11prov_get_session(ctx, &slotid, NULL, NULL,
                                  CK_UNAVAILABLE_INFORMATION, NULL, NULL, false,
                                  true, &s);
        if (ret != CKR_OK) {
            P11PROV_raise(ctx, ret, "Failed to open session on slot %lu",
                          slotid);
            return ret;
        }
    }

    ret = p11prov_SetAttributeValue(ctx, p11prov_session_handle(s), obj->handle,
                                    template, tsize);

    /* TODO: should we retry iterating value by value on each element of
     * template to be able to set as much as we can and return which attribute
     * exactly the token is refusing ? */

    if (s != session) {
        p11prov_session_free(s);
    }
    return ret;
}

static CK_RV get_all_from_cert(P11PROV_OBJ *crt, CK_ATTRIBUTE *attrs, int num)
{
    CK_ATTRIBUTE *type;
    CK_ATTRIBUTE *value;
    const unsigned char *val;
    X509 *x509 = NULL;
    EVP_PKEY *pkey;
    CK_RV rv;

    /* if CKA_CERTIFICATE_TYPE is not present assume CKC_X_509 */
    type = p11prov_obj_get_attr(crt, CKA_CERTIFICATE_TYPE);
    if (type) {
        CK_CERTIFICATE_TYPE crt_type = CKC_X_509;
        if (type->ulValueLen != sizeof(CK_CERTIFICATE_TYPE)
            || memcmp(type->pValue, &crt_type, type->ulValueLen) != 0) {
            return CKR_OBJECT_HANDLE_INVALID;
        }
    }

    value = p11prov_obj_get_attr(crt, CKA_VALUE);
    if (!value) {
        return CKR_GENERAL_ERROR;
    }

    val = value->pValue;
    x509 = d2i_X509(NULL, &val, value->ulValueLen);
    if (!x509) {
        return CKR_GENERAL_ERROR;
    }

    pkey = X509_get0_pubkey(x509);
    if (!pkey) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    if (EVP_PKEY_is_a(pkey, "RSA")) {
        OSSL_PARAM params[3];
        int ret;

        params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0);
        params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0);
        params[2] = OSSL_PARAM_construct_end();

        ret = EVP_PKEY_get_params(pkey, params);
        if (ret != RET_OSSL_OK) {
            rv = CKR_GENERAL_ERROR;
            goto done;
        }
        ret = OSSL_PARAM_modified(params);
        if (ret != RET_OSSL_OK) {
            rv = CKR_GENERAL_ERROR;
            goto done;
        }
        if (params[0].return_size == 0 || params[1].return_size == 0) {
            rv = CKR_GENERAL_ERROR;
            goto done;
        }
        params[0].data = OPENSSL_zalloc(params[0].return_size);
        params[1].data = OPENSSL_zalloc(params[1].return_size);
        if (!params[0].data || !params[1].data) {
            OPENSSL_free(params[0].data);
            OPENSSL_free(params[1].data);
            rv = CKR_HOST_MEMORY;
            goto done;
        }
        params[0].data_size = params[0].return_size;
        params[1].data_size = params[1].return_size;
        params[0].return_size = OSSL_PARAM_UNMODIFIED;
        params[1].return_size = OSSL_PARAM_UNMODIFIED;

        ret = EVP_PKEY_get_params(pkey, params);
        if (ret != RET_OSSL_OK) {
            OPENSSL_free(params[0].data);
            OPENSSL_free(params[1].data);
            rv = CKR_GENERAL_ERROR;
            goto done;
        }
        ret = OSSL_PARAM_modified(params);
        if (ret != RET_OSSL_OK) {
            OPENSSL_free(params[0].data);
            OPENSSL_free(params[1].data);
            rv = CKR_GENERAL_ERROR;
            goto done;
        }

        for (int i = 0; i < num; i++) {
            switch (attrs[i].type) {
            case CKA_MODULUS:
                attrs[i].pValue = params[0].data;
                attrs[i].ulValueLen = params[0].data_size;
                params[0].data = NULL;
                break;
            case CKA_PUBLIC_EXPONENT:
                attrs[i].pValue = params[1].data;
                attrs[i].ulValueLen = params[1].data_size;
                params[1].data = NULL;
                break;
            default:
                OPENSSL_free(params[0].data);
                OPENSSL_free(params[1].data);
                rv = CKR_ARGUMENTS_BAD;
                goto done;
            }
        }
        /* just in case caller didn't fetch all */
        OPENSSL_free(params[0].data);
        OPENSSL_free(params[1].data);

        rv = CKR_OK;
    } else if (EVP_PKEY_is_a(pkey, "EC")) {
        ASN1_OCTET_STRING ec_point_asn1 = { .type = V_ASN1_OCTET_STRING };
        unsigned char *ec_point = NULL;
        int ec_point_len;
        unsigned char *ec_params = NULL;
        int ec_params_len;

        ec_point_asn1.length = i2d_PublicKey(pkey, &ec_point_asn1.data);
        if (ec_point_asn1.length < 0) {
            rv = CKR_GENERAL_ERROR;
            goto done;
        }

        /* need to encode to keep p11prov_obj_export_public_ec_key() simple */
        ec_point_len = i2d_ASN1_OCTET_STRING(&ec_point_asn1, &ec_point);
        if (ec_point_len < 0) {
            OPENSSL_free(ec_point_asn1.data);
            rv = CKR_GENERAL_ERROR;
            goto done;
        }
        OPENSSL_free(ec_point_asn1.data);

        ec_params_len = i2d_KeyParams(pkey, &ec_params);
        if (ec_params_len < 0) {
            OPENSSL_free(ec_point);
            rv = CKR_GENERAL_ERROR;
            goto done;
        }

        for (int i = 0; i < num; i++) {
            switch (attrs[i].type) {
            case CKA_EC_POINT:
                attrs[i].pValue = ec_point;
                attrs[i].ulValueLen = ec_point_len;
                ec_point = NULL;
                break;
            case CKA_EC_PARAMS:
                attrs[i].pValue = ec_params;
                attrs[i].ulValueLen = ec_params_len;
                ec_params = NULL;
                break;
            default:
                OPENSSL_free(ec_point);
                OPENSSL_free(ec_params);
                rv = CKR_ARGUMENTS_BAD;
                goto done;
            }
        }
        /* just in case caller didn't fetch all */
        OPENSSL_free(ec_point);
        OPENSSL_free(ec_params);

        rv = CKR_OK;
    } else {
        rv = CKR_OBJECT_HANDLE_INVALID;
    }

done:
    if (rv != CKR_OK) {
        for (int i = 0; i < num; i++) {
            OPENSSL_free(attrs[i].pValue);
            attrs[i].pValue = NULL;
            attrs[i].ulValueLen = 0;
        }
    }
    X509_free(x509);
    return rv;
}

static CK_RV get_all_attrs(P11PROV_OBJ *obj, CK_ATTRIBUTE *attrs, int num)
{
    CK_ATTRIBUTE *res[num];
    CK_RV rv;

    for (int i = 0; i < num; i++) {
        res[i] = p11prov_obj_get_attr(obj, attrs[i].type);
        if (!res[i]) {
            return CKR_CANCEL;
        }
    }

    for (int i = 0; i < num; i++) {
        rv = p11prov_copy_attr(&attrs[i], res[i]);
        if (rv != CKR_OK) {
            for (i--; i >= 0; i--) {
                OPENSSL_free(attrs[i].pValue);
                attrs[i].ulValueLen = 0;
                attrs[i].pValue = NULL;
            }
            return rv;
        }
    }
    return CKR_OK;
}

static CK_RV get_public_attrs(P11PROV_OBJ *obj, CK_ATTRIBUTE *attrs, int num)
{
    P11PROV_OBJ *tmp = NULL;
    CK_RV rv;

    /* we couldn't get all of them, start fallback logic */
    switch (obj->class) {
    case CKO_PUBLIC_KEY:
        return get_all_attrs(obj, attrs, num);
    case CKO_PRIVATE_KEY:
        rv = get_all_attrs(obj, attrs, num);
        if (rv == CKR_OK) {
            return rv;
        }
        /* public attributes unavailable, try to find public key */
        tmp = find_associated_obj(obj->ctx, obj, CKO_PUBLIC_KEY);
        if (tmp) {
            rv = get_all_attrs(tmp, attrs, num);
            p11prov_obj_free(tmp);
            return rv;
        }
        /* no public key, try to find certificate */
        tmp = find_associated_obj(obj->ctx, obj, CKO_CERTIFICATE);
        if (tmp) {
            rv = get_all_from_cert(tmp, attrs, num);
            p11prov_obj_free(tmp);
            return rv;
        }
        break;
    case CKO_CERTIFICATE:
        return get_all_from_cert(obj, attrs, num);
    default:
        break;
    }

    return CKR_CANCEL;
}

/* Tokens return data in bigendian order, while openssl
 * wants it in host order, so we may need to fix the
 * endianness of the buffer.
 * Src and Dest, can be the same area, but not partially
 * overlapping memory areas */

#define RSA_PUB_ATTRS 2
int p11prov_obj_export_public_rsa_key(P11PROV_OBJ *obj, OSSL_CALLBACK *cb_fn,
                                      void *cb_arg)
{
    CK_ATTRIBUTE attrs[RSA_PUB_ATTRS] = { 0 };
    OSSL_PARAM params[RSA_PUB_ATTRS + 1];
    CK_RV rv;
    int ret;

    if (p11prov_obj_get_key_type(obj) != CKK_RSA) {
        return RET_OSSL_ERR;
    }

    attrs[0].type = CKA_MODULUS;
    attrs[1].type = CKA_PUBLIC_EXPONENT;

    rv = get_public_attrs(obj, attrs, RSA_PUB_ATTRS);
    if (rv != CKR_OK) {
        P11PROV_raise(obj->ctx, rv, "Failed to get public key attributes");
        return RET_OSSL_ERR;
    }

    byteswap_buf(attrs[0].pValue, attrs[0].pValue, attrs[0].ulValueLen);
    params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, attrs[0].pValue,
                                        attrs[0].ulValueLen);
    byteswap_buf(attrs[1].pValue, attrs[1].pValue, attrs[1].ulValueLen);
    params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, attrs[1].pValue,
                                        attrs[1].ulValueLen);
    params[RSA_PUB_ATTRS] = OSSL_PARAM_construct_end();

    ret = cb_fn(params, cb_arg);

    for (int i = 0; i < RSA_PUB_ATTRS; i++) {
        OPENSSL_free(attrs[i].pValue);
    }
    return ret;
}

#define EC_PUB_ATTRS 2
int p11prov_obj_export_public_ec_key(P11PROV_OBJ *obj, OSSL_CALLBACK *cb_fn,
                                     void *cb_arg)
{
    CK_ATTRIBUTE attrs[EC_PUB_ATTRS] = { 0 };
    OSSL_PARAM params[EC_PUB_ATTRS + 1];
    ASN1_OCTET_STRING *octet = NULL;
    EC_GROUP *group = NULL;
    const unsigned char *val;
    const char *curve_name;
    int curve_nid;
    CK_RV rv;
    int ret;

    if (p11prov_obj_get_key_type(obj) != CKK_EC) {
        return RET_OSSL_ERR;
    }

    attrs[0].type = CKA_EC_PARAMS;
    attrs[1].type = CKA_EC_POINT;

    rv = get_public_attrs(obj, attrs, EC_PUB_ATTRS);
    if (rv != CKR_OK) {
        P11PROV_raise(obj->ctx, rv, "Failed to get public key attributes");
        return RET_OSSL_ERR;
    }

    /* in d2i functions 'in' is overwritten to return the remainder of the
     * buffer after parsing, so we always need to avoid passing in our pointer
     * folders, to avoid having them clobbered */
    val = attrs[0].pValue;
    group = d2i_ECPKParameters(NULL, (const unsigned char **)&val,
                               attrs[0].ulValueLen);
    if (group == NULL) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    curve_nid = EC_GROUP_get_curve_name(group);
    if (curve_nid == NID_undef) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    curve_name = OSSL_EC_curve_nid2name(curve_nid);
    if (curve_name == NULL) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)curve_name, 0);

    val = attrs[1].pValue;
    octet = d2i_ASN1_OCTET_STRING(NULL, (const unsigned char **)&val,
                                  attrs[1].ulValueLen);
    if (octet == NULL) {
        return RET_OSSL_ERR;
    }
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  octet->data, octet->length);

    params[EC_PUB_ATTRS] = OSSL_PARAM_construct_end();

    ret = cb_fn(params, cb_arg);

done:
    /* must be freed after callback */
    for (int i = 0; i < EC_PUB_ATTRS; i++) {
        OPENSSL_free(attrs[i].pValue);
    }
    ASN1_OCTET_STRING_free(octet);
    EC_GROUP_free(group);
    return ret;
}
