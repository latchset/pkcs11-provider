/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "obj/internal.h"

const struct fetch_attrs RSA_public_attrs[] = {
    { { CKA_MODULUS, NULL, 0 }, true, true },
    { { CKA_PUBLIC_EXPONENT, NULL, 0 }, true, true },
    { { CKA_ID, NULL, 0 }, true, false },
    { { CKA_LABEL, NULL, 0 }, true, false },
};

const struct fetch_attrs RSA_private_attrs[] = {
    { { CKA_MODULUS, NULL, 0 }, true, true },
    /* not required on private keys because some tokens don't store it */
    { { CKA_PUBLIC_EXPONENT, NULL, 0 }, true, false },
    { { CKA_ID, NULL, 0 }, true, false },
    { { CKA_LABEL, NULL, 0 }, true, false },
    { { CKA_ALWAYS_AUTHENTICATE, NULL, 0 }, true, false },
};

const struct fetch_attrs EC_public_attrs[] = {
    { { CKA_EC_PARAMS, NULL, 0 }, true, true },
    { { CKA_EC_POINT, NULL, 0 }, true, true },
    { { CKA_ID, NULL, 0 }, true, false },
    { { CKA_LABEL, NULL, 0 }, true, false },
};

const struct fetch_attrs EC_private_attrs[] = {
    { { CKA_EC_PARAMS, NULL, 0 }, true, true },
    /* known vendor optimization to avoid storing
     * EC public key on HSM is to store EC_POINT on the private
     * one similarly to how RSA stores CKA_PUBLIC_EXPONENT, it is
     * out of spec but avoids p11prov_obj_find_associated later */
    { { CKA_EC_POINT, NULL, 0 }, true, false },
    { { CKA_ID, NULL, 0 }, true, false },
    { { CKA_LABEL, NULL, 0 }, true, false },
    { { CKA_ALWAYS_AUTHENTICATE, NULL, 0 }, true, false },
};

#define EC_EDWARDS_public_attrs EC_public_attrs
#define EC_EDWARDS_private_attrs EC_private_attrs

/* pre_process_ec_key_data() may add:
 * - CKA_P11PROV_CURVE_NID
 * - CKA_P11PROV_CURVE_NAME
 * - CKA_P11PROV_PUB_KEY */
#define EXTRA_EC_PARAMS 3

const struct fetch_attrs ML_DSA_public_attrs[] = {
    { { CKA_VALUE, NULL, 0 }, true, true },
    { { CKA_ID, NULL, 0 }, true, false },
    { { CKA_LABEL, NULL, 0 }, true, false },
};

const struct fetch_attrs ML_DSA_private_attrs[] = {
    { { CKA_ID, NULL, 0 }, true, false },
    { { CKA_LABEL, NULL, 0 }, true, false },
    { { CKA_ALWAYS_AUTHENTICATE, NULL, 0 }, true, false },
};

#define ML_KEM_public_attrs ML_DSA_public_attrs
#define ML_KEM_private_attrs ML_DSA_private_attrs

const struct fetch_attrs secret_key_attrs[] = {
    { { CKA_ID, NULL, 0 }, true, false },
    { { CKA_LABEL, NULL, 0 }, true, false },
    { { CKA_ALWAYS_AUTHENTICATE, NULL, 0 }, true, false },
    { { CKA_SENSITIVE, NULL, 0 }, true, false },
    { { CKA_EXTRACTABLE, NULL, 0 }, true, false },
    { { CKA_VALUE_LEN, NULL, 0 }, true, false },
};
#define SKATTRS sizeof(secret_key_attrs) / sizeof(struct fetch_attrs)

#define MAX_ATTRS_NUM 6

#define FILL_ATTRS(name, alloc) \
    { CKO_PUBLIC_KEY, CKK_##name, name##_public_attrs, \
      sizeof(name##_public_attrs) / sizeof(struct fetch_attrs), alloc }, \
    { \
        CKO_PRIVATE_KEY, CKK_##name, name##_private_attrs, \
            sizeof(name##_private_attrs) / sizeof(struct fetch_attrs), alloc \
    }

#define FILL_SECRET(name, alloc) \
    { CKO_SECRET_KEY, CKK_##name, secret_key_attrs, \
      sizeof(secret_key_attrs) / sizeof(struct fetch_attrs), alloc }
#define FILL_KNOWN_SECRETS(alloc) \
    FILL_SECRET(GENERIC_SECRET, alloc), FILL_SECRET(AES, alloc), \
        FILL_SECRET(SHA_1_HMAC, alloc), FILL_SECRET(SHA224_HMAC, alloc), \
        FILL_SECRET(SHA256_HMAC, alloc), FILL_SECRET(SHA384_HMAC, alloc), \
        FILL_SECRET(SHA512_HMAC, alloc), FILL_SECRET(SHA512_224_HMAC, alloc), \
        FILL_SECRET(SHA512_256_HMAC, alloc), \
        FILL_SECRET(SHA3_224_HMAC, alloc), FILL_SECRET(SHA3_256_HMAC, alloc), \
        FILL_SECRET(SHA3_384_HMAC, alloc), FILL_SECRET(SHA3_512_HMAC, alloc)

/* for each key type always alloc an extra attr to hold CKA_ALLOWED_MECHANISMS
 * some key type also have additional space requirements */
const struct key_attrs {
    CK_OBJECT_CLASS class;
    CK_KEY_TYPE type;
    const struct fetch_attrs *attrs;
    int num_attrs;
    int extra_alloc;
} key_attrs_list[] = {
    FILL_ATTRS(RSA, 1),
    /* EC keys require 3 extra allocations for synthetic attributes */
    FILL_ATTRS(EC, 1 + EXTRA_EC_PARAMS),
    FILL_ATTRS(EC_EDWARDS, 1 + EXTRA_EC_PARAMS),
    FILL_ATTRS(ML_DSA, 1),
    FILL_ATTRS(ML_KEM, 1),
    FILL_KNOWN_SECRETS(1),
    { 0, 0, NULL, 0, 0 },
};

static CK_RV prep_key_attrs(CK_OBJECT_CLASS class, CK_KEY_TYPE type,
                            struct fetch_attrs *dst, int *dst_size,
                            int *key_attrs_alloc)
{
    const struct key_attrs *item = NULL;

    for (int i = 0; key_attrs_list[i].num_attrs != 0; i++) {
        if (key_attrs_list[i].class == class
            && key_attrs_list[i].type == type) {
            item = &key_attrs_list[i];
            break;
        }
    }

    if (!item || item->num_attrs > *dst_size) {
        return CKR_GENERAL_ERROR;
    }

    for (int i = 0; i < item->num_attrs; i++) {
        dst[i] = item->attrs[i];
    }

    *dst_size = item->num_attrs;
    *key_attrs_alloc = item->num_attrs + item->extra_alloc;
    return CKR_OK;
}

static CK_RV pre_process_ec_key_data(P11PROV_OBJ *key);

static CK_RV fetch_key(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                       CK_OBJECT_HANDLE handle, P11PROV_OBJ *key)
{
    struct fetch_attrs attrs[MAX_ATTRS_NUM] = { 0 };
    int asize = sizeof(attrs) / sizeof(struct fetch_attrs);
    int alloc = 0;
    CK_ATTRIBUTE *a;
    CK_RV rv;

    rv = prep_key_attrs(key->class, key->data.key.type, attrs, &asize, &alloc);
    if (rv != CKR_OK) {
        P11PROV_debug("Unsupported key type (%lu)", key->data.key.type);
        return rv;
    }

    key->attrs = OPENSSL_zalloc(alloc * sizeof(CK_ATTRIBUTE));
    if (!key->attrs) {
        return CKR_HOST_MEMORY;
    }
    key->numattrs = 0;

    rv = p11prov_fetch_attributes(ctx, session, handle, attrs, asize);
    if (rv != CKR_OK) {
        /* free any allocated memory */
        p11prov_fetch_attrs_free(attrs, asize);
        return rv;
    }
    p11prov_move_alloc_attrs(attrs, asize, key->attrs, &key->numattrs);

    /* key->data.key.type is checked for validity in prep_key_attrs(),
     * here it is just a selector defaulting to secret keys */
    switch (key->data.key.type) {
    case CKK_RSA:
        a = p11prov_obj_get_attr(key, CKA_MODULUS);
        if (!a) {
            P11PROV_raise(key->ctx, CKR_GENERAL_ERROR, "Missing Modulus");
            return CKR_GENERAL_ERROR;
        }
        key->data.key.size = a->ulValueLen;
        key->data.key.bit_size = key->data.key.size * 8;
        return CKR_OK;
    case CKK_EC:
    case CKK_EC_EDWARDS:
        /* decode CKA_EC_PARAMS and store some extra attrs for convenience */
        return pre_process_ec_key_data(key);
    case CKK_ML_DSA:
        switch (key->data.key.param_set) {
        case CKP_ML_DSA_44:
            key->data.key.size = ML_DSA_44_PK_SIZE;
            break;
        case CKP_ML_DSA_65:
            key->data.key.size = ML_DSA_65_PK_SIZE;
            break;
        case CKP_ML_DSA_87:
            key->data.key.size = ML_DSA_87_PK_SIZE;
            break;
        default:
            return CKR_KEY_INDIGESTIBLE;
        }
        key->data.key.bit_size = key->data.key.size * 8;
        return CKR_OK;
    case CKK_ML_KEM:
        switch (key->data.key.param_set) {
        case CKP_ML_KEM_512:
            key->data.key.size = ML_KEM_512_PK_SIZE;
            break;
        case CKP_ML_KEM_768:
            key->data.key.size = ML_KEM_768_PK_SIZE;
            break;
        case CKP_ML_KEM_1024:
            key->data.key.size = ML_KEM_1024_PK_SIZE;
            break;
        default:
            return CKR_KEY_INDIGESTIBLE;
        }
        key->data.key.bit_size = key->data.key.size * 8;
        return CKR_OK;
    default:
        /* CKO_SECRET_KEY types */
        a = p11prov_obj_get_attr(key, CKA_VALUE_LEN);
        if (!a) {
            /* Not all tokens support this attributes, it's ok */
            P11PROV_debug("Failed to query key attribute CKA_VALUE_LEN");
        } else {
            if (a->ulValueLen != sizeof(CK_ULONG)) {
                P11PROV_raise(key->ctx, CKR_GENERAL_ERROR,
                              "Unsupported Key Size format");
                return CKR_GENERAL_ERROR;
            }
            key->data.key.size = *(CK_ULONG *)a->pValue;
            key->data.key.bit_size = key->data.key.size * 8;
        }
        return CKR_OK;
    }

    return CKR_GENERAL_ERROR;
}

const CK_BYTE ed25519_ec_params[] = { ED25519_EC_PARAMS };
const CK_BYTE ed448_ec_params[] = { ED448_EC_PARAMS };

static CK_RV pre_process_ec_key_data(P11PROV_OBJ *key)
{
    CK_ATTRIBUTE *attr;
    CK_KEY_TYPE type;
    const unsigned char *val;
    CK_BYTE *buffer;
    int buffer_size;
    const char *curve_name = NULL;
    int curve_nid;
    struct data_buffer ec_point = { 0 };
    CK_RV ret;

    attr = p11prov_obj_get_attr(key, CKA_EC_PARAMS);
    if (!attr) {
        key->data.key.bit_size = CK_UNAVAILABLE_INFORMATION;
        key->data.key.size = CK_UNAVAILABLE_INFORMATION;
        return CKR_KEY_INDIGESTIBLE;
    }

    type = p11prov_obj_get_key_type(key);
    if (type == CKK_EC) {
        EC_GROUP *group = NULL;
        /* in d2i functions 'in' is overwritten to return the remainder of
         * the buffer after parsing, so we always need to avoid passing in
         * our pointer holders, to avoid having them clobbered */
        val = attr->pValue;
        group = d2i_ECPKParameters(NULL, &val, attr->ulValueLen);
        if (group == NULL) {
            return CKR_KEY_INDIGESTIBLE;
        }

        curve_nid = EC_GROUP_get_curve_name(group);
        if (curve_nid != NID_undef) {
            curve_name = OSSL_EC_curve_nid2name(curve_nid);
            if (curve_name == NULL) {
                EC_GROUP_free(group);
                return CKR_KEY_INDIGESTIBLE;
            }
        }
        key->data.key.bit_size = EC_GROUP_order_bits(group);
        key->data.key.size = (key->data.key.bit_size + 7) / 8;
        EC_GROUP_free(group);
    } else if (type == CKK_EC_EDWARDS) {
        if (attr->ulValueLen == ED25519_EC_PARAMS_LEN
            && memcmp(attr->pValue, ed25519_ec_params, ED25519_EC_PARAMS_LEN)
                   == 0) {
            curve_name = ED25519;
            curve_nid = NID_ED25519;
            key->data.key.bit_size = ED25519_BIT_SIZE;
            key->data.key.size = ED25519_BYTE_SIZE;
        } else if (attr->ulValueLen == ED448_EC_PARAMS_LEN
                   && memcmp(attr->pValue, ed448_ec_params, ED448_EC_PARAMS_LEN)
                          == 0) {
            curve_name = ED448;
            curve_nid = NID_ED448;
            key->data.key.bit_size = ED448_BIT_SIZE;
            key->data.key.size = ED448_BYTE_SIZE;
        } else {
            const unsigned char *p = attr->pValue;
            ASN1_OBJECT *asn1_obj = d2i_ASN1_OBJECT(NULL, &p, attr->ulValueLen);
            if (asn1_obj == NULL) {
                return CKR_KEY_INDIGESTIBLE;
            }
            int nid = OBJ_obj2nid(asn1_obj);
            ASN1_OBJECT_free(asn1_obj);
            if (nid == NID_ED25519) {
                curve_name = ED25519;
                curve_nid = NID_ED25519;
                key->data.key.bit_size = ED25519_BIT_SIZE;
                key->data.key.size = ED25519_BYTE_SIZE;
            } else if (nid == NID_ED448) {
                curve_name = ED448;
                curve_nid = NID_ED448;
                key->data.key.bit_size = ED448_BIT_SIZE;
                key->data.key.size = ED448_BYTE_SIZE;
            } else {
                return CKR_KEY_INDIGESTIBLE;
            }
        }
    } else {
        return CKR_KEY_INDIGESTIBLE;
    }
    buffer_size = sizeof(curve_nid);
    buffer = OPENSSL_zalloc(buffer_size);
    if (!buffer) {
        return CKR_HOST_MEMORY;
    }
    memcpy(buffer, &curve_nid, buffer_size);
    CKATTR_ASSIGN(key->attrs[key->numattrs], CKA_P11PROV_CURVE_NID, buffer,
                  buffer_size);
    key->numattrs++;

    if (curve_name != NULL) {
        buffer_size = strlen(curve_name) + 1;
        buffer = (CK_BYTE *)OPENSSL_strdup(curve_name);
        if (!buffer) {
            return CKR_HOST_MEMORY;
        }
        CKATTR_ASSIGN(key->attrs[key->numattrs], CKA_P11PROV_CURVE_NAME, buffer,
                      buffer_size);
        key->numattrs++;
    }

    attr = p11prov_obj_get_attr(key, CKA_EC_POINT);
    if (!attr) {
        /* not available on private keys, so not fatal if absent */
        return CKR_OK;
    }

    ret = decode_ec_point(type, attr, &ec_point);
    if (ret != CKR_OK) {
        return ret;
    }

    /* takes the data allocated in ec_point */
    CKATTR_ASSIGN(key->attrs[key->numattrs], CKA_P11PROV_PUB_KEY, ec_point.data,
                  ec_point.length);
    key->numattrs++;
    return CKR_OK;
}

#define CERT_ATTRS_NUM 9
static CK_RV fetch_certificate(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                               CK_OBJECT_HANDLE object, P11PROV_OBJ *crt)
{
    struct fetch_attrs attrs[CERT_ATTRS_NUM];
    int num;
    CK_RV ret;

    crt->attrs = OPENSSL_zalloc(CERT_ATTRS_NUM * sizeof(CK_ATTRIBUTE));
    if (crt->attrs == NULL) {
        P11PROV_raise(ctx, CKR_HOST_MEMORY, "failed to allocate cert attrs");
        return CKR_HOST_MEMORY;
    }

    num = 0;
    FA_SET_VAR_VAL(attrs, num, CKA_CERTIFICATE_TYPE, crt->data.crt.type, true);
    FA_SET_VAR_VAL(attrs, num, CKA_TRUSTED, crt->data.crt.trusted, false);
    FA_SET_VAR_VAL(attrs, num, CKA_CERTIFICATE_CATEGORY, crt->data.crt.category,
                   false);
    FA_SET_BUF_ALLOC(attrs, num, CKA_SUBJECT, true);
    FA_SET_BUF_ALLOC(attrs, num, CKA_ID, false);
    FA_SET_BUF_ALLOC(attrs, num, CKA_ISSUER, false);
    FA_SET_BUF_ALLOC(attrs, num, CKA_SERIAL_NUMBER, false);
    FA_SET_BUF_ALLOC(attrs, num, CKA_VALUE, false);
    FA_SET_BUF_ALLOC(attrs, num, CKA_PUBLIC_KEY_INFO, false);

    ret = p11prov_fetch_attributes(ctx, session, object, attrs, num);
    if (ret != CKR_OK) {
        P11PROV_debug("Failed to query certificate attributes (%lu)", ret);
        p11prov_fetch_attrs_free(attrs, num);
        return ret;
    }

    crt->numattrs = 0;
    p11prov_move_alloc_attrs(attrs, num, crt->attrs, &crt->numattrs);

    return CKR_OK;
}

/* TODO: may want to have a hashmap with cached objects */
CK_RV p11prov_obj_from_handle(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                              CK_OBJECT_HANDLE handle, P11PROV_OBJ **object)
{
    P11PROV_OBJ *obj;
    struct fetch_attrs attrs[5];
    int num;
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
    obj->data.key.type = CK_UNAVAILABLE_INFORMATION;

    num = 0;
    FA_SET_VAR_VAL(attrs, num, CKA_CLASS, obj->class, true);
    FA_SET_VAR_VAL(attrs, num, CKA_KEY_TYPE, obj->data.key.type, false);
    FA_SET_VAR_VAL(attrs, num, CKA_COPYABLE, obj->cka_copyable, false);
    FA_SET_VAR_VAL(attrs, num, CKA_TOKEN, obj->cka_token, false);
    FA_SET_VAR_VAL(attrs, num, CKA_PARAMETER_SET, obj->data.key.param_set,
                   false);

    ret = p11prov_fetch_attributes(ctx, session, handle, attrs, num);
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
    case CKO_SECRET_KEY:
        ret = fetch_key(ctx, session, handle, obj);
        if (ret != CKR_OK) {
            p11prov_obj_free(obj);
            return ret;
        }

        /* do this at the end as it often won't be a supported attribute */
        ret = p11prov_token_sup_attr(ctx, obj->slotid, GET_ATTR,
                                     CKA_ALLOWED_MECHANISMS,
                                     &token_supports_allowed_mechs);
        if (ret != CKR_OK) {
            P11PROV_raise(ctx, ret, "Failed to probe quirk");
        } else if (token_supports_allowed_mechs == CK_TRUE) {
            struct fetch_attrs a[1];
            CK_ULONG an = 0;
            FA_SET_BUF_ALLOC(a, an, CKA_ALLOWED_MECHANISMS, false);
            ret = p11prov_fetch_attributes(ctx, session, handle, a, 1);
            if (ret == CKR_OK) {
                obj->attrs[obj->numattrs] = a[0].attr;
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
    case CKO_SECRET_KEY:
        CKATTR_ASSIGN(template[tsize], CKA_CLASS, &class, sizeof(class));
        tsize++;
        break;
    case CK_UNAVAILABLE_INFORMATION:
        break;
    default:
        /* nothing to find for us */
        return CKR_OK;
    }
    if (id.ulValueLen != 0) {
        template[tsize] = id;
        tsize++;
    }
    if (label.ulValueLen != 0) {
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
            /* keep a copy of the URI for refreshes as it may contain
             * things like a PIN necessary to log in */
            obj->refresh_uri = p11prov_copy_uri(uri);
            ret = cb(cb_ctx, obj);
        }
        if (ret != CKR_OK) {
            P11PROV_raise(provctx, ret, "Failed to store object");
            result = ret;
            break;
        }
    }

    P11PROV_debug("Find objects: found %lu objects; Returning %lx", total,
                  result);
    OPENSSL_free(objects);
    return result;
}

P11PROV_OBJ *p11prov_obj_find_associated(P11PROV_OBJ *obj,
                                         CK_OBJECT_CLASS class)
{
    CK_ATTRIBUTE template[2] = { 0 };
    CK_ATTRIBUTE *id;
    P11PROV_SESSION *session = NULL;
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE handle;
    CK_ULONG objcount = 0;
    P11PROV_OBJ *retobj = NULL;
    CK_RV ret, fret;

    P11PROV_debug("Find associated object");

    /* check if we have one already */
    retobj = p11prov_obj_get_associated(obj);
    if (retobj) {
        if (p11prov_obj_get_class(retobj) == class) {
            /* BINGO */
            return p11prov_obj_ref_no_cache(retobj);
        } else {
            retobj = NULL;
        }
    }

    id = p11prov_obj_get_attr(obj, CKA_ID);
    if (!id || id->ulValueLen == 0) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR,
                      "No CKA_ID in source object");
        goto done;
    }

    CKATTR_ASSIGN(template[0], CKA_CLASS, &class, sizeof(class));
    template[1] = *id;

    ret = p11prov_try_session_ref(obj, CK_UNAVAILABLE_INFORMATION, false, false,
                                  &session);
    if (ret != CKR_OK) {
        goto done;
    }

    sess = p11prov_session_handle(session);

    ret = p11prov_FindObjectsInit(obj->ctx, sess, template, 2);
    if (ret != CKR_OK) {
        goto done;
    }

    /* we expect a single entry */
    ret = p11prov_FindObjects(obj->ctx, sess, &handle, 1, &objcount);

    fret = p11prov_FindObjectsFinal(obj->ctx, sess);
    if (fret != CKR_OK) {
        /* this is not fatal */
        P11PROV_raise(obj->ctx, fret, "Failed to terminate object search");
    }

    if (ret != CKR_OK) {
        goto done;
    }
    if (objcount != 1) {
        P11PROV_raise(obj->ctx, ret, "Error in C_FindObjects (count=%ld)",
                      objcount);
        goto done;
    }

    ret = p11prov_obj_from_handle(obj->ctx, session, handle, &retobj);
    if (ret != CKR_OK) {
        P11PROV_raise(obj->ctx, ret, "Failed to get object from handle");
    }

    /* associate it so we do not have to search again on repeat calls */
    if (retobj && obj->assoc_obj == NULL) {
        obj->assoc_obj = p11prov_obj_ref_no_cache(retobj);
    }

done:
    p11prov_return_session(session);
    return retobj;
}

/* creates an empty (no public point) Public EC Key, (OpenSSL paramgen
 * function), that will later be filled in with a public EC key obtained
 * by a peer (generally for ECDH, but we don't have that context in the
 * code) */
P11PROV_OBJ *mock_pub_ec_key(P11PROV_CTX *ctx, CK_ATTRIBUTE_TYPE type,
                             CK_ATTRIBUTE *ec_params)
{
    P11PROV_OBJ *key;
    CK_RV ret;

    key =
        p11prov_obj_new(ctx, CK_UNAVAILABLE_INFORMATION,
                        CK_P11PROV_IMPORTED_HANDLE, CK_UNAVAILABLE_INFORMATION);
    if (!key) {
        return NULL;
    }

    key->class = CKO_PUBLIC_KEY;
    key->data.key.type = type;

    /* at this stage we have EC_PARAMS and the preprocessing
     * function will add CKA_P11PROV_CURVE_NID and
     * CKA_P11PROV_CURVE_NAME */
    key->attrs = OPENSSL_zalloc(EXTRA_EC_PARAMS * sizeof(CK_ATTRIBUTE));
    if (key->attrs == NULL) {
        P11PROV_raise(key->ctx, CKR_HOST_MEMORY,
                      "Failed to generate mock ec key");
        p11prov_obj_free(key);
        return NULL;
    }

    ret = p11prov_copy_attr(&key->attrs[0], ec_params);
    if (ret != CKR_OK) {
        P11PROV_raise(key->ctx, ret, "Failed to copy mock key attribute");
        p11prov_obj_free(key);
        return NULL;
    }
    key->numattrs++;

    /* verify params are ok */
    ret = pre_process_ec_key_data(key);
    if (ret != CKR_OK) {
        P11PROV_raise(key->ctx, ret, "Failed to process mock key data");
        p11prov_obj_free(key);
        return NULL;
    }

    return key;
}
