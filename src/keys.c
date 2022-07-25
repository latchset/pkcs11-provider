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
    if (key && __atomic_fetch_add(&key->refcnt, 1, __ATOMIC_ACQ_REL) > 0) {
        return key;
    }

    return NULL;
}

void p11prov_key_free(P11PROV_KEY *key)
{
    p11prov_debug("key free (%p)\n", key);

    if (key == NULL) {
        return;
    }
    if (__atomic_sub_fetch(&key->refcnt, 1, __ATOMIC_ACQ_REL) != 0) {
        p11prov_debug("key free: reference held\n");
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

static int fetch_rsa_key(CK_FUNCTION_LIST *f, CK_OBJECT_CLASS class,
                         CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                         P11PROV_KEY *key)
{
    struct fetch_attrs attrs[2];
    unsigned long n_len = 0, e_len = 0;
    CK_BYTE *n = NULL, *e = NULL;
    int ret;

    switch (class) {
    case CKO_PRIVATE_KEY:
        /* fallthrough */
    case CKO_PUBLIC_KEY:
        FA_ASSIGN_ALL(attrs[0], CKA_MODULUS, &n, &n_len, true, true);
        FA_ASSIGN_ALL(attrs[1], CKA_PUBLIC_EXPONENT, &e, &e_len, true, true);
        ret = p11prov_fetch_attributes(f, session, object, attrs, 2);
        if (ret != CKR_OK) {
            /* free any allocated memory */
            OPENSSL_free(n);
            OPENSSL_free(e);

            if (class == CKO_PRIVATE_KEY) {
                /* A private key may not always return these */
                return CKR_OK;
            }
            return ret;
        }

        key->key_size = n_len;
        key->attrs = OPENSSL_zalloc(2 * sizeof(CK_ATTRIBUTE));
        CKATTR_ASSIGN_ALL(key->attrs[0], CKA_MODULUS, n, n_len);
        CKATTR_ASSIGN_ALL(key->attrs[1], CKA_PUBLIC_EXPONENT, e, e_len);
        key->numattrs = 2;
        return CKR_OK;
    }
    return CKR_ARGUMENTS_BAD;
}

static int fetch_ec_public_key(CK_FUNCTION_LIST *f, CK_SESSION_HANDLE session,
                               CK_OBJECT_HANDLE object, P11PROV_KEY *key)
{
    struct fetch_attrs attrs[2];
    unsigned long params_len = 0, point_len = 0;
    CK_BYTE *params = NULL, *point = NULL;
    size_t n_bytes = 0;
    int ret;

    FA_ASSIGN_ALL(attrs[0], CKA_EC_PARAMS, &params, &params_len, true, true);
    FA_ASSIGN_ALL(attrs[1], CKA_EC_POINT, &point, &point_len, true, true);
    ret = p11prov_fetch_attributes(f, session, object, attrs, 2);
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
    key->attrs = OPENSSL_zalloc(2 * sizeof(CK_ATTRIBUTE));
    CKATTR_ASSIGN_ALL(key->attrs[0], CKA_EC_PARAMS, params, params_len);
    CKATTR_ASSIGN_ALL(key->attrs[1], CKA_EC_POINT, point, point_len);
    key->numattrs = 2;
    return CKR_OK;
}

/* TODO: may want to have a hashmap with cached keys */
static P11PROV_KEY *object_handle_to_key(CK_FUNCTION_LIST *f, CK_SLOT_ID slotid,
                                         CK_OBJECT_CLASS class,
                                         CK_SESSION_HANDLE session,
                                         CK_OBJECT_HANDLE object)
{
    P11PROV_KEY *key;
    unsigned long *key_type;
    unsigned long key_type_len = sizeof(CKA_KEY_TYPE);
    unsigned long label_len;
    struct fetch_attrs attrs[3];
    int ret;

    key = p11prov_key_new();
    if (key == NULL) {
        return NULL;
    }

    key_type = &key->type;
    FA_ASSIGN_ALL(attrs[0], CKA_KEY_TYPE, &key_type, &key_type_len, false,
                  true);
    FA_ASSIGN_ALL(attrs[1], CKA_ID, &key->id, &key->id_len, true, false);
    FA_ASSIGN_ALL(attrs[2], CKA_LABEL, &key->label, &label_len, true, false);
    /* TODO: fetch also other attributes as specified in
     * Spev v3 - 4.9 Private key objects  ?? */

    ret = p11prov_fetch_attributes(f, session, object, attrs, 3);
    if (ret != CKR_OK) {
        p11prov_debug("Failed to query object attributes (%d)\n", ret);
        p11prov_key_free(key);
        return NULL;
    }

    key->slotid = slotid;
    key->handle = object;
    key->class = class;

    switch (key->type) {
    case CKK_RSA:
        ret = fetch_rsa_key(f, class, session, object, key);
        if (ret != CKR_OK) {
            p11prov_key_free(key);
            return NULL;
        }
        break;
    case CKK_EC:
        if (class == CKO_PRIVATE_KEY) {
            /* no params to fetch */
            break;
        }
        ret = fetch_ec_public_key(f, session, object, key);
        if (ret != CKR_OK) {
            p11prov_key_free(key);
            return NULL;
        }
        break;
    default:
        /* unknown key type, we can't handle it */
        p11prov_debug("Unsupported key type (%d)\n", key->type);
        p11prov_key_free(key);
        return NULL;
    }

    return key;
}

int find_keys(P11PROV_CTX *provctx, P11PROV_KEY **priv, P11PROV_KEY **pub,
              CK_SLOT_ID slotid, CK_OBJECT_CLASS class, const unsigned char *id,
              size_t id_len, const char *label)
{
    CK_FUNCTION_LIST *f = p11prov_ctx_fns(provctx);
    CK_SESSION_HANDLE session;
    CK_ATTRIBUTE template[3] = {
        { CKA_CLASS, &class, sizeof(class) },
    };
    CK_ULONG tsize = 1;
    CK_ULONG objcount;
    P11PROV_KEY *privkey = NULL;
    P11PROV_KEY *key = NULL;
    int result = CKR_GENERAL_ERROR;
    int ret;

    p11prov_debug("Find keys\n");

    if (f == NULL) {
        return result;
    }

    ret = f->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (ret != CKR_OK) {
        P11PROV_raise(provctx, ret, "Failed to open session on slot %lu",
                      slotid);
        return ret;
    }

    if (id_len) {
        CKATTR_ASSIGN_ALL(template[tsize], CKA_ID, id, id_len);
        tsize++;
    }
    if (label) {
        CKATTR_ASSIGN_ALL(template[tsize], CKA_LABEL, label, strlen(label));
        tsize++;
    }

again:
    ret = f->C_FindObjectsInit(session, template, tsize);
    if (ret == CKR_OK) {
        do {
            CK_OBJECT_HANDLE object;
            /* TODO: pull multiple objects at once to reduce roundtrips */
            ret = f->C_FindObjects(session, &object, 1, &objcount);
            if (ret != CKR_OK || objcount == 0) {
                break;
            }

            key = object_handle_to_key(f, slotid, class, session, object);

            /* we'll get the first that parses fine */
            if (key) {
                result = CKR_OK;
                if (class == CKO_PRIVATE_KEY) {
                    *priv = privkey = key;
                    ret = f->C_FindObjectsFinal(session);
                    if (ret != CKR_OK) {
                        P11PROV_raise(provctx, ret,
                                      "Failed to terminate object search");
                    }
                    class = CKO_PUBLIC_KEY;
                    goto again;
                }
                if (key) {
                    /* it is not always possible to pull all (or any)
                     * attributes from private keys, so fixup key_size
                     * based on the public key if it is missing. */
                    if (privkey && privkey->key_size == 0) {
                        privkey->key_size = key->key_size;
                    }
                    *pub = key;
                }
                break;
            }

        } while (objcount > 0);

        ret = f->C_FindObjectsFinal(session);
        if (ret != CKR_OK) {
            P11PROV_raise(provctx, ret, "Failed to terminate object search");
        }
    } else {
        P11PROV_raise(provctx, ret, "Error returned by C_FindObjectsInit");
    }

    ret = f->C_CloseSession(session);
    if (ret != CKR_OK) {
        P11PROV_raise(provctx, ret, "Failed to close session %lu", session);
    }

    return result;
}

P11PROV_KEY *p11prov_create_secret_key(P11PROV_CTX *provctx,
                                       CK_SESSION_HANDLE session,
                                       bool session_key, unsigned char *secret,
                                       size_t secretlen)
{
    CK_FUNCTION_LIST *f;
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

    p11prov_debug("keys: create secret key (session:%lu secret:%p[%zu])\n",
                  session, secret, secretlen);

    f = p11prov_ctx_fns(provctx);
    if (f == NULL) {
        return NULL;
    }

    ret = f->C_GetSessionInfo(session, &session_info);
    if (ret != CKR_OK) {
        P11PROV_raise(provctx, ret, "Error returned by C_GetSessionInfo");
        return NULL;
    }
    if (((session_info.flags & CKF_RW_SESSION) == 0) && val_token == CK_TRUE) {
        p11prov_debug("Invalid read only session for token key request\n");
        return NULL;
    }

    ret = f->C_CreateObject(session, key_template, 5, &key_handle);
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
    ret = p11prov_fetch_attributes(f, session, key_handle, attrs, 2);
    if (ret != CKR_OK) {
        p11prov_debug("Failed to query object attributes (%d)\n", ret);
    }

    if (ret != CKR_OK) {
        p11prov_key_free(key);
        key = NULL;
    }
    return key;
}
