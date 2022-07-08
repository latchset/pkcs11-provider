/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

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

    CK_ULONG max_size;

    CK_ATTRIBUTE *attrs;
    unsigned long numattrs;

    int refcnt;
};

static P11PROV_KEY *p11prov_key_new(void)
{
    P11PROV_KEY *key;

    key = OPENSSL_zalloc(sizeof(P11PROV_KEY));
    if (!key) return NULL;

    key->refcnt = 1;

    return key;
}

P11PROV_KEY *p11prov_key_ref(P11PROV_KEY *key)
{
    if (key &&
        __atomic_fetch_add(&key->refcnt, 1, __ATOMIC_ACQ_REL) > 0) {
        return key;
    }

    return NULL;
}

void p11prov_key_free(P11PROV_KEY *key)
{
    p11prov_debug("key free (%p)\n", key);

    if (key == NULL) return;
    if (__atomic_sub_fetch(&key->refcnt, 1, __ATOMIC_ACQ_REL) != 0) {
        p11prov_debug("key free: reference held\n");
        return;
    }

    OPENSSL_free(key->id);
    OPENSSL_free(key->label);

    for (int i = 0; i < key->numattrs; i++) {
        OPENSSL_free(key->attrs[i].pValue);
    }
    OPENSSL_free(key->attrs);

    OPENSSL_clear_free(key, sizeof(P11PROV_KEY));
}

CK_ATTRIBUTE *p11prov_key_attr(P11PROV_KEY *key, CK_ATTRIBUTE_TYPE type)
{
    if (!key) return NULL;

    for (int i = 0; i < key->numattrs; i++) {
        if (key->attrs[i].type == type) {
            return &key->attrs[i];
        }
    }

    return NULL;
}

CK_KEY_TYPE p11prov_key_type(P11PROV_KEY *key)
{
    if (key) return key->type;
    return CK_UNAVAILABLE_INFORMATION;
}

CK_SLOT_ID p11prov_key_slotid(P11PROV_KEY *key)
{
    if (key) return key->slotid;
    return CK_UNAVAILABLE_INFORMATION;
}

CK_OBJECT_HANDLE p11prov_key_handle(P11PROV_KEY *key)
{
    if (key) return key->handle;
    return CK_INVALID_HANDLE;
}

CK_ULONG p11prov_key_sig_size(P11PROV_KEY *key)
{
    if (key == NULL) return CK_UNAVAILABLE_INFORMATION;
    return key->max_size;
}

struct fetch_attrs {
    CK_ATTRIBUTE_TYPE type;
    unsigned char **value;
    unsigned long *value_len;
    bool allocate;
    bool required;
};
#define FA_ASSIGN_ALL(x, _a, _b, _c, _d, _e) \
    do { \
        x.type = _a; \
        x.value = (unsigned char **)_b; \
        x.value_len = _c; \
        x.allocate = _d; \
        x.required = _e; \
    } while(0)

#define FA_RETURN_VAL(x, _a, _b) \
    do { \
        *x.value = _a; \
        *x.value_len = _b; \
    } while(0)

#define FA_RETURN_LEN(x, _a) *x.value_len = _a

#define CKATTR_ASSIGN_ALL(x, _a, _b, _c) \
    do { \
        x.type = _a; \
        x.pValue = (void *)_b; \
        x.ulValueLen = _c; \
    } while(0)

static int object_fetch_attributes(CK_FUNCTION_LIST *f,
                                   CK_SESSION_HANDLE session,
                                   CK_OBJECT_HANDLE object,
                                   struct fetch_attrs *attrs,
                                   unsigned long attrnums)
{
    CK_ATTRIBUTE q[attrnums];
    CK_ATTRIBUTE r[attrnums];
    int ret;

    for (int i = 0; i < attrnums; i++) {
        if (attrs[i].allocate) {
            CKATTR_ASSIGN_ALL(q[i], attrs[i].type, NULL, 0);
        } else {
            CKATTR_ASSIGN_ALL(q[i], attrs[i].type,
                              *attrs[i].value,
                              *attrs[i].value_len);
        }
    }

    /* try one shot, then fallback to individual calls if that fails */
    ret = f->C_GetAttributeValue(session, object, q, attrnums);
    if (ret == CKR_OK) {
        unsigned long retrnums = 0;
        for (int i = 0; i < attrnums; i++) {
            if (q[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                if (attrs[i].required) {
                    return -ENOENT;
                }
                FA_RETURN_LEN(attrs[i], 0);
                continue;
            }
            if (attrs[i].allocate) {
                /* allways allocate and zero one more, so that
                 * zero terminated strings work automatically */
                char *a = OPENSSL_zalloc(q[i].ulValueLen + 1);
                if (a == NULL) return -ENOMEM;
                FA_RETURN_VAL(attrs[i], a, q[i].ulValueLen);

                CKATTR_ASSIGN_ALL(r[retrnums], attrs[i].type,
                                  *attrs[i].value,
                                  *attrs[i].value_len);
                retrnums++;
            } else {
                FA_RETURN_LEN(attrs[i], q[i].ulValueLen);
            }
        }
        if (retrnums > 0) {
            ret = f->C_GetAttributeValue(session, object, r, retrnums);
        }
    } else if (ret == CKR_ATTRIBUTE_SENSITIVE ||
               ret == CKR_ATTRIBUTE_TYPE_INVALID) {
        p11prov_debug("Quering attributes one by one\n");
        /* go one by one as this PKCS11 does not have some attributes
         * and does not handle it gracefully */
        for (int i = 0; i < attrnums; i++) {
            if (attrs[i].allocate) {
                CKATTR_ASSIGN_ALL(q[0], attrs[i].type, NULL, 0);
                ret = f->C_GetAttributeValue(session, object, q, 1);
                if (ret != CKR_OK) {
                    if (attrs[i].required) return ret;
                } else {
                    char *a = OPENSSL_zalloc(q[0].ulValueLen + 1);
                    if (a == NULL) return -ENOMEM;
                    FA_RETURN_VAL(attrs[i], a, q[0].ulValueLen);
                }
            }
            CKATTR_ASSIGN_ALL(r[0], attrs[i].type,
                              *attrs[i].value,
                              *attrs[i].value_len);
            ret = f->C_GetAttributeValue(session, object, r, 1);
            if (ret != CKR_OK) {
                if (r[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                    FA_RETURN_LEN(attrs[i], 0);
                }
                if (attrs[i].required) return ret;
            }
            p11prov_debug("Attribute| type:%lu value:%p, len:%lu\n",
                          attrs[i].type, *attrs[i].value, *attrs[i].value_len);
        }
        ret = CKR_OK;
    }
    return ret;
}

static int fetch_rsa_key(CK_FUNCTION_LIST *f,
                         CK_OBJECT_CLASS class,
                         CK_SESSION_HANDLE session,
                         CK_OBJECT_HANDLE object,
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
        ret = object_fetch_attributes(f, session, object, attrs, 2);
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

        key->max_size = n_len;
        key->attrs = OPENSSL_zalloc(2 * sizeof(CK_ATTRIBUTE));
        CKATTR_ASSIGN_ALL(key->attrs[0], CKA_MODULUS, n, n_len);
        CKATTR_ASSIGN_ALL(key->attrs[1], CKA_PUBLIC_EXPONENT, e, e_len);
        key->numattrs = 2;
        return CKR_OK;
    }
    return CKR_ARGUMENTS_BAD;
}

static int fetch_ec_public_key(CK_FUNCTION_LIST *f,
                               CK_SESSION_HANDLE session,
                               CK_OBJECT_HANDLE object,
                               P11PROV_KEY *key)
{
    struct fetch_attrs attrs[2];
    unsigned long params_len = 0, point_len = 0;
    CK_BYTE *params = NULL, *point = NULL;
    size_t n_bytes;
    int ret;

    FA_ASSIGN_ALL(attrs[0], CKA_EC_PARAMS,
                  &params, &params_len, true, true);
    FA_ASSIGN_ALL(attrs[1], CKA_EC_POINT,
                  &point, &point_len, true, true);
    ret = object_fetch_attributes(f, session, object, attrs, 2);
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

    key->max_size = 2 * n_bytes;
    key->attrs = OPENSSL_zalloc(2 * sizeof(CK_ATTRIBUTE));
    CKATTR_ASSIGN_ALL(key->attrs[0], CKA_EC_PARAMS, params, params_len);
    CKATTR_ASSIGN_ALL(key->attrs[1], CKA_EC_POINT, point, point_len);
    key->numattrs = 2;
    return CKR_OK;
}

/* TODO: may want to have a hashmap with cached keys */
static P11PROV_KEY *object_handle_to_key(CK_FUNCTION_LIST *f,
                                         CK_SLOT_ID slotid,
                                         CK_OBJECT_CLASS class,
                                         CK_SESSION_HANDLE session,
                                         CK_OBJECT_HANDLE object)
{
    P11PROV_KEY *key;
    unsigned long *key_type;
    unsigned long key_type_len = sizeof(CKA_KEY_TYPE);
    unsigned long label_len;
    struct fetch_attrs attrs[3];
    unsigned long aa_len = 0;
    int ret;

    key = p11prov_key_new();
    if (key == NULL) return NULL;

    key_type = &key->type;
    FA_ASSIGN_ALL(attrs[0], CKA_KEY_TYPE,
                  &key_type, &key_type_len, false, true);
    FA_ASSIGN_ALL(attrs[1], CKA_ID,
                  &key->id, &key->id_len, true, false);
    FA_ASSIGN_ALL(attrs[2], CKA_LABEL,
                  &key->label, &label_len, true, false);
    /* TODO: fetch also other attributes as specified in
     * Spev v3 - 4.9 Private key objects  ?? */

    ret = object_fetch_attributes(f, session, object, attrs, 3);
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

int find_keys(PROVIDER_CTX *provctx,
              P11PROV_KEY **priv, P11PROV_KEY **pub,
              CK_SLOT_ID slotid, CK_OBJECT_CLASS class,
              const unsigned char *id, size_t id_len,
              const char *label)
{
    CK_FUNCTION_LIST *f = provider_ctx_fns(provctx);
    CK_SESSION_HANDLE session;
    CK_ATTRIBUTE template[3] = {
        { CKA_CLASS, &class, sizeof(class) },
    };
    CK_ULONG tsize = 1;
    CK_ULONG objcount;
    P11PROV_KEY *key = NULL;
    int result = CKR_GENERAL_ERROR;
    int ret;

    if (f == NULL) return result;

    ret = f->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (ret != CKR_OK) {
        p11prov_debug("OpenSession failed %d\n", ret);
        /* TODO: Err message */
        return ret;
    }

    if (id_len) {
        CKATTR_ASSIGN_ALL(template[tsize], CKA_ID,
                          id, id_len);
        tsize++;
    }
    if (label) {
        CKATTR_ASSIGN_ALL(template[tsize], CKA_LABEL,
                          label, strlen(label));
        tsize++;
    }

again:
    ret = f->C_FindObjectsInit(session, template, tsize);
    if (ret == CKR_OK) {
        do {
            CK_OBJECT_HANDLE object;
            /* TODO: pull multiple objects at once to reduce roundtrips */
            ret = f->C_FindObjects(session, &object, 1, &objcount);
            if (ret != CKR_OK || objcount == 0) break;

            key = object_handle_to_key(f, slotid, class, session, object);

            /* we'll get the first that parses fine */
            if (key) {
                result = CKR_OK;
                if (class == CKO_PRIVATE_KEY) {
                    *priv = key;
                    (void)f->C_FindObjectsFinal(session);
                    class = CKO_PUBLIC_KEY;
                    goto again;
                }
                if (key) {
                    *pub = key;
                }
                break;
            }

        } while (objcount > 0);

        (void)f->C_FindObjectsFinal(session);
    }

    if (ret != CKR_OK) {
        /* TODO: Err message */
        p11prov_debug("Failed to search keys\n");
    }

    ret = f->C_CloseSession(session);
    if (ret != CKR_OK) {
        p11prov_debug("Failed to close session\n");
    }

    return result;
}
