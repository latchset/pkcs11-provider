/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/obj_mac.h>
#include "platform/endian.h"

#define CKA_P11PROV_CURVE_NAME CKA_P11PROV_BASE + 1
#define CKA_P11PROV_CURVE_NID CKA_P11PROV_BASE + 2
#define CKA_P11PROV_PUB_KEY CKA_P11PROV_BASE + 3

struct p11prov_key {
    CK_KEY_TYPE type;
    CK_BBOOL always_auth;
    CK_ULONG bit_size;
    CK_ULONG size;
};

struct p11prov_crt {
    CK_CERTIFICATE_TYPE type;
    CK_CERTIFICATE_CATEGORY category;
    CK_BBOOL trusted;
};

struct p11prov_obj {
    P11PROV_CTX *ctx;
    bool raf; /* re-init after fork */

    CK_SLOT_ID slotid;
    CK_OBJECT_HANDLE handle;
    CK_OBJECT_CLASS class;
    CK_OBJECT_HANDLE cached;
    CK_BBOOL cka_copyable;
    CK_BBOOL cka_token;

    union {
        struct p11prov_key key;
        struct p11prov_crt crt;
    } data;

    CK_ATTRIBUTE *attrs;
    int numattrs;

    int refcnt;
    int poolid;
};

struct p11prov_obj_pool {
    P11PROV_CTX *provctx;
    CK_SLOT_ID slotid;

    P11PROV_OBJ **objects;
    int size;
    int num;
    int first_free;

    pthread_mutex_t lock;
};

CK_RV p11prov_obj_pool_init(P11PROV_CTX *ctx, CK_SLOT_ID id,
                            P11PROV_OBJ_POOL **_pool)
{
    P11PROV_OBJ_POOL *pool;
    int ret;

    P11PROV_debug("Creating new object pool");

    pool = OPENSSL_zalloc(sizeof(P11PROV_OBJ_POOL));
    if (!pool) {
        return CKR_HOST_MEMORY;
    }
    pool->provctx = ctx;
    pool->slotid = id;

    ret = MUTEX_INIT(pool);
    if (ret != CKR_OK) {
        OPENSSL_free(pool);
        return ret;
    }

    P11PROV_debug("New object pool %p created", pool);

    *_pool = pool;
    return CKR_OK;
}

void p11prov_obj_pool_free(P11PROV_OBJ_POOL *pool)
{
    P11PROV_debug("Freeing object pool %p", pool);

    if (!pool) {
        return;
    }

    if (MUTEX_LOCK(pool) == CKR_OK) {
        /* LOCKED SECTION ------------- */
        if (pool->num != 0) {
            P11PROV_debug("%d objects still in pool", pool->num);
        }
        OPENSSL_free(pool->objects);
        (void)MUTEX_UNLOCK(pool);
        /* ------------- LOCKED SECTION */ }
    else {
        P11PROV_debug("Failed to lock object pool, leaking it!");
        return;
    }

    (void)MUTEX_DESTROY(pool);
    OPENSSL_clear_free(pool, sizeof(P11PROV_OBJ_POOL));
}

void p11prov_obj_pool_fork_reset(P11PROV_OBJ_POOL *pool)
{
    P11PROV_debug("Resetting objects in pool %p", pool);

    if (!pool) {
        return;
    }

    if (MUTEX_LOCK(pool) == CKR_OK) {
        /* LOCKED SECTION ------------- */
        for (int i = 0; i < pool->size; i++) {
            P11PROV_OBJ *obj = pool->objects[i];

            if (!obj) {
                continue;
            }
            obj->raf = true;
            obj->handle = CK_INVALID_HANDLE;
            obj->cached = CK_INVALID_HANDLE;
        }

        (void)MUTEX_UNLOCK(pool);
        /* ------------- LOCKED SECTION */
    } else {
        P11PROV_debug("Failed to reset objects in pool");
    }
}

#define POOL_ALLOC_SIZE 32
#define POOL_MAX_SIZE (POOL_ALLOC_SIZE * (1 << 16))
static CK_RV obj_add_to_pool(P11PROV_OBJ *obj)
{
    P11PROV_OBJ_POOL *pool;
    CK_RV ret;

    ret = p11prov_slot_get_obj_pool(obj->ctx, obj->slotid, &pool);
    if (ret != CKR_OK) {
        return ret;
    }

    ret = MUTEX_LOCK(pool);
    if (ret != CKR_OK) {
        return ret;
    }

    /* LOCKED SECTION ------------- */
    if (pool->num >= pool->size) {
        P11PROV_OBJ **tmp;

        if (pool->size >= POOL_MAX_SIZE) {
            ret = CKR_HOST_MEMORY;
            P11PROV_raise(pool->provctx, ret, "Too many objects in pool");
            goto done;
        }
        tmp = OPENSSL_realloc(pool->objects, (pool->size + POOL_ALLOC_SIZE)
                                                 * sizeof(P11PROV_OBJ *));
        if (tmp == NULL) {
            ret = CKR_HOST_MEMORY;
            P11PROV_raise(pool->provctx, ret,
                          "Failed to re-allocate objects array");
            goto done;
        }
        memset(&tmp[pool->size], 0, POOL_ALLOC_SIZE * sizeof(P11PROV_OBJ *));
        pool->objects = tmp;
        pool->size += POOL_ALLOC_SIZE;
    }

    if (pool->first_free >= pool->size) {
        pool->first_free = 0;
    }

    for (int i = 0; i < pool->size; i++) {
        int idx = (i + pool->first_free) % pool->size;
        if (pool->objects[idx] == NULL) {
            pool->objects[idx] = obj;
            pool->num++;
            obj->poolid = idx;
            pool->first_free = idx + 1;
            ret = CKR_OK;
            goto done;
        }
    }

    /* if we couldn't find a free pool spot at this point,
     * something clearly went wrong, bail out */
    ret = CKR_GENERAL_ERROR;
    P11PROV_raise(pool->provctx, ret, "Objects pool in inconsistent state");

done:
    (void)MUTEX_UNLOCK(pool);
    /* ------------- LOCKED SECTION */

    return ret;
}

static void obj_rm_from_pool(P11PROV_OBJ *obj)
{
    P11PROV_OBJ_POOL *pool;
    CK_RV ret;

    ret = p11prov_slot_get_obj_pool(obj->ctx, obj->slotid, &pool);
    if (ret != CKR_OK) {
        return;
    }

    ret = MUTEX_LOCK(pool);
    if (ret != CKR_OK) {
        return;
    }

    /* LOCKED SECTION ------------- */
    if (obj->poolid > pool->size || pool->objects[obj->poolid] != obj) {
        ret = CKR_GENERAL_ERROR;
        P11PROV_raise(pool->provctx, ret, "Objects pool in inconsistent state");
        goto done;
    }

    pool->objects[obj->poolid] = NULL;
    pool->num--;
    if (pool->first_free > obj->poolid) {
        pool->first_free = obj->poolid;
    }
    obj->poolid = 0;

done:
    (void)MUTEX_UNLOCK(pool);
    /* ------------- LOCKED SECTION */
}

P11PROV_OBJ *p11prov_obj_new(P11PROV_CTX *ctx, CK_SLOT_ID slotid,
                             CK_OBJECT_HANDLE handle, CK_OBJECT_CLASS class)
{
    P11PROV_OBJ *obj;
    CK_RV ret;

    obj = OPENSSL_zalloc(sizeof(P11PROV_OBJ));
    if (obj == NULL) {
        return NULL;
    }
    obj->ctx = ctx;
    obj->slotid = slotid;
    obj->handle = handle;
    obj->class = class;
    obj->cached = CK_INVALID_HANDLE;

    obj->refcnt = 1;

    ret = obj_add_to_pool(obj);
    if (ret != CKR_OK) {
        OPENSSL_free(obj);
        obj = NULL;
    }
    return obj;
}

static void destroy_key_cache(P11PROV_OBJ *obj, P11PROV_SESSION *session)

{
    P11PROV_SESSION *_session = NULL;
    CK_SESSION_HANDLE sess;
    CK_RV ret;

    if (obj->cached == CK_INVALID_HANDLE) {
        return;
    }

    if (session) {
        sess = p11prov_session_handle(session);
    } else {
        ret = p11prov_take_login_session(obj->ctx, obj->slotid, &_session);
        if (ret != CKR_OK) {
            P11PROV_debug("Failed to get login session. Error %lx", ret);
            return;
        }
        sess = p11prov_session_handle(_session);
    }

    ret = p11prov_DestroyObject(obj->ctx, sess, obj->cached);
    if (ret != CKR_OK) {
        P11PROV_debug("Failed to destroy cached key. Error %lx", ret);
    }
    obj->cached = CK_INVALID_HANDLE;

    if (_session) {
        p11prov_return_session(_session);
    }
}

static CK_RV supports_caching(P11PROV_CTX *ctx, CK_SLOT_ID id, int action,
                              CK_BBOOL *data)
{
    CK_ULONG data_size = sizeof(CK_BBOOL);
    void *data_ptr = &data;
    const char *name = "Caching Supported";

    switch (action) {
    case GET_ATTR:
        return p11prov_ctx_get_quirk(ctx, id, name, data_ptr, &data_size);
    case SET_ATTR:
        return p11prov_ctx_set_quirk(ctx, id, name, data, data_size);
    default:
        return CKR_ARGUMENTS_BAD;
    }
}

static void cache_key(P11PROV_OBJ *obj)
{
    P11PROV_SESSION *session = NULL;
    CK_BBOOL val_false = CK_FALSE;
    CK_ATTRIBUTE template[] = { { CKA_TOKEN, &val_false, sizeof(val_false) } };
    CK_SESSION_HANDLE sess;
    CK_BBOOL can_cache = CK_TRUE;
    CK_RV ret;
    int cache_keys;

    /* check whether keys should be cached at all */
    cache_keys = p11prov_ctx_cache_keys(obj->ctx);
    if (cache_keys == P11PROV_CACHE_KEYS_NEVER) {
        return;
    }

    /* We cache only keys on the token */
    if ((obj->class != CKO_PRIVATE_KEY && obj->class != CKO_PUBLIC_KEY)
        || obj->cka_token != CK_TRUE || obj->cka_copyable != TRUE) {
        return;
    }

    ret = supports_caching(obj->ctx, obj->slotid, GET_ATTR, &can_cache);
    if (ret != CKR_OK) {
        P11PROV_raise(obj->ctx, ret, "Failed to get quirk");
    }
    if (can_cache != CK_TRUE) {
        /* switch copyable so we do not try again */
        obj->cka_copyable = CK_FALSE;
        return;
    }

    ret = p11prov_take_login_session(obj->ctx, obj->slotid, &session);
    if (ret != CKR_OK) {
        P11PROV_debug("Failed to get login session. Error %lx", ret);
        return;
    }

    /* If already cached, release and re-cache */
    destroy_key_cache(obj, session);

    sess = p11prov_session_handle(session);
    ret = p11prov_CopyObject(obj->ctx, sess, p11prov_obj_get_handle(obj),
                             template, 1, &obj->cached);
    if (ret != CKR_OK) {
        P11PROV_raise(obj->ctx, ret, "Failed to cache key");
        if (ret == CKR_FUNCTION_NOT_SUPPORTED) {
            can_cache = CK_FALSE;
            ret = supports_caching(obj->ctx, obj->slotid, SET_ATTR, &can_cache);
            if (ret != CKR_OK) {
                P11PROV_raise(obj->ctx, ret, "Failed to set quirk");
            }
        }
        /* switch copyable so we do not try again */
        obj->cka_copyable = CK_FALSE;
    } else {
        P11PROV_debug("Key %lu:%lu cached as %lu:%lu", obj->slotid, obj->handle,
                      sess, obj->cached);
    }

    p11prov_return_session(session);
    return;
}

P11PROV_OBJ *p11prov_obj_ref_no_cache(P11PROV_OBJ *obj)
{
    P11PROV_debug("Ref Object: %p (handle:%lu)", obj,
                  obj ? obj->handle : CK_INVALID_HANDLE);

    if (obj && __atomic_fetch_add(&obj->refcnt, 1, __ATOMIC_SEQ_CST) > 0) {
        return obj;
    }

    return NULL;
}

P11PROV_OBJ *p11prov_obj_ref(P11PROV_OBJ *obj)
{
    obj = p11prov_obj_ref_no_cache(obj);
    if (!obj) {
        return NULL;
    }

    /* When referenced it means we are likely going to try to use the key in
     * some operation, let's try to cache it in the tokens volatile memory for
     * those tokens that support the operation. This will result in much faster
     * key operations with some tokens as the keys are unencrypted in volatile
     * memory */
    if (obj->cached == CK_INVALID_HANDLE) {
        cache_key(obj);
    }

    return obj;
}

void p11prov_obj_free(P11PROV_OBJ *obj)
{
    P11PROV_debug("Free Object: %p (handle:%lu)", obj,
                  obj ? obj->handle : CK_INVALID_HANDLE);

    if (obj == NULL) {
        return;
    }
    if (__atomic_sub_fetch(&obj->refcnt, 1, __ATOMIC_SEQ_CST) != 0) {
        P11PROV_debug("object free: reference held");
        return;
    }

    obj_rm_from_pool(obj);

    destroy_key_cache(obj, NULL);

    for (int i = 0; i < obj->numattrs; i++) {
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

static void p11prov_obj_refresh(P11PROV_OBJ *obj);

CK_OBJECT_HANDLE p11prov_obj_get_handle(P11PROV_OBJ *obj)
{
    if (obj) {
        if (obj->raf) {
            p11prov_obj_refresh(obj);
        }
        if (obj->cached != CK_INVALID_HANDLE) {
            return obj->cached;
        }
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

    for (int i = 0; i < obj->numattrs; i++) {
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

CK_ULONG p11prov_obj_get_key_bit_size(P11PROV_OBJ *obj)
{
    if (obj) {
        switch (obj->class) {
        case CKO_PRIVATE_KEY:
        case CKO_PUBLIC_KEY:
            return obj->data.key.bit_size;
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

void p11prov_obj_to_store_reference(P11PROV_OBJ *obj, void **reference,
                                    size_t *reference_sz)
{
    /* The store context keeps reference to this object so we will not free
     * it while the store context is alive. When the applications wants to
     * reference the object, it will get its own reference through
     * p11prov_common_load(). After closing the store, the user should
     * not be able to use this reference anymore. */
    *reference = obj;
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

/* CKA_ID
 * CKA_LABEL
 * CKA_ALLOWED_MECHANISMS see p11prov_obj_from_handle() */
#define BASE_KEY_ATTRS_NUM 3

#define RSA_ATTRS_NUM (BASE_KEY_ATTRS_NUM + 2)
static int fetch_rsa_key(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                         CK_OBJECT_HANDLE object, P11PROV_OBJ *key)
{
    struct fetch_attrs attrs[RSA_ATTRS_NUM];
    CK_ATTRIBUTE *mod;
    int num;
    int ret;

    key->attrs = OPENSSL_zalloc(RSA_ATTRS_NUM * sizeof(CK_ATTRIBUTE));
    if (key->attrs == NULL) {
        return CKR_HOST_MEMORY;
    }

    num = 0;
    FA_SET_BUF_ALLOC(attrs, num, CKA_MODULUS, true);
    FA_SET_BUF_ALLOC(attrs, num, CKA_PUBLIC_EXPONENT, true);
    FA_SET_BUF_ALLOC(attrs, num, CKA_ID, false);
    FA_SET_BUF_ALLOC(attrs, num, CKA_LABEL, false);
    ret = p11prov_fetch_attributes(ctx, session, object, attrs, num);
    if (ret != CKR_OK) {
        /* free any allocated memory */
        p11prov_fetch_attrs_free(attrs, num);

        if (key->class == CKO_PRIVATE_KEY) {
            /* A private key may not always return these */
            return CKR_OK;
        }
        return ret;
    }

    key->numattrs = 0;
    p11prov_move_alloc_attrs(attrs, num, key->attrs, &key->numattrs);

    mod = p11prov_obj_get_attr(key, CKA_MODULUS);
    if (!mod) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR, "Missing Modulus");
        return CKR_GENERAL_ERROR;
    }
    key->data.key.size = mod->ulValueLen;
    key->data.key.bit_size = key->data.key.size * 8;

    return CKR_OK;
}

const CK_BYTE ed25519_ec_params[] = { ED25519_EC_PARAMS };
const CK_BYTE ed448_ec_params[] = { ED448_EC_PARAMS };

#define KEY_EC_PARAMS 3
static CK_RV pre_process_ec_key_data(P11PROV_OBJ *key)
{
    CK_ATTRIBUTE *attr;
    CK_KEY_TYPE type;
    const unsigned char *val;
    CK_BYTE *buffer;
    int buffer_size;
    const char *curve_name;
    int curve_nid;
    ASN1_OCTET_STRING *octet;

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
        if (curve_nid == NID_undef) {
            EC_GROUP_free(group);
            return CKR_KEY_INDIGESTIBLE;
        }
        curve_name = OSSL_EC_curve_nid2name(curve_nid);
        if (curve_name == NULL) {
            EC_GROUP_free(group);
            return CKR_KEY_INDIGESTIBLE;
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
            return CKR_KEY_INDIGESTIBLE;
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

    buffer_size = strlen(curve_name) + 1;
    buffer = (CK_BYTE *)OPENSSL_strdup(curve_name);
    if (!buffer) {
        return CKR_HOST_MEMORY;
    }
    CKATTR_ASSIGN(key->attrs[key->numattrs], CKA_P11PROV_CURVE_NAME, buffer,
                  buffer_size);
    key->numattrs++;

    attr = p11prov_obj_get_attr(key, CKA_EC_POINT);
    if (!attr) {
        /* not available on private keys, so not fatal if absent */
        return CKR_OK;
    }

    val = attr->pValue;
    octet = d2i_ASN1_OCTET_STRING(NULL, (const unsigned char **)&val,
                                  attr->ulValueLen);
    if (!octet) {
        return CKR_KEY_INDIGESTIBLE;
    }

    CKATTR_ASSIGN(key->attrs[key->numattrs], CKA_P11PROV_PUB_KEY, octet->data,
                  octet->length);
    key->numattrs++;

    /* moved octet data to attrs, do not free it */
    octet->data = NULL;
    octet->length = 0;
    ASN1_OCTET_STRING_free(octet);
    return CKR_OK;
}

#define EC_ATTRS_NUM (BASE_KEY_ATTRS_NUM + KEY_EC_PARAMS + 2)
static CK_RV fetch_ec_key(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                          CK_OBJECT_HANDLE object, P11PROV_OBJ *key)
{
    struct fetch_attrs attrs[EC_ATTRS_NUM];
    int num;
    CK_RV ret;

    key->attrs = OPENSSL_zalloc(EC_ATTRS_NUM * sizeof(CK_ATTRIBUTE));
    if (key->attrs == NULL) {
        return CKR_HOST_MEMORY;
    }

    num = 0;
    FA_SET_BUF_ALLOC(attrs, num, CKA_EC_PARAMS, true);
    if (key->class == CKO_PUBLIC_KEY) {
        FA_SET_BUF_ALLOC(attrs, num, CKA_EC_POINT, true);
    }
    FA_SET_BUF_ALLOC(attrs, num, CKA_ID, false);
    FA_SET_BUF_ALLOC(attrs, num, CKA_LABEL, false);
    ret = p11prov_fetch_attributes(ctx, session, object, attrs, num);
    if (ret != CKR_OK) {
        /* free any allocated memory */
        p11prov_fetch_attrs_free(attrs, num);
        return CKR_KEY_INDIGESTIBLE;
    }

    key->numattrs = 0;
    p11prov_move_alloc_attrs(attrs, num, key->attrs, &key->numattrs);

    /* decode CKA_EC_PARAMS and store some extra attrs for convenience */
    ret = pre_process_ec_key_data(key);

    return ret;
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
    struct fetch_attrs attrs[4];
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
        switch (obj->data.key.type) {
        case CKK_RSA:
            ret = fetch_rsa_key(ctx, session, handle, obj);
            if (ret != CKR_OK) {
                p11prov_obj_free(obj);
                return ret;
            }
            break;
        case CKK_EC:
        case CKK_EC_EDWARDS:
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
    if (!id || id->ulValueLen == 0) {
        P11PROV_raise(provctx, CKR_GENERAL_ERROR, "No CKA_ID in source object");
        goto done;
    }

    CKATTR_ASSIGN(template[0], CKA_CLASS, &class, sizeof(class));
    template[1] = *id;

    slotid = p11prov_obj_get_slotid(obj);

    ret = p11prov_get_session(provctx, &slotid, NULL, NULL,
                              CK_UNAVAILABLE_INFORMATION, NULL, NULL, true,
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
    p11prov_return_session(session);
    return retobj;
}

static void p11prov_obj_refresh(P11PROV_OBJ *obj)
{
    P11PROV_OBJ *tmp = NULL;
    tmp = find_associated_obj(obj->ctx, obj, obj->class);
    if (!tmp) {
        /* nothing we can do, invalid handle it is */
        return;
    }

    /* move over all the object data, then free the tmp */
    obj->handle = tmp->handle;
    obj->cached = tmp->cached;
    obj->cka_copyable = tmp->cka_copyable;
    obj->cka_token = tmp->cka_token;
    switch (obj->class) {
    case CKO_CERTIFICATE:
        obj->data.crt = tmp->data.crt;
        break;
    case CKO_PUBLIC_KEY:
    case CKO_PRIVATE_KEY:
        obj->data.key = tmp->data.key;
        break;
    default:
        break;
    }
    /* FIXME: How do we refresh attrs? What happens if a pointer
     * to an attr value was saved somewhere? Freeing ->attrs would
     * cause use-after-free issues */
    p11prov_obj_free(tmp);
    obj->raf = false;
}

#define SECRET_KEY_ATTRS 2
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
    struct fetch_attrs attrs[SECRET_KEY_ATTRS];
    int num;
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

    obj->attrs = OPENSSL_zalloc(SECRET_KEY_ATTRS * sizeof(CK_ATTRIBUTE));
    if (obj->attrs == NULL) {
        P11PROV_raise(provctx, CKR_HOST_MEMORY, "Allocation failure");
        p11prov_obj_free(obj);
        return NULL;
    }

    num = 0;
    FA_SET_BUF_ALLOC(attrs, num, CKA_ID, false);
    FA_SET_BUF_ALLOC(attrs, num, CKA_LABEL, false);
    ret = p11prov_fetch_attributes(provctx, session, key_handle, attrs, num);
    if (ret == CKR_OK) {
        obj->numattrs = 0;
        p11prov_move_alloc_attrs(attrs, num, obj->attrs, &obj->numattrs);
    } else {
        P11PROV_debug("Failed to query object attributes (%lu)", ret);
        p11prov_fetch_attrs_free(attrs, num);
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
            p11prov_return_session(s);
            s = *session = NULL;
            goto again;
        }
        /* fallthrough */
    default:
        if (*session == NULL) {
            p11prov_return_session(s);
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

    ret =
        p11prov_SetAttributeValue(ctx, p11prov_session_handle(s),
                                  p11prov_obj_get_handle(obj), template, tsize);

    if (obj->cached != CK_INVALID_HANDLE) {
        /* try to re-cache key to maintain matching attributes */
        cache_key(obj);
    }

    /* TODO: should we retry iterating value by value on each element of
     * template to be able to set as much as we can and return which attribute
     * exactly the token is refusing ? */

    if (s != session) {
        p11prov_return_session(s);
    }
    return ret;
}

#define MAX_KEY_ATTRS 2
static CK_RV get_all_from_cert(P11PROV_OBJ *crt, CK_ATTRIBUTE *attrs, int num)
{
    OSSL_PARAM params[MAX_KEY_ATTRS + 1] = { 0 };
    CK_ATTRIBUTE_TYPE types[MAX_KEY_ATTRS];
    CK_ATTRIBUTE *type;
    CK_ATTRIBUTE *value;
    const unsigned char *val;
    X509 *x509 = NULL;
    EVP_PKEY *pkey;
    int attrnum = 0;
    int ret;
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
        for (int i = 0; i < num; i++) {
            switch (attrs[i].type) {
            case CKA_MODULUS:
                types[attrnum] = CKA_MODULUS;
                params[attrnum] =
                    OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0);
                attrnum++;
                break;
            case CKA_PUBLIC_EXPONENT:
                types[attrnum] = CKA_PUBLIC_EXPONENT;
                params[attrnum] =
                    OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0);
                attrnum++;
                break;
            }
        }
    } else if (EVP_PKEY_is_a(pkey, "EC")) {
        for (int i = 0; i < num; i++) {
            switch (attrs[i].type) {
            case CKA_P11PROV_CURVE_NAME:
                types[attrnum] = CKA_P11PROV_CURVE_NAME;
                params[attrnum] = OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0);
                attrnum++;
                break;
            case CKA_P11PROV_PUB_KEY:
                types[attrnum] = CKA_P11PROV_PUB_KEY;
                params[attrnum] = OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_PUB_KEY, NULL, 0);
                attrnum++;
                break;
            }
        }
    } else if (EVP_PKEY_is_a(pkey, ED25519) || EVP_PKEY_is_a(pkey, ED448)) {
        for (int i = 0; i < num; i++) {
            switch (attrs[i].type) {
            case CKA_P11PROV_PUB_KEY:
                types[attrnum] = CKA_P11PROV_PUB_KEY;
                params[attrnum] = OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_PUB_KEY, NULL, 0);
                attrnum++;
                break;
            }
        }
    } else {
        rv = CKR_OBJECT_HANDLE_INVALID;
        goto done;
    }
    if (attrnum == 0) {
        rv = CKR_ARGUMENTS_BAD;
        goto done;
    }
    params[attrnum] = OSSL_PARAM_construct_end();

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

    for (int i = 0; i < attrnum; i++) {
        if (params[i].return_size == 0) {
            rv = CKR_GENERAL_ERROR;
            goto done;
        }
        /* allocate one more byte as null terminator to avoid buffer overruns
         * when this is converted to the OSSL_PARAM as utf8 string */
        params[i].data = OPENSSL_zalloc(params[i].return_size + 1);
        if (!params[i].data) {
            rv = CKR_HOST_MEMORY;
            goto done;
        }
        params[i].data_size = params[i].return_size;
        params[i].return_size = OSSL_PARAM_UNMODIFIED;
    }

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

    for (int i = 0; i < num; i++) {
        bool found = false;
        for (int j = 0; j < attrnum; j++) {
            if (attrs[i].type == types[j]) {
                if (!params[j].data) {
                    rv = CKR_GENERAL_ERROR;
                    goto done;
                }
                attrs[i].pValue = params[j].data;
                attrs[i].ulValueLen = params[j].data_size;
                params[j].data = NULL;
                found = true;
                break;
            }
        }
        if (!found) {
            rv = CKR_ARGUMENTS_BAD;
            goto done;
        }
    }

    rv = CKR_OK;

done:
    /* just in case caller didn't fetch all */
    for (int i = 0; i < attrnum; i++) {
        OPENSSL_free(params[i].data);
    }
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

    P11PROV_debug("Get Public Attributes (obj=%p, atrs=%p, num=%d)", obj, attrs,
                  num);

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

const char *p11prov_obj_get_ec_group_name(P11PROV_OBJ *obj)
{
    CK_ATTRIBUTE *attr;

    attr = p11prov_obj_get_attr(obj, CKA_P11PROV_CURVE_NAME);
    if (!attr) {
        /* this should never happen */
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Failed to get curve name");
        return NULL;
    }

    return (const char *)attr->pValue;
}

#define EC_MAX_PUB_ATTRS 2
int p11prov_obj_export_public_ec_key(P11PROV_OBJ *obj, OSSL_CALLBACK *cb_fn,
                                     void *cb_arg)
{
    CK_ATTRIBUTE attrs[EC_MAX_PUB_ATTRS] = { 0 };
    OSSL_PARAM params[EC_MAX_PUB_ATTRS + 1] = { 0 };
    CK_KEY_TYPE key_type;
    int n = 0;
    CK_RV rv;
    int ret;

    key_type = p11prov_obj_get_key_type(obj);
    switch (key_type) {
    case CKK_EC:
        attrs[0].type = CKA_P11PROV_CURVE_NAME;
        attrs[1].type = CKA_P11PROV_PUB_KEY;
        n = 2;
        break;
    case CKK_EC_EDWARDS:
        attrs[0].type = CKA_P11PROV_PUB_KEY;
        n = 1;
        break;
    default:
        return RET_OSSL_ERR;
    }

    rv = get_public_attrs(obj, attrs, n);
    if (rv != CKR_OK) {
        P11PROV_raise(obj->ctx, rv, "Failed to get public key attributes");
        return RET_OSSL_ERR;
    }

    n = 0;
    if (key_type == CKK_EC) {
        params[n] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, attrs[n].pValue, attrs[n].ulValueLen);
        n++;
    }
    params[n] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY, attrs[n].pValue, attrs[n].ulValueLen);
    n++;
    params[n] = OSSL_PARAM_construct_end();

    ret = cb_fn(params, cb_arg);

    /* must be freed after callback */
    for (int i = 0; i < n; i++) {
        OPENSSL_free(attrs[i].pValue);
    }
    return ret;
}
