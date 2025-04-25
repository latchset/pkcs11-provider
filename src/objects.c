/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/core.h>
#include <openssl/x509.h>
#include <openssl/obj_mac.h>
#include "platform/endian.h"

#define CKA_P11PROV_CURVE_NAME CKA_P11PROV_BASE + 1
#define CKA_P11PROV_CURVE_NID CKA_P11PROV_BASE + 2
#define CKA_P11PROV_PUB_KEY CKA_P11PROV_BASE + 3
#define CKA_P11PROV_PUB_KEY_X CKA_P11PROV_BASE + 4
#define CKA_P11PROV_PUB_KEY_Y CKA_P11PROV_BASE + 5

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

    P11PROV_URI *refresh_uri;
    char *public_uri;

    union {
        struct p11prov_key key;
        struct p11prov_crt crt;
    } data;

    CK_ATTRIBUTE *attrs;
    int numattrs;

    int refcnt;
    int poolid;

    P11PROV_OBJ *assoc_obj;
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
        /* ------------- LOCKED SECTION */
    } else {
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

    if (ret == CKR_OK) {
        P11PROV_debug("Object added to pool (idx=%d, obj=%p)", obj->poolid,
                      obj);
    }

    return ret;
}

static void obj_rm_from_pool(P11PROV_OBJ *obj)
{
    P11PROV_OBJ_POOL *pool;
    CK_RV ret;
    const char *errstr = NULL;

    if (obj->slotid == CK_UNAVAILABLE_INFORMATION) {
        /* a mock object */
        return;
    }

    ret = p11prov_slot_get_obj_pool(obj->ctx, obj->slotid, &pool);
    if (ret != CKR_OK) {
        return;
    }

    P11PROV_debug("Object to be removed from pool (idx=%d, obj=%p)",
                  obj->poolid, obj);

    ret = MUTEX_LOCK(pool);
    if (ret != CKR_OK) {
        return;
    }

    /* LOCKED SECTION ------------- */
    if (obj->poolid >= pool->size) {
        errstr = "small pool";
        goto done;
    }
    if (pool->objects[obj->poolid] != obj) {
        errstr = "obj already removed";
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

    if (errstr != NULL) {
        P11PROV_raise(pool->provctx, ret,
                      "Objects pool in inconsistent state - %s (obj=%p)",
                      errstr, obj);
    }
}

static CK_RV p11prov_obj_store_public_key(P11PROV_OBJ *key);

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

    if (handle == CK_P11PROV_IMPORTED_HANDLE) {
        /* mock object, return w/o adding to pool */
        return obj;
    }

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
        || obj->cka_token != CK_TRUE || obj->cka_copyable != CK_TRUE) {
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
    if (ret != CKR_OK || session == NULL) {
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

    OPENSSL_free(obj->public_uri);
    p11prov_uri_free(obj->refresh_uri);

    p11prov_obj_free(obj->assoc_obj);

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
        if (obj->handle == CK_P11PROV_IMPORTED_HANDLE) {
            /* This was a mock imported public key,
             * but we are being asked for the actual key handle
             * so it means we need to actually add the key to the
             * session in order to be able to perform operations
             * with the token */
            int rv;

            rv = p11prov_obj_store_public_key(obj);
            if (rv != CKR_OK) {
                return CK_INVALID_HANDLE;
            }
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

bool p11prov_obj_get_bool(P11PROV_OBJ *obj, CK_ATTRIBUTE_TYPE type, bool def)
{
    CK_ATTRIBUTE *attr = NULL;

    if (!obj) {
        return def;
    }

    for (int i = 0; i < obj->numattrs; i++) {
        if (obj->attrs[i].type == type) {
            attr = &obj->attrs[i];
        }
    }

    if (!attr || !attr->pValue) {
        return def;
    }

    if (attr->ulValueLen == sizeof(CK_BBOOL)) {
        if (*((CK_BBOOL *)attr->pValue) == CK_FALSE) {
            return false;
        } else {
            return true;
        }
    }

    return def;
}

CK_KEY_TYPE p11prov_obj_get_key_type(P11PROV_OBJ *obj)
{
    if (obj) {
        switch (obj->class) {
        case CKO_PRIVATE_KEY:
        case CKO_PUBLIC_KEY:
        case CKO_DOMAIN_PARAMETERS:
            return obj->data.key.type;
        }
    }
    return CK_UNAVAILABLE_INFORMATION;
}

bool p11prov_obj_is_rsa_pss(P11PROV_OBJ *obj)
{
    CK_BBOOL token_supports_allowed_mechs = CK_TRUE;
    CK_ATTRIBUTE *am = NULL;
    CK_MECHANISM_TYPE *allowed;
    P11PROV_OBJ *priv = NULL;
    int am_nmechs;
    CK_RV ret;

    /* If the token does not support this attribute, do not even try to figure
     * out the subtype. */
    ret = p11prov_token_sup_attr(obj->ctx, obj->slotid, GET_ATTR,
                                 CKA_ALLOWED_MECHANISMS,
                                 &token_supports_allowed_mechs);
    if (ret != CKR_OK) {
        P11PROV_raise(obj->ctx, ret, "Failed to probe quirk");
    } else if (token_supports_allowed_mechs == CK_FALSE) {
        return false;
    }

    am = p11prov_obj_get_attr(obj, CKA_ALLOWED_MECHANISMS);
    if (am == NULL || am->ulValueLen == 0) {
        /* The ALLOWED_MECHANISMS should be on both of the keys. But more
         * commonly they are available only on the private key. Check if we
         * have a priv key associated to this pub key and if so, use that one.
         * TODO we can try also certificate restrictions
         */
        if (obj->class == CKO_PRIVATE_KEY) {
            /* no limitations */
            return false;
        }

        /* Try to find private key */
        priv = p11prov_obj_find_associated(obj, CKO_PRIVATE_KEY);
        if (priv == NULL) {
            return false;
        }

        am = p11prov_obj_get_attr(priv, CKA_ALLOWED_MECHANISMS);
        if (am == NULL || am->ulValueLen == 0) {
            /* no limitations */
            p11prov_obj_free(priv);
            return false;
        }
    }
    allowed = (CK_MECHANISM_TYPE *)am->pValue;
    am_nmechs = am->ulValueLen / sizeof(CK_MECHANISM_TYPE);
    for (int i = 0; i < am_nmechs; i++) {
        bool found = false;
        for (int j = 0; j < P11PROV_N_RSAPSS_MECHS; j++) {
            if (allowed[i] == p11prov_rsapss_mechs[j]) {
                found = true;
                break;
            }
        }
        if (!found) {
            /* this is not a RSA-PSS mechanism. We can not enforce any
             * limitations */
            p11prov_obj_free(priv);
            return false;
        }
    }
    /* all allowed mechanisms fit into the list of RSA-PSS ones */
    p11prov_obj_free(priv);
    return true;
}

CK_ULONG p11prov_obj_get_key_bit_size(P11PROV_OBJ *obj)
{
    if (obj) {
        switch (obj->class) {
        case CKO_PRIVATE_KEY:
        case CKO_PUBLIC_KEY:
        case CKO_DOMAIN_PARAMETERS:
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
        case CKO_DOMAIN_PARAMETERS:
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

P11PROV_OBJ *p11prov_obj_get_associated(P11PROV_OBJ *obj)
{
    return obj->assoc_obj;
}

void p11prov_obj_set_associated(P11PROV_OBJ *obj, P11PROV_OBJ *assoc)
{
    if (obj == NULL) {
        return;
    }

    p11prov_obj_free(obj->assoc_obj);
    obj->assoc_obj = NULL;

    if (assoc == NULL) {
        return;
    }

    obj->assoc_obj = p11prov_obj_ref_no_cache(assoc);
}

const char *p11prov_obj_get_public_uri(P11PROV_OBJ *obj)
{
    if (!obj->public_uri) {
        obj->public_uri = p11prov_obj_to_uri(obj);
    }
    return obj->public_uri;
}

/* CKA_ID
 * CKA_LABEL
 * CKA_ALWAYS_AUTHENTICATE
 * CKA_ALLOWED_MECHANISMS see p11prov_obj_from_handle() */
#define BASE_KEY_ATTRS_NUM 4

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
    if (key->class == CKO_PRIVATE_KEY) {
        FA_SET_BUF_ALLOC(attrs, num, CKA_ALWAYS_AUTHENTICATE, false);
    }
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

static CK_RV decode_ec_point(CK_KEY_TYPE key_type, CK_ATTRIBUTE *attr,
                             struct data_buffer *ec_point)
{
    ASN1_OCTET_STRING *octet;
    const unsigned char *val;
    CK_RV ret = CKR_GENERAL_ERROR;
    int err;

    /* in d2i functions 'in' is overwritten to return the remainder of
     * the buffer after parsing, so we always need to avoid passing in
     * our pointer holders, to avoid having them clobbered */
    val = attr->pValue;
    octet = d2i_ASN1_OCTET_STRING(NULL, (const unsigned char **)&val,
                                  attr->ulValueLen);
    if (!octet) {
        /* 3.1 spec says CKA_EC_POINT is not DER encoded for Edwards and
         * Montgomery curves so do not fail in that case and just take
         * the value as is */
        if (key_type == CKK_EC) {
            return CKR_KEY_INDIGESTIBLE;
        } else {
            octet = ASN1_OCTET_STRING_new();
            if (!octet) {
                return CKR_HOST_MEMORY;
            }
            /* makes a copy of the value */
            err = ASN1_OCTET_STRING_set(octet, attr->pValue, attr->ulValueLen);
            if (err != RET_OSSL_OK) {
                ret = CKR_HOST_MEMORY;
                goto done;
            }
        }
    }

    ec_point->data = octet->data;
    ec_point->length = octet->length;

    /* moved octet data, do not free it */
    octet->data = NULL;
    octet->length = 0;

    ret = CKR_OK;
done:
    ASN1_OCTET_STRING_free(octet);
    return ret;
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
    } else {
        /* known vendor optimization to avoid storing
         * EC public key on HSM; can avoid
         * p11prov_obj_find_associated later
         */
        FA_SET_BUF_ALLOC(attrs, num, CKA_EC_POINT, false);
        FA_SET_BUF_ALLOC(attrs, num, CKA_ALWAYS_AUTHENTICATE, false);
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

static CK_RV fetch_secret_key(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                              CK_OBJECT_HANDLE object, P11PROV_OBJ *key)
{
    struct fetch_attrs attrs[BASE_KEY_ATTRS_NUM];
    int num;
    CK_RV ret;

    key->attrs = OPENSSL_zalloc(BASE_KEY_ATTRS_NUM * sizeof(CK_ATTRIBUTE));
    if (key->attrs == NULL) {
        return CKR_HOST_MEMORY;
    }

    num = 0;
    FA_SET_BUF_ALLOC(attrs, num, CKA_ID, false);
    FA_SET_BUF_ALLOC(attrs, num, CKA_LABEL, false);
    FA_SET_BUF_ALLOC(attrs, num, CKA_ALWAYS_AUTHENTICATE, false);

    ret = p11prov_fetch_attributes(ctx, session, object, attrs, num);
    if (ret != CKR_OK) {
        P11PROV_debug("Failed to query key attributes (%lu)", ret);
        p11prov_fetch_attrs_free(attrs, num);
        return ret;
    }

    key->numattrs = 0;
    p11prov_move_alloc_attrs(attrs, num, key->attrs, &key->numattrs);

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
    case CKO_SECRET_KEY:
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
        case CKK_GENERIC_SECRET:
        case CKK_AES:
        case CKK_SHA_1_HMAC:
        case CKK_SHA256_HMAC:
        case CKK_SHA384_HMAC:
        case CKK_SHA512_HMAC:
        case CKK_SHA224_HMAC:
        case CKK_SHA512_224_HMAC:
        case CKK_SHA512_256_HMAC:
        case CKK_SHA3_224_HMAC:
        case CKK_SHA3_256_HMAC:
        case CKK_SHA3_384_HMAC:
        case CKK_SHA3_512_HMAC:
            ret = fetch_secret_key(ctx, session, handle, obj);
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
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
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

    slotid = p11prov_obj_get_slotid(obj);

    ret = p11prov_get_session(obj->ctx, &slotid, NULL, NULL,
                              CK_UNAVAILABLE_INFORMATION, NULL, NULL, false,
                              false, &session);
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

static void p11prov_obj_refresh(P11PROV_OBJ *obj)
{
    int login_behavior;
    bool login = false;
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SESSION *session = NULL;
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_ATTRIBUTE template[3] = { 0 };
    CK_ATTRIBUTE *attr;
    int anum;
    CK_OBJECT_HANDLE handle;
    CK_ULONG objcount = 0;
    P11PROV_OBJ *tmp = NULL;
    CK_RV ret;

    P11PROV_debug("Refresh object %p", obj);

    if (obj->class == CKO_PRIVATE_KEY) {
        login = true;
    }
    login_behavior = p11prov_ctx_login_behavior(obj->ctx);
    if (login_behavior == PUBKEY_LOGIN_ALWAYS) {
        login = true;
    }

    slotid = p11prov_obj_get_slotid(obj);

    ret = p11prov_get_session(obj->ctx, &slotid, NULL, obj->refresh_uri,
                              CK_UNAVAILABLE_INFORMATION, NULL, NULL, login,
                              false, &session);

    if (ret != CKR_OK) {
        P11PROV_debug("Failed to get session to refresh object %p", obj);
        return;
    }

    sess = p11prov_session_handle(session);

    anum = 0;
    CKATTR_ASSIGN(template[anum], CKA_CLASS, &(obj->class), sizeof(obj->class));
    anum++;
    /* use CKA_ID if available */
    attr = p11prov_obj_get_attr(obj, CKA_ID);
    if (attr) {
        template[anum] = *attr;
        anum++;
    }
    /* use Label if available */
    attr = p11prov_obj_get_attr(obj, CKA_LABEL);
    if (attr) {
        template[anum] = *attr;
        anum++;
    }

    ret = p11prov_FindObjectsInit(obj->ctx, sess, template, anum);
    if (ret != CKR_OK) {
        goto done;
    }

    /* we expect a single entry */
    ret = p11prov_FindObjects(obj->ctx, sess, &handle, 1, &objcount);

    /* Finalizing is not fatal so ignore result */
    p11prov_FindObjectsFinal(obj->ctx, sess);

    if (ret != CKR_OK || objcount == 0) {
        P11PROV_raise(obj->ctx, ret,
                      "Failed to find refresh object %p (count=%ld)", obj,
                      objcount);
        goto done;
    }
    if (objcount != 1) {
        P11PROV_raise(obj->ctx, ret,
                      "Too many objects found on refresh (count=%ld)",
                      objcount);
        goto done;
    }

    ret = p11prov_obj_from_handle(obj->ctx, session, handle, &tmp);
    if (ret != CKR_OK) {
        P11PROV_raise(obj->ctx, ret, "Failed to get object from handle");
        goto done;
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
    case CKO_SECRET_KEY:
        obj->data.key = tmp->data.key;
        break;
    default:
        break;
    }
    OPENSSL_free(obj->public_uri);
    obj->public_uri = NULL;
    /* FIXME: How do we refresh attrs? What happens if a pointer
     * to an attr value was saved somewhere? Freeing ->attrs would
     * cause use-after-free issues */
    p11prov_obj_free(tmp);
    obj->raf = false;

    /* Refresh the associated object too if there is one */
    if (obj->assoc_obj && obj->assoc_obj->raf) {
        p11prov_obj_refresh(obj->assoc_obj);
    }

done:
    p11prov_return_session(session);
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
    case CKO_SECRET_KEY:
        return get_all_attrs(obj, attrs, num);
    case CKO_PRIVATE_KEY:
        rv = get_all_attrs(obj, attrs, num);
        if (rv == CKR_OK) {
            return rv;
        }
        /* public attributes unavailable, try to find public key */
        tmp = p11prov_obj_find_associated(obj, CKO_PUBLIC_KEY);
        if (tmp) {
            rv = get_all_attrs(tmp, attrs, num);
            p11prov_obj_free(tmp);
            return rv;
        }
        /* no public key, try to find certificate */
        tmp = p11prov_obj_find_associated(obj, CKO_CERTIFICATE);
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
static int p11prov_obj_export_public_rsa_key(P11PROV_OBJ *obj,
                                             OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    CK_ATTRIBUTE attrs[RSA_PUB_ATTRS] = { 0 };
    OSSL_PARAM params[RSA_PUB_ATTRS + 2];
    CK_RV rv;
    int ret, n = 0;

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
    params[n++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N,
                                          attrs[0].pValue, attrs[0].ulValueLen);
    byteswap_buf(attrs[1].pValue, attrs[1].pValue, attrs[1].ulValueLen);
    params[n++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E,
                                          attrs[1].pValue, attrs[1].ulValueLen);
    /* TODO: Add RSA-PSS restrictions if there is only one allowed mechanisms.
     * The PKCS#11 specification is not compatible with what OpenSSL expects
     * (unless we would have just one mechanisms specified in
     * ALLOWED_MECHANISMS) so its better to not add any restrictions now. */
#if 0
    if (p11prov_obj_is_rsa_pss(obj)) {
        params[n++] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_RSA_MASKGENFUNC, (char *)SN_mgf1, strlen(SN_mgf1));
        /* TODO other restrictions */
    }
#endif
    params[n++] = OSSL_PARAM_construct_end();

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

bool p11prov_obj_get_ec_compressed(P11PROV_OBJ *obj)
{
    CK_ATTRIBUTE *pub_key;
    uint8_t *buf;

    pub_key = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY);
    if (!pub_key) {
        obj = p11prov_obj_get_associated(obj);
        if (obj) {
            pub_key = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY);
        }
        if (!pub_key) {
            return false;
        }
    }
    buf = pub_key->pValue;

    return (buf[0] & 0x01) == 0x01;
}

static int ossl_param_construct_bn(P11PROV_CTX *provctx, OSSL_PARAM *param,
                                   const char *key, const BIGNUM *val)
{
    size_t bsize;
    void *buf;

    if (BN_is_negative(val)) {
        P11PROV_raise(provctx, CKR_GENERAL_ERROR,
                      "Negative big numbers are unsupported for %s", key);
        return 0;
    }

    bsize = (size_t)BN_num_bytes(val);
    /* We make sure that at least one byte is used, so zero is properly set */
    if (bsize == 0) {
        bsize++;
    }

    buf = OPENSSL_malloc(bsize);
    if (buf == NULL) {
        P11PROV_raise(provctx, CKR_HOST_MEMORY, "Allocating data for %s", key);
        return 0;
    }

    if (BN_bn2nativepad(val, buf, bsize) < 0) {
        return 0;
    }

    *param = OSSL_PARAM_construct_BN(key, buf, bsize);
    return 1;
}

static int ec_group_explicit_to_params(P11PROV_OBJ *obj, const EC_GROUP *group,
                                       OSSL_PARAM *params, int *nparam,
                                       BN_CTX *bnctx)
{
    int fid;
    const char *field_type;
    BIGNUM *p, *a, *b;
    const BIGNUM *order, *cofactor;
    const EC_POINT *generator;
    point_conversion_form_t genform;
    size_t bsize;
    void *buf;
    unsigned char *seed;
    size_t seed_len;

    fid = EC_GROUP_get_field_type(group);
    if (fid == NID_X9_62_prime_field) {
        field_type = SN_X9_62_prime_field;
    } else if (fid == NID_X9_62_characteristic_two_field) {
        field_type = SN_X9_62_characteristic_two_field;
    } else {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid EC field");
        return RET_OSSL_ERR;
    }

    params[(*nparam)++] = OSSL_PARAM_construct_utf8_string(
        OSSL_PKEY_PARAM_EC_FIELD_TYPE, (char *)field_type, 0);

    p = BN_CTX_get(bnctx);
    a = BN_CTX_get(bnctx);
    b = BN_CTX_get(bnctx);
    if (b == NULL) {
        return RET_OSSL_ERR;
    }

    if (!EC_GROUP_get_curve(group, p, a, b, bnctx)) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid curve");
        return RET_OSSL_ERR;
    }

    if (!ossl_param_construct_bn(obj->ctx, &params[(*nparam)++],
                                 OSSL_PKEY_PARAM_EC_P, p)
        || !ossl_param_construct_bn(obj->ctx, &params[(*nparam)++],
                                    OSSL_PKEY_PARAM_EC_A, a)
        || !ossl_param_construct_bn(obj->ctx, &params[(*nparam)++],
                                    OSSL_PKEY_PARAM_EC_B, b)) {
        return RET_OSSL_ERR;
    }

    order = EC_GROUP_get0_order(group);
    if (order == NULL) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid group order");
        return RET_OSSL_ERR;
    }
    if (!ossl_param_construct_bn(obj->ctx, &params[(*nparam)++],
                                 OSSL_PKEY_PARAM_EC_ORDER, order)) {
        return RET_OSSL_ERR;
    }

    generator = EC_GROUP_get0_generator(group);
    genform = EC_GROUP_get_point_conversion_form(group);
    if (generator == NULL) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid group generator");
        return RET_OSSL_ERR;
    }
    bsize = EC_POINT_point2oct(group, generator, genform, NULL, 0, bnctx);
    buf = OPENSSL_malloc(bsize);
    if (buf == NULL) {
        return RET_OSSL_ERR;
    }
    bsize = EC_POINT_point2oct(group, generator, genform, buf, bsize, bnctx);
    params[(*nparam)++] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_EC_GENERATOR, buf, bsize);

    cofactor = EC_GROUP_get0_cofactor(group);
    if (cofactor == NULL) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid group cofactor");
        return RET_OSSL_ERR;
    }
    if (!ossl_param_construct_bn(obj->ctx, &params[(*nparam)++],
                                 OSSL_PKEY_PARAM_EC_COFACTOR, cofactor)) {
        return RET_OSSL_ERR;
    }

    seed = EC_GROUP_get0_seed(group);
    seed_len = EC_GROUP_get_seed_len(group);
    if (seed != NULL && seed_len > 0) {
        params[(*nparam)++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_EC_SEED, seed, seed_len);
    }

    return RET_OSSL_OK;
}

/* Common:
 *   CKA_P11PROV_PUB_KEY     -> OSSL_PKEY_PARAM_PUB_KEY
 * Named curves:
 *   CKA_P11PROV_CURVE_NAME  -> OSSL_PKEY_PARAM_GROUP_NAME
 * Explicit curves:
 *   CKA_EC_PARAMS           -> OSSL_PKEY_PARAM_EC_FIELD_TYPE,
 *                              OSSL_PKEY_PARAM_EC_A,
 *                              OSSL_PKEY_PARAM_EC_B,
 *                              OSSL_PKEY_PARAM_EC_P,
 *                              OSSL_PKEY_PARAM_EC_GENERATOR,
 *                              OSSL_PKEY_PARAM_EC_ORDER,
 *                              OSSL_PKEY_PARAM_EC_COFACTOR,
 *                              OSSL_PKEY_PARAM_EC_SEED
 */
#define EC_MAX_PUB_ATTRS 2
#define EC_MAX_OSSL_PARAMS 9
static int p11prov_obj_export_public_ec_key(P11PROV_OBJ *obj, bool params_only,
                                            OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    CK_ATTRIBUTE attrs[EC_MAX_PUB_ATTRS] = { 0 };
    OSSL_PARAM params[EC_MAX_OSSL_PARAMS + 1] = { 0 };
    CK_KEY_TYPE key_type;
    int pub_key_attr = 0;
    int nattr = 0;
    int nparam = 0;
    CK_RV rv;
    int ret;
    EC_GROUP *group = NULL;
    int curve_nid = NID_undef;

    key_type = p11prov_obj_get_key_type(obj);
    switch (key_type) {
    case CKK_EC:
        attrs[0].type = CKA_P11PROV_CURVE_NID;
        rv = get_public_attrs(obj, attrs, 1);
        if (rv != CKR_OK) {
            P11PROV_raise(obj->ctx, rv, "Failed to get EC key curve nid");
            return RET_OSSL_ERR;
        }
        curve_nid = *(int *)attrs[0].pValue;
        OPENSSL_free(attrs[0].pValue);
        if (curve_nid == NID_undef) {
            attrs[0].type = CKA_EC_PARAMS;
        } else {
            attrs[0].type = CKA_P11PROV_CURVE_NAME;
        }
        nattr = 1;
        break;
    case CKK_EC_EDWARDS:
        break;
    default:
        return RET_OSSL_ERR;
    }

    if (!params_only) {
        pub_key_attr = nattr;
        attrs[nattr].type = CKA_P11PROV_PUB_KEY;
        nattr++;
    }

    rv = get_public_attrs(obj, attrs, nattr);
    if (rv != CKR_OK) {
        P11PROV_raise(obj->ctx, rv, "Failed to get public key attributes");
        return RET_OSSL_ERR;
    }

    if (!params_only) {
        params[nparam] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, attrs[pub_key_attr].pValue,
            attrs[pub_key_attr].ulValueLen);
        nparam++;
    }
    if (key_type == CKK_EC) {
        if (curve_nid == NID_undef) {
            BN_CTX *bnctx;

            /* in d2i functions 'in' is overwritten to return the remainder of
             * the buffer after parsing, so we always need to avoid passing in
             * our pointer holders, to avoid having them clobbered */
            const unsigned char *val = attrs[0].pValue;
            group = d2i_ECPKParameters(NULL, &val, attrs[0].ulValueLen);
            if (group == NULL) {
                ret = RET_OSSL_ERR;
                goto done;
            }
            bnctx = BN_CTX_new_ex(p11prov_ctx_get_libctx(obj->ctx));
            if (bnctx == NULL) {
                ret = RET_OSSL_ERR;
                goto done;
            }
            BN_CTX_start(bnctx);
            ret =
                ec_group_explicit_to_params(obj, group, params, &nparam, bnctx);
            BN_CTX_end(bnctx);
            BN_CTX_free(bnctx);
            if (ret != RET_OSSL_OK) {
                goto done;
            }
        } else {
            params[nparam] = OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_GROUP_NAME, attrs[0].pValue,
                attrs[0].ulValueLen);
            nparam++;
        }
    }
    params[nparam] = OSSL_PARAM_construct_end();

    ret = cb_fn(params, cb_arg);

done:
    /* must be freed after callback */
    EC_GROUP_free(group);
    for (int i = 0; i < nparam; i++) {
        if (strcmp(params[i].key, OSSL_PKEY_PARAM_PUB_KEY)
            && strcmp(params[i].key, OSSL_PKEY_PARAM_GROUP_NAME)
            && strcmp(params[i].key, OSSL_PKEY_PARAM_EC_FIELD_TYPE)) {
            OPENSSL_free(params[i].data);
        }
    }
    for (int i = 0; i < nattr; i++) {
        OPENSSL_free(attrs[i].pValue);
    }
    return ret;
}

int p11prov_obj_export_public_key(P11PROV_OBJ *obj, CK_KEY_TYPE key_type,
                                  bool search_related, bool params_only,
                                  OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    if (obj == NULL) {
        return RET_OSSL_ERR;
    }

    if (obj->class != CKO_PRIVATE_KEY && obj->class != CKO_PUBLIC_KEY) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid Object Class");
        return RET_OSSL_ERR;
    }

    if (key_type != CK_UNAVAILABLE_INFORMATION) {
        if (key_type != obj->data.key.type) {
            P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid Key Type");
            return RET_OSSL_ERR;
        }
    }

    if (!search_related && obj->class != CKO_PUBLIC_KEY) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Not a public Key");
        return RET_OSSL_ERR;
    }

    switch (obj->data.key.type) {
    case CKK_RSA:
        return p11prov_obj_export_public_rsa_key(obj, cb_fn, cb_arg);
    case CKK_EC:
    case CKK_EC_EDWARDS:
        return p11prov_obj_export_public_ec_key(obj, params_only, cb_fn,
                                                cb_arg);
    default:
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Unsupported key type");
        return RET_OSSL_ERR;
    }
}

int p11prov_obj_get_ed_pub_key(P11PROV_OBJ *obj, CK_ATTRIBUTE **pub)
{
    CK_ATTRIBUTE *a;

    P11PROV_debug("get ed pubkey %p", obj);

    if (!obj) {
        return RET_OSSL_ERR;
    }

    if (obj->class != CKO_PRIVATE_KEY && obj->class != CKO_PUBLIC_KEY) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid Object Class");
        return RET_OSSL_ERR;
    }

    if (obj->data.key.type != CKK_EC_EDWARDS) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Unsupported key type");
        return RET_OSSL_ERR;
    }

    /* check if we have a pub key associated to a private key */
    if (obj->class == CKO_PRIVATE_KEY) {
        P11PROV_OBJ *pobj = p11prov_obj_get_associated(obj);
        if (pobj && pobj->class == CKO_PUBLIC_KEY) {
            /* replace obj with the public one */
            obj = pobj;
        }
    }

    /* See if we have cached attributes first */
    a = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY);
    if (!a) {
        return RET_OSSL_ERR;
    }

    if (pub) {
        *pub = a;
    }
    return RET_OSSL_OK;
}

int p11prov_obj_get_ec_public_x_y(P11PROV_OBJ *obj, CK_ATTRIBUTE **pub_x,
                                  CK_ATTRIBUTE **pub_y)
{
    const unsigned char *val;
    void *tmp_ptr;
    CK_ATTRIBUTE *ec_params;
    CK_ATTRIBUTE *pub_key;
    EC_POINT *pub_point = NULL;
    EC_GROUP *group = NULL;
    CK_ATTRIBUTE *a_x;
    CK_ATTRIBUTE *a_y;
    BN_CTX *bnctx = NULL;
    BIGNUM *x;
    BIGNUM *y;
    int len;
    int ret;

    if (!obj) {
        return RET_OSSL_ERR;
    }

    if (obj->class != CKO_PRIVATE_KEY && obj->class != CKO_PUBLIC_KEY) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid Object Class");
        return RET_OSSL_ERR;
    }

    if (obj->data.key.type != CKK_EC) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Unsupported key type");
        return RET_OSSL_ERR;
    }

    /* check if we have a pub key associated to a private key */
    if (obj->class == CKO_PRIVATE_KEY) {
        P11PROV_OBJ *pub = p11prov_obj_get_associated(obj);
        if (pub && pub->class == CKO_PUBLIC_KEY) {
            /* replace obj with the public one */
            obj = pub;
        }
    }

    /* See if we have cached attributes first */
    a_x = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY_X);
    a_y = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY_Y);
    if (a_x && a_y) {
        if (pub_x) {
            *pub_x = a_x;
        }
        if (pub_y) {
            *pub_y = a_y;
        }
        return RET_OSSL_OK;
    }

    ec_params = p11prov_obj_get_attr(obj, CKA_EC_PARAMS);
    if (!ec_params) {
        return RET_OSSL_ERR;
    }
    pub_key = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY);
    if (!pub_key) {
        return RET_OSSL_ERR;
    }

    bnctx = BN_CTX_new();
    if (!bnctx) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    /* prevent modification of the attribute pointer */
    val = ec_params->pValue;
    group = d2i_ECPKParameters(NULL, &val, ec_params->ulValueLen);
    if (!group) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    x = BN_CTX_get(bnctx);
    y = BN_CTX_get(bnctx);
    if (!y) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    pub_point = EC_POINT_new(group);
    if (!pub_point) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    ret = EC_POINT_oct2point(group, pub_point, pub_key->pValue,
                             pub_key->ulValueLen, bnctx);
    if (ret != RET_OSSL_OK) {
        goto done;
    }

    ret = EC_POINT_get_affine_coordinates(group, pub_point, x, y, bnctx);
    if (ret != RET_OSSL_OK) {
        goto done;
    }

    /* cache values */
    tmp_ptr =
        OPENSSL_realloc(obj->attrs, sizeof(CK_ATTRIBUTE) * (obj->numattrs + 2));
    if (!tmp_ptr) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    obj->attrs = tmp_ptr;

    /* do x */
    a_x = &obj->attrs[obj->numattrs];
    a_x->type = CKA_P11PROV_PUB_KEY_X;
    a_x->ulValueLen = BN_num_bytes(x);
    a_x->pValue = OPENSSL_malloc(a_x->ulValueLen);
    if (!a_x->pValue) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    len = BN_bn2nativepad(x, a_x->pValue, a_x->ulValueLen);
    if (len == -1) {
        OPENSSL_free(a_x->pValue);
        ret = RET_OSSL_ERR;
        goto done;
    }
    obj->numattrs++;

    /* do y */
    a_y = &obj->attrs[obj->numattrs];
    a_y->type = CKA_P11PROV_PUB_KEY_Y;
    a_y->ulValueLen = BN_num_bytes(y);
    a_y->pValue = OPENSSL_malloc(a_y->ulValueLen);
    if (!a_y->pValue) {
        OPENSSL_free(a_y->pValue);
        ret = RET_OSSL_ERR;
        goto done;
    }
    len = BN_bn2nativepad(y, a_y->pValue, a_y->ulValueLen);
    if (len == -1) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    obj->numattrs++;

    if (pub_x) {
        *pub_x = a_x;
    }
    if (pub_y) {
        *pub_y = a_y;
    }

    ret = RET_OSSL_OK;

done:
    EC_POINT_free(pub_point);
    EC_GROUP_free(group);
    BN_CTX_free(bnctx);
    return ret;
}

CK_ATTRIBUTE *p11prov_obj_get_ec_public_raw(P11PROV_OBJ *key)
{
    CK_ATTRIBUTE *pub_key;

    if (!key) {
        return NULL;
    }

    if (key->data.key.type != CKK_EC) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR, "Unsupported key type");
        return NULL;
    }

    if (key->class != CKO_PRIVATE_KEY && key->class != CKO_PUBLIC_KEY) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR, "Invalid Object Class");
        return NULL;
    }

    /* check if we have a pub key associated to a private key */
    if (key->class == CKO_PRIVATE_KEY) {
        P11PROV_OBJ *pub = p11prov_obj_get_associated(key);
        if (pub && pub->class == CKO_PUBLIC_KEY) {
            /* replace obj with the public one */
            key = pub;
        }
    }

    pub_key = p11prov_obj_get_attr(key, CKA_P11PROV_PUB_KEY);
    if (!pub_key) {
        CK_ATTRIBUTE *ec_point;

        ec_point = p11prov_obj_get_attr(key, CKA_EC_POINT);
        if (ec_point) {
            struct data_buffer data = { 0 };
            void *tmp_ptr;
            CK_RV ret;

            ret = decode_ec_point(key->data.key.type, ec_point, &data);
            if (ret != CKR_OK) {
                P11PROV_raise(key->ctx, ret, "Failed to decode EC_POINT");
                return NULL;
            }

            tmp_ptr = OPENSSL_realloc(key->attrs, sizeof(CK_ATTRIBUTE)
                                                      * (key->numattrs + 1));
            if (!tmp_ptr) {
                P11PROV_raise(key->ctx, CKR_HOST_MEMORY,
                              "Failed to allocate memory key attributes");
                OPENSSL_free(data.data);
                return NULL;
            }
            key->attrs = tmp_ptr;

            /* takes the data allocated in data */
            CKATTR_ASSIGN(key->attrs[key->numattrs], CKA_P11PROV_PUB_KEY,
                          data.data, data.length);
            key->numattrs++;

            pub_key = &key->attrs[key->numattrs - 1];
        }
    }

    if (!pub_key) {
        P11PROV_debug("ECC Public Point not found");
    }
    return pub_key;
}

static int cmp_bn_attr(P11PROV_OBJ *key1, P11PROV_OBJ *key2,
                       CK_ATTRIBUTE_TYPE attr)
{
    BIGNUM *bx1;
    BIGNUM *bx2;
    CK_ATTRIBUTE *x1, *x2;
    int rc = RET_OSSL_ERR;

    /* is BN ?*/
    if (attr != CKA_MODULUS && attr != CKA_PUBLIC_EXPONENT) {
        return rc;
    }

    x1 = p11prov_obj_get_attr(key1, attr);
    x2 = p11prov_obj_get_attr(key2, attr);

    if (!x1 || !x2) {
        return rc;
    }

    bx1 = BN_native2bn(x1->pValue, x1->ulValueLen, NULL);
    bx2 = BN_native2bn(x2->pValue, x2->ulValueLen, NULL);

    if (BN_cmp(bx1, bx2) == 0) {
        rc = RET_OSSL_OK;
    }

    BN_free(bx1);
    BN_free(bx2);

    return rc;
}

static int cmp_attr(P11PROV_OBJ *key1, P11PROV_OBJ *key2,
                    CK_ATTRIBUTE_TYPE attr)
{
    CK_ATTRIBUTE *x1, *x2;

    x1 = p11prov_obj_get_attr(key1, attr);
    x2 = p11prov_obj_get_attr(key2, attr);
    if (!x1 || !x2) {
        return RET_OSSL_ERR;
    }
    if (x1->ulValueLen != x2->ulValueLen) {
        return RET_OSSL_ERR;
    }
    if (memcmp(x1->pValue, x2->pValue, x1->ulValueLen) != 0) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int cmp_public_key_values(P11PROV_OBJ *pub_key1, P11PROV_OBJ *pub_key2)
{
    int ret;

    switch (pub_key1->data.key.type) {
    case CKK_RSA:
        /* pub_key1 pub_key2 could be CKO_PRIVATE_KEY here but
         *  nevertheless contain these two attributes
         */
        ret = cmp_bn_attr(pub_key1, pub_key2, CKA_MODULUS);
        if (ret == RET_OSSL_ERR) {
            break;
        }
        ret = cmp_bn_attr(pub_key1, pub_key2, CKA_PUBLIC_EXPONENT);
        break;
    case CKK_EC:
    case CKK_EC_EDWARDS:
        ret = cmp_attr(pub_key1, pub_key2, CKA_P11PROV_PUB_KEY);
        break;
    default:
        ret = RET_OSSL_ERR;
    }

    return ret;
}

static int match_key_with_cert(P11PROV_OBJ *priv_key, P11PROV_OBJ *pub_key)
{
    P11PROV_OBJ *cert;
    CK_ATTRIBUTE attrs[2] = { 0 };
    CK_ATTRIBUTE *x;
    int num = 0;
    int ret = RET_OSSL_ERR;

    cert = p11prov_obj_find_associated(priv_key, CKO_CERTIFICATE);
    if (!cert) {
        P11PROV_raise(priv_key->ctx, CKR_GENERAL_ERROR,
                      "Could not find associated certificate object");
        return RET_OSSL_ERR;
    }

    switch (pub_key->data.key.type) {
    case CKK_RSA:
        attrs[0].type = CKA_MODULUS;
        attrs[1].type = CKA_PUBLIC_EXPONENT;
        num = 2;
        break;
    case CKK_EC:
    case CKK_EC_EDWARDS:
        attrs[0].type = CKA_P11PROV_PUB_KEY;
        num = 1;
        break;
    }

    ret = get_all_from_cert(cert, attrs, num);
    if (ret != CKR_OK) {
        P11PROV_raise(priv_key->ctx, ret,
                      "Failed to get public attrs from cert");
        ret = RET_OSSL_ERR;
        goto done;
    }

    switch (pub_key->data.key.type) {
    case CKK_RSA:
        x = p11prov_obj_get_attr(pub_key, CKA_MODULUS);
        if (!x || x->ulValueLen != attrs[0].ulValueLen
            || memcmp(x->pValue, attrs[0].pValue, x->ulValueLen) != 0) {
            ret = RET_OSSL_ERR;
            goto done;
        }

        x = p11prov_obj_get_attr(pub_key, CKA_PUBLIC_EXPONENT);
        if (!x || x->ulValueLen != attrs[1].ulValueLen
            || memcmp(x->pValue, attrs[1].pValue, x->ulValueLen) != 0) {
            ret = RET_OSSL_ERR;
            goto done;
        }

        ret = RET_OSSL_OK;
        break;
    case CKK_EC:
    case CKK_EC_EDWARDS:
        x = p11prov_obj_get_attr(pub_key, CKA_P11PROV_PUB_KEY);
        if (!x || x->ulValueLen != attrs[0].ulValueLen
            || memcmp(x->pValue, attrs[0].pValue, x->ulValueLen) != 0) {
            ret = RET_OSSL_ERR;
            goto done;
        }

        ret = RET_OSSL_OK;
        break;
    }

done:
    for (int i = 0; i < num; i++) {
        OPENSSL_free(attrs[i].pValue);
    }
    p11prov_obj_free(cert);
    return ret;
}

static int match_public_keys(P11PROV_OBJ *key1, P11PROV_OBJ *key2)
{
    P11PROV_OBJ *pub_key, *assoc_pub_key;
    P11PROV_OBJ *priv_key;
    int ret = RET_OSSL_ERR;

    /* avoid round-trip to HSM if keys have enough
     * attributes to do the logical comparison
     * CKK_RSA: MODULUS / PUBLIC_EXPONENT
     * CKK_EC: EC_POINT
     */
    ret = cmp_public_key_values(key1, key2);
    if (ret != RET_OSSL_ERR) {
        return ret;
    }

    /* one of the keys or both are private */
    if (key1->class == CKO_PUBLIC_KEY && key2->class == CKO_PRIVATE_KEY) {
        pub_key = key1;
        priv_key = key2;
    } else if (key1->class == CKO_PRIVATE_KEY
               && key2->class == CKO_PUBLIC_KEY) {
        pub_key = key2;
        priv_key = key1;
    } else {
        P11PROV_debug("We can't really match private keys");
        return RET_OSSL_ERR;
    }

    assoc_pub_key = p11prov_obj_find_associated(priv_key, CKO_PUBLIC_KEY);
    if (!assoc_pub_key) {
        P11PROV_raise(priv_key->ctx, CKR_GENERAL_ERROR,
                      "Could not find associated public key object");

        /* some tokens only store the public key in a cert and not in a
         * separate public key object */
        return match_key_with_cert(priv_key, pub_key);
    }

    if (assoc_pub_key->data.key.type != pub_key->data.key.type) {
        goto done;
    }

    ret = cmp_public_key_values(pub_key, assoc_pub_key);

done:
    p11prov_obj_free(assoc_pub_key);

    return ret;
}

static int p11prov_obj_get_ed_nid(CK_ATTRIBUTE *ecp)
{
    const unsigned char *val = ecp->pValue;
    ASN1_OBJECT *obj = d2i_ASN1_OBJECT(NULL, &val, ecp->ulValueLen);
    if (obj) {
        int nid = OBJ_obj2nid(obj);
        ASN1_OBJECT_free(obj);
        if (nid != NID_undef) {
            return nid;
        }
    }

    /* it might be the parameters are encoded printable string
     * for EdDSA which OpenSSL does not understand */
    if (ecp->ulValueLen == ED25519_EC_PARAMS_LEN
        && memcmp(ecp->pValue, ed25519_ec_params, ED25519_EC_PARAMS_LEN) == 0) {
        return NID_ED25519;
    } else if (ecp->ulValueLen == ED448_EC_PARAMS_LEN
               && memcmp(ecp->pValue, ed448_ec_params, ED448_EC_PARAMS_LEN)
                      == 0) {
        return NID_ED448;
    }
    return NID_undef;
}

int p11prov_obj_key_cmp(P11PROV_OBJ *key1, P11PROV_OBJ *key2, CK_KEY_TYPE type,
                        int cmp_type)
{
    int ret;

    /* immediate shortcircuit if it is the same handle */
    if (key1->slotid == key2->slotid && key1->handle == key2->handle) {
        return RET_OSSL_OK;
    }

    if (key1->class != CKO_PRIVATE_KEY && key1->class != CKO_PUBLIC_KEY) {
        /* not a key at all */
        return RET_OSSL_ERR;
    }
    if (key2->class != CKO_PRIVATE_KEY && key2->class != CKO_PUBLIC_KEY) {
        /* not a key at all */
        return RET_OSSL_ERR;
    }

    if (type != CK_UNAVAILABLE_INFORMATION && type != key1->data.key.type) {
        return RET_OSSL_ERR;
    }

    if (key1->data.key.type != key2->data.key.type) {
        return RET_OSSL_ERR;
    }

    if (key1->data.key.bit_size != key2->data.key.bit_size) {
        return RET_OSSL_ERR;
    }

    if (cmp_type & OBJ_CMP_KEY_PRIVATE) {
        if (key1->class != key2->class) {
            /* can't have private with differing key types */
            return RET_OSSL_ERR;
        }
        if (key1->class != CKO_PRIVATE_KEY) {
            return RET_OSSL_ERR;
        }
    }

    switch (key1->data.key.type) {
    case CKK_RSA:
        if (cmp_type & OBJ_CMP_KEY_PRIVATE) {
            /* unfortunately we can't really read private attributes
             * and there is no comparison function int he PKCS11 API.
             * Generally you do not have 2 identical keys stored in to two
             * separate objects so the initial shortcircuit that matches if
             * slotid/handle are identical will often cover this. When that
             * fails we have no option but to fail for now. */
            P11PROV_debug("We can't really match private keys");
            /* OTOH if modulus and exponent match either this is a broken key
             * or the private key must also match */
            cmp_type = OBJ_CMP_KEY_PUBLIC;
        }
        break;

    case CKK_EC:
        ret = cmp_attr(key1, key2, CKA_EC_PARAMS);
        if (ret != RET_OSSL_OK) {
            /* If EC_PARAMS do not match it may be due to encoding.
             * Fall back to slower conversions and compare via EC_GROUP */
            CK_ATTRIBUTE *ec_p;
            const unsigned char *val;
            EC_GROUP *group1 = NULL;
            EC_GROUP *group2 = NULL;
            BN_CTX *bnctx = NULL;

            ec_p = p11prov_obj_get_attr(key1, CKA_EC_PARAMS);
            if (!ec_p) {
                ret = RET_OSSL_ERR;
                goto out;
            }
            val = ec_p->pValue;
            group1 = d2i_ECPKParameters(NULL, &val, ec_p->ulValueLen);
            if (!group1) {
                ret = RET_OSSL_ERR;
                goto out;
            }

            ec_p = p11prov_obj_get_attr(key2, CKA_EC_PARAMS);
            if (!ec_p) {
                ret = RET_OSSL_ERR;
                goto out;
            }
            val = ec_p->pValue;
            group2 = d2i_ECPKParameters(NULL, &val, ec_p->ulValueLen);
            if (!group2) {
                ret = RET_OSSL_ERR;
                goto out;
            }

            bnctx = BN_CTX_new_ex(p11prov_ctx_get_libctx(key1->ctx));
            if (!bnctx) {
                ret = RET_OSSL_ERR;
                goto out;
            }

            ret = EC_GROUP_cmp(group1, group2, bnctx);
            if (ret == 0) {
                ret = RET_OSSL_OK;
            } else {
                ret = RET_OSSL_ERR;
            }

        out:
            EC_GROUP_free(group1);
            EC_GROUP_free(group2);
            BN_CTX_free(bnctx);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
        }
        if (cmp_type & OBJ_CMP_KEY_PRIVATE) {
            /* unfortunately we can't really read private attributes
             * and there is no comparison function int he PKCS11 API.
             * Generally you do not have 2 identical keys stored in to two
             * separate objects so the initial shortcircuit that matches if
             * slotid/handle are identical will often cover this. When that
             * fails we have no option but to fail for now. */
            P11PROV_debug("We can't really match private keys");
            /* OTOH if group and pub point match either this is a broken key
             * or the private key must also match */
            cmp_type = OBJ_CMP_KEY_PUBLIC;
        }
        break;
    case CKK_EC_EDWARDS:
        /* The EdDSA params can be encoded as printable string, which is
         * not recognized by OpenSSL and does not have respective EC_GROUP */
        ret = cmp_attr(key1, key2, CKA_EC_PARAMS);
        if (ret != RET_OSSL_OK) {
            /* If EC_PARAMS do not match it may be due to encoding. */
            CK_ATTRIBUTE *ec_p;
            int nid1;
            int nid2;

            ec_p = p11prov_obj_get_attr(key1, CKA_EC_PARAMS);
            if (!ec_p) {
                return RET_OSSL_ERR;
            }
            nid1 = p11prov_obj_get_ed_nid(ec_p);
            if (nid1 == NID_undef) {
                return RET_OSSL_ERR;
            }

            ec_p = p11prov_obj_get_attr(key2, CKA_EC_PARAMS);
            if (!ec_p) {
                return RET_OSSL_ERR;
            }
            nid2 = p11prov_obj_get_ed_nid(ec_p);
            if (nid2 == NID_undef) {
                return RET_OSSL_ERR;
            }
            if (nid1 != nid2) {
                return RET_OSSL_ERR;
            }
        }
        if (cmp_type & OBJ_CMP_KEY_PRIVATE) {
            /* unfortunately we can't really read private attributes
             * and there is no comparison function int he PKCS11 API.
             * Generally you do not have 2 identical keys stored in to two
             * separate objects so the initial shortcircuit that matches if
             * slotid/handle are identical will often cover this. When that
             * fails we have no option but to fail for now. */
            P11PROV_debug("We can't really match private keys");
            /* OTOH if group and pub point match either this is a broken key
             * or the private key must also match */
            cmp_type = OBJ_CMP_KEY_PUBLIC;
        }
        break;

    default:
        return RET_OSSL_ERR;
    }

    if (cmp_type & OBJ_CMP_KEY_PUBLIC) {
        ret = match_public_keys(key1, key2);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    /* if nothing fails it is a match */
    return RET_OSSL_OK;
}

static bool obj_match_attrs(P11PROV_OBJ *obj, CK_ATTRIBUTE *attrs, int numattrs)
{
    CK_ATTRIBUTE *x;
    for (int i = 0; i < numattrs; i++) {
        x = p11prov_obj_get_attr(obj, attrs[i].type);
        if (!x) {
            return false;
        }
        if (x->ulValueLen != attrs[i].ulValueLen) {
            return false;
        }
        if (memcmp(x->pValue, attrs[i].pValue, x->ulValueLen) != 0) {
            return false;
        }
    }
    /* match found */
    return true;
}

#define MAX_ATTRS_SIZE 4
struct pool_find_ctx {
    CK_KEY_TYPE type;
    CK_OBJECT_CLASS class;
    CK_ULONG key_size;
    CK_ULONG bit_size;
    CK_ATTRIBUTE attrs[MAX_ATTRS_SIZE];
    int numattrs;
    P11PROV_OBJ *found;
};

static bool pool_find_callback(void *pctx, P11PROV_OBJ_POOL *pool)
{
    struct pool_find_ctx *ctx = (struct pool_find_ctx *)pctx;
    P11PROV_OBJ *obj;
    CK_RV ret;

    if (!pool) {
        return false;
    }

    ret = MUTEX_LOCK(pool);
    if (ret != CKR_OK) {
        return false;
    }

    /* LOCKED SECTION ------------- */
    for (int i = 0; i < pool->num; i++) {
        obj = pool->objects[i];
        if (!obj) {
            continue;
        }
        if (obj->class != ctx->class) {
            continue;
        }
        if (obj->data.key.type != ctx->type) {
            continue;
        }
        if (obj->data.key.bit_size != ctx->bit_size) {
            continue;
        }
        if (obj_match_attrs(obj, ctx->attrs, ctx->numattrs)) {
            ctx->found = obj;
            break;
        }
    }

    (void)MUTEX_UNLOCK(pool);
    /* ------------- LOCKED SECTION */

    return (ctx->found != NULL);
}

static CK_RV param_to_attr(P11PROV_CTX *ctx, const OSSL_PARAM params[],
                           const char *param_key, CK_ATTRIBUTE *dst,
                           CK_ATTRIBUTE_TYPE type, bool byteswap)
{
    const OSSL_PARAM *p;
    CK_ATTRIBUTE tmp;
    CK_RV rv;

    p = OSSL_PARAM_locate_const(params, param_key);
    if (!p) {
        P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s", param_key);
        return CKR_KEY_INDIGESTIBLE;
    }
    tmp.type = type;
    tmp.ulValueLen = p->data_size;
    tmp.pValue = p->data;
    rv = p11prov_copy_attr(dst, &tmp);
    if (rv != CKR_OK) {
        P11PROV_raise(ctx, CKR_HOST_MEMORY, "No space for %s", param_key);
        return CKR_HOST_MEMORY;
    }
    if (byteswap) {
        byteswap_buf(dst->pValue, dst->pValue, dst->ulValueLen);
    }
    return CKR_OK;
}

static CK_RV prep_rsa_find(P11PROV_CTX *ctx, const OSSL_PARAM params[],
                           struct pool_find_ctx *findctx)
{
    data_buffer digest_data[5];
    data_buffer digest = { 0 };
    const OSSL_PARAM *p;
    size_t key_size;
    CK_RV rv;

    if (findctx->numattrs != MAX_ATTRS_SIZE) {
        return CKR_ARGUMENTS_BAD;
    }
    findctx->numattrs = 0;

    switch (findctx->class) {
    case CKO_PUBLIC_KEY:
        rv = param_to_attr(ctx, params, OSSL_PKEY_PARAM_RSA_N,
                           &findctx->attrs[0], CKA_MODULUS, true);
        if (rv != CKR_OK) {
            return rv;
        }
        findctx->numattrs++;
        key_size = findctx->attrs[0].ulValueLen;

        rv = param_to_attr(ctx, params, OSSL_PKEY_PARAM_RSA_E,
                           &findctx->attrs[1], CKA_PUBLIC_EXPONENT, true);
        if (rv != CKR_OK) {
            return rv;
        }
        findctx->numattrs++;
        break;
    case CKO_PRIVATE_KEY:
        /* A Token would never allow us to search by private exponent,
         * so we store a hash of the private key in CKA_ID */

        /* prefix */
        digest_data[0].data = (uint8_t *)"PrivKey";
        digest_data[0].length = 7;

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_RSA_N);
            return CKR_KEY_INDIGESTIBLE;
        }
        digest_data[1].data = p->data;
        digest_data[1].length = p->data_size;
        key_size = p->data_size;

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_RSA_E);
            return CKR_KEY_INDIGESTIBLE;
        }
        digest_data[2].data = p->data;
        digest_data[2].length = p->data_size;

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_RSA_D);
            return CKR_KEY_INDIGESTIBLE;
        }
        digest_data[3].data = p->data;
        digest_data[3].length = p->data_size;

        digest_data[4].data = NULL;

        rv = p11prov_digest_util(ctx, "sha256", NULL, digest_data, &digest);

        if (rv != CKR_OK) {
            return rv;
        }
        findctx->attrs[0].type = CKA_ID;
        findctx->attrs[0].pValue = digest.data;
        findctx->attrs[0].ulValueLen = digest.length;
        findctx->numattrs++;

        break;
    default:
        return CKR_GENERAL_ERROR;
    }

    findctx->key_size = key_size;
    findctx->bit_size = key_size * 8;

    return CKR_OK;
}

/* P-521 ~ 133 bytes, this should suffice */
#define MAX_EC_PUB_KEY_SIZE 150
static CK_RV prep_ec_find(P11PROV_CTX *ctx, const OSSL_PARAM params[],
                          struct pool_find_ctx *findctx)
{
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BN_CTX *bn_ctx = NULL;

    OSSL_PARAM tmp;
    const OSSL_PARAM *p;
    OSSL_PARAM pub_key[2] = { 0 };
    uint8_t pub_data[MAX_EC_PUB_KEY_SIZE];

    data_buffer digest_data[5];
    data_buffer digest = { 0 };

    const char *curve_name = NULL;
    int curve_nid;
    unsigned char *ecparams = NULL;
    int len, i;
    CK_RV rv;

    if (findctx->numattrs != MAX_ATTRS_SIZE) {
        return CKR_ARGUMENTS_BAD;
    }
    findctx->numattrs = 0;

    group = EC_GROUP_new_from_params(params, p11prov_ctx_get_libctx(ctx), NULL);
    if (!group) {
        P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Unable to decode ec group");
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    curve_nid = EC_GROUP_get_curve_name(group);
    if (curve_nid != NID_undef) {
        curve_name = OSSL_EC_curve_nid2name(curve_nid);
        if (!curve_name) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Unknown curve");
            rv = CKR_KEY_INDIGESTIBLE;
            goto done;
        }
    }

    len = i2d_ECPKParameters(group, &ecparams);
    if (len < 0) {
        P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Failed to encode EC params");
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    switch (findctx->class) {
    case CKO_PUBLIC_KEY:
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_PUB_KEY);
            EC_GROUP_free(group);
            rv = CKR_KEY_INDIGESTIBLE;
            goto done;
        }

        /* Providers may export in any format - OpenSSL < 3.0.8
         * ignores the "point-format" OSSL_PARAM and unconditionally uses
         * compressed format:
         * - https://github.com/openssl/openssl/pull/16624
         * - https://github.com/openssl/openssl/issues/16595
         *
         * Convert from compressed to uncompressed if necessary
         */
        if (((char *)p->data)[0] == '\x02' || ((char *)p->data)[0] == '\x03') {
            int ret, plen;

            P11PROV_debug(
                "OpenSSL 3.0.7 BUG - received compressed EC public key");
            pub_key[0].key = OSSL_PKEY_PARAM_PUB_KEY;
            pub_key[0].data_type = p->data_type;
            pub_key[0].data = pub_data;

            point = EC_POINT_new(group);
            bn_ctx = BN_CTX_new();
            ret =
                EC_POINT_oct2point(group, point, p->data, p->data_size, bn_ctx);
            if (!ret) {
                rv = CKR_KEY_INDIGESTIBLE;
                goto done;
            }

            plen = EC_POINT_point2oct(
                group, point, POINT_CONVERSION_UNCOMPRESSED, pub_key[0].data,
                MAX_EC_PUB_KEY_SIZE, bn_ctx);
            if (!plen) {
                rv = CKR_KEY_INDIGESTIBLE;
                goto done;
            }

            pub_key[0].data_size = plen;
            rv = param_to_attr(ctx, pub_key, OSSL_PKEY_PARAM_PUB_KEY,
                               &findctx->attrs[0], CKA_P11PROV_PUB_KEY, false);
            if (rv != CKR_OK) {
                goto done;
            }
        } else {
            rv = param_to_attr(ctx, params, OSSL_PKEY_PARAM_PUB_KEY,
                               &findctx->attrs[0], CKA_P11PROV_PUB_KEY, false);
            if (rv != CKR_OK) {
                goto done;
            }
        }

        findctx->numattrs++;

        break;
    case CKO_PRIVATE_KEY:
        /* A Token would never allow us to search by private exponent,
         * so we store a hash of the private key in CKA_ID */
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_PRIV_KEY);
            return CKR_KEY_INDIGESTIBLE;
        }

        i = 0;

        /* prefix */
        digest_data[i].data = (uint8_t *)"PrivKey";
        digest_data[i].length = 7;
        i++;

        if (curve_name) {
            digest_data[i].data = (uint8_t *)curve_name;
            digest_data[i].length = strlen(curve_name);
            i++;
        }

        digest_data[i].data = ecparams;
        digest_data[i].length = len;
        i++;

        digest_data[i].data = p->data;
        digest_data[i].length = p->data_size;
        i++;

        digest_data[i].data = NULL;

        rv = p11prov_digest_util(ctx, "sha256", NULL, digest_data, &digest);
        if (rv != CKR_OK) {
            return rv;
        }
        findctx->attrs[0].type = CKA_ID;
        findctx->attrs[0].pValue = digest.data;
        findctx->attrs[0].ulValueLen = digest.length;
        findctx->numattrs++;

        break;
    default:
        return CKR_GENERAL_ERROR;
    }

    /* common params */
    tmp.key = "EC Params";
    tmp.data = ecparams;
    tmp.data_size = len;
    rv = param_to_attr(ctx, &tmp, tmp.key, &findctx->attrs[findctx->numattrs],
                       CKA_EC_PARAMS, false);
    if (rv != CKR_OK) {
        goto done;
    }
    findctx->numattrs++;

    tmp.key = "EC Group";
    tmp.data = &curve_nid;
    tmp.data_size = sizeof(curve_nid);
    rv = param_to_attr(ctx, &tmp, tmp.key, &findctx->attrs[findctx->numattrs],
                       CKA_P11PROV_CURVE_NID, false);
    if (rv != CKR_OK) {
        goto done;
    }
    findctx->numattrs++;

    if (curve_name) {
        tmp.key = "EC Curve Name";
        tmp.data = (void *)curve_name;
        tmp.data_size = strlen(curve_name) + 1;
        rv = param_to_attr(ctx, &tmp, tmp.key,
                           &findctx->attrs[findctx->numattrs],
                           CKA_P11PROV_CURVE_NAME, false);
        if (rv != CKR_OK) {
            goto done;
        }
        findctx->numattrs++;
    }

    findctx->bit_size = EC_GROUP_order_bits(group);
    findctx->key_size = (findctx->bit_size + 7) / 8;
    rv = CKR_OK;

done:
    OPENSSL_free(ecparams);
    EC_GROUP_free(group);
    EC_POINT_free(point);
    BN_CTX_free(bn_ctx);
    return rv;
}

static CK_RV prep_ed_find(P11PROV_CTX *ctx, const OSSL_PARAM params[],
                          struct pool_find_ctx *findctx)
{
    OSSL_PARAM tmp;
    const OSSL_PARAM *p;

    data_buffer digest_data[4];
    data_buffer digest = { 0 };

    const unsigned char *ecparams = NULL;
    int len, i;
    CK_RV rv;

    if (findctx->numattrs != MAX_ATTRS_SIZE) {
        return CKR_ARGUMENTS_BAD;
    }
    findctx->numattrs = 0;

    switch (findctx->class) {
    case CKO_PUBLIC_KEY:
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_PUB_KEY);
            rv = CKR_KEY_INDIGESTIBLE;
            goto done;
        }

        if (p->data_size == ED25519_BYTE_SIZE) {
            ecparams = ed25519_ec_params;
            len = ED25519_EC_PARAMS_LEN;
            findctx->bit_size = ED25519_BIT_SIZE;
            findctx->key_size = ED25519_BYTE_SIZE;
        } else if (p->data_size == ED448_BYTE_SIZE) {
            ecparams = ed448_ec_params;
            len = ED448_EC_PARAMS_LEN;
            findctx->bit_size = ED448_BIT_SIZE;
            findctx->key_size = ED448_BYTE_SIZE;
        } else {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE,
                          "Public key of unknown length %lu", p->data_size);
            rv = CKR_KEY_INDIGESTIBLE;
            goto done;
        }

        rv = param_to_attr(ctx, params, OSSL_PKEY_PARAM_PUB_KEY,
                           &findctx->attrs[0], CKA_P11PROV_PUB_KEY, false);
        if (rv != CKR_OK) {
            goto done;
        }

        findctx->numattrs++;

        break;
    case CKO_PRIVATE_KEY:
        /* A Token would never allow us to search by private exponent,
         * so we store a hash of the private key in CKA_ID */
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_PRIV_KEY);
            return CKR_KEY_INDIGESTIBLE;
        }

        i = 0;

        if (p->data_size == ED25519_BYTE_SIZE) {
            ecparams = ed25519_ec_params;
            len = ED25519_EC_PARAMS_LEN;
            findctx->bit_size = ED25519_BIT_SIZE;
            findctx->key_size = ED25519_BYTE_SIZE;
        } else if (p->data_size == ED448_BYTE_SIZE) {
            ecparams = ed448_ec_params;
            len = ED448_EC_PARAMS_LEN;
            findctx->bit_size = ED448_BIT_SIZE;
            findctx->key_size = ED448_BYTE_SIZE;
        } else {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE,
                          "Private key of unknown length %lu", p->data_size);
            rv = CKR_KEY_INDIGESTIBLE;
            goto done;
        }

        /* prefix */
        digest_data[i].data = (uint8_t *)"PrivKey";
        digest_data[i].length = 7;
        i++;

        digest_data[i].data = (CK_BYTE *)ecparams;
        digest_data[i].length = len;
        i++;

        digest_data[i].data = p->data;
        digest_data[i].length = p->data_size;
        i++;

        digest_data[i].data = NULL;

        rv = p11prov_digest_util(ctx, "sha256", NULL, digest_data, &digest);
        if (rv != CKR_OK) {
            return rv;
        }
        findctx->attrs[0].type = CKA_ID;
        findctx->attrs[0].pValue = digest.data;
        findctx->attrs[0].ulValueLen = digest.length;
        findctx->numattrs++;

        break;
    default:
        return CKR_GENERAL_ERROR;
    }

    /* common params */
    tmp.key = "EC Params";
    tmp.data = (CK_BYTE *)ecparams;
    tmp.data_size = len;
    rv = param_to_attr(ctx, &tmp, tmp.key, &findctx->attrs[findctx->numattrs],
                       CKA_EC_PARAMS, false);
    if (rv != CKR_OK) {
        goto done;
    }
    findctx->numattrs++;
    rv = CKR_OK;

done:
    return rv;
}

static CK_RV return_dup_key(P11PROV_OBJ *dst, P11PROV_OBJ *src)
{
    CK_RV rv;

    P11PROV_debug("duplicating obj key (dst=%p, src=%p, handle=%lu, "
                  "slotid=%lu, raf=%d, numattrs=%d)",
                  dst, src, src->handle, src->slotid, src->raf, src->numattrs);

    dst->slotid = src->slotid;
    dst->handle = src->handle;
    dst->class = src->class;
    dst->cka_copyable = src->cka_copyable;
    dst->cka_token = src->cka_token;
    dst->data.key = src->data.key;

    /* Free existing attributes if any */
    for (int i = 0; i < dst->numattrs; i++) {
        OPENSSL_free(dst->attrs[i].pValue);
    }
    OPENSSL_free(dst->attrs);

    dst->attrs = OPENSSL_zalloc(sizeof(CK_ATTRIBUTE) * src->numattrs);
    if (!dst->attrs) {
        rv = CKR_HOST_MEMORY;
        P11PROV_raise(dst->ctx, rv, "Failed allocation");
        return rv;
    }
    dst->numattrs = 0;
    for (int i = 0; i < src->numattrs; i++) {
        rv = p11prov_copy_attr(&dst->attrs[i], &src->attrs[i]);
        if (rv != CKR_OK) {
            rv = CKR_HOST_MEMORY;
            P11PROV_raise(dst->ctx, rv, "Failed attr copy");
            return rv;
        }
        dst->numattrs++;
    }

    return CKR_OK;
}

static CK_RV fix_ec_key_import(P11PROV_OBJ *key, int allocattrs)
{
    CK_ATTRIBUTE *pub;
    ASN1_OCTET_STRING oct;
    unsigned char *der = NULL;
    int len;

    if (key->numattrs >= allocattrs) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR,
                      "Too many attributes?? %d >= %d", key->numattrs,
                      allocattrs);
        return CKR_GENERAL_ERROR;
    }

    pub = p11prov_obj_get_attr(key, CKA_P11PROV_PUB_KEY);
    if (!pub) {
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE, "No public key found");
        return CKR_KEY_INDIGESTIBLE;
    }

    oct.data = pub->pValue;
    oct.length = pub->ulValueLen;
    oct.flags = 0;

    len = i2d_ASN1_OCTET_STRING(&oct, &der);
    if (len < 0) {
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Failure to encode EC point to DER");
        return CKR_KEY_INDIGESTIBLE;
    }
    key->attrs[key->numattrs].type = CKA_EC_POINT;
    key->attrs[key->numattrs].pValue = der;
    key->attrs[key->numattrs].ulValueLen = len;
    key->numattrs++;

    P11PROV_debug("fixing EC key %p import", key);

    return CKR_OK;
}

static CK_RV p11prov_obj_import_public_key(P11PROV_OBJ *key, CK_KEY_TYPE type,
                                           const OSSL_PARAM params[])
{
    P11PROV_CTX *ctx;
    struct pool_find_ctx findctx = {
        .type = type,
        .class = CKO_PUBLIC_KEY,
        .bit_size = 0,
        .attrs = { { 0 } },
        .numattrs = MAX_ATTRS_SIZE,
        .found = NULL,
    };
    int allocattrs = 0;
    CK_RV rv;

    ctx = p11prov_obj_get_prov_ctx(key);
    if (!ctx) {
        return CKR_GENERAL_ERROR;
    }

    switch (type) {
    case CKK_RSA:
        P11PROV_debug("obj import of RSA public key %p", key);
        rv = prep_rsa_find(ctx, params, &findctx);
        if (rv != CKR_OK) {
            goto done;
        }
        allocattrs = RSA_ATTRS_NUM;
        break;

    case CKK_EC:
        P11PROV_debug("obj import of EC public key %p", key);
        rv = prep_ec_find(ctx, params, &findctx);
        if (rv != CKR_OK) {
            goto done;
        }
        allocattrs = EC_ATTRS_NUM;
        break;

    case CKK_EC_EDWARDS:
        P11PROV_debug("obj import of ED public key %p", key);
        rv = prep_ed_find(ctx, params, &findctx);
        if (rv != CKR_OK) {
            goto done;
        }
        allocattrs = EC_ATTRS_NUM;
        break;

    default:
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Unsupported key type: %08lx", type);
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    if (allocattrs < findctx.numattrs) {
        allocattrs = findctx.numattrs;
    }

    /* A common case with openssl is the request to import a key we already
     * actually have on the token. This happens because OpenSSL is greedy
     * and tries to export keys to its default provider before it even knows
     * what kind of operation it needs to do. Sometimes the operation ends up
     * being something that needs to be performed on the token. So try to see
     * if we already have this key */
    rv = p11prov_slot_find_obj_pool(ctx, pool_find_callback, &findctx);
    if (rv != CKR_OK) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR, "Failed to search pools");
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    if (findctx.found) {
        rv = return_dup_key(key, findctx.found);
        goto done;
    }

    /*
     * FIXME:
     * For things like ECDH we can get away with a mock object that just holds
     * data for now, but is not backed by an actual handle and key in the token.
     * Once this is not sufficient, we'll probably need to change functions to
     * pass in a valid session when requesting a handle from an object, so that
     * the key can be imported on the fly in the correct slot at the time the
     * operation needs to be performed.
     */
    P11PROV_debug("public key %p not found in the pool - using mock", key);

    /* move data */
    key->class = findctx.class;
    key->data.key.type = findctx.type;
    key->data.key.size = findctx.key_size;
    key->data.key.bit_size = findctx.bit_size;
    key->attrs = OPENSSL_malloc(sizeof(CK_ATTRIBUTE) * allocattrs);
    if (!key->attrs) {
        P11PROV_raise(key->ctx, CKR_HOST_MEMORY, "Failed allocation");
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    for (int i = 0; i < findctx.numattrs; i++) {
        key->attrs[i] = findctx.attrs[i];
        findctx.attrs[i].pValue = NULL;
    }
    key->numattrs = findctx.numattrs;
    findctx.numattrs = 0;

    if (type == CKK_EC || type == CKK_EC_EDWARDS) {
        rv = fix_ec_key_import(key, allocattrs);
    }

done:
    for (int i = 0; i < findctx.numattrs; i++) {
        OPENSSL_free(findctx.attrs[i].pValue);
    }
    return rv;
}

static CK_RV p11prov_store_rsa_public_key(P11PROV_OBJ *key)
{
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_false = CK_FALSE;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &key->class, sizeof(CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &key->data.key.type, sizeof(CK_KEY_TYPE) },
        /* we allow all operations as we do not know what is
         * the purpose of this key at import time */
        { CKA_ENCRYPT, &val_true, sizeof(val_true) },
        { CKA_VERIFY, &val_true, sizeof(val_true) },
        { CKA_WRAP, &val_true, sizeof(val_true) },
        /* public key part */
        { CKA_MODULUS, NULL, 0 }, /* 5 */
        { CKA_PUBLIC_EXPONENT, NULL, 0 }, /* 6 */
        /* TODO RSA PSS Params */
        { CKA_TOKEN, &val_false, sizeof(val_false) },
    };
    int na = sizeof(template) / sizeof(CK_ATTRIBUTE);
    CK_ATTRIBUTE *a;
    P11PROV_SLOTS_CTX *slots = NULL;
    CK_SLOT_ID slot = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SESSION *session = NULL;
    CK_RV rv = CKR_GENERAL_ERROR;

    a = p11prov_obj_get_attr(key, CKA_MODULUS);
    if (!a) {
        return CKR_GENERAL_ERROR;
    }
    template[5].pValue = a->pValue;
    template[5].ulValueLen = a->ulValueLen;

    a = p11prov_obj_get_attr(key, CKA_PUBLIC_EXPONENT);
    if (!a) {
        return CKR_GENERAL_ERROR;
    }
    template[6].pValue = a->pValue;
    template[6].ulValueLen = a->ulValueLen;

    slots = p11prov_ctx_get_slots(key->ctx);
    if (!slots) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    slot = p11prov_get_default_slot(slots);
    if (slot == CK_UNAVAILABLE_INFORMATION) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rv = p11prov_take_login_session(key->ctx, slot, &session);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_CreateObject(key->ctx, p11prov_session_handle(session),
                              template, na, &key->handle);
    if (rv != CKR_OK) {
        goto done;
    }

    key->slotid = slot;

    rv = CKR_OK;

done:
    p11prov_return_session(session);
    return rv;
}

static CK_RV p11prov_store_ec_public_key(P11PROV_OBJ *key)
{
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_false = CK_FALSE;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &key->class, sizeof(CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &key->data.key.type, sizeof(CK_KEY_TYPE) },
        /* we allow all operations as we do not know what is
         * the purpose of this key at import time */
        { CKA_DERIVE, &val_true, sizeof(val_true) },
        { CKA_VERIFY, &val_true, sizeof(val_true) },
        /* public part */
        { CKA_EC_PARAMS, NULL, 0 }, /* 4 */
        { CKA_EC_POINT, NULL, 0 }, /* 5 */
        { CKA_TOKEN, &val_false, sizeof(val_false) },
    };
    int na = sizeof(template) / sizeof(CK_ATTRIBUTE);
    CK_ATTRIBUTE *a;
    P11PROV_SLOTS_CTX *slots = NULL;
    CK_SLOT_ID slot = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SESSION *session = NULL;
    CK_RV rv = CKR_GENERAL_ERROR;

    a = p11prov_obj_get_attr(key, CKA_EC_PARAMS);
    if (!a) {
        return CKR_GENERAL_ERROR;
    }
    template[4].pValue = a->pValue;
    template[4].ulValueLen = a->ulValueLen;

    a = p11prov_obj_get_attr(key, CKA_EC_POINT);
    if (!a) {
        return CKR_GENERAL_ERROR;
    }
    template[5].pValue = a->pValue;
    template[5].ulValueLen = a->ulValueLen;

    slots = p11prov_ctx_get_slots(key->ctx);
    if (!slots) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    slot = p11prov_get_default_slot(slots);
    if (slot == CK_UNAVAILABLE_INFORMATION) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rv = p11prov_take_login_session(key->ctx, slot, &session);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_CreateObject(key->ctx, p11prov_session_handle(session),
                              template, na, &key->handle);
    if (rv != CKR_OK) {
        goto done;
    }

    key->slotid = slot;
    rv = CKR_OK;

done:
    p11prov_return_session(session);
    return rv;
}

static CK_RV p11prov_obj_store_public_key(P11PROV_OBJ *key)
{
    int rv;

    P11PROV_debug("Store imported public key=%p", key);

    if (key->class != CKO_PUBLIC_KEY) {
        P11PROV_raise(key->ctx, CKR_OBJECT_HANDLE_INVALID, "Invalid key type");
        return CKR_OBJECT_HANDLE_INVALID;
    }

    switch (key->data.key.type) {
    case CKK_RSA:
        rv = p11prov_store_rsa_public_key(key);
        break;
    case CKK_EC:
    case CKK_EC_EDWARDS:
        rv = p11prov_store_ec_public_key(key);
        break;

    default:
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR,
                      "Unsupported key type: %08lx, should NOT happen",
                      key->data.key.type);
        rv = CKR_GENERAL_ERROR;
    }

    if (rv == CKR_OK) {
        /* this is a real object now, add it to the pool, but do not
         * fail if the operation goes haywire for some reason */
        (void)obj_add_to_pool(key);
    }

    return rv;
}

static CK_RV get_bn(const OSSL_PARAM *p, CK_ATTRIBUTE *attr)
{
    BIGNUM *bn = NULL;
    int bnlen;
    int err = 0;
    CK_RV ret;

    if (p == NULL) {
        return CKR_KEY_INDIGESTIBLE;
    }

    /* FIXME: investigate if this needs to be done in constant time
     * See BN_FLG_CONSTTIME */

    err = OSSL_PARAM_get_BN(p, &bn);
    if (err != RET_OSSL_OK) {
        return CKR_KEY_INDIGESTIBLE;
    }

    bnlen = BN_num_bytes(bn);
    attr->pValue = OPENSSL_malloc(bnlen);
    if (!attr->pValue) {
        ret = CKR_HOST_MEMORY;
        goto done;
    }
    attr->ulValueLen = BN_bn2bin(bn, attr->pValue);
    if (attr->ulValueLen == 0 || attr->ulValueLen > bnlen) {
        attr->ulValueLen = bnlen;
        ret = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    ret = CKR_OK;

done:
    if (ret != CKR_OK) {
        OPENSSL_clear_free(attr->pValue, bnlen);
        attr->pValue = NULL;
    }
    BN_free(bn);
    return ret;
}

static CK_RV p11prov_store_rsa_private_key(P11PROV_OBJ *key,
                                           struct pool_find_ctx *findctx,
                                           const OSSL_PARAM params[])
{
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_false = CK_FALSE;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &findctx->class, sizeof(CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &findctx->type, sizeof(CK_KEY_TYPE) },
        { CKA_ID, findctx->attrs[0].pValue,
          findctx->attrs[0].ulValueLen }, /* 2 */
        { CKA_SENSITIVE, &val_true, sizeof(val_true) },
        { CKA_EXTRACTABLE, &val_false, sizeof(val_false) },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
        /* we allow all operations as we do not know what is
         * the purpose of this key at import time */
        { CKA_DECRYPT, &val_true, sizeof(val_true) },
        { CKA_SIGN, &val_true, sizeof(val_true) },
        { CKA_UNWRAP, &val_true, sizeof(val_true) },
        /* public key part */
        { CKA_MODULUS, NULL, 0 }, /* 9 */
        { CKA_PUBLIC_EXPONENT, NULL, 0 }, /* 10 */
        /* private key part */
        { CKA_PRIVATE_EXPONENT, NULL, 0 },
        { CKA_PRIME_1, NULL, 0 }, /* optional from here */
        { CKA_PRIME_2, NULL, 0 },
        { CKA_EXPONENT_1, NULL, 0 },
        { CKA_EXPONENT_2, NULL, 0 },
        { CKA_COEFFICIENT, NULL, 0 },
        /* TODO RSA PSS Params */
    };
    int na = 9; /* minimum will be 12, up to 17 */
    const char *required[] = {
        OSSL_PKEY_PARAM_RSA_N,
        OSSL_PKEY_PARAM_RSA_E,
        OSSL_PKEY_PARAM_RSA_D,
    };
    const char *optional[] = {
        OSSL_PKEY_PARAM_RSA_FACTOR1,      OSSL_PKEY_PARAM_RSA_FACTOR2,
        OSSL_PKEY_PARAM_RSA_EXPONENT1,    OSSL_PKEY_PARAM_RSA_EXPONENT2,
        OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
    };
    const OSSL_PARAM *p;
    P11PROV_SLOTS_CTX *slots = NULL;
    CK_SLOT_ID slot = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SESSION *session = NULL;
    CK_RV rv = CKR_GENERAL_ERROR;

    /* required params */
    for (int i = 0; i < 3; i++) {
        p = OSSL_PARAM_locate_const(params, required[i]);
        rv = get_bn(p, &template[na]);
        if (rv != CKR_OK) {
            goto done;
        }
        na++;
    }

    /* optional */
    for (int i = 0; i < 5; i++) {
        p = OSSL_PARAM_locate_const(params, optional[i]);
        if (p) {
            rv = get_bn(p, &template[na]);
            if (rv == CKR_OK) {
                na++;
            }
        } else {
            /* we must have all or none of the optional,
             * if any is missing we pretend none of them were given */
            for (; i >= 0; i--) {
                na--;
                OPENSSL_clear_free(template[na].pValue,
                                   template[na].ulValueLen);
            }
            break;
        }
    }

    slots = p11prov_ctx_get_slots(key->ctx);
    if (!slots) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    slot = p11prov_get_default_slot(slots);
    if (slot == CK_UNAVAILABLE_INFORMATION) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rv = p11prov_take_login_session(key->ctx, slot, &session);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_CreateObject(key->ctx, p11prov_session_handle(session),
                              template, na, &key->handle);
    if (rv != CKR_OK) {
        goto done;
    }

    key->slotid = slot;
    key->class = findctx->class;
    key->data.key.type = findctx->type;
    key->data.key.size = findctx->key_size;
    key->data.key.bit_size = findctx->bit_size;
    key->attrs = OPENSSL_zalloc(sizeof(CK_ATTRIBUTE) * 3);
    if (!key->attrs) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    key->numattrs = 0;
    /* cka_id */
    rv = p11prov_copy_attr(&key->attrs[key->numattrs], &template[2]);
    if (rv != CKR_OK) {
        goto done;
    }
    key->numattrs += 1;
    /* steal modulus */
    key->attrs[key->numattrs] = template[9];
    template[9].pValue = NULL;
    key->numattrs += 1;
    /* steal public exponent */
    key->attrs[key->numattrs] = template[10];
    template[10].pValue = NULL;
    key->numattrs += 1;

    rv = CKR_OK;

done:
    p11prov_return_session(session);
    for (int i = 9; i < na; i++) {
        OPENSSL_clear_free(template[i].pValue, template[i].ulValueLen);
    }
    return rv;
}

static CK_RV p11prov_store_ec_private_key(P11PROV_OBJ *key,
                                          struct pool_find_ctx *findctx,
                                          const OSSL_PARAM params[])
{
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_false = CK_FALSE;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &findctx->class, sizeof(CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &findctx->type, sizeof(CK_KEY_TYPE) },
        { CKA_ID, findctx->attrs[0].pValue,
          findctx->attrs[0].ulValueLen }, /* 2 */
        { CKA_SENSITIVE, &val_true, sizeof(val_true) },
        { CKA_EXTRACTABLE, &val_false, sizeof(val_false) },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
        /* we allow all operations as we do not know what is
         * the purpose of this key at import time */
        { CKA_DERIVE, &val_true, sizeof(val_true) },
        { CKA_SIGN, &val_true, sizeof(val_true) },
        /* public part */
        { CKA_EC_PARAMS, findctx->attrs[1].pValue,
          findctx->attrs[1].ulValueLen }, /* 8 */
        /* private key part */
        { CKA_VALUE, NULL, 0 }, /* 9 */
    };
    int na = 10;
    const OSSL_PARAM *p;
    P11PROV_SLOTS_CTX *slots = NULL;
    CK_SLOT_ID slot = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SESSION *session = NULL;
    CK_RV rv = CKR_GENERAL_ERROR;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    rv = get_bn(p, &template[9]);
    if (rv != CKR_OK) {
        goto done;
    }

    slots = p11prov_ctx_get_slots(key->ctx);
    if (!slots) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    slot = p11prov_get_default_slot(slots);
    if (slot == CK_UNAVAILABLE_INFORMATION) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rv = p11prov_take_login_session(key->ctx, slot, &session);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_CreateObject(key->ctx, p11prov_session_handle(session),
                              template, na, &key->handle);
    if (rv != CKR_OK) {
        goto done;
    }

    key->slotid = slot;
    key->class = findctx->class;
    key->data.key.type = findctx->type;
    key->data.key.size = findctx->key_size;
    key->data.key.bit_size = findctx->bit_size;
    key->attrs = OPENSSL_zalloc(sizeof(CK_ATTRIBUTE) * findctx->numattrs);
    if (!key->attrs) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    key->numattrs = 0;
    for (int i = 0; i < findctx->numattrs; i++) {
        rv = p11prov_copy_attr(&key->attrs[i], &findctx->attrs[i]);
        if (rv != CKR_OK) {
            rv = CKR_HOST_MEMORY;
            P11PROV_raise(key->ctx, rv, "Failed attr copy");
            goto done;
        }
        key->numattrs++;
    }

    rv = CKR_OK;

done:
    p11prov_return_session(session);
    OPENSSL_clear_free(template[9].pValue, template[9].ulValueLen);
    return rv;
}

static CK_RV p11prov_obj_import_private_key(P11PROV_OBJ *key, CK_KEY_TYPE type,
                                            const OSSL_PARAM params[])
{
    P11PROV_CTX *ctx;
    struct pool_find_ctx findctx = {
        .type = type,
        .class = CKO_PRIVATE_KEY,
        .attrs = { { 0 } },
        .numattrs = MAX_ATTRS_SIZE,
        .found = NULL,
    };
    CK_RV rv;

    ctx = p11prov_obj_get_prov_ctx(key);
    if (!ctx) {
        return CKR_GENERAL_ERROR;
    }

    switch (type) {
    case CKK_RSA:
        rv = prep_rsa_find(ctx, params, &findctx);
        if (rv != CKR_OK) {
            goto done;
        }
        break;

    case CKK_EC:
        rv = prep_ec_find(ctx, params, &findctx);
        if (rv != CKR_OK) {
            goto done;
        }
        break;

    case CKK_EC_EDWARDS:
        rv = prep_ed_find(ctx, params, &findctx);
        if (rv != CKR_OK) {
            goto done;
        }
        break;

    default:
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Unsupported key type: %08lx", type);
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    /* The only case for private keys is an application loading a key from
     * a file or other mean and then asking (explicitly or implicitly) a
     * pkcs11-provider mechanism to use it. There is no other case because
     * tokens do not allow to export private keys.
     *
     * However we may have had the request to load this key before so we
     * still need to check if we have previously uploaded this key as a
     * session key before. If not we will compute a hash of the private
     * key to store in CKA_ID for future lockup and store it in the token
     * on the long lived login session.
     */
    rv = p11prov_slot_find_obj_pool(ctx, pool_find_callback, &findctx);
    if (rv != CKR_OK) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR, "Failed to search pools");
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    if (findctx.found) {
        rv = return_dup_key(key, findctx.found);
        goto done;
    }

    /*
     * No cached object found, create a session key on the login session so
     * that its handle will live long enough for multiple operations.
     */

    switch (type) {
    case CKK_RSA:
        rv = p11prov_store_rsa_private_key(key, &findctx, params);
        break;
    case CKK_EC:
    case CKK_EC_EDWARDS:
        rv = p11prov_store_ec_private_key(key, &findctx, params);
        break;

    default:
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR,
                      "Unsupported key type: %08lx, should NOT happen", type);
        rv = CKR_GENERAL_ERROR;
    }

done:
    for (int i = 0; i < findctx.numattrs; i++) {
        OPENSSL_free(findctx.attrs[i].pValue);
    }
    return rv;
}

static CK_RV import_ec_params(P11PROV_OBJ *key, const OSSL_PARAM params[])
{
    P11PROV_CTX *ctx;
    EC_GROUP *group = NULL;
    const char *curve_name = NULL;
    int curve_nid;
    unsigned char *ecparams = NULL;
    CK_ATTRIBUTE *cka_ec_params;
    CK_ATTRIBUTE *cka_nid;
    CK_ATTRIBUTE *cka_name;
    CK_ATTRIBUTE tmp;
    int add_attrs = 0;
    int len;
    CK_RV rv;

    ctx = p11prov_obj_get_prov_ctx(key);
    if (!ctx) {
        return CKR_GENERAL_ERROR;
    }

    group = EC_GROUP_new_from_params(params, p11prov_ctx_get_libctx(ctx), NULL);
    if (!group) {
        P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Unable to decode ec group");
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    curve_nid = EC_GROUP_get_curve_name(group);
    if (curve_nid != NID_undef) {
        curve_name = OSSL_EC_curve_nid2name(curve_nid);
        if (!curve_name) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Unknown curve");
            rv = CKR_KEY_INDIGESTIBLE;
            goto done;
        }
    }

    len = i2d_ECPKParameters(group, &ecparams);
    if (len < 0) {
        P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Failed to encode EC params");
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    cka_ec_params = p11prov_obj_get_attr(key, CKA_EC_PARAMS);
    if (!cka_ec_params) {
        add_attrs += 1;
    }

    cka_nid = p11prov_obj_get_attr(key, CKA_P11PROV_CURVE_NID);
    if (!cka_nid) {
        add_attrs += 1;
    }

    cka_name = p11prov_obj_get_attr(key, CKA_P11PROV_CURVE_NAME);
    if (!cka_name && curve_name) {
        add_attrs += 1;
    }

    if (add_attrs > 0) {
        void *tmp_ptr;
        tmp_ptr = OPENSSL_realloc(
            key->attrs, sizeof(CK_ATTRIBUTE) * (key->numattrs + add_attrs));
        if (!tmp_ptr) {
            rv = CKR_HOST_MEMORY;
            goto done;
        }
        key->attrs = tmp_ptr;
    }

    /* EC Params */
    if (cka_ec_params) {
        OPENSSL_free(cka_ec_params->pValue);
    } else {
        cka_ec_params = &key->attrs[key->numattrs];
        key->numattrs++;
    }
    cka_ec_params->type = CKA_EC_PARAMS;
    cka_ec_params->pValue = ecparams;
    ecparams = NULL;
    cka_ec_params->ulValueLen = len;

    /* Curve Nid */
    if (cka_nid) {
        OPENSSL_free(cka_nid->pValue);
    } else {
        cka_nid = &key->attrs[key->numattrs];
        key->numattrs++;
    }
    cka_nid->pValue = NULL;
    tmp.type = CKA_P11PROV_CURVE_NID;
    tmp.pValue = &curve_nid;
    tmp.ulValueLen = sizeof(curve_nid);
    rv = p11prov_copy_attr(cka_nid, &tmp);
    if (rv != CKR_OK) {
        goto done;
    }

    /* Curve name */
    if (cka_name) {
        OPENSSL_free(cka_name->pValue);
        cka_name->type = CK_UNAVAILABLE_INFORMATION;
        cka_name->pValue = NULL;
        cka_name->ulValueLen = 0;
    }
    if (curve_name) {
        if (!cka_name) {
            cka_name = &key->attrs[key->numattrs];
            key->numattrs++;
        }
        tmp.type = CKA_P11PROV_CURVE_NAME;
        tmp.pValue = (void *)curve_name;
        tmp.ulValueLen = strlen(curve_name) + 1;
        rv = p11prov_copy_attr(cka_name, &tmp);
        if (rv != CKR_OK) {
            goto done;
        }
    }

    /* This is geneally the first call when importing keys from OpenSSL,
     * so ensure the other common object parameters are correct as well */
    key->data.key.type = CKK_EC;
    key->data.key.bit_size = EC_GROUP_order_bits(group);
    key->data.key.size = (key->data.key.bit_size + 7) / 8;

done:
    OPENSSL_free(ecparams);
    EC_GROUP_free(group);
    return rv;
}

static CK_RV p11prov_obj_set_domain_params(P11PROV_OBJ *key, CK_KEY_TYPE type,
                                           const OSSL_PARAM params[])
{
    switch (type) {
    case CKK_EC:
        /* EC_PARAMS */
        return import_ec_params(key, params);

    default:
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Unsupported key type: %08lx", type);
        return CKR_KEY_INDIGESTIBLE;
    }
}

CK_RV p11prov_obj_import_key(P11PROV_OBJ *key, CK_KEY_TYPE type,
                             CK_OBJECT_CLASS class, const OSSL_PARAM params[])
{
    /* This operation available only on new objects, can't import over an
     * existing one */
    if (key->class != CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(key->ctx, CKR_ARGUMENTS_BAD, "Non empty object");
        return CKR_ARGUMENTS_BAD;
    }

    switch (class) {
    case CKO_PUBLIC_KEY:
        key->class = CKO_PUBLIC_KEY;
        return p11prov_obj_import_public_key(key, type, params);
    case CKO_PRIVATE_KEY:
        key->class = CKO_PRIVATE_KEY;
        return p11prov_obj_import_private_key(key, type, params);
    case CKO_DOMAIN_PARAMETERS:
        key->class = CKO_DOMAIN_PARAMETERS;
        return p11prov_obj_set_domain_params(key, type, params);
    default:
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Invalid object class or key type");
        return CKR_KEY_INDIGESTIBLE;
    }
}

#if SKEY_SUPPORT

static CK_RV p11prov_store_aes_key(P11PROV_CTX *provctx, P11PROV_OBJ **ret,
                                   const unsigned char *secret,
                                   size_t secretlen, char *label,
                                   CK_FLAGS usage, bool session_key)
{
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_SLOT_ID slot = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SLOTS_CTX *slots = NULL;
    P11PROV_SESSION *session = NULL;
    CK_OBJECT_HANDLE key_handle;
    CK_BBOOL tokenobj = false;
    P11PROV_OBJ *obj;
    CK_RV rv;
    CK_ATTRIBUTE tmpl[12] = {
        { CKA_TOKEN, &tokenobj, sizeof(tokenobj) },
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_VALUE, (void *)secret, secretlen },
        { 0 },
    };
    size_t tmax = sizeof(tmpl) / sizeof(CK_ATTRIBUTE);
    size_t tsize = 4;

    P11PROV_debug("Creating secret key (%p[%zu]), token: %b, flags: %x", secret,
                  secretlen, !session_key, usage);

    /* Make it a token (permanent) object if necessary */
    if (!session_key) {
        tokenobj = true;
    }

    if (usage) {
        rv = p11prov_usage_to_template(tmpl, &tsize, tmax, usage);
        if (rv != CKR_OK) {
            P11PROV_raise(provctx, rv, "Failed to set key usage");
            return CKR_GENERAL_ERROR;
        }
    } else {
        rv = CKR_ARGUMENTS_BAD;
        P11PROV_raise(provctx, rv, "No key usage specified");
        return CKR_GENERAL_ERROR;
    }

    slots = p11prov_ctx_get_slots(provctx);
    if (!slots) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    slot = p11prov_get_default_slot(slots);
    if (slot == CK_UNAVAILABLE_INFORMATION) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rv = p11prov_take_login_session(provctx, slot, &session);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_CreateObject(provctx, p11prov_session_handle(session), tmpl,
                              tsize, &key_handle);
    if (rv != CKR_OK) {
        goto done;
    }

    obj = p11prov_obj_new(provctx, slot, key_handle, key_class);
    if (obj == NULL) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    obj->data.key.type = key_type;
    obj->data.key.bit_size = secretlen * 8;
    obj->data.key.size = secretlen;

    *ret = obj;
    rv = CKR_OK;

done:
    p11prov_return_session(session);
    return rv;
}

P11PROV_OBJ *p11prov_obj_import_secret_key(P11PROV_CTX *ctx, CK_KEY_TYPE type,
                                           const unsigned char *key,
                                           size_t keylen)
{
    CK_RV rv = CKR_KEY_INDIGESTIBLE;
    P11PROV_OBJ *obj = NULL;
    CK_FLAGS usage = CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY
                     | CKF_WRAP | CKF_UNWRAP | CKF_DERIVE;

    /* TODO: cache find, see other key types */

    switch (type) {
    case CKK_AES:
        rv = p11prov_store_aes_key(ctx, &obj, key, keylen, NULL, usage, true);
        if (rv != CKR_OK) {
            P11PROV_raise(ctx, rv, "Failed to import");
            goto done;
        }
        break;

    default:
        P11PROV_raise(ctx, rv, "Unsupported key type: %08lx", type);
        goto done;
    }

done:
    if (rv != CKR_OK) {
        p11prov_obj_free(obj);
        obj = NULL;
    }
    return obj;
}

#endif /* SKEY_SUPPORT */

CK_RV p11prov_obj_set_ec_encoded_public_key(P11PROV_OBJ *key,
                                            const void *pubkey,
                                            size_t pubkey_len)
{
    CK_RV rv;
    CK_ATTRIBUTE *pub;
    CK_ATTRIBUTE *ecpoint;
    CK_ATTRIBUTE new_pub;
    ASN1_OCTET_STRING oct;
    unsigned char *der = NULL;
    int add_attrs = 0;
    int len;

    if (key->handle != CK_P11PROV_IMPORTED_HANDLE) {
        /*
         * not a mock object, cannot set public key to a token object backed by
         * an actual handle.
         */
        /* not matching, error out */
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Cannot change public key of a token object");
        return CKR_KEY_INDIGESTIBLE;
    }

    switch (key->data.key.type) {
    case CKK_EC:
    case CKK_EC_EDWARDS:
        /* if class is still "domain parameters" convert it to
         * a public key */
        if (key->class == CKO_DOMAIN_PARAMETERS) {
            key->class = CKO_PUBLIC_KEY;
        } else if (key->class != CKO_PUBLIC_KEY) {
            /* check that this is a public key */
            P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                          "Invalid Key type, not a public key");
            return CKR_KEY_INDIGESTIBLE;
        }
        break;
    default:
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Invalid Key type, not an EC/ED key");
        return CKR_KEY_INDIGESTIBLE;
    }

    pub = p11prov_obj_get_attr(key, CKA_P11PROV_PUB_KEY);
    if (!pub) {
        add_attrs += 1;
    }

    ecpoint = p11prov_obj_get_attr(key, CKA_EC_POINT);
    if (!ecpoint) {
        add_attrs += 1;
    }

    if (add_attrs > 0) {
        void *ptr = OPENSSL_realloc(
            key->attrs, sizeof(CK_ATTRIBUTE) * (key->numattrs + add_attrs));
        if (!ptr) {
            P11PROV_raise(key->ctx, CKR_HOST_MEMORY,
                          "Failed to store key public key");
            return CKR_HOST_MEMORY;
        }
        key->attrs = ptr;
    }

    if (!pub) {
        pub = &key->attrs[key->numattrs];
        key->numattrs += 1;
    } else {
        OPENSSL_free(pub->pValue);
    }
    /* always memset as realloc does not guarantee zeroed data */
    memset(pub, 0, sizeof(CK_ATTRIBUTE));

    if (!ecpoint) {
        ecpoint = &key->attrs[key->numattrs];
        key->numattrs += 1;
    } else {
        OPENSSL_free(ecpoint->pValue);
    }
    /* always memset as realloc does not guarantee zeroed data */
    memset(ecpoint, 0, sizeof(CK_ATTRIBUTE));

    new_pub.type = CKA_P11PROV_PUB_KEY;
    new_pub.pValue = (CK_VOID_PTR)pubkey;
    new_pub.ulValueLen = (CK_ULONG)pubkey_len;
    rv = p11prov_copy_attr(pub, &new_pub);
    if (rv != CKR_OK) {
        return rv;
    }

    oct.data = (unsigned char *)pubkey;
    oct.length = (int)pubkey_len;
    oct.flags = 0;

    len = i2d_ASN1_OCTET_STRING(&oct, &der);
    if (len < 0) {
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Failure to encode EC point to DER");
        return CKR_KEY_INDIGESTIBLE;
    }
    ecpoint->type = CKA_EC_POINT;
    ecpoint->pValue = der;
    ecpoint->ulValueLen = len;

    return CKR_OK;
}

CK_RV p11prov_obj_copy_specific_attr(P11PROV_OBJ *pub_key,
                                     P11PROV_OBJ *priv_key,
                                     CK_ATTRIBUTE_TYPE type)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV ret = CKR_OK;

    if (!pub_key || !priv_key) {
        return CKR_ARGUMENTS_BAD;
    }

    attr = p11prov_obj_get_attr(pub_key, type);
    if (!attr) {
        P11PROV_debug("Failed to fetch the specific attribute");
        return CKR_GENERAL_ERROR;
    }

    ret = p11prov_copy_attr(&priv_key->attrs[priv_key->numattrs], attr);
    if (ret != CKR_OK) {
        P11PROV_raise(priv_key->ctx, ret, "Failed attr copy");
        return CKR_GENERAL_ERROR;
    }
    priv_key->numattrs++;

    return ret;
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
    key->attrs = OPENSSL_zalloc(KEY_EC_PARAMS * sizeof(CK_ATTRIBUTE));
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
