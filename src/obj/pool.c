/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "obj/internal.h"

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
CK_RV obj_add_to_pool(P11PROV_OBJ *obj)
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

void obj_rm_from_pool(P11PROV_OBJ *obj)
{
    P11PROV_OBJ_POOL *pool;
    CK_RV ret;
    const char *errstr = NULL;

    if (obj->poolid == -1) {
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
    obj->poolid = -1;

done:
    (void)MUTEX_UNLOCK(pool);
    /* ------------- LOCKED SECTION */

    if (errstr != NULL) {
        P11PROV_raise(pool->provctx, ret,
                      "Objects pool in inconsistent state - %s (obj=%p)",
                      errstr, obj);
    }
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

P11PROV_OBJ *p11prov_obj_pool_find(P11PROV_OBJ_POOL *pool,
                                   CK_OBJECT_CLASS class, CK_KEY_TYPE type,
                                   CK_ULONG param_set, CK_ULONG bit_size,
                                   CK_ATTRIBUTE *attrs, int numattrs)
{
    P11PROV_OBJ *ret = NULL;

    if (!pool) {
        return NULL;
    }

    /* LOCKED SECTION ------------- */
    if (MUTEX_LOCK(pool) == CKR_OK) {
        for (int i = 0; i < pool->num; i++) {
            P11PROV_OBJ *obj = pool->objects[i];
            if (!obj) {
                continue;
            }
            if (obj->class != class) {
                continue;
            }
            if (type != CK_UNAVAILABLE_INFORMATION
                && obj->data.key.type != type) {
                continue;
            }
            if (param_set != CK_UNAVAILABLE_INFORMATION
                && obj->data.key.param_set != param_set) {
                continue;
            }
            if (bit_size != CK_UNAVAILABLE_INFORMATION
                && obj->data.key.bit_size != bit_size) {
                continue;
            }
            if (obj_match_attrs(obj, attrs, numattrs)) {
                ret = obj;
                break;
            }
        }

        (void)MUTEX_UNLOCK(pool);
    }
    /* ------------- LOCKED SECTION */

    return ret;
}
