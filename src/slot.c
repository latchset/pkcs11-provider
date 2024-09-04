/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>

struct p11prov_slot {
    CK_SLOT_ID id;
    CK_SLOT_INFO slot;
    CK_TOKEN_INFO token;

    char *login_info;
    char *cached_pin;
    char *bad_pin;

    P11PROV_SESSION_POOL *pool;
    P11PROV_OBJ_POOL *objects;

    CK_MECHANISM_TYPE *mechs;
    int nmechs;

    CK_ULONG profiles[5];
};

struct p11prov_slots_ctx {
    P11PROV_CTX *provctx;
    P11PROV_SLOT **slots;
    int num;
    pthread_rwlock_t rwlock;

    /* This is the first slot that can be r/w and
     * accepts login */
    CK_SLOT_ID default_slot;
};

static void get_slot_profiles(P11PROV_CTX *ctx, struct p11prov_slot *slot)
{
    CK_SESSION_HANDLE session;
    CK_BBOOL token = CK_TRUE;
    CK_OBJECT_CLASS class = CKO_PROFILE;

    CK_ATTRIBUTE template[2] = {
        { CKA_TOKEN, &token, sizeof(token) },
        { CKA_CLASS, &class, sizeof(class) },
    };
    CK_OBJECT_HANDLE object[5];
    CK_ULONG objcount;
    int index = 0;
    int ret;

    ret = p11prov_OpenSession(ctx, slot->id, CKF_SERIAL_SESSION, NULL, NULL,
                              &session);
    if (ret != CKR_OK) {
        return;
    }

    ret = p11prov_FindObjectsInit(ctx, session, template, 2);
    if (ret != CKR_OK) {
        goto done;
    }

    /* at most 5 objects as there are 5 profiles for now */
    ret = p11prov_FindObjects(ctx, session, object, 5, &objcount);
    if (ret != CKR_OK) {
        (void)p11prov_FindObjectsFinal(ctx, session);
        goto done;
    }

    (void)p11prov_FindObjectsFinal(ctx, session);

    if (objcount == 0) {
        P11PROV_debug("No profiles for slot %lu", slot->id);
        goto done;
    }

    for (size_t i = 0; i < objcount; i++) {
        CK_ULONG value = CK_UNAVAILABLE_INFORMATION;
        CK_ATTRIBUTE profileid = { CKA_PROFILE_ID, &value, sizeof(value) };

        ret = p11prov_GetAttributeValue(ctx, session, object[i], &profileid, 1);
        if (ret != CKR_OK || value == CK_UNAVAILABLE_INFORMATION) {
            continue;
        }

        slot->profiles[index] = value;
        index++;
    }

done:
    (void)p11prov_CloseSession(ctx, session);
    return;
}

static void get_slot_mechanisms(P11PROV_CTX *ctx, struct p11prov_slot *slot)
{
    CK_ULONG mechs_num;
    int ret;

    ret = p11prov_GetMechanismList(ctx, slot->id, NULL, &mechs_num);
    if (ret != CKR_OK) {
        return;
    }

    P11PROV_debug("Slot(%lu) mechs found: %lu", slot->id, mechs_num);

    slot->mechs = OPENSSL_malloc(mechs_num * sizeof(CK_MECHANISM_TYPE));
    if (!slot->mechs) {
        P11PROV_raise(ctx, CKR_HOST_MEMORY, "Failed to alloc for mech list");
        return;
    }

    ret = p11prov_GetMechanismList(ctx, slot->id, slot->mechs, &mechs_num);
    if (ret != CKR_OK) {
        OPENSSL_free(slot->mechs);
        return;
    }
    slot->nmechs = mechs_num;
}

static const char slot_desc_fmt[] = "PKCS#11 Token (Slot %lu - %s)";

CK_RV p11prov_init_slots(P11PROV_CTX *ctx, P11PROV_SLOTS_CTX **slots)
{
    CK_ULONG num;
    CK_INFO ck_info;
    CK_SLOT_ID *slotid = NULL;
    struct p11prov_slots_ctx *sctx;
    CK_RV ret;
    int err;

    ck_info = p11prov_ctx_get_ck_info(ctx);

    sctx = OPENSSL_zalloc(sizeof(P11PROV_SLOTS_CTX));
    if (!sctx) {
        return CKR_HOST_MEMORY;
    }
    sctx->provctx = ctx;

    err = pthread_rwlock_init(&sctx->rwlock, NULL);
    if (err != 0) {
        err = errno;
        ret = CKR_CANT_LOCK;
        P11PROV_raise(ctx, ret, "Failed to init slots lock (errno:%d)", err);
        goto done;
    }

    ret = p11prov_GetSlotList(ctx, CK_FALSE, NULL, &num);
    if (ret) {
        goto done;
    }

    /* arbitrary number from libp11 */
    if (num > 0x10000) {
        ret = CKR_GENERAL_ERROR;
        goto done;
    }

    slotid = OPENSSL_malloc(num * sizeof(CK_SLOT_ID));
    if (!slotid) {
        ret = CKR_HOST_MEMORY;
        goto done;
    }

    ret = p11prov_GetSlotList(ctx, CK_FALSE, slotid, &num);
    if (ret) {
        goto done;
    }

    sctx->slots = OPENSSL_zalloc(num * sizeof(P11PROV_SLOT *));
    if (!sctx->slots) {
        ret = CKR_HOST_MEMORY;
        goto done;
    }

    sctx->default_slot = CK_UNAVAILABLE_INFORMATION;

    for (size_t i = 0; i < num; i++) {
        P11PROV_SLOT *slot;

        slot = OPENSSL_zalloc(sizeof(P11PROV_SLOT));
        if (!slot) {
            ret = CKR_HOST_MEMORY;
            goto done;
        }
        sctx->slots[sctx->num] = slot;

        ret = p11prov_GetSlotInfo(ctx, slotid[i], &slot->slot);
        if (ret != CKR_OK || (slot->slot.flags & CKF_TOKEN_PRESENT) == 0) {
            /* skip slot */
            continue;
        }
        ret = p11prov_GetTokenInfo(ctx, slotid[i], &slot->token);
        if (ret) {
            /* skip slot */
            continue;
        }

        trim(slot->slot.slotDescription);
        trim(slot->slot.manufacturerID);
        trim(slot->token.label);
        trim(slot->token.manufacturerID);
        trim(slot->token.model);
        trim(slot->token.serialNumber);

        slot->id = slotid[i];

        /* upper bound = slot_desc_fmt + LONG_MAX chars + MAX SLOT DESC */
        slot->login_info = p11prov_alloc_sprintf(
            sizeof(slot_desc_fmt) + 20 + sizeof(slot->slot.slotDescription) + 1,
            slot_desc_fmt, slot->id, slot->slot.slotDescription);
        if (!slot->login_info) {
            ret = CKR_HOST_MEMORY;
            goto done;
        }

        ret =
            p11prov_session_pool_init(ctx, &slot->token, slot->id, &slot->pool);
        if (ret) {
            goto done;
        }

        ret = p11prov_obj_pool_init(ctx, slot->id, &slot->objects);
        if (ret) {
            goto done;
        }

        /* profiles not available before version 3 */
        if (ck_info.cryptokiVersion.major >= 3) {
            get_slot_profiles(ctx, slot);
        }
        get_slot_mechanisms(ctx, slot);

        /* set default slot to the first one that can be used (for example
         * softoken has a slot that can't be used to store session keys)
         * and the following query excludes it */
        if ((sctx->default_slot == CK_UNAVAILABLE_INFORMATION)
            && (slot->token.flags & CKF_LOGIN_REQUIRED)
            && (slot->token.flags & CKF_USER_PIN_INITIALIZED)
            && (slot->token.flags & CKF_TOKEN_INITIALIZED)
            && (!(slot->token.flags & CKF_USER_PIN_LOCKED))) {
            sctx->default_slot = slot->id;
        }

        P11PROV_debug_slot(ctx, slot->id, &slot->slot, &slot->token,
                           slot->mechs, slot->nmechs, slot->profiles);

        sctx->num++;
    }

done:
    OPENSSL_free(slotid);

    if (ret != CKR_OK) {
        p11prov_free_slots(sctx);
        sctx = NULL;
    }

    *slots = sctx;
    return ret;
}

void p11prov_slot_fork_prepare(P11PROV_SLOTS_CTX *sctx)
{
    int err;

    /* attempt to get a write lock if possible, but fall back to a mere
     * read lock if not possible (for example because it would cause
     * a deadlock).
     * Holding a write lock here is slightly preferable in case the
     * application decides to create threads immediately after the fork
     * within an atfork handler that runs before ours.
     * Holding a write lock will prevent other threads from grabbing a
     * read lock before we can reset the locks. However we assume this
     * scenario to be mostly hypothetical and exceedingly rare given most
     * forks result in a exec(), and atfork() is also a rarely used
     * function, so falling back to a read lock to avoid deadlocks is ok
     * in the vast majority of use cases.
     */
    err = pthread_rwlock_trywrlock(&sctx->rwlock);
    if (err != 0) {
        err = pthread_rwlock_rdlock(&sctx->rwlock);
        if (err != 0) {
            err = errno;
            P11PROV_debug("Failed to get slots lock (errno:%d)", err);
            return;
        }
    }
}

void p11prov_slot_fork_release(P11PROV_SLOTS_CTX *sctx)
{
    int err;

    err = pthread_rwlock_unlock(&sctx->rwlock);
    if (err != 0) {
        err = errno;
        P11PROV_debug("Failed to release slots lock (errno:%d)", err);
    }
}

void p11prov_slot_fork_reset(P11PROV_SLOTS_CTX *sctx)
{
    int err;

    /* rwlock, saves TID internally, so we need to reset
     * after fork in the child */
    p11prov_force_rwlock_reinit(&sctx->rwlock);

    /* This is running in the fork handler, so there should be no
     * way to have other threads running, but just in case some
     * crazy library creates threads in their child handler */
    err = pthread_rwlock_wrlock(&sctx->rwlock);
    if (err != 0) {
        err = errno;
        P11PROV_debug("Failed to get slots lock (errno:%d)", err);
        return;
    }

    for (int i = 0; i < sctx->num; i++) {
        P11PROV_SLOT *slot = sctx->slots[i];

        /* invalidate all sessions */
        p11prov_session_pool_fork_reset(slot->pool);

        /* mark each object for revalidation */
        p11prov_obj_pool_fork_reset(slot->objects);
    }

    err = pthread_rwlock_unlock(&sctx->rwlock);
    if (err != 0) {
        err = errno;
        P11PROV_debug("Failed to release slots lock (errno:%d)", err);
    }
}

void p11prov_free_slots(P11PROV_SLOTS_CTX *sctx)
{
    int err;

    if (!sctx) {
        return;
    }
    err = pthread_rwlock_destroy(&sctx->rwlock);
    if (err != 0) {
        err = errno;
        P11PROV_raise(sctx->provctx, CKR_CANT_LOCK,
                      "Failed to destroy slots lock (errno:%d), leaking memory",
                      err);
        return;
    }
    if (sctx->num == 0) {
        return;
    }
    for (int i = 0; i < sctx->num; i++) {
        p11prov_session_pool_free(sctx->slots[i]->pool);
        p11prov_obj_pool_free(sctx->slots[i]->objects);
        OPENSSL_free(sctx->slots[i]->mechs);
        if (sctx->slots[i]->bad_pin) {
            OPENSSL_clear_free(sctx->slots[i]->bad_pin,
                               strlen(sctx->slots[i]->bad_pin));
        }
        if (sctx->slots[i]->cached_pin) {
            OPENSSL_clear_free(sctx->slots[i]->cached_pin,
                               strlen(sctx->slots[i]->cached_pin));
        }
        OPENSSL_free(sctx->slots[i]->login_info);
        OPENSSL_clear_free(sctx->slots[i], sizeof(P11PROV_SLOT));
    }
    OPENSSL_free(sctx->slots);
    OPENSSL_free(sctx);
}

CK_RV p11prov_take_slots(P11PROV_CTX *ctx, P11PROV_SLOTS_CTX **slots)
{
    P11PROV_SLOTS_CTX *sctx;
    int err;

    sctx = p11prov_ctx_get_slots(ctx);
    if (!sctx) {
        return CKR_GENERAL_ERROR;
    }

    err = pthread_rwlock_rdlock(&sctx->rwlock);
    if (err != 0) {
        err = errno;
        P11PROV_raise(ctx, CKR_CANT_LOCK, "Failed to get slots lock (errno:%d)",
                      err);
        *slots = NULL;
        return CKR_CANT_LOCK;
    }
    *slots = sctx;
    return CKR_OK;
}

void p11prov_return_slots(P11PROV_SLOTS_CTX *sctx)
{
    int err;
    err = pthread_rwlock_unlock(&sctx->rwlock);
    if (err != 0) {
        err = errno;
        P11PROV_raise(sctx->provctx, CKR_CANT_LOCK,
                      "Failed to release slots lock (errno:%d)", err);
    }
}

/* returns the slots at index idx and increments the index */
P11PROV_SLOT *p11prov_fetch_slot(P11PROV_SLOTS_CTX *sctx, int *idx)
{
    int i = *idx;

    if (i < 0 || i >= sctx->num) {
        return NULL;
    }
    *idx = i + 1;
    return sctx->slots[i];
}

P11PROV_SLOT *p11prov_get_slot_by_id(P11PROV_SLOTS_CTX *sctx, CK_SLOT_ID id)
{
    for (int s = 0; s < sctx->num; s++) {
        if (sctx->slots[s]->id == id) {
            return sctx->slots[s];
        }
    }
    return NULL;
}

int p11prov_slot_get_mechanisms(P11PROV_SLOT *slot, CK_MECHANISM_TYPE **mechs)
{
    if (!slot) {
        return 0;
    }
    *mechs = slot->mechs;
    return slot->nmechs;
}

int p11prov_check_mechanism(P11PROV_CTX *ctx, CK_SLOT_ID id,
                            CK_MECHANISM_TYPE mechtype)
{
    P11PROV_SLOTS_CTX *sctx;
    CK_RV ret;

    ret = p11prov_take_slots(ctx, &sctx);
    if (ret != CKR_OK) {
        return ret;
    }

    ret = CKR_MECHANISM_INVALID;

    for (int s = 0; s < sctx->num; s++) {
        if (sctx->slots[s]->id != id) {
            continue;
        }
        for (int i = 0; i < sctx->slots[s]->nmechs; i++) {
            if (sctx->slots[s]->mechs[i] == mechtype) {
                ret = CKR_OK;
                break;
            }
        }
    }

    p11prov_return_slots(sctx);
    return ret;
}

CK_RV p11prov_slot_get_obj_pool(P11PROV_CTX *ctx, CK_SLOT_ID id,
                                P11PROV_OBJ_POOL **pool)
{
    P11PROV_SLOT *slot = NULL;
    P11PROV_SLOTS_CTX *sctx;
    CK_RV ret;

    ret = p11prov_take_slots(ctx, &sctx);
    if (ret != CKR_OK) {
        return ret;
    }

    for (int s = 0; s < sctx->num; s++) {
        if (sctx->slots[s]->id == id) {
            slot = sctx->slots[s];
            break;
        }
    }

    if (!slot) {
        ret = CKR_SLOT_ID_INVALID;
    } else {
        if (slot->objects) {
            *pool = slot->objects;
            ret = CKR_OK;
        } else {
            ret = CKR_GENERAL_ERROR;
        }
    }

    p11prov_return_slots(sctx);
    return ret;
}

CK_RV p11prov_slot_find_obj_pool(P11PROV_CTX *ctx, slot_pool_callback cb,
                                 void *cb_ctx)
{
    P11PROV_SLOT *slot = NULL;
    P11PROV_SLOTS_CTX *sctx;
    bool found = false;
    CK_RV ret;

    ret = p11prov_take_slots(ctx, &sctx);
    if (ret != CKR_OK) {
        return ret;
    }

    for (int s = 0; s < sctx->num; s++) {
        slot = sctx->slots[s];
        if (slot->objects) {
            found = cb(cb_ctx, slot->objects);
        }
        if (found) {
            break;
        }
    }

    p11prov_return_slots(sctx);
    return CKR_OK;
}

CK_SLOT_ID p11prov_slot_get_slot_id(P11PROV_SLOT *slot)
{
    return slot->id;
}

CK_SLOT_INFO *p11prov_slot_get_slot(P11PROV_SLOT *slot)
{
    return &slot->slot;
}

CK_TOKEN_INFO *p11prov_slot_get_token(P11PROV_SLOT *slot)
{
    return &slot->token;
}

const char *p11prov_slot_get_login_info(P11PROV_SLOT *slot)
{
    return slot->login_info;
}

const char *p11prov_slot_get_bad_pin(P11PROV_SLOT *slot)
{
    return slot->bad_pin;
}

CK_RV p11prov_slot_set_bad_pin(P11PROV_SLOT *slot, const char *bad_pin)
{
    if (slot->bad_pin) {
        OPENSSL_clear_free(slot->bad_pin, strlen(slot->bad_pin));
    }
    slot->bad_pin = OPENSSL_strdup(bad_pin);
    if (!slot->bad_pin) {
        return CKR_HOST_MEMORY;
    }
    return CKR_OK;
}

const char *p11prov_slot_get_cached_pin(P11PROV_SLOT *slot)
{
    return slot->cached_pin;
}

CK_RV p11prov_slot_set_cached_pin(P11PROV_SLOT *slot, const char *cached_pin)
{
    if (slot->cached_pin) {
        OPENSSL_clear_free(slot->cached_pin, strlen(slot->cached_pin));
    }
    slot->cached_pin = OPENSSL_strdup(cached_pin);
    if (!slot->cached_pin) {
        return CKR_HOST_MEMORY;
    }
    return CKR_OK;
}

P11PROV_SESSION_POOL *p11prov_slot_get_session_pool(P11PROV_SLOT *slot)
{
    return slot->pool;
}

bool p11prov_slot_check_req_login(P11PROV_SLOT *slot)
{
    return slot->token.flags & CKF_LOGIN_REQUIRED;
}

CK_SLOT_ID p11prov_get_default_slot(P11PROV_SLOTS_CTX *sctx)
{
    return sctx->default_slot;
}
