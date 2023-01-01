/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>

/* Slot stuff */
struct p11prov_slot {
    CK_SLOT_ID id;
    CK_SLOT_INFO slot;
    CK_TOKEN_INFO token;

    P11PROV_SESSION_POOL *pool;

    CK_MECHANISM_TYPE *mechs;
    int nmechs;

    CK_ULONG profiles[5];
};

struct p11prov_slots_ctx {
    P11PROV_CTX *provctx;
    P11PROV_SLOT **slots;
    int num;
    pthread_rwlock_t rwlock;
};

static CK_RV session_pool_init(P11PROV_CTX *, CK_TOKEN_INFO *,
                               P11PROV_SESSION_POOL **);
static void session_pool_free(P11PROV_SESSION_POOL *);

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

static void trim_padded_field(CK_UTF8CHAR *field, ssize_t n)
{
    for (; n > 0 && field[n - 1] == ' '; n--) {
        field[n - 1] = 0;
    }
}

#define trim(x) trim_padded_field(x, sizeof(x))

CK_RV p11prov_init_slots(P11PROV_CTX *ctx, P11PROV_SLOTS_CTX **slots)
{
    CK_ULONG num;
    CK_SLOT_ID *slotid = NULL;
    struct p11prov_slots_ctx *sctx;
    CK_RV ret;
    int err;

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

        ret = session_pool_init(ctx, &slot->token, &slot->pool);
        if (ret) {
            goto done;
        }

        get_slot_profiles(ctx, slot);
        get_slot_mechanisms(ctx, slot);

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
        session_pool_free(sctx->slots[i]->pool);
        OPENSSL_free(sctx->slots[i]->mechs);
        OPENSSL_cleanse(sctx->slots[i], sizeof(P11PROV_SLOT));
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

int p11prov_slot_get_mechanisms(P11PROV_SLOT *slot, CK_MECHANISM_TYPE **mechs)
{
    if (!slot) {
        return 0;
    }
    *mechs = slot->mechs;
    return slot->nmechs;
}

/* Session stuff */
#define DEFLT_SESSION_FLAGS CKF_SERIAL_SESSION
struct p11prov_session {
    P11PROV_CTX *provctx;
    P11PROV_SESSION_POOL *pool;

    CK_SLOT_ID slotid;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;

    int refcnt;
    int free;

    /* used only for login sessions */
    bool login;
    pthread_mutex_t lock;
};

struct p11prov_session_pool {
    P11PROV_CTX *provctx;

    CK_ULONG max_sessions;
    CK_ULONG limit_sessions;
    CK_ULONG cur_sessions;

    P11PROV_SESSION **sessions;
    int num_p11sessions;

    P11PROV_SESSION *login_session;

    pthread_mutex_t lock;
};

/* in nanoseconds, 1 seconds */
#define MAX_WAIT 1000000000
/* sleep interval, 50 microseconds (max 20 attempts) */
#define SLEEP 50000
static CK_RV internal_session_open(P11PROV_SESSION_POOL *p, CK_SLOT_ID slot,
                                   CK_FLAGS flags, CK_SESSION_HANDLE *session)
{
    bool wait_ok = true;
    CK_ULONG cs = 0;
    uint64_t startime = 0;
    CK_RV ret;

    while (wait_ok) {
        if (cs == 0) {
            cs = __atomic_add_fetch(&p->cur_sessions, 1, __ATOMIC_SEQ_CST);
            if (cs > p->max_sessions) {
                P11PROV_debug_once("Max Session (%lu) exceeded!", cs);
                (void)__atomic_sub_fetch(&p->cur_sessions, 1, __ATOMIC_SEQ_CST);
                ret = CKR_SESSION_COUNT;
                cs = 0;
                wait_ok = cyclewait_with_timeout(MAX_WAIT, SLEEP, &startime);
                continue;
            }
        }

        wait_ok = false;
        ret = p11prov_OpenSession(p->provctx, slot, flags, NULL, NULL, session);
        P11PROV_debug("C_OpenSession ret:%lu (session: %lu)", ret, *session);
        if (ret == CKR_SESSION_COUNT) {
            wait_ok = cyclewait_with_timeout(MAX_WAIT, SLEEP, &startime);
        }
    }

    if (ret != CKR_OK && cs != 0) {
        (void)__atomic_sub_fetch(&p->cur_sessions, 1, __ATOMIC_SEQ_CST);
    }
    return ret;
}

static void internal_session_close(P11PROV_SESSION *session)
{
    if (session->session != CK_INVALID_HANDLE) {

        P11PROV_debug("Closing session %lu", session->session);
        (void)p11prov_CloseSession(session->provctx, session->session);
        /* regardless of the result the session is gone */
        if (session->pool) {
            (void)__atomic_fetch_sub(&session->pool->cur_sessions, 1,
                                     __ATOMIC_SEQ_CST);
        }
        session->session = CK_INVALID_HANDLE;
    }
    session->flags = CKF_SERIAL_SESSION;
}

static CK_RV session_pool_init(P11PROV_CTX *ctx, CK_TOKEN_INFO *token,
                               P11PROV_SESSION_POOL **_pool)
{
    P11PROV_SESSION_POOL *pool;
    int ret;

    P11PROV_debug("Creating new session pool");

    pool = OPENSSL_zalloc(sizeof(P11PROV_SESSION_POOL));
    if (!pool) {
        return CKR_HOST_MEMORY;
    }
    pool->provctx = ctx;

    ret = pthread_mutex_init(&pool->lock, 0);
    if (ret != 0) {
        ret = errno;
        P11PROV_raise(ctx, CKR_CANT_LOCK, "Failed to init mutex (errno:%d)",
                      ret);
        OPENSSL_free(pool);
        return CKR_CANT_LOCK;
    }

    if (token->ulMaxSessionCount != CK_EFFECTIVELY_INFINITE
        && token->ulMaxSessionCount != CK_UNAVAILABLE_INFORMATION) {
        pool->max_sessions = token->ulMaxSessionCount;
        /* keep a max of 10% of the sessions */
        pool->limit_sessions = pool->max_sessions / 10;
        if (pool->limit_sessions == 0) {
            pool->limit_sessions = 3;
        }
    } else {
        /* arbitrary max concurrent open sessions */
        pool->max_sessions = 1024;
        pool->limit_sessions = 8;
    }
    if (pool->limit_sessions > pool->max_sessions) {
        pool->limit_sessions = pool->max_sessions;
    }

    P11PROV_debug("New session pool %p created", pool);

    *_pool = pool;
    return CKR_OK;
}

static void session_pool_free(P11PROV_SESSION_POOL *pool)
{
    P11PROV_SESSION *session;

    P11PROV_debug("Freeing session pool %p", pool);

    if (!pool) {
        return;
    }

    /* deref login_session first */
    p11prov_session_free(pool->login_session);

    /* LOCKED SECTION ------------- */
    pthread_mutex_lock(&pool->lock);
    for (int i = 0; i < pool->num_p11sessions; i++) {
        session = pool->sessions[i];
        if (session->refcnt > 1) {
            P11PROV_raise(pool->provctx, CKR_GENERAL_ERROR,
                          "Can't free multiply-referenced session (%u)", i);
            /* orphan this session */
            session->pool = NULL;
            pool->sessions[i] = NULL;
            continue;
        }
        internal_session_close(session);
        OPENSSL_clear_free(session, sizeof(P11PROV_SESSION));
        pool->sessions[i] = NULL;
    }
    OPENSSL_free(pool->sessions);
    pool->sessions = NULL;
    pool->num_p11sessions = 0;
    pthread_mutex_unlock(&pool->lock);
    /* ------------- LOCKED SECTION */

    pthread_mutex_destroy(&pool->lock);
    OPENSSL_clear_free(pool, sizeof(P11PROV_SESSION_POOL));
}

#define SESS_ALLOC_SIZE 32
static P11PROV_SESSION *p11prov_session_new(P11PROV_CTX *ctx,
                                            struct p11prov_slot *slot)
{
    P11PROV_SESSION_POOL *p = slot->pool;
    P11PROV_SESSION *session;

    P11PROV_debug("Creating new P11PROV_SESSION session on pool %p", p);

    /* cap the amount of obtainable P11PROV_SESSIONs to double the max
     * number of available pkcs11 token sessions, just to have a limit
     * in case of runaway concurrent threads */
    if (p->num_p11sessions > (int)(p->max_sessions * 2)) {
        P11PROV_raise(ctx, CKR_SESSION_COUNT, "Max sessions limit reached");
        return NULL;
    }

    session = OPENSSL_zalloc(sizeof(P11PROV_SESSION));
    if (session == NULL) {
        P11PROV_raise(ctx, CKR_HOST_MEMORY, "Failed to allocate session");
        return NULL;
    }

    session->provctx = ctx;
    session->slotid = slot->id;
    session->session = CK_INVALID_HANDLE;
    session->flags = DEFLT_SESSION_FLAGS;
    session->pool = p;
    session->refcnt = 1;

    /* LOCKED SECTION ------------- */
    pthread_mutex_lock(&p->lock);

    /* check if we need to expand the sessions array */
    if ((p->num_p11sessions % SESS_ALLOC_SIZE) == 0) {
        P11PROV_SESSION **tmp =
            OPENSSL_realloc(p->sessions, (p->num_p11sessions + SESS_ALLOC_SIZE)
                                             * sizeof(P11PROV_SESSION *));
        if (tmp == NULL) {
            P11PROV_raise(ctx, CKR_HOST_MEMORY,
                          "Failed to re-allocate sessions array");
            OPENSSL_free(session);
            pthread_mutex_unlock(&p->lock);
            return NULL;
        }
        p->sessions = tmp;
    }
    p->sessions[p->num_p11sessions] = session;
    p->num_p11sessions++;

    pthread_mutex_unlock(&p->lock);
    /* ------------- LOCKED SECTION */

    P11PROV_debug("Total sessions: %d", p->num_p11sessions);

    return session;
}

static P11PROV_SESSION *p11prov_session_ref(P11PROV_SESSION *session)
{
    if (session
        && __atomic_fetch_add(&session->refcnt, 1, __ATOMIC_SEQ_CST) > 0) {
        return session;
    }

    return NULL;
}

static CK_RV p11prov_session_open(P11PROV_SESSION *session, bool login,
                                  CK_UTF8CHAR_PTR pin, CK_ULONG pinlen)
{
    P11PROV_SESSION_POOL *p = session->pool;
    CK_RV ret;

    ret = internal_session_open(p, session->slotid, session->flags,
                                &session->session);
    if (ret != CKR_OK) {
        P11PROV_raise(session->provctx, ret,
                      "Failed to open session on slot %lu", session->slotid);
        return ret;
    }

    if (login) {
        P11PROV_debug("Attempt Login on session %lu", session->session);
        /* Supports only USER login sessions for now */
        ret = p11prov_Login(session->provctx, session->session, CKU_USER, pin,
                            pinlen);
        if (ret == CKR_USER_ALREADY_LOGGED_IN) {
            ret = CKR_OK;
        }
        if (ret != CKR_OK) {
            internal_session_close(session);
        }
    }

    return ret;
}

void p11prov_session_free(P11PROV_SESSION *session)
{
    P11PROV_SESSION_POOL *p;
    CK_ULONG cur_sessions;
    bool ok;
    int expected;
    int ret;
    int ref;

    P11PROV_debug("Session Free %p", session);

    if (session == NULL) {
        return;
    }

    if (session->login) {
        ret = pthread_mutex_trylock(&session->lock);
        if (ret != 0) {
            ret = errno;
            P11PROV_raise(session->provctx, CKR_CANT_LOCK,
                          "Locked login session (errno=%d)", ret);
            return;
        }
        pthread_mutex_unlock(&session->lock);
    }

    ref = __atomic_sub_fetch(&session->refcnt, 1, __ATOMIC_SEQ_CST);
    if (ref > 1) {
        return;
    }
    if (ref < 1) {
        /* only the pool should really free sessions.
         * raise a warning */
        P11PROV_raise(session->provctx, CKR_GENERAL_ERROR,
                      "Potential double free in the calling code");
        /* and restore the refcnt to 1 */
        __atomic_store_n(&session->refcnt, 1, __ATOMIC_SEQ_CST);
        return;
    }

    /* last ref means we go busy -> free */

    if (session->login) {
        ret = pthread_mutex_destroy(&session->lock);
        if (ret != 0) {
            ret = errno;
            P11PROV_raise(session->provctx, CKR_CANT_LOCK,
                          "Locked login session (errno=%d)", ret);
            /* maintain busy */
            return;
        }
    }

    p = session->pool;
    if (p == NULL) {
        /* session was orphaned, just free it */
        internal_session_close(session);
        OPENSSL_clear_free(session, sizeof(P11PROV_SESSION));
        return;
    }

    if (p->login_session == session) {
        __atomic_store_n(&session->pool->login_session, NULL, __ATOMIC_SEQ_CST);
    }

    /* check if we used more than threshold sessions, in that case also
     * close the session to avoid hogging all the sessions of a token */
    cur_sessions = __atomic_load_n(&p->cur_sessions, __ATOMIC_SEQ_CST);
    if (cur_sessions > p->limit_sessions) {
        P11PROV_debug(
            "Session Free: Soft limit (%lu/%lu), releasing session: %lu",
            cur_sessions, p->limit_sessions, session->session);
        internal_session_close(session);
    }

    /* now that all is taken care of, set session to free so it can be
     * immediately taken by another thread */
    expected = 0;
    ok = __atomic_compare_exchange_n(&session->free, &expected, 1, false,
                                     __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    if (!ok) {
        P11PROV_raise(session->provctx, CKR_GENERAL_ERROR,
                      "Expected a busy session on freeing, got: %d", expected);
    }
}

CK_SESSION_HANDLE p11prov_session_handle(P11PROV_SESSION *session)
{
    return session->session;
}

CK_SLOT_ID p11prov_session_slotid(P11PROV_SESSION *session)
{
    return session->slotid;
}

static CK_RV token_login(P11PROV_CTX *provctx, struct p11prov_slot *slot,
                         P11PROV_URI *uri, OSSL_PASSPHRASE_CALLBACK *pw_cb,
                         void *pw_cbarg, bool reqlogin)
{
    P11PROV_SESSION *session = NULL;
    char cb_pin[MAX_PIN_LENGTH + 1] = { 0 };
    size_t cb_pin_len = 0;
    CK_UTF8CHAR_PTR pin = NULL_PTR;
    CK_ULONG pinlen = 0;
    CK_RV ret;

    if (slot->pool->login_session) {
        /* we already have a login_session */
        return CKR_OK;
    }

    if (uri) {
        pin = (CK_UTF8CHAR_PTR)p11prov_uri_get_pin(uri);
    }
    if (!pin) {
        pin = p11prov_ctx_pin(provctx);
    }
    if (pin) {
        pinlen = strlen((const char *)pin);
    } else if (pw_cb) {
        const char *info = "PKCS#11 Token";
        OSSL_PARAM params[2] = {
            OSSL_PARAM_DEFN(OSSL_PASSPHRASE_PARAM_INFO, OSSL_PARAM_UTF8_STRING,
                            (void *)info, sizeof(info)),
            OSSL_PARAM_END,
        };
        ret = pw_cb(cb_pin, sizeof(cb_pin), &cb_pin_len, params, pw_cbarg);
        if (ret != RET_OSSL_OK) {
            ret = CKR_GENERAL_ERROR;
            goto done;
        }
        if (cb_pin_len == 0) {
            ret = reqlogin ? CKR_CANCEL : CKR_OK;
            goto done;
        }

        pin = (CK_UTF8CHAR_PTR)cb_pin;
        pinlen = cb_pin_len;
    } else {
        ret = reqlogin ? CKR_CANCEL : CKR_OK;
        goto done;
    }

    session = p11prov_session_new(provctx, slot);
    if (session == NULL) {
        ret = CKR_GENERAL_ERROR;
        goto done;
    }

    session = p11prov_session_ref(session);
    if (session == NULL) {
        P11PROV_raise(provctx, CKR_GENERAL_ERROR,
                      "Failed to ref count session");
        /* intentionally leave this broken session busy so it won't be
         * used anymore */
        ret = CKR_GENERAL_ERROR;
        goto done;
    }

    ret = p11prov_session_open(session, true, pin, pinlen);
    if (ret == CKR_OK) {
        session->login = true;
        pthread_mutex_init(&session->lock, 0);
        session->pool->login_session = session;
    } else {
        p11prov_session_free(session);
    }

done:
    OPENSSL_cleanse(cb_pin, cb_pin_len);
    return ret;
}

static CK_RV check_slot(P11PROV_CTX *provctx, struct p11prov_slot *provslot,
                        bool reqlogin, P11PROV_URI *uri,
                        OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
                        CK_MECHANISM_TYPE mechtype)
{
    CK_RV ret = CKR_OK;

    if ((provslot->slot.flags & CKF_TOKEN_PRESENT) == 0) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    if ((provslot->token.flags & CKF_TOKEN_INITIALIZED) == 0) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    if (uri) {
        /* skip slots that do not match */
        ret = p11prov_uri_match_token(uri, &provslot->token);
        if (ret != CKR_OK) {
            return ret;
        }
    }
    if (mechtype != CK_UNAVAILABLE_INFORMATION) {
        bool found = false;
        for (int i = 0; i < provslot->nmechs; i++) {
            if (provslot->mechs[i] == mechtype) {
                found = true;
                break;
            }
        }
        if (!found) {
            /* slot not suitable */
            return CKR_CANCEL;
        }
    }

    if (!(provslot->token.flags & CKF_LOGIN_REQUIRED) && !reqlogin) {
        return CKR_OK;
    }

    return token_login(provctx, provslot, uri, pw_cb, pw_cbarg, reqlogin);
}

/* There are three possible ways to call this function.
 * 1. One shot call on a specific slot
 *      slotid must point to a specific slot number
 *      next_slotid must be NULL
 * 2. Find first viable slot
 *      slotid must point to a slot value of CK_UNAVAILABLE_INFORMATION
 *      next_slotid must be NULL
 * 3. slot iteration
 *      slotid must initially specify a value of CK_UNAVAILABLE_INFORMATION
 *      next_sloitd must NOT be NULL
 *      on following iterations the next_slotid value must be handed back
 *        as the slotid value
 *      if the function returns CK_UNAVAILABLE_INFORMATION in next_slotid
 *        it means there is no more slots to iterate over
 */
CK_RV p11prov_get_session(P11PROV_CTX *provctx, CK_SLOT_ID *slotid,
                          CK_SLOT_ID *next_slotid, P11PROV_URI *uri,
                          CK_MECHANISM_TYPE mechtype,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
                          bool reqlogin, bool rw, P11PROV_SESSION **_session)
{
    P11PROV_SLOTS_CTX *slots = NULL;
    P11PROV_SLOT *slot = NULL;
    CK_SLOT_ID id = *slotid;
    P11PROV_SESSION *session = NULL;
    CK_FLAGS flags = DEFLT_SESSION_FLAGS;
    int slot_idx;
    CK_RV ret;

    P11PROV_debug("Get session on slot %lu", id);

    ret = p11prov_take_slots(provctx, &slots);
    if (ret != CKR_OK) {
        return ret;
    }

    if (id != CK_UNAVAILABLE_INFORMATION && next_slotid == NULL) {
        slot_idx = 0;
        /* single shot request for a specific slot */
        for (slot = p11prov_fetch_slot(slots, &slot_idx); slot != NULL;
             slot = p11prov_fetch_slot(slots, &slot_idx)) {
            if (slot->id == id) {
                break;
            }
        }
        if (!slot) {
            ret = CKR_SLOT_ID_INVALID;
            goto done;
        }
        ret =
            check_slot(provctx, slot, reqlogin, uri, pw_cb, pw_cbarg, mechtype);
        if (ret != CKR_OK) {
            goto done;
        }
    } else {
        slot_idx = 0;
        ret = CKR_CANCEL;
        /* caller is cycling through slots, find the next viable one */
        for (slot = p11prov_fetch_slot(slots, &slot_idx); slot != NULL;
             slot = p11prov_fetch_slot(slots, &slot_idx)) {
            if (id != CK_UNAVAILABLE_INFORMATION && id != slot->id) {
                /* seek to next slot to check */
                continue;
            } else {
                /* found next slot */
                id = CK_UNAVAILABLE_INFORMATION;
            }

            ret = check_slot(provctx, slot, reqlogin, uri, pw_cb, pw_cbarg,
                             mechtype);
            if (ret != CKR_OK) {
                /* keep going */
                continue;
            }

            id = slot->id;
            break;
        }

        if (ret == CKR_OK) {
            /* Found a slot, return it and the next slot to the caller for
             * continuation if the current slot does not yield the desired
             * results */
            *slotid = id;
            if (next_slotid) {
                P11PROV_SLOT *next_slot;
                next_slot = p11prov_fetch_slot(slots, &slot_idx);
                if (next_slot) {
                    *next_slotid = next_slot->id;
                } else {
                    *next_slotid = CK_UNAVAILABLE_INFORMATION;
                }
            }
        } else {
            if (next_slotid) {
                *next_slotid = CK_UNAVAILABLE_INFORMATION;
            }
            goto done;
        }
    }

    if (rw) {
        flags |= CKF_RW_SESSION;
    }

    /* LOCKED SECTION ------------- */
    pthread_mutex_lock(&slot->pool->lock);
    for (int i = 0; i < slot->pool->num_p11sessions; i++) {
        if (slot->pool->sessions[i]->free) {
            /* store the first free session we find, but continue to search for
             * a free session with an actual cached token session */
            if (slot->pool->sessions[i]->session == CK_INVALID_HANDLE) {
                if (session == NULL) {
                    session = slot->pool->sessions[i];
                }
                continue;
            } else if (slot->pool->sessions[i]->flags == flags) {
                /* Bingo! A cached free session with a compatible handle */
                session = slot->pool->sessions[i];
                break;
            }
        }
    }
    if (session != NULL) {
        bool ok;
        int expected = 1;

        ok = __atomic_compare_exchange_n(&session->free, &expected, 0, false,
                                         __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        if (!ok) {
            P11PROV_raise(provctx, CKR_GENERAL_ERROR,
                          "Unexpected busy session while holding lock");
            ret = CKR_GENERAL_ERROR;
            /* null session here or it will be derefd on function exit */
            session = NULL;
        }
    }
    pthread_mutex_unlock(&slot->pool->lock);
    /* ------------- LOCKED SECTION */

    if (ret != CKR_OK) {
        goto done;
    }

    if (session == NULL) {
        session = p11prov_session_new(provctx, slot);
        if (session == NULL) {
            ret = CKR_GENERAL_ERROR;
            goto done;
        }
    }

    /* ref now, so we can simply p11prov_session_free() later on errors */
    session = p11prov_session_ref(session);
    if (session == NULL) {
        P11PROV_raise(provctx, CKR_GENERAL_ERROR,
                      "Failed to ref count session");
        /* intentionally leave this broken session busy so it won't be
         * used anymore */
        ret = CKR_GENERAL_ERROR;
        goto done;
    }

    session->flags = flags;

    if (session->session != CK_INVALID_HANDLE) {
        /* check that the pkcs11 session is still ok */
        CK_SESSION_INFO session_info;

        ret = p11prov_GetSessionInfo(session->provctx, session->session,
                                     &session_info);
        switch (ret) {
        case CKR_OK:
            if (session->flags != session_info.flags) {
                internal_session_close(session);
                /* internal_session_close() resets flags */
                session->flags = flags;
            }
            break;
        case CKR_SESSION_CLOSED:
        case CKR_SESSION_HANDLE_INVALID:
            (void)__atomic_sub_fetch(&slot->pool->cur_sessions, 1,
                                     __ATOMIC_SEQ_CST);
            session->session = CK_INVALID_HANDLE;
            break;
        default:
            ret = CKR_GENERAL_ERROR;
            goto done;
        }
    }

    if (session->session == CK_INVALID_HANDLE) {
        ret = p11prov_session_open(session, false, NULL, 0);
    }

done:
    if (ret == CKR_OK) {
        *_session = session;
    } else {
        p11prov_session_free(session);
    }
    p11prov_return_slots(slots);
    return ret;
}

CK_RV p11prov_take_login_session(P11PROV_CTX *provctx, CK_SLOT_ID slotid,
                                 P11PROV_SESSION **_session)
{
    P11PROV_SESSION *session = NULL;
    P11PROV_SLOTS_CTX *slots = NULL;
    P11PROV_SLOT *slot = NULL;
    int slot_idx = 0;
    CK_RV ret;

    P11PROV_debug("Get login session from slot %lu", slotid);

    ret = p11prov_take_slots(provctx, &slots);
    if (ret != CKR_OK) {
        return ret;
    }

    for (slot = p11prov_fetch_slot(slots, &slot_idx); slot != NULL;
         slot = p11prov_fetch_slot(slots, &slot_idx)) {

        if (slot->id == slotid) {
            break;
        }
    }
    if (!slot || !slot->pool) {
        ret = CKR_SLOT_ID_INVALID;
        goto done;
    }

    if (!slot->pool->login_session) {
        ret = CKR_USER_NOT_LOGGED_IN;
        goto done;
    }

    session = slot->pool->login_session;

    /* Serialize access to the login_session */
    pthread_mutex_lock(&session->lock);

    *_session = session;
    ret = CKR_OK;

done:
    p11prov_return_slots(slots);
    return ret;
}

void p11prov_return_login_session(P11PROV_SESSION *session)
{
    pthread_mutex_unlock(&session->lock);

    /* handle case where session was orphaned because locked while the
     * pool was being freed */
    if (session->pool == NULL) {
        p11prov_session_free(session);
    }
}
