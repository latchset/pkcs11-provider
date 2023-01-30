/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>
#include <sys/types.h>

/* Slot stuff */
struct p11prov_slot {
    CK_SLOT_ID id;
    CK_SLOT_INFO slot;
    CK_TOKEN_INFO token;

    char *login_info;
    char *bad_pin;

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

static CK_RV session_pool_init(P11PROV_CTX *ctx, CK_TOKEN_INFO *token,
                               CK_SLOT_ID id, P11PROV_SESSION_POOL **_pool);
static void session_pool_free(P11PROV_SESSION_POOL *pool);
static void session_free(P11PROV_SESSION *session);

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
static const char slot_desc_fmt[] = "PKCS#11 Token (Slot %lu - %s)";

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

        /* upper bound = slot_desc_fmt + LONG_MAX chars + MAX SLOT DESC */
        slot->login_info = p11prov_alloc_sprintf(
            sizeof(slot_desc_fmt) + 20 + sizeof(slot->slot.slotDescription) + 1,
            slot_desc_fmt, slot->id, slot->slot.slotDescription);
        if (!slot->login_info) {
            ret = CKR_HOST_MEMORY;
            goto done;
        }

        ret = session_pool_init(ctx, &slot->token, slot->id, &slot->pool);
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
        if (sctx->slots[i]->bad_pin) {
            OPENSSL_clear_free(sctx->slots[i]->bad_pin,
                               strlen(sctx->slots[i]->bad_pin));
        }
        OPENSSL_free(sctx->slots[i]->login_info);
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

#define MUTEX_RAISE_ERROR(_errstr) \
    P11PROV_raise(provctx, ret, "%s %s mutex (errno=%d)", _errstr, obj, err); \
    P11PROV_debug("Called from [%s:%d]%s()", file, line, func)

static CK_RV mutex_init(P11PROV_CTX *provctx, pthread_mutex_t *lock,
                        const char *obj, const char *file, int line,
                        const char *func)
{
    CK_RV ret = CKR_OK;
    int err;

    err = pthread_mutex_init(lock, NULL);
    if (err != 0) {
        err = errno;
        ret = CKR_CANT_LOCK;
        MUTEX_RAISE_ERROR("Failed to init");
    }
    return ret;
}
#define MUTEX_INIT(obj) \
    mutex_init((obj)->provctx, &(obj)->lock, #obj, OPENSSL_FILE, OPENSSL_LINE, \
               OPENSSL_FUNC)

static CK_RV mutex_lock(P11PROV_CTX *provctx, pthread_mutex_t *lock,
                        const char *obj, const char *file, int line,
                        const char *func)
{
    CK_RV ret = CKR_OK;
    int err;

    err = pthread_mutex_lock(lock);
    if (err != 0) {
        err = errno;
        ret = CKR_CANT_LOCK;
        MUTEX_RAISE_ERROR("Failed to lock");
    }
    return ret;
}
#define MUTEX_LOCK(obj) \
    mutex_lock((obj)->provctx, &(obj)->lock, #obj, OPENSSL_FILE, OPENSSL_LINE, \
               OPENSSL_FUNC)

static CK_RV mutex_try_lock(P11PROV_CTX *provctx, pthread_mutex_t *lock,
                            const char *obj, bool expect_unlocked,
                            const char *file, int line, const char *func)
{
    CK_RV ret = CKR_OK;
    int err;

    err = pthread_mutex_trylock(lock);
    if (err != 0) {
        err = errno;
        ret = CKR_CANT_LOCK;
        if (expect_unlocked) {
            MUTEX_RAISE_ERROR("Failed to trylock");
        }
    }
    return ret;
}
#define MUTEX_TRY_LOCK(obj, e) \
    mutex_try_lock((obj)->provctx, &(obj)->lock, #obj, (e), OPENSSL_FILE, \
                   OPENSSL_LINE, OPENSSL_FUNC)

static CK_RV mutex_unlock(P11PROV_CTX *provctx, pthread_mutex_t *lock,
                          const char *obj, const char *file, int line,
                          const char *func)
{
    CK_RV ret = CKR_OK;
    int err;

    err = pthread_mutex_unlock(lock);
    if (err != 0) {
        err = errno;
        ret = CKR_CANT_LOCK;
        MUTEX_RAISE_ERROR("Failed to unlock");
    }
    return ret;
}
#define MUTEX_UNLOCK(obj) \
    mutex_unlock((obj)->provctx, &(obj)->lock, #obj, OPENSSL_FILE, \
                 OPENSSL_LINE, OPENSSL_FUNC)

static CK_RV mutex_destroy(P11PROV_CTX *provctx, pthread_mutex_t *lock,
                           const char *obj, const char *file, int line,
                           const char *func)
{
    CK_RV ret = CKR_OK;
    int err;

    err = pthread_mutex_destroy(lock);
    if (err != 0) {
        err = errno;
        ret = CKR_CANT_LOCK;
        MUTEX_RAISE_ERROR("Failed to destroy");
    }
    return ret;
}
#define MUTEX_DESTROY(obj) \
    mutex_destroy((obj)->provctx, &(obj)->lock, #obj, OPENSSL_FILE, \
                  OPENSSL_LINE, OPENSSL_FUNC)

/* Session stuff */
#define DEFLT_SESSION_FLAGS CKF_SERIAL_SESSION
struct p11prov_session {
    P11PROV_CTX *provctx;
    P11PROV_SESSION_POOL *pool;

    CK_SLOT_ID slotid;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;

    pthread_mutex_t lock;

    p11prov_session_callback_t cb;
    void *cbarg;
};

struct p11prov_session_pool {
    P11PROV_CTX *provctx;
    CK_SLOT_ID slotid;

    int num_sessions;
    int max_sessions;
    int open_sessions;
    int max_cached_sessions;

    P11PROV_SESSION **sessions;

    P11PROV_SESSION *login_session;

    pthread_mutex_t lock;
};

static CK_RV token_session_callback(CK_SESSION_HANDLE hSession,
                                    CK_NOTIFICATION event,
                                    CK_VOID_PTR pApplication)
{
    P11PROV_SESSION *session = (P11PROV_SESSION *)pApplication;

    if (session->session != hSession) {
        /* something not right, let's ignore this callback */
        return CKR_OK;
    }

    if (session->cb) {
        return session->cb(session->cbarg);
    }

    return CKR_OK;
}

/* in nanoseconds, 1 seconds */
#define MAX_WAIT 1000000000
/* sleep interval, 50 microseconds (max 20 attempts) */
#define SLEEP 50000
static CK_RV token_session_open(P11PROV_SESSION *session, CK_FLAGS flags)
{
    uint64_t startime = 0;
    CK_RV ret;

    do {
        ret = p11prov_OpenSession(session->provctx, session->slotid, flags,
                                  session, token_session_callback,
                                  &session->session);
        P11PROV_debug("C_OpenSession ret:%lu (session: %lu)", ret,
                      session->session);
        if (ret != CKR_SESSION_COUNT) {
            break;
        }
    } while (cyclewait_with_timeout(MAX_WAIT, SLEEP, &startime));

    if (ret != CKR_OK) {
        session->session = CK_INVALID_HANDLE;
        session->flags = DEFLT_SESSION_FLAGS;
        return ret;
    }

    session->flags = flags;
    return CKR_OK;
}

static void token_session_close(P11PROV_SESSION *session)
{
    if (session->session != CK_INVALID_HANDLE) {
        P11PROV_debug("Closing session %lu", session->session);
        (void)p11prov_CloseSession(session->provctx, session->session);
        /* regardless of the result the session is gone */
        session->session = CK_INVALID_HANDLE;
        session->flags = DEFLT_SESSION_FLAGS;
    }
}

static CK_RV session_pool_init(P11PROV_CTX *ctx, CK_TOKEN_INFO *token,
                               CK_SLOT_ID id, P11PROV_SESSION_POOL **_pool)
{
    P11PROV_SESSION_POOL *pool;
    int ret;

    P11PROV_debug("Creating new session pool");

    pool = OPENSSL_zalloc(sizeof(P11PROV_SESSION_POOL));
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

    if (token->ulMaxSessionCount != CK_EFFECTIVELY_INFINITE
        && token->ulMaxSessionCount != CK_UNAVAILABLE_INFORMATION) {
        pool->max_sessions = token->ulMaxSessionCount;
        /* keep a max of 10% of the sessions */
        pool->max_cached_sessions = pool->max_sessions / 10;
        if (pool->max_cached_sessions == 0) {
            pool->max_cached_sessions = 3;
        }
    } else {
        /* arbitrary max concurrent open sessions */
        pool->max_sessions = 1024;
        pool->max_cached_sessions = 8;
    }
    if (pool->max_cached_sessions > pool->max_sessions) {
        pool->max_cached_sessions = pool->max_sessions;
    }

    P11PROV_debug("New session pool %p created", pool);

    *_pool = pool;
    return CKR_OK;
}

static void session_pool_free(P11PROV_SESSION_POOL *pool)
{
    P11PROV_debug("Freeing session pool %p", pool);

    if (!pool) {
        return;
    }

    /* LOCKED SECTION ------------- */
    if (MUTEX_LOCK(pool) == CKR_OK) {
        for (int i = 0; i < pool->num_sessions; i++) {
            session_free(pool->sessions[i]);
            pool->sessions[i] = NULL;
        }
        OPENSSL_free(pool->sessions);
        (void)MUTEX_UNLOCK(pool);
    }
    /* ------------- LOCKED SECTION */
    else {
        return;
    }

    (void)MUTEX_DESTROY(pool);
    OPENSSL_clear_free(pool, sizeof(P11PROV_SESSION_POOL));
}

#define SESS_ALLOC_SIZE 32

/* NOTE: to be called with Pool Lock held,
 * returns a locked session */
static CK_RV session_new(P11PROV_SESSION_POOL *pool, P11PROV_SESSION **_session)
{
    P11PROV_SESSION *session;
    int ret;

    P11PROV_debug("Creating new P11PROV_SESSION session on pool %p", pool);

    if (pool->num_sessions >= pool->max_sessions) {
        ret = CKR_SESSION_COUNT;
        P11PROV_raise(pool->provctx, ret, "Max sessions (%d) exceeded",
                      pool->max_sessions);
        return ret;
    }

    session = OPENSSL_zalloc(sizeof(P11PROV_SESSION));
    if (session == NULL) {
        ret = CKR_HOST_MEMORY;
        P11PROV_raise(pool->provctx, ret, "Failed to allocate session");
        return ret;
    }
    session->provctx = pool->provctx;
    session->slotid = pool->slotid;
    session->session = CK_INVALID_HANDLE;
    session->flags = DEFLT_SESSION_FLAGS;
    session->pool = pool;

    ret = MUTEX_INIT(session);
    if (ret != CKR_OK) {
        OPENSSL_free(session);
        return ret;
    }

    /* check if we need to expand the sessions array */
    if ((pool->num_sessions % SESS_ALLOC_SIZE) == 0) {
        P11PROV_SESSION **tmp = OPENSSL_realloc(
            pool->sessions,
            (pool->num_sessions + SESS_ALLOC_SIZE) * sizeof(P11PROV_SESSION *));
        if (tmp == NULL) {
            ret = CKR_HOST_MEMORY;
            P11PROV_raise(pool->provctx, ret,
                          "Failed to re-allocate sessions array");
            session_free(session);
            return ret;
        }
        pool->sessions = tmp;
    }

    ret = MUTEX_LOCK(session);
    if (ret != CKR_OK) {
        session_free(session);
        return ret;
    }

    pool->sessions[pool->num_sessions] = session;
    pool->num_sessions++;
    P11PROV_debug("Total sessions: %d", pool->num_sessions);

    *_session = session;
    return CKR_OK;
}

static CK_RV session_check(P11PROV_SESSION *session, CK_FLAGS flags,
                           CK_STATE *state)
{
    CK_SESSION_INFO session_info;
    int ret;

    if (!session) {
        return CKR_GENERAL_ERROR;
    }

    /* no handle, nothing to check */
    if (session->session == CK_INVALID_HANDLE) {
        return CKR_OK;
    }

    /* check that the pkcs11 session is still ok */
    ret = p11prov_GetSessionInfo(session->provctx, session->session,
                                 &session_info);
    if (ret == CKR_OK) {
        if (state) {
            *state = session_info.state;
        }
        if (flags == session_info.flags) {
            return ret;
        }
        (void)p11prov_CloseSession(session->provctx, session->session);
        session->session = CK_INVALID_HANDLE;
        /* tell the caller that the session was closed so they can
         * keep up with accounting */
        return CKR_SESSION_CLOSED;
    }

    /* session has been closed elsewhere, or otherwise unusable */
    session->session = CK_INVALID_HANDLE;
    return ret;
}

/* only call this from session_new or session_pool_free */
static void session_free(P11PROV_SESSION *session)
{
    int ret;

    P11PROV_debug("Session Free %p", session);

    if (session == NULL) {
        return;
    }

    ret = MUTEX_TRY_LOCK(session, false);
    if (ret != CKR_OK) {
        /* just orphan this session, will potentially leak memory ... */
        session->pool = NULL;
        return;
    }

    token_session_close(session);

    (void)MUTEX_UNLOCK(session);
    (void)MUTEX_DESTROY(session);
    OPENSSL_clear_free(session, sizeof(P11PROV_SESSION));
}

CK_SESSION_HANDLE p11prov_session_handle(P11PROV_SESSION *session)
{
    return session->session;
}

CK_SLOT_ID p11prov_session_slotid(P11PROV_SESSION *session)
{
    return session->slotid;
}

/* returns a locked login_session if _session is not NULL */
static CK_RV token_login(P11PROV_SESSION *session, P11PROV_URI *uri,
                         OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
                         struct p11prov_slot *slot)
{
    char cb_pin[MAX_PIN_LENGTH + 1] = { 0 };
    size_t cb_pin_len = 0;
    CK_UTF8CHAR_PTR pin = NULL_PTR;
    CK_ULONG pinlen = 0;
    CK_RV ret;

    if (!(slot->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
        if (uri) {
            pin = (CK_UTF8CHAR_PTR)p11prov_uri_get_pin(uri);
            if (slot->bad_pin && strcmp((char *)pin, slot->bad_pin) == 0) {
                P11PROV_raise(session->provctx, CKR_PIN_INVALID,
                              "Blocking stored PIN that failed a previous login"
                              " to avoid blocking the token");
                pin = NULL;
            }
        }
        if (!pin) {
            pin = p11prov_ctx_pin(session->provctx);
            if (slot->bad_pin && strcmp((char *)pin, slot->bad_pin) == 0) {
                P11PROV_raise(session->provctx, CKR_PIN_INVALID,
                              "Blocking stored PIN that failed a previous login"
                              " to avoid blocking the token");
                pin = NULL;
            }
        }
        if (pin) {
            pinlen = strlen((const char *)pin);
        } else if (pw_cb) {
            OSSL_PARAM params[2] = {
                OSSL_PARAM_DEFN(
                    OSSL_PASSPHRASE_PARAM_INFO, OSSL_PARAM_UTF8_STRING,
                    (void *)slot->login_info, strlen(slot->login_info)),
                OSSL_PARAM_END,
            };
            ret = pw_cb(cb_pin, sizeof(cb_pin), &cb_pin_len, params, pw_cbarg);
            if (ret != RET_OSSL_OK) {
                ret = CKR_GENERAL_ERROR;
                goto done;
            }
            if (cb_pin_len == 0) {
                ret = CKR_CANCEL;
                goto done;
            }

            pin = (CK_UTF8CHAR_PTR)cb_pin;
            pinlen = cb_pin_len;
        } else {
            ret = CKR_CANCEL;
            goto done;
        }
    }

    P11PROV_debug("Attempt Login on session %lu", session->session);
    /* Supports only USER login sessions for now */
    ret = p11prov_Login(session->provctx, session->session, CKU_USER, pin,
                        pinlen);
    if (ret == CKR_USER_ALREADY_LOGGED_IN) {
        ret = CKR_OK;
    } else {
        if (pin && ret == CKR_PIN_INCORRECT) {
            /* mark this pin as bad or we may end up locking the token */
            if (slot->bad_pin) {
                OPENSSL_clear_free(slot->bad_pin, strlen(slot->bad_pin));
            }
            slot->bad_pin = OPENSSL_strdup((const char *)pin);
            /* not much we can do on failure */
            if (!slot->bad_pin) {
                P11PROV_raise(session->provctx, CKR_HOST_MEMORY,
                              "Failed to set bad_pin");
            }
        }
    }

done:
    OPENSSL_cleanse(cb_pin, cb_pin_len);
    return ret;
}

static CK_RV check_slot(struct p11prov_slot *provslot, P11PROV_URI *uri,
                        CK_MECHANISM_TYPE mechtype, bool rw)
{
    if ((provslot->slot.flags & CKF_TOKEN_PRESENT) == 0) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    if ((provslot->token.flags & CKF_TOKEN_INITIALIZED) == 0) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    if (rw && (provslot->token.flags & CKF_WRITE_PROTECTED)) {
        return CKR_TOKEN_WRITE_PROTECTED;
    }
    if (uri) {
        CK_RV ret;
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
            return CKR_MECHANISM_INVALID;
        }
    }

    return CKR_OK;
}

static CK_RV fetch_session(P11PROV_SESSION_POOL *pool, CK_FLAGS flags,
                           P11PROV_SESSION **_session)
{
    P11PROV_SESSION *session = NULL;
    int ret;

    ret = MUTEX_LOCK(pool);
    if (ret != CKR_OK) {
        return ret;
    }
    /* LOCKED SECTION ------------- */

    /* try to find session with a cached handle first */
    for (int i = 0; i < pool->num_sessions; i++) {
        session = pool->sessions[i];
        if (session == pool->login_session) {
            continue;
        }
        if (session->flags == flags) {
            if (session->session != CK_INVALID_HANDLE) {
                ret = MUTEX_TRY_LOCK(session, false);
                if (ret == CKR_OK) {
                    /* Bingo! A compatible session with a cached handle */
                    goto done;
                }
            }
        }
    }

    /* try again, get any free session */
    for (int i = 0; i < pool->num_sessions; i++) {
        session = pool->sessions[i];
        if (session == pool->login_session) {
            continue;
        }
        ret = MUTEX_TRY_LOCK(session, false);
        if (ret == CKR_OK) {
            /* we got a free session */
            goto done;
        }
    }

    /* no free sessions, try to allocate a new one */
    ret = session_new(pool, &session);

done:
    (void)MUTEX_UNLOCK(pool);
    /* ------------- LOCKED SECTION */

    if (ret == CKR_OK) {
        *_session = session;
    }
    return ret;
}

static CK_RV slot_login(P11PROV_SLOT *slot, P11PROV_URI *uri,
                        OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
                        P11PROV_SESSION **_session)
{
    P11PROV_SESSION_POOL *pool = slot->pool;
    P11PROV_SESSION *session = NULL;
    CK_FLAGS flags = DEFLT_SESSION_FLAGS;
    CK_STATE state = CKS_RO_PUBLIC_SESSION;
    int num_open_sessions = 0;
    uint64_t startime = 0;
    CK_RV ret;

    /* try to lock the login_session */
    do {
        ret = MUTEX_LOCK(pool);
        if (ret != CKR_OK) {
            break;
        }

        /* LOCKED SECTION ------------- */
        session = pool->login_session;
        if (session) {
            ret = MUTEX_TRY_LOCK(session, false);
        }
        (void)MUTEX_UNLOCK(pool);
        /* ------------- LOCKED SECTION */

        /* we cycle only if we have a session but failed to lock it */
        if (ret == CKR_OK) {
            break;
        }

    } while (cyclewait_with_timeout(MAX_WAIT, SLEEP, &startime));

    if (ret != CKR_OK) {
        if (session) {
            P11PROV_raise(
                pool->provctx, ret,
                "Failed to lock login_session after several attemepts");
            session = NULL;
        }
        goto done;
    }

    if (session) {
        /* we have a login session */
        flags = session->flags;
    } else {
        ret = fetch_session(pool, flags, &session);
        if (ret != CKR_OK) {
            return ret;
        }
    }

    /* we have a locked session, check that it is ok */
    ret = session_check(session, flags, &state);
    if (ret == CKR_OK) {
        if (state == CKS_RW_PUBLIC_SESSION || state == CKS_RW_USER_FUNCTIONS
            || state == CKS_RW_SO_FUNCTIONS) {
            /* we have a valid logged in session */
            goto done;
        }
    } else {
        num_open_sessions--;
    }

    if (session->session == CK_INVALID_HANDLE) {
        ret = token_session_open(session, flags);
        if (ret == CKR_OK) {
            num_open_sessions++;
        } else {
            goto done;
        }
    }

    /* here we have a locked, open session */

    ret = token_login(session, uri, pw_cb, pw_cbarg, slot);

done:
    if (session) {
        /* if we found or created a session we need to update the pool
         * status */

        /* LOCKED SECTION ------------- */
        if (MUTEX_LOCK(pool) == CKR_OK) {

            pool->open_sessions += num_open_sessions;

            if (ret == CKR_OK) {
                if (pool->login_session == NULL) {
                    /* Any session can be used as login session.
                     * As long as there is one session open */
                    pool->login_session = session;
                }
            } else {
                if (pool->login_session == session) {
                    /* broken login session, unmark it as a login session */
                    pool->login_session = NULL;
                }
            }

            (void)MUTEX_UNLOCK(pool);
        }
        /* ------------- LOCKED SECTION */

        if (_session) {
            *_session = session;
        } else {
            /* unlock the session */
            p11prov_return_session(session);
        }
    }

    return ret;
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
    P11PROV_SESSION_POOL *pool = NULL;
    CK_SLOT_ID id = *slotid;
    P11PROV_SESSION *session = NULL;
    int num_open_sessions = 0;
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
        ret = check_slot(slot, uri, mechtype, rw);
        if (ret != CKR_OK) {
            goto done;
        }
        if ((slot->token.flags & CKF_LOGIN_REQUIRED) || reqlogin) {
            ret = slot_login(slot, uri, pw_cb, pw_cbarg, NULL);
            if (ret == CKR_CANCEL && !reqlogin) {
                ret = CKR_OK;
            }
            if (ret != CKR_OK) {
                goto done;
            }
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

            ret = check_slot(slot, uri, mechtype, rw);
            if (ret != CKR_OK) {
                /* keep going */
                continue;
            }
            if ((slot->token.flags & CKF_LOGIN_REQUIRED) || reqlogin) {
                ret = slot_login(slot, uri, pw_cb, pw_cbarg, NULL);
                if (ret == CKR_CANCEL && !reqlogin) {
                    ret = CKR_OK;
                }
                if (ret != CKR_OK) {
                    /* keep going */
                    continue;
                }
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

    pool = slot->pool;

    if (rw) {
        flags |= CKF_RW_SESSION;
    }

    ret = fetch_session(pool, flags, &session);
    if (ret == CKR_OK) {
        ret = session_check(session, flags, NULL);
        if (ret != CKR_OK) {
            num_open_sessions--;
            ret = CKR_OK;
        }
        if (session->session == CK_INVALID_HANDLE) {
            ret = token_session_open(session, flags);
            if (ret == CKR_OK) {
                num_open_sessions++;
            }
        }
    }

done:
    if (pool && num_open_sessions != 0) {

        /* if locking fails here we have bigger problems than
         * just bad accounting */

        /* LOCKED SECTION ------------- */
        if (MUTEX_LOCK(pool) == CKR_OK) {
            pool->open_sessions += num_open_sessions;
            (void)MUTEX_UNLOCK(pool);
        }
        /* ------------- LOCKED SECTION */
    }

    if (ret == CKR_OK) {
        *_session = session;
    } else {
        p11prov_return_session(session);
    }
    p11prov_return_slots(slots);
    return ret;
}

CK_RV p11prov_take_login_session(P11PROV_CTX *provctx, CK_SLOT_ID slotid,
                                 P11PROV_SESSION **_session)
{
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

    ret = slot_login(slot, NULL, NULL, NULL, _session);

done:
    p11prov_return_slots(slots);
    return ret;
}

void p11prov_return_session(P11PROV_SESSION *session)
{
    P11PROV_SESSION_POOL *pool;

    if (!session) {
        return;
    }

    /* remove any callback */
    p11prov_session_set_callback(session, NULL, NULL);

    pool = session->pool;

    if (pool) {
        /* peek at the pool lockless worst case we waste some time */
        if (pool->open_sessions >= pool->max_cached_sessions) {
            /* not much we can do if this fails,
             * but only accounting will be a bit off */

            /* LOCKED SECTION ------------- */
            if (MUTEX_LOCK(pool) == CKR_OK) {
                if (pool->open_sessions >= pool->max_cached_sessions
                    && session != pool->login_session) {
                    token_session_close(session);
                    pool->open_sessions--;
                }
                (void)MUTEX_UNLOCK(pool);
            }
            /* ------------- LOCKED SECTION */
        }
    }
    /* not much we can do if this fails */
    (void)MUTEX_UNLOCK(session);

    if (!pool) {
        /* handle case where session was orphaned because locked while
         * the pool was being freed */
        session_free(session);
    }
}

void p11prov_session_set_callback(P11PROV_SESSION *session,
                                  p11prov_session_callback_t cb, void *cbarg)
{
    session->cb = cb;
    session->cbarg = cbarg;
}
