/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>

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
    CK_FUNCTION_LIST *f;
    bool wait_ok = true;
    CK_ULONG cs = 0;
    uint64_t startime = 0;
    CK_RV ret;

    ret = p11prov_ctx_status(p->provctx, &f);
    if (ret != CKR_OK) {
        return ret;
    }

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
        ret = f->C_OpenSession(slot, flags, NULL, NULL, session);
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
        CK_FUNCTION_LIST *f;
        CK_RV ret;

        ret = p11prov_ctx_status(session->provctx, &f);
        if (ret == CKR_OK) {
            ret = f->C_CloseSession(session->session);
            if (ret != CKR_OK) {
                P11PROV_raise(session->provctx, ret,
                              "Failed to close session %lu", session->session);
            }
        }
        /* regardless of the result the session is gone */
        if (session->pool) {
            (void)__atomic_fetch_sub(&session->pool->cur_sessions, 1,
                                     __ATOMIC_SEQ_CST);
        }
        session->session = CK_INVALID_HANDLE;
    }
    session->flags = CKF_SERIAL_SESSION;
}

CK_RV p11prov_session_pool_init(P11PROV_CTX *ctx, CK_TOKEN_INFO *token,
                                P11PROV_SESSION_POOL **_pool)
{
    P11PROV_SESSION_POOL *pool;

    P11PROV_debug("Creating new session pool");

    pool = OPENSSL_zalloc(sizeof(P11PROV_SESSION_POOL));
    if (!pool) {
        return CKR_HOST_MEMORY;
    }
    pool->provctx = ctx;

    pthread_mutex_init(&pool->lock, 0);

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

CK_RV p11prov_session_pool_free(P11PROV_SESSION_POOL *pool)
{
    P11PROV_SESSION *session;

    P11PROV_debug("Freeing session pool %p", pool);

    if (!pool) {
        return CKR_OK;
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

    return CKR_OK;
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
        CK_FUNCTION_LIST *f;
        ret = p11prov_ctx_status(session->provctx, &f);
        if (ret == CKR_OK) {
            /* Supports only USER login sessions for now */
            ret = f->C_Login(session->session, CKU_USER, pin, pinlen);
        }
        P11PROV_debug("Login session; ret:%lu, session:%lu", ret,
                      session->session);
        if (ret == CKR_USER_ALREADY_LOGGED_IN) {
            ret = CKR_OK;
        }
        if (ret != CKR_OK) {
            P11PROV_raise(session->provctx, ret, "Error returned by C_Login");
            internal_session_close(session);
        }
    }

    return ret;
}

void p11prov_session_free(P11PROV_SESSION *session)
{
    int ref;

    P11PROV_debug("Session Free %p", session);

    if (session == NULL) {
        return;
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
    if (ref == 1) {
        P11PROV_SESSION_POOL *p = session->pool;
        CK_ULONG cur_sessions;
        bool ok;
        int expected = 0;

        if (p == NULL) {
            /* session was orphaned, just free it */
            internal_session_close(session);
            OPENSSL_clear_free(session, sizeof(P11PROV_SESSION));
            return;
        }

        if (p->login_session == session) {
            __atomic_store_n(&session->pool->login_session, NULL,
                             __ATOMIC_SEQ_CST);
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
        ok = __atomic_compare_exchange_n(&session->free, &expected, 1, false,
                                         __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        if (!ok) {
            P11PROV_raise(session->provctx, CKR_GENERAL_ERROR,
                          "Expected a busy session on freeing, got: %d",
                          expected);
        }
    }
}

CK_SESSION_HANDLE p11prov_session_handle(P11PROV_SESSION *session)
{
    return session->session;
}

static CK_RV token_login(P11PROV_CTX *provctx, struct p11prov_slot *slot,
                         P11PROV_URI *uri, OSSL_PASSPHRASE_CALLBACK *pw_cb,
                         void *pw_cbarg)
{
    P11PROV_SESSION *session;
    char cb_pin[MAX_PIN_LENGTH + 1] = { 0 };
    size_t cb_pin_len = 0;
    CK_UTF8CHAR_PTR pin = NULL_PTR;
    CK_ULONG pinlen = 0;
    CK_RV ret;

    if (slot->pool->login_session) {
        /* we already have a login_session */
        return CKR_OK;
    }

    session = p11prov_session_new(provctx, slot);
    if (session == NULL) {
        return CKR_GENERAL_ERROR;
    }

    /* ref now, so we can simply p11prov_ession_free() later on errors */
    session = p11prov_session_ref(session);
    if (session == NULL) {
        P11PROV_raise(provctx, CKR_GENERAL_ERROR,
                      "Failed to ref count session");
        /* intentionally leave this broken session busy so it won't be
         * used anymore */
        return CKR_GENERAL_ERROR;
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

        pin = (CK_UTF8CHAR_PTR)cb_pin;
        pinlen = cb_pin_len;
    } else {
        ret = CKR_GENERAL_ERROR;
        goto done;
    }

    ret = p11prov_session_open(session, true, pin, pinlen);

done:
    if (ret == CKR_OK) {
        session->pool->login_session = session;
    } else {
        p11prov_session_free(session);
    }
    OPENSSL_cleanse(cb_pin, cb_pin_len);
    return ret;
}

static CK_RV check_slot(P11PROV_CTX *provctx, struct p11prov_slot *provslot,
                        bool reqlogin, P11PROV_URI *uri,
                        OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
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
    }
    if (ret == CKR_OK
        && ((provslot->token.flags & CKF_LOGIN_REQUIRED) || reqlogin)) {
        ret = token_login(provctx, provslot, uri, pw_cb, pw_cbarg);
    }

    if (ret == CKR_OK && reqlogin && !provslot->pool->login_session) {
        ret = CKR_USER_NOT_LOGGED_IN;
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
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
                          bool reqlogin, bool rw, P11PROV_SESSION **_session)
{
    P11PROV_SESSION *session = NULL;
    CK_SLOT_ID id = *slotid;
    struct p11prov_slot *slots = NULL;
    struct p11prov_slot *slot = NULL;
    int nslots = 0;
    int i;
    CK_FLAGS flags = DEFLT_SESSION_FLAGS;
    CK_RV ret = CKR_CANCEL;

    P11PROV_debug("Get session on slot %lu", id);

    nslots = p11prov_ctx_get_slots(provctx, &slots);

    if (id != CK_UNAVAILABLE_INFORMATION && next_slotid == NULL) {
        /* single shot request for a specific slot */
        for (i = 0; i < nslots; i++) {
            if (slots[i].id == id) {
                slot = &slots[i];
            }
        }
        if (slot == NULL) {
            return CKR_SLOT_ID_INVALID;
        }
        ret = check_slot(provctx, slot, reqlogin, uri, pw_cb, pw_cbarg);
        if (ret != CKR_OK) {
            return ret;
        }
    } else {
        /* caller is cycling through slots, find the next viable one */
        for (i = 0; i < nslots; i++) {
            /* seek to next slot to check */
            if (id != CK_UNAVAILABLE_INFORMATION && id != slots[i].id) {
                continue;
            } else {
                /* found next slot */
                id = CK_UNAVAILABLE_INFORMATION;
            }

            ret =
                check_slot(provctx, &slots[i], reqlogin, uri, pw_cb, pw_cbarg);
            if (ret != CKR_OK) {
                /* keep going */
                continue;
            }

            slot = &slots[i];
            id = slots[i].id;
            break;
        }

        if (ret == CKR_OK) {
            /* Found a slot, return it and the next slot to the caller for
             * continuation if the current slot does not yield the desired
             * results */
            *slotid = id;
            if (next_slotid) {
                if (i + 1 < nslots) {
                    *next_slotid = slots[i + 1].id;
                } else {
                    *next_slotid = CK_UNAVAILABLE_INFORMATION;
                }
            }
        } else {
            if (next_slotid) {
                *next_slotid = CK_UNAVAILABLE_INFORMATION;
            }
            return ret;
        }
    }

    if (rw) {
        flags |= CKF_RW_SESSION;
    }

    /* LOCKED SECTION ------------- */
    pthread_mutex_lock(&slot->pool->lock);
    for (i = 0; i < slot->pool->num_p11sessions; i++) {
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
        }
    }
    pthread_mutex_unlock(&slot->pool->lock);
    /* ------------- LOCKED SECTION */

    if (ret != CKR_OK) {
        return ret;
    }

    if (session == NULL) {
        session = p11prov_session_new(provctx, slot);
        if (session == NULL) {
            return CKR_GENERAL_ERROR;
        }
    }

    /* ref now, so we can simply p11prov_session_free() later on errors */
    session = p11prov_session_ref(session);
    if (session == NULL) {
        P11PROV_raise(provctx, CKR_GENERAL_ERROR,
                      "Failed to ref count session");
        /* intentionally leave this broken session busy so it won't be
         * used anymore */
        return CKR_GENERAL_ERROR;
    }

    session->flags = flags;

    if (session->session != CK_INVALID_HANDLE) {
        /* check that the pkcs11 session is still ok */
        CK_FUNCTION_LIST *f;
        CK_SESSION_INFO session_info;

        ret = p11prov_ctx_status(provctx, &f);
        if (ret != CKR_OK) {
            goto done;
        }

        ret = f->C_GetSessionInfo(session->session, &session_info);
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
            P11PROV_raise(provctx, ret, "Error returned by C_GetSessionInfo");
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
    return ret;
}
