/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>
#include <sys/types.h>

#define DEFLT_SESSION_FLAGS CKF_SERIAL_SESSION
struct p11prov_session {
    P11PROV_CTX *provctx;
    P11PROV_SESSION_POOL *pool;

    CK_SLOT_ID slotid;
    CK_SESSION_HANDLE session;
    CK_STATE state;
    CK_FLAGS flags;

    pthread_mutex_t lock;
    bool in_use;

    p11prov_session_callback_t cb;
    void *cbarg;
};

struct p11prov_session_pool {
    P11PROV_CTX *provctx;
    CK_SLOT_ID slotid;

    CK_ULONG num_sessions;
    CK_ULONG max_sessions;
    CK_ULONG open_sessions;
    CK_ULONG max_cached_sessions;

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
    CK_SESSION_INFO session_info;
    uint64_t startime = 0;
    CK_RV ret;

    do {
        if (p11prov_ctx_no_session_callbacks(session->provctx)) {
            P11PROV_debug("Opening session without callbacks %lu",
                          session->session);
            ret = p11prov_OpenSession(session->provctx, session->slotid, flags,
                                      NULL, NULL, &session->session);
        } else {
            ret = p11prov_OpenSession(session->provctx, session->slotid, flags,
                                      session, token_session_callback,
                                      &session->session);
        }
        P11PROV_debug("C_OpenSession ret:%lu (session: %lu)", ret,
                      session->session);
        if (ret != CKR_SESSION_COUNT) {
            break;
        }
    } while (cyclewait_with_timeout(MAX_WAIT, SLEEP, &startime));

    if (ret != CKR_OK) {
        session->session = CK_INVALID_HANDLE;
        session->flags = DEFLT_SESSION_FLAGS;
        session->state = CK_UNAVAILABLE_INFORMATION;
        return ret;
    }

    session->flags = flags;

    /* get current state */
    ret = p11prov_GetSessionInfo(session->provctx, session->session,
                                 &session_info);
    if (ret == CKR_OK) {
        session->flags = session_info.flags;
        session->state = session_info.state;
    }
    return ret;
}

static void token_session_close(P11PROV_SESSION *session)
{
    if (session->session != CK_INVALID_HANDLE) {
        P11PROV_debug("Closing session %lu", session->session);
        (void)p11prov_CloseSession(session->provctx, session->session);
        /* regardless of the result the session is gone */
        session->session = CK_INVALID_HANDLE;
        session->flags = DEFLT_SESSION_FLAGS;
        session->state = CK_UNAVAILABLE_INFORMATION;
    }
}

CK_RV p11prov_session_pool_init(P11PROV_CTX *ctx, CK_TOKEN_INFO *token,
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
    } else {
        pool->max_sessions = MAX_CONCURRENT_SESSIONS;
    }

    pool->max_cached_sessions = p11prov_ctx_cache_sessions(ctx);
    if (pool->max_sessions < pool->max_cached_sessions) {
        pool->max_cached_sessions = pool->max_sessions - 1;
    }

    P11PROV_debug("New session pool %p created", pool);

    *_pool = pool;
    return CKR_OK;
}

static void session_free(P11PROV_SESSION *session);

void p11prov_session_pool_free(P11PROV_SESSION_POOL *pool)
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

static CK_RV session_new_bare(P11PROV_SESSION_POOL *pool,
                              P11PROV_SESSION **_session);

void p11prov_session_pool_fork_reset(P11PROV_SESSION_POOL *pool)
{
    P11PROV_debug("Resetting sessions in pool %p", pool);

    if (!pool) {
        return;
    }

    if (MUTEX_LOCK(pool) == CKR_OK) {
        /* LOCKED SECTION ------------- */
        pool->login_session = NULL;
        for (int i = 0; i < pool->num_sessions; i++) {
            P11PROV_SESSION *session = pool->sessions[i];
            CK_RV ret;

            session->session = CK_INVALID_HANDLE;
            session->flags = DEFLT_SESSION_FLAGS;
            session->state = CK_UNAVAILABLE_INFORMATION;
            session->in_use = false;
            session->cb = NULL;
            session->cbarg = NULL;

            /* at last reinit mutex and replace on failure */
            ret = MUTEX_INIT(session);
            if (ret != CKR_OK) {
                /* this is bad, but all we can do is hope this
                 * session will never be used and just orphan it */
                P11PROV_debug("Failed to reinint session lock");
                session->pool = NULL;
                /* if this fails nothing really we can do,
                 * we leave the current broken session and
                 * it will never be used because lockig it
                 * should always fail */
                ret = session_new_bare(pool, &session);
                if (ret != CKR_OK) {
                    /* session was unchanged, put the pool back */
                    session->pool = pool;
                }
            }
        }
        (void)MUTEX_UNLOCK(pool);
        /* ------------- LOCKED SECTION */
    } else {
        P11PROV_debug("Failed to reset sessions in pool");
    }
}

static CK_RV session_new_bare(P11PROV_SESSION_POOL *pool,
                              P11PROV_SESSION **_session)
{
    P11PROV_SESSION *session;
    int ret;

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
    session->state = CK_UNAVAILABLE_INFORMATION;
    session->pool = pool;

    ret = MUTEX_INIT(session);
    if (ret != CKR_OK) {
        OPENSSL_free(session);
        return ret;
    }

    *_session = session;
    return CKR_OK;
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
        P11PROV_raise(pool->provctx, ret, "Max sessions (%lu) exceeded",
                      pool->max_sessions);
        return ret;
    }

    ret = session_new_bare(pool, &session);
    if (ret != CKR_OK) {
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

    /* mark this session as owned only once nothing else can fail */
    session->in_use = true;

    pool->sessions[pool->num_sessions] = session;
    pool->num_sessions++;
    P11PROV_debug("Total sessions: %lu", pool->num_sessions);

    *_session = session;
    return CKR_OK;
}

static CK_RV session_check(P11PROV_SESSION *session, CK_FLAGS flags)
{
    CK_SESSION_INFO session_info;
    int ret;

    if (!session) {
        return CKR_GENERAL_ERROR;
    }

    /* lockless check, if this fails in any way it is bad regardless */
    if (!session->in_use) {
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
        session->state = session_info.state;
        if (flags == session_info.flags) {
            return CKR_OK;
        }
        (void)p11prov_CloseSession(session->provctx, session->session);
        /* tell the caller that the session was closed so they can
         * keep up with accounting */
        ret = CKR_SESSION_CLOSED;
    }

    /* session has been closed elsewhere, or otherwise unusable */
    session->session = CK_INVALID_HANDLE;
    session->state = CK_UNAVAILABLE_INFORMATION;
    return ret;
}

/* only call this from session_new or p11prov_session_pool_free */
static void session_free(P11PROV_SESSION *session)
{
    bool abandon = true;
    int ret;

    P11PROV_debug("Session Free %p", session);

    if (session == NULL) {
        return;
    }

    ret = MUTEX_LOCK(session);
    /* LOCKED SECTION ------------- */
    if (ret == CKR_OK) {
        if (!session->in_use) {
            abandon = false;
        }
        (void)MUTEX_UNLOCK(session);
        /* ------------- LOCKED SECTION */
    }

    if (abandon) {
        /* just orphan this session, will potentially leak memory ... */
        session->pool = NULL;
        return;
    }

    (void)MUTEX_DESTROY(session);

    token_session_close(session);

    OPENSSL_clear_free(session, sizeof(P11PROV_SESSION));
}

CK_SESSION_HANDLE p11prov_session_handle(P11PROV_SESSION *session)
{
    if (!session) {
        return CK_INVALID_HANDLE;
    }
    return session->session;
}

CK_SLOT_ID p11prov_session_slotid(P11PROV_SESSION *session)
{
    if (!session) {
        return CK_UNAVAILABLE_INFORMATION;
    }
    return session->slotid;
}

static int p11prov_session_prompt_for_pin(struct p11prov_slot *slot,
                                          char *cb_pin, size_t *cb_pin_len)
{
    char *prompt = NULL;
    UI *ui = UI_new_method(NULL);
    const char *login_info = p11prov_slot_get_login_info(slot);
    int ret;

    P11PROV_debug("Starting internal PIN prompt slot=%p", slot);

    if (ui == NULL) {
        ret = RET_OSSL_ERR;
        goto err;
    }
    prompt = UI_construct_prompt(ui, "PIN", login_info);
    if (!prompt) {
        ret = RET_OSSL_ERR;
        goto err;
    }
    ret = UI_dup_input_string(ui, prompt, UI_INPUT_FLAG_DEFAULT_PWD, cb_pin, 4,
                              MAX_PIN_LENGTH);
    if (ret <= 0) {
        ret = RET_OSSL_ERR;
        goto err;
    }

    if (UI_process(ui)) {
        ret = RET_OSSL_ERR;
        goto err;
    }

    *cb_pin_len = strlen(cb_pin);

err:
    OPENSSL_free(prompt);
    UI_free(ui);
    return ret;
}

/* returns a locked login_session if _session is not NULL */
static CK_RV token_login(P11PROV_SESSION *session, P11PROV_URI *uri,
                         OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
                         struct p11prov_slot *slot, CK_USER_TYPE user_type)
{
    char cb_pin[MAX_PIN_LENGTH + 1] = { 0 };
    size_t cb_pin_len = 0;
    CK_UTF8CHAR_PTR pin = NULL_PTR;
    CK_ULONG pinlen = 0;
    CK_TOKEN_INFO *token;
    bool cache = false;
    CK_RV ret;

    P11PROV_debug("Log into the token session=%p uri=%p slot=%p type=%lu",
                  session, uri, slot, user_type);

    token = p11prov_slot_get_token(slot);
    if (!(token->flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
        const char *cached_pin = p11prov_slot_get_cached_pin(slot);
        const char *bad_pin = p11prov_slot_get_bad_pin(slot);
        if (uri) {
            pin = (CK_UTF8CHAR_PTR)p11prov_uri_get_pin(uri);
        }
        if (!pin) {
            pin = p11prov_ctx_pin(session->provctx);
        }
        if (!pin && cached_pin) {
            pin = (CK_UTF8CHAR_PTR)cached_pin;
        }
        if (pin && bad_pin && strcmp((char *)pin, bad_pin) == 0) {
            P11PROV_raise(session->provctx, CKR_PIN_INVALID,
                          "Blocking stored PIN that failed a previous login"
                          " to avoid blocking the token");
            pin = NULL;
        }
        if (pin) {
            pinlen = strlen((const char *)pin);
        } else {
            if (pw_cb) {
                const char *login_info = p11prov_slot_get_login_info(slot);
                OSSL_PARAM params[2] = {
                    OSSL_PARAM_DEFN(OSSL_PASSPHRASE_PARAM_INFO,
                                    OSSL_PARAM_UTF8_STRING, (void *)login_info,
                                    strlen(login_info)),
                    OSSL_PARAM_END,
                };
                ret = pw_cb(cb_pin, sizeof(cb_pin), &cb_pin_len, params,
                            pw_cbarg);
                if (ret != RET_OSSL_OK) {
                    /* this error can mean anything from the user canceling
                     * the prompt to no UI method provided.
                     * Fall back to our prompt here */
                    ret = p11prov_session_prompt_for_pin(slot, (char *)cb_pin,
                                                         &cb_pin_len);
                    if (ret != RET_OSSL_OK) {
                        /* give up */
                        ret = CKR_GENERAL_ERROR;
                        goto done;
                    }
                }
            } else {
                /* We are asking the user off-band for the user consent -- from
                 * store we will always receive non-null (but unusable) callback
                 */
                ret = p11prov_session_prompt_for_pin(slot, (char *)cb_pin,
                                                     &cb_pin_len);
                if (ret != RET_OSSL_OK) {
                    ret = CKR_GENERAL_ERROR;
                    goto done;
                }
            }
            if (cb_pin_len == 0) {
                ret = CKR_CANCEL;
                goto done;
            }

            pin = (CK_UTF8CHAR_PTR)cb_pin;
            pinlen = cb_pin_len;

            cache = p11prov_ctx_cache_pins(session->provctx);
        }
    }

    P11PROV_debug("Attempt Login on session %lu", session->session);
    /* Supports only USER login sessions for now */
    ret = p11prov_Login(session->provctx, session->session, user_type, pin,
                        pinlen);
    if (ret == CKR_USER_ALREADY_LOGGED_IN) {
        ret = CKR_OK;
    } else {
        if (pin && ret == CKR_PIN_INCORRECT) {
            CK_RV trv;
            /* mark this pin as bad or we may end up locking the token */
            trv = p11prov_slot_set_bad_pin(slot, (const char *)pin);
            /* not much we can do on failure */
            if (trv != CKR_OK) {
                P11PROV_raise(session->provctx, trv, "Failed to set bad_pin");
            }
        }
    }
    if (ret == CKR_OK && pin && cache) {
        CK_RV trv;
        trv = p11prov_slot_set_cached_pin(slot, (const char *)pin);
        /* not much we can do on failure */
        if (trv != CKR_OK) {
            P11PROV_raise(session->provctx, trv, "Failed to cache pin");
        }
    }

done:
    OPENSSL_cleanse(cb_pin, cb_pin_len);
    return ret;
}

CK_RV p11prov_context_specific_login(P11PROV_SESSION *session, P11PROV_URI *uri,
                                     OSSL_PASSPHRASE_CALLBACK *pw_cb,
                                     void *pw_cbarg)
{
    P11PROV_SLOTS_CTX *sctx = NULL;
    P11PROV_SLOT *slot = NULL;
    CK_RV ret;

    P11PROV_debug("Providing context specific login session=%p uri=%p", session,
                  uri);

    ret = p11prov_take_slots(session->provctx, &sctx);
    if (ret != CKR_OK) {
        return CKR_GENERAL_ERROR;
    }

    slot = p11prov_get_slot_by_id(sctx, p11prov_session_slotid(session));
    if (!slot) {
        ret = CKR_GENERAL_ERROR;
        goto done;
    }

    ret =
        token_login(session, uri, pw_cb, pw_cbarg, slot, CKU_CONTEXT_SPECIFIC);

done:
    p11prov_return_slots(sctx);
    return ret;
}

static CK_RV check_slot(P11PROV_CTX *ctx, P11PROV_SLOT *slot, P11PROV_URI *uri,
                        CK_MECHANISM_TYPE mechtype, bool rw)
{
    CK_TOKEN_INFO *token;
    CK_SLOT_INFO *ck_slot;
    CK_SLOT_ID slotid;
    CK_RV ret;

    slotid = p11prov_slot_get_slot_id(slot);

    P11PROV_debug("Checking Slot id=%lu, uri=%p, mechtype=%lx, rw=%s)", slotid,
                  uri, mechtype, rw ? "true" : "false");

    ck_slot = p11prov_slot_get_slot(slot);
    if ((ck_slot->flags & CKF_TOKEN_PRESENT) == 0) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    token = p11prov_slot_get_token(slot);
    if ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    if (rw && (token->flags & CKF_WRITE_PROTECTED)) {
        return CKR_TOKEN_WRITE_PROTECTED;
    }
    if (uri) {
        ret = p11prov_uri_match_token(uri, slotid, ck_slot, token);
        if (ret != CKR_OK) {
            return ret;
        }
    }
    if (mechtype != CK_UNAVAILABLE_INFORMATION) {
        ret = p11prov_check_mechanism(ctx, slotid, mechtype);
        if (ret != CKR_OK) {
            return ret;
        }
    }
    return CKR_OK;
}

static bool is_login_state(CK_STATE state)
{
    switch (state) {
    case CKS_RO_USER_FUNCTIONS:
    case CKS_RW_USER_FUNCTIONS:
    case CKS_RW_SO_FUNCTIONS:
        return true;
    default:
        break;
    }
    return false;
}

static CK_RV fetch_session(P11PROV_SESSION_POOL *pool, CK_FLAGS flags,
                           bool login_session, P11PROV_SESSION **_session)
{
    P11PROV_SESSION *session = NULL;
    bool found = false;
    int ret;

    ret = MUTEX_LOCK(pool);
    if (ret != CKR_OK) {
        return ret;
    }
    /* LOCKED SECTION ------------- */

    if (login_session && pool->login_session) {
        ret = MUTEX_LOCK(pool->login_session);
        if (ret == CKR_OK) {
            if (pool->login_session->in_use) {
                if (is_login_state(pool->login_session->state)) {
                    ret = CKR_USER_ALREADY_LOGGED_IN;
                } else {
                    ret = CKR_CANT_LOCK;
                }
            } else {
                session = pool->login_session;
                session->in_use = true;
                found = true;
            }
            (void)MUTEX_UNLOCK(pool->login_session);
        }
        goto done;
    }

    /* try to find session with a cached handle first */
    for (int i = 0; i < pool->num_sessions && !found; i++) {
        session = pool->sessions[i];
        if (session == pool->login_session) {
            continue;
        }
        if (session->flags == flags) {
            if (session->session != CK_INVALID_HANDLE) {
                ret = MUTEX_LOCK(session);
                if (ret == CKR_OK) {
                    /* LOCKED SECTION ------------- */
                    if (!session->in_use) {
                        /* Bingo! A compatible session with a cached handle */
                        session->in_use = true;
                        found = true;
                    }
                    /* No luck */
                    (void)MUTEX_UNLOCK(session);
                    /* ------------- LOCKED SECTION */
                }
            }
        }
    }

    /* try again, get any free session */
    for (int i = 0; i < pool->num_sessions && !found; i++) {
        session = pool->sessions[i];
        if (session == pool->login_session) {
            continue;
        }
        ret = MUTEX_LOCK(session);
        if (ret == CKR_OK) {
            /* LOCKED SECTION ------------- */
            if (!session->in_use) {
                /* we got a free session */
                session->in_use = true;
                found = true;
            }
            /* No luck */
            (void)MUTEX_UNLOCK(session);
            /* ------------- LOCKED SECTION */
        }
    }

    if (!found) {
        session = NULL;
        /* no free sessions, try to allocate a new one */
        ret = session_new(pool, &session);
        if (ret == CKR_OK) {
            found = true;
        }
    }

done:
    if (login_session && found) {
        pool->login_session = session;
    }

    (void)MUTEX_UNLOCK(pool);
    /* ------------- LOCKED SECTION */

    if (ret == CKR_OK) {
        *_session = session;
    }
    return ret;
}

/* sleep interval, 5 microseconds */
#define LOCK_SLEEP 5000
static CK_RV slot_login(P11PROV_SLOT *slot, P11PROV_URI *uri,
                        OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
                        bool reqlogin, P11PROV_SESSION **_session)
{
    P11PROV_SESSION_POOL *pool = p11prov_slot_get_session_pool(slot);
    P11PROV_SESSION *session = NULL;
    CK_FLAGS flags = DEFLT_SESSION_FLAGS;
    int num_open_sessions = 0;
    CK_RV ret;

    /* try to get a login_session */
    ret = fetch_session(pool, flags, true, &session);
    if (ret == CKR_USER_ALREADY_LOGGED_IN && _session == NULL) {
        P11PROV_debug("A login session already exists");
        return CKR_OK;
    }

    if (ret != CKR_OK) {
        if (reqlogin) {
            /* try a few times to get a login session,
             * but eventually timeout if it doesn't work to avoid deadlocks */
            uint64_t startime = 0;
            do {
                ret = fetch_session(pool, flags, true, &session);
                if (ret == CKR_OK) {
                    break;
                }
            } while (cyclewait_with_timeout(MAX_WAIT, LOCK_SLEEP, &startime));
        }

        if (ret != CKR_OK) {
            P11PROV_raise(pool->provctx, ret, "Failed to fetch login_session");
            return ret;
        }
    }

    /* we acquired the session, check that it is ok */
    ret = session_check(session, session->flags);
    if (ret != CKR_OK) {
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

    if (is_login_state(session->state)) {
        /* we seem to already have a valid logged in session */
        ret = CKR_OK;
    } else {
        ret = token_login(session, uri, pw_cb, pw_cbarg, slot, CKU_USER);
    }

done:
    /* lock the pool only if needed */
    if (num_open_sessions != 0 || ret != CKR_OK) {

        /* LOCKED SECTION ------------- */
        if (MUTEX_LOCK(pool) == CKR_OK) {

            pool->open_sessions += num_open_sessions;

            if (ret != CKR_OK) {
                if (pool->login_session != session) {
                    /* something raced us during the login and replaced
                     * the login session, hands off */
                } else {
                    /* remove the session, as it is not a good one */
                    pool->login_session = NULL;
                }
            }

            (void)MUTEX_UNLOCK(pool);
        }
        /* ------------- LOCKED SECTION */
    }

    if (_session) {
        *_session = session;
    } else {
        /* unlock the session */
        p11prov_return_session(session);
    }
    return ret;
}

static bool check_skip_login(P11PROV_CTX *ctx, P11PROV_SLOT *slot)
{
    return p11prov_ctx_login_behavior(ctx) != PUBKEY_LOGIN_ALWAYS
           && !p11prov_slot_check_req_login(slot);
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

    P11PROV_debug("Get session on slot %lu, reqlogin=%s, rw=%s", id,
                  reqlogin ? "true" : "false", rw ? "true" : "false");

    ret = p11prov_take_slots(provctx, &slots);
    if (ret != CKR_OK) {
        return ret;
    }

    if (id != CK_UNAVAILABLE_INFORMATION && next_slotid == NULL) {
        P11PROV_debug("single-shot request for slot %lu", id);
        slot_idx = 0;
        /* single shot request for a specific slot */
        for (slot = p11prov_fetch_slot(slots, &slot_idx); slot != NULL;
             slot = p11prov_fetch_slot(slots, &slot_idx)) {
            if (p11prov_slot_get_slot_id(slot) == id) {
                break;
            }
        }
        if (!slot) {
            ret = CKR_SLOT_ID_INVALID;
            goto done;
        }
        ret = check_slot(provctx, slot, uri, mechtype, rw);
        if (ret != CKR_OK) {
            goto done;
        }
        if (reqlogin && !check_skip_login(provctx, slot)) {
            ret = slot_login(slot, uri, pw_cb, pw_cbarg, reqlogin, NULL);
            if (ret != CKR_OK) {
                goto done;
            }
        }
    } else {
        P11PROV_debug("cycle through available slots");
        slot_idx = 0;
        ret = CKR_CANCEL;

        /* set error mark so we can clear spurious errors on success */
        p11prov_set_error_mark(provctx);

        /* caller is cycling through slots, find the next viable one */
        for (slot = p11prov_fetch_slot(slots, &slot_idx); slot != NULL;
             slot = p11prov_fetch_slot(slots, &slot_idx)) {
            CK_SLOT_ID slot_id = p11prov_slot_get_slot_id(slot);
            if (id != CK_UNAVAILABLE_INFORMATION && id != slot_id) {
                /* seek to next slot to check */
                continue;
            } else {
                /* Found "next" slot.
                 * Reset the id, so from now on we check every following slot
                 * and return the first one that successfully passes checks.
                 */
                id = CK_UNAVAILABLE_INFORMATION;
            }

            ret = check_slot(provctx, slot, uri, mechtype, rw);
            if (ret != CKR_OK) {
                /* keep going */
                continue;
            }
            if (reqlogin && !check_skip_login(provctx, slot)) {
                ret = slot_login(slot, uri, pw_cb, pw_cbarg, reqlogin, NULL);
                if (ret != CKR_OK) {
                    /* keep going */
                    continue;
                }
            }

            id = slot_id;
            P11PROV_debug("Found a slot %lu", id);
            break;
        }

        if (ret == CKR_OK) {
            /* Found a slot, return it and the next slot to the caller for
             * continuation if the current slot does not yield the desired
             * results */

            /* if there was any error, remove it, as we got success */
            p11prov_pop_error_to_mark(provctx);

            *slotid = id;
            if (next_slotid) {
                P11PROV_SLOT *next_slot;
                next_slot = p11prov_fetch_slot(slots, &slot_idx);
                if (next_slot) {
                    *next_slotid = p11prov_slot_get_slot_id(next_slot);
                } else {
                    *next_slotid = CK_UNAVAILABLE_INFORMATION;
                }
            }
        } else {
            /* otherwise clear the mark and leave errors on the stack */
            p11prov_clear_last_error_mark(provctx);

            if (next_slotid) {
                *next_slotid = CK_UNAVAILABLE_INFORMATION;
            }
            goto done;
        }
    }

    pool = p11prov_slot_get_session_pool(slot);

    if (rw) {
        flags |= CKF_RW_SESSION;
    }

    ret = fetch_session(pool, flags, false, &session);
    if (ret == CKR_OK) {
        ret = session_check(session, flags);
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

        if (slotid == p11prov_slot_get_slot_id(slot)) {
            break;
        }
    }
    if (!slot || !p11prov_slot_get_session_pool(slot)) {
        ret = CKR_SLOT_ID_INVALID;
        goto done;
    }

    ret = slot_login(slot, NULL, NULL, NULL, false, _session);

done:
    p11prov_return_slots(slots);
    return ret;
}

void p11prov_return_session(P11PROV_SESSION *session)
{
    P11PROV_SESSION_POOL *pool;
    CK_RV ret;

    if (!session) {
        return;
    }

    /* remove any callback */
    p11prov_session_set_callback(session, NULL, NULL);

    pool = session->pool;

    if (pool) {
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

    ret = MUTEX_LOCK(session);
    if (ret == CKR_OK) {
        /* LOCKED SECTION ------------- */
        session->in_use = false;
        (void)MUTEX_UNLOCK(session);
        /* ------------- LOCKED SECTION */
    } else {
        /* not much we can do if this fails */
        P11PROV_raise(session->provctx, ret,
                      "Failed to release session object");
        return;
    }

    if (!pool) {
        /* handle case where session was orphaned because in use while
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
