/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>

/* Session stuff */
struct p11prov_session {
    P11PROV_CTX *provctx;

    CK_SLOT_ID slotid;
    CK_SESSION_HANDLE session;

    int refcnt;
};

P11PROV_SESSION *p11prov_session_new(P11PROV_CTX *ctx, CK_SLOT_ID slotid)
{
    P11PROV_SESSION *sess;

    sess = OPENSSL_zalloc(sizeof(P11PROV_SESSION));
    if (sess == NULL) {
        P11PROV_raise(ctx, CKR_HOST_MEMORY, "Failed to allocate session");
        return NULL;
    }

    sess->provctx = ctx;
    sess->slotid = slotid;
    sess->session = CK_INVALID_HANDLE;

    sess->refcnt = 1;

    return sess;
}

P11PROV_SESSION *p11prov_session_ref(P11PROV_SESSION *session)
{
    if (session
        && __atomic_fetch_add(&session->refcnt, 1, __ATOMIC_SEQ_CST) > 0) {
        return session;
    }

    return NULL;
}

CK_RV p11prov_session_open(P11PROV_SESSION *session, bool login,
                           CK_UTF8CHAR_PTR pin, CK_ULONG pinlen)
{
    CK_FUNCTION_LIST *f;
    CK_RV ret;

    ret = p11prov_ctx_status(session->provctx, &f);
    if (ret != CKR_OK) {
        return ret;
    }

    ret = f->C_OpenSession(session->slotid, CKF_SERIAL_SESSION, NULL, NULL,
                           &session->session);
    if (ret != CKR_OK) {
        P11PROV_raise(session->provctx, ret,
                      "Failed to open session on slot %lu", session->slotid);
        return CKR_FUNCTION_FAILED;
    }

    if (!login) {
        return CKR_OK;
    }

    /* Supports only USER login sessions for now */
    ret = f->C_Login(session->session, CKU_USER, pin, pinlen);
    if (ret != CKR_OK && ret != CKR_USER_ALREADY_LOGGED_IN) {
        int retc;
        P11PROV_raise(session->provctx, ret, "Error returned by C_Login");
        retc = f->C_CloseSession(session->session);
        if (retc != CKR_OK) {
            P11PROV_raise(session->provctx, retc, "Failed to close session %lu",
                          session->session);
        }
        return ret;
    }

    return CKR_OK;
}

void p11prov_session_free(P11PROV_SESSION *session)
{
    if (session == NULL) {
        return;
    }

    if (__atomic_sub_fetch(&session->refcnt, 1, __ATOMIC_SEQ_CST) != 0) {
        return;
    }

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
    }

    OPENSSL_clear_free(session, sizeof(P11PROV_SESSION));
}

CK_SESSION_HANDLE p11prov_session_handle(P11PROV_SESSION *session)
{
    return session->session;
}

static CK_RV token_login(P11PROV_CTX *provctx, CK_SLOT_ID slotid,
                         P11PROV_URI *uri, OSSL_PASSPHRASE_CALLBACK *pw_cb,
                         void *pw_cbarg)
{
    P11PROV_SESSION *sess;
    char cb_pin[MAX_PIN_LENGTH + 1] = { 0 };
    size_t cb_pin_len = 0;
    CK_UTF8CHAR_PTR pin;
    CK_ULONG pinlen = 0;
    CK_RV ret;

    ret = p11prov_ctx_get_login_session(provctx, &sess);
    if (ret != CKR_OK) {
        return ret;
    }
    if (sess) {
        /* we already have a login_session */
        return CKR_OK;
    }

    sess = p11prov_session_new(provctx, slotid);
    if (sess == NULL) {
        return CKR_HOST_MEMORY;
    }

    pin = (CK_UTF8CHAR_PTR)p11prov_uri_get_pin(uri);
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

    ret = p11prov_session_open(sess, true, pin, pinlen);

done:
    OPENSSL_cleanse(cb_pin, cb_pin_len);
    return ret;
}

CK_RV p11prov_get_session(P11PROV_CTX *provctx, CK_SLOT_ID *slotid,
                          CK_SLOT_ID *next_slotid, P11PROV_URI *uri,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
                          P11PROV_SESSION **session)
{
    P11PROV_SESSION *sess;
    CK_SLOT_ID id = *slotid;
    struct p11prov_slot *slots = NULL;
    int nslots = 0;
    int i;
    CK_RV ret = CKR_CANCEL;

    nslots = p11prov_ctx_lock_slots(provctx, &slots);

    for (i = 0; i < nslots; i++) {
        if (id != CK_UNAVAILABLE_INFORMATION && id != slots[i].id) {
            continue;
        }

        /* ignore slots that are not initialized */
        if ((slots[i].slot.flags & CKF_TOKEN_PRESENT) == 0) {
            continue;
        }
        if ((slots[i].token.flags & CKF_TOKEN_INITIALIZED) == 0) {
            continue;
        }

        id = slots[i].id;
        ret = CKR_OK;

        if (uri) {
            CK_TOKEN_INFO token = slots[i].token;

            /* skip slots that do not match */
            ret = p11prov_uri_match_token(uri, &token);
            if (ret == CKR_CANCEL) {
                continue;
            }
            if (ret == CKR_OK && (token.flags & CKF_LOGIN_REQUIRED)) {
                ret = token_login(provctx, id, uri, pw_cb, pw_cbarg);
            }
        }
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
        *next_slotid = CK_UNAVAILABLE_INFORMATION;
    }

    p11prov_ctx_unlock_slots(provctx, &slots);

    if (ret != CKR_OK) {
        return ret;
    }

    sess = p11prov_session_new(provctx, id);
    if (sess == NULL) {
        return CKR_HOST_MEMORY;
    }
    ret = p11prov_session_open(sess, false, NULL, 0);
    if (ret != CKR_OK) {
        return ret;
    }
    *session = sess;
    return CKR_OK;
}
