/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _SESSION_H
#define _SESSION_H

/* Sessions */
CK_RV p11prov_session_pool_init(P11PROV_CTX *ctx, CK_TOKEN_INFO *token,
                                CK_SLOT_ID id, P11PROV_SESSION_POOL **_pool);
void p11prov_session_pool_free(P11PROV_SESSION_POOL *pool);
void p11prov_session_pool_fork_reset(P11PROV_SESSION_POOL *pool);

CK_SESSION_HANDLE p11prov_session_handle(P11PROV_SESSION *session);
CK_SLOT_ID p11prov_session_slotid(P11PROV_SESSION *session);
CK_RV p11prov_get_session(P11PROV_CTX *provctx, CK_SLOT_ID *slotid,
                          CK_SLOT_ID *next_slotid, P11PROV_URI *uri,
                          CK_MECHANISM_TYPE mechtype,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
                          bool reqlogin, bool rw, P11PROV_SESSION **session);
CK_RV p11prov_take_login_session(P11PROV_CTX *provctx, CK_SLOT_ID slotid,
                                 P11PROV_SESSION **_session);
void p11prov_return_session(P11PROV_SESSION *session);

CK_RV p11prov_context_specific_login(P11PROV_SESSION *session, P11PROV_URI *uri,
                                     OSSL_PASSPHRASE_CALLBACK *pw_cb,
                                     void *pw_cbarg);

typedef CK_RV (*p11prov_session_callback_t)(void *cbarg);
void p11prov_session_set_callback(P11PROV_SESSION *session,
                                  p11prov_session_callback_t cb, void *cbarg);

/* Some reasonable limit */
#define MAX_CONCURRENT_SESSIONS 1024
#define MAX_CACHE_SESSIONS 5

#endif /* _SESSION_H */
