/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _SESSION_H
#define _SESSION_H

/* Slots */
CK_RV p11prov_get_slots(P11PROV_CTX *ctx, P11PROV_SLOT ***rslots, int *num);
void p11prov_free_slots(P11PROV_SLOT **slots, int nslots);
int p11prov_slot_get_mechanisms(P11PROV_SLOT *slot, CK_MECHANISM_TYPE **mechs);

/* Sessions */
CK_RV p11prov_session_pool_init(P11PROV_CTX *ctx, CK_TOKEN_INFO *token,
                                P11PROV_SESSION_POOL **_pool);
CK_RV p11prov_session_pool_free(P11PROV_SESSION_POOL *pool);
void p11prov_session_free(P11PROV_SESSION *session);
CK_SESSION_HANDLE p11prov_session_handle(P11PROV_SESSION *session);
CK_SLOT_ID p11prov_session_slotid(P11PROV_SESSION *session);
CK_RV p11prov_get_session(P11PROV_CTX *provctx, CK_SLOT_ID *slotid,
                          CK_SLOT_ID *next_slotid, P11PROV_URI *uri,
                          CK_MECHANISM_TYPE mechtype,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
                          bool reqlogin, bool rw, P11PROV_SESSION **session);
CK_RV p11prov_take_login_session(P11PROV_CTX *provctx, CK_SLOT_ID slotid,
                                 P11PROV_SESSION **_session);
void p11prov_return_login_session(P11PROV_SESSION *session);

#endif /* _SESSION_H */
