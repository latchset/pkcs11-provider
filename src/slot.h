/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _SLOT_H
#define _SLOT_H

/* Slots */
CK_RV p11prov_init_slots(P11PROV_CTX *ctx, P11PROV_SLOTS_CTX **slots);
void p11prov_free_slots(P11PROV_SLOTS_CTX *slots);
void p11prov_slot_fork_prepare(P11PROV_SLOTS_CTX *sctx);
void p11prov_slot_fork_release(P11PROV_SLOTS_CTX *sctx);
void p11prov_slot_fork_reset(P11PROV_SLOTS_CTX *sctx);
CK_RV p11prov_take_slots(P11PROV_CTX *ctx, P11PROV_SLOTS_CTX **slots);
void p11prov_return_slots(P11PROV_SLOTS_CTX *slots);
P11PROV_SLOT *p11prov_fetch_slot(P11PROV_SLOTS_CTX *sctx, int *idx);
P11PROV_SLOT *p11prov_get_slot_by_id(P11PROV_SLOTS_CTX *sctx, CK_SLOT_ID id);
int p11prov_slot_get_mechanisms(P11PROV_SLOT *slot, CK_MECHANISM_TYPE **mechs);
int p11prov_check_mechanism(P11PROV_CTX *ctx, CK_SLOT_ID id,
                            CK_MECHANISM_TYPE mechtype);
CK_RV p11prov_slot_get_obj_pool(P11PROV_CTX *provctx, CK_SLOT_ID id,
                                P11PROV_OBJ_POOL **pool);
typedef bool (*slot_pool_callback)(void *, P11PROV_OBJ_POOL *);
CK_RV p11prov_slot_find_obj_pool(P11PROV_CTX *ctx, slot_pool_callback cb,
                                 void *cb_ctx);
CK_SLOT_ID p11prov_slot_get_slot_id(P11PROV_SLOT *slot);
CK_SLOT_INFO *p11prov_slot_get_slot(P11PROV_SLOT *slot);
CK_TOKEN_INFO *p11prov_slot_get_token(P11PROV_SLOT *slot);
const char *p11prov_slot_get_login_info(P11PROV_SLOT *slot);
const char *p11prov_slot_get_bad_pin(P11PROV_SLOT *slot);
CK_RV p11prov_slot_set_bad_pin(P11PROV_SLOT *slot, const char *bad_pin);
const char *p11prov_slot_get_cached_pin(P11PROV_SLOT *slot);
CK_RV p11prov_slot_set_cached_pin(P11PROV_SLOT *slot, const char *cached_pin);
P11PROV_SESSION_POOL *p11prov_slot_get_session_pool(P11PROV_SLOT *slot);
bool p11prov_slot_check_req_login(P11PROV_SLOT *slot);

#endif /* _SLOT_H */
