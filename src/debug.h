/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _DEBUG_H
#define _DEBUG_H

/* Debugging */
extern int debug_lazy_init;
#define P11PROV_debug_status(action) \
    do { \
        int enabled = 0; \
        if (__atomic_compare_exchange_n(&debug_lazy_init, &enabled, -1, true, \
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) { \
            p11prov_debug_init(); \
        } \
        if (enabled >= 1) { \
            action; \
        } \
    } while (0)

#define P11PROV_debug(...) P11PROV_debug_status(p11prov_debug(__VA_ARGS__))

#define P11PROV_debug_mechanism(...) \
    P11PROV_debug_status(p11prov_debug_mechanism(__VA_ARGS__))

#define P11PROV_debug_slot(...) \
    P11PROV_debug_status(p11prov_debug_slot(__VA_ARGS__))

#define P11PROV_debug_once(...) \
    do { \
        static int called = 0; \
        if (!called) { \
            P11PROV_debug_status(p11prov_debug(__VA_ARGS__)); \
            called = 1; \
        } \
    } while (0)

void p11prov_debug_init(void);
void p11prov_debug(const char *fmt, ...);
void p11prov_debug_mechanism(P11PROV_CTX *ctx, CK_SLOT_ID slotid,
                             CK_MECHANISM_TYPE type);
void p11prov_debug_slot(P11PROV_CTX *ctx, CK_SLOT_ID slotid, CK_SLOT_INFO *slot,
                        CK_TOKEN_INFO *token, CK_MECHANISM_TYPE *mechs,
                        CK_ULONG mechs_num, CK_ULONG *profiles);

#endif /* _DEBUG_H */
