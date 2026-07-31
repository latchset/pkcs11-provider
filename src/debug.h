/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _DEBUG_H
#define _DEBUG_H

/* Debugging */
extern int debug_level;
#define P11PROV_debug(...) \
    do { \
        if (debug_level < 0) { \
            p11prov_debug_init(); \
        } \
        if (debug_level > 0) { \
            p11prov_debug(OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC, \
                          __VA_ARGS__); \
        } \
    } while (0)

#define P11PROV_debug_mechanism(...) \
    do { \
        if (debug_level < 0) { \
            p11prov_debug_init(); \
        } \
        if (debug_level > 0) { \
            p11prov_debug_mechanism(__VA_ARGS__); \
        } \
    } while (0)

#define P11PROV_debug_slot(...) \
    do { \
        if (debug_level < 0) { \
            p11prov_debug_init(); \
        } \
        if (debug_level > 0) { \
            p11prov_debug_slot(__VA_ARGS__); \
        } \
    } while (0)

#define P11PROV_debug_once(...) \
    do { \
        if (debug_level < 0) { \
            p11prov_debug_init(); \
        } \
        if (debug_level > 0) { \
            static int called = 0; \
            if (!called) { \
                P11PROV_debug(__VA_ARGS__); \
                called = 1; \
            } \
        } \
    } while (0)

void p11prov_debug_init(void);
void p11prov_debug(const char *file, int line, const char *func,
                   const char *fmt, ...);
void p11prov_debug_mechanism(P11PROV_CTX *ctx, CK_SLOT_ID slotid,
                             CK_MECHANISM_TYPE type);
void p11prov_debug_slot(P11PROV_CTX *ctx, CK_SLOT_ID slotid, CK_SLOT_INFO *slot,
                        CK_TOKEN_INFO *token, CK_MECHANISM_TYPE *mechs,
                        CK_ULONG mechs_num, CK_ULONG *profiles);

#endif /* _DEBUG_H */
