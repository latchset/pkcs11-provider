/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   Copyright 2025 NXP
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _PROVIDER_H
#define _PROVIDER_H

/* We need at least -D_XOPEN_SOURCE=700 for strnlen. */
#define _XOPEN_SOURCE 700
#include "config.h"

#include <stdbool.h>
#include <sys/types.h>

#include "pkcs11.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/types.h>
#include <openssl/crypto.h>
#include <openssl/macros.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/ui.h>

#ifdef OSSL_OP_SKEYMGMT
#define SKEY_SUPPORT 1
#else
#define SKEY_SUPPORT 0
#endif

#define UNUSED __attribute__((unused))
#define RET_OSSL_OK 1
#define RET_OSSL_ERR 0
#define RET_OSSL_BAD -1

#define P11PROV_PARAM_URI "pkcs11_uri"
#define P11PROV_PARAM_EPHEMERAL "pkcs11_ephemeral"
#define P11PROV_PARAM_KEY_USAGE "pkcs11_key_usage"
#define P11PROV_PARAM_SLOT_ID "pkcs11_slot_id"

#if SKEY_SUPPORT == 1
#define P11PROV_NAME_AES "AES"
#define P11PROV_NAME_GENERIC_SECRET "GENERIC-SECRET"
#endif

typedef struct p11prov_ctx P11PROV_CTX;
typedef struct p11prov_module_ctx P11PROV_MODULE;
typedef struct p11prov_interface P11PROV_INTERFACE;
typedef struct p11prov_uri P11PROV_URI;
typedef struct p11prov_obj P11PROV_OBJ;
typedef struct p11prov_slot P11PROV_SLOT;
typedef struct p11prov_slots_ctx P11PROV_SLOTS_CTX;
typedef struct p11prov_session P11PROV_SESSION;
typedef struct p11prov_session_pool P11PROV_SESSION_POOL;
typedef struct p11prov_obj_pool P11PROV_OBJ_POOL;

#ifdef __SANITIZE_ADDRESS__
#define P11PROV_ADDRESS_SANITIZER 1
#endif
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define P11PROV_ADDRESS_SANITIZER 1
#endif
#endif

/* Provider ctx */
enum p11prov_ctx_status {
    P11PROV_UNINITIALIZED = 0,
    P11PROV_OPS_NEEDS_INIT,
    P11PROV_INITIALIZED,
    P11PROV_NEEDS_REINIT,
    P11PROV_NO_DEINIT,
    P11PROV_IN_ERROR,
};

P11PROV_INTERFACE *p11prov_ctx_get_interface(P11PROV_CTX *ctx);
P11PROV_MODULE *p11prov_ctx_get_module(P11PROV_CTX *ctx);
void p11prov_ctx_set_status(P11PROV_CTX *ctx, enum p11prov_ctx_status status);
CK_UTF8CHAR_PTR p11prov_ctx_pin(P11PROV_CTX *ctx);
OSSL_LIB_CTX *p11prov_ctx_get_libctx(P11PROV_CTX *ctx);
CK_RV p11prov_ctx_status(P11PROV_CTX *ctx);
CK_SLOT_ID p11prov_ctx_get_default_slotid(P11PROV_CTX *ctx);
P11PROV_SLOTS_CTX *p11prov_ctx_get_slots(P11PROV_CTX *ctx);
void p11prov_ctx_set_slots(P11PROV_CTX *ctx, P11PROV_SLOTS_CTX *slots);
CK_RV p11prov_ctx_get_quirk(P11PROV_CTX *ctx, CK_SLOT_ID id, const char *name,
                            void **data, CK_ULONG *size);
CK_RV p11prov_ctx_set_quirk(P11PROV_CTX *ctx, CK_SLOT_ID id, const char *name,
                            void *data, CK_ULONG size);
#define GET_ATTR 0
#define SET_ATTR 1
CK_RV p11prov_token_sup_attr(P11PROV_CTX *ctx, CK_SLOT_ID id, int action,
                             CK_ATTRIBUTE_TYPE attr, CK_BBOOL *data);

#define CKU_LUNA_CU 0x80000001UL
CK_USER_TYPE p11prov_ctx_user_type(P11PROV_CTX *ctx);

#define ALLOW_EXPORT_PUBLIC 0
#define DISALLOW_EXPORT_PUBLIC 1
int p11prov_ctx_allow_export(P11PROV_CTX *ctx);

#define PUBKEY_LOGIN_AUTO 0
#define PUBKEY_LOGIN_ALWAYS 1
#define PUBKEY_LOGIN_NEVER 2
int p11prov_ctx_login_behavior(P11PROV_CTX *ctx);
bool p11prov_ctx_cache_pins(P11PROV_CTX *ctx);

enum p11prov_cache_keys {
    P11PROV_CACHE_KEYS_NEVER = 0,
    P11PROV_CACHE_KEYS_IN_SESSION,
};
int p11prov_ctx_cache_keys(P11PROV_CTX *ctx);
int p11prov_ctx_cache_sessions(P11PROV_CTX *ctx);

bool p11prov_ctx_is_call_blocked(P11PROV_CTX *ctx, uint64_t mask);
bool p11prov_ctx_no_session_callbacks(P11PROV_CTX *ctx);

CK_INFO p11prov_ctx_get_ck_info(P11PROV_CTX *ctx);
CK_RV p11prov_ctx_add_algs(P11PROV_CTX *ctx, int operation_id,
                           OSSL_ALGORITHM *algs);

#include "debug.h"

/* Errors */
void p11prov_raise(P11PROV_CTX *ctx, const char *file, int line,
                   const char *func, int errnum, const char *fmt, ...);

#define P11PROV_raise(ctx, errnum, format, ...) \
    do { \
        p11prov_raise((ctx), OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC, \
                      (errnum), format, ##__VA_ARGS__); \
        P11PROV_debug("Error: 0x%08lX; " format, (unsigned long)(errnum), \
                      ##__VA_ARGS__); \
    } while (0)

int p11prov_set_error_mark(P11PROV_CTX *ctx);
int p11prov_clear_last_error_mark(P11PROV_CTX *ctx);
int p11prov_pop_error_to_mark(P11PROV_CTX *ctx);

/* dispatching */
#define DECL_DISPATCH_FUNC(type, prefix, name) \
    static OSSL_FUNC_##type##_##name##_fn prefix##_##name

#include "interface.h"
#include "obj/object.h"
#include "util.h"
#include "session.h"
#include "slot.h"
#include "pk11_uri.h"

#include "registration.h"
#include "digests.h"

/* TLS */
int tls_group_capabilities(OSSL_CALLBACK *cb, void *arg);
int tls_sigalg_capabilities(OSSL_CALLBACK *cb, void *arg);

#endif /* _PROVIDER_H */
