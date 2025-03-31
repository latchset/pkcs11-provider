/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
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

#define P11PROV_DEFAULT_PROPERTIES "provider=pkcs11"
#define P11PROV_FIPS_PROPERTIES "provider=pkcs11,fips=yes"

#define P11PROV_NAME_RSA "RSA"
#define P11PROV_NAMES_RSA "RSA:rsaEncryption:1.2.840.113549.1.1.1"
#define P11PROV_DESCS_RSA "PKCS11 RSA Implementation"
#define P11PROV_NAME_RSAPSS "RSA-PSS"
#define P11PROV_NAMES_RSAPSS "RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10"
#define P11PROV_DESCS_RSAPSS "PKCS11 RSA PSS Implementation"
#define P11PROV_NAME_EC "EC"
#define P11PROV_NAMES_EC "EC:id-ecPublicKey:1.2.840.10045.2.1"
#define P11PROV_DESCS_EC "PKCS11 EC Implementation"
#define P11PROV_NAME_ECDSA "ECDSA"
#define P11PROV_NAMES_ECDSA P11PROV_NAME_ECDSA
#define P11PROV_DESCS_ECDSA "PKCS11 ECDSA Implementation"
#define P11PROV_NAME_ECDH "ECDH"
#define P11PROV_NAMES_ECDH P11PROV_NAME_ECDH
#define P11PROV_DESCS_ECDH "PKCS11 ECDH Implementation"
#define P11PROV_NAME_HKDF "HKDF"
#define P11PROV_NAMES_HKDF P11PROV_NAME_HKDF
#define P11PROV_DESCS_HKDF "PKCS11 HKDF Implementation"
#define P11PROV_NAMES_ED25519 "ED25519:1.3.101.112"
#define P11PROV_NAME_ED25519 "ED25519"
#define P11PROV_DESCS_ED25519 "PKCS11 ED25519 Implementation"
#define P11PROV_NAMES_ED448 "ED448:1.3.101.113"
#define P11PROV_NAME_ED448 "ED448"
#define P11PROV_DESCS_ED448 "PKCS11 ED448 Implementation"
#define P11PROV_NAMES_RAND "PKCS11-RAND"
#define P11PROV_DESCS_RAND "PKCS11 Random Generator"
#define P11PROV_NAME_CERTIFICATE "CERTIFICATE"
#define P11PROV_NAME_TLS13_KDF "TLS13-KDF"
#define P11PROV_NAMES_TLS13_KDF P11PROV_NAME_TLS13_KDF
#define P11PROV_DESCS_TLS13_KDF "PKCS11 TLS 1.3 HKDF Implementation"
#define P11PROV_NAMES_DER "DER"
#define P11PROV_DESCS_DER "DER decoder implementation in PKCS11 provider"
#define P11PROV_NAMES_URI "pkcs11"
#define P11PROV_DESCS_URI "PKCS11 URI Store"

#define P11PROV_PARAM_URI "pkcs11_uri"
#define P11PROV_PARAM_EPHEMERAL "pkcs11_ephemeral"
#define P11PROV_PARAM_KEY_USAGE "pkcs11_key_usage"
#define P11PROV_PARAM_SLOT_ID "pkcs11_slot_id"

#if SKEY_SUPPORT == 1

#define P11PROV_NAME_GENERIC_SECRET "GENERIC-SECRET"

#define P11PROV_NAME_AES "AES"
#define P11PROV_NAMES_AES "AES:2.16.840.1.101.3.4.1"
#define P11PROV_DESCS_AES "PKCS11 AES Implementation"
#define P11PROV_NAMES_AES_256_ECB "AES-256-ECB:2.16.840.1.101.3.4.1.41"
#define P11PROV_DESCS_AES_256_ECB "AES-256 ECB PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_ECB "AES-192-ECB:2.16.840.1.101.3.4.1.21"
#define P11PROV_DESCS_AES_192_ECB "AES-192 ECB PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_ECB "AES-128-ECB:2.16.840.1.101.3.4.1.1"
#define P11PROV_DESCS_AES_128_ECB "AES-128 ECB PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_CBC \
    "AES-256-CBC:AES256:aes256:2.16.840.1.101.3.4.1.42"
#define P11PROV_DESCS_AES_256_CBC "AES-256 CBC PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_CBC \
    "AES-192-CBC:AES192:aes192:2.16.840.1.101.3.4.1.22"
#define P11PROV_DESCS_AES_192_CBC "AES-192 CBC PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_CBC \
    "AES-128-CBC:AES128:aes128:2.16.840.1.101.3.4.1.2"
#define P11PROV_DESCS_AES_128_CBC "AES-128 CBC PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_OFB "AES-256-OFB:2.16.840.1.101.3.4.1.43"
#define P11PROV_DESCS_AES_256_OFB "AES-256 OFB PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_OFB "AES-192-OFB:2.16.840.1.101.3.4.1.23"
#define P11PROV_DESCS_AES_192_OFB "AES-192 OFB PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_OFB "AES-128-OFB:2.16.840.1.101.3.4.1.3"
#define P11PROV_DESCS_AES_128_OFB "AES-128 OFB PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_CFB "AES-256-CFB:2.16.840.1.101.3.4.1.44"
#define P11PROV_DESCS_AES_256_CFB \
    "AES-256 CFB128 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_CFB "AES-192-CFB:2.16.840.1.101.3.4.1.24"
#define P11PROV_DESCS_AES_192_CFB \
    "AES-192 CFB128 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_CFB "AES-128-CFB:2.16.840.1.101.3.4.1.4"
#define P11PROV_DESCS_AES_128_CFB \
    "AES-128 CFB128 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_CFB1 "AES-256-CFB1"
#define P11PROV_DESCS_AES_256_CFB1 "AES-256 CFB1 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_CFB1 "AES-192-CFB1"
#define P11PROV_DESCS_AES_192_CFB1 "AES-192 CFB1 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_CFB1 "AES-128-CFB1"
#define P11PROV_DESCS_AES_128_CFB1 "AES-128 CFB1 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_CFB8 "AES-256-CFB8"
#define P11PROV_DESCS_AES_256_CFB8 "AES-256 CFB8 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_CFB8 "AES-192-CFB8"
#define P11PROV_DESCS_AES_192_CFB8 "AES-192 CFB8 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_CFB8 "AES-128-CFB8"
#define P11PROV_DESCS_AES_128_CFB8 "AES-128 CFB8 PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_CTR "AES-256-CTR"
#define P11PROV_DESCS_AES_256_CTR "AES-256 CTR PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_CTR "AES-192-CTR"
#define P11PROV_DESCS_AES_192_CTR "AES-192 CTR PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_CTR "AES-128-CTR"
#define P11PROV_DESCS_AES_128_CTR "AES-128 CTR PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_256_CTS "AES-256-CBC-CTS"
#define P11PROV_DESCS_AES_256_CTS "AES-256 CTS PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_192_CTS "AES-192-CBC-CTS"
#define P11PROV_DESCS_AES_192_CTS "AES-192 CTS PKCS11 Provider Implementation"
#define P11PROV_NAMES_AES_128_CTS "AES-128-CBC-CTS"
#define P11PROV_DESCS_AES_128_CTS "AES-128 CTS PKCS11 Provider Implementation"

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

#if __SANITIZE_ADDRESS__
#define P11PROV_ADDRESS_SANITIZER 1
#endif
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define P11PROV_ADDRESS_SANITIZER 1
#endif
#endif

/* Provider ctx */
P11PROV_INTERFACE *p11prov_ctx_get_interface(P11PROV_CTX *ctx);
CK_UTF8CHAR_PTR p11prov_ctx_pin(P11PROV_CTX *ctx);
OSSL_LIB_CTX *p11prov_ctx_get_libctx(P11PROV_CTX *ctx);
CK_RV p11prov_ctx_status(P11PROV_CTX *ctx);
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
#include "objects.h"
#include "keymgmt.h"
#include "store.h"
#include "signature.h"
#include "asymmetric_cipher.h"
#include "exchange.h"
#include "kdf.h"
#include "encoder.h"
#include "digests.h"
#include "util.h"
#include "session.h"
#include "slot.h"
#include "random.h"
#include "pk11_uri.h"

#if SKEY_SUPPORT == 1
#include "cipher.h"
#include "skeymgmt.h"
#endif

/* TLS */
int tls_group_capabilities(OSSL_CALLBACK *cb, void *arg);

#endif /* _PROVIDER_H */
