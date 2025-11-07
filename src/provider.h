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
#define P11PROV_NAMES_RSA_SHA1 \
    "RSA-SHA1:RSA-SHA-1:sha1WithRSAEncryption:1.2.840.113549.1.1.5"
#define P11PROV_DESCS_RSA_SHA1 "PKCS11 RSA-SHA1 Implementation"
#define P11PROV_NAMES_RSA_SHA256 \
    "RSA-SHA2-256:RSA-SHA256:sha256WithRSAEncryption:1.2.840.113549.1.1.11"
#define P11PROV_DESCS_RSA_SHA256 "PKCS11 RSA-SHA256 Implementation"
#define P11PROV_NAMES_RSA_SHA384 \
    "RSA-SHA2-384:RSA-SHA384:sha384WithRSAEncryption:1.2.840.113549.1.1.12"
#define P11PROV_DESCS_RSA_SHA384 "PKCS11 RSA-SHA384 Implementation"
#define P11PROV_NAMES_RSA_SHA512 \
    "RSA-SHA2-512:RSA-SHA512:sha512WithRSAEncryption:1.2.840.113549.1.1.13"
#define P11PROV_DESCS_RSA_SHA512 "PKCS11 RSA-SHA512 Implementation"
#define P11PROV_NAMES_RSA_SHA224 \
    "RSA-SHA2-224:RSA-SHA224:sha224WithRSAEncryption:1.2.840.113549.1.1.14"
#define P11PROV_DESCS_RSA_SHA224 "PKCS11 RSA-SHA224 Implementation"
#define P11PROV_NAMES_RSA_SHA3_224 \
    "RSA-SHA3-224:id-rsassa-pkcs1-v1_5-with-sha3-224:2.16.840.1.101.3.4.3.13"
#define P11PROV_DESCS_RSA_SHA3_224 "PKCS11 RSA-SHA3_224 Implementation"
#define P11PROV_NAMES_RSA_SHA3_256 \
    "RSA-SHA3-256:id-rsassa-pkcs1-v1_5-with-sha3-256:2.16.840.1.101.3.4.3.14"
#define P11PROV_DESCS_RSA_SHA3_256 "PKCS11 RSA-SHA3_256 Implementation"
#define P11PROV_NAMES_RSA_SHA3_384 \
    "RSA-SHA3-384:id-rsassa-pkcs1-v1_5-with-sha3-384:2.16.840.1.101.3.4.3.15"
#define P11PROV_DESCS_RSA_SHA3_384 "PKCS11 RSA-SHA3_384 Implementation"
#define P11PROV_NAMES_RSA_SHA3_512 \
    "RSA-SHA3-512:id-rsassa-pkcs1-v1_5-with-sha3-512:2.16.840.1.101.3.4.3.16"
#define P11PROV_DESCS_RSA_SHA3_512 "PKCS11 RSA-SHA3_512 Implementation"
#define P11PROV_NAME_EC "EC"
#define P11PROV_NAMES_EC "EC:id-ecPublicKey:1.2.840.10045.2.1"
#define P11PROV_DESCS_EC "PKCS11 EC Implementation"
#define P11PROV_NAME_ECDSA "ECDSA"
#define P11PROV_NAMES_ECDSA P11PROV_NAME_ECDSA
#define P11PROV_DESCS_ECDSA "PKCS11 ECDSA Implementation"
#define P11PROV_NAMES_ECDSA_SHA1 \
    "ECDSA-SHA1:ECDSA-SHA-1:ecdsa-with-SHA1:1.2.840.10045.4.1"
#define P11PROV_DESCS_ECDSA_SHA1 "PKCS11 ECDSA-SHA1 Implementation"
#define P11PROV_NAMES_ECDSA_SHA224 \
    "ECDSA-SHA2-224:ECDSA-SHA224:ecdsa-with-SHA224:1.2.840.10045.4.3.1"
#define P11PROV_DESCS_ECDSA_SHA224 "PKCS11 ECDSA-SHA224 Implementation"
#define P11PROV_NAMES_ECDSA_SHA256 \
    "ECDSA-SHA2-256:ECDSA-SHA256:ecdsa-with-SHA256:1.2.840.10045.4.3.2"
#define P11PROV_DESCS_ECDSA_SHA256 "PKCS11 ECDSA-SHA256 Implementation"
#define P11PROV_NAMES_ECDSA_SHA384 \
    "ECDSA-SHA2-384:ECDSA-SHA384:ecdsa-with-SHA384:1.2.840.10045.4.3.3"
#define P11PROV_DESCS_ECDSA_SHA384 "PKCS11 ECDSA-SHA384 Implementation"
#define P11PROV_NAMES_ECDSA_SHA512 \
    "ECDSA-SHA2-512:ECDSA-SHA512:ecdsa-with-SHA512:1.2.840.10045.4.3.4"
#define P11PROV_DESCS_ECDSA_SHA512 "PKCS11 ECDSA-SHA512 Implementation"
#define P11PROV_NAMES_ECDSA_SHA3_224 \
    "ECDSA-SHA3-224:ecdsa_with_SHA3-224:id-ecdsa-with-sha3-224:2.16.840.1." \
    "101.3.4.3.9"
#define P11PROV_DESCS_ECDSA_SHA3_224 "PKCS11 ECDSA-SHA3_224 Implementation"
#define P11PROV_NAMES_ECDSA_SHA3_256 \
    "ECDSA-SHA3-256:ecdsa_with_SHA3-256:id-ecdsa-with-sha3-256:2.16.840.1." \
    "101.3.4.3.10"
#define P11PROV_DESCS_ECDSA_SHA3_256 "PKCS11 ECDSA-SHA3_256 Implementation"
#define P11PROV_NAMES_ECDSA_SHA3_384 \
    "ECDSA-SHA3-384:ecdsa_with_SHA3-384:id-ecdsa-with-sha3-384:2.16.840.1." \
    "101.3.4.3.11"
#define P11PROV_DESCS_ECDSA_SHA3_384 "PKCS11 ECDSA-SHA3_384 Implementation"
#define P11PROV_NAMES_ECDSA_SHA3_512 \
    "ECDSA-SHA3-512:ecdsa_with_SHA3-512:id-ecdsa-with-sha3-512:2.16.840.1." \
    "101.3.4.3.12"
#define P11PROV_DESCS_ECDSA_SHA3_512 "PKCS11 ECDSA-SHA3_512 Implementation"
#define P11PROV_NAME_ECDH "ECDH"
#define P11PROV_NAMES_ECDH P11PROV_NAME_ECDH
#define P11PROV_DESCS_ECDH "PKCS11 ECDH Implementation"
#define P11PROV_NAME_HKDF "HKDF"
#define P11PROV_NAMES_HKDF P11PROV_NAME_HKDF
#define P11PROV_DESCS_HKDF "PKCS11 HKDF Implementation"
#define P11PROV_NAMES_ED25519 "ED25519:1.3.101.112"
#define P11PROV_NAME_ED25519 "ED25519"
#define P11PROV_DESCS_ED25519 "PKCS11 ED25519 Implementation"
#define P11PROV_NAMES_ED25519ph "ED25519ph"
#define P11PROV_DESCS_ED25519ph "PKCS11 ED25519ph implementation"
#define P11PROV_NAMES_ED25519ctx "ED25519ctx"
#define P11PROV_DESCS_ED25519ctx "PKCS11 ED25519ctx implementation"
#define P11PROV_NAMES_ED448 "ED448:1.3.101.113"
#define P11PROV_NAME_ED448 "ED448"
#define P11PROV_DESCS_ED448 "PKCS11 ED448 Implementation"
#define P11PROV_NAMES_ED448ph "ED448ph"
#define P11PROV_DESCS_ED448ph "PKCS11 ED448ph implementation"
#define P11PROV_NAMES_X25519 "X25519:1.3.101.110"
#define P11PROV_NAME_X25519 "X25519"
#define P11PROV_DESCS_X25519 "PKCS11 X25519 Implementation"
#define P11PROV_NAMES_X448 "X448:1.3.101.111"
#define P11PROV_NAME_X448 "X448"
#define P11PROV_DESCS_X448 "PKCS11 X448 Implementation"
#define P11PROV_NAMES_ML_DSA_44 \
    "ML-DSA-44:MLDSA44:2.16.840.1.101.3.4.3.17:id-ml-dsa-44"
#define P11PROV_DESCS_ML_DSA_44 "PKCS11 ML-DSA-44 implementation"
#define P11PROV_NAMES_ML_DSA_65 \
    "ML-DSA-65:MLDSA65:2.16.840.1.101.3.4.3.18:id-ml-dsa-65"
#define P11PROV_DESCS_ML_DSA_65 "PKCS11 ML-DSA-65 implementation"
#define P11PROV_NAMES_ML_DSA_87 \
    "ML-DSA-87:MLDSA87:2.16.840.1.101.3.4.3.19:id-ml-dsa-87"
#define P11PROV_DESCS_ML_DSA_87 "PKCS11 ML-DSA-87 implementation"
#define P11PROV_NAMES_ML_KEM_512 \
    "ML-KEM-512:MLKEM512:id-alg-ml-kem-512:2.16.840.1.101.3.4.4.1"
#define P11PROV_DESCS_ML_KEM_512 "PKCS11 ML-KEM-512 implementation"
#define P11PROV_NAMES_ML_KEM_768 \
    "ML-KEM-768:MLKEM768:id-alg-ml-kem-768:2.16.840.1.101.3.4.4.2"
#define P11PROV_DESCS_ML_KEM_768 "PKCS11 ML-KEM-768 implementation"
#define P11PROV_NAMES_ML_KEM_1024 \
    "ML-KEM-1024:MLKEM1024:id-alg-ml-kem-1024:2.16.840.1.101.3.4.4.3"
#define P11PROV_DESCS_ML_KEM_1024 "PKCS11 ML-KEM-1024 implementation"
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
#define P11PROV_NAME_GENERIC_SECRET "GENERIC-SECRET"
#define P11PROV_NAMES_GENERIC_SECRET P11PROV_NAME_GENERIC_SECRET
#define P11PROV_DESCS_GENERIC_SECRET "PKCS11 Generic Secret Implementation"

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
#include "obj/object.h"
#include "kmgmt/keymgmt.h"
#include "store.h"
#include "sig/signature.h"
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
#include "kem.h"

#if SKEY_SUPPORT == 1
#include "cipher.h"
#include "kmgmt/skey.h"
#endif

/* TLS */
int tls_group_capabilities(OSSL_CALLBACK *cb, void *arg);
int tls_sigalg_capabilities(OSSL_CALLBACK *cb, void *arg);

#endif /* _PROVIDER_H */
