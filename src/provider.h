/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _PROVIDER_H
#define _PROVIDER_H

#define _XOPEN_SOURCE 500
#include "config.h"

#include <stdbool.h>

#include "pkcs11.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/types.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>

#define UNUSED __attribute__((unused))
#define RET_OSSL_OK 1
#define RET_OSSL_ERR 0
#define RET_OSSL_BAD -1

#define P11PROV_PKCS11_MODULE_PATH "pkcs11-module-path"
#define P11PROV_PKCS11_MODULE_INIT_ARGS "pkcs11-module-init-args"
#define P11PROV_PKCS11_MODULE_TOKEN_PIN "pkcs11-module-token-pin"
#define P11PROV_PKCS11_MODULE_ALLOW_EXPORT "pkcs11-module-allow-export"

#define P11PROV_DEFAULT_PROPERTIES "provider=pkcs11"
#define P11PROV_NAMES_RSA "RSA:rsaEncryption:1.2.840.113549.1.1.1"
#define P11PROV_DESCS_RSA "PKCS11 RSA Implementation"
#define P11PROV_NAMES_RSAPSS "RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10"
#define P11PROV_DESCS_RSAPSS "PKCS11 RSA PSS Implementation"
#define P11PROV_NAMES_EC "EC:id-ecPublicKey:1.2.840.10045.2.1"
#define P11PROV_DESCS_EC "PKCS11 EC Implementation"
#define P11PROV_NAMES_ECDSA "ECDSA"
#define P11PROV_DESCS_ECDSA "PKCS11 ECDSA Implementation"
#define P11PROV_NAMES_ECDH "ECDH"
#define P11PROV_DESCS_ECDH "PKCS11 ECDH Implementation"
#define P11PROV_NAMES_HKDF "HKDF"
#define P11PROV_DESCS_HKDF "PKCS11 HKDF Implementation"
#define P11PROV_DESCS_URI "PKCS11 URI Store"

#define P11PROV_PARAM_KEY_LABEL "pkcs11_key_label"
#define P11PROV_PARAM_KEY_ID "pkcs11_key_id"

typedef struct p11prov_ctx P11PROV_CTX;
typedef struct p11prov_key P11PROV_KEY;
typedef struct p11prov_uri P11PROV_URI;
typedef struct p11prov_obj P11PROV_OBJ;
typedef struct p11prov_session P11PROV_SESSION;
typedef struct p11prov_session_pool P11PROV_SESSION_POOL;

struct p11prov_slot {
    CK_SLOT_ID id;
    CK_SLOT_INFO slot;
    CK_TOKEN_INFO token;

    P11PROV_SESSION_POOL *pool;

    CK_MECHANISM_TYPE *mechs;
    CK_ULONG mechs_num;

    CK_ULONG profiles[5];
};

/* Provider ctx */
CK_UTF8CHAR_PTR p11prov_ctx_pin(P11PROV_CTX *ctx);
OSSL_LIB_CTX *p11prov_ctx_get_libctx(P11PROV_CTX *ctx);
CK_RV p11prov_ctx_status(P11PROV_CTX *ctx, CK_FUNCTION_LIST **fns);
int p11prov_ctx_get_slots(P11PROV_CTX *ctx, struct p11prov_slot **slots);
CK_RV p11prov_ctx_get_quirk(P11PROV_CTX *ctx, CK_SLOT_ID id, const char *name,
                            void **data, CK_ULONG *size);
CK_RV p11prov_ctx_set_quirk(P11PROV_CTX *ctx, CK_SLOT_ID id, const char *name,
                            void *data, CK_ULONG size);

#define ALLOW_EXPORT_PUBLIC 0
#define DISALLOW_EXPORT_PUBLIC 1
int p11prov_ctx_allow_export(P11PROV_CTX *ctx);

/* Errors */
void p11prov_raise(P11PROV_CTX *ctx, const char *file, int line,
                   const char *func, int errnum, const char *fmt, ...);

#define P11PROV_raise(ctx, errnum, ...) \
    do { \
        p11prov_raise((ctx), OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC, \
                      (errnum), __VA_ARGS__); \
        if (errnum) P11PROV_debug("Error: %lu", (unsigned long)(errnum)); \
        P11PROV_debug(__VA_ARGS__); \
    } while (0)

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
void p11prov_debug_slot(P11PROV_CTX *ctx, struct p11prov_slot *slot);

/* Keys */
P11PROV_KEY *p11prov_key_ref(P11PROV_KEY *key);
void p11prov_key_free(P11PROV_KEY *key);
CK_ATTRIBUTE *p11prov_key_attr(P11PROV_KEY *key, CK_ATTRIBUTE_TYPE type);
CK_OBJECT_CLASS p11prov_key_class(P11PROV_KEY *key);
CK_KEY_TYPE p11prov_key_type(P11PROV_KEY *key);
CK_SLOT_ID p11prov_key_slotid(P11PROV_KEY *key);
CK_OBJECT_HANDLE p11prov_key_handle(P11PROV_KEY *key);
CK_ULONG p11prov_key_size(P11PROV_KEY *key);

typedef CK_RV (*store_key_callback)(void *, P11PROV_KEY *);
P11PROV_KEY *p11prov_object_handle_to_key(P11PROV_CTX *ctx, CK_SLOT_ID slotid,
                                          P11PROV_SESSION *session,
                                          CK_OBJECT_HANDLE object);
CK_RV find_keys(P11PROV_CTX *provctx, P11PROV_SESSION *session,
                CK_SLOT_ID slotid, P11PROV_URI *uri, store_key_callback cb,
                void *cb_ctx);
P11PROV_KEY *find_associated_key(P11PROV_CTX *provctx, P11PROV_KEY *key,
                                 CK_OBJECT_CLASS class);
P11PROV_KEY *p11prov_create_secret_key(P11PROV_CTX *provctx,
                                       P11PROV_SESSION *session,
                                       bool session_key, unsigned char *secret,
                                       size_t secretlen);
CK_RV p11prov_derive_key(P11PROV_CTX *ctx, CK_SLOT_ID slotid,
                         CK_MECHANISM *mechanism, CK_OBJECT_HANDLE handle,
                         CK_ATTRIBUTE *template, CK_ULONG nattrs,
                         P11PROV_SESSION **session, CK_OBJECT_HANDLE *key);
CK_RV p11prov_key_set_attributes(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                                 P11PROV_KEY *key, CK_ATTRIBUTE *template,
                                 CK_ULONG tsize);

/* Object Store */
CK_RV p11prov_object_new(P11PROV_CTX *ctx, P11PROV_KEY *key,
                         P11PROV_OBJ **object);
void p11prov_object_free(P11PROV_OBJ *obj);
CK_OBJECT_CLASS p11prov_object_get_class(P11PROV_OBJ *obj);
P11PROV_OBJ *p11prov_obj_from_reference(const void *reference,
                                        size_t reference_sz);
int p11prov_object_export_public_rsa_key(P11PROV_OBJ *obj, OSSL_CALLBACK *cb_fn,
                                         void *cb_arg);
int p11prov_object_export_public_ec_key(P11PROV_OBJ *obj, OSSL_CALLBACK *cb_fn,
                                        void *cb_arg);
P11PROV_KEY *p11prov_object_get_key(P11PROV_OBJ *obj);

/* dispatching */
#define DECL_DISPATCH_FUNC(type, prefix, name) \
    static OSSL_FUNC_##type##_##name##_fn prefix##_##name

/* keymgmt */
#define DISPATCH_KEYMGMT_FN(type, name) \
    DECL_DISPATCH_FUNC(keymgmt, p11prov_##type, name)
#define DISPATCH_KEYMGMT_ELEM(type, NAME, name) \
    { \
        OSSL_FUNC_KEYMGMT_##NAME, (void (*)(void))p11prov_##type##_##name \
    }
extern const OSSL_DISPATCH p11prov_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_rsapss_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_ec_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_hkdf_keymgmt_functions[];

#define DISPATCH_STORE_FN(name) DECL_DISPATCH_FUNC(store, p11prov_store, name)
#define DISPATCH_STORE_ELEM(NAME, name) \
    { \
        OSSL_FUNC_STORE_##NAME, (void (*)(void))p11prov_store_##name \
    }
extern const OSSL_DISPATCH p11prov_store_functions[];

/* common sig functions */
#define DISPATCH_SIG_FN(name) DECL_DISPATCH_FUNC(signature, p11prov_sig, name)
#define DISPATCH_SIG_ELEM(prefix, NAME, name) \
    { \
        OSSL_FUNC_SIGNATURE_##NAME, (void (*)(void))p11prov_##prefix##_##name \
    }

/* rsa sig functions */
#define DISPATCH_RSASIG_FN(name) \
    DECL_DISPATCH_FUNC(signature, p11prov_rsasig, name)
extern const OSSL_DISPATCH p11prov_rsa_signature_functions[];

/* ecdsa sig functions */
#define DISPATCH_ECDSA_FN(name) \
    DECL_DISPATCH_FUNC(signature, p11prov_ecdsa, name)
extern const OSSL_DISPATCH p11prov_ecdsa_signature_functions[];

/* rsa encrypt/decrypt */
#define DISPATCH_RSAENC_FN(name) \
    DECL_DISPATCH_FUNC(asym_cipher, p11prov_rsaenc, name)
#define DISPATCH_RSAENC_ELEM(NAME, name) \
    { \
        OSSL_FUNC_ASYM_CIPHER_##NAME, (void (*)(void))p11prov_rsaenc_##name \
    }
extern const OSSL_DISPATCH p11prov_rsa_asym_cipher_functions[];

/* ecdh derivation */
#define DISPATCH_ECDH_FN(name) DECL_DISPATCH_FUNC(keyexch, p11prov_ecdh, name)
#define DISPATCH_ECDH_ELEM(prefix, NAME, name) \
    { \
        OSSL_FUNC_KEYEXCH_##NAME, (void (*)(void))p11prov_##prefix##_##name \
    }
extern const OSSL_DISPATCH p11prov_ecdh_exchange_functions[];

/* HKDF exchange and kdf fns */
#define DISPATCH_EXCHHKDF_FN(name) \
    DECL_DISPATCH_FUNC(keyexch, p11prov_exch_hkdf, name)
#define DISPATCH_EXCHHKDF_ELEM(prefix, NAME, name) \
    { \
        OSSL_FUNC_KEYEXCH_##NAME, (void (*)(void))p11prov_##prefix##_##name \
    }
extern const OSSL_DISPATCH p11prov_hkdf_exchange_functions[];
#define DISPATCH_HKDF_FN(name) DECL_DISPATCH_FUNC(kdf, p11prov_hkdf, name)
#define DISPATCH_HKDF_ELEM(prefix, NAME, name) \
    { \
        OSSL_FUNC_KDF_##NAME, (void (*)(void))p11prov_##prefix##_##name \
    }
extern const void *p11prov_hkdf_static_ctx;
extern const OSSL_DISPATCH p11prov_hkdf_kdf_functions[];

/* Encoders */
#define DISPATCH_TEXT_ENCODER_FN(type, name) \
    static OSSL_FUNC_encoder_##name##_fn p11prov_##type##_encoder_##name##_text
#define DISPATCH_TEXT_ENCODER_ELEM(NAME, type, name) \
    { \
        OSSL_FUNC_ENCODER_##NAME, \
            (void (*)(void))p11prov_##type##_encoder_##name \
    }
#define DISPATCH_BASE_ENCODER_FN(name) \
    DECL_DISPATCH_FUNC(encoder, p11prov_encoder, name)
#define DISPATCH_BASE_ENCODER_ELEM(NAME, name) \
    { \
        OSSL_FUNC_ENCODER_##NAME, (void (*)(void))p11prov_encoder_##name \
    }
#define DISPATCH_ENCODER_FN(type, structure, format, name) \
    DECL_DISPATCH_FUNC(encoder, \
                       p11prov_##type##_encoder_##structure##_##format, name)
#define DISPATCH_ENCODER_ELEM(NAME, type, structure, format, name) \
    { \
        OSSL_FUNC_ENCODER_##NAME, \
            (void (*)( \
                void))p11prov_##type##_encoder_##structure##_##format##_##name \
    }
extern const OSSL_DISPATCH p11prov_rsa_encoder_text_functions[];
extern const OSSL_DISPATCH p11prov_rsa_encoder_pkcs1_der_functions[];
extern const OSSL_DISPATCH p11prov_rsa_encoder_pkcs1_pem_functions[];
extern const OSSL_DISPATCH p11prov_rsa_encoder_spki_der_functions[];
extern const OSSL_DISPATCH p11prov_ec_encoder_pkcs1_der_functions[];
extern const OSSL_DISPATCH p11prov_ec_encoder_pkcs1_pem_functions[];
extern const OSSL_DISPATCH p11prov_ec_encoder_spki_der_functions[];

/* Digests */
#define DISPATCH_DIGEST_COMMON_FN(name) \
    DECL_DISPATCH_FUNC(digest, p11prov_digest, name)
#define DISPATCH_DIGEST_COMMON(NAME, name) \
    { \
        OSSL_FUNC_DIGEST_##NAME, (void (*)(void))p11prov_digest_##name \
    }
#define DISPATCH_DIGEST_FN(type, name) \
    DECL_DISPATCH_FUNC(digest, p11prov_##type, name)
#define DISPATCH_DIGEST_ELEM(digest, NAME, name) \
    { \
        OSSL_FUNC_DIGEST_##NAME, (void (*)(void))p11prov_##digest##_##name \
    }
extern const OSSL_DISPATCH p11prov_sha1_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha224_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha256_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha384_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha512_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha512_224_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha512_256_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha3_224_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha3_256_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha3_384_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha3_512_digest_functions[];

#define P11PROV_NAMES_SHA1 "SHA1:SHA-1:SSL3-SHA1:1.3.14.3.2.26"
#define P11PROV_DESCS_SHA1 "PKCS11 SHA1 Implementation"
#define P11PROV_NAMES_SHA2_224 "SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4"
#define P11PROV_DESCS_SHA2_224 "PKCS11 SHA2-224 Implementation"
#define P11PROV_NAMES_SHA2_256 "SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1"
#define P11PROV_DESCS_SHA2_256 "PKCS11 SHA2-256 Implementation"
#define P11PROV_NAMES_SHA2_384 "SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2"
#define P11PROV_DESCS_SHA2_384 "PKCS11 SHA2-384 Implementation"
#define P11PROV_NAMES_SHA2_512 "SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3"
#define P11PROV_DESCS_SHA2_512 "PKCS11 SHA2-512 Implementation"
#define P11PROV_NAMES_SHA2_512_224 \
    "SHA2-512/224:SHA-512/224:SHA512-224:2.16.840.1.101.3.4.2.5"
#define P11PROV_DESCS_SHA2_512_224 "PKCS11 SHA2-512/224 Implementation"
#define P11PROV_NAMES_SHA2_512_256 \
    "SHA2-512/256:SHA-512/256:SHA512-256:2.16.840.1.101.3.4.2.6"
#define P11PROV_DESCS_SHA2_512_256 "PKCS11 SHA2-512/224 Implementation"
#define P11PROV_NAMES_SHA3_224 "SHA3-224:2.16.840.1.101.3.4.2.7"
#define P11PROV_DESCS_SHA3_224 "PKCS11 SHA3-224 Implementation"
#define P11PROV_NAMES_SHA3_256 "SHA3-256:2.16.840.1.101.3.4.2.8"
#define P11PROV_DESCS_SHA3_256 "PKCS11 SHA3-256 Implementation"
#define P11PROV_NAMES_SHA3_384 "SHA3-384:2.16.840.1.101.3.4.2.9"
#define P11PROV_DESCS_SHA3_384 "PKCS11 SHA3-384 Implementation"
#define P11PROV_NAMES_SHA3_512 "SHA3-512:2.16.840.1.101.3.4.2.10"
#define P11PROV_DESCS_SHA3_512 "PKCS11 SHA3-512 Implementation"

struct p11prov_digest {
    CK_MECHANISM_TYPE digest;
    size_t block_size;
    size_t digest_size;
    const char *names[5]; /* must give a size for initialization ... */
};

CK_RV p11prov_digest_get_by_mechanism(CK_MECHANISM_TYPE mech,
                                      const struct p11prov_digest **digest);
CK_RV p11prov_digest_get_by_name(const char *name,
                                 const struct p11prov_digest **digest);
CK_RV p11prov_digest_get_by_param(const OSSL_PARAM *p,
                                  const struct p11prov_digest **digest);

/* Utilities to fetch objects from tokens */

struct fetch_attrs {
    CK_ATTRIBUTE_TYPE type;
    CK_BYTE **value;
    CK_ULONG *value_len;
    bool allocate;
    bool required;
};
#define FA_ASSIGN_ALL(x, _a, _b, _c, _d, _e) \
    do { \
        x.type = _a; \
        x.value = (unsigned char **)_b; \
        x.value_len = _c; \
        x.allocate = _d; \
        x.required = _e; \
    } while (0)

#define FA_RETURN_VAL(x, _a, _b) \
    do { \
        *x.value = _a; \
        *x.value_len = _b; \
    } while (0)

#define FA_RETURN_LEN(x, _a) *x.value_len = _a

#define CKATTR_ASSIGN_ALL(x, _a, _b, _c) \
    do { \
        x.type = (_a); \
        x.pValue = (void *)(_b); \
        x.ulValueLen = (_c); \
    } while (0)

CK_RV p11prov_fetch_attributes(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                               CK_OBJECT_HANDLE object,
                               struct fetch_attrs *attrs,
                               unsigned long attrnums);

#define MAX_PIN_LENGTH 32
P11PROV_URI *p11prov_parse_uri(const char *uri);
void p11prov_uri_free(P11PROV_URI *parsed_uri);
CK_OBJECT_CLASS p11prov_uri_get_class(P11PROV_URI *uri);
CK_ATTRIBUTE p11prov_uri_get_id(P11PROV_URI *uri);
CK_ATTRIBUTE p11prov_uri_get_label(P11PROV_URI *uri);
char *p11prov_uri_get_object(P11PROV_URI *uri);
char *p11prov_uri_get_pin(P11PROV_URI *uri);
CK_RV p11prov_uri_match_token(P11PROV_URI *uri, CK_TOKEN_INFO *token);
int p11prov_get_pin(const char *in, char **out);
bool cyclewait_with_timeout(uint64_t max_wait, uint64_t interval,
                            uint64_t *start_time);
#define GET_ATTR 0
#define SET_ATTR 1
CK_RV p11prov_token_sup_attr(P11PROV_CTX *ctx, CK_SLOT_ID id, int action,
                             CK_ATTRIBUTE_TYPE attr, CK_BBOOL *data);

/* Sessions */
CK_RV p11prov_session_pool_init(P11PROV_CTX *ctx, CK_TOKEN_INFO *token,
                                P11PROV_SESSION_POOL **_pool);
CK_RV p11prov_session_pool_free(P11PROV_SESSION_POOL *pool);
void p11prov_session_free(P11PROV_SESSION *session);
CK_SESSION_HANDLE p11prov_session_handle(P11PROV_SESSION *session);
CK_RV p11prov_get_session(P11PROV_CTX *provctx, CK_SLOT_ID *slotid,
                          CK_SLOT_ID *next_slotid, P11PROV_URI *uri,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
                          bool reqlogin, bool rw, P11PROV_SESSION **session);

/* TLS */
int tls_group_capabilities(OSSL_CALLBACK *cb, void *arg);

#endif /* _PROVIDER_H */
