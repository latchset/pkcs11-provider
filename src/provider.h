/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _PROVIDER_H
#define _PROVIDER_H

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

#define UNUSED  __attribute__((unused))
#define RET_OSSL_OK 1
#define RET_OSSL_ERR 0
#define RET_OSSL_BAD -1

#define P11PROV_PKCS11_MODULE_PATH "pkcs11-module-path"
#define P11PROV_PKCS11_MODULE_INIT_ARGS "pkcs11-module-init-args"

#define P11PROV_DEFAULT_PROPERTIES "provider=pkcs11"
#define P11PROV_NAMES_RSA "PKCS11-RSA"
#define P11PROV_DESCS_RSA "PKCS11 RSA Implementation"
#define P11PROV_NAMES_ECDSA "PKCS11-ECDSA"
#define P11PROV_DESCS_ECDSA "PKCS11 ECDSA Implementation"
#define P11PROV_NAMES_ECDH "PKCS11-ECDH"
#define P11PROV_DESCS_ECDH "PKCS11 ECDH Implementation"
#define P11PROV_NAMES_HKDF "PKCS11-HKDF"
#define P11PROV_DESCS_HKDF "PKCS11 HKDF Implementation"
#define P11PROV_DESCS_URI "PKCS11 URI Store"

typedef struct p11prov_ctx P11PROV_CTX;

struct p11prov_slot {
    CK_SLOT_ID id;
    CK_SLOT_INFO slot;
    CK_TOKEN_INFO token;

    CK_ULONG profiles[5];
};

OSSL_LIB_CTX *p11prov_ctx_get_libctx(P11PROV_CTX *ctx);
CK_FUNCTION_LIST *p11prov_ctx_fns(P11PROV_CTX *ctx);
int p11prov_ctx_lock_slots(P11PROV_CTX *ctx, struct p11prov_slot **slots);
void p11prov_ctx_unlock_slots(P11PROV_CTX *ctx, struct p11prov_slot **slots);

/* Errors */
void p11prov_raise(P11PROV_CTX *ctx,
                   const char *file, int line, const char *func,
                   int errnum, const char *fmt, ...);

#define P11PROV_raise(ctx, errnum, ...) \
do { \
    p11prov_raise((ctx), OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC, \
                  (errnum), __VA_ARGS__); \
    if (errnum) \
        p11prov_debug("Error: %lu", (unsigned long)(errnum)); \
    p11prov_debug(__VA_ARGS__); \
} while(0)

/* Debugging */
void p11prov_debug(const char *fmt, ...);
void p11prov_debug_mechanism(P11PROV_CTX *ctx, CK_SLOT_ID slotid,
                             CK_MECHANISM_TYPE type);
void p11prov_debug_token_info(CK_TOKEN_INFO info);
void p11prov_debug_slot(struct p11prov_slot *slot);

/* Keys */
typedef struct p11prov_key P11PROV_KEY;

P11PROV_KEY *p11prov_key_ref(P11PROV_KEY *key);
void p11prov_key_free(P11PROV_KEY *key);
CK_ATTRIBUTE *p11prov_key_attr(P11PROV_KEY *key, CK_ATTRIBUTE_TYPE type);
CK_KEY_TYPE p11prov_key_type(P11PROV_KEY *key);
CK_SLOT_ID p11prov_key_slotid(P11PROV_KEY *key);
CK_OBJECT_HANDLE p11prov_key_handle(P11PROV_KEY *key);
CK_ULONG p11prov_key_size(P11PROV_KEY *key);

int find_keys(P11PROV_CTX *provctx,
              P11PROV_KEY **priv, P11PROV_KEY **pub,
              CK_SLOT_ID slotid, CK_OBJECT_CLASS class,
              const unsigned char *id, size_t id_len,
              const char *label);
P11PROV_KEY *p11prov_create_secret_key(P11PROV_CTX *provctx,
                                       CK_SESSION_HANDLE session,
                                       bool session_key,
                                       unsigned char *secret,
                                       size_t secretlen);

/* Object Store */
typedef struct p11prov_object P11PROV_OBJECT;

void p11prov_object_free(P11PROV_OBJECT *obj);
bool p11prov_object_check_key(P11PROV_OBJECT *obj, bool priv);
int p11prov_object_export_public_rsa_key(P11PROV_OBJECT *obj,
                                         OSSL_CALLBACK *cb_fn, void *cb_arg);
P11PROV_KEY *p11prov_object_get_key(P11PROV_OBJECT *obj, bool priv);


/* dispatching */
#define DECL_DISPATCH_FUNC(type, prefix, name) \
    static OSSL_FUNC_##type##_##name##_fn prefix##_##name

/* rsa keymgmt */
#define DISPATCH_RSAKM_FN(name) \
    DECL_DISPATCH_FUNC(keymgmt, p11prov_rsakm, name)
#define DISPATCH_RSAKM_ELEM(NAME, name) \
    { OSSL_FUNC_KEYMGMT_##NAME, (void(*)(void))p11prov_rsakm_##name }
extern const OSSL_DISPATCH p11prov_rsa_keymgmt_functions[];

/* ecdsa keymgmt */
#define DISPATCH_ECKM_FN(name) \
    DECL_DISPATCH_FUNC(keymgmt, p11prov_eckm, name)
#define DISPATCH_ECKM_ELEM(NAME, name) \
    { OSSL_FUNC_KEYMGMT_##NAME, (void(*)(void))p11prov_eckm_##name }
extern const OSSL_DISPATCH p11prov_ecdsa_keymgmt_functions[];

/* hkdf keymgmt */
#define DISPATCH_HKDFKM_FN(name) \
    DECL_DISPATCH_FUNC(keymgmt, p11prov_hkdfkm, name)
#define DISPATCH_HKDFKM_ELEM(NAME, name) \
    { OSSL_FUNC_KEYMGMT_##NAME, (void(*)(void))p11prov_hkdfkm_##name }
extern const OSSL_DISPATCH p11prov_hkdf_keymgmt_functions[];

#define DISPATCH_STORE_FN(name) \
    DECL_DISPATCH_FUNC(store, p11prov_store, name)
#define DISPATCH_STORE_ELEM(NAME, name) \
    { OSSL_FUNC_STORE_##NAME, (void(*)(void))p11prov_store_##name }
extern const OSSL_DISPATCH p11prov_store_functions[];

/* common sig functions */
#define DISPATCH_SIG_FN(name) \
    DECL_DISPATCH_FUNC(signature, p11prov_sig, name)
#define DISPATCH_SIG_ELEM(prefix, NAME, name) \
    { OSSL_FUNC_SIGNATURE_##NAME, (void(*)(void))p11prov_##prefix##_##name }

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
    { OSSL_FUNC_ASYM_CIPHER_##NAME, (void(*)(void))p11prov_rsaenc_##name }
extern const OSSL_DISPATCH p11prov_rsa_asym_cipher_functions[];

/* ecdh derivation */
#define DISPATCH_ECDH_FN(name) \
    DECL_DISPATCH_FUNC(keyexch, p11prov_ecdh, name)
#define DISPATCH_ECDH_ELEM(prefix, NAME, name) \
    { OSSL_FUNC_KEYEXCH_##NAME, (void(*)(void))p11prov_##prefix##_##name }
extern const OSSL_DISPATCH p11prov_ecdh_exchange_functions[];

/* HKDF exchange and kdf fns */
#define DISPATCH_EXCHHKDF_FN(name) \
    DECL_DISPATCH_FUNC(keyexch, p11prov_exch_hkdf, name)
#define DISPATCH_EXCHHKDF_ELEM(prefix, NAME, name) \
    { OSSL_FUNC_KEYEXCH_##NAME, (void(*)(void))p11prov_##prefix##_##name }
extern const OSSL_DISPATCH p11prov_hkdf_exchange_functions[];
#define DISPATCH_HKDF_FN(name) \
    DECL_DISPATCH_FUNC(kdf, p11prov_hkdf, name)
#define DISPATCH_HKDF_ELEM(prefix, NAME, name) \
    { OSSL_FUNC_KDF_##NAME, (void(*)(void))p11prov_##prefix##_##name }
extern const void *p11prov_hkdfkm_static_ctx;
extern const OSSL_DISPATCH p11prov_hkdf_kdf_functions[];


/* Utilities to fetch objects from tokens */

struct fetch_attrs {
    CK_ATTRIBUTE_TYPE type;
    unsigned char **value;
    unsigned long *value_len;
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
    } while(0)

#define FA_RETURN_VAL(x, _a, _b) \
    do { \
        *x.value = _a; \
        *x.value_len = _b; \
    } while(0)

#define FA_RETURN_LEN(x, _a) *x.value_len = _a

#define CKATTR_ASSIGN_ALL(x, _a, _b, _c) \
    do { \
        x.type = _a; \
        x.pValue = (void *)_b; \
        x.ulValueLen = _c; \
    } while(0)

int p11prov_fetch_attributes(CK_FUNCTION_LIST *f,
                             CK_SESSION_HANDLE session,
                             CK_OBJECT_HANDLE object,
                             struct fetch_attrs *attrs,
                             unsigned long attrnums);

CK_SESSION_HANDLE p11prov_get_session(P11PROV_CTX *provctx,
                                      CK_SLOT_ID slotid);
void p11prov_put_session(P11PROV_CTX *provctx, CK_SESSION_HANDLE session);
#endif /* _PROVIDER_H */
