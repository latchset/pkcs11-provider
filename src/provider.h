/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

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
#define P11PROV_DESCS_URI "PKCS11 URI Store"

typedef struct st_provider_ctx PROVIDER_CTX;

struct p11prov_slot {
    CK_SLOT_ID id;
    CK_SLOT_INFO slot;
    CK_TOKEN_INFO token;
};

CK_FUNCTION_LIST *provider_ctx_fns(PROVIDER_CTX *ctx);
int provider_ctx_lock_slots(PROVIDER_CTX *ctx, struct p11prov_slot **slots);
void provider_ctx_unlock_slots(PROVIDER_CTX *ctx, struct p11prov_slot **slots);
void p11prov_debug(const char *fmt, ...);

/* Key Management */
extern const OSSL_DISPATCH p11prov_rsa_keymgmt_functions[];

/* Object Stores */
typedef struct p11prov_object P11PROV_OBJECT;
typedef struct p11prov_key P11PROV_KEY;

void p11prov_object_free(P11PROV_OBJECT *obj);
bool p11prov_object_check_key(P11PROV_OBJECT *obj, bool need_private);
int p11prov_object_export_public_rsa_key(P11PROV_OBJECT *obj,
                                         OSSL_CALLBACK *cb_fn, void *cb_arg);
P11PROV_KEY *p11prov_object_get_key(P11PROV_OBJECT *obj);

void p11prov_key_free(P11PROV_KEY *key);
CK_ATTRIBUTE *p11prov_key_attr(P11PROV_KEY *key, CK_ATTRIBUTE_TYPE type);
CK_SLOT_ID p11prov_key_slotid(P11PROV_KEY *key);
CK_OBJECT_HANDLE p11prov_key_hanlde(P11PROV_KEY *key);

extern const OSSL_DISPATCH p11prov_object_store_functions[];

/* Signatures */
extern const OSSL_DISPATCH p11prov_rsa_signature_functions[];

#endif /* _PROVIDER_H */
