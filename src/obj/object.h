/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _OBJECTS_H
#define _OBJECTS_H

/* Set the base to Vendor + 'OPP' for OpenSSL PKCS11 Provider */
#define CKA_P11PROV_BASE CKA_VENDOR_DEFINED + 0x4F5050

/* Special value for "imported key handle" */
#define CK_P11PROV_IMPORTED_HANDLE (CK_UNAVAILABLE_INFORMATION - 1)

/* Objects */
CK_RV p11prov_obj_pool_init(P11PROV_CTX *ctx, CK_SLOT_ID id,
                            P11PROV_OBJ_POOL **_pool);
void p11prov_obj_pool_free(P11PROV_OBJ_POOL *pool);
void p11prov_obj_pool_fork_reset(P11PROV_OBJ_POOL *pool);
P11PROV_OBJ *p11prov_obj_new(P11PROV_CTX *ctx, CK_SLOT_ID slotid,
                             CK_OBJECT_HANDLE handle, CK_OBJECT_CLASS class);
P11PROV_OBJ *p11prov_obj_ref_no_cache(P11PROV_OBJ *obj);
P11PROV_OBJ *p11prov_obj_ref(P11PROV_OBJ *obj);
void p11prov_obj_free(P11PROV_OBJ *obj);
CK_SLOT_ID p11prov_obj_get_slotid(P11PROV_OBJ *obj);
CK_OBJECT_HANDLE p11prov_obj_get_handle(P11PROV_OBJ *obj);
CK_OBJECT_CLASS p11prov_obj_get_class(P11PROV_OBJ *obj);
CK_ATTRIBUTE *p11prov_obj_get_attr(P11PROV_OBJ *obj, CK_ATTRIBUTE_TYPE type);
CK_RV p11prov_obj_add_attr(P11PROV_OBJ *obj, CK_ATTRIBUTE *attr);
bool p11prov_obj_get_bool(P11PROV_OBJ *obj, CK_ATTRIBUTE_TYPE type, bool def);
CK_KEY_TYPE p11prov_obj_get_key_type(P11PROV_OBJ *obj);
CK_ULONG p11prov_obj_get_key_bit_size(P11PROV_OBJ *obj);
CK_ULONG p11prov_obj_get_key_size(P11PROV_OBJ *obj);
CK_ULONG p11prov_obj_get_key_param_set(P11PROV_OBJ *obj);
void p11prov_obj_to_store_reference(P11PROV_OBJ *obj, void **reference,
                                    size_t *reference_sz);
P11PROV_OBJ *p11prov_obj_from_reference(const void *reference,
                                        size_t reference_sz);
P11PROV_CTX *p11prov_obj_get_prov_ctx(P11PROV_OBJ *obj);
P11PROV_OBJ *p11prov_obj_get_associated(P11PROV_OBJ *obj);
void p11prov_obj_set_associated(P11PROV_OBJ *obj, P11PROV_OBJ *assoc);
const char *p11prov_obj_get_public_uri(P11PROV_OBJ *obj);
void *p11prov_obj_from_typed_reference(const void *reference,
                                       size_t reference_sz,
                                       CK_KEY_TYPE key_type);
P11PROV_SESSION *p11prov_obj_get_session_ref(P11PROV_OBJ *obj);
void p11prov_obj_set_session_ref(P11PROV_OBJ *obj, P11PROV_SESSION *session);
P11PROV_URI *p11prov_obj_get_refresh_uri(P11PROV_OBJ *obj);
void p11prov_obj_set_class(P11PROV_OBJ *obj, CK_OBJECT_CLASS class);
void p11prov_obj_set_key_type(P11PROV_OBJ *obj, CK_KEY_TYPE type);
void p11prov_obj_set_key_params(P11PROV_OBJ *obj, CK_ULONG param_set);

typedef CK_RV (*store_obj_callback)(void *, P11PROV_OBJ *);
CK_RV p11prov_obj_from_handle(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                              CK_OBJECT_HANDLE handle, P11PROV_OBJ **object);
CK_RV p11prov_obj_find(P11PROV_CTX *provctx, P11PROV_SESSION *session,
                       CK_SLOT_ID slotid, P11PROV_URI *uri,
                       store_obj_callback cb, void *cb_ctx);
P11PROV_OBJ *p11prov_create_secret_key(P11PROV_CTX *provctx,
                                       P11PROV_SESSION *session,
                                       bool session_key, unsigned char *secret,
                                       size_t secretlen);
CK_RV p11prov_derive_key(P11PROV_OBJ *key, CK_MECHANISM *mechanism,
                         CK_ATTRIBUTE *template, CK_ULONG nattrs,
                         P11PROV_SESSION **_session, CK_OBJECT_HANDLE *dkey);
const char *p11prov_obj_get_ec_group_name(P11PROV_OBJ *obj);
bool p11prov_obj_get_ec_compressed(P11PROV_OBJ *obj);
int p11prov_obj_export_public_key(P11PROV_OBJ *obj, CK_KEY_TYPE key_type,
                                  bool search_related, bool params_only,
                                  OSSL_CALLBACK *cb_fn, void *cb_arg);
int p11prov_obj_get_ec_public_x_y(P11PROV_OBJ *obj, CK_ATTRIBUTE **pub_x,
                                  CK_ATTRIBUTE **pub_y);
int p11prov_obj_get_ed_pub_key(P11PROV_OBJ *obj, CK_ATTRIBUTE **pub);
CK_ATTRIBUTE *p11prov_obj_get_ec_public_raw(P11PROV_OBJ *key);
P11PROV_OBJ *mock_pub_ec_key(P11PROV_CTX *ctx, CK_ATTRIBUTE_TYPE type,
                             CK_ATTRIBUTE *ec_params);
bool p11prov_obj_is_rsa_pss(P11PROV_OBJ *obj);

#define OBJ_CMP_KEY_TYPE 0x00
#define OBJ_CMP_KEY_PUBLIC 0x01
#define OBJ_CMP_KEY_PRIVATE 0x02
int p11prov_obj_key_cmp(P11PROV_OBJ *obj1, P11PROV_OBJ *obj2, CK_KEY_TYPE type,
                        int cmp_type);

CK_RV p11prov_obj_import_key(P11PROV_OBJ *key, const OSSL_PARAM params[]);

P11PROV_OBJ *p11prov_obj_import_secret_key(P11PROV_CTX *ctx, CK_KEY_TYPE type,
                                           const unsigned char *key,
                                           size_t keylen);

CK_RV p11prov_obj_set_ec_encoded_public_key(P11PROV_OBJ *key,
                                            const void *pubkey,
                                            size_t pubkey_len);

P11PROV_OBJ *p11prov_obj_find_associated(P11PROV_OBJ *obj,
                                         CK_OBJECT_CLASS class);

#define ED25519 "ED25519"
#define ED25519_BIT_SIZE 256
#define ED25519_BYTE_SIZE ED25519_BIT_SIZE / 8
#define ED25519_SEC_BITS 128
#define ED25519_SIG_SIZE 64
#define ED25519_EC_PARAMS \
    0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, \
        0x31, 0x39
#define ED25519_EC_PARAMS_LEN 14
#define ED448 "ED448"
#define ED448_BIT_SIZE 456
#define ED448_BYTE_SIZE ED448_BIT_SIZE / 8
#define ED448_SEC_BITS 224
#define ED448_SIG_SIZE 114
#define ED448_EC_PARAMS \
    0x13, 0x0a, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x34, 0x34, 0x38
#define ED448_EC_PARAMS_LEN 12
extern const CK_BYTE ed25519_ec_params[];
extern const CK_BYTE ed448_ec_params[];

#define MLDSA_44 "ML-DSA-44"
#define MLDSA_65 "ML-DSA-65"
#define MLDSA_87 "ML-DSA-87"

/* See FIPS-204, 4. Parameter Sets */
#define ML_DSA_44_SK_SIZE 2560
#define ML_DSA_44_PK_SIZE 1312
#define ML_DSA_44_SIG_SIZE 2420
#define ML_DSA_65_SK_SIZE 4032
#define ML_DSA_65_PK_SIZE 1952
#define ML_DSA_65_SIG_SIZE 3309
#define ML_DSA_87_SK_SIZE 4896
#define ML_DSA_87_PK_SIZE 2592
#define ML_DSA_87_SIG_SIZE 4627

#define MLKEM_512 "ML-KEM-512"
#define MLKEM_768 "ML-KEM-768"
#define MLKEM_1024 "ML-KEM-1024"
#define ML_KEM_512_CIPHERTEXT_BYTES 768
#define ML_KEM_768_CIPHERTEXT_BYTES 1088
#define ML_KEM_1024_CIPHERTEXT_BYTES 1568

/* See FIPS-203, 4. Parameter Sets */
#define ML_KEM_512_PK_SIZE 800
#define ML_KEM_768_PK_SIZE 1184
#define ML_KEM_1024_PK_SIZE 1568
#define ML_KEM_512_CIPHERTEXT_BYTES 768
#define ML_KEM_768_CIPHERTEXT_BYTES 1088
#define ML_KEM_1024_CIPHERTEXT_BYTES 1568

#endif /* _OBJECTS_H */
