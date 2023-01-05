/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _OBJECTS_H
#define _OBJECTS_H

/* Set the base to Vendor + 'OPP' for OpenSSL PKCS11 Provider */
#define CKA_P11PROV_BASE CKA_VENDOR_DEFINED + 0x4F5050

/* Objects */
P11PROV_OBJ *p11prov_obj_new(P11PROV_CTX *ctx, CK_SLOT_ID slotid,
                             CK_OBJECT_HANDLE handle, CK_OBJECT_CLASS class);
P11PROV_OBJ *p11prov_obj_ref_no_cache(P11PROV_OBJ *obj);
P11PROV_OBJ *p11prov_obj_ref(P11PROV_OBJ *obj);
void p11prov_obj_free(P11PROV_OBJ *obj);
CK_SLOT_ID p11prov_obj_get_slotid(P11PROV_OBJ *obj);
CK_OBJECT_HANDLE p11prov_obj_get_handle(P11PROV_OBJ *obj);
CK_OBJECT_CLASS p11prov_obj_get_class(P11PROV_OBJ *obj);
CK_ATTRIBUTE *p11prov_obj_get_attr(P11PROV_OBJ *obj, CK_ATTRIBUTE_TYPE type);
CK_KEY_TYPE p11prov_obj_get_key_type(P11PROV_OBJ *obj);
CK_ULONG p11prov_obj_get_key_bit_size(P11PROV_OBJ *obj);
CK_ULONG p11prov_obj_get_key_size(P11PROV_OBJ *obj);
void p11prov_obj_to_reference(P11PROV_OBJ *obj, void **reference,
                              size_t *reference_sz);
P11PROV_OBJ *p11prov_obj_from_reference(const void *reference,
                                        size_t reference_sz);
P11PROV_CTX *p11prov_obj_get_prov_ctx(P11PROV_OBJ *obj);

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
CK_RV p11prov_derive_key(P11PROV_CTX *ctx, CK_SLOT_ID slotid,
                         CK_MECHANISM *mechanism, CK_OBJECT_HANDLE handle,
                         CK_ATTRIBUTE *template, CK_ULONG nattrs,
                         P11PROV_SESSION **session, CK_OBJECT_HANDLE *key);
CK_RV p11prov_obj_set_attributes(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                                 P11PROV_OBJ *obj, CK_ATTRIBUTE *template,
                                 CK_ULONG tsize);
int p11prov_obj_export_public_rsa_key(P11PROV_OBJ *obj, OSSL_CALLBACK *cb_fn,
                                      void *cb_arg);
int p11prov_obj_export_public_ec_key(P11PROV_OBJ *obj, OSSL_CALLBACK *cb_fn,
                                     void *cb_arg);
const char *p11prov_obj_get_ec_group_name(P11PROV_OBJ *obj);

#endif /* _OBJECTS_H */
