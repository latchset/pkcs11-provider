/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _OBJ_INTERNAL_H_
#define _OBJ_INTERNAL_H_

#include "provider.h"
#include "encoder.h"

struct p11prov_key {
    CK_KEY_TYPE type;
    CK_BBOOL always_auth;
    CK_ULONG bit_size;
    CK_ULONG size;
    CK_ULONG param_set;
};

struct p11prov_crt {
    CK_CERTIFICATE_TYPE type;
    CK_CERTIFICATE_CATEGORY category;
    CK_BBOOL trusted;
};

struct p11prov_obj {
    P11PROV_CTX *ctx;
    bool raf; /* re-init after fork */
    /* The provider stored the key on the token itself and this object
     * exclusively owns the resulting session object, which needs to be
     * destroyed when this structure is freed. Not equivalent to
     * cka_token being false: session objects can also be found on the
     * token or borrow their handle. */
    bool owns_key;

    CK_SLOT_ID slotid;
    CK_OBJECT_HANDLE handle;
    CK_OBJECT_CLASS class;
    CK_OBJECT_HANDLE cached;
    CK_BBOOL cka_copyable;
    CK_BBOOL cka_token;
    CK_FLAGS usage;

    P11PROV_URI *refresh_uri;
    char *public_uri;

    union {
        struct p11prov_key key;
        struct p11prov_crt crt;
    } data;

    p11prov_obj_get_template_fn get_template;

    CK_ATTRIBUTE *attrs;
    int numattrs;

    int refcnt;
    int poolid;

    P11PROV_OBJ *assoc_obj;
    /* reference held on the object that owns the borrowed handle */
    P11PROV_OBJ *ref_obj;
    P11PROV_SESSION *ref_session;
};

CK_RV p11prov_obj_store_public_key(P11PROV_OBJ *key);
CK_RV p11prov_obj_re_store_key(P11PROV_OBJ *key);
CK_RV obj_add_to_pool(P11PROV_OBJ *obj);
void obj_rm_from_pool(P11PROV_OBJ *obj);
P11PROV_OBJ *p11prov_obj_pool_find(P11PROV_OBJ_POOL *pool,
                                   CK_OBJECT_CLASS class, CK_KEY_TYPE type,
                                   CK_ULONG param_set, CK_ULONG bit_size,
                                   CK_ATTRIBUTE *attrs, int numattrs);
CK_RV decode_ec_point(P11PROV_CTX *provctx, CK_KEY_TYPE key_type,
                      CK_ULONG expected_size, CK_ATTRIBUTE *attr,
                      struct data_buffer *ec_point);
CK_RV get_attrs_from_cert(P11PROV_OBJ *crt, CK_ATTRIBUTE *attrs, int num);
CK_RV p11prov_match_curve(CK_KEY_TYPE type, CK_ATTRIBUTE *attr,
                          const char **curve_name, int *curve_nid,
                          CK_ULONG *key_bit_size, CK_ULONG *key_size);
CK_OBJECT_HANDLE p11prov_obj_get_handle_no_cache(P11PROV_OBJ *obj);
CK_RV p11prov_store_symmetric_key(P11PROV_CTX *provctx,
                                  P11PROV_SESSION *session,
                                  CK_KEY_TYPE key_type, bool session_key,
                                  const unsigned char *secret, size_t secretlen,
                                  CK_FLAGS usage, P11PROV_OBJ **ret);

#define CKA_P11PROV_CURVE_NAME CKA_P11PROV_BASE + 1
#define CKA_P11PROV_CURVE_NID CKA_P11PROV_BASE + 2
#define CKA_P11PROV_PUB_KEY CKA_P11PROV_BASE + 3
#define CKA_P11PROV_PUB_KEY_X CKA_P11PROV_BASE + 4
#define CKA_P11PROV_PUB_KEY_Y CKA_P11PROV_BASE + 5

#endif
