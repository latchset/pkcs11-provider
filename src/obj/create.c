/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "obj/internal.h"

#define SECRET_KEY_ATTRS 2
P11PROV_OBJ *p11prov_create_secret_key(P11PROV_CTX *provctx,
                                       P11PROV_SESSION *session,
                                       bool session_key, unsigned char *secret,
                                       size_t secretlen)
{
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_SESSION_INFO session_info;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_token = session_key ? CK_FALSE : CK_TRUE;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_TOKEN, &val_token, sizeof(val_token) },
        { CKA_DERIVE, &val_true, sizeof(val_true) },
        { CKA_VALUE, (void *)secret, secretlen },
    };
    CK_ULONG tcount = sizeof(template) / sizeof(CK_ATTRIBUTE);
    CK_OBJECT_HANDLE key_handle;
    P11PROV_OBJ *obj;
    struct fetch_attrs attrs[SECRET_KEY_ATTRS];
    int num;
    CK_RV ret;

    sess = p11prov_session_handle(session);

    P11PROV_debug("keys: create secret key (session:%lu secret:%p[%zu])", sess,
                  secret, secretlen);

    ret = p11prov_GetSessionInfo(provctx, sess, &session_info);
    if (ret != CKR_OK) {
        return NULL;
    }
    if (((session_info.flags & CKF_RW_SESSION) == 0) && val_token == CK_TRUE) {
        P11PROV_debug("Invalid read only session for token key request");
        return NULL;
    }

    ret = p11prov_CreateObject(provctx, sess, template, tcount, &key_handle);
    if (ret != CKR_OK) {
        return NULL;
    }

    obj = p11prov_obj_new(provctx, session_info.slotID, key_handle, key_class);
    if (obj == NULL) {
        return NULL;
    }
    obj->data.key.type = key_type;
    obj->data.key.size = secretlen;

    obj->attrs = OPENSSL_zalloc(SECRET_KEY_ATTRS * sizeof(CK_ATTRIBUTE));
    if (obj->attrs == NULL) {
        P11PROV_raise(provctx, CKR_HOST_MEMORY, "Allocation failure");
        p11prov_obj_free(obj);
        return NULL;
    }

    num = 0;
    FA_SET_BUF_ALLOC(attrs, num, CKA_ID, false);
    FA_SET_BUF_ALLOC(attrs, num, CKA_LABEL, false);
    ret = p11prov_fetch_attributes(provctx, session, key_handle, attrs, num);
    if (ret == CKR_OK) {
        obj->numattrs = 0;
        p11prov_move_alloc_attrs(attrs, num, obj->attrs, &obj->numattrs);
    } else {
        P11PROV_debug("Failed to query object attributes (%lu)", ret);
        p11prov_fetch_attrs_free(attrs, num);
        p11prov_obj_free(obj);
        obj = NULL;
    }
    return obj;
}

CK_RV p11prov_derive_key(P11PROV_OBJ *key, CK_MECHANISM *mechanism,
                         CK_ATTRIBUTE *template, CK_ULONG nattrs,
                         P11PROV_SESSION **_session, CK_OBJECT_HANDLE *dkey)
{
    P11PROV_CTX *ctx = p11prov_obj_get_prov_ctx(key);
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    P11PROV_SESSION *session = *_session;
    CK_RV ret;

    /* do this first as it may cause a refresh of the object that will
     * set internal fields correctly */
    handle = p11prov_obj_get_handle(key);
    if (handle == CK_INVALID_HANDLE) {
        ret = CKR_KEY_HANDLE_INVALID;
        P11PROV_raise(ctx, ret, "Invalid key handle");
        return ret;
    }

    if (!session) {
        ret = p11prov_try_session_ref(key, mechanism->mechanism, false, false,
                                      &session);
        if (ret != CKR_OK) {
            P11PROV_raise(ctx, ret, "Failed to acquire session");
            return ret;
        }
    }

    ret = p11prov_DeriveKey(ctx, p11prov_session_handle(session), mechanism,
                            handle, template, nattrs, dkey);
    if (ret == CKR_OK) {
        *_session = session;
    } else {
        if (*_session == NULL) {
            p11prov_return_session(session);
        }
    }
    return ret;
}
