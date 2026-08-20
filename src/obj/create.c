/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "obj/internal.h"

P11PROV_OBJ *p11prov_create_secret_key(P11PROV_CTX *provctx,
                                       P11PROV_SESSION *session, CK_FLAGS usage,
                                       bool session_key, unsigned char *secret,
                                       size_t secretlen)
{
    P11PROV_OBJ *key = NULL;
    CK_RV ret;

    P11PROV_debug("Creating secret key (secret:%p[%zu])", secret, secretlen);

    ret = p11prov_store_symmetric_key(provctx, session, CKK_GENERIC_SECRET,
                                      session_key, secret, secretlen, usage,
                                      &key);
    if (ret != CKR_OK) {
        goto done;
    }

    /* save data in case we need to refresh on fork */
    if (session_key) {
        CK_ATTRIBUTE value = { CKA_VALUE, (void *)secret, secretlen };

        /* destroy the session object when obj is freed */
        key->owns_key = true;

        key->attrs = OPENSSL_zalloc(sizeof(CK_ATTRIBUTE));
        if (key->attrs == NULL) {
            ret = CKR_HOST_MEMORY;
            goto done;
        }
        ret = p11prov_copy_attr(&key->attrs[0], &value);
        if (ret != CKR_OK) {
            goto done;
        }
        key->numattrs = 1;
        key->usage = usage;
    }

done:
    if (ret != CKR_OK) {
        P11PROV_raise(provctx, ret, "Failed to create secret key");
        p11prov_obj_free(key);
        key = NULL;
    }
    return key;
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
