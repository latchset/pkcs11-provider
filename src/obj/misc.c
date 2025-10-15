/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "obj/internal.h"

CK_RV p11prov_obj_set_attributes(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                                 P11PROV_OBJ *obj, CK_ATTRIBUTE *template,
                                 CK_ULONG tsize)
{
    P11PROV_SESSION *s = session;
    CK_SLOT_ID slotid = obj->slotid;
    CK_RV ret;

    if (!s) {
        ret = p11prov_get_session(ctx, &slotid, NULL, NULL,
                                  CK_UNAVAILABLE_INFORMATION, NULL, NULL, false,
                                  true, &s);
        if (ret != CKR_OK) {
            P11PROV_raise(ctx, ret, "Failed to open session on slot %lu",
                          slotid);
            return ret;
        }
    }

    ret =
        p11prov_SetAttributeValue(ctx, p11prov_session_handle(s),
                                  p11prov_obj_get_handle(obj), template, tsize);

    if (obj->cached != CK_INVALID_HANDLE) {
        /* try to re-cache key to maintain matching attributes */
        //cache_key(obj);
    }

    /* TODO: should we retry iterating value by value on each element of
     * template to be able to set as much as we can and return which attribute
     * exactly the token is refusing ? */

    if (s != session) {
        p11prov_return_session(s);
    }
    return ret;
}

CK_RV p11prov_obj_copy_specific_attr(P11PROV_OBJ *pub_key,
                                     P11PROV_OBJ *priv_key,
                                     CK_ATTRIBUTE_TYPE type)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV ret = CKR_OK;

    if (!pub_key || !priv_key) {
        return CKR_ARGUMENTS_BAD;
    }

    attr = p11prov_obj_get_attr(pub_key, type);
    if (!attr) {
        P11PROV_debug("Failed to fetch the specific attribute");
        return CKR_GENERAL_ERROR;
    }

    ret = p11prov_copy_attr(&priv_key->attrs[priv_key->numattrs], attr);
    if (ret != CKR_OK) {
        P11PROV_raise(priv_key->ctx, ret, "Failed attr copy");
        return CKR_GENERAL_ERROR;
    }
    priv_key->numattrs++;

    return ret;
}
