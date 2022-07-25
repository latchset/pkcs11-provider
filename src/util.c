/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"

int p11prov_fetch_attributes(CK_FUNCTION_LIST *f, CK_SESSION_HANDLE session,
                             CK_OBJECT_HANDLE object, struct fetch_attrs *attrs,
                             unsigned long attrnums)
{
    CK_ATTRIBUTE q[attrnums];
    CK_ATTRIBUTE r[attrnums];
    int ret;

    for (int i = 0; i < attrnums; i++) {
        if (attrs[i].allocate) {
            CKATTR_ASSIGN_ALL(q[i], attrs[i].type, NULL, 0);
        } else {
            CKATTR_ASSIGN_ALL(q[i], attrs[i].type, *attrs[i].value,
                              *attrs[i].value_len);
        }
    }

    /* try one shot, then fallback to individual calls if that fails */
    ret = f->C_GetAttributeValue(session, object, q, attrnums);
    if (ret == CKR_OK) {
        unsigned long retrnums = 0;
        for (int i = 0; i < attrnums; i++) {
            if (q[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                if (attrs[i].required) {
                    return -ENOENT;
                }
                FA_RETURN_LEN(attrs[i], 0);
                continue;
            }
            if (attrs[i].allocate) {
                /* always allocate and zero one more, so that
                 * zero terminated strings work automatically */
                char *a = OPENSSL_zalloc(q[i].ulValueLen + 1);
                if (a == NULL) {
                    return -ENOMEM;
                }
                FA_RETURN_VAL(attrs[i], a, q[i].ulValueLen);

                CKATTR_ASSIGN_ALL(r[retrnums], attrs[i].type, *attrs[i].value,
                                  *attrs[i].value_len);
                retrnums++;
            } else {
                FA_RETURN_LEN(attrs[i], q[i].ulValueLen);
            }
        }
        if (retrnums > 0) {
            ret = f->C_GetAttributeValue(session, object, r, retrnums);
        }
    } else if (ret == CKR_ATTRIBUTE_SENSITIVE
               || ret == CKR_ATTRIBUTE_TYPE_INVALID) {
        p11prov_debug("Quering attributes one by one\n");
        /* go one by one as this PKCS11 does not have some attributes
         * and does not handle it gracefully */
        for (int i = 0; i < attrnums; i++) {
            if (attrs[i].allocate) {
                CKATTR_ASSIGN_ALL(q[0], attrs[i].type, NULL, 0);
                ret = f->C_GetAttributeValue(session, object, q, 1);
                if (ret != CKR_OK) {
                    if (attrs[i].required) {
                        return ret;
                    }
                } else {
                    char *a = OPENSSL_zalloc(q[0].ulValueLen + 1);
                    if (a == NULL) {
                        return -ENOMEM;
                    }
                    FA_RETURN_VAL(attrs[i], a, q[0].ulValueLen);
                }
            }
            CKATTR_ASSIGN_ALL(r[0], attrs[i].type, *attrs[i].value,
                              *attrs[i].value_len);
            ret = f->C_GetAttributeValue(session, object, r, 1);
            if (ret != CKR_OK) {
                if (r[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                    FA_RETURN_LEN(attrs[i], 0);
                }
                if (attrs[i].required) {
                    return ret;
                }
            }
            p11prov_debug("Attribute| type:%lu value:%p, len:%lu\n",
                          attrs[i].type, *attrs[i].value, *attrs[i].value_len);
        }
        ret = CKR_OK;
    }
    return ret;
}

CK_SESSION_HANDLE p11prov_get_session(P11PROV_CTX *provctx, CK_SLOT_ID slotid)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_FUNCTION_LIST *f;
    CK_RV ret;

    if (slotid == CK_UNAVAILABLE_INFORMATION) {
        struct p11prov_slot *slots = NULL;
        int nslots = 0;

        nslots = p11prov_ctx_lock_slots(provctx, &slots);

        for (int i = 0; i < nslots; i++) {
            /* ignore slots that are not initialized */
            if (slots[i].slot.flags & CKF_TOKEN_PRESENT == 0) {
                continue;
            }
            if (slots[i].token.flags & CKF_TOKEN_INITIALIZED == 0) {
                continue;
            }

            slotid = slots[i].id;
        }

        p11prov_ctx_unlock_slots(provctx, &slots);
    }

    if (slotid == CK_UNAVAILABLE_INFORMATION) {
        goto done;
    }

    f = p11prov_ctx_fns(provctx);
    if (f == NULL) {
        goto done;
    }

    ret = f->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (ret != CKR_OK) {
        P11PROV_raise(provctx, ret, "Failed to open session on slot %lu",
                      slotid);
    }

done:
    return session;
}

void p11prov_put_session(P11PROV_CTX *provctx, CK_SESSION_HANDLE session)
{
    CK_FUNCTION_LIST *f;
    CK_RV ret;

    f = p11prov_ctx_fns(provctx);
    if (f == NULL) {
        return;
    }

    ret = f->C_CloseSession(session);
    if (ret != CKR_OK) {
        P11PROV_raise(provctx, ret, "Failed to close session %lu", session);
    }
}
