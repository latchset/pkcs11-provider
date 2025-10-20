/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "obj/internal.h"

/* internal support functions */

static CK_RV supports_caching(P11PROV_CTX *ctx, CK_SLOT_ID id, int action,
                              CK_BBOOL *data)
{
    CK_ULONG data_size = sizeof(CK_BBOOL);
    void *data_ptr = &data;
    const char *name = "Caching Supported";

    switch (action) {
    case GET_ATTR:
        return p11prov_ctx_get_quirk(ctx, id, name, data_ptr, &data_size);
    case SET_ATTR:
        return p11prov_ctx_set_quirk(ctx, id, name, data, data_size);
    default:
        return CKR_ARGUMENTS_BAD;
    }
}

static void destroy_key_cache(P11PROV_OBJ *obj, P11PROV_SESSION *session)

{
    P11PROV_SESSION *_session = NULL;
    CK_SESSION_HANDLE sess;
    CK_RV ret;

    if (obj->cached == CK_INVALID_HANDLE) {
        return;
    }

    if (session) {
        sess = p11prov_session_handle(session);
    } else {
        ret = p11prov_take_login_session(obj->ctx, obj->slotid, &_session);
        if (ret != CKR_OK) {
            P11PROV_debug("Failed to get login session. Error %lx", ret);
            return;
        }
        sess = p11prov_session_handle(_session);
    }

    ret = p11prov_DestroyObject(obj->ctx, sess, obj->cached);
    if (ret != CKR_OK) {
        P11PROV_debug("Failed to destroy cached key. Error %lx", ret);
    }
    obj->cached = CK_INVALID_HANDLE;

    if (_session) {
        p11prov_return_session(_session);
    }
}

static void cache_key(P11PROV_OBJ *obj)
{
    P11PROV_SESSION *session = NULL;
    CK_BBOOL val_false = CK_FALSE;
    CK_ATTRIBUTE template[] = { { CKA_TOKEN, &val_false, sizeof(val_false) } };
    CK_SESSION_HANDLE sess;
    CK_BBOOL can_cache = CK_TRUE;
    CK_RV ret;
    int cache_keys;

    /* check whether keys should be cached at all */
    cache_keys = p11prov_ctx_cache_keys(obj->ctx);
    if (cache_keys == P11PROV_CACHE_KEYS_NEVER) {
        return;
    }

    /* We cache only keys on the token */
    if ((obj->class != CKO_PRIVATE_KEY && obj->class != CKO_PUBLIC_KEY)
        || obj->cka_token != CK_TRUE || obj->cka_copyable != CK_TRUE) {
        return;
    }

    ret = supports_caching(obj->ctx, obj->slotid, GET_ATTR, &can_cache);
    if (ret != CKR_OK) {
        P11PROV_raise(obj->ctx, ret, "Failed to get quirk");
    }
    if (can_cache != CK_TRUE) {
        /* switch copyable so we do not try again */
        obj->cka_copyable = CK_FALSE;
        return;
    }

    ret = p11prov_take_login_session(obj->ctx, obj->slotid, &session);
    if (ret != CKR_OK || session == NULL) {
        P11PROV_debug("Failed to get login session. Error %lx", ret);
        return;
    }

    /* If already cached, release and re-cache */
    destroy_key_cache(obj, session);

    sess = p11prov_session_handle(session);
    ret = p11prov_CopyObject(obj->ctx, sess, p11prov_obj_get_handle(obj),
                             template, 1, &obj->cached);
    if (ret != CKR_OK) {
        P11PROV_raise(obj->ctx, ret, "Failed to cache key");
        if (ret == CKR_FUNCTION_NOT_SUPPORTED) {
            can_cache = CK_FALSE;
            ret = supports_caching(obj->ctx, obj->slotid, SET_ATTR, &can_cache);
            if (ret != CKR_OK) {
                P11PROV_raise(obj->ctx, ret, "Failed to set quirk");
            }
        }
        /* switch copyable so we do not try again */
        obj->cka_copyable = CK_FALSE;
    } else {
        P11PROV_debug("Key %lu:%lu cached as %lu:%lu", obj->slotid, obj->handle,
                      sess, obj->cached);
    }

    p11prov_return_session(session);
    return;
}

static void p11prov_obj_refresh(P11PROV_OBJ *obj)
{
    int login_behavior;
    bool login = false;
    P11PROV_SESSION *session = NULL;
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_ATTRIBUTE template[3] = { 0 };
    CK_ATTRIBUTE *attr;
    int anum;
    CK_OBJECT_HANDLE handle;
    CK_ULONG objcount = 0;
    P11PROV_OBJ *tmp = NULL;
    CK_RV ret;

    P11PROV_debug("Refresh object %p", obj);

    if (obj->class == CKO_PRIVATE_KEY || obj->class == CKO_SECRET_KEY) {
        login = true;
    }
    login_behavior = p11prov_ctx_login_behavior(obj->ctx);
    if (login_behavior == PUBKEY_LOGIN_ALWAYS) {
        login = true;
    }

    ret = p11prov_try_session_ref(obj, CK_UNAVAILABLE_INFORMATION, login, false,
                                  &session);
    if (ret != CKR_OK) {
        P11PROV_debug("Failed to get session to refresh object %p", obj);
        return;
    }

    sess = p11prov_session_handle(session);

    anum = 0;
    CKATTR_ASSIGN(template[anum], CKA_CLASS, &(obj->class), sizeof(obj->class));
    anum++;
    /* use CKA_ID if available */
    attr = p11prov_obj_get_attr(obj, CKA_ID);
    if (attr) {
        template[anum] = *attr;
        anum++;
    }
    /* use Label if available */
    attr = p11prov_obj_get_attr(obj, CKA_LABEL);
    if (attr) {
        template[anum] = *attr;
        anum++;
    }

    ret = p11prov_FindObjectsInit(obj->ctx, sess, template, anum);
    if (ret != CKR_OK) {
        goto done;
    }

    /* we expect a single entry */
    ret = p11prov_FindObjects(obj->ctx, sess, &handle, 1, &objcount);

    /* Finalizing is not fatal so ignore result */
    p11prov_FindObjectsFinal(obj->ctx, sess);

    if (ret != CKR_OK || objcount == 0) {
        P11PROV_raise(obj->ctx, ret,
                      "Failed to find refresh object %p (count=%ld)", obj,
                      objcount);
        goto done;
    }
    if (objcount != 1) {
        P11PROV_raise(obj->ctx, ret,
                      "Too many objects found on refresh (count=%ld)",
                      objcount);
        goto done;
    }

    ret = p11prov_obj_from_handle(obj->ctx, session, handle, &tmp);
    if (ret != CKR_OK) {
        P11PROV_raise(obj->ctx, ret, "Failed to get object from handle");
        goto done;
    }

    /* move over all the object data, then free the tmp */
    obj->handle = tmp->handle;
    obj->cached = tmp->cached;
    obj->cka_copyable = tmp->cka_copyable;
    obj->cka_token = tmp->cka_token;
    switch (obj->class) {
    case CKO_CERTIFICATE:
        obj->data.crt = tmp->data.crt;
        break;
    case CKO_PUBLIC_KEY:
    case CKO_PRIVATE_KEY:
    case CKO_SECRET_KEY:
        obj->data.key = tmp->data.key;
        break;
    default:
        break;
    }
    OPENSSL_free(obj->public_uri);
    obj->public_uri = NULL;
    /* FIXME: How do we refresh attrs? What happens if a pointer
     * to an attr value was saved somewhere? Freeing ->attrs would
     * cause use-after-free issues */
    p11prov_obj_free(tmp);
    obj->raf = false;

    /* Refresh the associated object too if there is one */
    if (obj->assoc_obj && obj->assoc_obj->raf) {
        p11prov_obj_refresh(obj->assoc_obj);
    }

done:
    p11prov_return_session(session);
}

/* Generic Object functions */

P11PROV_OBJ *p11prov_obj_new(P11PROV_CTX *ctx, CK_SLOT_ID slotid,
                             CK_OBJECT_HANDLE handle, CK_OBJECT_CLASS class)
{
    P11PROV_OBJ *obj;
    CK_RV ret;

    obj = OPENSSL_zalloc(sizeof(P11PROV_OBJ));
    if (obj == NULL) {
        return NULL;
    }
    obj->ctx = ctx;
    obj->slotid = slotid;
    obj->handle = handle;
    obj->class = class;
    obj->cached = CK_INVALID_HANDLE;

    obj->refcnt = 1;
    obj->poolid = -1;

    if (handle == CK_P11PROV_IMPORTED_HANDLE) {
        /* mock object, return w/o adding to pool */
        return obj;
    }

    ret = obj_add_to_pool(obj);
    if (ret != CKR_OK) {
        OPENSSL_free(obj);
        obj = NULL;
    }
    return obj;
}

void p11prov_obj_free(P11PROV_OBJ *obj)
{
    P11PROV_debug("Free Object: %p (handle:%lu)", obj,
                  obj ? obj->handle : CK_INVALID_HANDLE);

    if (obj == NULL) {
        return;
    }
    if (__atomic_sub_fetch(&obj->refcnt, 1, __ATOMIC_SEQ_CST) != 0) {
        P11PROV_debug("object free: reference held");
        return;
    }

    if (obj->ref_session) {
        p11prov_session_deref(obj->ref_session);
        obj->ref_session = NULL;
    }

    obj_rm_from_pool(obj);

    destroy_key_cache(obj, NULL);

    for (int i = 0; i < obj->numattrs; i++) {
        OPENSSL_free(obj->attrs[i].pValue);
    }
    OPENSSL_free(obj->attrs);

    OPENSSL_free(obj->public_uri);
    p11prov_uri_free(obj->refresh_uri);

    p11prov_obj_free(obj->assoc_obj);

    OPENSSL_clear_free(obj, sizeof(P11PROV_OBJ));
}

P11PROV_OBJ *p11prov_obj_ref_no_cache(P11PROV_OBJ *obj)
{
    P11PROV_debug("Ref Object: %p (handle:%lu)", obj,
                  obj ? obj->handle : CK_INVALID_HANDLE);

    if (obj && __atomic_fetch_add(&obj->refcnt, 1, __ATOMIC_SEQ_CST) > 0) {
        return obj;
    }

    return NULL;
}

P11PROV_OBJ *p11prov_obj_ref(P11PROV_OBJ *obj)
{
    obj = p11prov_obj_ref_no_cache(obj);
    if (!obj) {
        return NULL;
    }

    /* When referenced it means we are likely going to try to use the key in
     * some operation, let's try to cache it in the tokens volatile memory for
     * those tokens that support the operation. This will result in much faster
     * key operations with some tokens as the keys are unencrypted in volatile
     * memory */
    if (obj->cached == CK_INVALID_HANDLE) {
        cache_key(obj);
    }

    return obj;
}

void p11prov_obj_to_store_reference(P11PROV_OBJ *obj, void **reference,
                                    size_t *reference_sz)
{
    /* The store context keeps reference to this object so we will not free
     * it while the store context is alive. When the applications wants to
     * reference the object, it will get its own reference through
     * p11prov_obj_from_typed_reference(). After closing the store, the user should
     * not be able to use this reference anymore. */
    *reference = obj;
    *reference_sz = sizeof(P11PROV_OBJ);
}

P11PROV_OBJ *p11prov_obj_from_reference(const void *reference,
                                        size_t reference_sz)
{
    if (!reference || reference_sz != sizeof(P11PROV_OBJ)) {
        return NULL;
    }

    return (P11PROV_OBJ *)reference;
}

void *p11prov_obj_from_typed_reference(const void *reference,
                                       size_t reference_sz,
                                       CK_KEY_TYPE key_type)
{
    P11PROV_OBJ *key;

    /* the contents of the reference is the address to our object */
    key = p11prov_obj_from_reference(reference, reference_sz);
    if (key) {
        CK_KEY_TYPE type = CK_UNAVAILABLE_INFORMATION;

        type = p11prov_obj_get_key_type(key);
        if (type == key_type) {
            /* add ref count */
            key = p11prov_obj_ref_no_cache(key);
        } else {
            key = NULL;
        }
    }

    return key;
}

CK_SLOT_ID p11prov_obj_get_slotid(P11PROV_OBJ *obj)
{
    if (obj) {
        return obj->slotid;
    }
    return CK_UNAVAILABLE_INFORMATION;
}

CK_OBJECT_HANDLE p11prov_obj_get_handle(P11PROV_OBJ *obj)
{
    if (obj) {
        if (obj->raf) {
            p11prov_obj_refresh(obj);
        }
        if (obj->cached != CK_INVALID_HANDLE) {
            return obj->cached;
        }
        if (obj->handle == CK_P11PROV_IMPORTED_HANDLE) {
            /* This was a mock imported public key,
             * but we are being asked for the actual key handle
             * so it means we need to actually add the key to the
             * session in order to be able to perform operations
             * with the token */
            int rv;

            rv = p11prov_obj_store_public_key(obj);
            if (rv != CKR_OK) {
                return CK_INVALID_HANDLE;
            }
        }
        return obj->handle;
    }
    return CK_INVALID_HANDLE;
}

CK_OBJECT_CLASS p11prov_obj_get_class(P11PROV_OBJ *obj)
{
    if (obj) {
        return obj->class;
    }
    return CK_UNAVAILABLE_INFORMATION;
}

CK_ATTRIBUTE *p11prov_obj_get_attr(P11PROV_OBJ *obj, CK_ATTRIBUTE_TYPE type)
{
    if (!obj) {
        return NULL;
    }

    for (int i = 0; i < obj->numattrs; i++) {
        if (obj->attrs[i].type == type) {
            return &obj->attrs[i];
        }
    }

    return NULL;
}

bool p11prov_obj_get_bool(P11PROV_OBJ *obj, CK_ATTRIBUTE_TYPE type, bool def)
{
    CK_ATTRIBUTE *attr = NULL;

    if (!obj) {
        return def;
    }

    for (int i = 0; i < obj->numattrs; i++) {
        if (obj->attrs[i].type == type) {
            attr = &obj->attrs[i];
        }
    }

    if (!attr || !attr->pValue) {
        return def;
    }

    if (attr->ulValueLen == sizeof(CK_BBOOL)) {
        if (*((CK_BBOOL *)attr->pValue) == CK_FALSE) {
            return false;
        } else {
            return true;
        }
    }

    return def;
}

CK_KEY_TYPE p11prov_obj_get_key_type(P11PROV_OBJ *obj)
{
    if (obj) {
        switch (obj->class) {
        case CKO_PRIVATE_KEY:
        case CKO_PUBLIC_KEY:
        case CKO_DOMAIN_PARAMETERS:
        case CKO_SECRET_KEY:
            return obj->data.key.type;
        }
    }
    return CK_UNAVAILABLE_INFORMATION;
}

CK_ULONG p11prov_obj_get_key_bit_size(P11PROV_OBJ *obj)
{
    if (obj) {
        switch (obj->class) {
        case CKO_PRIVATE_KEY:
        case CKO_PUBLIC_KEY:
        case CKO_DOMAIN_PARAMETERS:
        case CKO_SECRET_KEY:
            return obj->data.key.bit_size;
        }
    }
    return CK_UNAVAILABLE_INFORMATION;
}

CK_ULONG p11prov_obj_get_key_size(P11PROV_OBJ *obj)
{
    if (obj) {
        switch (obj->class) {
        case CKO_PRIVATE_KEY:
        case CKO_PUBLIC_KEY:
        case CKO_DOMAIN_PARAMETERS:
        case CKO_SECRET_KEY:
            return obj->data.key.size;
        }
    }
    return CK_UNAVAILABLE_INFORMATION;
}

CK_ULONG p11prov_obj_get_key_param_set(P11PROV_OBJ *obj)
{
    if (obj) {
        switch (obj->class) {
        case CKO_PRIVATE_KEY:
        case CKO_PUBLIC_KEY:
        case CKO_DOMAIN_PARAMETERS:
            return obj->data.key.param_set;
        }
    }
    return CK_UNAVAILABLE_INFORMATION;
}

P11PROV_CTX *p11prov_obj_get_prov_ctx(P11PROV_OBJ *obj)
{
    if (!obj) {
        return NULL;
    }
    return obj->ctx;
}

const char *p11prov_obj_get_public_uri(P11PROV_OBJ *obj)
{
    if (!obj->public_uri) {
        obj->public_uri = p11prov_obj_to_uri(obj);
    }
    return obj->public_uri;
}

P11PROV_URI *p11prov_obj_get_refresh_uri(P11PROV_OBJ *obj)
{
    return obj->refresh_uri;
}

P11PROV_OBJ *p11prov_obj_get_associated(P11PROV_OBJ *obj)
{
    return obj->assoc_obj;
}
/* Get a pointer to the referenced session, if any */
P11PROV_SESSION *p11prov_obj_get_session_ref(P11PROV_OBJ *obj)
{
    return obj->ref_session;
}

CK_RV p11prov_obj_add_attr(P11PROV_OBJ *obj, CK_ATTRIBUTE *attr)
{
    CK_ATTRIBUTE *new_attrs;

    if (obj == NULL || attr == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    new_attrs =
        OPENSSL_realloc(obj->attrs, sizeof(CK_ATTRIBUTE) * (obj->numattrs + 1));
    if (new_attrs == NULL) {
        P11PROV_raise(obj->ctx, CKR_HOST_MEMORY,
                      "Failed to reallocate attributes for new attribute");
        return CKR_HOST_MEMORY;
    }
    obj->attrs = new_attrs;

    obj->attrs[obj->numattrs] = *attr;
    obj->numattrs++;

    return CKR_OK;
}

void p11prov_obj_set_associated(P11PROV_OBJ *obj, P11PROV_OBJ *assoc)
{
    if (obj == NULL) {
        return;
    }

    p11prov_obj_free(obj->assoc_obj);
    obj->assoc_obj = NULL;

    if (assoc == NULL) {
        return;
    }

    obj->assoc_obj = p11prov_obj_ref_no_cache(assoc);
}

/* reference a session and store it on the object so the session
 * cannot be closed while the object is still alive */
void p11prov_obj_set_session_ref(P11PROV_OBJ *obj, P11PROV_SESSION *session)
{
    p11prov_session_ref(session);
    obj->ref_session = session;
}

void p11prov_obj_set_class(P11PROV_OBJ *obj, CK_OBJECT_CLASS class)
{
    /* allow this only for mock objects */
    if (obj->handle == CK_P11PROV_IMPORTED_HANDLE) {
        obj->class = class;
    }
}

void p11prov_obj_set_key_type(P11PROV_OBJ *obj, CK_KEY_TYPE type)
{
    /* allow this only for mock objects */
    if (obj->handle == CK_P11PROV_IMPORTED_HANDLE) {
        obj->data.key.type = type;
    }
}

void p11prov_obj_set_key_params(P11PROV_OBJ *obj, CK_ULONG param_set)
{
    /* allow this only for mock objects */
    if (obj->handle == CK_P11PROV_IMPORTED_HANDLE) {
        obj->data.key.param_set = param_set;
    }
}
