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
        ret =
            p11prov_take_login_session(obj->ctx, obj->slotid, true, &_session);
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

static void destroy_owned_key(P11PROV_OBJ *obj)
{
    P11PROV_SESSION *session = NULL;
    CK_RV ret;

    if (!obj->owns_key) {
        return;
    }
    /* nothing to destroy if the key was never stored or was reset */
    if (obj->handle == CK_INVALID_HANDLE
        || obj->handle == CK_P11PROV_IMPORTED_HANDLE) {
        return;
    }

    ret = p11prov_try_session_ref(obj, CK_UNAVAILABLE_INFORMATION, false, false,
                                  &session);
    if (ret != CKR_OK) {
        P11PROV_debug("Failed to get session to destroy owned key. "
                      "Error %lx",
                      ret);
        return;
    }

    ret = p11prov_DestroyObject(obj->ctx, p11prov_session_handle(session),
                                obj->handle);
    if (ret != CKR_OK) {
        P11PROV_debug("Failed to destroy owned key. Error %lx", ret);
    }
    obj->handle = CK_INVALID_HANDLE;

    p11prov_return_session(session);
}

static void cache_key(P11PROV_OBJ *obj)
{
    P11PROV_SESSION *session = NULL;
    CK_BBOOL val_false = CK_FALSE;
    /* Cache as a session object.  Clear CKA_ID and give the copy a fixed
     * CKA_LABEL; otherwise it inherits the original id/label and, being a
     * separate object, is returned alongside the real key by id/label lookups
     * (e.g. a pkcs11: URI), breaking callers that expect a single match.  The
     * provider only refers to the copy by handle; the label keeps it
     * identifiable on the token. */
    CK_ATTRIBUTE template[] = {
        { CKA_TOKEN, &val_false, sizeof(val_false) },
        { CKA_ID, (CK_BYTE_PTR) "", 0 },
        { CKA_LABEL, (CK_BYTE_PTR) "Internal Session Only Copy",
          sizeof("Internal Session Only Copy") - 1 },
    };
    CK_SESSION_HANDLE sess;
    CK_OBJECT_HANDLE handle;
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

    handle = p11prov_obj_get_handle(obj);
    if (handle == CK_INVALID_HANDLE) {
        /* no point in proceeding here, nothing to "cache" */
        return;
    }

    /* caching is only an optimization, never trigger a login for it and
     * never leak errors to the caller */
    p11prov_set_error_mark(obj->ctx);

    ret = p11prov_take_login_session(obj->ctx, obj->slotid, true, &session);
    if (ret != CKR_OK || session == NULL) {
        P11PROV_debug("No usable login session for caching. Error %lx", ret);
        goto done;
    }

    /* If already cached, release and re-cache */
    destroy_key_cache(obj, session);

    sess = p11prov_session_handle(session);
    ret = p11prov_CopyObject(obj->ctx, sess, handle, template,
                             sizeof(template) / sizeof(template[0]),
                             &obj->cached);
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

done:
    p11prov_pop_error_to_mark(obj->ctx);
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

    if (obj->ref_obj) {
        /* re-borrow the handle from the owner */
        obj->handle = p11prov_obj_get_handle(obj->ref_obj);
        obj->raf = false;
        return;
    }

    if (obj->owns_key) {
        /* the key is not on the token anymore, as refresh happens on fork
         * where we fully reset the token sessions.
         * This means it needs to be stored again */
        ret = p11prov_obj_re_store_key(obj);
        if (ret != CKR_OK) {
            P11PROV_raise(obj->ctx, ret, "Failed to refresh stored object %p",
                          obj);
            return;
        }
        obj->raf = false;
        return;
    }

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
    obj->get_template = tmp->get_template;
    obj->free_template = tmp->free_template;
    obj->get_find_attrs = tmp->get_find_attrs;
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

    /* The associated object is refreshed on demand when its handle is
     * requested, doing it here could require a login (if it is a private
     * key) that is not needed for the current operation */

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

    /* stop being findable in the pool before destroying the handle */
    obj_rm_from_pool(obj);

    destroy_owned_key(obj);

    if (obj->ref_session) {
        p11prov_session_deref(obj->ref_session);
        obj->ref_session = NULL;
    }

    destroy_key_cache(obj, NULL);

    for (int i = 0; i < obj->numattrs; i++) {
        OPENSSL_clear_free(obj->attrs[i].pValue, obj->attrs[i].ulValueLen);
    }
    OPENSSL_free(obj->attrs);

    OPENSSL_free(obj->public_uri);
    p11prov_uri_free(obj->refresh_uri);

    p11prov_obj_free(obj->assoc_obj);
    p11prov_obj_free(obj->ref_obj);

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

CK_OBJECT_HANDLE p11prov_obj_get_handle_no_cache(P11PROV_OBJ *obj)
{
    if (!obj) {
        return CK_INVALID_HANDLE;
    }
    if (obj->raf) {
        p11prov_obj_refresh(obj);
    }
    /* we have a few mock object cases to handle */
    if (obj->handle == CK_P11PROV_IMPORTED_HANDLE) {
        int rv;

        /* if this is a synthetic public key,
         * first try to find if we have an actual key in the token.
         * if that fails, we store it like we do for imported keys.
         */
        if (obj->class == CKO_P11PROV_PUB_FROM_PRIV_KEY) {
            P11PROV_OBJ *priv, *pub;

            /* should never happen, but just in case */
            if (!obj->assoc_obj || obj->assoc_obj->class != CKO_PRIVATE_KEY) {
                return CK_INVALID_HANDLE;
            }

            /* search */
            priv = obj->assoc_obj;
            pub = p11prov_obj_find_associated(priv, CKO_PUBLIC_KEY);
            if (pub) {
                /* we found it, and the function re-associates this new
                 * public key with the private, in the future priv->pub
                 * requests will find the token key directly.
                 *
                 * We still need to handle code that references the mock
                 * object though, so we copy over the pub key data */
                rv = p11prov_obj_copy_key_data(obj, pub);
                p11prov_obj_free(pub);
                if (rv != CKR_OK) {
                    return CK_INVALID_HANDLE;
                }

                return obj->handle;
            }

            /* intentionally continue with the next step, which will
             * store a new public key session object on the token
             * from the info on the private key */
        }

        /* This was a mock imported public key,
         * but we are being asked for the actual key handle
         * so it means we need to actually add the key to the
         * session in order to be able to perform operations
         * with the token */
        rv = p11prov_obj_re_store_key(obj);
        if (rv != CKR_OK) {
            return CK_INVALID_HANDLE;
        }
    }
    return obj->handle;
}

CK_OBJECT_HANDLE p11prov_obj_get_handle(P11PROV_OBJ *obj)
{
    if (!obj) {
        return CK_INVALID_HANDLE;
    }
    if (obj->cached != CK_INVALID_HANDLE) {
        return obj->cached;
    }
    return p11prov_obj_get_handle_no_cache(obj);
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

CK_ATTRIBUTE *p11prov_obj_get_public_attr(P11PROV_OBJ *obj,
                                          CK_ATTRIBUTE_TYPE type)
{
    if (!obj) {
        return NULL;
    }

    for (int i = 0; i < obj->numattrs; i++) {
        if (obj->attrs[i].type == type) {
            return &obj->attrs[i];
        }
    }

    /* search public key if the private key does not have it */
    if (obj->class == CKO_PRIVATE_KEY) {
        P11PROV_OBJ *pubobj = p11prov_obj_find_associated(obj, CKO_PUBLIC_KEY);
        if (pubobj == NULL) {
            return NULL;
        }

        /* p11prov_obj_find_associated, associates the object with obj,
         * so it is ok to return a pointer into its array as the following
         * p11prov_obj_free() will just dereference our pointer, but the
         * object is still held alive by obj itself */
        for (int i = 0; i < pubobj->numattrs; i++) {
            if (pubobj->attrs[i].type == type) {
                return &pubobj->attrs[i];
            }
        }

        p11prov_obj_free(pubobj);
    }

    return NULL;
}

int p11prov_obj_get_template(P11PROV_OBJ *obj, CK_OBJECT_CLASS class,
                             const OSSL_PARAM *params, CK_ATTRIBUTE *template)
{
    if (!obj || !obj->get_template) {
        return -1;
    }
    return obj->get_template(obj, class, params, template);
}

void p11prov_obj_free_template(P11PROV_OBJ *obj, CK_OBJECT_CLASS class,
                               CK_ATTRIBUTE *template, int tmpl_cnt)
{
    if (obj && obj->free_template) {
        obj->free_template(obj, class, template, tmpl_cnt);
    }
}

CK_RV p11prov_obj_get_find_attrs(P11PROV_OBJ *obj, CK_OBJECT_CLASS class,
                                 const OSSL_PARAM *params,
                                 CK_ATTRIBUTE attrs[static MAX_FIND_ATTRS_SIZE],
                                 int *numattrs)
{
    if (!obj || !obj->get_find_attrs) {
        return CKR_ARGUMENTS_BAD;
    }
    return obj->get_find_attrs(obj, class, params, attrs, numattrs);
}

void p11prov_obj_set_get_find_attrs(
    P11PROV_OBJ *obj, p11prov_obj_get_find_attrs_fn get_find_attrs)
{
    if (obj->handle == CK_P11PROV_IMPORTED_HANDLE) {
        obj->get_find_attrs = get_find_attrs;
    }
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

static bool is_key(CK_OBJECT_CLASS class)
{
    switch (class) {
    case CKO_PRIVATE_KEY:
    case CKO_PUBLIC_KEY:
    case CKO_DOMAIN_PARAMETERS:
    case CKO_SECRET_KEY:
    case CKO_P11PROV_NEW_KEY:
    case CKO_P11PROV_PUB_FROM_PRIV_KEY:
        return true;
    default:
        return false;
    }
}

CK_KEY_TYPE p11prov_obj_get_key_type(P11PROV_OBJ *obj)
{
    if (obj && is_key(obj->class)) {
        return obj->data.key.type;
    }
    return CK_UNAVAILABLE_INFORMATION;
}

CK_ULONG p11prov_obj_get_key_bit_size(P11PROV_OBJ *obj)
{
    if (obj && is_key(obj->class)) {
        return obj->data.key.bit_size;
    }
    return CK_UNAVAILABLE_INFORMATION;
}

CK_ULONG p11prov_obj_get_key_size(P11PROV_OBJ *obj)
{
    if (obj && is_key(obj->class)) {
        return obj->data.key.size;
    }
    return CK_UNAVAILABLE_INFORMATION;
}

CK_ULONG p11prov_obj_get_key_param_set(P11PROV_OBJ *obj)
{
    if (obj && is_key(obj->class)) {
        return obj->data.key.param_set;
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
    if (obj->ref_session) {
        p11prov_session_deref(obj->ref_session);
    }
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

void p11prov_obj_set_get_template(P11PROV_OBJ *obj,
                                  p11prov_obj_get_template_fn get_template)
{
    if (obj->handle == CK_P11PROV_IMPORTED_HANDLE) {
        obj->get_template = get_template;
    }
}

void p11prov_obj_set_free_template(P11PROV_OBJ *obj,
                                   p11prov_obj_free_template_fn free_template)
{
    if (obj->handle == CK_P11PROV_IMPORTED_HANDLE) {
        obj->free_template = free_template;
    }
}

void p11prov_obj_set_key_params(P11PROV_OBJ *obj, CK_ULONG param_set)
{
    /* allow this only for mock objects */
    if (obj->handle == CK_P11PROV_IMPORTED_HANDLE) {
        obj->data.key.param_set = param_set;
    }
}

void p11prov_obj_set_key_bits(P11PROV_OBJ *obj, CK_ULONG key_bit_size,
                              CK_ULONG key_size)
{
    /* allow this only for mock objects */
    if (obj->handle == CK_P11PROV_IMPORTED_HANDLE) {
        obj->data.key.bit_size = key_bit_size;
        obj->data.key.size = key_size;
    }
}
