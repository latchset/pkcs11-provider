/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "obj/internal.h"
#include "platform/endian.h"

struct pool_find_ctx {
    CK_KEY_TYPE type;
    CK_OBJECT_CLASS class;
    CK_ULONG key_size;
    CK_ULONG bit_size;
    CK_ULONG param_set;
    CK_ATTRIBUTE attrs[MAX_FIND_ATTRS_SIZE];
    int numattrs;
    P11PROV_OBJ *found;
};

static bool pool_find_callback(void *pctx, P11PROV_OBJ_POOL *pool)
{
    struct pool_find_ctx *ctx = (struct pool_find_ctx *)pctx;

    ctx->found =
        p11prov_obj_pool_find(pool, ctx->class, ctx->type, ctx->param_set,
                              ctx->bit_size, ctx->attrs, ctx->numattrs);

    return (ctx->found != NULL);
}

CK_RV p11prov_obj_copy_key_data(P11PROV_OBJ *dst, P11PROV_OBJ *src)
{
    CK_RV rv;

    P11PROV_debug("duplicating obj key (dst=%p, src=%p, handle=%lu, "
                  "slotid=%lu, raf=%d, numattrs=%d)",
                  dst, src, src->handle, src->slotid, src->raf, src->numattrs);

    /* we don't overwrite real key objects */
    if (dst->poolid != -1) {
        rv = CKR_GENERAL_ERROR;
        P11PROV_raise(src->ctx, rv, "Invalid destination object");
        return CKR_GENERAL_ERROR;
    }

    dst->slotid = src->slotid;
    /* ensure the source handle is valid (this may refresh the object or
     * store a mock one), but use the no_cache variant as we want a handle
     * to the real object here, not the ephemeral cache copy */
    dst->handle = p11prov_obj_get_handle_no_cache(src);
    if (src->ref_obj) {
        /* borrow the handle from the same owner as the source */
        dst->ref_obj = p11prov_obj_ref_no_cache(src->ref_obj);
    } else if (src->owns_key) {
        /* keep the owner alive as the handle is destroyed on its free */
        dst->ref_obj = p11prov_obj_ref_no_cache(src);
    }
    dst->class = src->class;
    dst->cka_copyable = src->cka_copyable;
    dst->cka_token = src->cka_token;
    dst->data.key = src->data.key;
    dst->get_template = src->get_template;
    dst->free_template = src->free_template;
    dst->get_find_attrs = src->get_find_attrs;

    /* Free existing attributes if any */
    for (int i = 0; i < dst->numattrs; i++) {
        OPENSSL_free(dst->attrs[i].pValue);
    }
    OPENSSL_free(dst->attrs);

    dst->attrs = OPENSSL_zalloc(sizeof(CK_ATTRIBUTE) * src->numattrs);
    if (!dst->attrs) {
        rv = CKR_HOST_MEMORY;
        P11PROV_raise(dst->ctx, rv, "Failed allocation");
        return rv;
    }
    dst->numattrs = 0;
    for (int i = 0; i < src->numattrs; i++) {
        rv = p11prov_copy_attr(&dst->attrs[i], &src->attrs[i]);
        if (rv != CKR_OK) {
            rv = CKR_HOST_MEMORY;
            P11PROV_raise(dst->ctx, rv, "Failed attr copy");
            return rv;
        }
        dst->numattrs++;
    }

    rv = obj_add_to_pool(dst);
    if (rv != CKR_OK) {
        /* Perhaps we should fail here, but failing to add the object on the
         * pool id will not prevent its usage, so just emit a debug line */
        P11PROV_debug("Failed to add key duplicate to pool id");
    }

    return CKR_OK;
}

static CK_RV fix_ec_key_import(P11PROV_OBJ *key, int allocattrs)
{
    CK_RV ret = CKR_GENERAL_ERROR;
    CK_ATTRIBUTE *pub;
    ASN1_OCTET_STRING *oct = NULL;
    unsigned char *der = NULL;
    int len;

    if (key->numattrs >= allocattrs) {
        P11PROV_raise(key->ctx, ret, "Too many attributes?? %d >= %d",
                      key->numattrs, allocattrs);
        goto done;
    }

    pub = p11prov_obj_get_attr(key, CKA_P11PROV_PUB_KEY);
    if (!pub) {
        ret = CKR_KEY_INDIGESTIBLE;
        P11PROV_raise(key->ctx, ret, "No public key found");
        goto done;
    }

    oct = ASN1_OCTET_STRING_new();
    if (!oct) {
        goto done;
    }
    if (!ASN1_STRING_set(oct, pub->pValue, pub->ulValueLen)) {
        goto done;
    }
    /* FIXME: should we set just bytes for Edwards and Montgomery keys? */
    len = i2d_ASN1_OCTET_STRING(oct, &der);
    if (len < 0) {
        ret = CKR_KEY_INDIGESTIBLE;
        P11PROV_raise(key->ctx, ret, "Failure to encode EC point to DER");
        goto done;
    }
    key->attrs[key->numattrs].type = CKA_EC_POINT;
    key->attrs[key->numattrs].pValue = der;
    der = NULL;
    key->attrs[key->numattrs].ulValueLen = len;
    key->numattrs++;

    P11PROV_debug("fixing EC key %p import", key);

    ret = CKR_OK;

done:
    OPENSSL_free(der);
    ASN1_OCTET_STRING_free(oct);

    return ret;
}

static CK_RV p11prov_obj_import_public_key(P11PROV_OBJ *key,
                                           const OSSL_PARAM params[])
{
    P11PROV_CTX *ctx;
    struct pool_find_ctx findctx = {
        .type = key->data.key.type,
        .class = CKO_PUBLIC_KEY,
        .bit_size = 0,
        .param_set = key->data.key.param_set,
        .attrs = { { 0 } },
        .numattrs = 0,
        .found = NULL,
    };
    int allocattrs = 0;
    CK_RV rv;

    ctx = p11prov_obj_get_prov_ctx(key);
    if (!ctx) {
        return CKR_GENERAL_ERROR;
    }

    P11PROV_debug("obj import of public key %p (type: %08lx)", key,
                  findctx.type);
    rv = p11prov_obj_get_find_attrs(key, findctx.class, params, findctx.attrs,
                                    &findctx.numattrs);
    if (rv != CKR_OK) {
        goto done;
    }
    findctx.key_size = p11prov_obj_get_key_size(key);
    findctx.bit_size = p11prov_obj_get_key_bit_size(key);

    allocattrs = findctx.numattrs;
    switch (findctx.type) {
    case CKK_EC:
    case CKK_EC_EDWARDS:
    case CKK_EC_MONTGOMERY:
        allocattrs += 1;
        break;
    }

    /* A common case with openssl is the request to import a key we already
     * actually have on the token. This happens because OpenSSL is greedy
     * and tries to export keys to its default provider before it even knows
     * what kind of operation it needs to do. Sometimes the operation ends up
     * being something that needs to be performed on the token. So try to see
     * if we already have this key */
    rv = p11prov_slot_find_obj_pool(ctx, pool_find_callback, &findctx);
    if (rv != CKR_OK) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR, "Failed to search pools");
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    if (findctx.found) {
        rv = p11prov_obj_copy_key_data(key, findctx.found);
        goto done;
    }

    /*
     * FIXME:
     * For things like ECDH we can get away with a mock object that just holds
     * data for now, but is not backed by an actual handle and key in the token.
     * Once this is not sufficient, we'll probably need to change functions to
     * pass in a valid session when requesting a handle from an object, so that
     * the key can be imported on the fly in the correct slot at the time the
     * operation needs to be performed.
     */
    P11PROV_debug("public key %p not found in the pool - using mock", key);

    /* move missing data */
    key->data.key.size = findctx.key_size;
    key->data.key.bit_size = findctx.bit_size;
    key->attrs = OPENSSL_malloc(sizeof(CK_ATTRIBUTE) * allocattrs);
    if (!key->attrs) {
        P11PROV_raise(key->ctx, CKR_HOST_MEMORY, "Failed allocation");
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    for (int i = 0; i < findctx.numattrs; i++) {
        key->attrs[i] = findctx.attrs[i];
        findctx.attrs[i].pValue = NULL;
    }
    key->numattrs = findctx.numattrs;
    findctx.numattrs = 0;

    switch (findctx.type) {
    case CKK_EC:
    case CKK_EC_EDWARDS:
    case CKK_EC_MONTGOMERY:
        rv = fix_ec_key_import(key, allocattrs);
        break;
    }

done:
    for (int i = 0; i < findctx.numattrs; i++) {
        OPENSSL_free(findctx.attrs[i].pValue);
    }
    return rv;
}

static CK_RV store_key(P11PROV_OBJ *key, P11PROV_SESSION *in_session,
                       CK_ATTRIBUTE *tmpl, int tmpl_cnt)
{
    P11PROV_SLOTS_CTX *slots = NULL;
    CK_SLOT_ID slot = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SESSION *session = in_session;
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_RV rv;

    if (!in_session) {
        slots = p11prov_ctx_get_slots(key->ctx);
        if (!slots) {
            return CKR_GENERAL_ERROR;
        }

        slot = p11prov_get_default_slot(slots);
        if (slot == CK_UNAVAILABLE_INFORMATION) {
            return CKR_GENERAL_ERROR;
        }

        rv = p11prov_get_session(key->ctx, &slot, NULL, key->refresh_uri,
                                 CK_UNAVAILABLE_INFORMATION, NULL, NULL, false,
                                 true, &session);
        if (rv != CKR_OK) {
            goto done;
        }
        sess = p11prov_session_handle(session);
    } else {
        CK_SESSION_INFO session_info;
        CK_BBOOL val_token = CK_FALSE;

        sess = p11prov_session_handle(session);
        rv = p11prov_GetSessionInfo(key->ctx, sess, &session_info);
        if (rv != CKR_OK) {
            goto done;
        }
        slot = session_info.slotID;

        for (int i = 0; i < tmpl_cnt; i++) {
            if (tmpl[i].type == CKA_TOKEN) {
                val_token = *(CK_BBOOL *)tmpl[i].pValue;
                break;
            }
        }

        if (((session_info.flags & CKF_RW_SESSION) == 0)
            && val_token == CK_TRUE) {
            P11PROV_debug("Invalid read only session for token key request");
            rv = CKR_SESSION_HANDLE_INVALID;
            goto done;
        }
    }

    P11PROV_debug("Creating key on session %lu", sess);
    rv = p11prov_CreateObject(key->ctx, sess, tmpl, tmpl_cnt, &key->handle);
    if (rv != CKR_OK) {
        goto done;
    }

    key->slotid = slot;

    rv = CKR_OK;

done:
    if (rv == CKR_OK) {
        /* this is a real object now, add it to the pool, but do not
         * fail if the operation goes haywire for some reason */
        (void)obj_add_to_pool(key);

        /* we just created an ephemeral key on this session, ensure the
         * session is not closed until the key goes away */
        p11prov_obj_set_session_ref(key, session);
    }
    if (in_session != session) {
        p11prov_return_session(session);
    }
    return rv;
}

CK_RV p11prov_pkeyinfo_to_pubkey(CK_ATTRIBUTE *pkeyinfo, CK_ATTRIBUTE *attr)
{
    X509_PUBKEY *pubkey = NULL;
    const unsigned char *val;
    long len;
    const unsigned char *pk;
    int pklen;
    CK_RV rv = CKR_GENERAL_ERROR;

    val = pkeyinfo->pValue;
    len = pkeyinfo->ulValueLen;
    pubkey = d2i_X509_PUBKEY(NULL, &val, len);
    if (!pubkey) {
        return CKR_KEY_INDIGESTIBLE;
    }

    if (X509_PUBKEY_get0_param(NULL, &pk, &pklen, NULL, pubkey) != 1) {
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    /* EC point/ML(-DSA/KEM) key as OpenSSL handles it */
    attr->pValue = OPENSSL_memdup(pk, pklen);
    if (!attr->pValue) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    attr->ulValueLen = pklen;

    rv = CKR_OK;
done:
    X509_PUBKEY_free(pubkey);
    return rv;
}

static CK_RV pub_from_priv_attrs(P11PROV_OBJ *key)
{
    CK_ATTRIBUTE *pkeyinfo;
    CK_ATTRIBUTE *add_attrs;
    CK_ATTRIBUTE *params;
    CK_RV rv = CKR_GENERAL_ERROR;

    if (key->assoc_obj->class != CKO_PRIVATE_KEY) {
        rv = CKR_OBJECT_HANDLE_INVALID;
        P11PROV_raise(key->ctx, rv, "Expected associated private key");
        return rv;
    }

    /* ensure we have the proper class now that all
     * attributes are in place */
    key->class = CKO_PUBLIC_KEY;
    key->cka_token = false;

    pkeyinfo = p11prov_obj_get_attr(key->assoc_obj, CKA_PUBLIC_KEY_INFO);
    if (!pkeyinfo) {
        return CKR_GENERAL_ERROR;
    }

    /* max 3 attributes for each key type */
    add_attrs =
        OPENSSL_realloc(key->attrs, sizeof(CK_ATTRIBUTE) * (key->numattrs + 3));
    if (!add_attrs) {
        return CKR_HOST_MEMORY;
    }
    key->attrs = add_attrs;

    switch (key->data.key.type) {
    case CKK_RSA:
        rv = rsa_pkeyinfo_to_attrs(pkeyinfo, &key->attrs[key->numattrs]);
        if (rv != CKR_OK) {
            break;
        }
        key->numattrs += 2;
        break;
    case CKK_EC:
    case CKK_EC_EDWARDS:
    case CKK_EC_MONTGOMERY:
        /* ec params */
        params = p11prov_obj_get_attr(key->assoc_obj, CKA_EC_PARAMS);
        if (params) {
            rv = p11prov_copy_attr(&key->attrs[key->numattrs], params);
        }
        if (rv != CKR_OK) {
            break;
        }
        key->numattrs++;
        key->attrs[key->numattrs].type = CKA_P11PROV_PUB_KEY;
        rv = p11prov_pkeyinfo_to_pubkey(pkeyinfo, &key->attrs[key->numattrs]);
        if (rv != CKR_OK) {
            break;
        }
        key->numattrs++;
        /* Finally convert plain point to encoded point */
        rv = fix_ec_key_import(key, key->numattrs + 1);
        break;
    case CKK_ML_DSA:
    case CKK_ML_KEM:
    case CKK_SLH_DSA:
        /* param set */
        params = p11prov_obj_get_attr(key->assoc_obj, CKA_PARAMETER_SET);
        if (params) {
            rv = p11prov_copy_attr(&key->attrs[key->numattrs], params);
        }
        if (rv != CKR_OK) {
            break;
        }
        key->numattrs++;
        key->attrs[key->numattrs].type = CKA_VALUE;
        rv = p11prov_pkeyinfo_to_pubkey(pkeyinfo, &key->attrs[key->numattrs]);
        if (rv != CKR_OK) {
            break;
        }
        key->numattrs++;
        break;

    default:
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR,
                      "Unsupported key type: %08lx, should NOT happen",
                      key->data.key.type);
        rv = CKR_GENERAL_ERROR;
    }

    return rv;
}

CK_RV p11prov_obj_store_public_key(P11PROV_OBJ *key)
{
    CK_ATTRIBUTE template[P11PROV_PUBKEY_MAX_TEMPLATE_SIZE];
    int tmpl_cnt;
    int rv;

    P11PROV_debug("Store imported public key=%p", key);

    if (key->class == CKO_P11PROV_PUB_FROM_PRIV_KEY) {
        rv = pub_from_priv_attrs(key);
        if (rv != CKR_OK) {
            P11PROV_raise(key->ctx, rv, "Failed to import pub key info");
            return rv;
        }
    }

    if (key->class != CKO_PUBLIC_KEY) {
        rv = CKR_OBJECT_HANDLE_INVALID;
        P11PROV_raise(key->ctx, rv, "Invalid key type");
        return rv;
    }

    tmpl_cnt = p11prov_obj_get_template(key, key->class, NULL, template);
    if (tmpl_cnt <= 0) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR,
                      "Unsupported key type: %08lx, should NOT happen",
                      key->data.key.type);
        return CKR_GENERAL_ERROR;
    }

    rv = store_key(key, NULL, template, tmpl_cnt);

    if (rv == CKR_OK) {
        /* destroy the session object when key is freed */
        key->owns_key = true;
    }

    return rv;
}

CK_RV p11prov_obj_re_store_key(P11PROV_OBJ *key)
{
    if (key->class == CKO_SECRET_KEY) {
        P11PROV_OBJ *stored_key = NULL;
        CK_RV rv;

        CK_ATTRIBUTE *value = p11prov_obj_get_attr(key, CKA_VALUE);
        if (!value || !value->pValue) {
            P11PROV_debug("Missing value");
            return CKR_GENERAL_ERROR;
        }

        rv = p11prov_store_symmetric_key(
            key->ctx, key->ref_session, key->data.key.type, true, value->pValue,
            value->ulValueLen, key->usage, &stored_key);
        if (rv == CKR_OK) {
            key->handle = stored_key->handle;
            key->slotid = stored_key->slotid;
            p11prov_obj_set_session_ref(key, stored_key->ref_session);
            p11prov_obj_free(stored_key);
        }

        return rv;
    } else {
        return p11prov_obj_store_public_key(key);
    }
}

static CK_RV p11prov_obj_import_private_key(P11PROV_OBJ *key,
                                            const OSSL_PARAM params[])
{
    P11PROV_CTX *ctx;
    struct pool_find_ctx findctx = {
        .type = key->data.key.type,
        .class = CKO_PRIVATE_KEY,
        .param_set = key->data.key.param_set,
        .attrs = { { 0 } },
        .numattrs = 0,
        .found = NULL,
    };
    CK_ATTRIBUTE template[P11PROV_PRIVKEY_MAX_TEMPLATE_SIZE];
    int tmpl_cnt = 0;
    int allocattrs;
    CK_RV rv;

    ctx = p11prov_obj_get_prov_ctx(key);
    if (!ctx) {
        return CKR_GENERAL_ERROR;
    }

    P11PROV_debug("obj import of private key %p (type: %08lx)", key,
                  findctx.type);
    rv = p11prov_obj_get_find_attrs(key, findctx.class, params, findctx.attrs,
                                    &findctx.numattrs);
    if (rv != CKR_OK) {
        goto done;
    }
    findctx.key_size = p11prov_obj_get_key_size(key);
    findctx.bit_size = p11prov_obj_get_key_bit_size(key);

    /* The only case for private keys is an application loading a key from
     * a file or other mean and then asking (explicitly or implicitly) a
     * pkcs11-provider mechanism to use it. There is no other case because
     * tokens do not allow to export private keys.
     *
     * However we may have had the request to load this key before so we
     * still need to check if we have previously uploaded this key as a
     * session key before. If not we will compute a hash of the private
     * key to store in CKA_ID for future lockup and store it in the token
     * on the long lived login session.
     */
    rv = p11prov_slot_find_obj_pool(ctx, pool_find_callback, &findctx);
    if (rv != CKR_OK) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR, "Failed to search pools");
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    if (findctx.found) {
        rv = p11prov_obj_copy_key_data(key, findctx.found);
        goto done;
    }

    /*
     * No cached object found, create a session key on the login session so
     * that its handle will live long enough for multiple operations.
     */

    key->data.key.size = findctx.key_size;
    key->data.key.bit_size = findctx.bit_size;
    allocattrs = findctx.numattrs;
    key->attrs = OPENSSL_zalloc(sizeof(CK_ATTRIBUTE) * allocattrs);
    if (!key->attrs) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    key->numattrs = 0;
    for (int i = 0; i < findctx.numattrs; i++) {
        rv = p11prov_copy_attr(&key->attrs[i], &findctx.attrs[i]);
        if (rv != CKR_OK) {
            rv = CKR_HOST_MEMORY;
            P11PROV_raise(key->ctx, rv, "Failed attr copy");
            goto done;
        }
        key->numattrs++;
    }

    tmpl_cnt = p11prov_obj_get_template(key, findctx.class, params, template);
    if (tmpl_cnt <= 0) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rv = store_key(key, NULL, template, tmpl_cnt);
    if (rv != CKR_OK) {
        goto done;
    }

done:
    p11prov_obj_free_template(key, findctx.class, template, tmpl_cnt);
    for (int i = 0; i < findctx.numattrs; i++) {
        OPENSSL_free(findctx.attrs[i].pValue);
    }
    return rv;
}

static CK_RV import_ec_params(P11PROV_OBJ *key, const OSSL_PARAM params[])
{
    P11PROV_CTX *ctx;
    EC_GROUP *group = NULL;
    const char *curve_name = NULL;
    int curve_nid;
    unsigned char *ecparams = NULL;
    CK_ATTRIBUTE *cka_ec_params;
    CK_ATTRIBUTE *cka_nid;
    CK_ATTRIBUTE *cka_name;
    CK_ATTRIBUTE tmp;
    int add_attrs = 0;
    int len;
    CK_RV rv;

    ctx = p11prov_obj_get_prov_ctx(key);
    if (!ctx) {
        return CKR_GENERAL_ERROR;
    }

    group = EC_GROUP_new_from_params(params, p11prov_ctx_get_libctx(ctx), NULL);
    if (!group) {
        P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Unable to decode ec group");
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    curve_name = p11prov_ec_group_to_curve_name(group, &curve_nid);
    if (curve_name == NULL && curve_nid != NID_undef) {
        P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Unknown curve");
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    len = i2d_ECPKParameters(group, &ecparams);
    if (len < 0) {
        P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Failed to encode EC params");
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    cka_ec_params = p11prov_obj_get_attr(key, CKA_EC_PARAMS);
    if (!cka_ec_params) {
        add_attrs += 1;
    }

    cka_nid = p11prov_obj_get_attr(key, CKA_P11PROV_CURVE_NID);
    if (!cka_nid) {
        add_attrs += 1;
    }

    cka_name = p11prov_obj_get_attr(key, CKA_P11PROV_CURVE_NAME);
    if (!cka_name && curve_name) {
        add_attrs += 1;
    }

    if (add_attrs > 0) {
        void *tmp_ptr;
        tmp_ptr = OPENSSL_realloc(
            key->attrs, sizeof(CK_ATTRIBUTE) * (key->numattrs + add_attrs));
        if (!tmp_ptr) {
            rv = CKR_HOST_MEMORY;
            goto done;
        }
        key->attrs = tmp_ptr;
    }

    /* EC Params */
    if (cka_ec_params) {
        OPENSSL_free(cka_ec_params->pValue);
    } else {
        cka_ec_params = &key->attrs[key->numattrs];
        key->numattrs++;
    }
    cka_ec_params->type = CKA_EC_PARAMS;
    cka_ec_params->pValue = ecparams;
    ecparams = NULL;
    cka_ec_params->ulValueLen = len;

    /* Curve Nid */
    if (cka_nid) {
        OPENSSL_free(cka_nid->pValue);
    } else {
        cka_nid = &key->attrs[key->numattrs];
        key->numattrs++;
    }
    cka_nid->pValue = NULL;
    tmp.type = CKA_P11PROV_CURVE_NID;
    tmp.pValue = &curve_nid;
    tmp.ulValueLen = sizeof(curve_nid);
    rv = p11prov_copy_attr(cka_nid, &tmp);
    if (rv != CKR_OK) {
        goto done;
    }

    /* Curve name */
    if (cka_name) {
        OPENSSL_free(cka_name->pValue);
        cka_name->type = CK_UNAVAILABLE_INFORMATION;
        cka_name->pValue = NULL;
        cka_name->ulValueLen = 0;
    }
    if (curve_name) {
        if (!cka_name) {
            cka_name = &key->attrs[key->numattrs];
            key->numattrs++;
        }
        tmp.type = CKA_P11PROV_CURVE_NAME;
        tmp.pValue = (void *)curve_name;
        tmp.ulValueLen = strlen(curve_name) + 1;
        rv = p11prov_copy_attr(cka_name, &tmp);
        if (rv != CKR_OK) {
            goto done;
        }
    }

    /* This is geneally the first call when importing keys from OpenSSL,
     * so ensure the other common object parameters are correct as well */
    key->data.key.type = CKK_EC;
    key->data.key.bit_size = EC_GROUP_order_bits(group);
    key->data.key.size = (key->data.key.bit_size + 7) / 8;

done:
    OPENSSL_free(ecparams);
    EC_GROUP_free(group);
    return rv;
}

static CK_RV p11prov_obj_set_domain_params(P11PROV_OBJ *key,
                                           const OSSL_PARAM params[])
{
    switch (key->data.key.type) {
    case CKK_EC:
        /* EC_PARAMS */
        return import_ec_params(key, params);

    default:
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Unsupported key type: %08lx", key->data.key.type);
        return CKR_KEY_INDIGESTIBLE;
    }
}

CK_RV p11prov_obj_import_key(P11PROV_OBJ *key, const OSSL_PARAM params[])
{
    /* This operation available only on new mock objects, can't import over an
     * existing one */
    if (key->handle != CK_P11PROV_IMPORTED_HANDLE) {
        P11PROV_raise(key->ctx, CKR_ARGUMENTS_BAD, "Non empty object");
        return CKR_ARGUMENTS_BAD;
    }

    switch (key->class) {
    case CKO_PUBLIC_KEY:
        return p11prov_obj_import_public_key(key, params);
    case CKO_PRIVATE_KEY:
        return p11prov_obj_import_private_key(key, params);
    case CKO_DOMAIN_PARAMETERS:
        return p11prov_obj_set_domain_params(key, params);
    default:
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Invalid object class or key type");
        return CKR_KEY_INDIGESTIBLE;
    }
}

CK_RV p11prov_store_symmetric_key(P11PROV_CTX *provctx,
                                  P11PROV_SESSION *session,
                                  CK_KEY_TYPE key_type, bool session_key,
                                  const unsigned char *secret, size_t secretlen,
                                  CK_FLAGS usage, P11PROV_OBJ **ret)
{
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_BBOOL tokenobj = session_key ? CK_FALSE : CK_TRUE;
    P11PROV_OBJ *key = NULL;
    CK_RV rv;
    CK_ATTRIBUTE template[12] = {
        { CKA_TOKEN, &tokenobj, sizeof(tokenobj) },
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_VALUE, (void *)secret, secretlen },
        { 0 },
    };
    size_t tmax = sizeof(template) / sizeof(CK_ATTRIBUTE);
    size_t tsize = 4;

    P11PROV_debug("Creating secret key (%p[%zu]), flags: %lx", secret,
                  secretlen, usage);

    if (usage) {
        rv = p11prov_usage_to_template(template, &tsize, tmax, usage);
        if (rv != CKR_OK) {
            P11PROV_raise(provctx, rv, "Failed to set key usage");
            return CKR_GENERAL_ERROR;
        }
    } else {
        rv = CKR_ARGUMENTS_BAD;
        P11PROV_raise(provctx, rv, "No key usage specified");
        return CKR_GENERAL_ERROR;
    }

    key = p11prov_obj_new(provctx, CK_UNAVAILABLE_INFORMATION,
                          CK_P11PROV_IMPORTED_HANDLE, key_class);
    if (key == NULL) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    key->data.key.type = key_type;
    key->data.key.bit_size = secretlen * 8;
    key->data.key.size = secretlen;

    rv = store_key(key, session, template, tsize);
    if (rv != CKR_OK) {
        goto done;
    }

    *ret = key;
    rv = CKR_OK;

done:
    if (rv != CKR_OK) {
        p11prov_obj_free(key);
    }
    return rv;
}

#if SKEY_SUPPORT

P11PROV_OBJ *p11prov_obj_import_secret_key(P11PROV_CTX *ctx, CK_KEY_TYPE type,
                                           const unsigned char *keydata,
                                           size_t keylen)
{
    CK_RV rv = CKR_KEY_INDIGESTIBLE;
    P11PROV_OBJ *key = NULL;
    CK_FLAGS usage = CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY
                     | CKF_WRAP | CKF_UNWRAP | CKF_DERIVE;

    /* TODO: cache find, see other key types */

    rv = p11prov_store_symmetric_key(ctx, NULL, type, true, keydata, keylen,
                                     usage, &key);
    if (rv != CKR_OK) {
        P11PROV_raise(ctx, rv, "Failed to import");
        return NULL;
    }
    return key;
}

#endif /* SKEY_SUPPORT */
