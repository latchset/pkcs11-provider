/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "kmgmt/internal.h"
#include "openssl/rand.h"

struct key_generator *p11prov_kmgmt_gen_init(void *provctx, CK_KEY_TYPE type,
                                             CK_MECHANISM_TYPE mech)
{
    struct key_generator *ctx;
    int ret;

    ret = p11prov_ctx_status(provctx);
    if (ret != CKR_OK) {
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(struct key_generator));
    if (ctx == NULL) {
        P11PROV_raise(provctx, CKR_HOST_MEMORY, "Failed to get key_generator");
        return NULL;
    }

    ctx->provctx = (P11PROV_CTX *)provctx;
    ctx->type = type;
    ctx->mechanism.mechanism = mech;

    return ctx;
}

int p11prov_kmgmt_gen_set_params(struct key_generator *ctx,
                                 const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    int ret;

    if (!ctx) {
        return RET_OSSL_ERR;
    }

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, P11PROV_PARAM_URI);
    if (p) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING) {
            return RET_OSSL_ERR;
        }
        if (!p->data || p->data_size == 0) {
            return RET_OSSL_ERR;
        }
        if (ctx->uri) {
            p11prov_uri_free(ctx->uri);
        }
        ctx->uri = p11prov_parse_uri(ctx->provctx, (const char *)p->data);
        if (!ctx->uri) {
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, P11PROV_PARAM_KEY_USAGE);
    if (p) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING) {
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_get_utf8_string(p, &ctx->key_usage, 0);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

CK_RV p11prov_kmgmt_gen_callback(void *cbarg)
{
    struct key_generator *ctx = (struct key_generator *)cbarg;
    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END };
    int data = 0;
    int ret;

    if (!ctx->cb_fn) {
        return CKR_OK;
    }

    params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &data);
    params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &data);

    ret = ctx->cb_fn(params, ctx->cb_arg);
    if (ret != RET_OSSL_OK) {
        return CKR_CANCEL;
    }

    return CKR_OK;
}

const CK_BBOOL val_true = CK_TRUE;
const CK_BBOOL val_false = CK_FALSE;

static void set_bool_val(CK_ATTRIBUTE *attr, bool val)
{
    if (val) {
        attr->pValue = DISCARD_CONST(&val_true);
    } else {
        attr->pValue = DISCARD_CONST(&val_false);
    }
}

static void common_key_usage_set_attrs(CK_ATTRIBUTE *template, int tsize,
                                       bool enc, bool sig, bool der, bool wrap)
{
    for (int i = 0; i < tsize; i++) {
        switch (template[i].type) {
        case CKA_ENCRYPT:
        case CKA_DECRYPT:
            set_bool_val(&template[i], enc);
            break;
        case CKA_VERIFY:
        case CKA_VERIFY_RECOVER:
        case CKA_SIGN:
        case CKA_SIGN_RECOVER:
            set_bool_val(&template[i], sig);
            break;
        case CKA_DERIVE:
            set_bool_val(&template[i], der);
            break;
        case CKA_WRAP:
        case CKA_UNWRAP:
            set_bool_val(&template[i], wrap);
            break;
        default:
            break;
        }
    }
}

/*
 * Takes a Key Usage string, which must be a space separated list of tokens.
 * The tokens are the Key usage flag names as defined in ISO/IEC 9594-8 (X.509)
 * Only the following tokens are recognized:
 *  - dataEncipherment
 *  - digitalSignature
 *  - keyAgreement
 *  - keyEncipherment
 * uses: Table 25 from pkcs#11 3.1 spec for mappings for public keys
 * and an analogous mapping for private keys
 */
static CK_RV common_key_usage_to_tmpl(const char *key_usage,
                                      CK_ATTRIBUTE *pubtmpl,
                                      CK_ATTRIBUTE *privtmpl, int pubtsize,
                                      int privtsize)
{
    const char *str = NULL;
    size_t len = 0;
    bool enc = false;
    bool sig = false;
    bool der = false;
    bool wrap = false;

    if (key_usage == NULL) {
        /* leave defaults as set by templates */
        return CKR_OK;
    }

    str = key_usage;
    len = strlen(key_usage);
    while (str) {
        const char *tok = str;
        size_t toklen = len;
        const char *p = strchr(str, ' ');
        if (p) {
            toklen = p - str;
            len -= toklen + 1;
            p += 1;
        }
        str = p;
        if (strncmp(tok, "dataEncipherment", toklen) == 0) {
            enc = true;
        } else if (strncmp(tok, "digitalSignature", toklen) == 0) {
            sig = true;
        } else if (strncmp(tok, "keyAgreement", toklen) == 0) {
            der = true;
        } else if (strncmp(tok, "keyEncipherment", toklen) == 0) {
            wrap = true;
        } else {
            return CKR_ARGUMENTS_BAD;
        }
    }

    common_key_usage_set_attrs(pubtmpl, pubtsize, enc, sig, der, wrap);
    common_key_usage_set_attrs(privtmpl, privtsize, enc, sig, der, wrap);

    return CKR_OK;
}

int p11prov_kmgmt_gen(struct key_generator *ctx, CK_ATTRIBUTE *pubkey_template,
                      CK_ATTRIBUTE *privkey_template, int pubtsize,
                      int privtsize, OSSL_CALLBACK *cb_fn, void *cb_arg,
                      void **key)
{
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_BYTE id[16];
    CK_OBJECT_HANDLE privkey;
    CK_OBJECT_HANDLE pubkey;
    P11PROV_SESSION *session = NULL;
    CK_SESSION_HANDLE sh;
    P11PROV_OBJ *pub_key = NULL;
    P11PROV_OBJ *priv_key = NULL;
    CK_ATTRIBUTE cka_id = { 0 };
    CK_ATTRIBUTE label = { 0 };
    CK_RV ret;

    ret = common_key_usage_to_tmpl(ctx->key_usage, pubkey_template,
                                   privkey_template, pubtsize, privtsize);
    if (ret != CKR_OK) {
        P11PROV_raise(ctx->provctx, ret, "Failed to map Key Usage");
        return ret;
    }

    if (ctx->uri) {
        cka_id = p11prov_uri_get_id(ctx->uri);
        label = p11prov_uri_get_label(ctx->uri);
    }

    ret = p11prov_get_session(ctx->provctx, &slotid, NULL, ctx->uri,
                              ctx->mechanism.mechanism, NULL, NULL, true, true,
                              &session);
    if (ret != CKR_OK) {
        return ret;
    }

    if (cb_fn) {
        ctx->cb_fn = cb_fn;
        ctx->cb_arg = cb_arg;
        p11prov_session_set_callback(session, p11prov_kmgmt_gen_callback, ctx);
    }

    sh = p11prov_session_handle(session);

    if (cka_id.ulValueLen == 0) {
        int err = RET_OSSL_ERR;
        /* generate unique id for the key */
        err = RAND_bytes_ex(p11prov_ctx_get_libctx(ctx->provctx), id,
                            sizeof(id), 0);
        if (err != RET_OSSL_OK) {
            ret = CKR_GENERAL_ERROR;
            P11PROV_raise(ctx->provctx, ret, "Failed to source random buffer");
            goto done;
        }
        cka_id.type = CKA_ID;
        cka_id.pValue = id;
        cka_id.ulValueLen = 16;
    }
    pubkey_template[pubtsize] = cka_id;
    pubtsize++;
    privkey_template[privtsize] = cka_id;
    privtsize++;
    if (label.ulValueLen != 0) {
        pubkey_template[pubtsize] = label;
        pubtsize++;
        privkey_template[privtsize] = label;
        privtsize++;
    }

    ret = p11prov_GenerateKeyPair(ctx->provctx, sh, &ctx->mechanism,
                                  pubkey_template, pubtsize, privkey_template,
                                  privtsize, &pubkey, &privkey);
    if (ret != CKR_OK) {
        goto done;
    }

    ret = p11prov_obj_from_handle(ctx->provctx, session, pubkey, &pub_key);
    if (ret != CKR_OK) {
        goto done;
    }

    ret = p11prov_obj_from_handle(ctx->provctx, session, privkey, &priv_key);
    if (ret != CKR_OK) {
        goto done;
    }

    /* set the public key object as associated object of the private key,
     * this way a public key can always be found from the private key and
     * operations that assume an EVP_PKEY represent both can find what
     * they need.
     * This operation takes a reference so we can safely free pub_key */
    p11prov_obj_set_associated(priv_key, pub_key);

done:
    if (ret != CKR_OK) {
        p11prov_obj_free(priv_key);
        priv_key = NULL;
    }
    p11prov_return_session(session);
    p11prov_obj_free(pub_key);
    *key = priv_key;
    return ret;
}

int p11prov_kmgmt_match(const void *keydata1, const void *keydata2,
                        CK_KEY_TYPE type, int selection)
{
    P11PROV_OBJ *key1 = (P11PROV_OBJ *)keydata1;
    P11PROV_OBJ *key2 = (P11PROV_OBJ *)keydata2;
    int cmp_type = OBJ_CMP_KEY_TYPE;

    P11PROV_debug("key (type: %ld) match %p %p %d", type, keydata1, keydata2,
                  selection);

    if (key1 == key2) {
        return RET_OSSL_OK;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        cmp_type |= OBJ_CMP_KEY_PUBLIC;
    }
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        cmp_type |= OBJ_CMP_KEY_PRIVATE;
    }

    return p11prov_obj_key_cmp(key1, key2, type, cmp_type);
}

#define DFLT_DIGEST "SHA256"

int p11prov_kmgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ret;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST);
    if (p) {
        ret = OSSL_PARAM_set_utf8_string(p, DFLT_DIGEST);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

void p11prov_kmgmt_gen_cleanup(struct key_generator *ctx)
{
    P11PROV_debug("kmgmt gen_cleanup %p", ctx);
    OPENSSL_free(ctx->key_usage);
    p11prov_uri_free(ctx->uri);
    OPENSSL_clear_free(ctx, sizeof(struct key_generator));
}

void *p11prov_kmgmt_new(void *provctx, CK_KEY_TYPE type)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_OBJ *key;
    CK_RV ret;

    ret = p11prov_ctx_status(ctx);
    if (ret != CKR_OK) {
        return NULL;
    }

    key =
        p11prov_obj_new(provctx, CK_UNAVAILABLE_INFORMATION,
                        CK_P11PROV_IMPORTED_HANDLE, CK_UNAVAILABLE_INFORMATION);
    if (key) {
        p11prov_obj_set_key_type(key, type);
    }

    return key;
}

void p11prov_kmgmt_free(void *key)
{
    P11PROV_debug("Free key %p (type %ld)", key, p11prov_obj_get_key_type(key));
    p11prov_obj_free((P11PROV_OBJ *)key);
}

void *p11prov_kmgmt_load(const void *ref, size_t ref_sz, CK_KEY_TYPE type)
{
    P11PROV_debug("key (type: %ld) load %p, %ld", type, ref, ref_sz);
    return p11prov_obj_from_typed_reference(ref, ref_sz, type);
}

int p11prov_kmgmt_has(const void *keydata, int selection)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;

    P11PROV_debug("key has %p %d", key, selection);

    if (!key) {
        return RET_OSSL_ERR;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (p11prov_obj_get_class(key) != CKO_PRIVATE_KEY) {
            return RET_OSSL_ERR;
        }
    }

    /* We always return OK when asked for a PUBLIC KEY, even if we only have a
     * private key, as we can try to fetch the associated public key as needed
     * if asked for an export (main reason to do this), or other operations */

    return RET_OSSL_OK;
}

int p11prov_kmgmt_import(CK_KEY_TYPE type, CK_ULONG param_set,
                         const char *priv_param_name, void *keydata,
                         int selection, const OSSL_PARAM params[])
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    CK_OBJECT_CLASS class = CK_UNAVAILABLE_INFORMATION;
    CK_RV rv;

    P11PROV_debug("key %p (type: %ld) import", key, type);

    if (!key) {
        return RET_OSSL_ERR;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        class = CKO_PRIVATE_KEY;
    } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        class = CKO_PUBLIC_KEY;
    } else if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
        P11PROV_debug("import of domain parameters is only for EC keys");
        /* There are no Domain parameters associated with an
         * ECX or RSA, etc.. key in OpenSSL, so there is nothing really
         * we can import */
        if (type != CKK_EC) {
            return RET_OSSL_ERR;
        }
        class = CKO_DOMAIN_PARAMETERS;
    } else {
        return RET_OSSL_ERR;
    }

    /* NOTE: the following is needed because of bug:
     * https://github.com/openssl/openssl/issues/21596
     * it can be removed once we can depend on a recent enough version
     * after it is fixed */
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        const OSSL_PARAM *p;
        p = OSSL_PARAM_locate_const(params, priv_param_name);
        if (!p) {
            /* not really a private key */
            class = CKO_PUBLIC_KEY;
        }
    }

    p11prov_obj_set_class(key, class);
    /* Check that the key type (which is set at object creation type
     * by p11prov_kmgmt_new() matches the source key. We can't check
     * before the class is set because p11prov_obj_get_key_type() does
     * not return a type until the class is set, and we can't set it in
     * p11prov_kmgmt_new() because the class type is unknown; OpenSSL
     * does not provide the expected type at that time. */
    if (p11prov_obj_get_key_type(key) != type) {
        return RET_OSSL_ERR;
    }
    if (param_set != CK_UNAVAILABLE_INFORMATION) {
        p11prov_obj_set_key_params(key, param_set);
    }

    rv = p11prov_obj_import_key(key, params);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

int p11prov_kmgmt_export(void *keydata, int selection, OSSL_CALLBACK *cb_fn,
                         void *cb_arg)
{

    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    P11PROV_CTX *ctx = p11prov_obj_get_prov_ctx(key);
    CK_OBJECT_CLASS class = p11prov_obj_get_class(key);
    CK_KEY_TYPE type = p11prov_obj_get_key_type(key);
    bool params_only = false;

    P11PROV_debug("key %p export (type: %ld, selection: %d)", key, type,
                  selection);

    if (!key) {
        return RET_OSSL_ERR;
    }

    if (class == CKO_PRIVATE_KEY
        && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) {
        /* can't export private keys */
        return RET_OSSL_ERR;
    }

    if (p11prov_ctx_allow_export(ctx) & DISALLOW_EXPORT_PUBLIC) {
        return RET_OSSL_ERR;
    }

    if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
        if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {
            params_only = true;
        }
        if (type != CKK_EC && params_only) {
            /* Domain parameters allowed only with CKK_EC */
            return RET_OSSL_ERR;
        }
    }

    return p11prov_obj_export_public_key(key, type, true, params_only, cb_fn,
                                         cb_arg);
}
