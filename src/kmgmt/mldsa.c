/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "kmgmt/internal.h"

DISPATCH_KEYMGMT_FN(mldsa, new);
DISPATCH_KEYMGMT_FN(mldsa, gen_cleanup);
DISPATCH_KEYMGMT_FN(mldsa_44, gen_init);
DISPATCH_KEYMGMT_FN(mldsa_65, gen_init);
DISPATCH_KEYMGMT_FN(mldsa_87, gen_init);
DISPATCH_KEYMGMT_FN(mldsa, gen_settable_params);
DISPATCH_KEYMGMT_FN(mldsa, gen);
DISPATCH_KEYMGMT_FN(mldsa, free);
DISPATCH_KEYMGMT_FN(mldsa, has);
DISPATCH_KEYMGMT_FN(mldsa, match);
DISPATCH_KEYMGMT_FN(mldsa, import_types);
DISPATCH_KEYMGMT_FN(mldsa, export);
DISPATCH_KEYMGMT_FN(mldsa, export_types);
DISPATCH_KEYMGMT_FN(mldsa, get_params);
DISPATCH_KEYMGMT_FN(mldsa, gettable_params);

static void *p11prov_mldsa_new(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    CK_RV ret;

    P11PROV_debug("mldsa new");

    ret = p11prov_ctx_status(ctx);
    if (ret != CKR_OK) {
        return NULL;
    }

    return p11prov_obj_new(provctx, CK_UNAVAILABLE_INFORMATION,
                           CK_P11PROV_IMPORTED_HANDLE,
                           CK_UNAVAILABLE_INFORMATION);
}

static void p11prov_mldsa_gen_cleanup(void *genctx)
{
    struct key_generator *ctx = (struct key_generator *)genctx;

    P11PROV_debug("mldsa gen_cleanup %p", genctx);

    p11prov_kmgmt_gen_cleanup(ctx);
}

static void *p11prov_mldsa_gen_init_int(void *provctx, int selection,
                                        const OSSL_PARAM params[],
                                        CK_ML_DSA_PARAMETER_SET_TYPE param_set)
{
    struct key_generator *ctx = NULL;
    int ret;

    P11PROV_debug("mldsa gen_init %p", provctx);

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
        P11PROV_raise(provctx, CKR_ARGUMENTS_BAD, "Unsupported selection");
        return NULL;
    }

    ctx = p11prov_kmgmt_gen_init(provctx, CKK_ML_DSA, CKM_ML_DSA_KEY_PAIR_GEN);
    if (!ctx) {
        return NULL;
    }

    ctx->data.mldsa.param_set = param_set;

    ret = p11prov_kmgmt_gen_set_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        p11prov_mldsa_gen_cleanup(ctx);
        return NULL;
    }
    return ctx;
}

static void *p11prov_mldsa_44_gen_init(void *provctx, int selection,
                                       const OSSL_PARAM params[])
{
    return p11prov_mldsa_gen_init_int(provctx, selection, params,
                                      CKP_ML_DSA_44);
}

static void *p11prov_mldsa_65_gen_init(void *provctx, int selection,
                                       const OSSL_PARAM params[])
{
    return p11prov_mldsa_gen_init_int(provctx, selection, params,
                                      CKP_ML_DSA_65);
}

static void *p11prov_mldsa_87_gen_init(void *provctx, int selection,
                                       const OSSL_PARAM params[])
{
    return p11prov_mldsa_gen_init_int(provctx, selection, params,
                                      CKP_ML_DSA_87);
}

static const OSSL_PARAM *p11prov_mldsa_gen_settable_params(void *genctx,
                                                           void *provctx)
{
    static OSSL_PARAM p11prov_mldsa_params[] = {
        OSSL_PARAM_utf8_string(P11PROV_PARAM_URI, NULL, 0),
        OSSL_PARAM_utf8_string(P11PROV_PARAM_KEY_USAGE, NULL, 0),
        OSSL_PARAM_END,
    };
    return p11prov_mldsa_params;
}

extern const CK_BBOOL val_true;
extern const CK_BBOOL val_false;

static void *p11prov_mldsa_gen(void *genctx, OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    struct key_generator *ctx = (struct key_generator *)genctx;
    void *key;
    CK_RV ret;

    /* always leave space for CKA_ID and CKA_LABEL */
#define MLDSA_PUBKEY_TMPL_SIZE 3
    CK_ATTRIBUTE pubkey_template[MLDSA_PUBKEY_TMPL_SIZE + COMMON_TMPL_SIZE] = {
        { CKA_TOKEN, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_VERIFY, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_PARAMETER_SET, &ctx->data.mldsa.param_set,
          sizeof(ctx->data.mldsa.param_set) },
    };
#define MLDSA_PRIVKEY_TMPL_SIZE 4
    CK_ATTRIBUTE
    privkey_template[MLDSA_PRIVKEY_TMPL_SIZE + COMMON_TMPL_SIZE] = {
        { CKA_TOKEN, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_PRIVATE, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_SENSITIVE, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_SIGN, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
    };
    int pubtsize = MLDSA_PUBKEY_TMPL_SIZE;
    int privtsize = MLDSA_PRIVKEY_TMPL_SIZE;

    P11PROV_debug("mldsa gen %p %p %p", ctx, cb_fn, cb_arg);

    ret = p11prov_kmgmt_gen(ctx, pubkey_template, privkey_template, pubtsize,
                            privtsize, cb_fn, cb_arg, &key);
    if (ret != CKR_OK) {
        P11PROV_raise(ctx->provctx, ret, "mldsa Key generation failed");
        return NULL;
    }
    return key;
}
static void p11prov_mldsa_free(void *key)
{
    P11PROV_debug("mldsa free %p", key);
    p11prov_obj_free((P11PROV_OBJ *)key);
}

static void *p11prov_mldsa_load(const void *reference, size_t reference_sz)
{
    P11PROV_debug("mldsa load %p, %ld", reference, reference_sz);
    return p11prov_obj_from_typed_reference(reference, reference_sz,
                                            CKK_ML_DSA);
}

static int p11prov_mldsa_has(const void *keydata, int selection)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;

    P11PROV_debug("mldsa has %p %d", key, selection);

    if (key == NULL) {
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

static int p11prov_mldsa_match(const void *keydata1, const void *keydata2,
                               int selection)
{
    P11PROV_debug("mldsa match %p %p %d", keydata1, keydata2, selection);

    return p11prov_kmgmt_match(keydata1, keydata2, CKK_ML_DSA, selection);
}

static int p11prov_mldsa_import(void *keydata, int selection,
                                const OSSL_PARAM params[],
                                CK_ML_DSA_PARAMETER_SET_TYPE param_set)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    CK_OBJECT_CLASS class = CK_UNAVAILABLE_INFORMATION;
    CK_RV rv;

    P11PROV_debug("mldsa import %p", key);

    if (!key) {
        return RET_OSSL_ERR;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        class = CKO_PRIVATE_KEY;
    } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        class = CKO_PUBLIC_KEY;
    } else if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
        class = CKO_DOMAIN_PARAMETERS;
    }

    /* NOTE: the following is needed because of bug:
     * https://github.com/openssl/openssl/issues/21596
     * it can be removed once we can depend on a recent enough version
     * after it is fixed */
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        const OSSL_PARAM *p;
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (!p) {
            /* not really a private key */
            class = CKO_PUBLIC_KEY;
        }
    }

    p11prov_obj_set_class(key, class);
    p11prov_obj_set_key_type(key, CKK_ML_DSA);
    p11prov_obj_set_key_params(key, param_set);

    rv = p11prov_obj_import_key(key, params);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_mldsa_44_import(void *keydata, int selection,
                                   const OSSL_PARAM params[])
{
    return p11prov_mldsa_import(keydata, selection, params, CKP_ML_DSA_44);
}

static int p11prov_mldsa_65_import(void *keydata, int selection,
                                   const OSSL_PARAM params[])
{
    return p11prov_mldsa_import(keydata, selection, params, CKP_ML_DSA_65);
}

static int p11prov_mldsa_87_import(void *keydata, int selection,
                                   const OSSL_PARAM params[])
{
    return p11prov_mldsa_import(keydata, selection, params, CKP_ML_DSA_87);
}

static int p11prov_mldsa_export(void *keydata, int selection,
                                OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    P11PROV_CTX *ctx = p11prov_obj_get_prov_ctx(key);
    CK_OBJECT_CLASS class = p11prov_obj_get_class(key);

    P11PROV_debug("mldsa export %p, selection= %d", keydata, selection);

    if (key == NULL) {
        return RET_OSSL_ERR;
    }

    if (p11prov_ctx_allow_export(ctx) & DISALLOW_EXPORT_PUBLIC) {
        return RET_OSSL_ERR;
    }

    /* if anything else is asked for we can't provide it, so be strict */
    if ((class == CKO_PUBLIC_KEY) || (selection & ~(PUBLIC_PARAMS)) == 0) {
        return p11prov_obj_export_public_key(key, CKK_ML_DSA, true, false,
                                             cb_fn, cb_arg);
    }

    return RET_OSSL_ERR;
}

#ifndef OSSL_PKEY_PARAM_ML_DSA_SEED
#define OSSL_PKEY_PARAM_ML_DSA_SEED "seed"
#endif

static const OSSL_PARAM *p11prov_mldsa_import_types(int selection)
{
    static const OSSL_PARAM p11prov_mldsa_imp_key_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
        OSSL_PARAM_END,
    };
    P11PROV_debug("mldsa import types");
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
        return p11prov_mldsa_imp_key_types;
    }
    return NULL;
}

static const OSSL_PARAM *p11prov_mldsa_export_types(int selection)
{
    static const OSSL_PARAM p11prov_mldsa_exp_key_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END,
    };
    P11PROV_debug("mldsa export types");
    if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return p11prov_mldsa_exp_key_types;
    }
    return NULL;
}

static int p11prov_mldsa_get_params(void *keydata, OSSL_PARAM params[])
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    CK_ULONG param_set = p11prov_obj_get_key_param_set(key);
    OSSL_PARAM *p;
    int ret;

    P11PROV_debug("mldsa get params %p", keydata);

    if (key == NULL) {
        return RET_OSSL_ERR;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p) {
        CK_ULONG bits_size = p11prov_obj_get_key_bit_size(key);
        if (bits_size == 0) {
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_int(p, bits_size);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p) {
        int secbits = 0;
        switch (param_set) {
        case CKP_ML_DSA_44:
            secbits = 128;
            break;
        case CKP_ML_DSA_65:
            secbits = 192;
            break;
        case CKP_ML_DSA_87:
            secbits = 256;
            break;
        }
        if (secbits == 0) {
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_int(p, secbits);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p) {
        int sigsize = 0;
        switch (param_set) {
        case CKP_ML_DSA_44:
            sigsize = ML_DSA_44_SIG_SIZE;
            break;
        case CKP_ML_DSA_65:
            sigsize = ML_DSA_65_SIG_SIZE;
            break;
        case CKP_ML_DSA_87:
            sigsize = ML_DSA_87_SIG_SIZE;
            break;
        }
        if (sigsize == 0) {
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_int(p, sigsize);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p) {
        CK_ATTRIBUTE *pub;

        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            return RET_OSSL_ERR;
        }
        pub = p11prov_obj_get_attr(key, CKA_VALUE);
        if (!pub) {
            return RET_OSSL_ERR;
        }

        p->return_size = pub->ulValueLen;
        if (p->data) {
            if (p->data_size < pub->ulValueLen) {
                return RET_OSSL_ERR;
            }
            memcpy(p->data, pub->pValue, pub->ulValueLen);
            p->data_size = pub->ulValueLen;
        }
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_mldsa_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_mldsa44_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(mldsa, NEW, new),
    DISPATCH_KEYMGMT_ELEM(mldsa_44, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(mldsa, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(mldsa, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(mldsa, FREE, free),
    DISPATCH_KEYMGMT_ELEM(mldsa, HAS, has),
    DISPATCH_KEYMGMT_ELEM(mldsa, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(mldsa_44, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(mldsa, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(mldsa, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(mldsa, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(mldsa, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mldsa65_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(mldsa, NEW, new),
    DISPATCH_KEYMGMT_ELEM(mldsa_65, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(mldsa, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(mldsa, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(mldsa, FREE, free),
    DISPATCH_KEYMGMT_ELEM(mldsa, HAS, has),
    DISPATCH_KEYMGMT_ELEM(mldsa, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(mldsa_65, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(mldsa, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(mldsa, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(mldsa, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(mldsa, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mldsa87_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(mldsa, NEW, new),
    DISPATCH_KEYMGMT_ELEM(mldsa_87, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(mldsa, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(mldsa, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(mldsa, FREE, free),
    DISPATCH_KEYMGMT_ELEM(mldsa, HAS, has),
    DISPATCH_KEYMGMT_ELEM(mldsa, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(mldsa_87, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(mldsa, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(mldsa, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(mldsa, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(mldsa, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};
