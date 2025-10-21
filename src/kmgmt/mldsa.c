/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "kmgmt/internal.h"

DISPATCH_KEYMGMT_FN(mldsa, new);
DISPATCH_KEYMGMT_FN(mldsa_44, gen_init);
DISPATCH_KEYMGMT_FN(mldsa_65, gen_init);
DISPATCH_KEYMGMT_FN(mldsa_87, gen_init);
DISPATCH_KEYMGMT_FN(mldsa, gen_settable_params);
DISPATCH_KEYMGMT_FN(mldsa, gen);
DISPATCH_KEYMGMT_FN(mldsa, load);
DISPATCH_KEYMGMT_FN(mldsa, match);
DISPATCH_KEYMGMT_FN(mldsa, import_types);
DISPATCH_KEYMGMT_FN(mldsa, export_types);
DISPATCH_KEYMGMT_FN(mldsa, get_params);
DISPATCH_KEYMGMT_FN(mldsa, gettable_params);

static void *p11prov_mldsa_new(void *provctx)
{
    P11PROV_debug("mldsa new");
    return p11prov_kmgmt_new(provctx, CKK_ML_DSA);
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
        p11prov_kmgmt_gen_cleanup(ctx);
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

static void *p11prov_mldsa_load(const void *reference, size_t reference_sz)
{
    return p11prov_kmgmt_load(reference, reference_sz, CKK_ML_DSA);
}

static int p11prov_mldsa_match(const void *keydata1, const void *keydata2,
                               int selection)
{
    return p11prov_kmgmt_match(keydata1, keydata2, CKK_ML_DSA, selection);
}

static int p11prov_mldsa_44_import(void *keydata, int selection,
                                   const OSSL_PARAM params[])
{
    return p11prov_kmgmt_import(CKK_ML_DSA, CKP_ML_DSA_44,
                                OSSL_PKEY_PARAM_PRIV_KEY, keydata, selection,
                                params);
}

static int p11prov_mldsa_65_import(void *keydata, int selection,
                                   const OSSL_PARAM params[])
{
    return p11prov_kmgmt_import(CKK_ML_DSA, CKP_ML_DSA_65,
                                OSSL_PKEY_PARAM_PRIV_KEY, keydata, selection,
                                params);
}

static int p11prov_mldsa_87_import(void *keydata, int selection,
                                   const OSSL_PARAM params[])
{
    return p11prov_kmgmt_import(CKK_ML_DSA, CKP_ML_DSA_87,
                                OSSL_PKEY_PARAM_PRIV_KEY, keydata, selection,
                                params);
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
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
    if (p) {
        ret = OSSL_PARAM_set_utf8_string(p, "");
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

#define p11prov_mldsa_gen_cleanup p11prov_kmgmt_gen_cleanup
#define p11prov_mldsa_free p11prov_kmgmt_free
#define p11prov_mldsa_has p11prov_kmgmt_has
#define p11prov_mldsa_export p11prov_kmgmt_export

const OSSL_DISPATCH p11prov_mldsa44_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(mldsa, NEW, new),
    DISPATCH_KEYMGMT_ELEM(mldsa_44, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(mldsa, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(mldsa, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(mldsa_44, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(mldsa, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(mldsa, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(mldsa, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mldsa65_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(mldsa, NEW, new),
    DISPATCH_KEYMGMT_ELEM(mldsa_65, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(mldsa, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(mldsa, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(mldsa_65, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(mldsa, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(mldsa, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(mldsa, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mldsa87_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(mldsa, NEW, new),
    DISPATCH_KEYMGMT_ELEM(mldsa_87, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(mldsa, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(mldsa, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(mldsa_87, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(mldsa, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(mldsa, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(mldsa, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(mldsa, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};
