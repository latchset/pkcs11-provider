/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "kmgmt/internal.h"

DISPATCH_KEYMGMT_FN(mlkem, new);
DISPATCH_KEYMGMT_FN(mlkem_512, gen_init);
DISPATCH_KEYMGMT_FN(mlkem_768, gen_init);
DISPATCH_KEYMGMT_FN(mlkem_1024, gen_init);
DISPATCH_KEYMGMT_FN(mlkem, gen_settable_params);
DISPATCH_KEYMGMT_FN(mlkem, gen);
DISPATCH_KEYMGMT_FN(mlkem, load);
DISPATCH_KEYMGMT_FN(mlkem, match);
DISPATCH_KEYMGMT_FN(mlkem, import_types);
DISPATCH_KEYMGMT_FN(mlkem, export_types);
DISPATCH_KEYMGMT_FN(mlkem, get_params);
DISPATCH_KEYMGMT_FN(mlkem, gettable_params);
DISPATCH_KEYMGMT_FN(mlkem_512, import);
DISPATCH_KEYMGMT_FN(mlkem_768, import);
DISPATCH_KEYMGMT_FN(mlkem_1024, import);

static void *p11prov_mlkem_new(void *provctx)
{
    P11PROV_debug("mlkem new");
    return p11prov_kmgmt_new(provctx, CKK_ML_KEM);
}

static void *p11prov_mlkem_gen_init_int(void *provctx, int selection,
                                        const OSSL_PARAM params[],
                                        CK_ML_KEM_PARAMETER_SET_TYPE param_set)
{
    struct key_generator *ctx = NULL;
    int ret;

    P11PROV_debug("mlkem gen_init %p", provctx);

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
        P11PROV_raise(provctx, CKR_ARGUMENTS_BAD, "Unsupported selection");
        return NULL;
    }

    ctx = p11prov_kmgmt_gen_init(provctx, CKK_ML_KEM, CKM_ML_KEM_KEY_PAIR_GEN);
    if (!ctx) {
        return NULL;
    }

    ctx->data.mlkem.param_set = param_set;

    ret = p11prov_kmgmt_gen_set_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        p11prov_kmgmt_gen_cleanup(ctx);
        return NULL;
    }
    return ctx;
}

static void *p11prov_mlkem_512_gen_init(void *provctx, int selection,
                                        const OSSL_PARAM params[])
{
    return p11prov_mlkem_gen_init_int(provctx, selection, params,
                                      CKP_ML_KEM_512);
}

static void *p11prov_mlkem_768_gen_init(void *provctx, int selection,
                                        const OSSL_PARAM params[])
{
    return p11prov_mlkem_gen_init_int(provctx, selection, params,
                                      CKP_ML_KEM_768);
}

static void *p11prov_mlkem_1024_gen_init(void *provctx, int selection,
                                         const OSSL_PARAM params[])
{
    return p11prov_mlkem_gen_init_int(provctx, selection, params,
                                      CKP_ML_KEM_1024);
}

static const OSSL_PARAM *p11prov_mlkem_gen_settable_params(void *genctx,
                                                           void *provctx)
{
    static OSSL_PARAM p11prov_mlkem_params[] = {
        OSSL_PARAM_utf8_string(P11PROV_PARAM_URI, NULL, 0),
        OSSL_PARAM_utf8_string(P11PROV_PARAM_KEY_USAGE, NULL, 0),
        OSSL_PARAM_END,
    };
    return p11prov_mlkem_params;
}

extern const CK_BBOOL val_true;
extern const CK_BBOOL val_false;

static void *p11prov_mlkem_gen(void *genctx, OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    struct key_generator *ctx = (struct key_generator *)genctx;
    void *key;
    CK_RV ret;

    /* always leave space for CKA_ID and CKA_LABEL */
#define MLKEM_PUBKEY_TMPL_SIZE 3
    CK_ATTRIBUTE pubkey_template[MLKEM_PUBKEY_TMPL_SIZE + COMMON_TMPL_SIZE] = {
        { CKA_TOKEN, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_ENCAPSULATE, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_PARAMETER_SET, &ctx->data.mlkem.param_set,
          sizeof(ctx->data.mlkem.param_set) },
    };
#define MLKEM_PRIVKEY_TMPL_SIZE 4
    CK_ATTRIBUTE
    privkey_template[MLKEM_PRIVKEY_TMPL_SIZE + COMMON_TMPL_SIZE] = {
        { CKA_TOKEN, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_PRIVATE, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_SENSITIVE, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_DECAPSULATE, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
    };
    int pubtsize = MLKEM_PUBKEY_TMPL_SIZE;
    int privtsize = MLKEM_PRIVKEY_TMPL_SIZE;

    P11PROV_debug("mlkem gen %p %p %p", ctx, cb_fn, cb_arg);

    ret = p11prov_kmgmt_gen(ctx, pubkey_template, privkey_template, pubtsize,
                            privtsize, cb_fn, cb_arg, &key);
    if (ret != CKR_OK) {
        P11PROV_raise(ctx->provctx, ret, "mlkem Key generation failed");
        return NULL;
    }
    return key;
}

static void *p11prov_mlkem_load(const void *reference, size_t reference_sz)
{
    return p11prov_kmgmt_load(reference, reference_sz, CKK_ML_KEM);
}

static int p11prov_mlkem_match(const void *keydata1, const void *keydata2,
                               int selection)
{
    return p11prov_kmgmt_match(keydata1, keydata2, CKK_ML_KEM, selection);
}

static int p11prov_mlkem_512_import(void *keydata, int selection,
                                    const OSSL_PARAM params[])
{
    return p11prov_kmgmt_import(CKK_ML_KEM, CKP_ML_KEM_512,
                                OSSL_PKEY_PARAM_PRIV_KEY, keydata, selection,
                                params);
}

static int p11prov_mlkem_768_import(void *keydata, int selection,
                                    const OSSL_PARAM params[])
{
    return p11prov_kmgmt_import(CKK_ML_KEM, CKP_ML_KEM_768,
                                OSSL_PKEY_PARAM_PRIV_KEY, keydata, selection,
                                params);
}

static int p11prov_mlkem_1024_import(void *keydata, int selection,
                                     const OSSL_PARAM params[])
{
    return p11prov_kmgmt_import(CKK_ML_KEM, CKP_ML_KEM_1024,
                                OSSL_PKEY_PARAM_PRIV_KEY, keydata, selection,
                                params);
}

static const OSSL_PARAM *p11prov_mlkem_import_types(int selection)
{
    static const OSSL_PARAM p11prov_mlkem_imp_key_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END,
    };
    P11PROV_debug("mlkem import types");
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
        return p11prov_mlkem_imp_key_types;
    }
    return NULL;
}

static const OSSL_PARAM *p11prov_mlkem_export_types(int selection)
{
    static const OSSL_PARAM p11prov_mlkem_exp_key_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END,
    };
    P11PROV_debug("mlkem export types");
    if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return p11prov_mlkem_exp_key_types;
    }
    return NULL;
}

static int p11prov_mlkem_get_params(void *keydata, OSSL_PARAM params[])
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    CK_ULONG param_set = p11prov_obj_get_key_param_set(key);
    OSSL_PARAM *p;
    int ret;

    P11PROV_debug("mlkem get params %p", keydata);

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
        case CKP_ML_KEM_512:
            secbits = 128;
            break;
        case CKP_ML_KEM_768:
            secbits = 192;
            break;
        case CKP_ML_KEM_1024:
            secbits = 256;
            break;
        default:
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_int(p, secbits);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p) {
        int kemsize = 0;
        switch (param_set) {
        case CKP_ML_KEM_512:
            kemsize = ML_KEM_512_CIPHERTEXT_BYTES;
            break;
        case CKP_ML_KEM_768:
            kemsize = ML_KEM_768_CIPHERTEXT_BYTES;
            break;
        case CKP_ML_KEM_1024:
            kemsize = ML_KEM_1024_CIPHERTEXT_BYTES;
            break;
        default:
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_int(p, kemsize);
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

static const OSSL_PARAM *p11prov_mlkem_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_mlkem512_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(mlkem, NEW, new),
    DISPATCH_KEYMGMT_ELEM(mlkem_512, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(mlkem, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(mlkem, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(mlkem_512, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(mlkem, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(mlkem, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(mlkem, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mlkem768_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(mlkem, NEW, new),
    DISPATCH_KEYMGMT_ELEM(mlkem_768, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(mlkem, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(mlkem, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(mlkem_768, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(mlkem, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(mlkem, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(mlkem, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mlkem1024_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(mlkem, NEW, new),
    DISPATCH_KEYMGMT_ELEM(mlkem_1024, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(mlkem, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(mlkem, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(mlkem_1024, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(mlkem, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(mlkem, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(mlkem, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};
