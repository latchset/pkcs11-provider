/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "kmgmt/internal.h"

DISPATCH_KEYMGMT_FN(mlkem_512, new);
DISPATCH_KEYMGMT_FN(mlkem_768, new);
DISPATCH_KEYMGMT_FN(mlkem_1024, new);
DISPATCH_KEYMGMT_FN(mlkem_512, gen_init);
DISPATCH_KEYMGMT_FN(mlkem_768, gen_init);
DISPATCH_KEYMGMT_FN(mlkem_1024, gen_init);
DISPATCH_KEYMGMT_FN(mlkem, gen_settable_params);
DISPATCH_KEYMGMT_FN(mlkem, gen);
DISPATCH_KEYMGMT_FN(mlkem, load);
DISPATCH_KEYMGMT_FN(mlkem, match);
DISPATCH_KEYMGMT_FN(mlkem, import);
DISPATCH_KEYMGMT_FN(mlkem, import_types);
DISPATCH_KEYMGMT_FN(mlkem, export_types);
DISPATCH_KEYMGMT_FN(mlkem, get_params);
DISPATCH_KEYMGMT_FN(mlkem, gettable_params);

extern const CK_BBOOL val_true;
extern const CK_BBOOL val_false;

#define MLKEM_PUBKEY_TEMPLATE_SIZE 6
#define MLKEM_PRIVKEY_TEMPLATE_SIZE 10
_Static_assert(MLKEM_PUBKEY_TEMPLATE_SIZE <= P11PROV_PUBKEY_MAX_TEMPLATE_SIZE,
               "ML-KEM public key template size exceeds maximum");
_Static_assert(MLKEM_PRIVKEY_TEMPLATE_SIZE <= P11PROV_PRIVKEY_MAX_TEMPLATE_SIZE,
               "ML-KEM private key template size exceeds maximum");

static int p11prov_mlkem_get_template(P11PROV_OBJ *obj, CK_OBJECT_CLASS class,
                                      const OSSL_PARAM *params,
                                      CK_ATTRIBUTE *template)
{
    static const CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY;
    static const CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
    static const CK_KEY_TYPE mlkem_type = CKK_ML_KEM;
    const OSSL_PARAM *p;
    CK_ATTRIBUTE *a;
    int cnt;

    if (!obj || p11prov_obj_get_key_type(obj) != CKK_ML_KEM
        || p11prov_obj_get_class(obj) != class) {
        return -1;
    }

    if (!template) {
        switch (class) {
        case CKO_PUBLIC_KEY:
            return MLKEM_PUBKEY_TEMPLATE_SIZE;
        case CKO_PRIVATE_KEY:
            return MLKEM_PRIVKEY_TEMPLATE_SIZE;
        default:
            return -1;
        }
    }

    template[0].type = CKA_KEY_TYPE;
    template[0].pValue = DISCARD_CONST(&mlkem_type);
    template[0].ulValueLen = sizeof(CK_KEY_TYPE);

    template[1].type = CKA_TOKEN;
    template[1].pValue = DISCARD_CONST(&val_false);
    template[1].ulValueLen = sizeof(CK_BBOOL);

    a = p11prov_obj_get_attr(obj, CKA_PARAMETER_SET);
    if (!a) {
        return -1;
    }
    template[2] = *a;

    switch (class) {
    case CKO_PUBLIC_KEY:
        template[3].type = CKA_CLASS;
        template[3].pValue = DISCARD_CONST(&pub_class);
        template[3].ulValueLen = sizeof(CK_OBJECT_CLASS);

        template[4].type = CKA_ENCAPSULATE;
        template[4].pValue = DISCARD_CONST(&val_true);
        template[4].ulValueLen = sizeof(CK_BBOOL);

        a = p11prov_obj_get_attr(obj, CKA_VALUE);
        if (!a) {
            return -1;
        }
        template[5] = *a;

        return 6;

    case CKO_PRIVATE_KEY:
        if (!params) {
            return -1;
        }

        template[3].type = CKA_CLASS;
        template[3].pValue = DISCARD_CONST(&priv_class);
        template[3].ulValueLen = sizeof(CK_OBJECT_CLASS);

        template[4].type = CKA_ID;
        template[4].pValue = NULL;
        template[4].ulValueLen = 0;

        template[5].type = CKA_SENSITIVE;
        template[5].pValue = DISCARD_CONST(&val_true);
        template[5].ulValueLen = sizeof(CK_BBOOL);

        template[6].type = CKA_EXTRACTABLE;
        template[6].pValue = DISCARD_CONST(&val_false);
        template[6].ulValueLen = sizeof(CK_BBOOL);

        template[7].type = CKA_DECAPSULATE;
        template[7].pValue = DISCARD_CONST(&val_true);
        template[7].ulValueLen = sizeof(CK_BBOOL);

        cnt = 8;
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (!p) {
            return -1;
        }
        template[cnt].type = CKA_VALUE;
        template[cnt].pValue = p->data;
        template[cnt].ulValueLen = p->data_size;
        cnt++;

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_KEM_SEED);
        if (p) {
            template[cnt].type = CKA_SEED;
            template[cnt].pValue = p->data;
            template[cnt].ulValueLen = p->data_size;
            cnt++;
        }

        return cnt;

    default:
        return -1;
    }
}

static CK_RV p11prov_mlkem_get_find_attrs(
    P11PROV_OBJ *obj, CK_OBJECT_CLASS class, const OSSL_PARAM *params,
    CK_ATTRIBUTE attrs[static MAX_FIND_ATTRS_SIZE], int *out_numattrs)
{
    P11PROV_CTX *ctx = p11prov_obj_get_prov_ctx(obj);
    CK_ULONG param_set = p11prov_obj_get_key_param_set(obj);
    const OSSL_PARAM *p;
    int numattrs = 0;
    CK_ULONG key_size;
    CK_RV rv;

    if (!obj || !params || !out_numattrs
        || p11prov_obj_get_key_type(obj) != CKK_ML_KEM) {
        return CKR_ARGUMENTS_BAD;
    }

    switch (param_set) {
    case CKP_ML_KEM_512:
        key_size = ML_KEM_512_PK_SIZE;
        break;
    case CKP_ML_KEM_768:
        key_size = ML_KEM_768_PK_SIZE;
        break;
    case CKP_ML_KEM_1024:
        key_size = ML_KEM_1024_PK_SIZE;
        break;
    default:
        return CKR_KEY_INDIGESTIBLE;
    }

    switch (class) {
    case CKO_PUBLIC_KEY:
        rv = p11prov_kmgmt_params_to_attr(ctx, attrs, &numattrs, params,
                                          OSSL_PKEY_PARAM_PUB_KEY, CKA_VALUE,
                                          false);
        if (rv != CKR_OK) {
            goto done;
        }
        if (key_size != attrs[numattrs - 1].ulValueLen) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE,
                          "Unexpected public key size %lu (expected %lu)",
                          attrs[0].ulValueLen, key_size);
            rv = CKR_KEY_INDIGESTIBLE;
            goto done;
        }
        break;

    case CKO_PRIVATE_KEY:
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_PRIV_KEY);
            return CKR_KEY_INDIGESTIBLE;
        }

        rv = p11prov_kmgmt_privkey_to_id(
            ctx, attrs, &numattrs, (const uint8_t *)"ML-KEM", 6,
            (const uint8_t *)&param_set, sizeof(param_set), p->data,
            p->data_size);
        if (rv != CKR_OK) {
            goto done;
        }
        break;

    default:
        return CKR_GENERAL_ERROR;
    }

    /* common params */
    rv = p11prov_kmgmt_param_data_to_attr(attrs, &numattrs, CKA_PARAMETER_SET,
                                          (uint8_t *)&param_set,
                                          sizeof(param_set), false);
    if (rv != CKR_OK) {
        goto done;
    }

    p11prov_obj_set_key_bits(obj, key_size * 8, key_size);
    *out_numattrs = numattrs;
    rv = CKR_OK;

done:
    if (rv != CKR_OK) {
        for (int i = 0; i < numattrs; i++) {
            OPENSSL_free(attrs[i].pValue);
            attrs[i].pValue = NULL;
        }
        *out_numattrs = 0;
    }
    return rv;
}

static void *p11prov_mlkem_new_int(void *provctx,
                                   CK_ML_KEM_PARAMETER_SET_TYPE param_set)
{
    P11PROV_OBJ *key;

    P11PROV_debug("mlkem new");
    key = p11prov_kmgmt_new(provctx, CKK_ML_KEM);
    if (key) {
        p11prov_obj_set_key_params(key, param_set);
        p11prov_obj_set_get_template(key, p11prov_mlkem_get_template);
        p11prov_obj_set_get_find_attrs(key, p11prov_mlkem_get_find_attrs);
    }
    return key;
}

static void *p11prov_mlkem_512_new(void *provctx)
{
    return p11prov_mlkem_new_int(provctx, CKP_ML_KEM_512);
}

static void *p11prov_mlkem_768_new(void *provctx)
{
    return p11prov_mlkem_new_int(provctx, CKP_ML_KEM_768);
}

static void *p11prov_mlkem_1024_new(void *provctx)
{
    return p11prov_mlkem_new_int(provctx, CKP_ML_KEM_1024);
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

static int p11prov_mlkem_import(void *keydata, int selection,
                                const OSSL_PARAM params[])
{
    p11prov_obj_set_get_find_attrs((P11PROV_OBJ *)keydata,
                                   p11prov_mlkem_get_find_attrs);
    return p11prov_kmgmt_import(CKK_ML_KEM, CK_UNAVAILABLE_INFORMATION,
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
        pub = p11prov_obj_get_public_attr(key, CKA_VALUE);
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
    DISPATCH_KEYMGMT_ELEM(mlkem_512, NEW, new),
    DISPATCH_KEYMGMT_ELEM(mlkem_512, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(mlkem, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(mlkem, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(mlkem, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(mlkem, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(mlkem, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(mlkem, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mlkem768_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(mlkem_768, NEW, new),
    DISPATCH_KEYMGMT_ELEM(mlkem_768, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(mlkem, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(mlkem, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(mlkem, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(mlkem, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(mlkem, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(mlkem, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mlkem1024_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(mlkem_1024, NEW, new),
    DISPATCH_KEYMGMT_ELEM(mlkem_1024, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(mlkem, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(mlkem, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(mlkem, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(mlkem, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(mlkem, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(mlkem, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(mlkem, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};
