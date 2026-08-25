/* Copyright (C) 2026 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "kmgmt/internal.h"

DISPATCH_KEYMGMT_FN(slhdsa_sha2_128s, new);
DISPATCH_KEYMGMT_FN(slhdsa_sha2_128f, new);
DISPATCH_KEYMGMT_FN(slhdsa_sha2_192s, new);
DISPATCH_KEYMGMT_FN(slhdsa_sha2_192f, new);
DISPATCH_KEYMGMT_FN(slhdsa_sha2_256s, new);
DISPATCH_KEYMGMT_FN(slhdsa_sha2_256f, new);
DISPATCH_KEYMGMT_FN(slhdsa_shake_128s, new);
DISPATCH_KEYMGMT_FN(slhdsa_shake_128f, new);
DISPATCH_KEYMGMT_FN(slhdsa_shake_192s, new);
DISPATCH_KEYMGMT_FN(slhdsa_shake_192f, new);
DISPATCH_KEYMGMT_FN(slhdsa_shake_256s, new);
DISPATCH_KEYMGMT_FN(slhdsa_shake_256f, new);
DISPATCH_KEYMGMT_FN(slhdsa_sha2_128s, gen_init);
DISPATCH_KEYMGMT_FN(slhdsa_sha2_128f, gen_init);
DISPATCH_KEYMGMT_FN(slhdsa_sha2_192s, gen_init);
DISPATCH_KEYMGMT_FN(slhdsa_sha2_192f, gen_init);
DISPATCH_KEYMGMT_FN(slhdsa_sha2_256s, gen_init);
DISPATCH_KEYMGMT_FN(slhdsa_sha2_256f, gen_init);
DISPATCH_KEYMGMT_FN(slhdsa_shake_128s, gen_init);
DISPATCH_KEYMGMT_FN(slhdsa_shake_128f, gen_init);
DISPATCH_KEYMGMT_FN(slhdsa_shake_192s, gen_init);
DISPATCH_KEYMGMT_FN(slhdsa_shake_192f, gen_init);
DISPATCH_KEYMGMT_FN(slhdsa_shake_256s, gen_init);
DISPATCH_KEYMGMT_FN(slhdsa_shake_256f, gen_init);
DISPATCH_KEYMGMT_FN(slhdsa, gen_settable_params);
DISPATCH_KEYMGMT_FN(slhdsa, gen);
DISPATCH_KEYMGMT_FN(slhdsa, load);
DISPATCH_KEYMGMT_FN(slhdsa, match);
DISPATCH_KEYMGMT_FN(slhdsa, import);
DISPATCH_KEYMGMT_FN(slhdsa, import_types);
DISPATCH_KEYMGMT_FN(slhdsa, export_types);
DISPATCH_KEYMGMT_FN(slhdsa, get_params);
DISPATCH_KEYMGMT_FN(slhdsa, gettable_params);

extern const CK_BBOOL val_true;
extern const CK_BBOOL val_false;

#define SLHDSA_PUBKEY_TEMPLATE_SIZE 6
#define SLHDSA_PRIVKEY_TEMPLATE_SIZE 10
_Static_assert(SLHDSA_PUBKEY_TEMPLATE_SIZE <= P11PROV_PUBKEY_MAX_TEMPLATE_SIZE,
               "SLH-DSA public key template size exceeds maximum");
_Static_assert(SLHDSA_PRIVKEY_TEMPLATE_SIZE
                   <= P11PROV_PRIVKEY_MAX_TEMPLATE_SIZE,
               "SLH-DSA private key template size exceeds maximum");

static int p11prov_slhdsa_get_template(P11PROV_OBJ *obj, CK_OBJECT_CLASS class,
                                       const OSSL_PARAM *params,
                                       CK_ATTRIBUTE *template)
{
    static const CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY;
    static const CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
    static const CK_KEY_TYPE slhdsa_type = CKK_SLH_DSA;
    const OSSL_PARAM *p;
    CK_ATTRIBUTE *a;
    int cnt;

    if (!obj || p11prov_obj_get_key_type(obj) != CKK_SLH_DSA
        || p11prov_obj_get_class(obj) != class) {
        return -1;
    }

    if (!template) {
        switch (class) {
        case CKO_PUBLIC_KEY:
            return SLHDSA_PUBKEY_TEMPLATE_SIZE;
        case CKO_PRIVATE_KEY:
            return SLHDSA_PRIVKEY_TEMPLATE_SIZE;
        default:
            return -1;
        }
    }

    template[0].type = CKA_KEY_TYPE;
    template[0].pValue = DISCARD_CONST(&slhdsa_type);
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

        template[4].type = CKA_VERIFY;
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

        template[7].type = CKA_SIGN;
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

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SLH_DSA_SEED);
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

static CK_RV p11prov_slhdsa_get_find_attrs(
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
        || p11prov_obj_get_key_type(obj) != CKK_SLH_DSA) {
        return CKR_ARGUMENTS_BAD;
    }

    switch (param_set) {
    case CKP_SLH_DSA_SHA2_128S:
        key_size = SLH_DSA_SHA2_128S_PK_SIZE;
        break;
    case CKP_SLH_DSA_SHA2_128F:
        key_size = SLH_DSA_SHA2_128F_PK_SIZE;
        break;
    case CKP_SLH_DSA_SHA2_192S:
        key_size = SLH_DSA_SHA2_192S_PK_SIZE;
        break;
    case CKP_SLH_DSA_SHA2_192F:
        key_size = SLH_DSA_SHA2_192F_PK_SIZE;
        break;
    case CKP_SLH_DSA_SHA2_256S:
        key_size = SLH_DSA_SHA2_256S_PK_SIZE;
        break;
    case CKP_SLH_DSA_SHA2_256F:
        key_size = SLH_DSA_SHA2_256F_PK_SIZE;
        break;
    case CKP_SLH_DSA_SHAKE_128S:
        key_size = SLH_DSA_SHAKE_128S_PK_SIZE;
        break;
    case CKP_SLH_DSA_SHAKE_128F:
        key_size = SLH_DSA_SHAKE_128F_PK_SIZE;
        break;
    case CKP_SLH_DSA_SHAKE_192S:
        key_size = SLH_DSA_SHAKE_192S_PK_SIZE;
        break;
    case CKP_SLH_DSA_SHAKE_192F:
        key_size = SLH_DSA_SHAKE_192F_PK_SIZE;
        break;
    case CKP_SLH_DSA_SHAKE_256S:
        key_size = SLH_DSA_SHAKE_256S_PK_SIZE;
        break;
    case CKP_SLH_DSA_SHAKE_256F:
        key_size = SLH_DSA_SHAKE_256F_PK_SIZE;
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
            ctx, attrs, &numattrs, (const uint8_t *)"SLH-DSA", 7,
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

static void *p11prov_slhdsa_new_int(void *provctx,
                                    CK_SLH_DSA_PARAMETER_SET_TYPE param_set)
{
    P11PROV_OBJ *key;

    P11PROV_debug("slhdsa new");
    key = p11prov_kmgmt_new(provctx, CKK_SLH_DSA);
    if (key) {
        p11prov_obj_set_key_params(key, param_set);
        p11prov_obj_set_get_template(key, p11prov_slhdsa_get_template);
        p11prov_obj_set_get_find_attrs(key, p11prov_slhdsa_get_find_attrs);
    }
    return key;
}

#define SLHDSA_NEW(name, param_set) \
    static void *p11prov_slhdsa_##name##_new(void *provctx) \
    { \
        return p11prov_slhdsa_new_int(provctx, param_set); \
    }

SLHDSA_NEW(sha2_128s, CKP_SLH_DSA_SHA2_128S)
SLHDSA_NEW(sha2_128f, CKP_SLH_DSA_SHA2_128F)
SLHDSA_NEW(sha2_192s, CKP_SLH_DSA_SHA2_192S)
SLHDSA_NEW(sha2_192f, CKP_SLH_DSA_SHA2_192F)
SLHDSA_NEW(sha2_256s, CKP_SLH_DSA_SHA2_256S)
SLHDSA_NEW(sha2_256f, CKP_SLH_DSA_SHA2_256F)
SLHDSA_NEW(shake_128s, CKP_SLH_DSA_SHAKE_128S)
SLHDSA_NEW(shake_128f, CKP_SLH_DSA_SHAKE_128F)
SLHDSA_NEW(shake_192s, CKP_SLH_DSA_SHAKE_192S)
SLHDSA_NEW(shake_192f, CKP_SLH_DSA_SHAKE_192F)
SLHDSA_NEW(shake_256s, CKP_SLH_DSA_SHAKE_256S)
SLHDSA_NEW(shake_256f, CKP_SLH_DSA_SHAKE_256F)

static void *
p11prov_slhdsa_gen_init_int(void *provctx, int selection,
                            const OSSL_PARAM params[],
                            CK_SLH_DSA_PARAMETER_SET_TYPE param_set)
{
    struct key_generator *ctx = NULL;
    int ret;

    P11PROV_debug("slhdsa gen_init %p", provctx);

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
        P11PROV_raise(provctx, CKR_ARGUMENTS_BAD, "Unsupported selection");
        return NULL;
    }

    ctx =
        p11prov_kmgmt_gen_init(provctx, CKK_SLH_DSA, CKM_SLH_DSA_KEY_PAIR_GEN);
    if (!ctx) {
        return NULL;
    }

    ctx->data.slhdsa.param_set = param_set;

    ret = p11prov_kmgmt_gen_set_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        p11prov_kmgmt_gen_cleanup(ctx);
        return NULL;
    }
    return ctx;
}

#define SLHDSA_GEN_INIT(name, param_set) \
    static void *p11prov_slhdsa_##name##_gen_init( \
        void *provctx, int selection, const OSSL_PARAM params[]) \
    { \
        return p11prov_slhdsa_gen_init_int(provctx, selection, params, \
                                           param_set); \
    }

SLHDSA_GEN_INIT(sha2_128s, CKP_SLH_DSA_SHA2_128S)
SLHDSA_GEN_INIT(sha2_128f, CKP_SLH_DSA_SHA2_128F)
SLHDSA_GEN_INIT(sha2_192s, CKP_SLH_DSA_SHA2_192S)
SLHDSA_GEN_INIT(sha2_192f, CKP_SLH_DSA_SHA2_192F)
SLHDSA_GEN_INIT(sha2_256s, CKP_SLH_DSA_SHA2_256S)
SLHDSA_GEN_INIT(sha2_256f, CKP_SLH_DSA_SHA2_256F)
SLHDSA_GEN_INIT(shake_128s, CKP_SLH_DSA_SHAKE_128S)
SLHDSA_GEN_INIT(shake_128f, CKP_SLH_DSA_SHAKE_128F)
SLHDSA_GEN_INIT(shake_192s, CKP_SLH_DSA_SHAKE_192S)
SLHDSA_GEN_INIT(shake_192f, CKP_SLH_DSA_SHAKE_192F)
SLHDSA_GEN_INIT(shake_256s, CKP_SLH_DSA_SHAKE_256S)
SLHDSA_GEN_INIT(shake_256f, CKP_SLH_DSA_SHAKE_256F)

static const OSSL_PARAM *p11prov_slhdsa_gen_settable_params(void *genctx,
                                                            void *provctx)
{
    static OSSL_PARAM p11prov_slhdsa_params[] = {
        OSSL_PARAM_utf8_string(P11PROV_PARAM_URI, NULL, 0),
        OSSL_PARAM_utf8_string(P11PROV_PARAM_KEY_USAGE, NULL, 0),
        OSSL_PARAM_END,
    };
    return p11prov_slhdsa_params;
}

static void *p11prov_slhdsa_gen(void *genctx, OSSL_CALLBACK *cb_fn,
                                void *cb_arg)
{
    struct key_generator *ctx = (struct key_generator *)genctx;
    void *key;
    CK_RV ret;

#define SLHDSA_PUBKEY_TMPL_SIZE 3
    CK_ATTRIBUTE pubkey_template[SLHDSA_PUBKEY_TMPL_SIZE + COMMON_TMPL_SIZE] = {
        { CKA_TOKEN, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_VERIFY, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_PARAMETER_SET, &ctx->data.slhdsa.param_set,
          sizeof(ctx->data.slhdsa.param_set) },
    };
#define SLHDSA_PRIVKEY_TMPL_SIZE 4
    CK_ATTRIBUTE
    privkey_template[SLHDSA_PRIVKEY_TMPL_SIZE + COMMON_TMPL_SIZE] = {
        { CKA_TOKEN, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_PRIVATE, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_SENSITIVE, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_SIGN, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
    };
    int pubtsize = SLHDSA_PUBKEY_TMPL_SIZE;
    int privtsize = SLHDSA_PRIVKEY_TMPL_SIZE;

    P11PROV_debug("slhdsa gen %p %p %p", ctx, cb_fn, cb_arg);

    ret = p11prov_kmgmt_gen(ctx, pubkey_template, privkey_template, pubtsize,
                            privtsize, cb_fn, cb_arg, &key);
    if (ret != CKR_OK) {
        P11PROV_raise(ctx->provctx, ret, "slhdsa Key generation failed");
        return NULL;
    }
    return key;
}

static void *p11prov_slhdsa_load(const void *reference, size_t reference_sz)
{
    return p11prov_kmgmt_load(reference, reference_sz, CKK_SLH_DSA);
}

static int p11prov_slhdsa_match(const void *keydata1, const void *keydata2,
                                int selection)
{
    return p11prov_kmgmt_match(keydata1, keydata2, CKK_SLH_DSA, selection);
}

static int p11prov_slhdsa_import(void *keydata, int selection,
                                 const OSSL_PARAM params[])
{
    p11prov_obj_set_get_find_attrs((P11PROV_OBJ *)keydata,
                                   p11prov_slhdsa_get_find_attrs);
    return p11prov_kmgmt_import(CKK_SLH_DSA, CK_UNAVAILABLE_INFORMATION,
                                OSSL_PKEY_PARAM_PRIV_KEY, keydata, selection,
                                params);
}

static const OSSL_PARAM *p11prov_slhdsa_import_types(int selection)
{
    static const OSSL_PARAM p11prov_slhdsa_imp_key_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END,
    };
    P11PROV_debug("slhdsa import types");
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
        return p11prov_slhdsa_imp_key_types;
    }
    return NULL;
}

static const OSSL_PARAM *p11prov_slhdsa_export_types(int selection)
{
    static const OSSL_PARAM p11prov_slhdsa_exp_key_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END,
    };
    P11PROV_debug("slhdsa export types");
    if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return p11prov_slhdsa_exp_key_types;
    }
    return NULL;
}

static int p11prov_slhdsa_get_params(void *keydata, OSSL_PARAM params[])
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    CK_ULONG param_set = p11prov_obj_get_key_param_set(key);
    OSSL_PARAM *p;
    int ret;

    P11PROV_debug("slhdsa get params %p", keydata);

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
        case CKP_SLH_DSA_SHA2_128S:
        case CKP_SLH_DSA_SHA2_128F:
        case CKP_SLH_DSA_SHAKE_128S:
        case CKP_SLH_DSA_SHAKE_128F:
            secbits = 128;
            break;
        case CKP_SLH_DSA_SHA2_192S:
        case CKP_SLH_DSA_SHA2_192F:
        case CKP_SLH_DSA_SHAKE_192S:
        case CKP_SLH_DSA_SHAKE_192F:
            secbits = 192;
            break;
        case CKP_SLH_DSA_SHA2_256S:
        case CKP_SLH_DSA_SHA2_256F:
        case CKP_SLH_DSA_SHAKE_256S:
        case CKP_SLH_DSA_SHAKE_256F:
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
        case CKP_SLH_DSA_SHA2_128S:
        case CKP_SLH_DSA_SHAKE_128S:
            sigsize = SLH_DSA_SHA2_128S_SIG_SIZE;
            break;
        case CKP_SLH_DSA_SHA2_128F:
        case CKP_SLH_DSA_SHAKE_128F:
            sigsize = SLH_DSA_SHA2_128F_SIG_SIZE;
            break;
        case CKP_SLH_DSA_SHA2_192S:
        case CKP_SLH_DSA_SHAKE_192S:
            sigsize = SLH_DSA_SHA2_192S_SIG_SIZE;
            break;
        case CKP_SLH_DSA_SHA2_192F:
        case CKP_SLH_DSA_SHAKE_192F:
            sigsize = SLH_DSA_SHA2_192F_SIG_SIZE;
            break;
        case CKP_SLH_DSA_SHA2_256S:
        case CKP_SLH_DSA_SHAKE_256S:
            sigsize = SLH_DSA_SHA2_256S_SIG_SIZE;
            break;
        case CKP_SLH_DSA_SHA2_256F:
        case CKP_SLH_DSA_SHAKE_256F:
            sigsize = SLH_DSA_SHA2_256F_SIG_SIZE;
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

static const OSSL_PARAM *p11prov_slhdsa_gettable_params(void *provctx)
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

#define p11prov_slhdsa_gen_cleanup p11prov_kmgmt_gen_cleanup
#define p11prov_slhdsa_free p11prov_kmgmt_free
#define p11prov_slhdsa_has p11prov_kmgmt_has
#define p11prov_slhdsa_export p11prov_kmgmt_export

#define SLHDSA_KEYMGMT_FUNCTIONS(name) \
    const OSSL_DISPATCH p11prov_slhdsa_##name##_keymgmt_functions[] = { \
        DISPATCH_KEYMGMT_ELEM(slhdsa_##name, NEW, new), \
        DISPATCH_KEYMGMT_ELEM(slhdsa_##name, GEN_INIT, gen_init), \
        DISPATCH_KEYMGMT_ELEM(slhdsa, GEN, gen), \
        DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_CLEANUP, gen_cleanup), \
        DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_SET_PARAMS, gen_set_params), \
        DISPATCH_KEYMGMT_ELEM(slhdsa, GEN_SETTABLE_PARAMS, \
                              gen_settable_params), \
        DISPATCH_KEYMGMT_ELEM(slhdsa, LOAD, load), \
        DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free), \
        DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has), \
        DISPATCH_KEYMGMT_ELEM(slhdsa, MATCH, match), \
        DISPATCH_KEYMGMT_ELEM(slhdsa, IMPORT, import), \
        DISPATCH_KEYMGMT_ELEM(slhdsa, IMPORT_TYPES, import_types), \
        DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export), \
        DISPATCH_KEYMGMT_ELEM(slhdsa, EXPORT_TYPES, export_types), \
        DISPATCH_KEYMGMT_ELEM(slhdsa, GET_PARAMS, get_params), \
        DISPATCH_KEYMGMT_ELEM(slhdsa, GETTABLE_PARAMS, gettable_params), \
        { 0, NULL }, \
    };

SLHDSA_KEYMGMT_FUNCTIONS(sha2_128s)
SLHDSA_KEYMGMT_FUNCTIONS(sha2_128f)
SLHDSA_KEYMGMT_FUNCTIONS(sha2_192s)
SLHDSA_KEYMGMT_FUNCTIONS(sha2_192f)
SLHDSA_KEYMGMT_FUNCTIONS(sha2_256s)
SLHDSA_KEYMGMT_FUNCTIONS(sha2_256f)
SLHDSA_KEYMGMT_FUNCTIONS(shake_128s)
SLHDSA_KEYMGMT_FUNCTIONS(shake_128f)
SLHDSA_KEYMGMT_FUNCTIONS(shake_192s)
SLHDSA_KEYMGMT_FUNCTIONS(shake_192f)
SLHDSA_KEYMGMT_FUNCTIONS(shake_256s)
SLHDSA_KEYMGMT_FUNCTIONS(shake_256f)
