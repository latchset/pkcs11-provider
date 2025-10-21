/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "kmgmt/internal.h"

#define X962_PRIME_OID 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01
#define X962_PRIME_OID_LEN 7
#define SECG_OID 0x2B, 0x81, 0x04, 0x00
#define SECG_OID_LEN 4
#define OID_ID 0x06

#define DEF_EC_PARAM(cname, base, num) \
    const CK_BYTE cname##_param[] = { OID_ID, base##_LEN + 1, base, num }
#define NAME_TO_PARAM(cname) \
    { .name = #cname, \
      .ec_param = cname##_param, \
      .ec_param_size = sizeof(cname##_param) }
#define ALIAS_TO_PARAM(alias, cname) \
    { .name = alias, \
      .ec_param = cname##_param, \
      .ec_param_size = sizeof(cname##_param) }

DEF_EC_PARAM(secp112r1, SECG_OID, 0x06);
DEF_EC_PARAM(secp112r2, SECG_OID, 0x07);
DEF_EC_PARAM(secp128r1, SECG_OID, 0x1C);
DEF_EC_PARAM(secp128r2, SECG_OID, 0x1D);
DEF_EC_PARAM(secp160k1, SECG_OID, 0x09);
DEF_EC_PARAM(secp160r1, SECG_OID, 0x08);
DEF_EC_PARAM(secp160r2, SECG_OID, 0x1E);
DEF_EC_PARAM(secp192k1, SECG_OID, 0x1F);
DEF_EC_PARAM(secp224k1, SECG_OID, 0x20);
DEF_EC_PARAM(secp224r1, SECG_OID, 0x21);
DEF_EC_PARAM(secp256k1, SECG_OID, 0x0A);
DEF_EC_PARAM(secp384r1, SECG_OID, 0x22);
DEF_EC_PARAM(secp521r1, SECG_OID, 0x23);
DEF_EC_PARAM(prime192v1, X962_PRIME_OID, 0x01);
DEF_EC_PARAM(prime192v2, X962_PRIME_OID, 0x02);
DEF_EC_PARAM(prime192v3, X962_PRIME_OID, 0x03);
DEF_EC_PARAM(prime239v1, X962_PRIME_OID, 0x04);
DEF_EC_PARAM(prime239v2, X962_PRIME_OID, 0x05);
DEF_EC_PARAM(prime239v3, X962_PRIME_OID, 0x06);
DEF_EC_PARAM(prime256v1, X962_PRIME_OID, 0x07);

struct {
    const char *name;
    const CK_BYTE *ec_param;
    CK_ULONG ec_param_size;
} ec_name_to_params[] = {
    /* secg curves */
    NAME_TO_PARAM(secp112r1),
    NAME_TO_PARAM(secp112r2),
    NAME_TO_PARAM(secp128r1),
    NAME_TO_PARAM(secp128r2),
    NAME_TO_PARAM(secp160k1),
    NAME_TO_PARAM(secp160r1),
    NAME_TO_PARAM(secp160r2),
    NAME_TO_PARAM(secp192k1),
    NAME_TO_PARAM(secp224k1),
    NAME_TO_PARAM(secp224r1),
    NAME_TO_PARAM(secp256k1),
    NAME_TO_PARAM(secp384r1),
    NAME_TO_PARAM(secp521r1),
    /* X9.62 prime curves */
    NAME_TO_PARAM(prime192v1),
    NAME_TO_PARAM(prime192v2),
    NAME_TO_PARAM(prime192v3),
    NAME_TO_PARAM(prime239v1),
    NAME_TO_PARAM(prime239v2),
    NAME_TO_PARAM(prime239v3),
    NAME_TO_PARAM(prime256v1),
    /* NIST aliases */
    ALIAS_TO_PARAM("P-192", prime192v1),
    ALIAS_TO_PARAM("P-224", secp224r1),
    ALIAS_TO_PARAM("P-256", prime256v1),
    ALIAS_TO_PARAM("P-384", secp384r1),
    ALIAS_TO_PARAM("P-521", secp521r1),
    { NULL, NULL, 0 },
};

DISPATCH_KEYMGMT_FN(ec, new);
DISPATCH_KEYMGMT_FN(ec, gen_init);
DISPATCH_KEYMGMT_FN(ec, gen_settable_params);
DISPATCH_KEYMGMT_FN(ec, gen_set_params);
DISPATCH_KEYMGMT_FN(ec, gen);
DISPATCH_KEYMGMT_FN(ec, load);
DISPATCH_KEYMGMT_FN(ec, match);
DISPATCH_KEYMGMT_FN(ec, import);
DISPATCH_KEYMGMT_FN(ec, import_types);
DISPATCH_KEYMGMT_FN(ec, export_types);
DISPATCH_KEYMGMT_FN(ec, query_operation_name);
DISPATCH_KEYMGMT_FN(ec, get_params);
DISPATCH_KEYMGMT_FN(ec, gettable_params);
DISPATCH_KEYMGMT_FN(ec, set_params);
DISPATCH_KEYMGMT_FN(ec, settable_params);

static void *p11prov_ec_new(void *provctx)
{
    P11PROV_debug("ec new");
    return p11prov_kmgmt_new(provctx, CKK_EC);
}

static void *p11prov_ec_gen_init(void *provctx, int selection,
                                 const OSSL_PARAM params[])
{
    struct key_generator *ctx = NULL;
    int ret;

    P11PROV_debug("ec gen_init %p", provctx);

    /* we need to allow to initialize a generation of just domain parameters,
     * as this is used by OpenSSL for ECDH, to set the expected parameters
     * first and then import the received public peer key */
    if ((selection & OSSL_KEYMGMT_SELECT_ALL) == 0) {
        P11PROV_raise(provctx, CKR_ARGUMENTS_BAD, "Unsupported selection");
        return NULL;
    }

    ctx = p11prov_kmgmt_gen_init(provctx, CKK_EC, CKM_EC_KEY_PAIR_GEN);
    if (!ctx) {
        return NULL;
    }

    /* set defaults */
    ctx->data.ec.ec_params = prime256v1_param;
    ctx->data.ec.ec_params_size = sizeof(prime256v1_param);

    /* is this a parameter generator request ? */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
        ctx->data.ec.paramgen = true;
    }

    ret = p11prov_ec_gen_set_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        p11prov_kmgmt_gen_cleanup(ctx);
        ctx = NULL;
    }
    return ctx;
}

static const OSSL_PARAM *p11prov_ec_gen_settable_params(void *genctx,
                                                        void *provctx)
{
    static OSSL_PARAM p11prov_ec_params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_utf8_string(P11PROV_PARAM_URI, NULL, 0),
        OSSL_PARAM_utf8_string(P11PROV_PARAM_KEY_USAGE, NULL, 0),
        OSSL_PARAM_END,
    };
    return p11prov_ec_params;
}

#define P11PROV_ED_NAME "p11prov_edname"

static int p11prov_ec_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct key_generator *ctx = (struct key_generator *)genctx;
    const OSSL_PARAM *p;

    if (!ctx) {
        return RET_OSSL_ERR;
    }

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    switch (ctx->type) {
    case CKK_EC:
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
        if (p) {
            int i;
            if (p->data_type != OSSL_PARAM_UTF8_STRING) {
                return RET_OSSL_ERR;
            }
            for (i = 0; ec_name_to_params[i].name != NULL; i++) {
                if (strcmp(ec_name_to_params[i].name, p->data) == 0) {
                    break;
                }
            }
            if (ec_name_to_params[i].name == NULL) {
                P11PROV_raise(ctx->provctx, CKR_ARGUMENTS_BAD,
                              "Unknown Curve %*s", (int)p->data_size,
                              (char *)p->data);
                return RET_OSSL_ERR;
            }
            ctx->data.ec.ec_params = ec_name_to_params[i].ec_param;
            ctx->data.ec.ec_params_size = ec_name_to_params[i].ec_param_size;
        }
        break;
    case CKK_EC_EDWARDS:
        p = OSSL_PARAM_locate_const(params, P11PROV_ED_NAME);
        if (p) {
            if (p->data_type != OSSL_PARAM_UTF8_STRING) {
                return RET_OSSL_ERR;
            }
            if (strcmp(p->data, ED25519) == 0) {
                ctx->data.ec.ec_params = ed25519_ec_params;
                ctx->data.ec.ec_params_size = ED25519_EC_PARAMS_LEN;
            } else if (strcmp(p->data, ED448) == 0) {
                ctx->data.ec.ec_params = ed448_ec_params;
                ctx->data.ec.ec_params_size = ED448_EC_PARAMS_LEN;
            } else {
                P11PROV_raise(ctx->provctx, CKR_ARGUMENTS_BAD,
                              "Unknown edwards curve '%*s'", (int)p->data_size,
                              (char *)p->data);
                return RET_OSSL_ERR;
            }
        }
        break;
    default:
        P11PROV_raise(ctx->provctx, CKR_ARGUMENTS_BAD,
                      "Invalid key gen type %lu", ctx->type);
        return RET_OSSL_ERR;
    }

    return p11prov_kmgmt_gen_set_params(ctx, params);
}

extern const CK_BBOOL val_true;
extern const CK_BBOOL val_false;

static void *p11prov_ec_gen(void *genctx, OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    struct key_generator *ctx = (struct key_generator *)genctx;
    void *key;
    CK_RV ret;

    if (ctx->data.ec.paramgen) {
        /* OpenSSL asked for a paramgen, basically it wants an
         * empty key of a specific group that it will be filling
         * up with public params later */
        CK_ATTRIBUTE ec_params = {
            .type = CKA_EC_PARAMS,
            .pValue = (CK_VOID_PTR)ctx->data.ec.ec_params,
            .ulValueLen = (CK_ULONG)ctx->data.ec.ec_params_size,
        };

        return mock_pub_ec_key(ctx->provctx, ctx->type, &ec_params);
    }

    /* always leave space for CKA_ID and CKA_LABEL */
#define EC_PUBKEY_TMPL_SIZE 5
    CK_ATTRIBUTE pubkey_template[EC_PUBKEY_TMPL_SIZE + COMMON_TMPL_SIZE] = {
        { CKA_TOKEN, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_DERIVE, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_VERIFY, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_WRAP, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_EC_PARAMS, (CK_BYTE *)ctx->data.ec.ec_params,
          ctx->data.ec.ec_params_size },
    };
#define EC_PRIVKEY_TMPL_SIZE 6
    CK_ATTRIBUTE privkey_template[EC_PRIVKEY_TMPL_SIZE + COMMON_TMPL_SIZE] = {
        { CKA_TOKEN, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_DERIVE, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_PRIVATE, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_SENSITIVE, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_SIGN, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_UNWRAP, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        /* TODO?
         * CKA_SUBJECT
         * CKA_COPYABLE = true ?
         */
    };
    int pubtsize = EC_PUBKEY_TMPL_SIZE;
    int privtsize = EC_PRIVKEY_TMPL_SIZE;

    P11PROV_debug("ec gen %p %p %p", ctx, cb_fn, cb_arg);

    ret = p11prov_kmgmt_gen(ctx, pubkey_template, privkey_template, pubtsize,
                            privtsize, cb_fn, cb_arg, &key);
    if (ret != CKR_OK) {
        P11PROV_raise(ctx->provctx, ret, "EC Key generation failed");
        return NULL;
    }
    return key;
}

static void *p11prov_ec_load(const void *reference, size_t reference_sz)
{
    return p11prov_kmgmt_load(reference, reference_sz, CKK_EC);
}

static int p11prov_ec_match(const void *keydata1, const void *keydata2,
                            int selection)
{
    P11PROV_debug("ec match %p %p %d", keydata1, keydata2, selection);

    return p11prov_kmgmt_match(keydata1, keydata2, CKK_EC, selection);
}

static int p11prov_ec_import(void *keydata, int selection,
                             const OSSL_PARAM params[])
{
    return p11prov_kmgmt_import(CKK_EC, CK_UNAVAILABLE_INFORMATION,
                                OSSL_PKEY_PARAM_PRIV_KEY, keydata, selection,
                                params);
}

static const OSSL_PARAM p11prov_ec_key_types[] = {
    OSSL_PARAM_END,
};

static const OSSL_PARAM *p11prov_ec_import_types(int selection)
{
    P11PROV_debug("ec import types");
    if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return p11prov_ec_key_types;
    }
    return NULL;
}

static const OSSL_PARAM *p11prov_ec_export_types(int selection)
{
    P11PROV_debug("ec export types");
    if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return p11prov_ec_key_types;
    }
    return NULL;
}

static const char *p11prov_ec_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
        return P11PROV_NAME_ECDSA;
    case OSSL_OP_KEYEXCH:
        return P11PROV_NAME_ECDH;
    }
    return NULL;
}

#define CURVE_521_BITS 521
#define MAX_CURVE_BITS CURVE_521_BITS
#define MAX_CURVE_SIZE ((MAX_CURVE_BITS + 7) / 8)

static int p11prov_ec_secbits(int bits)
{
    /* common values from various NIST documents */
    if (bits < 224) {
        return 0;
    }
    if (bits < 256) {
        return 112;
    }
    if (bits < 384) {
        return 128;
    }
    if (bits < 512) {
        return 192;
    }
    return 256;
}

static int p11prov_ec_get_params(void *keydata, OSSL_PARAM params[])
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    OSSL_PARAM *p;
    CK_ULONG group_size;
    int ret;

    P11PROV_debug("ec get params %p", keydata);

    if (key == NULL) {
        return RET_OSSL_ERR;
    }

    group_size = p11prov_obj_get_key_bit_size(key);
    if (group_size == CK_UNAVAILABLE_INFORMATION) {
        return RET_OSSL_ERR;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p) {
        ret = OSSL_PARAM_set_int(p, group_size);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p) {
        /* TODO: as above, plus use log() for intermediate values */
        int secbits = p11prov_ec_secbits(group_size);
        ret = OSSL_PARAM_set_int(p, secbits);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p) {
        /* add room for ECDSA Signature DER overhead */
        CK_ULONG size = p11prov_obj_get_key_size(key);
        if (size > MAX_CURVE_SIZE) {
            /* coverity started looking for silly integer overflows */
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_int(p, 3 + (size + 4) * 2);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p) {
        const char *curve_name = p11prov_obj_get_ec_group_name(key);
        if (curve_name == NULL) {
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_utf8_string(p, curve_name);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_PUB_X);
    if (p) {
        CK_ATTRIBUTE *pub_x;

        if (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER) {
            return RET_OSSL_ERR;
        }
        ret = p11prov_obj_get_ec_public_x_y(key, &pub_x, NULL);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        p->return_size = pub_x->ulValueLen;
        if (p->data) {
            if (p->data_size < pub_x->ulValueLen) {
                return RET_OSSL_ERR;
            }
            memcpy(p->data, pub_x->pValue, pub_x->ulValueLen);
            p->data_size = pub_x->ulValueLen;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_PUB_Y);
    if (p) {
        CK_ATTRIBUTE *pub_y;

        if (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER) {
            return RET_OSSL_ERR;
        }
        ret = p11prov_obj_get_ec_public_x_y(key, NULL, &pub_y);
        if (ret != RET_OSSL_OK) {
            return ret;
        }

        p->return_size = pub_y->ulValueLen;
        if (p->data) {
            if (p->data_size < pub_y->ulValueLen) {
                return RET_OSSL_ERR;
            }
            memcpy(p->data, pub_y->pValue, pub_y->ulValueLen);
            p->data_size = pub_y->ulValueLen;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p) {
        CK_ATTRIBUTE *pub_key;

        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            return RET_OSSL_ERR;
        }

        pub_key = p11prov_obj_get_ec_public_raw(key);
        if (!pub_key) {
            return RET_OSSL_ERR;
        }

        p->return_size = pub_key->ulValueLen;
        if (p->data) {
            if (p->data_size < pub_key->ulValueLen) {
                return RET_OSSL_ERR;
            }
            memcpy(p->data, pub_key->pValue, pub_key->ulValueLen);
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT);
    if (p) {
        bool compressed = p11prov_obj_get_ec_compressed(key);
        if (compressed) {
            ret = OSSL_PARAM_set_utf8_string(p, "compressed");
        } else {
            ret = OSSL_PARAM_set_utf8_string(p, "uncompressed");
        }
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return p11prov_kmgmt_get_params(keydata, params);
}

static const OSSL_PARAM *p11prov_ec_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL,
                               0),
        /*
         * OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAM
         * OSSL_PKEY_PARAM_EC_ENCODING
         * OSSL_PKEY_PARAM_EC_FIELD_TYPE
         * OSSL_PKEY_PARAM_EC_P
         * OSSL_PKEY_PARAM_EC_A
         * OSSL_PKEY_PARAM_EC_B
         * OSSL_PKEY_PARAM_EC_GENERATOR
         * OSSL_PKEY_PARAM_EC_ORDER
         * OSSL_PKEY_PARAM_EC_COFACTOR
         * OSSL_PKEY_PARAM_EC_SEED
         * OSSL_PKEY_PARAM_PUB_KEY
         * OSSL_PKEY_PARAM_PRIV_KEY
         * OSSL_PKEY_PARAM_USE_COFACTOR_ECDH
         * OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC
         */
        OSSL_PARAM_END,
    };
    return params;
}

static int p11prov_ec_set_params(void *keydata, const OSSL_PARAM params[])
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    const OSSL_PARAM *p;

    P11PROV_debug("ec set params %p", keydata);

    if (key == NULL) {
        return RET_OSSL_ERR;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            return RET_OSSL_ERR;
        }
        if (p11prov_obj_set_ec_encoded_public_key(key, p->data, p->data_size)
            != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_ec_settable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_ec_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(ec, NEW, new),
    DISPATCH_KEYMGMT_ELEM(ec, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(ec, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(ec, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(ec, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(ec, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(ec, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(ec, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(ec, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(ec, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(ec, QUERY_OPERATION_NAME, query_operation_name),
    DISPATCH_KEYMGMT_ELEM(ec, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(ec, GETTABLE_PARAMS, gettable_params),
    DISPATCH_KEYMGMT_ELEM(ec, SET_PARAMS, set_params),
    DISPATCH_KEYMGMT_ELEM(ec, SETTABLE_PARAMS, settable_params),
    { 0, NULL },
};

DISPATCH_KEYMGMT_FN(ed, new);
DISPATCH_KEYMGMT_FN(ed25519, gen_init);
DISPATCH_KEYMGMT_FN(ed448, gen_init);
DISPATCH_KEYMGMT_FN(ed, gen_settable_params);
DISPATCH_KEYMGMT_FN(ed, load);
DISPATCH_KEYMGMT_FN(ed, match);
DISPATCH_KEYMGMT_FN(ed, import_types);
DISPATCH_KEYMGMT_FN(ed, export_types);
DISPATCH_KEYMGMT_FN(ed, get_params);
DISPATCH_KEYMGMT_FN(ed, gettable_params);
DISPATCH_KEYMGMT_FN(ed, set_params);
DISPATCH_KEYMGMT_FN(ed, settable_params);

static void *p11prov_ed_new(void *provctx)
{
    P11PROV_debug("ed new");
    return p11prov_kmgmt_new(provctx, CKK_EC_EDWARDS);
}

static void *p11prov_ed25519_gen_init(void *provctx, int selection,
                                      const OSSL_PARAM params[])
{
    struct key_generator *ctx = NULL;
    const OSSL_PARAM curve[] = { OSSL_PARAM_utf8_string(P11PROV_ED_NAME,
                                                        (void *)ED25519,
                                                        sizeof(ED25519)),
                                 OSSL_PARAM_END };
    int ret;

    P11PROV_debug("ed25519 gen_init %p", provctx);

    /* we need to allow to initialize a generation of just domain parameters,
     * as this is used by OpenSSL for ECDH, to set the expected parameters
     * first and then import the received public peer key */
    if ((selection & OSSL_KEYMGMT_SELECT_ALL) == 0) {
        P11PROV_raise(provctx, CKR_ARGUMENTS_BAD, "Unsupported selection");
        return NULL;
    }

    ctx = p11prov_kmgmt_gen_init(provctx, CKK_EC_EDWARDS,
                                 CKM_EC_EDWARDS_KEY_PAIR_GEN);
    if (!ctx) {
        return NULL;
    }

    /* is this a parameter generator request ? */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
        ctx->data.ec.paramgen = true;
    }

    /* set defaults */
    ret = p11prov_ec_gen_set_params(ctx, curve);
    if (ret != RET_OSSL_OK) {
        p11prov_kmgmt_gen_cleanup(ctx);
        return NULL;
    }

    ret = p11prov_ec_gen_set_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        p11prov_kmgmt_gen_cleanup(ctx);
        return NULL;
    }
    return ctx;
}

static void *p11prov_ed448_gen_init(void *provctx, int selection,
                                    const OSSL_PARAM params[])
{
    struct key_generator *ctx = NULL;
    const OSSL_PARAM curve[] = {
        OSSL_PARAM_utf8_string(P11PROV_ED_NAME, (void *)ED448, sizeof(ED448)),
        OSSL_PARAM_END
    };
    int ret;

    P11PROV_debug("ed448 gen_init %p", provctx);

    /* we need to allow to initialize a generation of just domain parameters,
     * as this is used by OpenSSL for ECDH, to set the expected parameters
     * first and then import the received public peer key */
    if ((selection & OSSL_KEYMGMT_SELECT_ALL) == 0) {
        P11PROV_raise(provctx, CKR_ARGUMENTS_BAD, "Unsupported selection");
        return NULL;
    }

    ctx = p11prov_kmgmt_gen_init(provctx, CKK_EC_EDWARDS,
                                 CKM_EC_EDWARDS_KEY_PAIR_GEN);
    if (!ctx) {
        return NULL;
    }

    /* is this a parameter generator request ? */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
        ctx->data.ec.paramgen = true;
    }

    /* set defaults */
    ret = p11prov_ec_gen_set_params(ctx, curve);
    if (ret != RET_OSSL_OK) {
        p11prov_kmgmt_gen_cleanup(ctx);
        return NULL;
    }

    ret = p11prov_ec_gen_set_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        p11prov_kmgmt_gen_cleanup(ctx);
        return NULL;
    }
    return ctx;
}

static const OSSL_PARAM *p11prov_ed_gen_settable_params(void *genctx,
                                                        void *provctx)
{
    static OSSL_PARAM p11prov_ed_params[] = {
        OSSL_PARAM_utf8_string(P11PROV_PARAM_URI, NULL, 0),
        OSSL_PARAM_utf8_string(P11PROV_PARAM_KEY_USAGE, NULL, 0),
        OSSL_PARAM_END,
    };
    return p11prov_ed_params;
}

static void *p11prov_ed_load(const void *reference, size_t reference_sz)
{
    return p11prov_kmgmt_load(reference, reference_sz, CKK_EC_EDWARDS);
}

static int p11prov_ed_match(const void *keydata1, const void *keydata2,
                            int selection)
{
    return p11prov_kmgmt_match(keydata1, keydata2, CKK_EC_EDWARDS, selection);
}

static int p11prov_ed_import(void *keydata, int selection,
                             const OSSL_PARAM params[])
{
    return p11prov_kmgmt_import(CKK_EC_EDWARDS, CK_UNAVAILABLE_INFORMATION,
                                OSSL_PKEY_PARAM_PRIV_KEY, keydata, selection,
                                params);
}

static const OSSL_PARAM *p11prov_ed_import_types(int selection)
{
    static const OSSL_PARAM p11prov_ed_imp_key_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END,
    };
    P11PROV_debug("ed import types");
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
        return p11prov_ed_imp_key_types;
    }
    return NULL;
}

static const OSSL_PARAM *p11prov_ed_export_types(int selection)
{
    static const OSSL_PARAM p11prov_ed_exp_key_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END,
    };
    P11PROV_debug("ed export types");
    if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return p11prov_ed_exp_key_types;
    }
    return NULL;
}

static const char *p11prov_ed25519_query_operation_name(int operation_id)
{
    if (operation_id == OSSL_OP_SIGNATURE) {
        return P11PROV_NAME_ED25519;
    }
    return NULL;
}

static const char *p11prov_ed448_query_operation_name(int operation_id)
{
    if (operation_id == OSSL_OP_SIGNATURE) {
        return P11PROV_NAME_ED448;
    }
    return NULL;
}

static int p11prov_ed_get_params(void *keydata, OSSL_PARAM params[])
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    OSSL_PARAM *p;
    CK_ULONG group_size;
    int ret;

    P11PROV_debug("ed get params %p", keydata);

    if (key == NULL) {
        return RET_OSSL_ERR;
    }

    group_size = p11prov_obj_get_key_bit_size(key);
    if (group_size == CK_UNAVAILABLE_INFORMATION) {
        return RET_OSSL_ERR;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p) {
        ret = OSSL_PARAM_set_int(p, group_size);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p) {
        int secbits;
        if (group_size == ED448_BIT_SIZE) {
            secbits = ED448_SEC_BITS;
        } else if (group_size == ED25519_BIT_SIZE) {
            secbits = ED25519_SEC_BITS;
        } else {
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_int(p, secbits);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p) {
        int sigsize;
        if (group_size == ED448_BIT_SIZE) {
            sigsize = ED448_SIG_SIZE;
        } else if (group_size == ED25519_BIT_SIZE) {
            sigsize = ED25519_SIG_SIZE;
        } else {
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
        ret = p11prov_obj_get_ed_pub_key(key, &pub);
        if (ret != RET_OSSL_OK) {
            return ret;
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

static const OSSL_PARAM *p11prov_ed_gettable_params(void *provctx)
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

static int p11prov_ed_set_params(void *keydata, const OSSL_PARAM params[])
{
    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_ed_settable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_ed25519_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(ed, NEW, new),
    DISPATCH_KEYMGMT_ELEM(ed25519, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(ec, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(ec, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(ed, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(ed, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(ed, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(ed, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(ed, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(ed, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(ed25519, QUERY_OPERATION_NAME, query_operation_name),
    DISPATCH_KEYMGMT_ELEM(ed, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(ed, GETTABLE_PARAMS, gettable_params),
    DISPATCH_KEYMGMT_ELEM(ed, SET_PARAMS, set_params),
    DISPATCH_KEYMGMT_ELEM(ed, SETTABLE_PARAMS, settable_params),
    /* TODO: validate, dup? */
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_ed448_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(ed, NEW, new),
    DISPATCH_KEYMGMT_ELEM(ed448, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(ec, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(kmgmt, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(ec, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(ed, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(ed, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(ed, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(ed, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(ed, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(ed, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(ed448, QUERY_OPERATION_NAME, query_operation_name),
    DISPATCH_KEYMGMT_ELEM(ed, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(ed, GETTABLE_PARAMS, gettable_params),
    DISPATCH_KEYMGMT_ELEM(ed, SET_PARAMS, set_params),
    DISPATCH_KEYMGMT_ELEM(ed, SETTABLE_PARAMS, settable_params),
    /* TODO: validate, dup? */
    { 0, NULL },
};
