/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "platform/endian.h"
#include <string.h>

DISPATCH_KEYMGMT_FN(common, gen_set_params);
DISPATCH_KEYMGMT_FN(common, gen_cleanup);

DISPATCH_KEYMGMT_FN(rsa, new);
DISPATCH_KEYMGMT_FN(rsa, gen_init);
DISPATCH_KEYMGMT_FN(rsa, gen);
DISPATCH_KEYMGMT_FN(rsa, gen_settable_params);
DISPATCH_KEYMGMT_FN(rsa, load);
DISPATCH_KEYMGMT_FN(rsa, free);
DISPATCH_KEYMGMT_FN(rsa, has);
DISPATCH_KEYMGMT_FN(rsa, import);
DISPATCH_KEYMGMT_FN(rsa, import_types);
DISPATCH_KEYMGMT_FN(rsa, export);
DISPATCH_KEYMGMT_FN(rsa, export_types);
DISPATCH_KEYMGMT_FN(rsa, query_operation_name);
DISPATCH_KEYMGMT_FN(rsa, get_params);
DISPATCH_KEYMGMT_FN(rsa, gettable_params);

#define X962_PRIME_OID 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01
#define X962_PRIME_OID_LEN 7
#define SECG_OID 0x2B, 0x81, 0x04, 0x00
#define SECG_OID_LEN 4
#define OID_ID 0x06

#define DEF_EC_PARAM(cname, base, num) \
    const CK_BYTE cname##_param[] = { OID_ID, base##_LEN + 1, base, num }
#define NAME_TO_PARAM(cname) \
    { \
        .name = #cname, .ec_param = cname##_param, \
        .ec_param_size = sizeof(cname##_param) \
    }
#define ALIAS_TO_PARAM(alias, cname) \
    { \
        .name = alias, .ec_param = cname##_param, \
        .ec_param_size = sizeof(cname##_param) \
    }

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

struct key_generator {
    P11PROV_CTX *provctx;

    CK_KEY_TYPE type;

    char *label;
    CK_BYTE *id;
    CK_ULONG id_len;

    CK_MECHANISM mechanism;

    union {
        struct {
            CK_ULONG modulus_bits;
            CK_BYTE exponent[8];
            CK_ULONG exponent_size;
            CK_MECHANISM_TYPE *allowed_types;
            CK_ULONG allowed_types_size;
        } rsa;
        struct {
            const CK_BYTE *ec_params;
            CK_ULONG ec_params_size;
        } ec;
    } data;

    OSSL_CALLBACK *cb_fn;
    void *cb_arg;
};

static void *p11prov_common_gen_init(void *provctx, int selection,
                                     CK_KEY_TYPE type,
                                     const OSSL_PARAM params[])
{
    struct key_generator *ctx = NULL;
    /* big endian 65537 */
    unsigned char def_e[] = { 0x01, 0x00, 0x01 };
    int ret;

    P11PROV_debug("rsa gen_init %p", provctx);

    ret = p11prov_ctx_status(provctx);
    if (ret != CKR_OK) {
        return NULL;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
        P11PROV_raise(provctx, CKR_ARGUMENTS_BAD, "Unsupported selection");
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(struct key_generator));
    if (ctx == NULL) {
        P11PROV_raise(provctx, CKR_HOST_MEMORY, "Failed to get key_generator");
        return NULL;
    }
    ctx->provctx = (P11PROV_CTX *)provctx;
    ctx->type = type;

    /* set defaults */
    switch (type) {
    case CKK_RSA:
        ctx->mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        ctx->data.rsa.modulus_bits = 2048;
        ctx->data.rsa.exponent_size = sizeof(def_e);
        memcpy(ctx->data.rsa.exponent, def_e, ctx->data.rsa.exponent_size);
        break;
    case CKK_EC:
        ctx->mechanism.mechanism = CKM_EC_KEY_PAIR_GEN;
        ctx->data.ec.ec_params = prime256v1_param;
        ctx->data.ec.ec_params_size = sizeof(prime256v1_param);
        break;
    default:
        P11PROV_raise(provctx, CKR_ARGUMENTS_BAD, "Invalid type %lu", type);
        OPENSSL_free(ctx);
        return NULL;
    }

    ret = p11prov_common_gen_set_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        p11prov_common_gen_cleanup(ctx);
        ctx = NULL;
    }
    return ctx;
}

static int p11prov_common_gen_set_params(void *genctx,
                                         const OSSL_PARAM params[])
{
    struct key_generator *ctx = (struct key_generator *)genctx;
    const OSSL_PARAM *p;
    int ret;

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, P11PROV_PARAM_KEY_LABEL);
    if (p) {
        ret = OSSL_PARAM_get_utf8_string(p, &ctx->label, 0);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate_const(params, P11PROV_PARAM_KEY_ID);
    if (p) {
        size_t id_len;
        ret = OSSL_PARAM_get_octet_string(p, (void **)&ctx->id, 0, &id_len);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        ctx->id_len = id_len;
    }
    switch (ctx->type) {
    case CKK_RSA:
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS);
        if (p) {
            size_t nbits;
            ret = OSSL_PARAM_get_size_t(p, &nbits);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
            ctx->data.rsa.modulus_bits = nbits;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PRIMES);
        if (p) {
            size_t primes;
            ret = OSSL_PARAM_get_size_t(p, &primes);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
            if (primes != 2) {
                P11PROV_raise(ctx->provctx, CKR_ARGUMENTS_BAD,
                              "No multi-prime support");
                return RET_OSSL_ERR;
            }
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
        if (p) {
            if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
                if (p->data_size > 8) {
                    P11PROV_raise(ctx->provctx, CKR_ARGUMENTS_BAD,
                                  "Unsupported RSA exponent size");
                    return RET_OSSL_ERR;
                }
                /* fix byte order if necessary while copying */
                byteswap_buf(p->data, ctx->data.rsa.exponent, p->data_size);
                ctx->data.rsa.exponent_size = p->data_size;
            } else {
                P11PROV_raise(ctx->provctx, CKR_ARGUMENTS_BAD,
                              "Only unsigned integers for RSA Exponent");
                return RET_OSSL_ERR;
            }
        }
        break;
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
    default:
        P11PROV_raise(ctx->provctx, CKR_ARGUMENTS_BAD,
                      "Invalid key gen type %lu", ctx->type);
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static CK_RV common_gen_callback(void *cbarg)
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

static void *p11prov_common_gen(struct key_generator *ctx,
                                CK_ATTRIBUTE *pubkey_template,
                                CK_ATTRIBUTE *privkey_template, int pubtsize,
                                int privtsize, OSSL_CALLBACK *cb_fn,
                                void *cb_arg)
{
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_BYTE id[16];
    CK_BYTE_PTR id_ptr;
    CK_ULONG id_len;
    CK_OBJECT_HANDLE privkey;
    CK_OBJECT_HANDLE pubkey;
    P11PROV_SESSION *session = NULL;
    CK_SESSION_HANDLE sh;
    P11PROV_OBJ *key = NULL;
    CK_RV ret;

    /* FIXME: how do we get a URI to select the right slot ? */
    ret = p11prov_get_session(ctx->provctx, &slotid, NULL, NULL,
                              ctx->mechanism.mechanism, NULL, NULL, true, true,
                              &session);
    if (ret != CKR_OK) {
        return NULL;
    }

    if (cb_fn) {
        ctx->cb_fn = cb_fn;
        ctx->cb_arg = cb_arg;
        p11prov_session_set_callback(session, common_gen_callback, ctx);
    }

    sh = p11prov_session_handle(session);

    if (ctx->id_len != 0) {
        id_ptr = ctx->id;
        id_len = ctx->id_len;
    } else {
        /* generate unique id for the key */
        ret = p11prov_GenerateRandom(ctx->provctx, sh, id, sizeof(id));
        if (ret != CKR_OK) {
            p11prov_return_session(session);
            return NULL;
        }
        id_ptr = id;
        id_len = 16;
    }
    pubkey_template[pubtsize].type = CKA_ID;
    pubkey_template[pubtsize].pValue = id_ptr;
    pubkey_template[pubtsize].ulValueLen = id_len;
    pubtsize++;
    privkey_template[privtsize].type = CKA_ID;
    privkey_template[privtsize].pValue = id_ptr;
    privkey_template[privtsize].ulValueLen = id_len;
    privtsize++;
    if (ctx->label) {
        CK_ULONG len = strlen(ctx->label);
        pubkey_template[pubtsize].type = CKA_LABEL;
        pubkey_template[pubtsize].pValue = ctx->label;
        pubkey_template[pubtsize].ulValueLen = len;
        pubtsize++;
        privkey_template[privtsize].type = CKA_LABEL;
        privkey_template[privtsize].pValue = ctx->label;
        privkey_template[privtsize].ulValueLen = len;
        privtsize++;
    }

    ret = p11prov_GenerateKeyPair(ctx->provctx, sh, &ctx->mechanism,
                                  pubkey_template, pubtsize, privkey_template,
                                  privtsize, &pubkey, &privkey);
    if (ret != CKR_OK) {
        p11prov_return_session(session);
        return NULL;
    }

    ret = p11prov_obj_from_handle(ctx->provctx, session, privkey, &key);
    if (ret != CKR_OK) {
        p11prov_return_session(session);
        return NULL;
    }

    p11prov_return_session(session);
    return key;
}

static void p11prov_common_gen_cleanup(void *genctx)
{
    struct key_generator *ctx = (struct key_generator *)genctx;

    P11PROV_debug("common gen_cleanup %p", genctx);

    if (ctx->label) {
        OPENSSL_free(ctx->label);
    }
    if (ctx->id) {
        OPENSSL_clear_free(ctx->id, ctx->id_len);
    }
    if (ctx->type == CKK_RSA) {
        if (ctx->data.rsa.allowed_types_size) {
            OPENSSL_free(ctx->data.rsa.allowed_types);
        }
    }

    OPENSSL_clear_free(genctx, sizeof(struct key_generator));
}

/* RSA gen key */
static void *p11prov_rsa_gen_init(void *provctx, int selection,
                                  const OSSL_PARAM params[])
{
    P11PROV_debug("rsa gen_init %p", provctx);

    return p11prov_common_gen_init(provctx, selection, CKK_RSA, params);
}

static void *p11prov_rsa_gen(void *genctx, OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    struct key_generator *ctx = (struct key_generator *)genctx;
    CK_BBOOL val_true = CK_TRUE;
    /* CK_BBOOL val_false = CK_FALSE; */

    /* always leave space for CKA_ID and CKA_LABEL */
#define RSA_PUBKEY_TMPL_SIZE 6
    CK_ATTRIBUTE pubkey_template[RSA_PUBKEY_TMPL_SIZE + 2] = {
        { CKA_ENCRYPT, &val_true, sizeof(val_true) },
        { CKA_VERIFY, &val_true, sizeof(val_true) },
        { CKA_WRAP, &val_true, sizeof(val_true) },
        { CKA_TOKEN, &val_true, sizeof(CK_BBOOL) },
        { CKA_MODULUS_BITS, &ctx->data.rsa.modulus_bits,
          sizeof(ctx->data.rsa.modulus_bits) },
        { CKA_PUBLIC_EXPONENT, &ctx->data.rsa.exponent,
          ctx->data.rsa.exponent_size },
    };
#define RSA_PRIVKEY_TMPL_SIZE 6
    CK_ATTRIBUTE privkey_template[RSA_PRIVKEY_TMPL_SIZE + 2] = {
        { CKA_TOKEN, &val_true, sizeof(CK_BBOOL) },
        { CKA_PRIVATE, &val_true, sizeof(CK_BBOOL) },
        { CKA_SENSITIVE, &val_true, sizeof(CK_BBOOL) },
        { CKA_DECRYPT, &val_true, sizeof(CK_BBOOL) },
        { CKA_SIGN, &val_true, sizeof(CK_BBOOL) },
        { CKA_UNWRAP, &val_true, sizeof(CK_BBOOL) },
        /* TODO?
         * CKA_SUBJECT
         * CKA_COPYABLE = true ?
         */
    };
    int pubtsize = RSA_PUBKEY_TMPL_SIZE;
    int privtsize = RSA_PRIVKEY_TMPL_SIZE;

    P11PROV_debug("rsa gen %p %p %p", genctx, cb_fn, cb_arg);

    return p11prov_common_gen(ctx, pubkey_template, privkey_template, pubtsize,
                              privtsize, cb_fn, cb_arg);
}

static const OSSL_PARAM *p11prov_rsa_gen_settable_params(void *genctx,
                                                         void *provctx)
{
    static OSSL_PARAM p11prov_rsa_params[] = {
        OSSL_PARAM_utf8_string(P11PROV_PARAM_KEY_LABEL, NULL, 0),
        OSSL_PARAM_octet_string(P11PROV_PARAM_KEY_ID, NULL, 0),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END,
    };
    return p11prov_rsa_params;
}

static void *p11prov_rsa_new(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    CK_RV ret;

    P11PROV_debug("rsa new");

    ret = p11prov_ctx_status(ctx);
    if (ret != CKR_OK) {
        return NULL;
    }

    return p11prov_obj_new(provctx, CK_UNAVAILABLE_INFORMATION,
                           CK_INVALID_HANDLE, CK_UNAVAILABLE_INFORMATION);
}

static void p11prov_rsa_free(void *key)
{
    P11PROV_debug("rsa free %p", key);
    p11prov_obj_free((P11PROV_OBJ *)key);
}

static void *p11prov_rsa_load(const void *reference, size_t reference_sz)
{
    P11PROV_OBJ *key;

    P11PROV_debug("rsa load %p, %ld", reference, reference_sz);

    /* the contents of the reference is the address to our object */
    key = p11prov_obj_from_reference(reference, reference_sz);
    if (key) {
        CK_KEY_TYPE type = CK_UNAVAILABLE_INFORMATION;

        type = p11prov_obj_get_key_type(key);
        if (type == CKK_RSA) {
            /* add ref count */
            key = p11prov_obj_ref_no_cache(key);
        } else {
            key = NULL;
        }
    }

    return key;
}

static int p11prov_rsa_has(const void *keydata, int selection)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;

    P11PROV_debug("rsa has %p %d", key, selection);

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

static int p11prov_rsa_import(void *keydata, int selection,
                              const OSSL_PARAM params[])
{
    P11PROV_debug("rsa import %p", keydata);
    return RET_OSSL_ERR;
}

#define PUBLIC_PARAMS \
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS

static int p11prov_rsa_export(void *keydata, int selection,
                              OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    P11PROV_CTX *ctx = p11prov_obj_get_prov_ctx(key);

    P11PROV_debug("rsa export %p", keydata);

    if (key == NULL) {
        return RET_OSSL_ERR;
    }

    if (p11prov_ctx_allow_export(ctx) & DISALLOW_EXPORT_PUBLIC) {
        return RET_OSSL_ERR;
    }

    /* if anything else is asked for we can't provide it, so be strict */
    if ((selection & ~(PUBLIC_PARAMS)) == 0) {
        return p11prov_obj_export_public_rsa_key(key, cb_fn, cb_arg);
    }

    return RET_OSSL_ERR;
}

static const OSSL_PARAM p11prov_rsa_key_types[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_END,
};

static const OSSL_PARAM *p11prov_rsa_import_types(int selection)
{
    P11PROV_debug("rsa import types");
    if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return p11prov_rsa_key_types;
    }
    return NULL;
}

static const OSSL_PARAM *p11prov_rsa_export_types(int selection)
{
    P11PROV_debug("rsa export types");
    if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return p11prov_rsa_key_types;
    }
    return NULL;
}

static const char *p11prov_rsa_query_operation_name(int operation_id)
{
    return P11PROV_NAME_RSA;
}

static int p11prov_rsa_secbits(int bits)
{
    /* common values from various NIST documents */
    switch (bits) {
    case 2048:
        return 112;
    case 3072:
        return 128;
    case 4096:
        return 152;
    case 6144:
        return 176;
    case 7680:
        return 192;
    case 8192:
        return 200;
    case 15360:
        return 256;
    }

    /* TODO: do better calculations,
     * see ossl_ifc_ffc_compute_security_bits() */

    /* NOLINTBEGIN(readability-braces-around-statements) */
    if (bits >= 15360) return 256;
    if (bits >= 8192) return 200;
    if (bits >= 7680) return 192;
    if (bits >= 6144) return 176;
    if (bits >= 4096) return 152;
    if (bits >= 3072) return 128;
    if (bits >= 2048) return 112;
    /* NOLINTEND(readability-braces-around-statements) */

    return 0;
}

static int p11prov_rsa_get_params(void *keydata, OSSL_PARAM params[])
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    CK_ATTRIBUTE *modulus;
    OSSL_PARAM *p;
    int ret;

    P11PROV_debug("rsa get params %p", keydata);

    if (key == NULL) {
        return RET_OSSL_ERR;
    }

    modulus = p11prov_obj_get_attr(key, CKA_MODULUS);
    if (modulus == NULL) {
        ret = RET_OSSL_ERR;
        return ret;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p) {
        /* TODO: may want to try to get CKA_MODULUS_BITS,
         * and fallback only if unavailable */
        ret = OSSL_PARAM_set_int(p, modulus->ulValueLen * 8);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p) {
        /* TODO: as above, plus use log() for intermediate values */
        int secbits = p11prov_rsa_secbits(modulus->ulValueLen * 8);
        ret = OSSL_PARAM_set_int(p, secbits);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p) {
        ret = OSSL_PARAM_set_int(p, modulus->ulValueLen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_rsa_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        /* OSSL_PKEY_PARAM_DEFAULT_DIGEST,
         * OSSL_PKEY_PARAM_RSA_N,
         * OSSL_PKEY_PARAM_RSA_E, */
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_rsa_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(rsa, NEW, new),
    DISPATCH_KEYMGMT_ELEM(rsa, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(rsa, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(common, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(rsa, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(common, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(rsa, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(rsa, FREE, free),
    DISPATCH_KEYMGMT_ELEM(rsa, HAS, has),
    DISPATCH_KEYMGMT_ELEM(rsa, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(rsa, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(rsa, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(rsa, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(rsa, QUERY_OPERATION_NAME, query_operation_name),
    DISPATCH_KEYMGMT_ELEM(rsa, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(rsa, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};

DISPATCH_KEYMGMT_FN(rsapss, gen);
DISPATCH_KEYMGMT_FN(rsa, gen_settable_params);

static CK_RV set_default_rsapss_mechanisms(struct key_generator *ctx)
{
    CK_MECHANISM_TYPE rsapss_mechs[] = {
        CKM_SHA1_RSA_PKCS_PSS,     CKM_SHA224_RSA_PKCS_PSS,
        CKM_SHA256_RSA_PKCS_PSS,   CKM_SHA384_RSA_PKCS_PSS,
        CKM_SHA512_RSA_PKCS_PSS,   CKM_SHA3_224_RSA_PKCS_PSS,
        CKM_SHA3_256_RSA_PKCS_PSS, CKM_SHA3_384_RSA_PKCS_PSS,
        CKM_SHA3_512_RSA_PKCS_PSS
    };

    ctx->data.rsa.allowed_types = OPENSSL_malloc(sizeof(rsapss_mechs));
    if (ctx->data.rsa.allowed_types == NULL) {
        P11PROV_raise(ctx->provctx, CKR_HOST_MEMORY, "Allocating data");
        return CKR_HOST_MEMORY;
    }
    memcpy(ctx->data.rsa.allowed_types, rsapss_mechs, sizeof(rsapss_mechs));
    ctx->data.rsa.allowed_types_size =
        sizeof(rsapss_mechs) / sizeof(CK_MECHANISM_TYPE);

    return CKR_OK;
}

static void *p11prov_rsapss_gen(void *genctx, OSSL_CALLBACK *cb_fn,
                                void *cb_arg)
{
    struct key_generator *ctx = (struct key_generator *)genctx;
    CK_BBOOL token_supports_allowed_mechs = CK_TRUE;
    P11PROV_OBJ *key = NULL;
    CK_RV ret;

    key = p11prov_rsa_gen(genctx, cb_fn, cb_arg);
    if (!key) {
        return NULL;
    }

    /* params could already be caying pss restriction. If allowed_types
     * is already set, skip setting defaults */
    if (!ctx->data.rsa.allowed_types) {
        ret = set_default_rsapss_mechanisms(ctx);
        if (ret != CKR_OK) {
            P11PROV_raise(ctx->provctx, ret, "Failed to get pss params");
            goto done;
        }
    }

    ret = p11prov_token_sup_attr(ctx->provctx, p11prov_obj_get_slotid(key),
                                 GET_ATTR, CKA_ALLOWED_MECHANISMS,
                                 &token_supports_allowed_mechs);
    if (ret != CKR_OK) {
        P11PROV_raise(ctx->provctx, ret, "Failed to probe quirk");
        goto done;
    }

    if (token_supports_allowed_mechs == CK_TRUE) {
        CK_ATTRIBUTE template[] = {
            { CKA_ALLOWED_MECHANISMS, ctx->data.rsa.allowed_types,
              ctx->data.rsa.allowed_types_size },
        };
        CK_ULONG tsize = 1;

        ret = p11prov_obj_set_attributes(ctx->provctx, NULL, key, template,
                                         tsize);
        if (ret != CKR_OK) {
            P11PROV_debug("Failed to add RSAPSS restrictions (%lu)", ret);
            if (ret == CKR_ATTRIBUTE_TYPE_INVALID) {
                /* set quirk to disable future attempts for this token */
                token_supports_allowed_mechs = CK_FALSE;
                (void)p11prov_token_sup_attr(
                    ctx->provctx, p11prov_obj_get_slotid(key), SET_ATTR,
                    CKA_ALLOWED_MECHANISMS, &token_supports_allowed_mechs);
            }
        }
    }

    ret = CKR_OK;

done:
    if (ret != CKR_OK) {
        p11prov_obj_free(key);
        key = NULL;
    }
    return key;
}

static const OSSL_PARAM *p11prov_rsapss_gen_settable_params(void *genctx,
                                                            void *provctx)
{
    static OSSL_PARAM p11prov_rsapss_params[] = {
        OSSL_PARAM_utf8_string(P11PROV_PARAM_KEY_LABEL, NULL, 0),
        OSSL_PARAM_octet_string(P11PROV_PARAM_KEY_ID, NULL, 0),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, NULL, 0),
        /* unsupportable yet:
         * OSSL_PKEY_PARAM_RSA_DIGEST_PROPS
         * OSSL_PKEY_PARAM_RSA_MASKGENFUNC
         * OSSL_PKEY_PARAM_RSA_MGF1_DIGEST
         * OSSL_PKEY_PARAM_RSA_PSS_SALTLEN */
        OSSL_PARAM_END,
    };
    return p11prov_rsapss_params;
}

const OSSL_DISPATCH p11prov_rsapss_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(rsa, NEW, new),
    DISPATCH_KEYMGMT_ELEM(rsa, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(rsapss, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(common, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(rsapss, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(common, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(rsa, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(rsa, FREE, free),
    DISPATCH_KEYMGMT_ELEM(rsa, HAS, has),
    DISPATCH_KEYMGMT_ELEM(rsa, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(rsa, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(rsa, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(rsa, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(rsa, QUERY_OPERATION_NAME, query_operation_name),
    DISPATCH_KEYMGMT_ELEM(rsa, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(rsa, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};

DISPATCH_KEYMGMT_FN(ec, new);
DISPATCH_KEYMGMT_FN(ec, gen_init);
DISPATCH_KEYMGMT_FN(ec, gen);
DISPATCH_KEYMGMT_FN(ec, gen_settable_params);
DISPATCH_KEYMGMT_FN(ec, load);
DISPATCH_KEYMGMT_FN(ec, free);
DISPATCH_KEYMGMT_FN(ec, has);
DISPATCH_KEYMGMT_FN(ec, import);
DISPATCH_KEYMGMT_FN(ec, import_types);
DISPATCH_KEYMGMT_FN(ec, export);
DISPATCH_KEYMGMT_FN(ec, export_types);
DISPATCH_KEYMGMT_FN(ec, query_operation_name);
DISPATCH_KEYMGMT_FN(ec, get_params);
DISPATCH_KEYMGMT_FN(ec, gettable_params);

static void *p11prov_ec_new(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    CK_RV ret;

    P11PROV_debug("ec new");

    ret = p11prov_ctx_status(ctx);
    if (ret != CKR_OK) {
        return NULL;
    }

    return NULL;
}

static void *p11prov_ec_gen_init(void *provctx, int selection,
                                 const OSSL_PARAM params[])
{
    P11PROV_debug("ec gen_init %p", provctx);

    return p11prov_common_gen_init(provctx, selection, CKK_EC, params);
}

static void *p11prov_ec_gen(void *genctx, OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    struct key_generator *ctx = (struct key_generator *)genctx;
    CK_BBOOL val_true = CK_TRUE;
    /* CK_BBOOL val_false = CK_FALSE; */

    /* always leave space for CKA_ID and CKA_LABEL */
#define EC_PUBKEY_TMPL_SIZE 5
    CK_ATTRIBUTE pubkey_template[EC_PUBKEY_TMPL_SIZE + 2] = {
        { CKA_TOKEN, &val_true, sizeof(CK_BBOOL) },
        { CKA_DERIVE, &val_true, sizeof(val_true) },
        { CKA_VERIFY, &val_true, sizeof(val_true) },
        { CKA_WRAP, &val_true, sizeof(val_true) },
        { CKA_EC_PARAMS, (CK_BYTE *)ctx->data.ec.ec_params,
          ctx->data.ec.ec_params_size },
    };
#define EC_PRIVKEY_TMPL_SIZE 6
    CK_ATTRIBUTE privkey_template[EC_PRIVKEY_TMPL_SIZE + 2] = {
        { CKA_TOKEN, &val_true, sizeof(CK_BBOOL) },
        { CKA_PRIVATE, &val_true, sizeof(CK_BBOOL) },
        { CKA_SENSITIVE, &val_true, sizeof(CK_BBOOL) },
        { CKA_SIGN, &val_true, sizeof(CK_BBOOL) },
        { CKA_UNWRAP, &val_true, sizeof(CK_BBOOL) },
        /* TODO?
         * CKA_SUBJECT
         * CKA_COPYABLE = true ?
         */
    };
    int pubtsize = EC_PUBKEY_TMPL_SIZE;
    int privtsize = EC_PRIVKEY_TMPL_SIZE;

    P11PROV_debug("ec gen %p %p %p", ctx, cb_fn, cb_arg);

    return p11prov_common_gen(ctx, pubkey_template, privkey_template, pubtsize,
                              privtsize, cb_fn, cb_arg);
}

static const OSSL_PARAM *p11prov_ec_gen_settable_params(void *genctx,
                                                        void *provctx)
{
    static OSSL_PARAM p11prov_ec_params[] = {
        OSSL_PARAM_utf8_string(P11PROV_PARAM_KEY_LABEL, NULL, 0),
        OSSL_PARAM_octet_string(P11PROV_PARAM_KEY_ID, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_END,
    };
    return p11prov_ec_params;
}

static void p11prov_ec_free(void *key)
{
    P11PROV_debug("ec free %p", key);
    p11prov_obj_free((P11PROV_OBJ *)key);
}

static void *p11prov_ec_load(const void *reference, size_t reference_sz)
{
    P11PROV_OBJ *key;

    P11PROV_debug("ec load %p, %ld", reference, reference_sz);

    /* the contents of the reference is the address to our object */
    key = p11prov_obj_from_reference(reference, reference_sz);
    if (key) {
        CK_KEY_TYPE type = CK_UNAVAILABLE_INFORMATION;

        type = p11prov_obj_get_key_type(key);
        if (type == CKK_EC) {
            /* add ref count */
            key = p11prov_obj_ref_no_cache(key);
        } else {
            key = NULL;
        }
    }

    return key;
}

static int p11prov_ec_has(const void *keydata, int selection)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;

    P11PROV_debug("ec has %p %d", key, selection);

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

static int p11prov_ec_import(void *keydata, int selection,
                             const OSSL_PARAM params[])
{
    P11PROV_debug("ec import %p", keydata);
    return RET_OSSL_ERR;
}

static int p11prov_ec_export(void *keydata, int selection, OSSL_CALLBACK *cb_fn,
                             void *cb_arg)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    P11PROV_CTX *ctx = p11prov_obj_get_prov_ctx(key);

    P11PROV_debug("ec export %p", keydata);

    if (key == NULL) {
        return RET_OSSL_ERR;
    }

    if (p11prov_ctx_allow_export(ctx) & DISALLOW_EXPORT_PUBLIC) {
        return RET_OSSL_ERR;
    }

    /* this will return the public EC_POINT as well as DOMAIN_PARAMTERS */
    if ((selection & ~(PUBLIC_PARAMS)) == 0) {
        return p11prov_obj_export_public_ec_key(key, cb_fn, cb_arg);
    }

    return RET_OSSL_ERR;
}

static const OSSL_PARAM p11prov_ec_key_types[] = {
    /*
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
 */
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

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_ec_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        /* OSSL_PKEY_PARAM_DEFAULT_DIGEST
         * OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY
         * OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAM
         * OSSL_PKEY_PARAM_EC_ENCODING
         * OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT
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
         * OSSL_PKEY_PARAM_EC_PUB_X
         * OSSL_PKEY_PARAM_EC_PUB_Y
         */
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_ec_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(ec, NEW, new),
    DISPATCH_KEYMGMT_ELEM(ec, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(ec, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(common, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(common, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(ec, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(ec, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(ec, FREE, free),
    DISPATCH_KEYMGMT_ELEM(ec, HAS, has),
    DISPATCH_KEYMGMT_ELEM(ec, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(ec, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(ec, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(ec, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(ec, QUERY_OPERATION_NAME, query_operation_name),
    DISPATCH_KEYMGMT_ELEM(ec, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(ec, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};

DISPATCH_KEYMGMT_FN(hkdf, new);
DISPATCH_KEYMGMT_FN(hkdf, free);
DISPATCH_KEYMGMT_FN(hkdf, query_operation_name);
DISPATCH_KEYMGMT_FN(hkdf, has);

const void *p11prov_hkdf_static_ctx = NULL;

static void *p11prov_hkdf_new(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    CK_RV ret;

    P11PROV_debug("hkdf keymgmt new");

    ret = p11prov_ctx_status(ctx);
    if (ret != CKR_OK) {
        return NULL;
    }

    return (void *)&p11prov_hkdf_static_ctx;
}

static void p11prov_hkdf_free(void *kdfdata)
{
    P11PROV_debug("hkdf keymgmt free %p", kdfdata);

    if (kdfdata != &p11prov_hkdf_static_ctx) {
        P11PROV_debug("Invalid HKDF Keymgmt context: %p != %p", kdfdata,
                      &p11prov_hkdf_static_ctx);
    }
}

static const char *p11prov_hkdf_query_operation_name(int operation_id)
{
    P11PROV_debug("hkdf keymgmt query op name %d", operation_id);

    return P11PROV_NAME_HKDF;
}

static int p11prov_hkdf_has(const void *kdfdata, int selection)
{
    P11PROV_debug("hkdf keymgmt has");
    if (kdfdata != &p11prov_hkdf_static_ctx) {
        P11PROV_debug("Invalid HKDF Keymgmt context: %p != %p", kdfdata,
                      &p11prov_hkdf_static_ctx);
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

const OSSL_DISPATCH p11prov_hkdf_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(hkdf, NEW, new),
    DISPATCH_KEYMGMT_ELEM(hkdf, FREE, free),
    DISPATCH_KEYMGMT_ELEM(hkdf, QUERY_OPERATION_NAME, query_operation_name),
    DISPATCH_KEYMGMT_ELEM(hkdf, HAS, has),
    { 0, NULL },
};
