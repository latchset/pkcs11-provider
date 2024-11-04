/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "platform/endian.h"
#include "openssl/rand.h"
#include <string.h>

#define DFLT_DIGEST "SHA256"

DISPATCH_KEYMGMT_FN(common, gen_set_params);
DISPATCH_KEYMGMT_FN(common, gen_cleanup);

DISPATCH_KEYMGMT_FN(rsa, new);
DISPATCH_KEYMGMT_FN(rsa, gen_init);
DISPATCH_KEYMGMT_FN(rsa, gen);
DISPATCH_KEYMGMT_FN(rsa, gen_settable_params);
DISPATCH_KEYMGMT_FN(rsa, load);
DISPATCH_KEYMGMT_FN(rsa, free);
DISPATCH_KEYMGMT_FN(rsa, has);
DISPATCH_KEYMGMT_FN(rsa, match);
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

    P11PROV_URI *uri;
    char *key_usage;

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

static int p11prov_common_gen_set_params(void *genctx,
                                         const OSSL_PARAM params[])
{
    struct key_generator *ctx = (struct key_generator *)genctx;
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
    case CKK_EC_EDWARDS:
        p = OSSL_PARAM_locate_const(params, "p11prov_edname");
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

/* Common attributes that may currently be added to the template
 * CKA_ID
 * CKA_LABEL
 */
#define COMMON_TMPL_SIZE 2

const CK_BBOOL val_true = CK_TRUE;
const CK_BBOOL val_false = CK_FALSE;
#define DISCARD_CONST(x) (void *)(x)

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
static CK_RV common_key_usage_to_tmpl(struct key_generator *ctx,
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

    if (!ctx->key_usage) {
        /* leave defaults as set by templates */
        return CKR_OK;
    }

    str = ctx->key_usage;
    len = strlen(ctx->key_usage);
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

static int p11prov_common_gen(struct key_generator *ctx,
                              CK_ATTRIBUTE *pubkey_template,
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

    ret = common_key_usage_to_tmpl(ctx, pubkey_template, privkey_template,
                                   pubtsize, privtsize);
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
        p11prov_session_set_callback(session, common_gen_callback, ctx);
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

    ret = p11prov_merge_pub_attrs_into_priv(pub_key, priv_key);

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

static void p11prov_common_gen_cleanup(void *genctx)
{
    struct key_generator *ctx = (struct key_generator *)genctx;

    P11PROV_debug("common gen_cleanup %p", genctx);

    OPENSSL_free(ctx->key_usage);
    p11prov_uri_free(ctx->uri);

    if (ctx->type == CKK_RSA) {
        if (ctx->data.rsa.allowed_types_size) {
            OPENSSL_free(ctx->data.rsa.allowed_types);
        }
    }

    OPENSSL_clear_free(genctx, sizeof(struct key_generator));
}

static void *p11prov_common_load(const void *reference, size_t reference_sz,
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

static int p11prov_common_match(const void *keydata1, const void *keydata2,
                                CK_KEY_TYPE type, int selection)
{
    P11PROV_OBJ *key1 = (P11PROV_OBJ *)keydata1;
    P11PROV_OBJ *key2 = (P11PROV_OBJ *)keydata2;
    int cmp_type = OBJ_CMP_KEY_TYPE;

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

/* RSA gen key */
static void *p11prov_rsa_gen_init(void *provctx, int selection,
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
    ctx->type = CKK_RSA;

    /* set defaults */
    ctx->mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    ctx->data.rsa.modulus_bits = 2048;
    ctx->data.rsa.exponent_size = sizeof(def_e);
    memcpy(ctx->data.rsa.exponent, def_e, ctx->data.rsa.exponent_size);

    ret = p11prov_common_gen_set_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        p11prov_common_gen_cleanup(ctx);
        ctx = NULL;
    }
    return ctx;
}

static int p11prov_rsa_gen_internal(void *genctx, OSSL_CALLBACK *cb_fn,
                                    void *cb_arg, void **key,
                                    bool add_allow_mechs)
{
    struct key_generator *ctx = (struct key_generator *)genctx;

    /* always leave space for CKA_ID and CKA_LABEL */
#define RSA_PUBKEY_TMPL_SIZE 6
    CK_ATTRIBUTE pubkey_template[RSA_PUBKEY_TMPL_SIZE + COMMON_TMPL_SIZE] = {
        { CKA_ENCRYPT, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_VERIFY, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_WRAP, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_TOKEN, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_MODULUS_BITS, &ctx->data.rsa.modulus_bits,
          sizeof(ctx->data.rsa.modulus_bits) },
        { CKA_PUBLIC_EXPONENT, &ctx->data.rsa.exponent,
          ctx->data.rsa.exponent_size },
    };
#define RSA_PRIVKEY_TMPL_SIZE 6
#define RSA_PRIVKEY_MAX RSA_PRIVKEY_TMPL_SIZE + 1 + COMMON_TMPL_SIZE
    CK_ATTRIBUTE privkey_template[RSA_PRIVKEY_MAX] = {
        { CKA_TOKEN, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_PRIVATE, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_SENSITIVE, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_DECRYPT, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_SIGN, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        { CKA_UNWRAP, DISCARD_CONST(&val_true), sizeof(CK_BBOOL) },
        /* 7. Optional CKA_ALLOWED_MECHANISMS */
        /* TODO?
         * CKA_SUBJECT
         * CKA_COPYABLE = true ?
         */
    };

    int pubtsize = RSA_PUBKEY_TMPL_SIZE;
    int privtsize = RSA_PRIVKEY_TMPL_SIZE;

    if (add_allow_mechs) {
        privkey_template[privtsize].type = CKA_ALLOWED_MECHANISMS;
        privkey_template[privtsize].pValue =
            DISCARD_CONST(ctx->data.rsa.allowed_types);
        privkey_template[privtsize].ulValueLen =
            ctx->data.rsa.allowed_types_size;
        privtsize++;
    }

    P11PROV_debug("rsa gen %p %p %p", genctx, cb_fn, cb_arg);

    return p11prov_common_gen(ctx, pubkey_template, privkey_template, pubtsize,
                              privtsize, cb_fn, cb_arg, key);
}

static void *p11prov_rsa_gen(void *genctx, OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    struct key_generator *ctx = (struct key_generator *)genctx;
    void *key;
    CK_RV ret;

    ret = p11prov_rsa_gen_internal(genctx, cb_fn, cb_arg, &key, false);
    if (ret != CKR_OK) {
        P11PROV_raise(ctx->provctx, ret, "RSA Key Gen failed");
        return NULL;
    }
    return key;
}

static const OSSL_PARAM *p11prov_rsa_gen_settable_params(void *genctx,
                                                         void *provctx)
{
    static OSSL_PARAM p11prov_rsa_params[] = {
        OSSL_PARAM_utf8_string(P11PROV_PARAM_URI, NULL, 0),
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
                           CK_P11PROV_IMPORTED_HANDLE,
                           CK_UNAVAILABLE_INFORMATION);
}

static void p11prov_rsa_free(void *key)
{
    P11PROV_debug("rsa free %p", key);
    p11prov_obj_free((P11PROV_OBJ *)key);
}

static void *p11prov_rsa_load(const void *reference, size_t reference_sz)
{
    P11PROV_debug("rsa load %p, %ld", reference, reference_sz);
    return p11prov_common_load(reference, reference_sz, CKK_RSA);
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

static int p11prov_rsa_match(const void *keydata1, const void *keydata2,
                             int selection)
{
    P11PROV_debug("rsa match %p %p %d", keydata1, keydata2, selection);

    return p11prov_common_match(keydata1, keydata2, CKK_RSA, selection);
}

static int p11prov_rsa_import(void *keydata, int selection,
                              const OSSL_PARAM params[])
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_RV rv;

    P11PROV_debug("rsa import %p", key);

    if (!key) {
        return RET_OSSL_ERR;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        class = CKO_PRIVATE_KEY;
    }

    /* NOTE: the following is needed because of bug:
     * https://github.com/openssl/openssl/issues/21596
     * it can be removed once we can depend on a recent enough version
     * after it is fixed */
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        const OSSL_PARAM *p;
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D);
        if (!p) {
            /* not really a private key */
            class = CKO_PUBLIC_KEY;
        }
    }

    rv = p11prov_obj_import_key(key, CKK_RSA, class, params);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

#define PUBLIC_PARAMS \
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS

static int p11prov_rsa_export(void *keydata, int selection,
                              OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    P11PROV_CTX *ctx = p11prov_obj_get_prov_ctx(key);
    CK_OBJECT_CLASS class = p11prov_obj_get_class(key);

    P11PROV_debug("rsa export %p", keydata);

    if (key == NULL) {
        return RET_OSSL_ERR;
    }

    if (p11prov_ctx_allow_export(ctx) & DISALLOW_EXPORT_PUBLIC) {
        return RET_OSSL_ERR;
    }

    /* if anything else is asked for we can't provide it, so be strict */
    if ((class == CKO_PUBLIC_KEY) || (selection & ~(PUBLIC_PARAMS)) == 0) {
        return p11prov_obj_export_public_key(key, CKK_RSA, true, cb_fn, cb_arg);
    }

    return RET_OSSL_ERR;
}

#define RSA_KEY_ATTRS_SIZE 2
static const OSSL_PARAM p11prov_rsa_key_types[RSA_KEY_ATTRS_SIZE + 1] = {
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
    if (!modulus) {
        return RET_OSSL_ERR;
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
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST);
    if (p) {
        ret = OSSL_PARAM_set_utf8_string(p, DFLT_DIGEST);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_N);
    if (p) {
        if (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER) {
            return RET_OSSL_ERR;
        }
        p->return_size = modulus->ulValueLen;
        if (p->data) {
            if (p->data_size < modulus->ulValueLen) {
                return RET_OSSL_ERR;
            }
            byteswap_buf(modulus->pValue, p->data, modulus->ulValueLen);
            p->data_size = modulus->ulValueLen;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_E);
    if (p) {
        CK_ATTRIBUTE *exp;

        if (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER) {
            return RET_OSSL_ERR;
        }
        exp = p11prov_obj_get_attr(key, CKA_PUBLIC_EXPONENT);
        if (!exp) {
            return RET_OSSL_ERR;
        }
        p->return_size = exp->ulValueLen;
        if (p->data) {
            if (p->data_size < exp->ulValueLen) {
                return RET_OSSL_ERR;
            }
            byteswap_buf(exp->pValue, p->data, exp->ulValueLen);
            p->data_size = exp->ulValueLen;
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
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        /* PKCS#11 does not have restrictions associated to keys so
         * we can't support OSSL_PKEY_PARAM_MANDATORY_DIGEST yet */
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
    DISPATCH_KEYMGMT_ELEM(rsa, MATCH, match),
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
        CKM_SHA3_512_RSA_PKCS_PSS, CKM_RSA_PKCS_PSS
    };

    ctx->data.rsa.allowed_types = OPENSSL_malloc(sizeof(rsapss_mechs));
    if (ctx->data.rsa.allowed_types == NULL) {
        P11PROV_raise(ctx->provctx, CKR_HOST_MEMORY, "Allocating data");
        return CKR_HOST_MEMORY;
    }
    memcpy(ctx->data.rsa.allowed_types, rsapss_mechs, sizeof(rsapss_mechs));
    ctx->data.rsa.allowed_types_size = sizeof(rsapss_mechs);

    return CKR_OK;
}

static void *p11prov_rsapss_gen(void *genctx, OSSL_CALLBACK *cb_fn,
                                void *cb_arg)
{
    struct key_generator *ctx = (struct key_generator *)genctx;
    CK_BBOOL token_supports_allowed_mechs = CK_TRUE;
    bool set_quirk = false;
    void *key = NULL;
    CK_RV ret;

    /* check if we can add CKA_ALLOWED_MECHANISMS at all */
    ret = p11prov_token_sup_attr(ctx->provctx, p11prov_obj_get_slotid(key),
                                 GET_ATTR, CKA_ALLOWED_MECHANISMS,
                                 &token_supports_allowed_mechs);
    if (ret != CKR_OK) {
        P11PROV_raise(ctx->provctx, ret,
                      "Failed to probe CKA_ALLOWED_MECHANISMS quirk");
        goto done;
    }

    if (token_supports_allowed_mechs) {
        /* We always want to restrict PSS keys to just the PSS mechanisms.
         * If a specific restriction is not already set then set defaults */
        if (!ctx->data.rsa.allowed_types) {
            ret = set_default_rsapss_mechanisms(ctx);
            if (ret != CKR_OK) {
                P11PROV_raise(ctx->provctx, ret,
                              "Failed to set default pss params");
                goto done;
            }
        }

        ret = p11prov_rsa_gen_internal(genctx, cb_fn, cb_arg, &key, true);
        switch (ret) {
        case CKR_OK:
            break;
        case CKR_ATTRIBUTE_TYPE_INVALID:
            /* Failed: This may be because the token does not support
             * CKA_ALLOWED_MECHANISMS, so we retry again later without it. */
            P11PROV_debug("Failed to Generate PSS key with restrictions");

            token_supports_allowed_mechs = CK_FALSE;
            /* if the quirk has never been set we'll get back what we
             * defaulted to, if that is the case then set the quirk.
             * Otherwise the quirk was successfully probed earlier
             * and we'll ignore setting anything as this may also be
             * a fluke or a key specific failure */
            ret = p11prov_token_sup_attr(
                ctx->provctx, p11prov_obj_get_slotid(key), GET_ATTR,
                CKA_ALLOWED_MECHANISMS, &token_supports_allowed_mechs);
            if (ret != CKR_OK) {
                P11PROV_raise(ctx->provctx, ret, "Failed to probe quirk");
            } else if (token_supports_allowed_mechs == CK_FALSE) {
                /* The previous check didn't hit a stored quirk, so
                 * signal to set one later based on the outcome of the
                 * next attempt. */
                set_quirk = true;
            }
            break;
        default:
            /* In theory we should consider this error fatal, but given
             * NSS sotoken returns CKR_GENERAL_ERROR just because it does
             * not understand one attribute in the template we better
             * retry anyway, as other tokens may return other errors too.
             * The only penalty is that we won't set the quirk and keep
             * retrying because we can't be sure the attribute is not
             * valid in general ... */
            break;
        }
    }

    if (!key) {
        ret = p11prov_rsa_gen_internal(genctx, cb_fn, cb_arg, &key, false);
        if (ret != CKR_OK) {
            goto done;
        }

        if (set_quirk) {
            token_supports_allowed_mechs = CK_FALSE;
            (void)p11prov_token_sup_attr(
                ctx->provctx, p11prov_obj_get_slotid(key), SET_ATTR,
                CKA_ALLOWED_MECHANISMS, &token_supports_allowed_mechs);
        }
    }

    ret = CKR_OK;

done:
    if (ret != CKR_OK) {
        P11PROV_raise(ctx->provctx, ret, "Failed to generate RSA-PSS key");
        return NULL;
    }
    return key;
}

static int p11prov_rsapss_gen_set_params(void *genctx,
                                         const OSSL_PARAM params[])
{
    struct key_generator *ctx = (struct key_generator *)genctx;
    const OSSL_PARAM *p;
    int ret;

    if (!ctx) {
        return RET_OSSL_ERR;
    }

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DIGEST);
    if (p) {
        CK_MECHANISM_TYPE digest_mech = CK_UNAVAILABLE_INFORMATION;
        CK_MECHANISM_TYPE allowed_mech = CK_UNAVAILABLE_INFORMATION;
        const char *digest = NULL;
        CK_RV rv;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        rv = p11prov_digest_get_by_name(digest, &digest_mech);
        if (rv != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
        allowed_mech = p11prov_digest_to_rsapss_mech(digest_mech);
        P11PROV_debug("Restrict RSAPSS DIGEST to %s (mech: %lu)", digest,
                      allowed_mech);
        if (allowed_mech == CK_UNAVAILABLE_INFORMATION) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
        /* overwrites any previous setting */
        ctx->data.rsa.allowed_types_size = sizeof(CK_MECHANISM_TYPE);
        ctx->data.rsa.allowed_types = OPENSSL_realloc(
            ctx->data.rsa.allowed_types, ctx->data.rsa.allowed_types_size);

        if (!ctx->data.rsa.allowed_types) {
            ctx->data.rsa.allowed_types_size = 0;
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return RET_OSSL_ERR;
        }
        ctx->data.rsa.allowed_types[0] = allowed_mech;
    }

    return p11prov_common_gen_set_params(genctx, params);
}

static const OSSL_PARAM *p11prov_rsapss_gen_settable_params(void *genctx,
                                                            void *provctx)
{
    static OSSL_PARAM p11prov_rsapss_params[] = {
        OSSL_PARAM_utf8_string(P11PROV_PARAM_URI, NULL, 0),
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
    DISPATCH_KEYMGMT_ELEM(rsapss, GEN_SET_PARAMS, gen_set_params),
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
DISPATCH_KEYMGMT_FN(ec, match);
DISPATCH_KEYMGMT_FN(ec, import);
DISPATCH_KEYMGMT_FN(ec, import_types);
DISPATCH_KEYMGMT_FN(ec, export);
DISPATCH_KEYMGMT_FN(ec, export_types);
DISPATCH_KEYMGMT_FN(ec, query_operation_name);
DISPATCH_KEYMGMT_FN(ec, get_params);
DISPATCH_KEYMGMT_FN(ec, gettable_params);
DISPATCH_KEYMGMT_FN(ec, set_params);
DISPATCH_KEYMGMT_FN(ec, settable_params);

static void *p11prov_ec_new(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    CK_RV ret;

    P11PROV_debug("ec new");

    ret = p11prov_ctx_status(ctx);
    if (ret != CKR_OK) {
        return NULL;
    }

    return p11prov_obj_new(provctx, CK_UNAVAILABLE_INFORMATION,
                           CK_P11PROV_IMPORTED_HANDLE,
                           CK_UNAVAILABLE_INFORMATION);
}

static void *p11prov_ec_gen_init(void *provctx, int selection,
                                 const OSSL_PARAM params[])
{
    struct key_generator *ctx = NULL;
    int ret;

    P11PROV_debug("ec gen_init %p", provctx);

    ret = p11prov_ctx_status(provctx);
    if (ret != CKR_OK) {
        return NULL;
    }

    /* we need to allow to initialize a generation of just domain parameters,
     * as this is used by OpenSSL for ECDH, to set the expected parameters
     * first and then import the received public peer key */
    if ((selection & OSSL_KEYMGMT_SELECT_ALL) == 0) {
        P11PROV_raise(provctx, CKR_ARGUMENTS_BAD, "Unsupported selection");
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(struct key_generator));
    if (ctx == NULL) {
        P11PROV_raise(provctx, CKR_HOST_MEMORY, "Failed to get key_generator");
        return NULL;
    }
    ctx->provctx = (P11PROV_CTX *)provctx;
    ctx->type = CKK_EC;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        ctx->mechanism.mechanism = CKM_EC_KEY_PAIR_GEN;
    } else {
        ctx->mechanism.mechanism = CK_UNAVAILABLE_INFORMATION;
    }

    /* set defaults */
    ctx->data.ec.ec_params = prime256v1_param;
    ctx->data.ec.ec_params_size = sizeof(prime256v1_param);

    ret = p11prov_common_gen_set_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        p11prov_common_gen_cleanup(ctx);
        ctx = NULL;
    }
    return ctx;
}

static void *p11prov_ec_gen(void *genctx, OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    struct key_generator *ctx = (struct key_generator *)genctx;
    void *key;
    CK_RV ret;

    if (ctx->mechanism.mechanism == CK_UNAVAILABLE_INFORMATION) {
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

    ret = p11prov_common_gen(ctx, pubkey_template, privkey_template, pubtsize,
                             privtsize, cb_fn, cb_arg, &key);
    if (ret != CKR_OK) {
        P11PROV_raise(ctx->provctx, ret, "EC Key generation failed");
        return NULL;
    }
    return key;
}

static const OSSL_PARAM *p11prov_ec_gen_settable_params(void *genctx,
                                                        void *provctx)
{
    static OSSL_PARAM p11prov_ec_params[] = {
        OSSL_PARAM_utf8_string(P11PROV_PARAM_URI, NULL, 0),
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
    P11PROV_debug("ec load %p, %ld", reference, reference_sz);
    return p11prov_common_load(reference, reference_sz, CKK_EC);
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

static int p11prov_ec_match(const void *keydata1, const void *keydata2,
                            int selection)
{
    P11PROV_debug("ec match %p %p %d", keydata1, keydata2, selection);

    return p11prov_common_match(keydata1, keydata2, CKK_EC, selection);
}

static int p11prov_ec_import_genr(CK_KEY_TYPE key_type, void *keydata,
                                  int selection, const OSSL_PARAM params[])
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_RV rv;

    P11PROV_debug("ec import %p", key);

    if (!key) {
        return RET_OSSL_ERR;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        class = CKO_PRIVATE_KEY;
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

    rv = p11prov_obj_import_key(key, key_type, class, params);
    if (rv != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_ec_import(void *keydata, int selection,
                             const OSSL_PARAM params[])
{
    return p11prov_ec_import_genr(CKK_EC, keydata, selection, params);
}

static int p11prov_ec_export(void *keydata, int selection, OSSL_CALLBACK *cb_fn,
                             void *cb_arg)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    P11PROV_CTX *ctx = p11prov_obj_get_prov_ctx(key);
    CK_OBJECT_CLASS class = p11prov_obj_get_class(key);

    P11PROV_debug("ec export %p", keydata);

    if (key == NULL) {
        return RET_OSSL_ERR;
    }

    if (p11prov_ctx_allow_export(ctx) & DISALLOW_EXPORT_PUBLIC) {
        return RET_OSSL_ERR;
    }

    /* this will return the public EC_POINT as well as DOMAIN_PARAMTERS */
    if ((class == CKO_PUBLIC_KEY) || (selection & ~(PUBLIC_PARAMS)) == 0) {
        return p11prov_obj_export_public_key(key, CKK_EC, true, cb_fn, cb_arg);
    }

    return RET_OSSL_ERR;
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
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST);
    if (p) {
        ret = OSSL_PARAM_set_utf8_string(p, DFLT_DIGEST);
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

    return RET_OSSL_OK;
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
    DISPATCH_KEYMGMT_ELEM(common, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(common, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(ec, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(ec, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(ec, FREE, free),
    DISPATCH_KEYMGMT_ELEM(ec, HAS, has),
    DISPATCH_KEYMGMT_ELEM(ec, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(ec, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(ec, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(ec, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(ec, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(ec, QUERY_OPERATION_NAME, query_operation_name),
    DISPATCH_KEYMGMT_ELEM(ec, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(ec, GETTABLE_PARAMS, gettable_params),
    DISPATCH_KEYMGMT_ELEM(ec, SET_PARAMS, set_params),
    DISPATCH_KEYMGMT_ELEM(ec, SETTABLE_PARAMS, settable_params),
    { 0, NULL },
};

DISPATCH_KEYMGMT_FN(ed25519, gen_init);
DISPATCH_KEYMGMT_FN(ed448, gen_init);
DISPATCH_KEYMGMT_FN(ed, gen_settable_params);
DISPATCH_KEYMGMT_FN(ed, load);
DISPATCH_KEYMGMT_FN(ed, match);
DISPATCH_KEYMGMT_FN(ed, import_types);
DISPATCH_KEYMGMT_FN(ed, export);
DISPATCH_KEYMGMT_FN(ed, export_types);
DISPATCH_KEYMGMT_FN(ed, get_params);
DISPATCH_KEYMGMT_FN(ed, gettable_params);
DISPATCH_KEYMGMT_FN(ed, set_params);
DISPATCH_KEYMGMT_FN(ed, settable_params);

static void *p11prov_ed25519_gen_init(void *provctx, int selection,
                                      const OSSL_PARAM params[])
{
    struct key_generator *ctx = NULL;
    const OSSL_PARAM curve[] = { OSSL_PARAM_utf8_string("p11prov_edname",
                                                        (void *)ED25519,
                                                        sizeof(ED25519)),
                                 OSSL_PARAM_END };
    int ret;

    P11PROV_debug("ed25519 gen_init %p", provctx);

    ret = p11prov_ctx_status(provctx);
    if (ret != CKR_OK) {
        return NULL;
    }

    /* we need to allow to initialize a generation of just domain parameters,
     * as this is used by OpenSSL for ECDH, to set the expected parameters
     * first and then import the received public peer key */
    if ((selection & OSSL_KEYMGMT_SELECT_ALL) == 0) {
        P11PROV_raise(provctx, CKR_ARGUMENTS_BAD, "Unsupported selection");
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(struct key_generator));
    if (ctx == NULL) {
        P11PROV_raise(provctx, CKR_HOST_MEMORY, "Failed to get key_generator");
        return NULL;
    }
    ctx->provctx = (P11PROV_CTX *)provctx;
    ctx->type = CKK_EC_EDWARDS;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        ctx->mechanism.mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN;
    }

    /* set defaults */
    ret = p11prov_common_gen_set_params(ctx, curve);
    if (ret != RET_OSSL_OK) {
        p11prov_common_gen_cleanup(ctx);
        return NULL;
    }

    ret = p11prov_common_gen_set_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        p11prov_common_gen_cleanup(ctx);
        return NULL;
    }
    return ctx;
}

static void *p11prov_ed448_gen_init(void *provctx, int selection,
                                    const OSSL_PARAM params[])
{
    struct key_generator *ctx = NULL;
    const OSSL_PARAM curve[] = {
        OSSL_PARAM_utf8_string("p11prov_edname", (void *)ED448, sizeof(ED448)),
        OSSL_PARAM_END
    };
    int ret;

    P11PROV_debug("ed448 gen_init %p", provctx);

    ret = p11prov_ctx_status(provctx);
    if (ret != CKR_OK) {
        return NULL;
    }

    /* we need to allow to initialize a generation of just domain parameters,
     * as this is used by OpenSSL for ECDH, to set the expected parameters
     * first and then import the received public peer key */
    if ((selection & OSSL_KEYMGMT_SELECT_ALL) == 0) {
        P11PROV_raise(provctx, CKR_ARGUMENTS_BAD, "Unsupported selection");
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(struct key_generator));
    if (ctx == NULL) {
        P11PROV_raise(provctx, CKR_HOST_MEMORY, "Failed to get key_generator");
        return NULL;
    }
    ctx->provctx = (P11PROV_CTX *)provctx;
    ctx->type = CKK_EC_EDWARDS;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        ctx->mechanism.mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN;
    }

    /* set defaults */
    ret = p11prov_common_gen_set_params(ctx, curve);
    if (ret != RET_OSSL_OK) {
        p11prov_common_gen_cleanup(ctx);
        return NULL;
    }

    ret = p11prov_common_gen_set_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        p11prov_common_gen_cleanup(ctx);
        return NULL;
    }
    return ctx;
}

static const OSSL_PARAM *p11prov_ed_gen_settable_params(void *genctx,
                                                        void *provctx)
{
    static OSSL_PARAM p11prov_ed_params[] = {
        OSSL_PARAM_utf8_string(P11PROV_PARAM_URI, NULL, 0),
        OSSL_PARAM_END,
    };
    return p11prov_ed_params;
}

static void *p11prov_ed_load(const void *reference, size_t reference_sz)
{
    P11PROV_debug("ed load %p, %ld", reference, reference_sz);
    return p11prov_common_load(reference, reference_sz, CKK_EC_EDWARDS);
}

static int p11prov_ed_match(const void *keydata1, const void *keydata2,
                            int selection)
{
    P11PROV_debug("ed match %p %p %d", keydata1, keydata2, selection);

    return p11prov_common_match(keydata1, keydata2, CKK_EC_EDWARDS, selection);
}

static int p11prov_ed_export(void *keydata, int selection, OSSL_CALLBACK *cb_fn,
                             void *cb_arg)
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    P11PROV_CTX *ctx = p11prov_obj_get_prov_ctx(key);
    CK_OBJECT_CLASS class = p11prov_obj_get_class(key);

    P11PROV_debug("ed export %p", keydata);

    if (key == NULL) {
        return RET_OSSL_ERR;
    }

    if (p11prov_ctx_allow_export(ctx) & DISALLOW_EXPORT_PUBLIC) {
        return RET_OSSL_ERR;
    }

    /* this will return the public EC_POINT */
    if ((class == CKO_PUBLIC_KEY) || (selection & ~(PUBLIC_PARAMS)) == 0) {
        return p11prov_obj_export_public_key(key, CKK_EC_EDWARDS, true, cb_fn,
                                             cb_arg);
    }

    return RET_OSSL_ERR;
}

static int p11prov_ed_import(void *keydata, int selection,
                             const OSSL_PARAM params[])
{
    return p11prov_ec_import_genr(CKK_EC_EDWARDS, keydata, selection, params);
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
    DISPATCH_KEYMGMT_ELEM(ec, NEW, new),
    DISPATCH_KEYMGMT_ELEM(ed25519, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(ec, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(common, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(common, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(ed, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(ed, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(ec, FREE, free),
    DISPATCH_KEYMGMT_ELEM(ec, HAS, has),
    DISPATCH_KEYMGMT_ELEM(ed, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(ed, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(ed, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(ed, EXPORT, export),
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
    DISPATCH_KEYMGMT_ELEM(ec, NEW, new),
    DISPATCH_KEYMGMT_ELEM(ed448, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(ec, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(common, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(common, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(ed, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(ed, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(ec, FREE, free),
    DISPATCH_KEYMGMT_ELEM(ec, HAS, has),
    DISPATCH_KEYMGMT_ELEM(ed, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(ed, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(ed, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(ed, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(ed, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(ed448, QUERY_OPERATION_NAME, query_operation_name),
    DISPATCH_KEYMGMT_ELEM(ed, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(ed, GETTABLE_PARAMS, gettable_params),
    DISPATCH_KEYMGMT_ELEM(ed, SET_PARAMS, set_params),
    DISPATCH_KEYMGMT_ELEM(ed, SETTABLE_PARAMS, settable_params),
    /* TODO: validate, dup? */
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
