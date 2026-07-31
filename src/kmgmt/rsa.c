/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "platform/endian.h"
#include "kmgmt/internal.h"

DISPATCH_KEYMGMT_FN(rsa, new);
DISPATCH_KEYMGMT_FN(rsa, gen_cleanup);
DISPATCH_KEYMGMT_FN(rsa, gen_init);
DISPATCH_KEYMGMT_FN(rsa, gen_settable_params);
DISPATCH_KEYMGMT_FN(rsa, gen_set_params);
DISPATCH_KEYMGMT_FN(rsa, gen);
DISPATCH_KEYMGMT_FN(rsa, load);
DISPATCH_KEYMGMT_FN(rsa, match);
DISPATCH_KEYMGMT_FN(rsa, import);
DISPATCH_KEYMGMT_FN(rsa, import_types);
DISPATCH_KEYMGMT_FN(rsa, export_types);
DISPATCH_KEYMGMT_FN(rsa, query_operation_name);
DISPATCH_KEYMGMT_FN(rsa, get_params);
DISPATCH_KEYMGMT_FN(rsa, gettable_params);

static void *p11prov_rsa_new(void *provctx)
{
    P11PROV_debug("rsa new");
    return p11prov_kmgmt_new(provctx, CKK_RSA);
}

static void p11prov_rsa_gen_cleanup(void *genctx)
{
    struct key_generator *ctx = (struct key_generator *)genctx;

    P11PROV_debug("rsa gen_cleanup %p", genctx);

    if (ctx->data.rsa.allowed_types_size) {
        OPENSSL_free(ctx->data.rsa.allowed_types);
    }
    p11prov_kmgmt_gen_cleanup(ctx);
}

/* RSA gen key */
static struct key_generator *p11prov_rsa_gen_init_int(void *provctx,
                                                      int selection)
{
    struct key_generator *ctx = NULL;
    /* big endian 65537 */
    unsigned char def_e[] = { 0x01, 0x00, 0x01 };

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
        P11PROV_raise(provctx, CKR_ARGUMENTS_BAD, "Unsupported selection");
        return NULL;
    }

    ctx = p11prov_kmgmt_gen_init(provctx, CKK_RSA, CKM_RSA_PKCS_KEY_PAIR_GEN);
    if (!ctx) {
        return NULL;
    }

    /* set defaults */
    ctx->data.rsa.modulus_bits = 2048;
    ctx->data.rsa.exponent_size = sizeof(def_e);
    memcpy(ctx->data.rsa.exponent, def_e, ctx->data.rsa.exponent_size);

    return ctx;
}

static void *p11prov_rsa_gen_init(void *provctx, int selection,
                                  const OSSL_PARAM params[])
{
    struct key_generator *ctx = NULL;
    int ret;

    P11PROV_debug("rsa gen_init %p", provctx);

    ctx = p11prov_rsa_gen_init_int(provctx, selection);
    if (!ctx) {
        return NULL;
    }

    ret = p11prov_rsa_gen_set_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        p11prov_rsa_gen_cleanup(ctx);
        ctx = NULL;
    }
    return ctx;
}

static const OSSL_PARAM *p11prov_rsa_gen_settable_params(void *genctx,
                                                         void *provctx)
{
    static OSSL_PARAM p11prov_rsa_params[] = {
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_utf8_string(P11PROV_PARAM_URI, NULL, 0),
        OSSL_PARAM_utf8_string(P11PROV_PARAM_KEY_USAGE, NULL, 0),
        OSSL_PARAM_END,
    };
    return p11prov_rsa_params;
}

static int p11prov_rsa_gen_set_params(void *genctx, const OSSL_PARAM params[])
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

    return p11prov_kmgmt_gen_set_params(ctx, params);
}

extern const CK_BBOOL val_true;
extern const CK_BBOOL val_false;

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

    return p11prov_kmgmt_gen(ctx, pubkey_template, privkey_template, pubtsize,
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

static void *p11prov_rsa_load(const void *reference, size_t reference_sz)
{
    return p11prov_kmgmt_load(reference, reference_sz, CKK_RSA);
}

static int p11prov_rsa_match(const void *keydata1, const void *keydata2,
                             int selection)
{
    return p11prov_kmgmt_match(keydata1, keydata2, CKK_RSA, selection);
}

static int p11prov_rsa_import(void *keydata, int selection,
                              const OSSL_PARAM params[])
{
    return p11prov_kmgmt_import(CKK_RSA, CK_UNAVAILABLE_INFORMATION,
                                OSSL_PKEY_PARAM_RSA_D, keydata, selection,
                                params);
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
    /* TODO: do better calculations,
     * see ossl_ifc_ffc_compute_security_bits() */

    /* common values from various NIST documents */
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

    return p11prov_kmgmt_get_params(keydata, params);
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
    DISPATCH_KEYMGMT_ELEM(rsa, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(rsa, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(rsa, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(rsa, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(rsa, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(rsa, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(rsa, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(rsa, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(rsa, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(rsa, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(rsa, QUERY_OPERATION_NAME, query_operation_name),
    DISPATCH_KEYMGMT_ELEM(rsa, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(rsa, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};

DISPATCH_KEYMGMT_FN(rsapss, gen_init);
DISPATCH_KEYMGMT_FN(rsapss, gen_settable_params);
DISPATCH_KEYMGMT_FN(rsapss, gen_set_params);
DISPATCH_KEYMGMT_FN(rsapss, gen);

const CK_MECHANISM_TYPE p11prov_rsapss_mechs[P11PROV_N_RSAPSS_MECHS] = {
    CKM_SHA1_RSA_PKCS_PSS,     CKM_SHA224_RSA_PKCS_PSS,
    CKM_SHA256_RSA_PKCS_PSS,   CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512_RSA_PKCS_PSS,   CKM_SHA3_224_RSA_PKCS_PSS,
    CKM_SHA3_256_RSA_PKCS_PSS, CKM_SHA3_384_RSA_PKCS_PSS,
    CKM_SHA3_512_RSA_PKCS_PSS, CKM_RSA_PKCS_PSS
};

static CK_RV set_default_rsapss_mechanisms(struct key_generator *ctx)
{
    size_t mechs_size = sizeof(CK_MECHANISM_TYPE) * P11PROV_N_RSAPSS_MECHS;
    ctx->data.rsa.allowed_types = OPENSSL_malloc(mechs_size);
    if (ctx->data.rsa.allowed_types == NULL) {
        P11PROV_raise(ctx->provctx, CKR_HOST_MEMORY, "Allocating data");
        return CKR_HOST_MEMORY;
    }
    memcpy(ctx->data.rsa.allowed_types, p11prov_rsapss_mechs, mechs_size);
    ctx->data.rsa.allowed_types_size = mechs_size;

    return CKR_OK;
}

static void *p11prov_rsapss_gen_init(void *provctx, int selection,
                                     const OSSL_PARAM params[])
{
    struct key_generator *ctx = NULL;
    int ret;

    P11PROV_debug("rsa-pss gen_init %p", provctx);

    ctx = p11prov_rsa_gen_init_int(provctx, selection);
    if (!ctx) {
        return NULL;
    }

    ret = p11prov_rsapss_gen_set_params(ctx, params);
    if (ret != RET_OSSL_OK) {
        p11prov_rsa_gen_cleanup(ctx);
        ctx = NULL;
    }
    return ctx;
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

static const OSSL_PARAM *p11prov_rsapss_gen_settable_params(void *genctx,
                                                            void *provctx)
{
    static OSSL_PARAM p11prov_rsapss_params[] = {
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, NULL, 0),
        /* unsupportable yet:
         * OSSL_PKEY_PARAM_RSA_DIGEST_PROPS
         * OSSL_PKEY_PARAM_RSA_MASKGENFUNC
         * OSSL_PKEY_PARAM_RSA_MGF1_DIGEST
         * OSSL_PKEY_PARAM_RSA_PSS_SALTLEN */
        OSSL_PARAM_utf8_string(P11PROV_PARAM_URI, NULL, 0),
        OSSL_PARAM_utf8_string(P11PROV_PARAM_KEY_USAGE, NULL, 0),
        OSSL_PARAM_END,
    };
    return p11prov_rsapss_params;
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

    return p11prov_rsa_gen_set_params(ctx, params);
}

const OSSL_DISPATCH p11prov_rsapss_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(rsa, NEW, new),
    DISPATCH_KEYMGMT_ELEM(rsapss, GEN_INIT, gen_init),
    DISPATCH_KEYMGMT_ELEM(rsapss, GEN, gen),
    DISPATCH_KEYMGMT_ELEM(rsapss, GEN_SET_PARAMS, gen_set_params),
    DISPATCH_KEYMGMT_ELEM(rsapss, GEN_SETTABLE_PARAMS, gen_settable_params),
    DISPATCH_KEYMGMT_ELEM(rsa, GEN_CLEANUP, gen_cleanup),
    DISPATCH_KEYMGMT_ELEM(rsa, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(rsa, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(rsa, IMPORT, import),
    DISPATCH_KEYMGMT_ELEM(rsa, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(rsa, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(rsa, QUERY_OPERATION_NAME, query_operation_name),
    DISPATCH_KEYMGMT_ELEM(rsa, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(rsa, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};
