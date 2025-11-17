/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "pk11_uri.h"
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

static int p11prov_print_bn(BIO *out, const OSSL_PARAM *p, const char *str,
                            int indent)
{
    BIGNUM *bn = NULL;
    int ret;

    ret = OSSL_PARAM_get_BN(p, &bn);
    if (ret != RET_OSSL_OK) {
        return RET_OSSL_ERR;
    }
    ret = ASN1_bn_print(out, str, bn, NULL, indent);
    BN_free(bn);

    return ret;
}

static int p11prov_print_buf(BIO *out, const OSSL_PARAM *p, const char *str,
                             int indent)
{
    int ret;

    if (p->data_type != OSSL_PARAM_OCTET_STRING) {
        return RET_OSSL_ERR;
    }
    BIO_printf(out, "%s\n", str);
    ret = ASN1_buf_print(out, p->data, p->data_size, indent);

    return ret;
}

static int p11prov_print_ASN1_INTEGER(BIO *out, ASN1_INTEGER *n,
                                      const char *str, int indent)
{
    BIGNUM *bn = NULL;
    int ret;

    bn = ASN1_INTEGER_to_BN(n, NULL);
    if (!bn) {
        return RET_OSSL_ERR;
    }
    ret = ASN1_bn_print(out, str, bn, NULL, indent);
    BN_free(bn);

    return ret;
}

DISPATCH_BASE_ENCODER_FN(newctx);
DISPATCH_BASE_ENCODER_FN(freectx);

DISPATCH_ENCODER_FN(common, priv_key_info, pem, does_selection);

struct p11prov_encoder_ctx {
    P11PROV_CTX *provctx;
};

static void *p11prov_encoder_newctx(void *provctx)
{
    struct p11prov_encoder_ctx *ctx;

    ctx = OPENSSL_zalloc(sizeof(struct p11prov_encoder_ctx));
    if (!ctx) {
        P11PROV_raise(provctx, CKR_HOST_MEMORY, "Allocation failed");
        return NULL;
    }
    ctx->provctx = provctx;
    return ctx;
}

static void p11prov_encoder_freectx(void *ctx)
{
    OPENSSL_free(ctx);
}

static const char *p11prov_key_type_name(P11PROV_OBJ *key)
{
    CK_KEY_TYPE type;
    CK_ULONG subtype;
    type = p11prov_obj_get_key_type(key);

    switch (type) {
    case CKK_RSA:
        return "RSA";
    case CKK_EC:
        return "EC";
    case CKK_EC_EDWARDS:
        subtype = p11prov_obj_get_key_bit_size(key);
        switch (subtype) {
        case ED25519_BIT_SIZE:
            return "ED25519";
        case ED448_BIT_SIZE:
            return "ED448";
        }
        break;
    case CKK_EC_MONTGOMERY:
        subtype = p11prov_obj_get_key_bit_size(key);
        switch (subtype) {
        case X25519_BIT_SIZE:
            return "X25519";
        case X448_BIT_SIZE:
            return "X448";
        }
        break;
    case CKK_ML_DSA:
        subtype = p11prov_obj_get_key_param_set(key);
        switch (subtype) {
        case CKP_ML_DSA_44:
            return "ML-DSA-44";
        case CKP_ML_DSA_65:
            return "ML-DSA-65";
        case CKP_ML_DSA_87:
            return "ML-DSA-87";
        }
        break;
    case CKK_ML_KEM:
        subtype = p11prov_obj_get_key_param_set(key);
        switch (subtype) {
        case CKP_ML_KEM_512:
            return "ML-KEM-512";
        case CKP_ML_KEM_768:
            return "ML-KEM-768";
        case CKP_ML_KEM_1024:
            return "ML-KEM-1024";
        }
        break;
    }
    return NULL;
}

#include "encoder.gen.c"

static P11PROV_RSA_PUBKEY *decode_rsa_pubkey(CK_ATTRIBUTE *pkeyinfo)
{
    P11PROV_RSA_PUBKEY *rsakey = NULL;
    X509_PUBKEY *pubkey = NULL;
    const unsigned char *val;
    long len;
    const unsigned char *pk;
    int pklen;

    val = pkeyinfo->pValue;
    len = pkeyinfo->ulValueLen;

    pubkey = d2i_X509_PUBKEY(NULL, &val, len);
    if (!pubkey) {
        return NULL;
    }

    if (X509_PUBKEY_get0_param(NULL, &pk, &pklen, NULL, pubkey) != 1) {
        goto done;
    }

    rsakey = d2i_P11PROV_RSA_PUBKEY(NULL, &pk, pklen);

done:
    X509_PUBKEY_free(pubkey);
    return rsakey;
}

/* Stick this one in here because the necessary functions are in
 * the generated code and it is easier this way, we may want to
 * reorganize the code later on. */
CK_RV rsa_pkeyinfo_to_attrs(CK_ATTRIBUTE *pkeyinfo, CK_ATTRIBUTE *attrs)
{
    P11PROV_RSA_PUBKEY *rsakey = NULL;
    BIGNUM *n = NULL, *e = NULL;
    CK_ATTRIBUTE *a_n = NULL;
    CK_ATTRIBUTE *a_e = NULL;
    CK_RV rv = CKR_GENERAL_ERROR;

    rsakey = decode_rsa_pubkey(pkeyinfo);

    n = ASN1_INTEGER_to_BN(rsakey->n, NULL);
    e = ASN1_INTEGER_to_BN(rsakey->e, NULL);
    if (!n || !e) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    /* modulus */
    a_n = &attrs[0];
    a_n->type = CKA_MODULUS;
    a_n->pValue = NULL;
    rv = p11prov_bn_to_attr(a_n, n);
    if (rv != CKR_OK) {
        goto done;
    }

    /* public exponent */
    a_e = &attrs[1];
    a_e->type = CKA_PUBLIC_EXPONENT;
    a_e->pValue = NULL;
    rv = p11prov_bn_to_attr(a_e, e);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = CKR_OK;

done:
    if (rv != CKR_OK) {
        if (a_n) {
            OPENSSL_free(a_n->pValue);
        }
        if (a_e) {
            OPENSSL_free(a_e->pValue);
        }
    }
    BN_free(n);
    BN_free(e);
    P11PROV_RSA_PUBKEY_free(rsakey);
    return rv;
}

int p11prov_rsa_pubkey_to_x509(X509_PUBKEY *pubkey, P11PROV_OBJ *key);
int p11prov_ec_pubkey_to_x509(X509_PUBKEY *pubkey, P11PROV_OBJ *key);
int p11prov_mldsa_pubkey_to_x509(X509_PUBKEY *pubkey, P11PROV_OBJ *key);
int p11prov_mlkem_pubkey_to_x509(X509_PUBKEY *pubkey, P11PROV_OBJ *key);

static X509_PUBKEY *p11prov_pubkey_to_x509(P11PROV_OBJ *key)
{
    X509_PUBKEY *pubkey = NULL;
    CK_KEY_TYPE type;
    int ret = RET_OSSL_ERR;

    pubkey = X509_PUBKEY_new();
    if (!pubkey) {
        return NULL;
    }

    type = p11prov_obj_get_key_type(key);
    switch (type) {
    case CKK_RSA:
        ret = p11prov_rsa_pubkey_to_x509(pubkey, key);
        break;
    case CKK_EC:
    case CKK_EC_EDWARDS:
    case CKK_EC_MONTGOMERY:
        ret = p11prov_ec_pubkey_to_x509(pubkey, key);
        break;
    case CKK_ML_DSA:
        ret = p11prov_mldsa_pubkey_to_x509(pubkey, key);
        break;
    case CKK_ML_KEM:
        ret = p11prov_mlkem_pubkey_to_x509(pubkey, key);
        break;
    default:
        break;
    }

    if (ret != RET_OSSL_OK) {
        X509_PUBKEY_free(pubkey);
        pubkey = NULL;
    }
    return pubkey;
}

static int p11prov_common_encoder_spki_der_encode(
    void *inctx, OSSL_CORE_BIO *cbio, const void *inkey,
    const OSSL_PARAM key_abstract[], int selection,
    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct p11prov_encoder_ctx *ctx = (struct p11prov_encoder_ctx *)inctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)inkey;
    CK_KEY_TYPE type;
    const char *type_name;
    CK_ATTRIBUTE *pkeyinfo = NULL;
    X509_PUBKEY *pubkey = NULL;
    BIO *out = NULL;
    int ret;

    /* we only return public key info */
    if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {
        return RET_OSSL_ERR;
    }

    type_name = p11prov_key_type_name(key);
    if (!type_name) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Unknown Key Type");
        ret = RET_OSSL_ERR;
        goto done;
    }

    P11PROV_debug("DER Encoding %s SubjectPublicKeyInfo", type_name);

    out = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cbio);
    if (!out) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to init BIO");
        ret = RET_OSSL_ERR;
        goto done;
    }

    type = p11prov_obj_get_key_type(key);
    if (type != CKK_RSA) {
        /* we exclude RSA because we need to recompute a different
         * SubjectPublicKeyInfo in the RSA-PSS case, PKCS#11 only stores
         * a RSA-PKCS SubjectPublicKeyInfo*/
        pkeyinfo = p11prov_obj_get_attr(key, CKA_PUBLIC_KEY_INFO);
    }
    if (pkeyinfo && pkeyinfo->ulValueLen > 0) {
        int len = BIO_write(out, pkeyinfo->pValue, pkeyinfo->ulValueLen);
        if (len == pkeyinfo->ulValueLen) {
            ret = RET_OSSL_OK;
        } else {
            ret = RET_OSSL_ERR;
        }
    } else {
        pubkey = p11prov_pubkey_to_x509(key);
        if (!pubkey) {
            ret = RET_OSSL_ERR;
            goto done;
        }

        ret = i2d_X509_PUBKEY_bio(out, pubkey);
    }

done:
    X509_PUBKEY_free(pubkey);
    BIO_free(out);
    return ret;
}

static int p11prov_print_public_key(const OSSL_PARAM *params, void *bio)
{
    BIO *out = (BIO *)bio;
    const OSSL_PARAM *p;
    int ret;

    /* Modulus (RSA) */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
    if (p) {
        ret = p11prov_print_bn(out, p, "Modulus:", 0);
        if (ret != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }

    /* Exponent (RSA) */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    if (p) {
        ret = p11prov_print_bn(out, p, "Exponent:", 0);
        if (ret != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }

    /* Pub key (ECC/ML-DSA/ML-KEM) */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p) {
        ret = p11prov_print_buf(out, p, "Pub:", 4);
        if (ret != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }

    /* Name (ECC) */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p) {
        const char *name;
        int nid;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &name);
        if (ret != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }

        BIO_printf(out, "ASN1 OID: %s\n", name);

        /* Print also NIST name if any */
        nid = OBJ_txt2nid(name);
        if (nid != NID_undef) {
            name = EC_curve_nid2nist(nid);
            if (name) {
                BIO_printf(out, "NIST CURVE: %s\n", name);
            }
        }
    }

    return RET_OSSL_OK;
}

static int p11prov_print_pkeyinfo(CK_ATTRIBUTE *pkeyinfo, BIO *out)
{
    X509_PUBKEY *pubkey = NULL;
    const unsigned char *val = pkeyinfo->pValue;
    long len = pkeyinfo->ulValueLen;
    const unsigned char *pk;
    int pklen;
    ASN1_OBJECT *spkioid;
    X509_ALGOR *alg;
    int nid;
    int ret;

    pubkey = d2i_X509_PUBKEY(NULL, &val, len);
    if (!pubkey) {
        return RET_OSSL_ERR;
    }

    ret = X509_PUBKEY_get0_param(&spkioid, &pk, &pklen, &alg, pubkey);
    if (ret != RET_OSSL_OK) {
        goto done;
    }

    nid = OBJ_obj2nid(spkioid);
    if (nid == NID_rsaEncryption || nid == NID_rsassaPss) {
        P11PROV_RSA_PUBKEY *asn1key;

        asn1key = d2i_P11PROV_RSA_PUBKEY(NULL, &pk, pklen);
        if (!asn1key) {
            ret = RET_OSSL_ERR;
            goto done;
        }

        ret = p11prov_print_ASN1_INTEGER(out, asn1key->n, "Modulus:", 0);
        if (ret != RET_OSSL_OK) {
            P11PROV_RSA_PUBKEY_free(asn1key);
            goto done;
        }

        ret = p11prov_print_ASN1_INTEGER(out, asn1key->e, "Exponent:", 0);
        if (ret != RET_OSSL_OK) {
            P11PROV_RSA_PUBKEY_free(asn1key);
            goto done;
        }

        P11PROV_RSA_PUBKEY_free(asn1key);
        ret = RET_OSSL_OK;

    } else if (nid == NID_X9_62_id_ecPublicKey) {
        const void *pval;
        int ptype = 0;

        X509_ALGOR_get0(NULL, &ptype, &pval, alg);
        if (ptype == V_ASN1_OBJECT) {
            const char *name;

            nid = OBJ_obj2nid(pval);
            BIO_printf(out, "ASN1 OID: %s\n", OBJ_nid2sn(nid));

            name = EC_curve_nid2nist(nid);
            if (name) {
                BIO_printf(out, "NIST CURVE: %s\n", name);
            }
        } else if (ptype == V_ASN1_SEQUENCE) {
            const ASN1_STRING *pstr = pval;
            const unsigned char *pm = pstr->data;
            int pmlen = pstr->length;
            EC_GROUP *group;

            group = d2i_ECPKParameters(NULL, &pm, pmlen);
            if (group) {
                nid = EC_GROUP_get_curve_name(group);
                if (nid != NID_undef) {
                    const char *name;
                    BIO_printf(out, "ASN1 OID: %s\n", OBJ_nid2sn(nid));
                    name = OSSL_EC_curve_nid2name(nid);
                    if (name) {
                        BIO_printf(out, "CURVE NAME: %s\n", name);
                    }
                } else {
                    nid = EC_GROUP_get_field_type(group);
                    BIO_printf(out, "FIELD TYPE: %s\n", OBJ_nid2sn(nid));
                }
                EC_GROUP_free(group);
            } else {
                BIO_printf(out, "Error: [Failed to decode EC Parameters]");
            }
        } else {
            /* Should never happen */
            BIO_printf(out, "Error: [Failed to decode EC Parameters]");
            ret = RET_OSSL_ERR;
            goto done;
        }

        BIO_printf(out, "Pub:\n");
        ret = ASN1_buf_print(out, pk, pklen, 4);

    } else if (nid == NID_ED25519 || nid == NID_ED448 || nid == NID_X25519
               || nid == NID_X448) {
        BIO_printf(out, "Pub:\n");
        ret = ASN1_buf_print(out, pk, pklen, 4);
    }
#ifdef NID_ML_DSA_44
    else if (nid == NID_ML_DSA_44 || nid == NID_ML_DSA_65
             || nid == NID_ML_DSA_87) {
        BIO_printf(out, "Pub:\n");
        ret = ASN1_buf_print(out, pk, pklen, 4);
    }
#endif
#ifdef NID_ML_KEM_512
    else if (nid == NID_ML_KEM_512 || nid == NID_ML_KEM_768
             || nid == NID_ML_KEM_1024) {
        BIO_printf(out, "Pub:\n");
        ret = ASN1_buf_print(out, pk, pklen, 4);
    }
#endif
    else {
        ret = RET_OSSL_ERR;
    }

done:
    X509_PUBKEY_free(pubkey);
    return ret;
}

static int p11prov_common_encoder_encode_text(void *inctx, OSSL_CORE_BIO *cbio,
                                              const void *inkey,
                                              const OSSL_PARAM key_abstract[],
                                              int selection,
                                              OSSL_PASSPHRASE_CALLBACK *cb,
                                              void *cbarg)
{
    struct p11prov_encoder_ctx *ctx = (struct p11prov_encoder_ctx *)inctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)inkey;
    const char *type_name;
    CK_OBJECT_CLASS class;
    CK_ULONG keysize;
    const char *uri = NULL;
    BIO *out;
    int ret;

    type_name = p11prov_key_type_name(key);
    if (!type_name) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Unknown Key Type");
        return RET_OSSL_ERR;
    }

    P11PROV_debug("%s Text Encoder", type_name);

    out = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cbio);
    if (!out) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to init BIO");
        return RET_OSSL_ERR;
    }

    class = p11prov_obj_get_class(key);
    keysize = p11prov_obj_get_key_bit_size(key);

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (class != CKO_PRIVATE_KEY) {
            BIO_printf(out, "[Error: Invalid key data]\n");
            goto done;
        }
        BIO_printf(out, "PKCS11 %s Private Key (%lu bits)\n", type_name,
                   keysize);
        BIO_printf(out, "[Can't export and print private key data]\n");
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        CK_KEY_TYPE type = p11prov_obj_get_key_type(key);
        CK_ATTRIBUTE *pkeyinfo = NULL;
        P11PROV_OBJ *public = NULL;
        bool free_public = false;

        BIO_printf(out, "PKCS11 %s Public Key (%lu bits)\n", type_name,
                   keysize);

        if (class == CKO_PUBLIC_KEY) {
            pkeyinfo = p11prov_obj_get_attr(key, CKA_PUBLIC_KEY_INFO);
            if (pkeyinfo) {
                if (pkeyinfo->ulValueLen == 0) {
                    pkeyinfo = NULL;
                }
            }
            if (!pkeyinfo) {
                public = key;
            }
        } else {
            /* Hopefully we have info on the private key */
            pkeyinfo = p11prov_obj_get_attr(key, CKA_PUBLIC_KEY_INFO);
            if (pkeyinfo && pkeyinfo->ulValueLen == 0) {
                pkeyinfo = NULL;
            }
            /* Otherwise try the most expensive option */
            if (!pkeyinfo) {
                public = p11prov_obj_find_associated(key, CKO_PUBLIC_KEY);
                free_public = true;
            }
            if (public) {
                pkeyinfo = p11prov_obj_get_attr(public, CKA_PUBLIC_KEY_INFO);
                if (pkeyinfo && pkeyinfo->ulValueLen > 0) {
                    public = NULL;
                } else {
                    pkeyinfo = NULL;
                }
            }
            if (!public && !pkeyinfo) {
                BIO_printf(out, "[Error: Failed to source public key info]\n");
            }
        }
        if (public) {
            ret = p11prov_obj_export_public_key(public, type, true,
                                                p11prov_print_public_key, out);
            if (ret != RET_OSSL_OK) {
                BIO_printf(out, "[Error: Failed to decode public key data]\n");
            }
            if (free_public) {
                p11prov_obj_free(public);
            }
        } else if (pkeyinfo) {
            ret = p11prov_print_pkeyinfo(pkeyinfo, out);
            if (ret != RET_OSSL_OK) {
                BIO_printf(out, "[Error: Failed to decode public key info]\n");
            }
        }
    }

    uri = p11prov_obj_get_public_uri(key);
    if (uri) {
        BIO_printf(out, "URI %s\n", uri);
    }

done:
    BIO_free(out);
    return RET_OSSL_OK;
}

const OSSL_DISPATCH p11prov_rsa_encoder_text_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_TEXT_ENCODER_ELEM(ENCODE, common, encode_text),
    { 0, NULL },
};

static int p11prov_rsa_set_asn1key_data(const OSSL_PARAM *params, void *key)
{
    P11PROV_RSA_PUBKEY *asn1key = (P11PROV_RSA_PUBKEY *)key;
    const OSSL_PARAM *p;
    void *aret = NULL;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    int ret;

    /* Modulus */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
    if (!p) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    ret = OSSL_PARAM_get_BN(p, &n);
    if (ret != RET_OSSL_OK) {
        goto done;
    }

    aret = BN_to_ASN1_INTEGER(n, asn1key->n);
    if (!aret) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    /* Exponent */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    if (!p) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    ret = OSSL_PARAM_get_BN(p, &e);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    aret = BN_to_ASN1_INTEGER(e, asn1key->e);
    if (!aret) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    ret = RET_OSSL_OK;

done:
    BN_free(n);
    BN_free(e);
    return ret;
}

static P11PROV_RSA_PUBKEY *p11prov_rsa_pubkey_to_asn1(P11PROV_OBJ *key)
{
    P11PROV_RSA_PUBKEY *asn1key = NULL;
    int ret;

    asn1key = P11PROV_RSA_PUBKEY_new();
    if (!asn1key) {
        return NULL;
    }

    ret = p11prov_obj_export_public_key(key, CKK_RSA, true,
                                        p11prov_rsa_set_asn1key_data, asn1key);

    if (ret != RET_OSSL_OK) {
        P11PROV_RSA_PUBKEY_free(asn1key);
        return NULL;
    }

    return asn1key;
}

static int p11prov_rsa_pubkey_to_der(P11PROV_OBJ *key, unsigned char **der,
                                     int *derlen)
{
    CK_ATTRIBUTE *pkeyinfo = NULL;
    P11PROV_RSA_PUBKEY *asn1key;

    /* try with Public Key Info, and fallback to exporting */
    pkeyinfo = p11prov_obj_get_attr(key, CKA_PUBLIC_KEY_INFO);
    if (pkeyinfo && pkeyinfo->ulValueLen > 0) {
        asn1key = decode_rsa_pubkey(pkeyinfo);
    } else {
        asn1key = p11prov_rsa_pubkey_to_asn1(key);
    }
    if (!asn1key) {
        return RET_OSSL_ERR;
    }

    *derlen = i2d_P11PROV_RSA_PUBKEY(asn1key, der);
    if (*derlen < 0) {
        return RET_OSSL_ERR;
    }
    P11PROV_RSA_PUBKEY_free(asn1key);
    return RET_OSSL_OK;
}

int p11prov_rsa_pubkey_to_x509(X509_PUBKEY *pubkey, P11PROV_OBJ *key)
{
    unsigned char *der = NULL;
    int derlen = 0;
    int ret, nid, ptype;
    ASN1_STRING *pval = NULL;

    ret = p11prov_rsa_pubkey_to_der(key, &der, &derlen);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    if (p11prov_obj_is_rsa_pss(key)) {
        nid = NID_rsassaPss;
        /* This is RSA-PSS key without additional restrictions */
        pval = NULL;
        ptype = V_ASN1_UNDEF;
        /* TODO implement restrictions here based on ALLOWED_MECHANISMS */
    } else {
        /* this is generic RSA key without restrictions */
        nid = NID_rsaEncryption;
        ptype = V_ASN1_NULL;
    }
    ret = X509_PUBKEY_set0_param(pubkey, OBJ_nid2obj(nid), ptype, pval, der,
                                 derlen);
    if (ret != RET_OSSL_OK) {
        OPENSSL_free(der);
    }
    return ret;
}

DISPATCH_ENCODER_FN(rsa, pkcs1, der, does_selection);

static int p11prov_rsa_encoder_pkcs1_der_does_selection(void *inctx,
                                                        int selection)
{
    return RET_OSSL_ERR;
}

static int p11prov_rsa_encoder_pkcs1_der_encode(
    void *inctx, OSSL_CORE_BIO *cbio, const void *inkey,
    const OSSL_PARAM key_abstract[], int selection,
    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return RET_OSSL_ERR;
}

const OSSL_DISPATCH p11prov_rsa_encoder_pkcs1_der_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, rsa, pkcs1, der, does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, rsa, pkcs1, der, encode),
    { 0, NULL },
};

DISPATCH_ENCODER_FN(rsa, pkcs1, pem, does_selection);

static int p11prov_rsa_encoder_pkcs1_pem_does_selection(void *inctx,
                                                        int selection)
{
    return RET_OSSL_ERR;
}

static int p11prov_rsa_encoder_pkcs1_pem_encode(
    void *inctx, OSSL_CORE_BIO *cbio, const void *inkey,
    const OSSL_PARAM key_abstract[], int selection,
    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return RET_OSSL_ERR;
}

const OSSL_DISPATCH p11prov_rsa_encoder_pkcs1_pem_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, rsa, pkcs1, pem, does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, rsa, pkcs1, pem, encode),
    { 0, NULL },
};

/* SubjectPublicKeyInfo DER Encode */
DISPATCH_ENCODER_FN(rsa, spki, der, does_selection);

static int p11prov_rsa_encoder_spki_der_does_selection(void *inctx,
                                                       int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return RET_OSSL_OK;
    }
    return RET_OSSL_ERR;
}

const OSSL_DISPATCH p11prov_rsa_encoder_spki_der_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, rsa, spki, der, does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, common, spki, der, encode),
    { 0, NULL },
};

/* SubjectPublicKeyInfo PEM Encode */
DISPATCH_ENCODER_FN(rsa, spki, pem, does_selection);

static int p11prov_rsa_encoder_spki_pem_does_selection(void *inctx,
                                                       int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return RET_OSSL_OK;
    }
    return RET_OSSL_ERR;
}

static int p11prov_rsa_encoder_spki_pem_encode(void *inctx, OSSL_CORE_BIO *cbio,
                                               const void *inkey,
                                               const OSSL_PARAM key_abstract[],
                                               int selection,
                                               OSSL_PASSPHRASE_CALLBACK *cb,
                                               void *cbarg)
{
    struct p11prov_encoder_ctx *ctx = (struct p11prov_encoder_ctx *)inctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)inkey;
    CK_KEY_TYPE type;
    CK_ATTRIBUTE *pkeyinfo = NULL;
    P11PROV_RSA_PUBKEY *asn1key = NULL;
    BIO *out = NULL;
    int ret;

    P11PROV_debug("RSA PKCS1 PEM Encoder");

    /* we only return public key info */
    if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {
        return RET_OSSL_ERR;
    }

    type = p11prov_obj_get_key_type(key);
    if (type != CKK_RSA) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Invalid Key Type");
        ret = RET_OSSL_ERR;
        goto done;
    }

    /* try with Public Key Info, and fallback to exporting */
    pkeyinfo = p11prov_obj_get_attr(key, CKA_PUBLIC_KEY_INFO);
    if (pkeyinfo && pkeyinfo->ulValueLen > 0) {
        asn1key = decode_rsa_pubkey(pkeyinfo);
    } else {
        asn1key = p11prov_rsa_pubkey_to_asn1(key);
    }
    if (!asn1key) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    out = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cbio);
    if (!out) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to init BIO");
        ret = RET_OSSL_ERR;
        goto done;
    }

    ret = PEM_write_bio_P11PROV_RSA_PUBKEY(out, asn1key);

done:
    P11PROV_RSA_PUBKEY_free(asn1key);
    BIO_free(out);
    return ret;
}

const OSSL_DISPATCH p11prov_rsa_encoder_spki_pem_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, rsa, spki, pem, does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, rsa, spki, pem, encode),
    { 0, NULL },
};

static P11PROV_PK11_URI *p11prov_encoder_private_key_to_asn1(P11PROV_CTX *pctx,
                                                             P11PROV_OBJ *key)
{
    P11PROV_PK11_URI *out = NULL;
    const char *uri = NULL;
    size_t uri_len;
    int ret = RET_OSSL_ERR;

    uri = p11prov_obj_get_public_uri(key);
    if (!uri) {
        goto done;
    }

    uri_len = strlen(uri);
    P11PROV_debug("uri=%s", uri);

    out = P11PROV_PK11_URI_new();
    if (!out) {
        goto done;
    }

    if (!ASN1_STRING_set(out->desc, P11PROV_DESCS_URI_FILE,
                         sizeof(P11PROV_DESCS_URI_FILE) - 1)) {
        goto done;
    }
    if (!ASN1_STRING_set(out->uri, uri, uri_len)) {
        goto done;
    }

    ret = RET_OSSL_OK;

done:
    if (ret != RET_OSSL_OK) {
        P11PROV_PK11_URI_free(out);
        out = NULL;
    }
    return out;
}

static int p11prov_encoder_private_key_write_pem(
    CK_KEY_TYPE expected_key_type, void *inctx, OSSL_CORE_BIO *cbio,
    const void *inkey, const OSSL_PARAM key_abstract[], int selection,
    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct p11prov_encoder_ctx *ctx = (struct p11prov_encoder_ctx *)inctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)inkey;
    CK_KEY_TYPE key_type;
    P11PROV_PK11_URI *asn1 = NULL;
    BIO *out = NULL;
    int ret;

    key_type = p11prov_obj_get_key_type(key);
    if (key_type != expected_key_type) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR,
                      "Key type mismatch (actual:%lu,expected:%lu)", key_type,
                      expected_key_type);
        ret = RET_OSSL_ERR;
        goto done;
    }

    asn1 = p11prov_encoder_private_key_to_asn1(ctx->provctx, key);
    if (!asn1) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR,
                      "Failed to encode private key");
        ret = RET_OSSL_ERR;
        goto done;
    }

    out = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cbio);
    if (!out) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to init BIO");
        ret = RET_OSSL_ERR;
        goto done;
    }

    ret = PEM_write_bio_P11PROV_PK11_URI(out, asn1);
    if (ret != RET_OSSL_OK) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR,
                      "Failed to write BIO PEM");
        goto done;
    }

done:
    P11PROV_PK11_URI_free(asn1);
    BIO_free(out);
    return ret;
}

static int p11prov_rsa_encoder_priv_key_info_pem_encode(
    void *inctx, OSSL_CORE_BIO *cbio, const void *inkey,
    const OSSL_PARAM key_abstract[], int selection,
    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return p11prov_encoder_private_key_write_pem(
        CKK_RSA, inctx, cbio, inkey, key_abstract, selection, cb, cbarg);
}

const OSSL_DISPATCH p11prov_rsa_encoder_priv_key_info_pem_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, common, priv_key_info, pem,
                          does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, rsa, priv_key_info, pem, encode),
    { 0, NULL },
};

/* ECDSA */

struct ecdsa_key_point {
    union {
        ASN1_OBJECT *object;
        ASN1_STRING *sequence;
    } curve;
    unsigned char *octet;
    int curve_type;
    size_t octet_len;
};

static void ecdsa_key_point_free(struct ecdsa_key_point *k)
{
    if (k->curve_type == V_ASN1_SEQUENCE) {
        ASN1_STRING_free(k->curve.sequence);
    } else if (k->curve_type == V_ASN1_OBJECT) {
        ASN1_OBJECT_free(k->curve.object);
    }
    k->curve.object = NULL;
    k->curve_type = V_ASN1_UNDEF;
    if (k->octet) {
        OPENSSL_free(k->octet);
        k->octet = NULL;
    }
    k->octet_len = 0;
}

static int p11prov_ec_set_keypoint_data(const OSSL_PARAM *params, void *key)
{
    struct ecdsa_key_point *keypoint = (struct ecdsa_key_point *)key;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING) {
            return RET_OSSL_ERR;
        }
        keypoint->curve.object = OBJ_txt2obj(p->data, 0);
        if (!keypoint->curve.object) {
            return RET_OSSL_ERR;
        }
        keypoint->curve_type = V_ASN1_OBJECT;
    } else {
        EC_GROUP *group = EC_GROUP_new_from_params(params, NULL, NULL);
        if (!group) {
            return RET_OSSL_ERR;
        }
        ASN1_STRING *pstr = NULL;
        pstr = ASN1_STRING_new();
        if (pstr == NULL) {
            EC_GROUP_free(group);
            return RET_OSSL_ERR;
        }
        pstr->length = i2d_ECPKParameters(group, &pstr->data);
        EC_GROUP_free(group);
        if (pstr->length <= 0) {
            ASN1_STRING_free(pstr);
            return RET_OSSL_ERR;
        }
        keypoint->curve.sequence = pstr;
        keypoint->curve_type = V_ASN1_SEQUENCE;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (!p) {
        return RET_OSSL_ERR;
    }
    if (p->data_type != OSSL_PARAM_OCTET_STRING) {
        return RET_OSSL_ERR;
    }
    keypoint->octet = OPENSSL_memdup(p->data, p->data_size);
    if (!keypoint->octet) {
        return RET_OSSL_ERR;
    }
    keypoint->octet_len = p->data_size;

    return RET_OSSL_OK;
}

int p11prov_ec_pubkey_to_x509(X509_PUBKEY *pubkey, P11PROV_OBJ *key)
{
    struct ecdsa_key_point keypoint = { 0 };
    int ret;

    ret =
        p11prov_obj_export_public_key(key, CK_UNAVAILABLE_INFORMATION, false,
                                      p11prov_ec_set_keypoint_data, &keypoint);
    if (ret != RET_OSSL_OK) {
        ecdsa_key_point_free(&keypoint);
        return ret;
    }

    ret = X509_PUBKEY_set0_param(pubkey, OBJ_nid2obj(NID_X9_62_id_ecPublicKey),
                                 keypoint.curve_type, keypoint.curve.object,
                                 keypoint.octet, keypoint.octet_len);
    if (ret != RET_OSSL_OK) {
        ecdsa_key_point_free(&keypoint);
        return ret;
    }

    return RET_OSSL_OK;
}

DISPATCH_ENCODER_FN(ec, pkcs1, der, does_selection);

static int p11prov_ec_encoder_pkcs1_der_does_selection(void *inctx,
                                                       int selection)
{
    return RET_OSSL_ERR;
}

static int p11prov_ec_encoder_pkcs1_der_encode(void *inctx, OSSL_CORE_BIO *cbio,
                                               const void *inkey,
                                               const OSSL_PARAM key_abstract[],
                                               int selection,
                                               OSSL_PASSPHRASE_CALLBACK *cb,
                                               void *cbarg)
{
    return RET_OSSL_ERR;
}

const OSSL_DISPATCH p11prov_ec_encoder_pkcs1_der_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, ec, pkcs1, der, does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, ec, pkcs1, der, encode),
    { 0, NULL },
};

DISPATCH_ENCODER_FN(ec, pkcs1, pem, does_selection);

static int p11prov_ec_encoder_pkcs1_pem_does_selection(void *inctx,
                                                       int selection)
{
    return RET_OSSL_ERR;
}

static int p11prov_ec_encoder_pkcs1_pem_encode(void *inctx, OSSL_CORE_BIO *cbio,
                                               const void *inkey,
                                               const OSSL_PARAM key_abstract[],
                                               int selection,
                                               OSSL_PASSPHRASE_CALLBACK *cb,
                                               void *cbarg)
{
    return RET_OSSL_ERR;
}

const OSSL_DISPATCH p11prov_ec_encoder_pkcs1_pem_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, ec, pkcs1, pem, does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, ec, pkcs1, pem, encode),
    { 0, NULL },
};

/* SubjectPublicKeyInfo DER Encode */
DISPATCH_ENCODER_FN(ec, spki, der, does_selection);

static int p11prov_ec_encoder_spki_der_does_selection(void *inctx,
                                                      int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return RET_OSSL_OK;
    }
    return RET_OSSL_ERR;
}

const OSSL_DISPATCH p11prov_ec_encoder_spki_der_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, ec, spki, der, does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, common, spki, der, encode),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_ec_encoder_text_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_TEXT_ENCODER_ELEM(ENCODE, common, encode_text),
    { 0, NULL },
};

static int p11prov_ec_encoder_priv_key_info_pem_encode(
    void *inctx, OSSL_CORE_BIO *cbio, const void *inkey,
    const OSSL_PARAM key_abstract[], int selection,
    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return p11prov_encoder_private_key_write_pem(
        CKK_EC, inctx, cbio, inkey, key_abstract, selection, cb, cbarg);
}

const OSSL_DISPATCH p11prov_ec_encoder_priv_key_info_pem_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, common, priv_key_info, pem,
                          does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, ec, priv_key_info, pem, encode),
    { 0, NULL },
};

static int p11prov_ec_edwards_encoder_priv_key_info_pem_encode(
    void *inctx, OSSL_CORE_BIO *cbio, const void *inkey,
    const OSSL_PARAM key_abstract[], int selection,
    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return p11prov_encoder_private_key_write_pem(
        CKK_EC_EDWARDS, inctx, cbio, inkey, key_abstract, selection, cb, cbarg);
}

const OSSL_DISPATCH p11prov_ec_edwards_encoder_priv_key_info_pem_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, common, priv_key_info, pem,
                          does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, ec_edwards, priv_key_info, pem, encode),
    { 0, NULL },
};

static int p11prov_ec_montgomery_encoder_priv_key_info_pem_encode(
    void *inctx, OSSL_CORE_BIO *cbio, const void *inkey,
    const OSSL_PARAM key_abstract[], int selection,
    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return p11prov_encoder_private_key_write_pem(CKK_EC_MONTGOMERY, inctx, cbio,
                                                 inkey, key_abstract, selection,
                                                 cb, cbarg);
}

const OSSL_DISPATCH
    p11prov_ec_montgomery_encoder_priv_key_info_pem_functions[] = {
        DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
        DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
        DISPATCH_ENCODER_ELEM(DOES_SELECTION, common, priv_key_info, pem,
                              does_selection),
        DISPATCH_ENCODER_ELEM(ENCODE, ec_montgomery, priv_key_info, pem,
                              encode),
        { 0, NULL },
    };

static int
p11prov_common_encoder_priv_key_info_pem_does_selection(void *inctx,
                                                        int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        return RET_OSSL_OK;
    }
    return RET_OSSL_ERR;
}

const OSSL_DISPATCH p11prov_ec_edwards_encoder_text_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_TEXT_ENCODER_ELEM(ENCODE, common, encode_text),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_ec_montgomery_encoder_text_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_TEXT_ENCODER_ELEM(ENCODE, common, encode_text),
    { 0, NULL },
};

/* ML-DSA */

struct mldsa_key_point {
    unsigned char *octet;
    size_t len;
};

#ifdef NID_ML_DSA_44
static int p11prov_mldsa_set_keypoint_data(const OSSL_PARAM *params, void *key)
{
    struct mldsa_key_point *keypoint = (struct mldsa_key_point *)key;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (!p) {
        return RET_OSSL_ERR;
    }
    if (p->data_type != OSSL_PARAM_OCTET_STRING) {
        return RET_OSSL_ERR;
    }
    keypoint->octet = OPENSSL_memdup(p->data, p->data_size);
    if (!keypoint->octet) {
        return RET_OSSL_ERR;
    }
    keypoint->len = p->data_size;

    return RET_OSSL_OK;
}
#endif /* defined(NID_ML_DSA_44) */

int p11prov_mldsa_pubkey_to_x509(X509_PUBKEY *pubkey, P11PROV_OBJ *key)
{
    int ret = RET_OSSL_ERR;
#ifdef NID_ML_DSA_44
    struct mldsa_key_point keypoint = { 0 };
    int nid = NID_undef;

    switch (p11prov_obj_get_key_param_set(key)) {
    case CKP_ML_DSA_44:
        nid = NID_ML_DSA_44;
        break;
    case CKP_ML_DSA_65:
        nid = NID_ML_DSA_65;
        break;
    case CKP_ML_DSA_87:
        nid = NID_ML_DSA_87;
        break;
    default:
        goto done;
    }

    ret = p11prov_obj_export_public_key(
        key, CKK_ML_DSA, true, p11prov_mldsa_set_keypoint_data, &keypoint);
    if (ret != RET_OSSL_OK) {
        goto done;
    }

    ret = X509_PUBKEY_set0_param(pubkey, OBJ_nid2obj(nid), V_ASN1_UNDEF, NULL,
                                 keypoint.octet, keypoint.len);

done:
    if (ret != RET_OSSL_OK) {
        OPENSSL_clear_free(keypoint.octet, keypoint.len);
    }
#endif

    return ret;
}

/* SubjectPublicKeyInfo DER Encode */
DISPATCH_ENCODER_FN(mldsa, spki, der, does_selection);

static int p11prov_mldsa_encoder_spki_der_does_selection(void *inctx,
                                                         int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return RET_OSSL_OK;
    }
    return RET_OSSL_ERR;
}

const OSSL_DISPATCH p11prov_mldsa_encoder_spki_der_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, mldsa, spki, der, does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, common, spki, der, encode),
    { 0, NULL },
};

static int p11prov_mldsa_encoder_priv_key_info_pem_encode(
    void *inctx, OSSL_CORE_BIO *cbio, const void *inkey,
    const OSSL_PARAM key_abstract[], int selection,
    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return p11prov_encoder_private_key_write_pem(
        CKK_ML_DSA, inctx, cbio, inkey, key_abstract, selection, cb, cbarg);
}

const OSSL_DISPATCH p11prov_mldsa_encoder_priv_key_info_pem_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, common, priv_key_info, pem,
                          does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, mldsa, priv_key_info, pem, encode),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mldsa_encoder_text_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_TEXT_ENCODER_ELEM(ENCODE, common, encode_text),
    { 0, NULL },
};

/* ML-KEM */

struct mlkem_key_point {
    unsigned char *octet;
    size_t len;
};

#ifdef NID_ML_KEM_512
static int p11prov_mlkem_set_keypoint_data(const OSSL_PARAM *params, void *key)
{
    struct mlkem_key_point *keypoint = (struct mlkem_key_point *)key;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (!p) {
        return RET_OSSL_ERR;
    }
    if (p->data_type != OSSL_PARAM_OCTET_STRING) {
        return RET_OSSL_ERR;
    }
    keypoint->octet = OPENSSL_memdup(p->data, p->data_size);
    if (!keypoint->octet) {
        return RET_OSSL_ERR;
    }
    keypoint->len = p->data_size;

    return RET_OSSL_OK;
}
#endif /* defined(NID_ML_KEM_512) */

int p11prov_mlkem_pubkey_to_x509(X509_PUBKEY *pubkey, P11PROV_OBJ *key)
{
    int ret = RET_OSSL_ERR;
#ifdef NID_ML_KEM_512
    struct mlkem_key_point keypoint = { 0 };
    int nid = NID_undef;

    switch (p11prov_obj_get_key_param_set(key)) {
    case CKP_ML_KEM_512:
        nid = NID_ML_KEM_512;
        break;
    case CKP_ML_KEM_768:
        nid = NID_ML_KEM_768;
        break;
    case CKP_ML_KEM_1024:
        nid = NID_ML_KEM_1024;
        break;
    default:
        goto done;
    }

    ret = p11prov_obj_export_public_key(
        key, CKK_ML_KEM, true, p11prov_mlkem_set_keypoint_data, &keypoint);
    if (ret != RET_OSSL_OK) {
        goto done;
    }

    ret = X509_PUBKEY_set0_param(pubkey, OBJ_nid2obj(nid), V_ASN1_UNDEF, NULL,
                                 keypoint.octet, keypoint.len);

done:
    if (ret != RET_OSSL_OK) {
        OPENSSL_clear_free(keypoint.octet, keypoint.len);
    }
#endif

    return ret;
}

/* SubjectPublicKeyInfo DER Encode */
DISPATCH_ENCODER_FN(mlkem, spki, der, does_selection);

static int p11prov_mlkem_encoder_spki_der_does_selection(void *inctx,
                                                         int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return RET_OSSL_OK;
    }
    return RET_OSSL_ERR;
}

const OSSL_DISPATCH p11prov_mlkem_encoder_spki_der_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, mlkem, spki, der, does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, common, spki, der, encode),
    { 0, NULL },
};

static int p11prov_mlkem_encoder_priv_key_info_pem_encode(
    void *inctx, OSSL_CORE_BIO *cbio, const void *inkey,
    const OSSL_PARAM key_abstract[], int selection,
    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return p11prov_encoder_private_key_write_pem(
        CKK_ML_KEM, inctx, cbio, inkey, key_abstract, selection, cb, cbarg);
}

const OSSL_DISPATCH p11prov_mlkem_encoder_priv_key_info_pem_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, common, priv_key_info, pem,
                          does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, mlkem, priv_key_info, pem, encode),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_mlkem_encoder_text_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_TEXT_ENCODER_ELEM(ENCODE, common, encode_text),
    { 0, NULL },
};
