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
    ASN1_bn_print(out, str, bn, NULL, indent);
    BN_free(bn);

    return RET_OSSL_OK;
}

static int p11prov_print_buf(BIO *out, const OSSL_PARAM *p, const char *str,
                             int indent)
{
    if (p->data_type != OSSL_PARAM_OCTET_STRING) {
        return RET_OSSL_ERR;
    }
    BIO_printf(out, "%s\n", str);
    ASN1_buf_print(out, p->data, p->data_size, indent);

    return RET_OSSL_OK;
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

DISPATCH_TEXT_ENCODER_FN(rsa, encode);

static int p11prov_rsa_print_public_key(const OSSL_PARAM *params, void *bio)
{
    BIO *out = (BIO *)bio;
    const OSSL_PARAM *p;
    int ret;

    /* Modulus */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
    if (p) {
        ret = p11prov_print_bn(out, p, "Modulus:", 0);
        if (ret != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }

    /* Exponent */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    if (p) {
        ret = p11prov_print_bn(out, p, "Exponent:", 0);
        if (ret != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_OK;
}

static int p11prov_rsa_encoder_encode_text(void *inctx, OSSL_CORE_BIO *cbio,
                                           const void *inkey,
                                           const OSSL_PARAM key_abstract[],
                                           int selection,
                                           OSSL_PASSPHRASE_CALLBACK *cb,
                                           void *cbarg)
{
    struct p11prov_encoder_ctx *ctx = (struct p11prov_encoder_ctx *)inctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)inkey;
    CK_KEY_TYPE type;
    CK_OBJECT_CLASS class;
    CK_ULONG keysize;
    const char *uri = NULL;
    BIO *out;
    int ret;

    P11PROV_debug("RSA Text Encoder");

    type = p11prov_obj_get_key_type(key);
    if (type != CKK_RSA) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Invalid Key Type");
        return RET_OSSL_ERR;
    }
    class = p11prov_obj_get_class(key);

    out = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cbio);
    if (!out) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to init BIO");
        return RET_OSSL_ERR;
    }

    keysize = p11prov_obj_get_key_bit_size(key);

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (class != CKO_PRIVATE_KEY) {
            BIO_printf(out, "[Error: Invalid key data]\n");
            goto done;
        }
        BIO_printf(out, "PKCS11 RSA Private Key (%lu bits)\n", keysize);
        BIO_printf(out, "[Can't export and print private key data]\n");
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (class != CKO_PUBLIC_KEY) {
            P11PROV_OBJ *assoc;

            assoc = p11prov_obj_find_associated(key, CKO_PUBLIC_KEY);
            if (!assoc) {
                BIO_printf(out, "[Error: Failed to source public key data]\n");
                goto done;
            }

            /* replace key before printing the rest */
            key = assoc;
        }
        BIO_printf(out, "PKCS11 RSA Public Key (%lu bits)\n", keysize);
        ret = p11prov_obj_export_public_key(key, CKK_RSA, true, false,
                                            p11prov_rsa_print_public_key, out);
        if (ret != RET_OSSL_OK) {
            BIO_printf(out, "[Error: Failed to decode public key data]\n");
        }
    }

    uri = p11prov_obj_get_public_uri(key);
    if (uri) {
        BIO_printf(out, "URI %s\n", uri);
    }

done:
    if (key != inkey) {
        p11prov_obj_free(key);
    }
    BIO_free(out);
    return RET_OSSL_OK;
}

const OSSL_DISPATCH p11prov_rsa_encoder_text_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_TEXT_ENCODER_ELEM(ENCODE, rsa, encode_text),
    { 0, NULL },
};

#include "encoder.gen.c"

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
    P11PROV_RSA_PUBKEY *asn1key;
    int ret;

    asn1key = P11PROV_RSA_PUBKEY_new();
    if (!asn1key) {
        return NULL;
    }

    ret = p11prov_obj_export_public_key(key, CKK_RSA, true, false,
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
    P11PROV_RSA_PUBKEY *asn1key;

    asn1key = p11prov_rsa_pubkey_to_asn1(key);
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

static X509_PUBKEY *p11prov_rsa_pubkey_to_x509(P11PROV_OBJ *key)
{
    X509_PUBKEY *pubkey;
    unsigned char *der = NULL;
    int derlen = 0;
    int ret, nid, ptype;
    ASN1_STRING *pval = NULL;

    ret = p11prov_rsa_pubkey_to_der(key, &der, &derlen);
    if (ret != RET_OSSL_OK) {
        return NULL;
    }

    pubkey = X509_PUBKEY_new();
    if (!pubkey) {
        OPENSSL_free(der);
        return NULL;
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
        X509_PUBKEY_free(pubkey);
        return NULL;
    }

    return pubkey;
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

static int p11prov_rsa_encoder_spki_der_encode(void *inctx, OSSL_CORE_BIO *cbio,
                                               const void *inkey,
                                               const OSSL_PARAM key_abstract[],
                                               int selection,
                                               OSSL_PASSPHRASE_CALLBACK *cb,
                                               void *cbarg)
{
    struct p11prov_encoder_ctx *ctx = (struct p11prov_encoder_ctx *)inctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)inkey;
    CK_KEY_TYPE type;
    X509_PUBKEY *pubkey = NULL;
    BIO *out = NULL;
    int ret;

    P11PROV_debug("RSA SubjectPublicKeyInfo DER Encoder");

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

    out = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cbio);
    if (!out) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to init BIO");
        ret = RET_OSSL_ERR;
        goto done;
    }

    pubkey = p11prov_rsa_pubkey_to_x509(key);
    if (!pubkey) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    ret = i2d_X509_PUBKEY_bio(out, pubkey);

done:
    X509_PUBKEY_free(pubkey);
    BIO_free(out);
    return ret;
}

const OSSL_DISPATCH p11prov_rsa_encoder_spki_der_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, rsa, spki, der, does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, rsa, spki, der, encode),
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

    asn1key = p11prov_rsa_pubkey_to_asn1(key);
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

static X509_PUBKEY *p11prov_ec_pubkey_to_x509(P11PROV_OBJ *key)
{
    struct ecdsa_key_point keypoint = { 0 };
    X509_PUBKEY *pubkey;
    int ret;

    ret = p11prov_obj_export_public_key(
        key, CKK_EC, true, false, p11prov_ec_set_keypoint_data, &keypoint);
    if (ret != RET_OSSL_OK) {
        ecdsa_key_point_free(&keypoint);
        return NULL;
    }

    pubkey = X509_PUBKEY_new();
    if (!pubkey) {
        ecdsa_key_point_free(&keypoint);
        return NULL;
    }

    ret = X509_PUBKEY_set0_param(pubkey, OBJ_nid2obj(NID_X9_62_id_ecPublicKey),
                                 keypoint.curve_type, keypoint.curve.object,
                                 keypoint.octet, keypoint.octet_len);
    if (ret != RET_OSSL_OK) {
        ecdsa_key_point_free(&keypoint);
        X509_PUBKEY_free(pubkey);
        return NULL;
    }

    return pubkey;
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

static int p11prov_ec_encoder_spki_der_encode(void *inctx, OSSL_CORE_BIO *cbio,
                                              const void *inkey,
                                              const OSSL_PARAM key_abstract[],
                                              int selection,
                                              OSSL_PASSPHRASE_CALLBACK *cb,
                                              void *cbarg)
{
    struct p11prov_encoder_ctx *ctx = (struct p11prov_encoder_ctx *)inctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)inkey;
    CK_KEY_TYPE type;
    X509_PUBKEY *pubkey = NULL;
    BIO *out = NULL;
    int ret;

    P11PROV_debug("EC SubjectPublicKeyInfo DER Encoder");

    /* we only return public key info */
    if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {
        return RET_OSSL_ERR;
    }

    type = p11prov_obj_get_key_type(key);
    if (type != CKK_EC) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Invalid Key Type");
        ret = RET_OSSL_ERR;
        goto done;
    }

    out = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cbio);
    if (!out) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to init BIO");
        ret = RET_OSSL_ERR;
        goto done;
    }

    pubkey = p11prov_ec_pubkey_to_x509(key);
    if (!pubkey) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    ret = i2d_X509_PUBKEY_bio(out, pubkey);

done:
    X509_PUBKEY_free(pubkey);
    BIO_free(out);
    return ret;
}

const OSSL_DISPATCH p11prov_ec_encoder_spki_der_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, ec, spki, der, does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, ec, spki, der, encode),
    { 0, NULL },
};

DISPATCH_TEXT_ENCODER_FN(ec, encode);

static int p11prov_ec_print_public_key(const OSSL_PARAM *params, void *bio)
{
    BIO *out = (BIO *)bio;
    const OSSL_PARAM *p;
    int ret;

    /* Pub key */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p) {
        ret = p11prov_print_buf(out, p, "Pub:", 4);
        if (ret != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }

    /* Name */
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

static int p11prov_ec_encoder_encode_text(void *inctx, OSSL_CORE_BIO *cbio,
                                          const void *inkey,
                                          const OSSL_PARAM key_abstract[],
                                          int selection,
                                          OSSL_PASSPHRASE_CALLBACK *cb,
                                          void *cbarg)
{
    struct p11prov_encoder_ctx *ctx = (struct p11prov_encoder_ctx *)inctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)inkey;
    CK_KEY_TYPE type;
    CK_OBJECT_CLASS class;
    CK_ULONG keysize;
    const char *uri = NULL;
    BIO *out;
    int ret;

    P11PROV_debug("EC Text Encoder");

    type = p11prov_obj_get_key_type(key);
    if (type != CKK_EC) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Invalid Key Type");
        return RET_OSSL_ERR;
    }
    class = p11prov_obj_get_class(key);

    out = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cbio);
    if (!out) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to init BIO");
        return RET_OSSL_ERR;
    }

    keysize = p11prov_obj_get_key_bit_size(key);
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (class != CKO_PRIVATE_KEY) {
            BIO_printf(out, "[Error: Invalid key data]\n");
            goto done;
        }
        BIO_printf(out, "PKCS11 EC Private Key (%lu bits)\n", keysize);
        BIO_printf(out, "[Can't export and print private key data]\n");
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (class != CKO_PUBLIC_KEY) {
            P11PROV_OBJ *assoc;

            assoc = p11prov_obj_find_associated(key, CKO_PUBLIC_KEY);
            if (!assoc) {
                BIO_printf(out, "[Error: Failed to source public key data]\n");
                goto done;
            }

            /* replace key before printing the rest */
            key = assoc;
        }
        BIO_printf(out, "PKCS11 EC Public Key (%lu bits)\n", keysize);
        ret = p11prov_obj_export_public_key(key, CKK_EC, true, false,
                                            p11prov_ec_print_public_key, out);
        if (ret != RET_OSSL_OK) {
            BIO_printf(out, "[Error: Failed to decode public key data]\n");
        }
    }

    uri = p11prov_obj_get_public_uri(key);
    if (uri) {
        BIO_printf(out, "URI %s\n", uri);
    }

done:
    if (key != inkey) {
        p11prov_obj_free(key);
    }
    BIO_free(out);
    return RET_OSSL_OK;
}

const OSSL_DISPATCH p11prov_ec_encoder_text_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_TEXT_ENCODER_ELEM(ENCODE, ec, encode_text),
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

static int
p11prov_common_encoder_priv_key_info_pem_does_selection(void *inctx,
                                                        int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        return RET_OSSL_OK;
    }
    return RET_OSSL_ERR;
}

DISPATCH_TEXT_ENCODER_FN(ec_edwards, encode);

static int p11prov_ec_edwards_encoder_encode_text(
    void *inctx, OSSL_CORE_BIO *cbio, const void *inkey,
    const OSSL_PARAM key_abstract[], int selection,
    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct p11prov_encoder_ctx *ctx = (struct p11prov_encoder_ctx *)inctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)inkey;
    CK_KEY_TYPE type;
    CK_OBJECT_CLASS class;
    CK_ULONG keysize;
    const char *type_name = ED25519;
    const char *uri = NULL;
    BIO *out;
    int ret;

    P11PROV_debug("EdDSA Text Encoder");

    type = p11prov_obj_get_key_type(key);
    if (type != CKK_EC_EDWARDS) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Invalid Key Type");
        return RET_OSSL_ERR;
    }
    class = p11prov_obj_get_class(key);

    out = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cbio);
    if (!out) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to init BIO");
        return RET_OSSL_ERR;
    }

    keysize = p11prov_obj_get_key_bit_size(key);
    if (keysize == ED448_BIT_SIZE) {
        type_name = ED448;
    }
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
        if (class != CKO_PUBLIC_KEY) {
            P11PROV_OBJ *assoc;

            assoc = p11prov_obj_find_associated(key, CKO_PUBLIC_KEY);
            if (!assoc) {
                BIO_printf(out, "[Error: Failed to source public key data]\n");
                goto done;
            }

            /* replace key before printing the rest */
            key = assoc;
        }
        BIO_printf(out, "PKCS11 %s Public Key (%lu bits)\n", type_name,
                   keysize);
        ret = p11prov_obj_export_public_key(key, CKK_EC_EDWARDS, true, false,
                                            p11prov_ec_print_public_key, out);
        /* FIXME if we want print in different format */
        if (ret != RET_OSSL_OK) {
            BIO_printf(out, "[Error: Failed to decode public key data]\n");
        }
    }

    uri = p11prov_obj_get_public_uri(key);
    if (uri) {
        BIO_printf(out, "URI %s\n", uri);
    }

done:
    if (key != inkey) {
        p11prov_obj_free(key);
    }
    BIO_free(out);
    return RET_OSSL_OK;
}

const OSSL_DISPATCH p11prov_ec_edwards_encoder_text_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_TEXT_ENCODER_ELEM(ENCODE, ec_edwards, encode_text),
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

static X509_PUBKEY *p11prov_mldsa_pubkey_to_x509(P11PROV_OBJ *key)
{
#ifdef NID_ML_DSA_44
    struct mldsa_key_point keypoint = { 0 };
    X509_PUBKEY *pubkey;
    int nid = NID_undef;
    int ret;

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
        return NULL;
    }

    ret = p11prov_obj_export_public_key(key, CKK_ML_DSA, true, false,
                                        p11prov_mldsa_set_keypoint_data,
                                        &keypoint);
    if (ret != RET_OSSL_OK) {
        OPENSSL_clear_free(keypoint.octet, keypoint.len);
        return NULL;
    }

    pubkey = X509_PUBKEY_new();
    if (!pubkey) {
        OPENSSL_clear_free(keypoint.octet, keypoint.len);
        return NULL;
    }

    ret = X509_PUBKEY_set0_param(pubkey, OBJ_nid2obj(nid), V_ASN1_UNDEF, NULL,
                                 keypoint.octet, keypoint.len);
    if (ret != RET_OSSL_OK) {
        OPENSSL_clear_free(keypoint.octet, keypoint.len);
        X509_PUBKEY_free(pubkey);
        return NULL;
    }

    return pubkey;
#else
    return NULL;
#endif
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

static int p11prov_mldsa_encoder_spki_der_encode(
    void *inctx, OSSL_CORE_BIO *cbio, const void *inkey,
    const OSSL_PARAM key_abstract[], int selection,
    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct p11prov_encoder_ctx *ctx = (struct p11prov_encoder_ctx *)inctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)inkey;
    CK_KEY_TYPE type;
    X509_PUBKEY *pubkey = NULL;
    BIO *out = NULL;
    int ret;

    P11PROV_debug("mldsa SubjectPublicKeyInfo DER Encoder");

    /* we only return public key info */
    if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {
        return RET_OSSL_ERR;
    }

    type = p11prov_obj_get_key_type(key);
    if (type != CKK_ML_DSA) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Invalid Key Type");
        ret = RET_OSSL_ERR;
        goto done;
    }

    out = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cbio);
    if (!out) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to init BIO");
        ret = RET_OSSL_ERR;
        goto done;
    }

    pubkey = p11prov_mldsa_pubkey_to_x509(key);
    if (!pubkey) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    ret = i2d_X509_PUBKEY_bio(out, pubkey);

done:
    X509_PUBKEY_free(pubkey);
    BIO_free(out);
    return ret;
}

const OSSL_DISPATCH p11prov_mldsa_encoder_spki_der_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_ENCODER_ELEM(DOES_SELECTION, mldsa, spki, der, does_selection),
    DISPATCH_ENCODER_ELEM(ENCODE, mldsa, spki, der, encode),
    { 0, NULL },
};

static int p11prov_mldsa_print_public_key(const OSSL_PARAM *params, void *bio)
{
    BIO *out = (BIO *)bio;
    const OSSL_PARAM *p;
    int ret;

    /* Pub key */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p) {
        ret = p11prov_print_buf(out, p, "Pub:", 4);
        if (ret != RET_OSSL_OK) {
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_OK;
}

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

DISPATCH_TEXT_ENCODER_FN(mldsa, encode);

static int p11prov_mldsa_encoder_encode_text(void *inctx, OSSL_CORE_BIO *cbio,
                                             const void *inkey,
                                             const OSSL_PARAM key_abstract[],
                                             int selection,
                                             OSSL_PASSPHRASE_CALLBACK *cb,
                                             void *cbarg)
{
    struct p11prov_encoder_ctx *ctx = (struct p11prov_encoder_ctx *)inctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)inkey;
    CK_KEY_TYPE type;
    CK_OBJECT_CLASS class;
    CK_ULONG param_set;
    const char *type_name = "ML-DSA";
    const char *uri = NULL;
    BIO *out;
    int ret;

    P11PROV_debug("mldsa Text Encoder");

    type = p11prov_obj_get_key_type(key);
    if (type != CKK_ML_DSA) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Invalid Key Type");
        return RET_OSSL_ERR;
    }
    class = p11prov_obj_get_class(key);

    out = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cbio);
    if (!out) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to init BIO");
        return RET_OSSL_ERR;
    }

    param_set = p11prov_obj_get_key_param_set(key);
    switch (param_set) {
    case CKP_ML_DSA_44:
        type_name = "ML-DSA-44";
        break;
    case CKP_ML_DSA_65:
        type_name = "ML-DSA-65";
        break;
    case CKP_ML_DSA_87:
        type_name = "ML-DSA-87";
        break;
    default:
        BIO_printf(out, "[Error: Key Parameter set unnknown %ld]", param_set);
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (class != CKO_PRIVATE_KEY) {
            BIO_printf(out, "[Error: Invalid key data]\n");
            goto done;
        }
        BIO_printf(out, "PKCS11 %s Private Key\n", type_name);
        BIO_printf(out, "[Can't export and print private key data]\n");
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (class != CKO_PUBLIC_KEY) {
            P11PROV_OBJ *assoc;

            assoc = p11prov_obj_find_associated(key, CKO_PUBLIC_KEY);
            if (!assoc) {
                BIO_printf(out, "[Error: Failed to source public key data]\n");
                goto done;
            }

            /* replace key before printing the rest */
            key = assoc;
        }
        BIO_printf(out, "PKCS11 %s Public Key\n", type_name);
        ret = p11prov_obj_export_public_key(
            key, CKK_ML_DSA, true, false, p11prov_mldsa_print_public_key, out);
        /* FIXME if we want print in different format */
        if (ret != RET_OSSL_OK) {
            BIO_printf(out, "[Error: Failed to decode public key data]\n");
        }
    }

    uri = p11prov_obj_get_public_uri(key);
    if (uri) {
        BIO_printf(out, "URI %s\n", uri);
    }

done:
    if (key != inkey) {
        p11prov_obj_free(key);
    }
    BIO_free(out);
    return RET_OSSL_OK;
}

const OSSL_DISPATCH p11prov_mldsa_encoder_text_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_TEXT_ENCODER_ELEM(ENCODE, mldsa, encode_text),
    { 0, NULL },
};
