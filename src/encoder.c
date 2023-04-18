/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
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
    CK_ULONG keysize;
    char *uri = NULL;
    BIO *out;
    int ret;

    P11PROV_debug("RSA Text Encoder");

    type = p11prov_obj_get_key_type(key);
    if (type != CKK_RSA) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Invalid Key Type");
        return RET_OSSL_ERR;
    }

    out = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cbio);
    if (!out) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to init BIO");
        return RET_OSSL_ERR;
    }

    keysize = p11prov_obj_get_key_bit_size(key);

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        CK_OBJECT_CLASS class = p11prov_obj_get_class(key);
        if (class != CKO_PRIVATE_KEY) {
            return RET_OSSL_ERR;
        }
        BIO_printf(out, "PKCS11 RSA Private Key (%lu bits)\n", keysize);
        BIO_printf(out, "[Can't export and print private key data]\n");
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        BIO_printf(out, "PKCS11 RSA Public Key (%lu bits)\n", keysize);
        ret = p11prov_obj_export_public_rsa_key(
            key, p11prov_rsa_print_public_key, out);
        if (ret != RET_OSSL_OK) {
            BIO_printf(out, "[Error: Failed to decode public key data]\n");
        }
    }

    uri = p11prov_key_to_uri(ctx->provctx, key);
    if (uri) {
        BIO_printf(out, "URI %s\n", uri);
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

    ret = p11prov_obj_export_public_rsa_key(key, p11prov_rsa_set_asn1key_data,
                                            asn1key);

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
    int ret;

    ret = p11prov_rsa_pubkey_to_der(key, &der, &derlen);
    if (ret != RET_OSSL_OK) {
        return NULL;
    }

    pubkey = X509_PUBKEY_new();
    if (!pubkey) {
        OPENSSL_free(der);
        return NULL;
    }

    ret = X509_PUBKEY_set0_param(pubkey, OBJ_nid2obj(NID_rsaEncryption),
                                 V_ASN1_NULL, NULL, der, derlen);
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

/* ECDSA */

struct ecdsa_key_point {
    ASN1_OBJECT *curve;
    unsigned char *octet;
    size_t octet_len;
};

static void ecdsa_key_point_free(struct ecdsa_key_point *k)
{
    if (k->curve) {
        ASN1_OBJECT_free(k->curve);
        k->curve = NULL;
    }
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
    if (!p) {
        return RET_OSSL_ERR;
    }
    if (p->data_type != OSSL_PARAM_UTF8_STRING) {
        return RET_OSSL_ERR;
    }
    keypoint->curve = OBJ_txt2obj(p->data, 0);
    if (!keypoint->curve) {
        return RET_OSSL_ERR;
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

    ret = p11prov_obj_export_public_ec_key(key, p11prov_ec_set_keypoint_data,
                                           &keypoint);
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
                                 V_ASN1_OBJECT, keypoint.curve, keypoint.octet,
                                 keypoint.octet_len);
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
    CK_ULONG keysize;
    char *uri = NULL;
    BIO *out;
    int ret;

    P11PROV_debug("EC Text Encoder");

    type = p11prov_obj_get_key_type(key);
    if (type != CKK_EC) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Invalid Key Type");
        return RET_OSSL_ERR;
    }

    out = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cbio);
    if (!out) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to init BIO");
        return RET_OSSL_ERR;
    }

    keysize = p11prov_obj_get_key_bit_size(key);
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        CK_OBJECT_CLASS class = p11prov_obj_get_class(key);
        if (class != CKO_PRIVATE_KEY) {
            return RET_OSSL_ERR;
        }
        BIO_printf(out, "PKCS11 EC Private Key (%lu bits)\n", keysize);
        BIO_printf(out, "[Can't export and print private key data]\n");
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        BIO_printf(out, "PKCS11 EC Public Key (%lu bits)\n", keysize);
        ret = p11prov_obj_export_public_ec_key(key, p11prov_ec_print_public_key,
                                               out);
        if (ret != RET_OSSL_OK) {
            BIO_printf(out, "[Error: Failed to decode public key data]\n");
        }
    }

    uri = p11prov_key_to_uri(ctx->provctx, key);
    if (uri) {
        BIO_printf(out, "URI %s\n", uri);
    }

    OPENSSL_free(uri);
    BIO_free(out);
    return RET_OSSL_OK;
}

const OSSL_DISPATCH p11prov_ec_encoder_text_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_TEXT_ENCODER_ELEM(ENCODE, ec, encode_text),
    { 0, NULL },
};
