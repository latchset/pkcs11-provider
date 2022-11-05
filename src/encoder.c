/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <openssl/bio.h>

static void print_data_buffer(BIO *out, CK_BYTE *buf, int len, int justify,
                              int linelen)
{
    int lines = 1;
    int plen = len;
    int pidx = 0;

    if (linelen) {
        lines = len / linelen;
        if (len % linelen) {
            lines++;
        }
        plen = linelen;
    }

    for (int l = 0; l < lines; l++) {
        int i;
        if (plen > len) {
            plen = len;
        }
        if (justify) {
            BIO_printf(out, "%*s", justify, "");
        }
        for (i = 0; i < plen; i++) {
            char c[2];
            c[0] = (buf[pidx + i] >> 4);
            c[1] = (buf[pidx + i] & 0x0f);
            for (int j = 0; j < 2; j++) {
                c[j] += '0';
                if (c[j] > '9') {
                    c[j] += ('a' - '0' - 10);
                }
            }
            BIO_write(out, c, 2);
        }
        len -= plen;
        pidx += i;
        BIO_write(out, "\n", 1);
    }
}

DISPATCH_BASE_ENCODER_FN(newctx);
DISPATCH_BASE_ENCODER_FN(freectx);
DISPATCH_TEXT_ENCODER_FN(rsa, encode);

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

static int p11prov_rsa_encoder_encode_text(void *inctx, OSSL_CORE_BIO *cbio,
                                           const void *inkey,
                                           const OSSL_PARAM key_abstract[],
                                           int selection,
                                           OSSL_PASSPHRASE_CALLBACK *cb,
                                           void *cbarg)
{
    struct p11prov_encoder_ctx *ctx = (struct p11prov_encoder_ctx *)inctx;
    CK_OBJECT_CLASS class = CK_UNAVAILABLE_INFORMATION;
    P11PROV_OBJ *obj = (P11PROV_OBJ *)inkey;
    P11PROV_KEY *key;
    CK_KEY_TYPE type;
    CK_ULONG keysize;
    CK_ATTRIBUTE *a;
    BIO *out;

    P11PROV_debug("RSA Text Encoder");

    switch (selection) {
    case OSSL_KEYMGMT_SELECT_PRIVATE_KEY:
        class = CKO_PRIVATE_KEY;
        break;
    case OSSL_KEYMGMT_SELECT_PUBLIC_KEY:
        class = CKO_PUBLIC_KEY;
        break;
    case OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS:
        return RET_OSSL_ERR;
    }

    key = p11prov_object_get_key(obj);
    if (!key) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Invalid Object class");
        return RET_OSSL_ERR;
    }

    if (p11prov_key_class(key) != class) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Invalid Key class");
        p11prov_key_free(key);
        return RET_OSSL_ERR;
    }

    type = p11prov_key_type(key);
    if (type != CKK_RSA) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Invalid Key Type");
        p11prov_key_free(key);
        return RET_OSSL_ERR;
    }

    out = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cbio);
    if (!out) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to init BIO");
        p11prov_key_free(key);
        return RET_OSSL_ERR;
    }

    keysize = p11prov_key_size(key);
    if (class == CKO_PRIVATE_KEY) {
        BIO_printf(out, "PKCS11 RSA Private Key (%lu bits)\n", keysize * 8);
    } else {
        BIO_printf(out, "PKCS11 RSA Public Key (%lu bits)\n", keysize * 8);
    }

    a = p11prov_key_attr(key, CKA_ID);
    if (a) {
        if (a->ulValueLen > 16) {
            BIO_printf(out, "  Key ID:\n");
            print_data_buffer(out, a->pValue, a->ulValueLen, 4, 16);
        } else {
            BIO_printf(out, "  Key ID: ");
            print_data_buffer(out, a->pValue, a->ulValueLen, 0, 0);
        }
    }
    a = p11prov_key_attr(key, CKA_LABEL);
    if (a) {
        BIO_printf(out, "  Label: %*s\n", (int)a->ulValueLen,
                   (char *)a->pValue);
    }
    a = p11prov_key_attr(key, CKA_PUBLIC_EXPONENT);
    if (a) {
        BIO_printf(out, "  Exponent: 0x");
        print_data_buffer(out, a->pValue, a->ulValueLen, 0, 0);
        BIO_write(out, "\n", 1);
    }
    a = p11prov_key_attr(key, CKA_MODULUS);
    if (a) {
        BIO_printf(out, "  Modulus:\n");
        print_data_buffer(out, a->pValue, a->ulValueLen, 4, 16);
    }

    BIO_free(out);
    p11prov_key_free(key);
    return RET_OSSL_OK;
}

const OSSL_DISPATCH p11prov_rsa_encoder_text_functions[] = {
    DISPATCH_BASE_ENCODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_ENCODER_ELEM(FREECTX, freectx),
    DISPATCH_TEXT_ENCODER_ELEM(ENCODE, rsa, encode_text),
    { 0, NULL },
};

DISPATCH_ENCODER_FN(rsa, pkcs1, der, does_selection);

static int p11prov_rsa_encoder_pkcs1_der_does_selection(void *inctx,
                                                        int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        return RET_OSSL_ERR;
    } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return RET_OSSL_ERR;
    } else if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
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
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        return RET_OSSL_ERR;
    } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return RET_OSSL_ERR;
    } else if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
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
