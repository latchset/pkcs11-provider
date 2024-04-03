/* Copyright (C) 2023 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0
*/

#include "provider.h"
#include "decoder.h"
#include "store.h"
#include "util.h"
#include "pk11_uri.h"
#include <openssl/asn1t.h>
#include <openssl/bio.h>

typedef struct p11prov_decoder_ctx {
    P11PROV_CTX *provctx;
} P11PROV_DECODER_CTX;

static void *p11prov_decoder_newctx(void *provctx)
{
    P11PROV_DECODER_CTX *dctx;
    dctx = OPENSSL_zalloc(sizeof(P11PROV_DECODER_CTX));
    if (!dctx) {
        return NULL;
    }

    dctx->provctx = provctx;
    return dctx;
}

static void p11prov_decoder_freectx(void *ctx)
{
    OPENSSL_clear_free(ctx, sizeof(P11PROV_DECODER_CTX));
}

static int obj_desc_verify(P11PROV_PK11_URI *obj)
{
    const char *desc = NULL;
    int desc_len;
    desc = (const char *)ASN1_STRING_get0_data(obj->desc);
    desc_len = ASN1_STRING_length(obj->desc);
    if (!desc || desc_len <= 0) {
        P11PROV_debug("Failed to get description");
        return RET_OSSL_ERR;
    }

    if (desc_len != (sizeof(P11PROV_DESCS_URI_FILE) - 1)
        || 0 != strncmp(desc, P11PROV_DESCS_URI_FILE, desc_len)) {
        P11PROV_debug("Description string does not match");
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static char *obj_uri_get1(P11PROV_PK11_URI *obj)
{
    const unsigned char *uri = ASN1_STRING_get0_data(obj->uri);
    int uri_len = ASN1_STRING_length(obj->uri);
    if (!uri || uri_len <= 0) {
        P11PROV_debug("Failed to get URI");
        return NULL;
    }
    return p11prov_alloc_sprintf(uri_len, "%*s", uri_len, uri);
}

struct desired_data_type_cbdata {
    const char *desired_data_type;
    OSSL_CALLBACK *cb;
    void *cbarg;
};

static int filter_for_desired_data_type(const OSSL_PARAM params[], void *arg)
{
    struct desired_data_type_cbdata *cbdata = arg;
    const OSSL_PARAM *p =
        OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_TYPE);
    const char *data_type = NULL;

    if (p && OSSL_PARAM_get_utf8_string_ptr(p, &data_type)
        && 0 == strcmp(cbdata->desired_data_type, data_type)) {
        return cbdata->cb(params, cbdata->cbarg);
    }

    return RET_OSSL_CARRY_ON_DECODING;
}

static int load_obj(const P11PROV_DECODER_CTX *ctx, const unsigned char *der,
                    long der_len, struct desired_data_type_cbdata *cbdata,
                    OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    P11PROV_PK11_URI *obj = NULL;
    char *uri = NULL;

    obj = d2i_P11PROV_PK11_URI(NULL, &der, der_len);
    if (!obj) {
        P11PROV_debug("P11 KEY DECODER d2i_P11PROV_PK11_URI failed");
        goto done;
    }

    if (!obj_desc_verify(obj)) {
        goto done;
    }

    uri = obj_uri_get1(obj);
    if (!uri) {
        goto done;
    }

    p11prov_store_direct_fetch(ctx->provctx, uri, filter_for_desired_data_type,
                               cbdata, pw_cb, pw_cbarg);
done:
    OPENSSL_free(uri);
    P11PROV_PK11_URI_free(obj);
    return RET_OSSL_CARRY_ON_DECODING;
}

static int p11prov_der_decoder_p11prov_obj_decode(
    const char *desired_data_type, void *inctx, OSSL_CORE_BIO *cin,
    int selection, OSSL_CALLBACK *object_cb, void *object_cbarg,
    OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    const P11PROV_DECODER_CTX *ctx = inctx;
    BIO *bin;
    unsigned char *der = NULL;
    long der_len;
    int ret = RET_OSSL_CARRY_ON_DECODING;

    bin = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cin);
    if (!bin) {
        P11PROV_debug("P11 DECODER BIO_new_from_core_bio failed");
        goto done;
    }

    der_len = BIO_get_mem_data(bin, &der);
    if (der_len <= 0) {
        P11PROV_debug("P11 DECODER BIO_get_mem_data failed");
        goto done;
    }

    struct desired_data_type_cbdata cbdata = {
        .desired_data_type = desired_data_type,
        .cb = object_cb,
        .cbarg = object_cbarg,
    };

    ret = load_obj(ctx, der, der_len, &cbdata, pw_cb, pw_cbarg);

done:
    BIO_free(bin);
    P11PROV_debug("der decoder (carry on:%d)", ret);
    return ret;
}

static int p11prov_pem_decoder_p11prov_der_decode(
    void *inctx, OSSL_CORE_BIO *cin, int selection, OSSL_CALLBACK *object_cb,
    void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{

    BIO *bin;
    char *pem_label;
    char *pem_header;
    unsigned char *der_data;
    long der_len;
    OSSL_PARAM params[3];
    int ret = RET_OSSL_CARRY_ON_DECODING;
    P11PROV_DECODER_CTX *ctx = inctx;

    bin = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cin);
    if (!bin) {
        P11PROV_debug("BIO_new_from_core_bio failed");
        return RET_OSSL_CARRY_ON_DECODING;
    }

    P11PROV_debug("PEM_read_bio (fpos:%u)", BIO_tell(bin));

    if (PEM_read_bio(bin, &pem_label, &pem_header, &der_data, &der_len) > 0
        && strcmp(pem_label, P11PROV_PEM_LABEL) == 0) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                      der_data, der_len);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_STRUCTURE, (char *)P11PROV_DER_STRUCTURE, 0);
        params[2] = OSSL_PARAM_construct_end();
        ret = object_cb(params, object_cbarg);
    }

    OPENSSL_free(pem_label);
    OPENSSL_free(pem_header);
    OPENSSL_free(der_data);
    BIO_free(bin);

    P11PROV_debug("pem decoder (carry on:%d)", ret);
    return ret;
}

P11PROV_DER_COMMON_DECODE_FN(P11PROV_NAME_RSA, rsa)
P11PROV_DER_COMMON_DECODE_FN(P11PROV_NAME_EC, ec)
P11PROV_DER_COMMON_DECODE_FN(P11PROV_NAME_ED25519, ed25519)
P11PROV_DER_COMMON_DECODE_FN(P11PROV_NAME_ED448, ed448)

DISPATCH_DECODER_FN_LIST(pem, p11prov, der);
DISPATCH_DECODER_FN_LIST(der, p11prov, rsa);
DISPATCH_DECODER_FN_LIST(der, p11prov, ec);
DISPATCH_DECODER_FN_LIST(der, p11prov, ed25519);
DISPATCH_DECODER_FN_LIST(der, p11prov, ed448);
