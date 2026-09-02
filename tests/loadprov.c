/* Copyright (C) 2026 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/store.h>
#include "util.h"

int main(int argc, char *argv[])
{
#if CAN_LOAD_PKCS11_PROVIDER
    OSSL_LIB_CTX *p11_libctx = NULL;
    OSSL_PROVIDER *def_prov = NULL;
    OSSL_PROVIDER *p11_prov = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    const unsigned char data[] = "Sign Me!";
    unsigned char *sig = NULL;
    size_t siglen = 0;
    OSSL_PARAM params[2];
    int ret;

    params[0] = OSSL_PARAM_construct_utf8_string(
        "pkcs11-module-encode-provider-uri-to-pem", (char *)"true", 0);
    params[1] = OSSL_PARAM_construct_end();

    p11_libctx = util_load_pkcs11_libctx(&def_prov, &p11_prov, params);
    if (p11_prov == NULL) {
        PRINTERROSSL("Failed to load pkcs11 provider\n");
        exit(EXIT_FAILURE);
    }

    key = util_gen_key_ex(p11_libctx, "RSA 2048", "tloadprov test key");
    if (key == NULL) {
        PRINTERROSSL("Failed to generate key\n");
        exit(EXIT_FAILURE);
    }

    siglen = EVP_PKEY_get_size(key);
    sig = OPENSSL_zalloc(siglen);
    if (sig == NULL) {
        PRINTERROSSL("Failed to allocate signature buffer\n");
        exit(EXIT_FAILURE);
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        PRINTERROSSL("Failed to create EVP_MD_CTX\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestSignInit_ex(md_ctx, NULL, "SHA256", p11_libctx, NULL, key,
                                NULL);
    if (ret != 1) {
        PRINTERROSSL("Failed to init EVP_DigestSign\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestSign(md_ctx, sig, &siglen, data, sizeof(data));
    if (ret != 1) {
        PRINTERROSSL("Failed to perform EVP_DigestSign\n");
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(md_ctx);
    OPENSSL_free(sig);
    EVP_PKEY_free(key);
    OSSL_PROVIDER_unload(p11_prov);
    OSSL_PROVIDER_unload(def_prov);
    OSSL_LIB_CTX_free(p11_libctx);
#endif
    PRINTERR("ALL A-OK!\n");
    exit(EXIT_SUCCESS);
}
