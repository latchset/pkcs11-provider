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
#if defined(OSSL_PROVIDER_load_ex)
    OSSL_PROVIDER *prov = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    const unsigned char data[] = "Sign Me!";
    unsigned char *sig = NULL;
    size_t siglen = 0;
    OSSL_PARAM params[5];
    const char *module = getenv("PKCS11_PROVIDER_MODULE");
    const char *pin = getenv("PINVALUE");
    const char *libspath = getenv("LIBSPATH");
    int p = 0;
    int ret;

    if (module == NULL) {
        PRINTERR("PKCS11_PROVIDER_MODULE environment variable is absent\n");
        exit(EXIT_FAILURE);
    }
    if (pin == NULL) {
        PRINTERR("PINVALUE environment variable is absent\n");
        exit(EXIT_FAILURE);
    }
    if (libspath == NULL) {
        PRINTERR("LIBSPATH environment variable is absent\n");
        exit(EXIT_FAILURE);
    }

    params[p++] = OSSL_PARAM_construct_utf8_string("pkc11-module-path",
                                                   (char *)module, 0);
    params[p++] = OSSL_PARAM_construct_utf8_string("pkcs11-module-token-pin",
                                                   (char *)pin, 0);
    params[p++] = OSSL_PARAM_construct_utf8_string(
        "pkcs11-module-encode-provider-uri-to-pem", (char *)"true", 0);
    params[p++] = OSSL_PARAM_construct_utf8_string(
        "pkcs11-module-load-behavior", (char *)"early", 0);
    params[p++] = OSSL_PARAM_construct_end();

    if (!OSSL_PROVIDER_available(NULL, "default")) {
        PRINTERR("Default provider is not loaded\n");
        exit(EXIT_FAILURE);
    }

    OSSL_PROVIDER_set_default_search_path(NULL, libspath);

    prov = OSSL_PROVIDER_load_ex(NULL, "pkcs11", params);
    if (prov == NULL) {
        PRINTERROSSL("Failed to load pkcs11 provider\n");
        exit(EXIT_FAILURE);
    }

    key = util_gen_key("RSA 2048", "tloadprov test key");
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

    ret = EVP_DigestSignInit_ex(md_ctx, NULL, "SHA256", NULL, NULL, key, NULL);
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
    OSSL_PROVIDER_unload(prov);
#endif
    PRINTERR("ALL A-OK!\n");
    exit(EXIT_SUCCESS);
}
