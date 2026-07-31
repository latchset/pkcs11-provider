/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#define EXIT_TEST_SKIPPED 77

int main(int argc, char *argv[])
{
    const char *propq = "provider=pkcs11";
    const char *digest = "sha256";
    const char *provname;
    const OSSL_PROVIDER *pk11prov;

    EVP_MD *pk11md = EVP_MD_fetch(NULL, digest, propq);
    if (!pk11md) {
        fprintf(stderr, "%s: Unsupported by pkcs11 token\n", digest);
        exit(EXIT_TEST_SKIPPED);
    }

    pk11prov = EVP_MD_get0_provider(pk11md);
    provname = OSSL_PROVIDER_get0_name(pk11prov);

    if (strcmp(provname, "pkcs11") != 0) {
        fprintf(stderr, "%s: Not a pkcs11 method, provider=%s\n", digest,
                provname);
        EVP_MD_free(pk11md);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL || EVP_DigestInit_ex(mdctx, pk11md, NULL) == 0) {
        fprintf(stderr, "%s: Failed to initialize digest\n", digest);
        EVP_MD_free(pk11md);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX *mdctx_dup = EVP_MD_CTX_new();
    if (EVP_MD_CTX_copy_ex(mdctx_dup, mdctx) == 0) {
        char error_string[2048];
        ERR_error_string_n(ERR_peek_last_error(), error_string,
                           sizeof error_string);
        fprintf(stderr, "%s\n", error_string);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);
    EVP_MD_CTX_free(mdctx_dup);
    EVP_MD_free(pk11md);

    fprintf(stderr, "Success");
    exit(EXIT_SUCCESS);
}
