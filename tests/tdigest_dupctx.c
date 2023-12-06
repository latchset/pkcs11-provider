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
        exit(EXIT_FAILURE);
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
    EVP_DigestInit_ex(mdctx, pk11md, NULL);

    EVP_MD_CTX *mdctx_dup = EVP_MD_CTX_new();
    EVP_MD_CTX_copy(mdctx_dup, mdctx);

    char error_string[2048];
    ERR_error_string_n(ERR_peek_last_error(), error_string,
                       sizeof error_string);
    printf("%s\n", error_string);

    EVP_MD_CTX_free(mdctx);
    EVP_MD_CTX_free(mdctx_dup);

    EVP_MD_free(pk11md);

    exit(EXIT_SUCCESS);
}
