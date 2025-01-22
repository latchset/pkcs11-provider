/* Copyright (C) 2025 Jakub Zelenka <jakub.openssl@gmail.com>
   SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/store.h>
#include <sys/wait.h>
#include <stdio.h>
#include "util.h"

int main(int argc, char *argv[])
{
    EVP_PKEY *pubkey, *pubkey_main;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pubkey>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *pubkey_uri = argv[1];

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    pubkey_main = load_key_ex(pubkey_uri, "provider=pkcs11");
    if (!pubkey_main) {
        exit(EXIT_FAILURE);
    }

    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int ret;

    ret = EVP_PKEY_todata(pubkey_main, EVP_PKEY_PUBLIC_KEY, &params);
    if (ret != 1) {
        PRINTERROSSL("Failed to export key params\n");
        EVP_PKEY_free(pubkey_main);
        exit(EXIT_FAILURE);
    }

    pctx = EVP_PKEY_CTX_new_from_name(
        NULL, EVP_PKEY_get0_type_name(pubkey_main), "provider=pkcs11");
    EVP_PKEY_free(pubkey_main);
    if (!pctx) {
        PRINTERROSSL("Failed to create fromdata ctx\n");
        OSSL_PARAM_free(params);
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_fromdata_init(pctx);
    if (ret != 1) {
        PRINTERROSSL("Failed to init fromdata\n");
        EVP_PKEY_CTX_free(pctx);
        OSSL_PARAM_free(params);
        exit(EXIT_FAILURE);
    }

    pubkey = NULL;
    ret = EVP_PKEY_fromdata(pctx, &pubkey, EVP_PKEY_PUBLIC_KEY, params);
    if (ret != 1) {
        PRINTERROSSL("Failed to import key via fromdata\n");
        EVP_PKEY_CTX_free(pctx);
        OSSL_PARAM_free(params);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);

    EVP_PKEY_free(pubkey);

    exit(EXIT_SUCCESS);
}
