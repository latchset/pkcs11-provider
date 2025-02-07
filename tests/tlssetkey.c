/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include "util.h"

int main(int argc, char *argv[])
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    SSL_CTX *ctx;
    int ret = 0;

    if (argc != 3) {
        fprintf(stderr, "Usage: tlssetkey [certuri] [pkeyuri]\n");
        exit(EXIT_FAILURE);
    }
    cert = load_cert(argv[1], NULL, NULL);
    pkey = load_key(argv[2]);

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL Context\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    ret = SSL_CTX_use_certificate(ctx, cert);
    if (ret != 1) {
        fprintf(stderr, "Failed to set Certificate");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    ret = SSL_CTX_use_PrivateKey(ctx, pkey);
    if (ret != 1) {
        fprintf(stderr, "Failed to set Private Key");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "Cert and Key successfully set on TLS Context!\n");

    SSL_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    exit(EXIT_SUCCESS);
}
