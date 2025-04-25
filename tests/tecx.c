/* Copyright (C) 2023 Timo Teräs <timo.teras@iki.fi>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/store.h>
#include <openssl/core_names.h>
#include "util.h"

static void ecdh_test(EVP_PKEY *a, EVP_PKEY *b)
{
    unsigned char secret[64];
    size_t secretlen = 64;
    EVP_PKEY_CTX *derivectx;

    derivectx = EVP_PKEY_CTX_new_from_pkey(NULL, a, NULL);
    if (!derivectx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed!");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_derive_init(derivectx) != 1) {
        fprintf(stderr, "EVP_PKEY_derive_init failed!");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_derive_set_peer(derivectx, b) != 1) {
        fprintf(stderr, "EVP_PKEY_derive_set_peer failed!");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_derive(derivectx, secret, &secretlen) != 1) {
        fprintf(stderr, "EVP_PKEY_derive failed!");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(derivectx);
}

int main(int argc, char *argv[])
{
    EVP_PKEY *a, *b;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s [keyuri-a] [keyuri-b]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    a = load_key(argv[1]);
    b = load_key(argv[2]);

    ecdh_test(a, b);

    EVP_PKEY_free(a);
    EVP_PKEY_free(b);

    PRINTERR("ALL A-OK!\n");
    exit(EXIT_SUCCESS);
}
