/* Copyright (C) 2023 Timo Teräs <timo.teras@iki.fi>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/store.h>
#include <openssl/core_names.h>
#include "util.h"

int main(int argc, char *argv[])
{
    EVP_PKEY *a, *b;
    int rc = EXIT_FAILURE;

    if (argc != 3) {
        fprintf(stderr, "Usage: tcmpkeys [keyuri-a] [keyuri-b]\n");
        exit(EXIT_FAILURE);
    }
    a = load_key(argv[1]);
    b = load_key(argv[2]);
    if (EVP_PKEY_eq(a, b) == 1) {
        rc = EXIT_SUCCESS;
    }
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    return rc;
}
