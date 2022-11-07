/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <openssl/ssl.h>

int main(int argc, char *argv[])
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL Context\n");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "SSL Context works!\n");

    exit(EXIT_SUCCESS);
}
