/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static void ossl_err_print(void)
{
    bool first = true;
    unsigned long err = 0;
    while (true) {
        const char *file, *func, *data;
        int line;
        err = ERR_get_error_all(&file, &line, &func, &data, NULL);
        if (err == 0) break;

        char buf[1024];
        ERR_error_string_n(err, buf, sizeof(buf));

        const char *fmt =
            first ? ": %s (in function %s in %s:%d): %s\n"
                  : "  caused by: %s (in function %s in %s:%d): %s\n";
        fprintf(stderr, fmt, buf, func, file, line, data);

        first = false;
    }
    if (first) fprintf(stderr, "\n");
}

int main(int argc, char *argv[])
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL Context\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "SSL Context works!\n");

    exit(EXIT_SUCCESS);
}
