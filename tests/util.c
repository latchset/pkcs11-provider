/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdbool.h>
#include <openssl/err.h>
#include <openssl/store.h>
#include "util.h"

void ossl_err_print(void)
{
    bool first = true;
    unsigned long err = 0;
    while (true) {
        const char *file, *func, *data;
        int line;
        err = ERR_get_error_all(&file, &line, &func, &data, NULL);
        if (err == 0) {
            break;
        }

        char buf[1024];
        ERR_error_string_n(err, buf, sizeof(buf));

        const char *fmt =
            first ? ": %s (in function %s in %s:%d): %s\n"
                  : "  caused by: %s (in function %s in %s:%d): %s\n";
        fprintf(stderr, fmt, buf, func, file, line, data);

        first = false;
    }
    if (first) {
        fprintf(stderr, "\n");
    }
}

EVP_PKEY *load_key(const char *uri)
{
    OSSL_STORE_CTX *store;
    OSSL_STORE_INFO *info;
    EVP_PKEY *key = NULL;

    if (!uri) {
        fprintf(stderr, "Invalid NULL uri");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    store = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
    if (store == NULL) {
        fprintf(stderr, "Failed to open store: %s\n", uri);
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    if ((strncmp(uri, "pkcs11:", 7) == 0)
        && strstr(uri, "type=private") == NULL) {
        /* This is a workaround for OpenSSL < 3.2.0 where the code fails
         * to correctly source public keys unless explicitly requested
         * via an expect hint */
        if (OSSL_STORE_expect(store, OSSL_STORE_INFO_PUBKEY) != 1) {
            fprintf(stderr, "Failed to expect Public Key File\n");
            exit(EXIT_FAILURE);
        }
    }

    for (info = OSSL_STORE_load(store); info != NULL;
         info = OSSL_STORE_load(store)) {
        int type = OSSL_STORE_INFO_get_type(info);

        if (key != NULL) {
            fprintf(stderr, "Multiple keys matching URI: %s\n", uri);
            exit(EXIT_FAILURE);
        }

        switch (type) {
        case OSSL_STORE_INFO_PUBKEY:
            key = OSSL_STORE_INFO_get1_PUBKEY(info);
            break;
        case OSSL_STORE_INFO_PKEY:
            key = OSSL_STORE_INFO_get1_PKEY(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    if (key == NULL) {
        fprintf(stderr, "Failed to load key from URI: %s\n", uri);
        ossl_err_print();
        exit(EXIT_FAILURE);
    }
    OSSL_STORE_close(store);

    return key;
}

X509 *load_cert(const char *uri)
{
    OSSL_STORE_CTX *store;
    OSSL_STORE_INFO *info;
    X509 *cert = NULL;

    if (!uri) {
        fprintf(stderr, "Invalid NULL uri");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    store = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
    if (store == NULL) {
        fprintf(stderr, "Failed to open store: %s\n", uri);
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    for (info = OSSL_STORE_load(store); info != NULL;
         info = OSSL_STORE_load(store)) {
        int type = OSSL_STORE_INFO_get_type(info);

        if (cert != NULL) {
            fprintf(stderr, "Multiple certs matching URI: %s\n", uri);
            exit(EXIT_FAILURE);
        }

        switch (type) {
        case OSSL_STORE_INFO_CERT:
            cert = OSSL_STORE_INFO_get1_CERT(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    if (cert == NULL) {
        fprintf(stderr, "Failed to load cert from URI: %s\n", uri);
        ossl_err_print();
        exit(EXIT_FAILURE);
    }
    OSSL_STORE_close(store);

    return cert;
}
