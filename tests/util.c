/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <openssl/err.h>
#include <openssl/store.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
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
        fprintf(stderr, "[No errors on the OpenSSL stack]\n");
    }
    fflush(stderr);
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

X509 *load_cert(const char *uri, const UI_METHOD *ui_method, void *ui_data)
{
    OSSL_STORE_CTX *store;
    OSSL_STORE_INFO *info;
    X509 *cert = NULL;

    if (!uri) {
        fprintf(stderr, "Invalid NULL uri");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    store = OSSL_STORE_open(uri, ui_method, ui_data, NULL, NULL);
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

void hexify(char *out, unsigned char *byte, size_t len)
{
    char c[2], s;

    for (size_t i = 0; i < len; i++) {
        out[i * 3] = '%';
        c[0] = byte[i] >> 4;
        c[1] = byte[i] & 0x0f;
        for (int j = 0; j < 2; j++) {
            if (c[j] < 0x0A) {
                s = '0';
            } else {
                s = 'a' - 10;
            }
            out[i * 3 + 1 + j] = c[j] + s;
        }
    }
    out[len * 3] = '\0';
}

EVP_PKEY *util_gen_key(const char *type, const char *label)
{
    unsigned char id[16];
    char idhex[16 * 3 + 1];
    char *uri;
    const char *name = NULL;
    const char *ec_name = "EC";
    const char *named_curve = "named_curve";
    const char *curve = NULL;
    size_t rsa_bits = 3072;
    OSSL_PARAM params[4];
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key = NULL;
    int pnum = 0;
    int ret;

    ret = RAND_bytes(id, 16);
    if (ret != 1) {
        PRINTERROSSL("Failed to set generate key id\n");
        exit(EXIT_FAILURE);
    }

    hexify(idhex, id, 16);
    ret = asprintf(&uri, "pkcs11:object=%s;id=%s", label, idhex);
    if (ret == -1) {
        fprintf(stderr, "Failed to allocate uri\n");
        exit(EXIT_FAILURE);
    }

    params[pnum++] = OSSL_PARAM_construct_utf8_string("pkcs11_uri", uri, 0);
    if (strcmp(type, "RSA") == 0) {
        name = "RSA";
        params[pnum++] =
            OSSL_PARAM_construct_size_t("rsa_keygen_bits", &rsa_bits);
    } else if (strcmp(type, "RSA 2048") == 0) {
        name = "RSA";
        rsa_bits = 2048;
        params[pnum++] =
            OSSL_PARAM_construct_size_t("rsa_keygen_bits", &rsa_bits);
    } else if (strcmp(type, "RSA 3072") == 0) {
        name = "RSA";
        rsa_bits = 3072;
        params[pnum++] =
            OSSL_PARAM_construct_size_t("rsa_keygen_bits", &rsa_bits);
    } else if (strcmp(type, "RSA 4096") == 0) {
        name = "RSA";
        rsa_bits = 4096;
        params[pnum++] =
            OSSL_PARAM_construct_size_t("rsa_keygen_bits", &rsa_bits);
    } else if (strcmp(type, "P-256") == 0) {
        curve = "P-256";
    } else if (strcmp(type, "P-384") == 0) {
        curve = "P-384";
    } else if (strcmp(type, "P-521") == 0) {
        curve = "P-521";
    } else if (strcmp(type, "ED 25519") == 0) {
        name = "ED25519";
    } else if (strcmp(type, "ED 448") == 0) {
        name = "ED448";
    } else {
        /* Fall back to the provided type */
        name = type;
    }

    if (curve) {
        name = ec_name;
        params[pnum++] = OSSL_PARAM_construct_utf8_string("ec_paramgen_curve",
                                                          (char *)curve, 0);
        params[pnum++] = OSSL_PARAM_construct_utf8_string(
            "ec_param_enc", (char *)named_curve, 0);
    }

    params[pnum++] = OSSL_PARAM_construct_end();

    ctx = EVP_PKEY_CTX_new_from_name(NULL, name, "provider=pkcs11");
    if (ctx == NULL) {
        PRINTERROSSL("Failed to init PKEY context\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_keygen_init(ctx);
    if (ret != 1) {
        PRINTERROSSL("Failed to init keygen\n");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_set_params(ctx, params);

    ret = EVP_PKEY_generate(ctx, &key);
    EVP_PKEY_CTX_free(ctx);
    if (ret != 1) {
        PRINTERROSSL("Failed to generate key\n");
        exit(EXIT_FAILURE);
    }

    free(uri);
    return key;
}
