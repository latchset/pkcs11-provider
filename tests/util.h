/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>

#define PRINTERR(...) \
    do { \
        fprintf(stderr, __VA_ARGS__); \
        fflush(stderr); \
    } while (0)

#define PRINTERROSSL(...) \
    do { \
        fprintf(stderr, __VA_ARGS__); \
        ERR_print_errors_fp(stderr); \
        fflush(stderr); \
    } while (0)

void ossl_err_print(void);
EVP_PKEY *load_key(const char *uri);
X509 *load_cert(const char *uri, const UI_METHOD *ui_method, void *ui_data);
void hexify(char *out, unsigned char *byte, size_t len);
EVP_PKEY *util_gen_key(const char *type, const char *label);
