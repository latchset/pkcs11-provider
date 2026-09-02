/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   Copyright 2025 NXP
   SPDX-License-Identifier: Apache-2.0 */

#include "config.h"

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/provider.h>

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
EVP_PKEY *load_key_ex(const char *uri, const char *propq);
EVP_PKEY *load_key(const char *uri);
X509 *load_cert(const char *uri, const UI_METHOD *ui_method, void *ui_data);
void hexify(char *out, unsigned char *byte, size_t len);
void unhexify(unsigned char *out, size_t *outlen, const char *in);
EVP_PKEY *util_gen_key_ex(OSSL_LIB_CTX *libctx, const char *type,
                          const char *label);
EVP_PKEY *util_gen_key(const char *type, const char *label);
unsigned char *util_read_file(const char *path, size_t *size);
unsigned char *util_read_test_file(const char *filename, size_t *size);
OSSL_LIB_CTX *util_load_default_libctx(OSSL_PROVIDER **prov);
#if defined(HAVE_OSSL_PROVIDER_LOAD_EX)
#define CAN_LOAD_PKCS11_PROVIDER 1
OSSL_PROVIDER *util_load_pkcs11_provider(OSSL_LIB_CTX *libctx,
                                         const OSSL_PARAM *extra_params);
OSSL_LIB_CTX *util_load_pkcs11_libctx(OSSL_PROVIDER **def_prov,
                                      OSSL_PROVIDER **p11_prov,
                                      const OSSL_PARAM *extra_params);
#else
#define CAN_LOAD_PKCS11_PROVIDER 0
#endif
