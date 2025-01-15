/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include "util.h"

static void test_pkcs1_with_tls_padding(void)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *prikey;
    EVP_PKEY *pubkey;
    unsigned char plain[SSL_MAX_MASTER_KEY_LENGTH] = { 0x03, 0x03, 0x01 };
    unsigned char enc[1024];
    unsigned char dec[1024];
    size_t enclen;
    size_t declen;
    unsigned int ver = 0x0303;
    const OSSL_PARAM ver_params[] = {
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, &ver),
        OSSL_PARAM_END
    };
    int err;

    pubkey = load_key(getenv("PUBURI"));

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pubkey, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to init pkey ctx for puburi\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }
    err = EVP_PKEY_encrypt_init(ctx);
    if (err != 1) {
        fprintf(stderr, "Failed to init encrypt ctx\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }
    err = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    if (err != 1) {
        fprintf(stderr, "Failed to set padding on encrypt ctx\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    enclen = sizeof(enc);
    err = EVP_PKEY_encrypt(ctx, enc, &enclen, plain, sizeof(plain));
    if (err != 1) {
        fprintf(stderr, "Failed to encrypt TLS master key\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubkey);

    prikey = load_key(getenv("PRIURI"));

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, prikey, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to init pkey ctx for priuri\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }
    err = EVP_PKEY_decrypt_init(ctx);
    if (err != 1) {
        fprintf(stderr, "Failed to init decrypt ctx\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }
    err = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_WITH_TLS_PADDING);
    if (err != 1) {
        fprintf(stderr, "Failed to set padding on decrypt ctx\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    err = EVP_PKEY_CTX_set_params(ctx, ver_params);
    if (err != 1) {
        fprintf(stderr, "Failed to set version params\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    declen = sizeof(dec);
    err = EVP_PKEY_decrypt(ctx, dec, &declen, enc, enclen);
    if (err != 1) {
        fprintf(stderr, "Failed to decrypt TLS master key\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(prikey);

    if ((declen != sizeof(plain)) || (memcmp(plain, dec, declen) != 0)) {
        fprintf(stderr, "Fail, decrypted master secret differs from input\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    SSL_CTX *ctx;
    char *env;

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL Context\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "SSL Context works!\n");

    SSL_CTX_free(ctx);

    env = getenv("SUPPORT_RSA_PKCS1_ENCRYPTION");
    if (env && env[0] == "1") {
        test_pkcs1_with_tls_padding();
    }

    exit(EXIT_SUCCESS);
}
