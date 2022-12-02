/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/store.h>
#include <openssl/rand.h>

static EVP_PKEY *gen_key(void)
{
    char label[] = "##########: Fork Test Key";
    unsigned char id[16];
    size_t rsa_bits = 3072;
    OSSL_PARAM params[5];
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key = NULL;
    int miniid;
    int ret;

    /* RSA */
    ret = RAND_bytes(id, 16);
    if (ret != 1) {
        fprintf(stderr, "Failed to set generate key id\n");
        exit(EXIT_FAILURE);
    }

    miniid = (id[0] << 24) + (id[1] << 16) + (id[2] << 8) + id[3];
    snprintf(label, 10, "%08x", miniid);

    params[0] = OSSL_PARAM_construct_utf8_string("pkcs11_key_label", label, 0);
    params[1] = OSSL_PARAM_construct_octet_string("pkcs11_key_id", id, 16);
    params[2] = OSSL_PARAM_construct_size_t("rsa_keygen_bits", &rsa_bits);
    params[3] = OSSL_PARAM_construct_end();

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=pkcs11");
    if (ctx == NULL) {
        fprintf(stderr, "Failed to init PKEY context\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_keygen_init(ctx);
    if (ret != 1) {
        fprintf(stderr, "Failed to init keygen\n");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_set_params(ctx, params);

    ret = EVP_PKEY_generate(ctx, &key);
    if (ret != 1) {
        fprintf(stderr, "Failed to generate key\n");
        exit(EXIT_FAILURE);
    }

    return key;
}

static void sign_op(EVP_PKEY *key, pid_t pid)
{
    size_t size = EVP_PKEY_get_size(key);
    unsigned char sig[size];
    const char *data = "Sign Me!";
    EVP_MD_CTX *sign_md;
    int ret;

    sign_md = EVP_MD_CTX_new();
    ret = EVP_DigestSignInit_ex(sign_md, NULL, "SHA256", NULL, NULL, key, NULL);
    if (ret != 1) {
        fprintf(stderr, "Failed to init EVP_DigestSign (pid = %d)\n", pid);
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestSignUpdate(sign_md, data, sizeof(data));
    if (ret != 1) {
        fprintf(stderr, "Failed to EVP_DigestSignUpdate (pid = %d)\n", pid);
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestSignFinal(sign_md, sig, &size);
    if (ret != 1) {
        fprintf(stderr, "Failed to EVP_DigestSignFinal-ize (pid = %d)\n", pid);
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(sign_md);
}

int main(int argc, char *argv[])
{
    EVP_PKEY *key;
    pid_t pid;

    key = gen_key();

    /* test a simple op first */
    sign_op(key, 0);

    /* now fork and see if operations keep succeeding on both sides */
    pid = fork();
    if (pid == -1) {
        fprintf(stderr, "Fork failed");
        exit(EXIT_FAILURE);
    }

    sign_op(key, pid);

    fprintf(stderr, "ALL A-OK!");
    exit(EXIT_SUCCESS);
}
