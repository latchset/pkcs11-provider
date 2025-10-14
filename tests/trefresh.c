/* Copyright (C) 2025 Jakub Zelenka <jakub.openssl@gmail.com>
   SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/store.h>
#include <sys/wait.h>
#include <stdio.h>
#include "util.h"

static unsigned char *read_file(const char *filename, size_t *len) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        PRINTERR("Failed to open file: %s\n", filename);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    *len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *data = malloc(*len);
    if (!data) {
        PRINTERR("Failed to allocate memory for file\n");
        fclose(fp);
        return NULL;
    }

    if (fread(data, 1, *len, fp) != *len) {
        PRINTERR("Failed to read file\n");
        free(data);
        fclose(fp);
        return NULL;
    }

    fclose(fp);
    return data;
}

static void verify_op(EVP_PKEY *key, const char *input_file,
                      const unsigned char *sig, size_t sig_len,
                      pid_t pid, const char *stage) {
    EVP_MD_CTX *mdctx = NULL;
    unsigned char *input_data = NULL;
    size_t input_len;
    int ret;

    input_data = read_file(input_file, &input_len);
    if (!input_data) {
        PRINTERR("Failed to read input file (pid = %d, stage = %s)\n", pid,
                 stage);
        exit(EXIT_FAILURE);
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        PRINTERR("Failed to create MD_CTX (pid = %d, stage = %s)\n", pid,
                 stage);
        free(input_data);
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestVerifyInit_ex(mdctx, NULL, "sha256", NULL,
                                  "provider=pkcs11", key, NULL);
    if (ret != 1) {
        PRINTERROSSL("Failed to init digest verify (pid = %d, stage = %s)\n",
                     pid, stage);
        EVP_MD_CTX_free(mdctx);
        free(input_data);
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestVerifyUpdate(mdctx, input_data, input_len);
    if (ret != 1) {
        PRINTERROSSL("Failed to update digest verify (pid = %d, stage = %s)\n",
                     pid, stage);
        EVP_MD_CTX_free(mdctx);
        free(input_data);
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestVerifyFinal(mdctx, sig, sig_len);
    if (ret != 1) {
        PRINTERROSSL("Failed to verify signature (pid = %d, stage = %s)\n",
                     pid, stage);
        EVP_MD_CTX_free(mdctx);
        free(input_data);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);
    free(input_data);
}

static int do_public_encryption(EVP_PKEY *pubkey) {
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *out = NULL;
    size_t outlen;
    const char *msg = "Hello PKCS11!";
    int ret = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pubkey, "provider=pkcs11");
    if (!ctx) {
        PRINTERROSSL("Failed to create encryption context\n");
        goto cleanup;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        PRINTERROSSL("Failed to initialize encryption\n");
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        PRINTERROSSL("Failed to set padding\n");
        goto cleanup;
    }

    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, (const unsigned char*)msg, strlen(msg)) <= 0) {
        PRINTERROSSL("Failed to determine output length\n");
        goto cleanup;
    }

    out = OPENSSL_malloc(outlen);
    if (!out) {
        PRINTERROSSL("Failed to allocate output buffer\n");
        goto cleanup;
    }

    if (EVP_PKEY_encrypt(ctx, out, &outlen, (const unsigned char*)msg, strlen(msg)) <= 0) {
        PRINTERROSSL("Encryption failed\n");
        goto cleanup;
    }
    
    printf("Encryption successful! Encrypted %zu bytes\n", outlen);
    printf("Original message: %s\n", msg);
    printf("Encrypted data (hex): ");
    for (size_t i = 0; i < outlen; i++) {
        printf("%02x", out[i]);
    }
    printf("\n");
    
    ret = 1;

cleanup:
    if (out) OPENSSL_free(out);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    
    if (!ret) {
        ERR_print_errors_fp(stderr);
    }
    
    return ret;
}

int main(int argc, char *argv[]) {
    EVP_PKEY *pubkey, *privkey;
    unsigned char *sig;
    size_t sig_len;
    pid_t pid;
    int status;

    if (argc != 5) {
        fprintf(stderr, "Usage: %s <privkey_uri> <pubkey_uri> <input_file> <signature_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *privkey_uri = argv[1];
    const char *pubkey_uri = argv[2];
    const char *input_file = argv[3];
    const char *sig_file = argv[4];

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    sig = read_file(sig_file, &sig_len);
    if (!sig) {
        exit(EXIT_FAILURE);
    }

    privkey = load_key(privkey_uri);
    if (!privkey) {
        free(sig);
        exit(EXIT_FAILURE);
    }

    pubkey = load_key_ex(pubkey_uri, "provider=pkcs11");
    if (!pubkey) {
        EVP_PKEY_free(privkey);
        free(sig);
        exit(EXIT_FAILURE);
    }

    /* This is to test import */
    printf("Compare keys: %d\n", EVP_PKEY_eq(pubkey, privkey));

    pid = fork();
    if (pid == -1) {
        PRINTERR("Fork failed\n");
        EVP_PKEY_free(privkey);
        EVP_PKEY_free(pubkey);
        free(sig);
        exit(EXIT_FAILURE);
    }
    if (pid == 0) {
        /* verify and pub encrypt in child as refresh after for happens there */
        verify_op(pubkey, input_file, sig, sig_len, pid, "post-fork");
        do_public_encryption(pubkey);
        EVP_PKEY_free(privkey);
        EVP_PKEY_free(pubkey);
        PRINTERR("Child Done\n");
        exit(EXIT_SUCCESS);
    }

    /* nothing to do in parent as we just need to wait for child result */
    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);

    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        PRINTERR("Child failure\n");
        free(sig);
        exit(EXIT_FAILURE);
    }

    free(sig);

    exit(EXIT_SUCCESS);
}
