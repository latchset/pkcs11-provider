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

static unsigned char *compute_sha256(const char *input_file, size_t *hash_len) {
    unsigned char *input_data;
    size_t input_len;
    unsigned char *hash;
    EVP_MD_CTX *mdctx;
    unsigned int md_len;

    input_data = read_file(input_file, &input_len);
    if (!input_data) {
        return NULL;
    }

    hash = malloc(EVP_MAX_MD_SIZE);
    if (!hash) {
        PRINTERR("Failed to allocate memory for hash\n");
        free(input_data);
        return NULL;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        PRINTERR("Failed to create MD context\n");
        free(input_data);
        free(hash);
        return NULL;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        PRINTERROSSL("Failed to init digest\n");
        EVP_MD_CTX_free(mdctx);
        free(input_data);
        free(hash);
        return NULL;
    }

    if (EVP_DigestUpdate(mdctx, input_data, input_len) != 1) {
        PRINTERROSSL("Failed to update digest\n");
        EVP_MD_CTX_free(mdctx);
        free(input_data);
        free(hash);
        return NULL;
    }

    if (EVP_DigestFinal_ex(mdctx, hash, &md_len) != 1) {
        PRINTERROSSL("Failed to finalize digest\n");
        EVP_MD_CTX_free(mdctx);
        free(input_data);
        free(hash);
        return NULL;
    }

    EVP_MD_CTX_free(mdctx);
    free(input_data);

    *hash_len = md_len;
    return hash;
}

static void verify_op(EVP_PKEY *key, const unsigned char *hash, size_t hash_len,
                      const unsigned char *sig, size_t sig_len,
                      pid_t pid, const char *stage) {
    EVP_PKEY_CTX *pctx;
    int ret;

    pctx = EVP_PKEY_CTX_new(key, NULL);
    if (!pctx) {
        PRINTERR("Failed to create PKEY_CTX (pid = %d, stage = %s)\n", pid, stage);
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_verify_init(pctx);
    if (ret != 1) {
        PRINTERROSSL("Failed to init verify (pid = %d, stage = %s)\n",
                     pid, stage);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_base_id(key) == EVP_PKEY_RSA) {
        ret = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
        if (ret <= 0) {
            PRINTERROSSL("Failed to set RSA padding (pid = %d, stage = %s)\n",
                         pid, stage);
            EVP_PKEY_CTX_free(pctx);
            exit(EXIT_FAILURE);
        }
    }

    ret = EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha256());
    if (ret <= 0) {
        PRINTERROSSL("Failed to set signature MD (pid = %d, stage = %s)\n",
                     pid, stage);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_verify(pctx, sig, sig_len, hash, hash_len);
    if (ret != 1) {
        PRINTERROSSL("Failed to verify signature (pid = %d, stage = %s)\n",
                     pid, stage);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(pctx);
}

int main(int argc, char *argv[]) {
    EVP_PKEY *key;
    unsigned char *sig;
    unsigned char *hash;
    size_t sig_len;
    size_t hash_len;
    pid_t pid;
    int status;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s <PKCS11_URI> <input_file> <signature_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *pkcs11_uri = argv[1];
    const char *input_file = argv[2];
    const char *sig_file = argv[3];

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    hash = compute_sha256(input_file, &hash_len);
    if (!hash) {
        exit(EXIT_FAILURE);
    }

    sig = read_file(sig_file, &sig_len);
    if (!sig) {
        free(hash);
        exit(EXIT_FAILURE);
    }

    /* TODO: this is currently loads pub key to the store and does not use PKCS11 verify opts */
    key = load_key(pkcs11_uri);
    if (!key) {
        free(hash);
        free(sig);
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid == -1) {
        PRINTERR("Fork failed\n");
        EVP_PKEY_free(key);
        free(hash);
        free(sig);
        exit(EXIT_FAILURE);
    }
    if (pid == 0) {
        /* verify in child */
        verify_op(key, hash, hash_len, sig, sig_len, pid, "post-fork");
        EVP_PKEY_free(key);
        PRINTERR("Child Done\n");
        exit(EXIT_SUCCESS);
    }

    /* verify in parent */
    verify_op(key, hash, hash_len, sig, sig_len, pid, "post-fork");

    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        PRINTERR("Child failure\n");
        free(hash);
        free(sig);
        exit(EXIT_FAILURE);
    }

    free(hash);
    free(sig);

    exit(EXIT_SUCCESS);
}
