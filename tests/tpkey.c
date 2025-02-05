/* Copyright (C) 2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/store.h>
#include <sys/wait.h>
#include "util.h"

static void sign_op(EVP_PKEY *key, const char *data, size_t len,
                    unsigned char **signature, size_t *siglen)
{
    size_t size = EVP_PKEY_get_size(key);
    unsigned char *sig;
    EVP_MD_CTX *sign_md;
    int ret;

    sig = OPENSSL_zalloc(size);
    if (!sig) {
        PRINTERROSSL("Failed to allocate signature buffer\n");
        exit(EXIT_FAILURE);
    }

    *signature = sig;
    *siglen = size;

    sign_md = EVP_MD_CTX_new();
    ret = EVP_DigestSignInit_ex(sign_md, NULL, "SHA256", NULL, NULL, key, NULL);
    if (ret != 1) {
        PRINTERROSSL("Failed to init EVP_DigestSign\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestSignUpdate(sign_md, data, len);
    if (ret != 1) {
        PRINTERROSSL("Failed to EVP_DigestSignUpdate\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestSignFinal(sign_md, sig, siglen);
    if (ret != 1) {
        PRINTERROSSL("Failed to EVP_DigestSignFinal-ize\n");
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(sign_md);
}

static void verify_op(EVP_PKEY *key, const char *data, size_t len,
                      unsigned char *signature, size_t siglen)
{
    EVP_MD_CTX *ver_md;
    int ret;

    ver_md = EVP_MD_CTX_new();
    ret =
        EVP_DigestVerifyInit_ex(ver_md, NULL, "SHA256", NULL, NULL, key, NULL);
    if (ret != 1) {
        PRINTERROSSL("Failed to init EVP_DigestVerify\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestVerifyUpdate(ver_md, data, len);
    if (ret != 1) {
        PRINTERROSSL("Failed to EVP_DigestVerifyUpdate\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestVerifyFinal(ver_md, signature, siglen);
    if (ret != 1) {
        PRINTERROSSL("Failed to EVP_DigestVerifyFinal-ize/bad signature\n");
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(ver_md);
}

static void check_public_info(EVP_PKEY *key)
{
    BIO *membio = BIO_new(BIO_s_mem());
    BUF_MEM *memdata = NULL;
    const char *type = "type=public";
    void *found = NULL;
    int ret;

    if (!membio) {
        PRINTERROSSL("Failed to instantiate Memory BIO\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_print_public(membio, key, 0, NULL);
    if (ret != 1) {
        PRINTERROSSL("Failed to print public key info\n");
        exit(EXIT_FAILURE);
    }

    BIO_get_mem_ptr(membio, &memdata);
    if (!memdata) {
        PRINTERROSSL("Failed to fetch BIO memory pointer\n");
        exit(EXIT_FAILURE);
    }

    found = memmem(memdata->data, memdata->length, type, sizeof(type) - 1);
    if (!found) {
        PRINTERR("%.*s\n", (int)memdata->length, memdata->data);
        PRINTERROSSL("Public type indicator not found in printout!\n");
        exit(EXIT_FAILURE);
    }

    BIO_free(membio);
}

int main(int argc, char *argv[])
{
    const char *data = "Sign Me!";
    unsigned char *sig;
    size_t siglen;
    EVP_PKEY *key;

    key = util_gen_key("Pkey sigver Test");

    /* test a simple op first */
    sign_op(key, data, sizeof(data), &sig, &siglen);

    verify_op(key, data, sizeof(data), sig, siglen);

    check_public_info(key);

    PRINTERR("ALL A-OK!\n");
    exit(EXIT_SUCCESS);
}
