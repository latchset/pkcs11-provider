/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/store.h>
#include <sys/wait.h>
#include "util.h"

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
        PRINTERROSSL("Failed to init EVP_DigestSign (pid = %d)\n", pid);
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestSignUpdate(sign_md, data, sizeof(data));
    if (ret != 1) {
        PRINTERROSSL("Failed to EVP_DigestSignUpdate (pid = %d)\n", pid);
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestSignFinal(sign_md, sig, &size);
    if (ret != 1) {
        PRINTERROSSL("Failed to EVP_DigestSignFinal-ize (pid = %d)\n", pid);
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(sign_md);

    if (pid == 0) {
        EVP_PKEY_free(key);
        PRINTERR("Child Done\n");
        exit(EXIT_SUCCESS);
    }
}

/* forks in the middle of an op to check the child one fails */
static void fork_sign_op(EVP_PKEY *key)
{
    size_t size = EVP_PKEY_get_size(key);
    unsigned char sig[size];
    const char *data = "Sign Me!";
    EVP_MD_CTX *sign_md;
    pid_t pid;
    int ret;

    sign_md = EVP_MD_CTX_new();
    ret = EVP_DigestSignInit_ex(sign_md, NULL, "SHA256", NULL, NULL, key, NULL);
    if (ret != 1) {
        PRINTERROSSL("Failed to init EVP_DigestSign\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestSignUpdate(sign_md, data, sizeof(data));
    if (ret != 1) {
        PRINTERROSSL("Failed to EVP_DigestSignUpdate\n");
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid == -1) {
        PRINTERR("Fork failed");
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestSignFinal(sign_md, sig, &size);
    EVP_MD_CTX_free(sign_md);

    if (pid == 0) {
        /* child */
        if (ret != 0) {
            /* should have returned error in the child */
            PRINTERR("Child failed to fail!\n");
            exit(EXIT_FAILURE);
        }
        EVP_PKEY_free(key);
        PRINTERR("Child Done\n");
        fflush(stderr);
        exit(EXIT_SUCCESS);
    } else {
        int status;

        EVP_PKEY_free(key);
        /* parent */
        if (ret != 1) {
            PRINTERROSSL("Failed to EVP_DigestSignFinal-ize\n");
            exit(EXIT_FAILURE);
        }

        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            PRINTERR("Child failure\n");
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char *argv[])
{
    EVP_PKEY *key;
    pid_t pid;
    int status;

    key = util_gen_key("RSA", "Fork-Test");

    /* test a simple op first */
    sign_op(key, -1);

    /* now fork and see if operations keep succeeding on both sides */
    pid = fork();
    if (pid == -1) {
        PRINTERR("Fork failed\n");
        exit(EXIT_FAILURE);
    }

    /* child just exits in sign_po */
    sign_op(key, pid);

    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        PRINTERR("Child failure\n");
        exit(EXIT_FAILURE);
    }

    fork_sign_op(key);

    PRINTERR("ALL A-OK!\n");
    exit(EXIT_SUCCESS);
}
