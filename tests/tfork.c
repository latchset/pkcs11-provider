/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
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

static int verify_op(EVP_PKEY *key, unsigned char *data, size_t datalen,
                     unsigned char *sig, size_t siglen, pid_t pid)
{
    EVP_SIGNATURE *sig_alg;
    EVP_PKEY_CTX *pctx;
    int ret;

    sig_alg = EVP_SIGNATURE_fetch(NULL, "ECDSA", "provider=pkcs11");
    if (!sig_alg) {
        PRINTERROSSL("Failed to fetch ECDSA signature algorithm (pid = %d)\n",
                     (int)pid);
        return 0;
    }

    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=pkcs11");
    if (!pctx) {
        PRINTERROSSL("Failed to create EVP_PKEY_CTX (pid = %d)\n", (int)pid);
        EVP_SIGNATURE_free(sig_alg);
        return 0;
    }

    ret = EVP_PKEY_verify_init(pctx);
    if (ret != 1) {
        PRINTERROSSL("Failed to init EVP_PKEY_verify (pid = %d)\n", (int)pid);
        EVP_PKEY_CTX_free(pctx);
        EVP_SIGNATURE_free(sig_alg);
        return 0;
    }

    ret = EVP_PKEY_verify(pctx, sig, siglen, data, datalen);
    if (ret != 1) {
        PRINTERROSSL("Failed to EVP_PKEY_verify (pid = %d)\n", (int)pid);
        EVP_PKEY_CTX_free(pctx);
        EVP_SIGNATURE_free(sig_alg);
        return 0;
    }

    EVP_PKEY_CTX_free(pctx);
    EVP_SIGNATURE_free(sig_alg);

    return 1;
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

static void fork_verify_op(void)
{
    OSSL_PARAM *params = NULL;
    EVP_PKEY *pubkey = NULL;
    EVP_PKEY *pk11_key = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_STORE_CTX *sctx = NULL;
    unsigned char *sig = NULL;
    size_t siglen;
    unsigned char *data = NULL;
    size_t datalen;
    int ret;
    int pipefds[2];
    pid_t pid;
    const char *test_path;
    char path[1024];

    test_path = getenv("TEST_PATH");
    if (!test_path) {
        test_path = "tests";
    }

    snprintf(path, sizeof(path), "%s/fork-pubkey.pem", test_path);
    sctx = OSSL_STORE_open(path, NULL, NULL, NULL, NULL);
    if (!sctx) {
        PRINTERROSSL("Failed to open %s\n", path);
        exit(EXIT_FAILURE);
    }

    while (!OSSL_STORE_eof(sctx)) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(sctx);

        if (!info) continue;

        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
            pubkey = OSSL_STORE_INFO_get1_PKEY(info);
        } else if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PUBKEY) {
            pubkey = OSSL_STORE_INFO_get1_PUBKEY(info);
        }
        OSSL_STORE_INFO_free(info);

        if (pubkey) break;
    }
    OSSL_STORE_close(sctx);

    if (!pubkey) {
        PRINTERROSSL("Failed to read %s\n", path);
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_todata(pubkey, EVP_PKEY_PUBLIC_KEY, &params);
    if (ret != 1) {
        PRINTERROSSL("Failed to export key to params\n");
        exit(EXIT_FAILURE);
    }

    pctx = EVP_PKEY_CTX_new_from_name(NULL, EVP_PKEY_get0_type_name(pubkey),
                                      "provider=pkcs11");
    if (!pctx) {
        PRINTERROSSL("Failed to create EVP_PKEY_CTX for pkcs11\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_fromdata_init(pctx) != 1
        || EVP_PKEY_fromdata(pctx, &pk11_key, EVP_PKEY_PUBLIC_KEY, params)
               != 1) {
        PRINTERROSSL("Failed to import key to pkcs11 provider\n");
        exit(EXIT_FAILURE);
    }
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    EVP_PKEY_free(pubkey);

    sig = util_read_test_file("fork-data.sig", &siglen);
    data = util_read_test_file("fork-data.txt", &datalen);

    /* first verify_op */
    ret = verify_op(pk11_key, data, datalen, sig, siglen, -1);
    if (ret != 1) {
        PRINTERR("First verify_op failed\n");
        exit(EXIT_FAILURE);
    }

    if (pipe(pipefds) == -1) {
        PRINTERR("Pipe failed\n");
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid == -1) {
        PRINTERR("Fork failed\n");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        /* child */
        close(pipefds[0]);
        int child_res = verify_op(pk11_key, data, datalen, sig, siglen, 0);
        if (write(pipefds[1], &child_res, sizeof(child_res))
            != sizeof(child_res)) {
            PRINTERR("Child write to pipe failed\n");
        }
        close(pipefds[1]);
        EVP_PKEY_free(pk11_key);
        free(data);
        free(sig);
        PRINTERR("Child Done\n");
        exit(child_res == 1 ? EXIT_SUCCESS : EXIT_FAILURE);
    } else {
        /* parent */
        int parent_res;
        int child_res = 0;
        int status = 0;
        ssize_t rlen;

        close(pipefds[1]);

        parent_res = verify_op(pk11_key, data, datalen, sig, siglen, pid);

        rlen = read(pipefds[0], &child_res, sizeof(child_res));
        close(pipefds[0]);

        waitpid(pid, &status, 0);

        EVP_PKEY_free(pk11_key);
        free(data);
        free(sig);

        if (parent_res != 1) {
            PRINTERR("Parent verify_op failed\n");
            exit(EXIT_FAILURE);
        }

        if (rlen != sizeof(child_res) || child_res != 1) {
            PRINTERR("Child verify_op failed\n");
            exit(EXIT_FAILURE);
        }

        if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
            PRINTERR("Child failure status\n");
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

    /* child just exits in sign_op */
    sign_op(key, pid);

    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        PRINTERR("Child failure\n");
        exit(EXIT_FAILURE);
    }

    fork_sign_op(key);

    fork_verify_op();

    PRINTERR("ALL A-OK!\n");
    exit(EXIT_SUCCESS);
}
