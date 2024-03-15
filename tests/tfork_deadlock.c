/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <sys/wait.h>

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

static void sign_op(EVP_PKEY *key)
{
    size_t size = EVP_PKEY_get_size(key);
    unsigned char sig[size];
    const char *data = "Sign Me!";
    EVP_MD_CTX *sign_md;
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

    ret = EVP_DigestSignFinal(sign_md, sig, &size);
    if (ret != 1) {
        PRINTERROSSL("Failed to EVP_DigestSignFinal-ize\n");
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(sign_md);
}

static int ui_fork_in_callback(UI *ui, UI_STRING *uis)
{
    const char *pinvalue;
    enum UI_string_types type;
    pid_t pid;
    int status;

    pinvalue = getenv("PINVALUE");
    if (!pinvalue) {
        fprintf(stderr, "PINVALUE not defined\n");
        exit(EXIT_FAILURE);
    }

    /* now fork while in the callback to check if we deadlock */
    pid = fork();
    if (pid == -1) {
        PRINTERR("Fork failed\n");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        PRINTERR("Child Done");
        exit(EXIT_SUCCESS);
    }

    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        PRINTERR("Child failure\n");
        exit(EXIT_FAILURE);
    }

    type = UI_get_string_type(uis);
    switch (type) {
    case UIT_PROMPT:
        fprintf(stderr, "Prompt: \"%s\"\n", UI_get0_output_string(uis));
        fprintf(stderr, "Returning: %s\n", pinvalue);
        UI_set_result(ui, uis, pinvalue);
        return 1;
    default:
        fprintf(stderr, "Unexpected UI type: %d\n", (int)type);
        exit(EXIT_FAILURE);
    }

    return 0;
}

#ifdef __APPLE__
/* No sigtimedwait on MacOS, so let's just fail this test */
static int sigtimedwait(const sigset_t *set, siginfo_t *info,
                        const struct timespec *timeout)
{
    errno = EPERM;
    return -1;
}
#endif

int main(int argc, char *argv[])
{
    const char *keyuri = NULL;
    UI_METHOD *ui_method = NULL;
    OSSL_STORE_CTX *store;
    OSSL_STORE_INFO *info;
    EVP_PKEY *key = NULL;
    sigset_t mask;
    sigset_t orig_mask;
    struct timespec timeout;
    pid_t pid;
    int status;

    keyuri = getenv("PRIURI");
    /* optional first argument is a PKCS#11 uri of the key to test.
     * Default is provided by environment variable BASEURI */
    if (argc > 1) {
        keyuri = argv[1];
    }
    if (!keyuri) {
        fprintf(stderr, "PRIURI not defined\n");
        exit(EXIT_FAILURE);
    }

    ui_method = UI_create_method("Pin Fork Test");
    if (!ui_method) {
        fprintf(stderr, "Failed to set up UI_METHOD\n");
        exit(EXIT_FAILURE);
    }
    (void)UI_method_set_reader(ui_method, ui_fork_in_callback);

    /* prepare timeout handler */
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);

    status = sigprocmask(SIG_BLOCK, &mask, &orig_mask);
    if (status == -1) {
        PRINTERR("Sigprocmask failed\n");
        exit(EXIT_FAILURE);
    }

    /* now fork so we can monitor the "parent" process */
    pid = fork();
    if (pid == -1) {
        PRINTERR("Fork failed\n");
        exit(EXIT_FAILURE);
    }

    /* controller parent */
    if (pid != 0) {
        /* Wait  a max of 5 seconds. Should be enough even on slow
         * containers */
        timeout.tv_sec = 5;
        timeout.tv_nsec = 0;

    retry:
        status = sigtimedwait(&mask, NULL, &timeout);
        if (status == -1) {
            if (errno == EINTR) {
                /* not the right signal */
                goto retry;
            }
            if (errno == EAGAIN) {
                PRINTERR("Timeout, Child likely deadlocked!\n");
                kill(pid, SIGKILL);
                exit(EXIT_FAILURE);
            }
            PRINTERR("Unknown Error: %d", errno);
            kill(pid, SIGKILL);
            exit(EXIT_FAILURE);
        }

        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            PRINTERR("Parent's failure\n");
            exit(EXIT_FAILURE);
        }

        PRINTERR("ALL A-OK!\n");
        UI_destroy_method(ui_method);
        exit(EXIT_SUCCESS);
    }

    /* regular "parent" process (child of controlling parent) */

    store = OSSL_STORE_open_ex(keyuri, NULL, "provider=pkcs11", ui_method, NULL,
                               NULL, NULL, NULL);
    if (store == NULL) {
        fprintf(stderr, "Failed to open pkcs11 store\n");
        exit(EXIT_FAILURE);
    }

    for (info = OSSL_STORE_load(store); info != NULL;
         info = OSSL_STORE_load(store)) {
        int type = OSSL_STORE_INFO_get_type(info);

        switch (type) {
        case OSSL_STORE_INFO_PKEY:
            key = OSSL_STORE_INFO_get1_PKEY(info);
            break;
        default:
            fprintf(stderr, "Invalid data from store\n");
            exit(EXIT_FAILURE);
        }
        OSSL_STORE_INFO_free(info);
    }

    OSSL_STORE_close(store);

    if (!key) {
        fprintf(stderr, "Failed to find key\n");
        exit(EXIT_FAILURE);
    }

    sign_op(key);
    EVP_PKEY_free(key);
    UI_destroy_method(ui_method);
    PRINTERR("Parent Done");
    exit(EXIT_SUCCESS);
}
