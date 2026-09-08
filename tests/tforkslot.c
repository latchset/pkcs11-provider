/* Copyright (C) 2026 Jakub Zelenka <jakub.openssl@gmail.com>
   SPDX-License-Identifier: Apache-2.0 */

/* Public key operations on a key stored in a non-default slot must never
 * try to log in with the configured (default slot) PIN nor prompt for a
 * PIN.  This happened from the session key cache after a fork, when the
 * login session was reset and the key copy had to be re-created. */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ui.h>
#include "util.h"

static const unsigned char data[] = "Sign Me!";
static int prompts = 0;

static int ui_reader(UI *ui, UI_STRING *uis)
{
    prompts++;
    PRINTERR("Unexpected PIN prompt: \"%s\"\n", UI_get0_output_string(uis));
    return 0;
}

static void check(int ok, const char *stage)
{
    if (!ok) {
        PRINTERROSSL("%s failed\n", stage);
        exit(EXIT_FAILURE);
    }
    if (ERR_peek_error() != 0) {
        PRINTERROSSL("Errors left on the stack after %s\n", stage);
        exit(EXIT_FAILURE);
    }
    if (prompts != 0) {
        PRINTERR("PIN prompt attempted during %s\n", stage);
        exit(EXIT_FAILURE);
    }
    PRINTERR("%s ok\n", stage);
}

static void sign_op(EVP_PKEY *key, unsigned char *sig, size_t *siglen,
                    const char *stage)
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    int ret = 0;

    if (md) {
        ret = EVP_DigestSignInit_ex(md, NULL, "SHA256", NULL, NULL, key, NULL)
                  == 1
              && EVP_DigestSign(md, sig, siglen, data, sizeof(data)) == 1;
    }
    EVP_MD_CTX_free(md);
    check(ret, stage);
}

static void verify_op(EVP_PKEY *key, const unsigned char *sig, size_t siglen,
                      const char *stage)
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    int ret = 0;

    if (md) {
        ret = EVP_DigestVerifyInit_ex(md, NULL, "SHA256", NULL, NULL, key, NULL)
                  == 1
              && EVP_DigestVerify(md, sig, siglen, data, sizeof(data)) == 1;
    }
    EVP_MD_CTX_free(md);
    check(ret, stage);
}

static void encrypt_op(EVP_PKEY *key, const char *stage)
{
    EVP_PKEY_CTX *ctx =
        EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=pkcs11");
    unsigned char out[1024];
    size_t outlen = sizeof(out);
    int ret = 0;

    if (ctx) {
        ret = EVP_PKEY_encrypt_init(ctx) == 1
              && EVP_PKEY_encrypt(ctx, out, &outlen, data, sizeof(data)) == 1;
    }
    EVP_PKEY_CTX_free(ctx);
    check(ret, stage);
}

int main(int argc, char *argv[])
{
    const char *priuri = getenv("PRIURI2WITHPINVALUE");
    const char *puburi = getenv("PUBURI2");
    UI_METHOD *ui_method;
    EVP_PKEY *priv, *pub;
    unsigned char sig[1024];
    size_t siglen = sizeof(sig);
    pid_t pid;
    int status;

    if (!priuri || !puburi) {
        PRINTERR("PRIURI2WITHPINVALUE or PUBURI2 not defined\n");
        exit(EXIT_FAILURE);
    }

    priv = load_key(priuri);
    pub = load_key_ex(puburi, "provider=pkcs11");

    /* the match looks up the public key associated with the private key
     * and adds it to the object pool without any PIN */
    check(EVP_PKEY_eq(pub, priv) == 1, "match");
    sign_op(priv, sig, &siglen, "sign");

    /* any PIN prompt from now on is an error */
    ui_method = UI_create_method("tforkslot");
    if (!ui_method) {
        PRINTERR("Failed to set up UI_METHOD\n");
        exit(EXIT_FAILURE);
    }
    (void)UI_method_set_reader(ui_method, ui_reader);
    (void)UI_set_default_method(ui_method);

    pid = fork();
    if (pid == -1) {
        PRINTERR("Fork failed\n");
        exit(EXIT_FAILURE);
    }
    if (pid == 0) {
        /* the sessions are reset after fork, so the public key operations
         * find no logged in session; run each twice as a login failure is
         * only reported on the following attempt */
        verify_op(priv, sig, siglen, "child verify with private key 1");
        verify_op(priv, sig, siglen, "child verify with private key 2");
        verify_op(pub, sig, siglen, "child verify with public key 1");
        verify_op(pub, sig, siglen, "child verify with public key 2");
        encrypt_op(pub, "child encrypt with public key");
        /* the URI PIN must still be usable for the private key */
        sign_op(priv, sig, &siglen, "child sign");
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        PRINTERR("Child Done\n");
        exit(EXIT_SUCCESS);
    }

    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);

    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        PRINTERR("Child failure\n");
        exit(EXIT_FAILURE);
    }

    UI_set_default_method(NULL);
    UI_destroy_method(ui_method);
    exit(EXIT_SUCCESS);
}
