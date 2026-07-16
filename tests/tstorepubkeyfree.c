/* Copyright (C) 2026 Jakub Zelenka <jakub.openssl@gmail.com>
   SPDX-License-Identifier: Apache-2.0 */

/* Regression test for imported public keys leaking token session objects.
 *
 * When an imported public key is used in a token operation, the provider
 * stores it on the token as a session object (C_CreateObject).  That object
 * must be destroyed again when the last key using it is freed, otherwise
 * every unique imported public key leaks one object on the long lived login
 * session.
 *
 * The test counts the public key objects matching a token URI, imports a
 * public key twice and uses it to force the provider to store it on the
 * token (count goes up by one and the copy shares the stored object), then
 * frees the keys and verifies the stored object is gone (count drops back). */

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/store.h>
#include <stdio.h>
#include "util.h"

static unsigned char tbs[32] = { 0 };
static unsigned char sig[1024];
static size_t siglen;

/* Count the number of objects matching the URI. */
static int count_matches(const char *uri)
{
    OSSL_STORE_CTX *store;
    OSSL_STORE_INFO *info;
    int count = 0;

    store = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
    if (store == NULL) {
        fprintf(stderr, "Failed to open store: %s\n", uri);
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    for (info = OSSL_STORE_load(store); info != NULL;
         info = OSSL_STORE_load(store)) {
        count++;
        OSSL_STORE_INFO_free(info);
    }

    OSSL_STORE_close(store);
    return count;
}

static void check_count(const char *uri, int expected, const char *when)
{
    int count = count_matches(uri);

    if (count != expected) {
        fprintf(stderr, "Expected %d matches %s, got %d for %s\n", expected,
                when, count, uri);
        exit(EXIT_FAILURE);
    }
}

static void sign_data(const char *uri)
{
    EVP_PKEY *key;
    EVP_PKEY_CTX *ctx;

    key = load_key_ex(uri, "provider=pkcs11");
    if (!key) {
        exit(EXIT_FAILURE);
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=pkcs11");
    if (ctx == NULL) {
        PRINTERROSSL("Failed to create signature context\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_sign_init(ctx) != 1) {
        PRINTERROSSL("Failed to init signature\n");
        exit(EXIT_FAILURE);
    }
    siglen = sizeof(sig);
    if (EVP_PKEY_sign(ctx, sig, &siglen, tbs, sizeof(tbs)) != 1) {
        PRINTERROSSL("Failed to sign\n");
        exit(EXIT_FAILURE);
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
}

/* The verification forces the imported key to be stored on the token. */
static void verify_data(EVP_PKEY *key)
{
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=pkcs11");
    if (ctx == NULL) {
        PRINTERROSSL("Failed to create verification context\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_verify_init(ctx) != 1) {
        PRINTERROSSL("Failed to init verification\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_verify(ctx, sig, siglen, tbs, sizeof(tbs)) != 1) {
        PRINTERROSSL("Failed to verify\n");
        exit(EXIT_FAILURE);
    }
    EVP_PKEY_CTX_free(ctx);
}

static EVP_PKEY *import_pubkey(const char *type_name, OSSL_PARAM *params)
{
    EVP_PKEY_CTX *pctx;
    EVP_PKEY *pubkey = NULL;
    int ret;

    pctx = EVP_PKEY_CTX_new_from_name(NULL, type_name, "provider=pkcs11");
    if (!pctx) {
        PRINTERROSSL("Failed to create fromdata ctx\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_fromdata_init(pctx);
    if (ret != 1) {
        PRINTERROSSL("Failed to init fromdata\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_fromdata(pctx, &pubkey, EVP_PKEY_PUBLIC_KEY, params);
    if (ret != 1) {
        PRINTERROSSL("Failed to import key via fromdata\n");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(pctx);
    return pubkey;
}

int main(int argc, char *argv[])
{
    EVP_PKEY *pubkey_main, *pubkey1, *pubkey2;
    OSSL_PARAM *params = NULL;
    char *type_name;
    int before;
    int ret;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s <privkey> <pubkey> <matchuri>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *privkey_uri = argv[1];
    const char *pubkey_uri = argv[2];
    const char *match_uri = argv[3];

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    sign_data(privkey_uri);

    pubkey_main = load_key_ex(pubkey_uri, "provider=pkcs11");
    if (!pubkey_main) {
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_todata(pubkey_main, EVP_PKEY_PUBLIC_KEY, &params);
    if (ret != 1) {
        PRINTERROSSL("Failed to export key params\n");
        exit(EXIT_FAILURE);
    }

    type_name = OPENSSL_strdup(EVP_PKEY_get0_type_name(pubkey_main));
    if (!type_name) {
        fprintf(stderr, "Failed to copy key type name\n");
        exit(EXIT_FAILURE);
    }
    /* free the token key so the import below cannot just reuse it */
    EVP_PKEY_free(pubkey_main);

    before = count_matches(match_uri);

    pubkey1 = import_pubkey(type_name, params);
    verify_data(pubkey1);
    check_count(match_uri, before + 1, "after the first imported key is used");

    /* the second import shares the object stored by the first one */
    pubkey2 = import_pubkey(type_name, params);
    verify_data(pubkey2);
    check_count(match_uri, before + 1, "after the second imported key is used");

    /* the stored object is kept until all keys using it are freed */
    EVP_PKEY_free(pubkey1);
    verify_data(pubkey2);
    check_count(match_uri, before + 1, "after the first imported key is freed");

    EVP_PKEY_free(pubkey2);
    check_count(match_uri, before, "after all imported keys are freed");

    OSSL_PARAM_free(params);
    OPENSSL_free(type_name);

    fprintf(stderr, "ALL A-OK\n");

    exit(EXIT_SUCCESS);
}
