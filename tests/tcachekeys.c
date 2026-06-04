/* Copyright (C) 2026 Michal Nowak <mnowak@isc.org>
   SPDX-License-Identifier: Apache-2.0 */

/* Regression test for the session key cache leaking into URI lookups.
 *
 * When a token key is used in an operation, the provider copies it into a
 * session object to speed up subsequent operations (key caching).  The copy
 * must not inherit the original CKA_ID/CKA_LABEL, otherwise an object search
 * that matches on id or label (e.g. loading a key by a pkcs11: URI) returns
 * the copy alongside the real key -- two matches where exactly one is
 * expected.
 *
 * The test creates a key with a unique, well-defined label and id on the
 * token, counts how many objects match its URI, then uses the key (forcing
 * it to be cached) and counts again.  The count must stay at one. */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/store.h>
#include <openssl/evp.h>
#include "util.h"

/* Count the number of private key objects matching the URI. */
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

    if (OSSL_STORE_expect(store, OSSL_STORE_INFO_PKEY) != 1) {
        fprintf(stderr, "Failed to expect private key\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    for (info = OSSL_STORE_load(store); info != NULL;
         info = OSSL_STORE_load(store)) {
        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
            count++;
        }
        OSSL_STORE_INFO_free(info);
    }

    OSSL_STORE_close(store);
    return count;
}

/* Use the key in a signature operation; this is what triggers the provider to
 * cache the token key into a session object. */
static void use_key(EVP_PKEY *key)
{
    EVP_PKEY_CTX *ctx;
    unsigned char tbs[32] = { 0 };
    unsigned char sig[1024];
    size_t siglen = sizeof(sig);

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (ctx == NULL) {
        PRINTERROSSL("Failed to create signature context\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_sign_init(ctx) != 1) {
        PRINTERROSSL("Failed to init signature\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_sign(ctx, sig, &siglen, tbs, sizeof(tbs)) != 1) {
        PRINTERROSSL("Failed to sign\n");
        exit(EXIT_FAILURE);
    }
    EVP_PKEY_CTX_free(ctx);
}

int main(void)
{
    EVP_PKEY *key;
    char label[64];
    char *uri = NULL;
    int before, after;
    int ret;

    /* A unique label keeps the lookup scoped to the key we just generated,
     * regardless of what else is already on the token. */
    ret = snprintf(label, sizeof(label), "cachekeyleak-%d", (int)getpid());
    if (ret < 0 || ret >= (int)sizeof(label)) {
        fprintf(stderr, "Failed to build label\n");
        exit(EXIT_FAILURE);
    }

    key = util_gen_key("RSA 2048", label);

    ret = asprintf(&uri, "pkcs11:object=%s;type=private", label);
    if (ret == -1) {
        fprintf(stderr, "Failed to allocate uri\n");
        exit(EXIT_FAILURE);
    }

    /* Before the key is used it cannot have been cached yet. */
    before = count_matches(uri);
    if (before != 1) {
        fprintf(stderr,
                "Expected exactly one match before caching, got %d for %s\n",
                before, uri);
        exit(EXIT_FAILURE);
    }

    /* Using the key causes the provider to cache it as a session object. */
    use_key(key);

    /* The cached copy must not be returned by the URI lookup. */
    after = count_matches(uri);
    if (after != 1) {
        fprintf(stderr,
                "Expected exactly one match after caching, got %d for %s\n"
                "(the session key cache leaked into the URI lookup)\n",
                after, uri);
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "ALL A-OK\n");

    free(uri);
    EVP_PKEY_free(key);
    return EXIT_SUCCESS;
}
