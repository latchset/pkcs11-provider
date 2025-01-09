/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/store.h>

/* concurrent operations */
#define CNUM 16

int main(int argc, char *argv[])
{
    const char *baseuri;
    OSSL_STORE_CTX *store;
    OSSL_STORE_INFO *info;
    EVP_PKEY *prikey = NULL;
    EVP_PKEY *pubkey = NULL;
    EVP_MD_CTX *sign_md[CNUM] = {};
    const char *mdname = "SHA256";
    int ret;

    baseuri = getenv("BASEURI");
    /* optional first argument is a PKCS#11 uri of the key to test.
     * Default is provided by environment variable BASEURI */
    if (argc > 1) {
        baseuri = argv[1];
    }
    if (baseuri == NULL) {
        fprintf(stderr, "No BASEURI\n");
        exit(EXIT_FAILURE);
    }

    store = OSSL_STORE_open(baseuri, NULL, NULL, NULL, NULL);
    if (store == NULL) {
        fprintf(stderr, "Failed to open pkcs11 store\n");
        exit(EXIT_FAILURE);
    }

    for (info = OSSL_STORE_load(store); info != NULL;
         info = OSSL_STORE_load(store)) {
        int type = OSSL_STORE_INFO_get_type(info);

        switch (type) {
        case OSSL_STORE_INFO_PUBKEY:
            pubkey = OSSL_STORE_INFO_get1_PUBKEY(info);
            break;
        case OSSL_STORE_INFO_PKEY:
            prikey = OSSL_STORE_INFO_get1_PKEY(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    if (pubkey == NULL) {
        fprintf(stderr, "Failed to load public key\n");
        exit(EXIT_FAILURE);
    }

    if (prikey == NULL) {
        fprintf(stderr, "Failed to load private key\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_get_id(prikey) == EVP_PKEY_ED25519
        || EVP_PKEY_get_id(prikey) == EVP_PKEY_ED448) {
        mdname = NULL;
    }

    /* Do this twice to check that freeing and taling again sessions
     * works correctly and caching of open sessions work as expected */
    for (int r = 0; r < 2; r++) {
        const unsigned char *data = (unsigned char *)"Sign Me!";
        /* Start a series of signing operation so code grabs sessions */
        for (int c = 0; c < CNUM; c++) {
            sign_md[c] = EVP_MD_CTX_new();
            if (sign_md[c] == NULL) {
                fprintf(stderr, "Failed to init EVP_MD_CTX\n");
                exit(EXIT_FAILURE);
            }

            ret = EVP_DigestSignInit_ex(sign_md[c], NULL, mdname, NULL, NULL,
                                        prikey, NULL);
            if (ret != 1) {
                fprintf(stderr, "Failed to init EVP_DigestSign\n");
                exit(EXIT_FAILURE);
            }

            /* do not finalize just yet, leave this open to hold on sessions */
        }

        for (int c = 0; c < CNUM; c++) {
            size_t size = EVP_PKEY_get_size(prikey);
            unsigned char sig[size];
            ret = EVP_DigestSign(sign_md[c], sig, &size, data, sizeof(data));
            if (ret != 1) {
                fprintf(stderr, "Failed to EVP_DigestSignFinal-ize\n");
                exit(EXIT_FAILURE);
            }
            EVP_MD_CTX_free(sign_md[c]);
        }
    }

    OSSL_STORE_close(store);
    EVP_PKEY_free(prikey);
    EVP_PKEY_free(pubkey);

    fprintf(stderr, "ALL A-OK!");

    exit(EXIT_SUCCESS);
}
