/* Copyright (C) 2023 Jakub Jelen <jjelen@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/store.h>
#include <openssl/core_names.h>

static void test_group_name(EVP_PKEY *pkey)
{
    char gname[25] = { 0 };
    int ret;

    ret = EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                         gname, 25, NULL);
    if (ret != 1) {
        fprintf(stderr, "Failed to get the group name\n");
        exit(EXIT_FAILURE);
    }

    if (strcmp(gname, "prime256v1") != 0) {
        fprintf(stderr, "Received unexpected group name. Got %s\n", gname);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    const char *baseuri;
    OSSL_STORE_CTX *store;
    OSSL_STORE_INFO *info;
    EVP_PKEY *prikey = NULL;
    EVP_PKEY *pubkey = NULL;

    baseuri = getenv("ECBASEURI");
    if (baseuri == NULL) {
        fprintf(stderr, "No ECBASEURI\n");
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
    test_group_name(pubkey);
    EVP_PKEY_free(pubkey);

    if (prikey == NULL) {
        fprintf(stderr, "Failed to load private key\n");
        exit(EXIT_FAILURE);
    }
    test_group_name(prikey);
    EVP_PKEY_free(prikey);

    OSSL_STORE_close(store);
}
