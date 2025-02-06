/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/store.h>
#include <openssl/rand.h>
#include "util.h"

static void check_rsa_key(EVP_PKEY *pubkey)
{
    BIGNUM *tmp = NULL;
    int ret;

    ret = EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_RSA_E, &tmp);
    if (ret != 1) {
        PRINTERR("Failed to get E param from public key\n");
        exit(EXIT_FAILURE);
    } else {
        BN_free(tmp);
        tmp = NULL;
    }
    ret = EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_RSA_N, &tmp);
    if (ret != 1) {
        PRINTERR("Failed to get N param from public key\n");
        exit(EXIT_FAILURE);
    } else {
        int bits;
        bits = EVP_PKEY_get_bits(pubkey);
        if (bits < 3072) {
            PRINTERR("Expected 3072 bits key, got %d\n", bits);
            exit(EXIT_FAILURE);
        }
        BN_free(tmp);
        tmp = NULL;
    }
}

static void check_ec_key(EVP_PKEY *pubkey)
{
    BIGNUM *tmp = NULL;
    int ret;

    ret = EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_EC_PUB_X, &tmp);
    if (ret != 1) {
        PRINTERR("Failed to get X param from public key\n");
        exit(EXIT_FAILURE);
    } else {
        BN_free(tmp);
        tmp = NULL;
    }
    ret = EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_EC_PUB_Y, &tmp);
    if (ret != 1) {
        PRINTERR("Failed to get Y param from public key\n");
        exit(EXIT_FAILURE);
    } else {
        BN_free(tmp);
        tmp = NULL;
    }
}

static void check_eddsa_key(EVP_PKEY *pubkey)
{
    unsigned char *tmp = NULL;
    size_t len = 0;
    int ret;

    ret = EVP_PKEY_get_octet_string_param(pubkey, OSSL_PKEY_PARAM_PUB_KEY, NULL,
                                          0, &len);
    if (ret != 1) {
        PRINTERR("Failed to get public key size\n");
        exit(EXIT_FAILURE);
    }
    tmp = malloc(len);
    if (tmp == NULL) {
        PRINTERR("Failed to allocate memory for public key\n");
        exit(EXIT_FAILURE);
    }
    ret = EVP_PKEY_get_octet_string_param(pubkey, OSSL_PKEY_PARAM_PUB_KEY, tmp,
                                          len, NULL);
    if (ret != 1) {
        PRINTERR("Failed to get public key\n");
        exit(EXIT_FAILURE);
    } else {
        free(tmp);
        tmp = NULL;
    }
}

static void check_keys(OSSL_STORE_CTX *store, const char *key_type)
{
    OSSL_STORE_INFO *info;
    EVP_PKEY *pubkey = NULL;
    EVP_PKEY *privkey = NULL;

    for (info = OSSL_STORE_load(store); info != NULL;
         info = OSSL_STORE_load(store)) {
        int type = OSSL_STORE_INFO_get_type(info);

        switch (type) {
        case OSSL_STORE_INFO_PUBKEY:
            if (pubkey != NULL) {
                PRINTERR("Duplicate public key found!\n");
                exit(EXIT_FAILURE);
            }
            pubkey = OSSL_STORE_INFO_get1_PUBKEY(info);
            break;
        case OSSL_STORE_INFO_PKEY:
            if (privkey != NULL) {
                PRINTERR("Duplicate private key found!\n");
                exit(EXIT_FAILURE);
            }
            privkey = OSSL_STORE_INFO_get1_PKEY(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    if (pubkey == NULL) {
        PRINTERR("Failed to load public key\n");
        exit(EXIT_FAILURE);
    }

    if (privkey == NULL) {
        PRINTERR("Failed to load private key\n");
        exit(EXIT_FAILURE);
    }

    /* check we can get pub params from key */
    if (strcmp(key_type, "RSA") == 0 || strcmp(key_type, "RSA-PSS") == 0) {
        check_rsa_key(pubkey);
    } else if (strcmp(key_type, "EC") == 0) {
        check_ec_key(pubkey);
    } else if (strcmp(key_type, "ED25519") == 0
               || strcmp(key_type, "ED448") == 0) {
        check_eddsa_key(pubkey);
    }

    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);
}

static void gen_keys(const char *key_type, const char *label, const char *idhex,
                     const OSSL_PARAM *params, bool fail)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key = NULL;
    char *uri;
    OSSL_STORE_CTX *store;
    OSSL_STORE_SEARCH *search;
    int ret;

    fprintf(stdout, "Generate %s\n", key_type);

    ctx = EVP_PKEY_CTX_new_from_name(NULL, key_type, "provider=pkcs11");
    if (ctx == NULL) {
        PRINTERR("Failed to init PKEY context\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_keygen_init(ctx);
    if (ret != 1) {
        PRINTERR("Failed to init keygen\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_CTX_set_params(ctx, params);
    if (ret != 1) {
        PRINTERR("Failed to set params\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_generate(ctx, &key);
    if (ret != 1) {
        if (!fail) {
            PRINTERR("Failed to generate key\n");
            exit(EXIT_FAILURE);
        }
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    if (fail) {
        PRINTERR("Key generation unexpectedly succeeded\n");
        exit(EXIT_FAILURE);
    }

    if (strcmp(key_type, "RSA") == 0 || strcmp(key_type, "RSA-PSS") == 0) {
        check_rsa_key(key);
    } else if (strcmp(key_type, "EC") == 0) {
        check_ec_key(key);
    } else if (strcmp(key_type, "ED25519") == 0
               || strcmp(key_type, "ED448") == 0) {
        check_eddsa_key(key);
    }

    EVP_PKEY_free(key);
    key = NULL;
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* now try to search by id */
    fprintf(stdout, "Search by ID\n");

    ret = asprintf(&uri, "pkcs11:id=%s", idhex);
    if (ret == -1) {
        PRINTERR("Failed to allocate uri\n");
        exit(EXIT_FAILURE);
    }

    store = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
    if (store == NULL) {
        PRINTERR("Failed to open pkcs11 store\n");
        exit(EXIT_FAILURE);
    }
    free(uri);

    check_keys(store, key_type);

    OSSL_STORE_close(store);

    /* now make sure we can filter by label */
    fprintf(stdout, "Search by Label\n");

    store = OSSL_STORE_open("pkcs11:", NULL, NULL, NULL, NULL);
    if (store == NULL) {
        PRINTERR("Failed to open pkcs11 store\n");
        exit(EXIT_FAILURE);
    }

    search = OSSL_STORE_SEARCH_by_alias(label);
    if (search == NULL) {
        PRINTERR("Failed to create store search filter\n");
        exit(EXIT_FAILURE);
    }
    ret = OSSL_STORE_find(store, search);
    if (ret != 1) {
        PRINTERR("Failed to set store search filter\n");
        exit(EXIT_FAILURE);
    }
    OSSL_STORE_SEARCH_free(search);

    check_keys(store, key_type);

    OSSL_STORE_close(store);
}

static void sign_test(const char *label, const char *mdname,
                      const OSSL_PARAM *params, bool fail)
{
    OSSL_STORE_CTX *store;
    OSSL_STORE_SEARCH *search;
    OSSL_STORE_INFO *info;
    EVP_PKEY *privkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    const unsigned char data[] = "Plaintext Data";
    unsigned char sigret[4096];
    size_t siglen = 4096;
    int ret;

    fprintf(stdout, "Test signature\n");

    store = OSSL_STORE_open("pkcs11:", NULL, NULL, NULL, NULL);
    if (store == NULL) {
        PRINTERR("Failed to open pkcs11 store\n");
        exit(EXIT_FAILURE);
    }

    search = OSSL_STORE_SEARCH_by_alias(label);
    if (search == NULL) {
        PRINTERR("Failed to create store search filter\n");
        exit(EXIT_FAILURE);
    }
    ret = OSSL_STORE_find(store, search);
    if (ret != 1) {
        PRINTERR("Failed to set store search filter\n");
        exit(EXIT_FAILURE);
    }
    OSSL_STORE_SEARCH_free(search);

    for (info = OSSL_STORE_load(store); info != NULL;
         info = OSSL_STORE_load(store)) {
        int type = OSSL_STORE_INFO_get_type(info);

        if (type == OSSL_STORE_INFO_PKEY) {
            privkey = OSSL_STORE_INFO_get1_PKEY(info);
            OSSL_STORE_INFO_free(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    OSSL_STORE_close(store);

    if (privkey == NULL) {
        PRINTERR("Failed to load private key\n");
        exit(EXIT_FAILURE);
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        PRINTERR("Failed to init MD_CTX\n");
        exit(EXIT_FAILURE);
    }

    ret =
        EVP_DigestSignInit_ex(ctx, &pctx, mdname, NULL, NULL, privkey, params);
    if (ret == 0) {
        PRINTERR("Failed to init Sig Ctx\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_DigestSign(ctx, sigret, &siglen, data, sizeof(data));
    if (ret == 0) {
        if (!fail) {
            PRINTERR("Failed to generate signature\n");
            exit(EXIT_FAILURE);
        }
    } else {
        if (fail) {
            PRINTERR("Expected failure, but signature worked\n");
            exit(EXIT_FAILURE);
        }
    }

    EVP_PKEY_free(privkey);
    EVP_MD_CTX_free(ctx);
}

static char *tokenize(char **result, int max, char *str)
{
    char *copy;
    char *ptr;
    char *saveptr;
    int num = 0;

    copy = strdup(str);
    if (!copy) {
        PRINTERR("strdup failed\n");
        exit(EXIT_FAILURE);
    }

    ptr = copy;
    saveptr = NULL;

    while (num < max) {
        char *tok = strtok_r(ptr, ",", &saveptr);
        ptr = NULL;
        if (tok == NULL) {
            break;
        }
        result[num] = strdup(tok);
        if (!result[num]) {
            PRINTERR("strdup failed\n");
            exit(EXIT_FAILURE);
        }
        num++;
    }

    result[num] = NULL;
    return copy;
}

static void freetokens(char **tokens)
{
    for (int num = 0; tokens[num] != NULL; num++) {
        free(tokens[num]);
        tokens[num] = NULL;
    }
}

int main(int argc, char *argv[])
{
    char *tests[11] = { 0 };
    char *label;
    unsigned char id[16];
    char idhex[16 * 3 + 1];
    char *uri;
    size_t rsa_bits = 3072;
    const char *key_usage = "dataEncipherment keyEncipherment";
    const char *bad_usage = "dataEncipherment gibberish ";
    char *copy = NULL;
    OSSL_PARAM params[4];
    int miniid;
    int num;
    int ret;

    if (argc > 1) {
        copy = tokenize(tests, 10, argv[1]);
    }

    for (num = 0; num < 10 && tests[num] != NULL; num++) {
        if (strcmp(tests[num], "RSA") == 0) {
            ret = RAND_bytes(id, 16);
            if (ret != 1) {
                PRINTERR("Failed to generate key id\n");
                exit(EXIT_FAILURE);
            }
            miniid = (id[0] << 24) + (id[1] << 16) + (id[2] << 8) + id[3];
            ret = asprintf(&label, "Test-RSA-gen-%08x", miniid);
            if (ret == -1) {
                PRINTERR("Failed to make label\n");
                exit(EXIT_FAILURE);
            }
            hexify(idhex, id, 16);
            ret = asprintf(&uri, "pkcs11:object=%s;id=%s", label, idhex);
            if (ret == -1) {
                PRINTERR("Failed to compose PKCS#11 URI\n");
                exit(EXIT_FAILURE);
            }
            params[0] = OSSL_PARAM_construct_utf8_string("pkcs11_uri", uri, 0);
            params[1] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_BITS,
                                                    &rsa_bits);
            params[2] = OSSL_PARAM_construct_end();

            gen_keys("RSA", label, idhex, params, false);

            sign_test(label, "SHA256", NULL, false);

            free(label);
            free(uri);

        } else if (strcmp(tests[num], "RSA-PSS") == 0) {
            ret = RAND_bytes(id, 16);
            if (ret != 1) {
                PRINTERR("Failed to generate key id\n");
                exit(EXIT_FAILURE);
            }
            miniid = (id[0] << 24) + (id[1] << 16) + (id[2] << 8) + id[3];
            ret = asprintf(&label, "Test-RSA-PSS-gen-%08x", miniid);
            if (ret == -1) {
                PRINTERR("Failed to make label\n");
                exit(EXIT_FAILURE);
            }
            hexify(idhex, id, 16);
            ret = asprintf(&uri, "pkcs11:object=%s;id=%s", label, idhex);
            if (ret == -1) {
                PRINTERR("Failed to compose PKCS#11 URI\n");
                exit(EXIT_FAILURE);
            }
            params[0] = OSSL_PARAM_construct_utf8_string("pkcs11_uri", uri, 0);
            params[1] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_BITS,
                                                    &rsa_bits);
            params[2] = OSSL_PARAM_construct_utf8_string("rsa_pss_keygen_md",
                                                         (char *)"SHA256", 0);
            params[3] = OSSL_PARAM_construct_end();

            gen_keys("RSA-PSS", label, idhex, params, false);
            free(label);
            free(uri);

        } else if (strcmp(tests[num], "EC") == 0) {
            ret = RAND_bytes(id, 16);
            if (ret != 1) {
                PRINTERR("Failed to generate key id\n");
                exit(EXIT_FAILURE);
            }
            miniid = (id[0] << 24) + (id[1] << 16) + (id[2] << 8) + id[3];
            ret = asprintf(&label, "Test-EC-gen-%08x", miniid);
            if (ret == -1) {
                PRINTERR("Failed to make label\n");
                exit(EXIT_FAILURE);
            }
            hexify(idhex, id, 16);
            ret = asprintf(&uri, "pkcs11:object=%s;id=%s", label, idhex);
            if (ret == -1) {
                PRINTERR("Failed to compose PKCS#11 URI\n");
                exit(EXIT_FAILURE);
            }
            params[0] = OSSL_PARAM_construct_utf8_string("pkcs11_uri", uri, 0);
            params[1] = OSSL_PARAM_construct_utf8_string("ec_paramgen_curve",
                                                         (char *)"P-256", 0);
            params[2] = OSSL_PARAM_construct_end();

            gen_keys("EC", label, idhex, params, false);

            sign_test(label, "SHA256", NULL, false);

            free(label);
            free(uri);

        } else if (strcmp(tests[num], "RSAKeyUsage") == 0) {
            ret = RAND_bytes(id, 16);
            if (ret != 1) {
                PRINTERR("Failed to generate key id\n");
                exit(EXIT_FAILURE);
            }
            miniid = (id[0] << 24) + (id[1] << 16) + (id[2] << 8) + id[3];
            ret = asprintf(&label, "Test-RSA-Key-Usage-%08x", miniid);
            if (ret == -1) {
                PRINTERR("Failed to make label\n");
                exit(EXIT_FAILURE);
            }
            hexify(idhex, id, 16);
            ret = asprintf(&uri, "pkcs11:object=%s;id=%s", label, idhex);
            if (ret == -1) {
                PRINTERR("Failed to compose PKCS#11 URI\n");
                exit(EXIT_FAILURE);
            }
            params[0] = OSSL_PARAM_construct_utf8_string("pkcs11_uri", uri, 0);
            params[1] = OSSL_PARAM_construct_utf8_string("pkcs11_key_usage",
                                                         (char *)key_usage, 0);
            params[2] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_BITS,
                                                    &rsa_bits);
            params[3] = OSSL_PARAM_construct_end();

            gen_keys("RSA", label, idhex, params, false);

            sign_test(label, "SHA256", NULL, true);

            params[1] = OSSL_PARAM_construct_utf8_string("pkcs11_key_usage",
                                                         (char *)bad_usage, 0);

            gen_keys("RSA", label, idhex, params, true);

            free(label);
            free(uri);
        } else if (strcmp(tests[num], "ED25519") == 0
                   || strcmp(tests[num], "ED448") == 0) {
            const char *context = "context string";
            const char *instance = "Ed25519ph";

            if (strcmp(tests[num], "ED448") == 0) {
                instance = "Ed448ph";
            }

            ret = RAND_bytes(id, 16);
            if (ret != 1) {
                PRINTERR("Failed to generate key id\n");
                exit(EXIT_FAILURE);
            }
            miniid = (id[0] << 24) + (id[1] << 16) + (id[2] << 8) + id[3];
            ret = asprintf(&label, "Test-Ed-gen-%08x", miniid);
            if (ret == -1) {
                PRINTERR("Failed to make label\n");
                exit(EXIT_FAILURE);
            }
            hexify(idhex, id, 16);
            ret = asprintf(&uri, "pkcs11:object=%s;id=%s", label, idhex);
            if (ret == -1) {
                PRINTERR("Failed to compose PKCS#11 URI\n");
                exit(EXIT_FAILURE);
            }
            params[0] = OSSL_PARAM_construct_utf8_string("pkcs11_uri", uri, 0);
            params[1] = OSSL_PARAM_construct_end();

            gen_keys(tests[num], label, idhex, params, false);

            sign_test(label, NULL, NULL, false);

/* these are not defined in OpenSSL 3.0 so just skip the test */
#ifdef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
            /* Test again with context string */
            params[0] = OSSL_PARAM_construct_octet_string(
                OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void *)context,
                sizeof(context));
            params[1] = OSSL_PARAM_construct_end();
            sign_test(label, NULL, params, false);

            /* Test again with prehash */
            params[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_SIGNATURE_PARAM_INSTANCE, (char *)instance,
                strlen(instance));
            params[1] = OSSL_PARAM_construct_end();
            sign_test(label, NULL, params, false);
#else
            (void)instance;
            (void)context;
#endif

            free(label);
            free(uri);
        } else {
            PRINTERR("Unknown test type [%s]\n", tests[num]);
            exit(EXIT_FAILURE);
        }
    }

    freetokens(tests);
    free(copy);
    PRINTERR("Performed tests: %d\n", num);
    exit(EXIT_SUCCESS);
}
