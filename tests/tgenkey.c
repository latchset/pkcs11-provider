/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/store.h>
#include <openssl/rand.h>

static void hexify(char *out, unsigned char *byte, size_t len)
{
    char c[2], s;

    for (size_t i = 0; i < len; i++) {
        out[i * 3] = '%';
        c[0] = byte[i] >> 4;
        c[1] = byte[i] & 0x0f;
        for (int j = 0; j < 2; j++) {
            if (c[j] < 0x0A) {
                s = '0';
            } else {
                s = 'a' - 10;
            }
            out[i * 3 + 1 + j] = c[j] + s;
        }
    }
    out[len * 3] = '\0';
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
                fprintf(stderr, "Duplicate public key found!");
                exit(EXIT_FAILURE);
            }
            pubkey = OSSL_STORE_INFO_get1_PUBKEY(info);
            break;
        case OSSL_STORE_INFO_PKEY:
            if (privkey != NULL) {
                fprintf(stderr, "Duplicate private key found!");
                exit(EXIT_FAILURE);
            }
            privkey = OSSL_STORE_INFO_get1_PKEY(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    if (pubkey == NULL) {
        fprintf(stderr, "Failed to load public key\n");
        exit(EXIT_FAILURE);
    }

    if (privkey == NULL) {
        fprintf(stderr, "Failed to load private key\n");
        exit(EXIT_FAILURE);
    }

    /* check we can get pub params from key */
    if (strcmp(key_type, "RSA") == 0) {
        BIGNUM *tmp = NULL;
        int ret;

        ret = EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_RSA_E, &tmp);
        if (ret != 1) {
            fprintf(stderr, "Failed to get E param from public key");
            exit(EXIT_FAILURE);
        } else {
            BN_free(tmp);
            tmp = NULL;
        }
        ret = EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_RSA_N, &tmp);
        if (ret != 1) {
            fprintf(stderr, "Failed to get N param from public key");
            exit(EXIT_FAILURE);
        } else {
            BN_free(tmp);
            tmp = NULL;
        }
    } else if (strcmp(key_type, "EC") == 0) {
        BIGNUM *tmp = NULL;
        int ret;

        ret = EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_EC_PUB_X, &tmp);
        if (ret != 1) {
            fprintf(stderr, "Failed to get X param from public key");
            exit(EXIT_FAILURE);
        } else {
            BN_free(tmp);
            tmp = NULL;
        }
        ret = EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_EC_PUB_Y, &tmp);
        if (ret != 1) {
            fprintf(stderr, "Failed to get Y param from public key");
            exit(EXIT_FAILURE);
        } else {
            BN_free(tmp);
            tmp = NULL;
        }
    }

    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);
}

static void gen_keys(const char *key_type, const char *label, unsigned char *id,
                     const char *idhex, const OSSL_PARAM *params)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key = NULL;
    char *uri;
    OSSL_STORE_CTX *store;
    OSSL_STORE_SEARCH *search;
    int ret;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, key_type, "provider=pkcs11");
    if (ctx == NULL) {
        fprintf(stderr, "Failed to init PKEY context\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_keygen_init(ctx);
    if (ret != 1) {
        fprintf(stderr, "Failed to init keygen\n");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_set_params(ctx, params);

    ret = EVP_PKEY_generate(ctx, &key);
    if (ret != 1) {
        fprintf(stderr, "Failed to generate key\n");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_free(key);
    key = NULL;
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* now try to search by id */
    ret = asprintf(&uri, "pkcs11:id=%s", idhex);
    if (ret == -1) {
        fprintf(stderr, "Failed to allocate uri\n");
        exit(EXIT_FAILURE);
    }

    store = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
    if (store == NULL) {
        fprintf(stderr, "Failed to open pkcs11 store\n");
        exit(EXIT_FAILURE);
    }
    free(uri);

    check_keys(store, key_type);

    OSSL_STORE_close(store);

    /* now make sure we can filter by label */
    store = OSSL_STORE_open("pkcs11:", NULL, NULL, NULL, NULL);
    if (store == NULL) {
        fprintf(stderr, "Failed to open pkcs11 store\n");
        exit(EXIT_FAILURE);
    }

    search = OSSL_STORE_SEARCH_by_alias(label);
    if (search == NULL) {
        fprintf(stderr, "Failed to create store search filter\n");
        exit(EXIT_FAILURE);
    }
    ret = OSSL_STORE_find(store, search);
    if (ret != 1) {
        fprintf(stderr, "Failed to set store search filter\n");
        exit(EXIT_FAILURE);
    }
    OSSL_STORE_SEARCH_free(search);

    check_keys(store, key_type);

    OSSL_STORE_close(store);
}

int main(int argc, char *argv[])
{
    char *label;
    unsigned char id[16];
    char idhex[16 * 3 + 1];
    size_t rsa_bits = 3072;
    OSSL_PARAM params[5];
    int ret;

    /* RSA */
    ret = RAND_bytes(id, 16);
    if (ret != 1) {
        fprintf(stderr, "Failed to set generate key id\n");
        exit(EXIT_FAILURE);
    }
    hexify(idhex, id, 16);
    ret = asprintf(&label, "Test RSA gen [%.9s]", idhex);
    if (ret == -1) {
        fprintf(stderr, "Failed to make label");
        exit(EXIT_FAILURE);
    }
    params[0] = OSSL_PARAM_construct_utf8_string("pkcs11_key_label", label, 0);
    params[1] = OSSL_PARAM_construct_octet_string("pkcs11_key_id", id, 16);
    params[2] = OSSL_PARAM_construct_size_t("rsa_keygen_bits", &rsa_bits);
    params[3] = OSSL_PARAM_construct_end();

    gen_keys("RSA", label, id, idhex, params);
    free(label);

    /* RSA-PSS */
    ret = RAND_bytes(id, 16);
    if (ret != 1) {
        fprintf(stderr, "Failed to set generate key id\n");
        exit(EXIT_FAILURE);
    }
    hexify(idhex, id, 16);
    ret = asprintf(&label, "Test RSA-PSS gen [%.9s]", idhex);
    if (ret == -1) {
        fprintf(stderr, "Failed to make label");
        exit(EXIT_FAILURE);
    }
    params[0] = OSSL_PARAM_construct_utf8_string("pkcs11_key_label", label, 0);
    params[1] = OSSL_PARAM_construct_octet_string("pkcs11_key_id", id, 16);
    params[2] = OSSL_PARAM_construct_size_t("rsa_keygen_bits", &rsa_bits);
    params[3] = OSSL_PARAM_construct_utf8_string("rsa_pss_keygen_md",
                                                 (char *)"SHA256", 0);
    params[4] = OSSL_PARAM_construct_end();

    gen_keys("RSA-PSS", label, id, idhex, params);
    free(label);

    /* EC */
    ret = RAND_bytes(id, 16);
    if (ret != 1) {
        fprintf(stderr, "Failed to set generate key id\n");
        exit(EXIT_FAILURE);
    }
    hexify(idhex, id, 16);
    ret = asprintf(&label, "Test EC gen [%.9s]", idhex);
    if (ret == -1) {
        fprintf(stderr, "Failed to make label");
        exit(EXIT_FAILURE);
    }
    params[0] = OSSL_PARAM_construct_utf8_string("pkcs11_key_label", label, 0);
    params[1] = OSSL_PARAM_construct_octet_string("pkcs11_key_id", id, 16);
    params[2] = OSSL_PARAM_construct_utf8_string("ec_paramgen_curve",
                                                 (char *)"P-256", 0);
    params[3] = OSSL_PARAM_construct_end();

    gen_keys("EC", label, id, idhex, params);
    free(label);

    fprintf(stderr, "ALL A-OK!");
    exit(EXIT_SUCCESS);
}
