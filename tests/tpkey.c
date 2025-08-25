/* Copyright (C) 2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/store.h>
#include <sys/wait.h>
#include "util.h"

static void sign_op(EVP_PKEY *key, bool oneshot, const char *digest,
                    const unsigned char *data, size_t len,
                    unsigned char **signature, size_t *siglen)
{
    size_t size = EVP_PKEY_get_size(key);
    unsigned char *sig;
    EVP_MD_CTX *sign_md;
    int ret;

    sig = OPENSSL_zalloc(size);
    if (!sig) {
        PRINTERROSSL("Failed to allocate signature buffer\n");
        exit(EXIT_FAILURE);
    }

    *signature = sig;
    *siglen = size;

    sign_md = EVP_MD_CTX_new();
    ret = EVP_DigestSignInit_ex(sign_md, NULL, digest, NULL, NULL, key, NULL);
    if (ret != 1) {
        PRINTERROSSL("Failed to init EVP_DigestSign\n");
        exit(EXIT_FAILURE);
    }

    if (oneshot) {
        ret = EVP_DigestSign(sign_md, sig, siglen, data, len);
        if (ret != 1) {
            PRINTERROSSL("Failed to EVP_DigestSign\n");
            exit(EXIT_FAILURE);
        }
    } else {
        ret = EVP_DigestSignUpdate(sign_md, data, len);
        if (ret != 1) {
            PRINTERROSSL("Failed to EVP_DigestSignUpdate\n");
            exit(EXIT_FAILURE);
        }
        ret = EVP_DigestSignFinal(sign_md, sig, siglen);
        if (ret != 1) {
            PRINTERROSSL("Failed to EVP_DigestSignFinal-ize\n");
            exit(EXIT_FAILURE);
        }
    }

    EVP_MD_CTX_free(sign_md);
}

static void verify_op(EVP_PKEY *key, bool oneshot, const char *digest,
                      const unsigned char *data, size_t len,
                      unsigned char *signature, size_t siglen)
{
    EVP_MD_CTX *ver_md;
    int ret;

    ver_md = EVP_MD_CTX_new();
    ret = EVP_DigestVerifyInit_ex(ver_md, NULL, digest, NULL, NULL, key, NULL);
    if (ret != 1) {
        PRINTERROSSL("Failed to init EVP_DigestVerify\n");
        exit(EXIT_FAILURE);
    }

    if (oneshot) {
        ret = EVP_DigestVerify(ver_md, signature, siglen, data, len);
        if (ret != 1) {
            PRINTERROSSL("Failed to EVP_DigestVerify\n");
            exit(EXIT_FAILURE);
        }
    } else {
        ret = EVP_DigestVerifyUpdate(ver_md, data, len);
        if (ret != 1) {
            PRINTERROSSL("Failed to EVP_DigestVerifyUpdate\n");
            exit(EXIT_FAILURE);
        }
        ret = EVP_DigestVerifyFinal(ver_md, signature, siglen);
        if (ret != 1) {
            PRINTERROSSL("Failed to EVP_DigestVerifyFinal-ize/bad signature\n");
            exit(EXIT_FAILURE);
        }
    }

    EVP_MD_CTX_free(ver_md);
}

#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
static void sign_msg_op(EVP_PKEY *key, bool oneshot, const char *sigalgname,
                        const unsigned char *data, size_t len,
                        unsigned char **signature, size_t *siglen)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_SIGNATURE *sigalg = NULL;
    size_t size;
    unsigned char *sig;
    int ret;

    size = EVP_PKEY_get_size(key);
    sig = OPENSSL_zalloc(size);
    if (!sig) {
        PRINTERROSSL("Failed to allocate signature buffer\n");
        exit(EXIT_FAILURE);
    }

    *signature = sig;
    *siglen = size;

    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (!pctx) {
        PRINTERROSSL("Failed to create pkey ctx\n");
        exit(EXIT_FAILURE);
    }

    sigalg = EVP_SIGNATURE_fetch(NULL, sigalgname, "provider=pkcs11");
    if (!sigalg) {
        PRINTERROSSL("Failed to fetch %s signature\n", sigalgname);
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_sign_message_init(pctx, sigalg, NULL);
    if (ret != 1) {
        PRINTERROSSL("Failed to init EVP_PKEY_sign_message\n");
        exit(EXIT_FAILURE);
    }

    if (oneshot) {
        ret = EVP_PKEY_sign(pctx, sig, siglen, data, len);
        if (ret != 1) {
            PRINTERROSSL("Failed to EVP_PKEY_sign\n");
            exit(EXIT_FAILURE);
        }
    } else {
        ret = EVP_PKEY_sign_message_update(pctx, data, len);
        if (ret != 1) {
            PRINTERROSSL("Failed to EVP_PKEY_sign_message_update\n");
            exit(EXIT_FAILURE);
        }
        ret = EVP_PKEY_sign_message_final(pctx, sig, siglen);
        if (ret != 1) {
            PRINTERROSSL("Failed to EVP_PKEY_sign_message_final-ize\n");
            exit(EXIT_FAILURE);
        }
    }

    EVP_SIGNATURE_free(sigalg);
    EVP_PKEY_CTX_free(pctx);
}

static void verify_msg_op(EVP_PKEY *key, bool oneshot, const char *sigalgname,
                          const unsigned char *data, size_t len,
                          unsigned char *signature, size_t siglen)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_SIGNATURE *sigalg = NULL;
    int ret;

    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (!pctx) {
        PRINTERROSSL("Failed to create pkey ctx\n");
        exit(EXIT_FAILURE);
    }

    sigalg = EVP_SIGNATURE_fetch(NULL, sigalgname, "provider=pkcs11");
    if (!sigalg) {
        PRINTERROSSL("Failed to fetch %s signature\n", sigalgname);
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_verify_message_init(pctx, sigalg, NULL);
    if (ret != 1) {
        PRINTERROSSL("Failed to init EVP_PKEY_verify_message\n");
        exit(EXIT_FAILURE);
    }

    if (oneshot) {
        ret = EVP_PKEY_verify(pctx, signature, siglen, data, len);
        if (ret != 1) {
            PRINTERROSSL("Failed to EVP_PKEY_verify\n");
            exit(EXIT_FAILURE);
        }
    } else {
        ret = EVP_PKEY_verify_message_update(pctx, data, len);
        if (ret != 1) {
            PRINTERROSSL("Failed to EVP_PKEY_verify_message_update\n");
            exit(EXIT_FAILURE);
        }
        ret = EVP_PKEY_CTX_set_signature(pctx, signature, siglen);
        if (ret != 1) {
            PRINTERROSSL("Failed to set signature for verify\n");
            exit(EXIT_FAILURE);
        }
        ret = EVP_PKEY_verify_message_final(pctx);
        if (ret != 1) {
            PRINTERROSSL(
                "Failed to EVP_PKEY_verify_message_final-ize/bad signature\n");
            exit(EXIT_FAILURE);
        }
    }

    EVP_SIGNATURE_free(sigalg);
    EVP_PKEY_CTX_free(pctx);
}
#endif

static void check_public_info(EVP_PKEY *key)
{
    BIO *membio = BIO_new(BIO_s_mem());
    BUF_MEM *memdata = NULL;
    const char *type = "type=public";
    void *found = NULL;
    int ret;

    if (!membio) {
        PRINTERROSSL("Failed to instantiate Memory BIO\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_print_public(membio, key, 0, NULL);
    if (ret != 1) {
        PRINTERROSSL("Failed to print public key info\n");
        exit(EXIT_FAILURE);
    }

    BIO_get_mem_ptr(membio, &memdata);
    if (!memdata) {
        PRINTERROSSL("Failed to fetch BIO memory pointer\n");
        exit(EXIT_FAILURE);
    }

    found = memmem(memdata->data, memdata->length, type, sizeof(type) - 1);
    if (!found) {
        PRINTERR("%.*s\n", (int)memdata->length, memdata->data);
        PRINTERROSSL("Public type indicator not found in printout!\n");
        exit(EXIT_FAILURE);
    }

    BIO_free(membio);
}

static void check_peer_ec_key_copy(void)
{
    EVP_PKEY *key;
    size_t key_bits;
    EVP_PKEY *peer_key;
    size_t peer_key_bits;

    key = util_gen_key("P-256", "Pkey peer copy Test");
    key_bits = EVP_PKEY_bits(key);

    peer_key = EVP_PKEY_new();
    EVP_PKEY_copy_parameters(peer_key, key);
    peer_key_bits = EVP_PKEY_bits(peer_key);

    if (key_bits != peer_key_bits) {
        fprintf(stderr, "key_bits(%ld) != peer_key_bits(%ld)\n", key_bits,
                peer_key_bits);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(key);
}

int main(int argc, char *argv[])
{
    const char *driver = NULL;
    const unsigned char *data = (const unsigned char *)"Sign Me!";
    unsigned char *sig;
    size_t siglen;
    EVP_PKEY *key;
    int i;

    struct test_data {
        const char *key_type;
        const char *label;
        const char *digest;
        const char *sigalg;
        bool oneshot;
    };

    const struct test_data tests[] = {
        { "RSA 2048", "RSA Pkey sigver Test", "SHA256", "RSA-SHA256", false },
        { "P-256", "EC Pkey sigver Test", "SHA256", "ECDSA-SHA256", false },
        { "ED 25519", "ED Pkey sigver Test", NULL, "ED25519", true },
        { "ED 25519", "ED Pkey sigver Test", NULL, "Ed25519ph", true },
        { "ML-DSA-44", "ML-DSA-44 Pkey sigver Test", NULL, "ML-DSA-44", true },
        { "ML-DSA-65", "ML-DSA-65 Pkey sigver Test", NULL, "ML-DSA-65", true },
        { "ML-DSA-87", "ML-DSA-87 Pkey sigver Test", NULL, "ML-DSA-87", true },
    };

    driver = getenv("TOKEN_DRIVER");
    if (driver == NULL) {
        PRINTERR("TOKEN_DRIVER Environment variable is absent\n");
        driver = "NULL";
    } else {
        PRINTERR("Driver %s\n", driver);
    }

    for (i = 0; i < (sizeof(tests) / sizeof(tests[0])); i++) {
        /* Softokn does not handle Edwards keys yet */
        if (strcmp(tests[i].key_type, "ED 25519") == 0
            && strcmp(driver, "softokn") == 0) {
            continue;
        }

        /* ML-DSA is handled only in kryoptic so far */
        if (strncmp(tests[i].key_type, "ML-DSA", 6) == 0
            && strcmp(driver, "kryoptic") != 0) {
            continue;
        }

        PRINTERR("Testing key type %s\n", tests[i].key_type);
        key = util_gen_key(tests[i].key_type, tests[i].label);

        /* test a simple op first */
        sign_op(key, tests[i].oneshot, tests[i].digest, data, sizeof(data),
                &sig, &siglen);
        verify_op(key, tests[i].oneshot, tests[i].digest, data, sizeof(data),
                  sig, siglen);
        OPENSSL_free(sig);

#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
        /* older version of softhsm do not have CKM_ECDSA_<digest> mechs */
        if (strcmp(tests[i].key_type, "P-256") == 0
            && strcmp(driver, "softhsm") == 0) {
            continue;
        }
        /* test message-based ops */
        sign_msg_op(key, tests[i].oneshot, tests[i].sigalg, data, sizeof(data),
                    &sig, &siglen);
        verify_msg_op(key, tests[i].oneshot, tests[i].sigalg, data,
                      sizeof(data), sig, siglen);
        OPENSSL_free(sig);
#endif

        check_public_info(key);

        EVP_PKEY_free(key);
    }

    /* This test is EC specific */
    check_peer_ec_key_copy();

    PRINTERR("ALL A-OK!\n");
    exit(EXIT_SUCCESS);
}
