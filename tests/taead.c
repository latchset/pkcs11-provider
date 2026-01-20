/* Copyright 2025 NXP
   SPDX-License-Identifier: Apache-2.0
*/

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/store.h>
#include <openssl/core_names.h>
#include "util.h"

#if SKEY_SUPPORT == 1

#define MAX_DATA_LEN 1024

static int aead_encrypt_data(const char *algorithm, const char *propq,
                             bool skey, const uint8_t *key, size_t keylen,
                             const uint8_t *iv, size_t ivlen,
                             const uint8_t *input, size_t inputlen,
                             const uint8_t *aad, size_t aadlen, uint8_t *output,
                             size_t *outputlen, uint8_t *tag, size_t *taglen)
{
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_SKEY *skey_obj = NULL;
    int status = EXIT_FAILURE;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed!\n");
        goto end;
    }

    cipher = EVP_CIPHER_fetch(NULL, algorithm, propq);
    if (!cipher) {
        fprintf(stderr, "EVP_CIPHER_fetch failed!\n");
        goto end;
    }

    int tmplen = 0;
    int inlen = (int)inputlen;
    int outlen = (int)(*outputlen);

    OSSL_PARAM init_params[] = { OSSL_PARAM_construct_size_t(
                                     OSSL_CIPHER_PARAM_AEAD_IVLEN, &ivlen),
                                 OSSL_PARAM_construct_end() };

    if (skey) {
        int actualkeylen = EVP_CIPHER_get_key_length(cipher);
        if (keylen < actualkeylen) {
            fprintf(stderr, "Provided key length too small!\n");
            goto end;
        }

        skey_obj = EVP_SKEY_import_raw_key(NULL, "AES", (unsigned char *)key,
                                           actualkeylen, propq);
        if (!skey_obj) {
            fprintf(stderr, "EVP_SKEY_import_raw_key failed!\n");
            goto end;
        }

        if (EVP_CipherInit_SKEY(ctx, cipher, skey_obj, iv, ivlen, 1,
                                init_params)
            != 1) {
            fprintf(stderr, "EVP_CipherInit_SKEY failed!\n");
            goto end;
        }
    } else {
        if (EVP_EncryptInit_ex2(ctx, cipher, key, iv, init_params) != 1) {
            fprintf(stderr, "EVP_EncryptInit_ex2 failed!\n");
            goto end;
        }
    }

    if (EVP_EncryptUpdate(ctx, NULL, &outlen, aad, aadlen) != 1
        || EVP_EncryptUpdate(ctx, output, &outlen, input, inlen) != 1
        || EVP_EncryptFinal_ex(ctx, output, &tmplen) != 1) {
        fprintf(stderr, "EVP_Encrypt* failed!\n");
        goto end;
    }

    OSSL_PARAM tag_enc_params[] = { OSSL_PARAM_construct_octet_string(
                                        OSSL_CIPHER_PARAM_AEAD_TAG, tag,
                                        *taglen),
                                    OSSL_PARAM_construct_end() };
    if (EVP_CIPHER_CTX_get_params(ctx, tag_enc_params) != 1) {
        fprintf(stderr, "EVP_CIPHER_CTX_get_params failed!\n");
        goto end;
    }

    *outputlen = outlen;

    status = EXIT_SUCCESS;

end:
    if (skey_obj) EVP_SKEY_free(skey_obj);
    if (cipher) EVP_CIPHER_free(cipher);
    if (ctx) EVP_CIPHER_CTX_free(ctx);

    return status;
}

static int aead_decrypt_data(const char *algorithm, const char *propq,
                             bool skey, const uint8_t *key, size_t keylen,
                             const uint8_t *iv, size_t ivlen,
                             const uint8_t *input, size_t inputlen,
                             const uint8_t *aad, size_t aadlen, uint8_t *output,
                             size_t *outputlen, uint8_t *tag, size_t taglen)
{
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_SKEY *skey_obj = NULL;
    int status = EXIT_FAILURE;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed!\n");
        goto end;
    }

    cipher = EVP_CIPHER_fetch(NULL, algorithm, propq);
    if (!cipher) {
        fprintf(stderr, "EVP_CIPHER_fetch failed!\n");
        goto end;
    }

    int tmplen = 0;
    int inlen = (int)inputlen;
    int outlen = (int)(*outputlen);

    OSSL_PARAM init_params[] = { OSSL_PARAM_construct_size_t(
                                     OSSL_CIPHER_PARAM_AEAD_IVLEN, &ivlen),
                                 OSSL_PARAM_construct_end() };

    OSSL_PARAM tag_params[] = { OSSL_PARAM_construct_octet_string(
                                    OSSL_CIPHER_PARAM_AEAD_TAG, tag, taglen),
                                OSSL_PARAM_construct_end() };

    if (skey) {
        int actualkeylen = EVP_CIPHER_get_key_length(cipher);
        if (keylen < actualkeylen) {
            fprintf(stderr, "Provided key length too small!\n");
            goto end;
        }

        skey_obj = EVP_SKEY_import_raw_key(NULL, "AES", (unsigned char *)key,
                                           actualkeylen, propq);
        if (!skey_obj) {
            fprintf(stderr, "EVP_SKEY_import_raw_key failed!\n");
            goto end;
        }

        if (EVP_CipherInit_SKEY(ctx, cipher, skey_obj, iv, ivlen, 0,
                                init_params)
            != 1) {
            fprintf(stderr, "EVP_CipherInit_SKEY failed!\n");
            goto end;
        }
    } else {
        if (EVP_DecryptInit_ex2(ctx, cipher, key, iv, init_params) != 1) {
            fprintf(stderr, "EVP_DecryptInit_ex2 failed!\n");
            goto end;
        }
    }

    if (EVP_CIPHER_CTX_set_params(ctx, tag_params) != 1
        || EVP_DecryptUpdate(ctx, NULL, &inlen, aad, aadlen) != 1
        || EVP_DecryptUpdate(ctx, output, &outlen, input, inputlen) != 1
        || EVP_DecryptFinal_ex(ctx, output, &tmplen) != 1) {
        fprintf(stderr, "EVP_Decrypt* failed!\n");
        goto end;
    }

    *outputlen = outlen;

    status = EXIT_SUCCESS;

end:
    if (skey_obj) EVP_SKEY_free(skey_obj);
    if (cipher) EVP_CIPHER_free(cipher);
    if (ctx) EVP_CIPHER_CTX_free(ctx);

    return status;
}

static int aead_test(const char *algorithm, bool skey, const uint8_t *key,
                     size_t keylen, const uint8_t *iv, size_t ivlen,
                     const uint8_t *aad, size_t aadlen, const uint8_t *data,
                     size_t datalen)
{
    unsigned char ciphertext1[MAX_DATA_LEN] = { 0 };
    size_t ciphertextlen1 = datalen;
    unsigned char plaintext1[MAX_DATA_LEN] = { 0 };
    size_t plaintextlen1 = datalen;
    unsigned char tag1[EVP_MAX_AEAD_TAG_LENGTH] = { 0 };
    size_t taglen1 = sizeof(tag1);

    unsigned char ciphertext2[MAX_DATA_LEN] = { 0 };
    size_t ciphertextlen2 = sizeof(ciphertext2);
    unsigned char plaintext2[MAX_DATA_LEN] = { 0 };
    size_t plaintextlen2 = sizeof(plaintext2);
    unsigned char tag2[EVP_MAX_AEAD_TAG_LENGTH] = { 0 };
    size_t taglen2 = sizeof(tag2);

    if (aead_encrypt_data(algorithm, "provider=pkcs11", skey, key, keylen, iv,
                          ivlen, data, datalen, aad, aadlen, ciphertext1,
                          &ciphertextlen1, tag1, &taglen1)
        != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (aead_encrypt_data(algorithm, "provider=default", skey, key, keylen, iv,
                          ivlen, data, datalen, aad, aadlen, ciphertext2,
                          &ciphertextlen2, tag2, &taglen2)
        != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (ciphertextlen1 != ciphertextlen2 || taglen1 != taglen2) {
        fprintf(stderr, "Ciphertext or tag length mismatch!\n");
        return EXIT_FAILURE;
    }

    if (memcmp(ciphertext1, ciphertext2, ciphertextlen1) != 0) {
        fprintf(stderr, "Ciphertext mismatch!\n");
        return EXIT_FAILURE;
    }

    if (memcmp(tag1, tag2, taglen1) != 0) {
        fprintf(stderr, "Tag mismatch!\n");
        return EXIT_FAILURE;
    }

    /* Decrypt with pkcs11 provider the output from default provider */
    if (aead_decrypt_data(algorithm, "provider=pkcs11", skey, key, keylen, iv,
                          ivlen, ciphertext2, ciphertextlen2, aad, aadlen,
                          plaintext1, &plaintextlen1, tag1, taglen1)
        != EXIT_SUCCESS)
        return EXIT_FAILURE;

    /* Decrypt with default provider the output from pkcs11 provider */
    if (aead_decrypt_data(algorithm, "provider=default", skey, key, keylen, iv,
                          ivlen, ciphertext1, ciphertextlen1, aad, aadlen,
                          plaintext2, &plaintextlen2, tag2, taglen2)
        != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (plaintextlen1 != plaintextlen2) {
        fprintf(stderr, "Plaintext length mismatch!\n");
        return EXIT_FAILURE;
    }

    if (memcmp(plaintext1, plaintext2, plaintextlen1) != 0) {
        fprintf(stderr, "Recovered plaintext mismatch!\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    unsigned char key[EVP_MAX_KEY_LENGTH] = { 0 };
    size_t keylen = sizeof(key);
    unsigned char iv[EVP_MAX_IV_LENGTH] = { 0 };
    size_t ivlen = sizeof(iv);

    if (argc != 6) {
        fprintf(stderr, "Usage: %s [algorithm] [hexkey] [hexiv] [aad] [data]\n",
                argv[0]);
        fprintf(stderr,
                "    Algorithms: AES-128-GCM, AES-192-GCM, AES-256-GCM,\n"
                "                CHACHA20-POLY1305\n");
        exit(EXIT_FAILURE);
    }

    unhexify(key, &keylen, argv[2]);
    unhexify(iv, &ivlen, argv[3]);

    int status = EXIT_SUCCESS;

    status =
        aead_test(argv[1], true, key, keylen, iv, ivlen, (uint8_t *)argv[4],
                  strlen(argv[4]), (uint8_t *)argv[5], strlen(argv[5]));
    if (status != EXIT_SUCCESS) {
        return status;
    }
    PRINTERR("Skey - OK\n");

    status =
        aead_test(argv[1], false, key, keylen, iv, ivlen, (uint8_t *)argv[4],
                  strlen(argv[4]), (uint8_t *)argv[5], strlen(argv[5]));
    if (status != EXIT_SUCCESS) {
        return status;
    }
    PRINTERR("Legacy - OK\n");

    return status;
}
#else
int main(int argc, char *argv[])
{
    return 0;
}
#endif
