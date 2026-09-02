/* Copyright (C) 2026 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include "util.h"

struct sshkdf_test_case {
    const char *name;
    const char *digest;
    const unsigned char *key;
    size_t key_len;
    const unsigned char *xcghash;
    size_t xcghash_len;
    const unsigned char *session_id;
    size_t session_id_len;
    char type;
    size_t out_len;
};

static const unsigned char key1[] = {
    0x00, 0x00, 0x00, 0x20, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
    0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
};
static const unsigned char xcghash1[] = {
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
    0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
    0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
};
static const unsigned char session_id1[] = {
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
    0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
    0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
};

static const unsigned char key2[] = { 0x52, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x20,
                                      0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x20,
                                      0x4b, 0x65, 0x79, 0x20, 0x46, 0x6f, 0x72,
                                      0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6e,
                                      0x67, 0x21, 0x23, 0x24 };
static const unsigned char xcghash2[] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
    0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};
static const unsigned char session_id2[] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
    0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
    0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
};

static const struct sshkdf_test_case test_cases[] = {
    { "SHA256, type A, 512 bytes", "SHA256", key1, sizeof(key1), xcghash1,
      sizeof(xcghash1), session_id1, sizeof(session_id1), 'A', 512 },
    { "SHA256, type B, 16 bytes", "SHA256", key1, sizeof(key1), xcghash1,
      sizeof(xcghash1), session_id1, sizeof(session_id1), 'B', 16 },
    { "SHA256, type C, 32 bytes", "SHA256", key1, sizeof(key1), xcghash1,
      sizeof(xcghash1), session_id1, sizeof(session_id1), 'C', 32 },
    { "SHA256, type D, 48 bytes", "SHA256", key1, sizeof(key1), xcghash1,
      sizeof(xcghash1), session_id1, sizeof(session_id1), 'D', 48 },
    { "SHA256, type E, 64 bytes", "SHA256", key1, sizeof(key1), xcghash1,
      sizeof(xcghash1), session_id1, sizeof(session_id1), 'E', 64 },
    { "SHA256, type F, 128 bytes", "SHA256", key1, sizeof(key1), xcghash1,
      sizeof(xcghash1), session_id1, sizeof(session_id1), 'F', 128 },
    { "SHA1, type A, 20 bytes", "SHA1", key2, sizeof(key2), xcghash2,
      sizeof(xcghash2), session_id2, sizeof(session_id2), 'A', 20 },
    { "SHA1, type B, 40 bytes", "SHA1", key2, sizeof(key2), xcghash2,
      sizeof(xcghash2), session_id2, sizeof(session_id2), 'B', 40 },
    { "SHA1, type C, 64 bytes", "SHA1", key2, sizeof(key2), xcghash2,
      sizeof(xcghash2), session_id2, sizeof(session_id2), 'C', 64 },
    { "SHA224, type A, 28 bytes", "SHA224", key2, sizeof(key2), xcghash2,
      sizeof(xcghash2), session_id2, sizeof(session_id2), 'A', 28 },
    { "SHA224, type D, 56 bytes", "SHA224", key2, sizeof(key2), xcghash2,
      sizeof(xcghash2), session_id2, sizeof(session_id2), 'D', 56 },
    { "SHA384, type B, 48 bytes", "SHA384", key2, sizeof(key2), xcghash2,
      sizeof(xcghash2), session_id2, sizeof(session_id2), 'B', 48 },
    { "SHA384, type E, 96 bytes", "SHA384", key2, sizeof(key2), xcghash2,
      sizeof(xcghash2), session_id2, sizeof(session_id2), 'E', 96 },
    { "SHA512, type C, 64 bytes", "SHA512", key2, sizeof(key2), xcghash2,
      sizeof(xcghash2), session_id2, sizeof(session_id2), 'C', 64 },
    { "SHA512, type F, 128 bytes", "SHA512", key2, sizeof(key2), xcghash2,
      sizeof(xcghash2), session_id2, sizeof(session_id2), 'F', 128 },
};

static int derive_default_sshkdf(OSSL_LIB_CTX *def_libctx,
                                 const struct sshkdf_test_case *tc,
                                 unsigned char *out, size_t outlen)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    char type_str[2] = { tc->type, '\0' };
    OSSL_PARAM params[6];
    int p = 0;
    int ret;

    kdf = EVP_KDF_fetch(def_libctx, "SSHKDF", "provider=default");
    if (!kdf) {
        PRINTERROSSL("EVP_KDF_fetch for default SSHKDF failed\n");
        return -1;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        PRINTERROSSL("EVP_KDF_CTX_new for default SSHKDF failed\n");
        EVP_KDF_free(kdf);
        return -1;
    }

    params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                   (char *)tc->digest, 0);
    params[p++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, (void *)tc->key, tc->key_len);
    params[p++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SSHKDF_XCGHASH, (void *)tc->xcghash, tc->xcghash_len);
    params[p++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SSHKDF_SESSION_ID, (void *)tc->session_id,
        tc->session_id_len);
    params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
                                                   type_str, 0);
    params[p++] = OSSL_PARAM_construct_end();

    ret = EVP_KDF_derive(kctx, out, outlen, params);
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);

    return ret == 1 ? 0 : -1;
}

static void test_classic_interface(OSSL_LIB_CTX *def_libctx, EVP_KDF *kdf)
{
    size_t num_tests = sizeof(test_cases) / sizeof(test_cases[0]);
    size_t i;

    PRINTERR("Testing SSHKDF classic interface ...\n");

    for (i = 0; i < num_tests; i++) {
        const struct sshkdf_test_case *tc = &test_cases[i];
        EVP_KDF_CTX *kctx = NULL;
        unsigned char *expected = NULL;
        unsigned char *derived = NULL;
        char type_str[2] = { tc->type, '\0' };
        OSSL_PARAM params[6];
        int p = 0;
        int ret;

        PRINTERR("  SSHKDF classic: %s ...\n", tc->name);

        expected = OPENSSL_zalloc(tc->out_len);
        derived = OPENSSL_zalloc(tc->out_len);
        if (!expected || !derived) {
            PRINTERR("Failed to allocate memory\n");
            exit(EXIT_FAILURE);
        }

        if (derive_default_sshkdf(def_libctx, tc, expected, tc->out_len) != 0) {
            PRINTERR("Failed to compute default reference for '%s'\n",
                     tc->name);
            exit(EXIT_FAILURE);
        }

        kctx = EVP_KDF_CTX_new(kdf);
        if (!kctx) {
            PRINTERROSSL("EVP_KDF_CTX_new failed for '%s'\n", tc->name);
            exit(EXIT_FAILURE);
        }

        params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                       (char *)tc->digest, 0);
        params[p++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY, (void *)tc->key, tc->key_len);
        params[p++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SSHKDF_XCGHASH, (void *)tc->xcghash,
            tc->xcghash_len);
        params[p++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SSHKDF_SESSION_ID, (void *)tc->session_id,
            tc->session_id_len);
        params[p++] = OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_SSHKDF_TYPE, type_str, 0);
        params[p++] = OSSL_PARAM_construct_end();

        ret = EVP_KDF_derive(kctx, derived, tc->out_len, params);
        if (ret != 1) {
            PRINTERROSSL("EVP_KDF_derive failed for '%s'\n", tc->name);
            exit(EXIT_FAILURE);
        }

        if (memcmp(derived, expected, tc->out_len) != 0) {
            PRINTERR("Output mismatch for '%s'\n", tc->name);
            exit(EXIT_FAILURE);
        }

        EVP_KDF_CTX_free(kctx);
        OPENSSL_free(expected);
        OPENSSL_free(derived);
    }

    /* Test setting params via EVP_KDF_CTX_set_params then deriving with NULL params */
    {
        const struct sshkdf_test_case *tc = &test_cases[0];
        EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
        unsigned char *expected = OPENSSL_zalloc(tc->out_len);
        unsigned char *derived = OPENSSL_zalloc(tc->out_len);
        char type_str[2] = { tc->type, '\0' };
        OSSL_PARAM params[6];
        int p = 0;

        if (!kctx || !expected || !derived) {
            PRINTERR("Failed to allocate memory\n");
            exit(EXIT_FAILURE);
        }
        if (derive_default_sshkdf(def_libctx, tc, expected, tc->out_len) != 0) {
            PRINTERR("Failed to compute default reference\n");
            exit(EXIT_FAILURE);
        }

        params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                       (char *)tc->digest, 0);
        params[p++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY, (void *)tc->key, tc->key_len);
        params[p++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SSHKDF_XCGHASH, (void *)tc->xcghash,
            tc->xcghash_len);
        params[p++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SSHKDF_SESSION_ID, (void *)tc->session_id,
            tc->session_id_len);
        params[p++] = OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_SSHKDF_TYPE, type_str, 0);
        params[p++] = OSSL_PARAM_construct_end();

        if (EVP_KDF_CTX_set_params(kctx, params) != 1
            || EVP_KDF_derive(kctx, derived, tc->out_len, NULL) != 1
            || memcmp(derived, expected, tc->out_len) != 0) {
            PRINTERR("EVP_KDF_CTX_set_params + EVP_KDF_derive failed\n");
            exit(EXIT_FAILURE);
        }
        EVP_KDF_CTX_free(kctx);
        OPENSSL_free(expected);
        OPENSSL_free(derived);
    }
}

#if defined(OSSL_FUNC_KDF_DERIVE_SKEY)
static void test_aes_encrypt_decrypt(OSSL_LIB_CTX *def_libctx,
                                     OSSL_LIB_CTX *p11_libctx, EVP_SKEY *skey,
                                     const unsigned char *expected_key,
                                     size_t key_len, const char *test_name)
{
    const char *cipher_name = NULL;
    if (key_len == 16) {
        cipher_name = "AES-128-CBC";
    } else if (key_len == 24) {
        cipher_name = "AES-192-CBC";
    } else if (key_len == 32) {
        cipher_name = "AES-256-CBC";
    } else {
        PRINTERR("Unsupported AES key length: %zu\n", key_len);
        exit(EXIT_FAILURE);
    }

    const unsigned char plaintext[] = "SSHKDF AES derived key test 1234567890!";
    size_t pt_len = sizeof(plaintext);
    unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    unsigned char ciphertext[128] = { 0 };
    int ct_len = 0, tmp_len = 0;
    unsigned char decrypted[128] = { 0 };
    int dt_len = 0;

    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER *cipher =
        EVP_CIPHER_fetch(p11_libctx, cipher_name, "provider=pkcs11");
    if (!cctx || !cipher) {
        PRINTERROSSL("Failed to allocate cipher context or fetch cipher\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_CipherInit_SKEY(cctx, cipher, skey, iv, sizeof(iv), 1, NULL) != 1) {
        PRINTERROSSL("EVP_CipherInit_SKEY failed for '%s'\n", test_name);
        exit(EXIT_FAILURE);
    }
    if (EVP_EncryptUpdate(cctx, ciphertext, &ct_len, plaintext, (int)pt_len)
        != 1) {
        PRINTERROSSL("EVP_EncryptUpdate failed for '%s'\n", test_name);
        exit(EXIT_FAILURE);
    }
    if (EVP_EncryptFinal_ex(cctx, ciphertext + ct_len, &tmp_len) != 1) {
        PRINTERROSSL("EVP_EncryptFinal_ex failed for '%s'\n", test_name);
        exit(EXIT_FAILURE);
    }
    ct_len += tmp_len;
    EVP_CIPHER_CTX_free(cctx);
    EVP_CIPHER_free(cipher);

    cctx = EVP_CIPHER_CTX_new();
    cipher = EVP_CIPHER_fetch(def_libctx, cipher_name, "provider=default");
    if (!cctx || !cipher) {
        PRINTERROSSL(
            "Failed to allocate cipher context or fetch default cipher\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_DecryptInit_ex2(cctx, cipher, expected_key, iv, NULL) != 1) {
        PRINTERROSSL("EVP_DecryptInit_ex2 failed for '%s'\n", test_name);
        exit(EXIT_FAILURE);
    }
    if (EVP_DecryptUpdate(cctx, decrypted, &dt_len, ciphertext, ct_len) != 1) {
        PRINTERROSSL("EVP_DecryptUpdate failed for '%s'\n", test_name);
        exit(EXIT_FAILURE);
    }
    if (EVP_DecryptFinal_ex(cctx, decrypted + dt_len, &tmp_len) != 1) {
        PRINTERROSSL("EVP_DecryptFinal_ex failed for '%s'\n", test_name);
        exit(EXIT_FAILURE);
    }
    dt_len += tmp_len;
    EVP_CIPHER_CTX_free(cctx);
    EVP_CIPHER_free(cipher);

    if (dt_len != (int)pt_len || memcmp(decrypted, plaintext, pt_len) != 0) {
        PRINTERR("Decrypted plaintext mismatch for '%s'\n", test_name);
        exit(EXIT_FAILURE);
    }
}

static void test_skey_interface(OSSL_LIB_CTX *def_libctx,
                                OSSL_LIB_CTX *p11_libctx, EVP_KDF *kdf)
{
    EVP_SKEYMGMT *skeymgmt = NULL;
    EVP_SKEYMGMT *aes_skeymgmt = NULL;
    size_t num_tests = sizeof(test_cases) / sizeof(test_cases[0]);
    size_t i;

    PRINTERR("Testing SSHKDF SKEY interface ...\n");

    skeymgmt =
        EVP_SKEYMGMT_fetch(p11_libctx, "GENERIC-SECRET", "provider=pkcs11");
    if (!skeymgmt) {
        PRINTERR("EVP_SKEYMGMT_fetch for GENERIC-SECRET failed, skipping SKEY "
                 "tests\n");
        return;
    }
    aes_skeymgmt = EVP_SKEYMGMT_fetch(p11_libctx, "AES", "provider=pkcs11");
    if (!aes_skeymgmt) {
        PRINTERR("EVP_SKEYMGMT_fetch for AES failed, skipping SKEY tests\n");
        EVP_SKEYMGMT_free(skeymgmt);
        return;
    }

    for (i = 0; i < num_tests; i++) {
        const struct sshkdf_test_case *tc = &test_cases[i];
        EVP_KDF_CTX *kctx = NULL;
        EVP_SKEY *skey = NULL;
        EVP_SKEY *out_skey = NULL;
        unsigned char *expected = NULL;
        unsigned char *derived = NULL;
        char type_str[2] = { tc->type, '\0' };
        OSSL_PARAM sparams[2];
        OSSL_PARAM params[5];
        int p = 0;
        int ret;

        PRINTERR("  SSHKDF SKEY: %s ...\n", tc->name);

        expected = OPENSSL_zalloc(tc->out_len);
        derived = OPENSSL_zalloc(tc->out_len);
        if (!expected || !derived) {
            PRINTERR("Failed to allocate memory\n");
            exit(EXIT_FAILURE);
        }

        if (derive_default_sshkdf(def_libctx, tc, expected, tc->out_len) != 0) {
            PRINTERR("Failed to compute default reference for '%s'\n",
                     tc->name);
            exit(EXIT_FAILURE);
        }

        sparams[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SKEY_PARAM_RAW_BYTES, (void *)tc->key, tc->key_len);
        sparams[1] = OSSL_PARAM_construct_end();

        skey = EVP_SKEY_import_SKEYMGMT(
            p11_libctx, skeymgmt, OSSL_SKEYMGMT_SELECT_SECRET_KEY, sparams);
        if (!skey) {
            PRINTERROSSL("EVP_SKEY_import_SKEYMGMT failed for '%s'\n",
                         tc->name);
            exit(EXIT_FAILURE);
        }

        kctx = EVP_KDF_CTX_new(kdf);
        if (!kctx) {
            PRINTERROSSL("EVP_KDF_CTX_new failed for '%s'\n", tc->name);
            EVP_SKEY_free(skey);
            exit(EXIT_FAILURE);
        }

        if (EVP_KDF_CTX_set_SKEY(kctx, skey, NULL) <= 0) {
            PRINTERROSSL("EVP_KDF_CTX_set_SKEY failed for '%s'\n", tc->name);
            EVP_SKEY_free(skey);
            exit(EXIT_FAILURE);
        }
        EVP_SKEY_free(skey);

        params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                       (char *)tc->digest, 0);
        params[p++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SSHKDF_XCGHASH, (void *)tc->xcghash,
            tc->xcghash_len);
        params[p++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SSHKDF_SESSION_ID, (void *)tc->session_id,
            tc->session_id_len);
        params[p++] = OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_SSHKDF_TYPE, type_str, 0);
        params[p++] = OSSL_PARAM_construct_end();

        ret = EVP_KDF_derive(kctx, derived, tc->out_len, params);
        if (ret != 1) {
            PRINTERROSSL("EVP_KDF_derive with SKEY failed for '%s'\n",
                         tc->name);
            exit(EXIT_FAILURE);
        }

        if (memcmp(derived, expected, tc->out_len) != 0) {
            PRINTERR("Output mismatch for SKEY '%s'\n", tc->name);
            exit(EXIT_FAILURE);
        }

        /* For type C keys with AES key length, also test EVP_KDF_derive_SKEY with AES */
        if (tc->type == 'C'
            && (tc->out_len == 16 || tc->out_len == 24 || tc->out_len == 32)) {
            EVP_KDF_CTX_reset(kctx);
            skey = EVP_SKEY_import_SKEYMGMT(
                p11_libctx, skeymgmt, OSSL_SKEYMGMT_SELECT_SECRET_KEY, sparams);
            if (!skey) {
                PRINTERROSSL("EVP_SKEY_import_SKEYMGMT failed for '%s'\n",
                             tc->name);
                exit(EXIT_FAILURE);
            }
            if (EVP_KDF_CTX_set_SKEY(kctx, skey, NULL) <= 0) {
                PRINTERROSSL("EVP_KDF_CTX_set_SKEY failed for '%s'\n",
                             tc->name);
                EVP_SKEY_free(skey);
                exit(EXIT_FAILURE);
            }
            EVP_SKEY_free(skey);

            out_skey = EVP_KDF_derive_SKEY(kctx, aes_skeymgmt, "AES", NULL,
                                           tc->out_len, params);
            if (!out_skey) {
                PRINTERROSSL("EVP_KDF_derive_SKEY failed for '%s'\n", tc->name);
                exit(EXIT_FAILURE);
            }

            /* The SKEY is not extractable, so verify we got the correct key out
             * by *using* in a way that will fail the operation if they key is
             * wrong */
            test_aes_encrypt_decrypt(def_libctx, p11_libctx, out_skey, expected,
                                     tc->out_len, tc->name);
            EVP_SKEY_free(out_skey);
        }

        EVP_KDF_CTX_free(kctx);
        OPENSSL_free(expected);
        OPENSSL_free(derived);
    }

    /* Test setting SKEY with explicit OSSL_KDF_PARAM_KEY and non-matching name */
    {
        const struct sshkdf_test_case *tc = &test_cases[0];
        EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
        OSSL_PARAM sparams[2];
        EVP_SKEY *skey;

        sparams[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SKEY_PARAM_RAW_BYTES, (void *)tc->key, tc->key_len);
        sparams[1] = OSSL_PARAM_construct_end();
        skey = EVP_SKEY_import_SKEYMGMT(
            p11_libctx, skeymgmt, OSSL_SKEYMGMT_SELECT_SECRET_KEY, sparams);
        if (!skey || !kctx) {
            PRINTERR("Failed to allocate / import skey\n");
            exit(EXIT_FAILURE);
        }

        /* Test setting SKEY with explicit "key" param name */
        if (EVP_KDF_CTX_set_SKEY(kctx, skey, OSSL_KDF_PARAM_KEY) <= 0) {
            PRINTERR("EVP_KDF_CTX_set_SKEY with OSSL_KDF_PARAM_KEY failed\n");
            exit(EXIT_FAILURE);
        }

        /* Test setting SKEY with non-matching param name (should be ignored and succeed) */
        if (EVP_KDF_CTX_set_SKEY(kctx, skey, "non_matching_param") <= 0) {
            PRINTERR("EVP_KDF_CTX_set_SKEY with other name failed\n");
            exit(EXIT_FAILURE);
        }

        EVP_SKEY_free(skey);
        EVP_KDF_CTX_free(kctx);
    }

    EVP_SKEYMGMT_free(aes_skeymgmt);
    EVP_SKEYMGMT_free(skeymgmt);
}
#endif

static void test_params_and_reset(OSSL_LIB_CTX *def_libctx, EVP_KDF *kdf)
{
    EVP_KDF_CTX *kctx = NULL;
    const OSSL_PARAM *gettable, *settable;
    size_t sz = 0, param_sz = 0;
    unsigned char out1[32], out2[32], ref[32];
    OSSL_PARAM params[6];
    OSSL_PARAM get_params[2];
    int p = 0;

    PRINTERR("Testing params and reset ...\n");

    gettable = EVP_KDF_gettable_ctx_params(kdf);
    settable = EVP_KDF_settable_ctx_params(kdf);
    if (!gettable || !settable) {
        PRINTERR("gettable/settable ctx params returned NULL\n");
        exit(EXIT_FAILURE);
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        PRINTERROSSL("EVP_KDF_CTX_new failed\n");
        exit(EXIT_FAILURE);
    }

    /* Test EVP_KDF_CTX_get_params with NULL params */
    if (EVP_KDF_CTX_get_params(kctx, NULL) != 1) {
        PRINTERROSSL("EVP_KDF_CTX_get_params with NULL failed\n");
        exit(EXIT_FAILURE);
    }

    /* Test EVP_KDF_CTX_get_params with OSSL_KDF_PARAM_SIZE */
    get_params[0] = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &param_sz);
    get_params[1] = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_get_params(kctx, get_params) != 1) {
        PRINTERROSSL("EVP_KDF_CTX_get_params for OSSL_KDF_PARAM_SIZE failed\n");
        exit(EXIT_FAILURE);
    }
    if (param_sz != SIZE_MAX) {
        PRINTERR("Expected OSSL_KDF_PARAM_SIZE == SIZE_MAX, got %zu\n",
                 param_sz);
        exit(EXIT_FAILURE);
    }

    /* Also verify EVP_KDF_CTX_get_kdf_size helper */
    sz = EVP_KDF_CTX_get_kdf_size(kctx);
    if (sz != SIZE_MAX) {
        PRINTERR("Expected EVP_KDF_CTX_get_kdf_size == SIZE_MAX, got %zu\n",
                 sz);
        exit(EXIT_FAILURE);
    }

    /* Set params, derive out1 */
    params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                   (char *)"SHA256", 0);
    params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                    (void *)key1, sizeof(key1));
    params[p++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SSHKDF_XCGHASH, (void *)xcghash1, sizeof(xcghash1));
    params[p++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SSHKDF_SESSION_ID, (void *)session_id1,
        sizeof(session_id1));
    params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
                                                   (char *)"A", 0);
    params[p++] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out1, sizeof(out1), params) != 1) {
        PRINTERROSSL("EVP_KDF_derive before reset failed\n");
        exit(EXIT_FAILURE);
    }

    /* Reset context */
    EVP_KDF_CTX_reset(kctx);

    /* Derive again after reset on new params */
    p = 0;
    params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                   (char *)"SHA256", 0);
    params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                    (void *)key1, sizeof(key1));
    params[p++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SSHKDF_XCGHASH, (void *)xcghash1, sizeof(xcghash1));
    params[p++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SSHKDF_SESSION_ID, (void *)session_id1,
        sizeof(session_id1));
    params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
                                                   (char *)"B", 0);
    params[p++] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out2, sizeof(out2), params) != 1) {
        PRINTERROSSL("EVP_KDF_derive after reset failed\n");
        exit(EXIT_FAILURE);
    }

    if (derive_default_sshkdf(def_libctx, &test_cases[1], ref, sizeof(ref))
        != 0) {
        PRINTERR("derive_default_sshkdf failed\n");
        exit(EXIT_FAILURE);
    }

    if (memcmp(out2, ref, sizeof(ref)) != 0) {
        PRINTERR("Output mismatch after reset\n");
        exit(EXIT_FAILURE);
    }

    EVP_KDF_CTX_free(kctx);
}

static void test_negative_cases(EVP_KDF *kdf)
{
    EVP_KDF_CTX *kctx = NULL;
    unsigned char out[32];
    OSSL_PARAM params[6];

    PRINTERR("Testing negative / edge cases ...\n");

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        PRINTERROSSL("EVP_KDF_CTX_new failed\n");
        exit(EXIT_FAILURE);
    }

    /* 1. Missing all parameters */
    if (EVP_KDF_derive(kctx, out, sizeof(out), NULL) == 1) {
        PRINTERR("Derive without parameters unexpectedly succeeded\n");
        exit(EXIT_FAILURE);
    }
    ERR_clear_error();

    /* 2. Missing key */
    EVP_KDF_CTX_reset(kctx);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                 (char *)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SSHKDF_XCGHASH, (void *)xcghash1, sizeof(xcghash1));
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SSHKDF_SESSION_ID, (void *)session_id1,
        sizeof(session_id1));
    params[3] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
                                                 (char *)"A", 0);
    params[4] = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kctx, out, sizeof(out), params) == 1) {
        PRINTERR("Derive without key unexpectedly succeeded\n");
        exit(EXIT_FAILURE);
    }
    ERR_clear_error();

    /* 3. Missing digest */
    EVP_KDF_CTX_reset(kctx);
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                  (void *)key1, sizeof(key1));
    params[1] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SSHKDF_XCGHASH, (void *)xcghash1, sizeof(xcghash1));
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SSHKDF_SESSION_ID, (void *)session_id1,
        sizeof(session_id1));
    params[3] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
                                                 (char *)"A", 0);
    params[4] = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kctx, out, sizeof(out), params) == 1) {
        PRINTERR("Derive without digest unexpectedly succeeded\n");
        exit(EXIT_FAILURE);
    }
    ERR_clear_error();

    /* 4. Missing xcghash */
    EVP_KDF_CTX_reset(kctx);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                 (char *)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                  (void *)key1, sizeof(key1));
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SSHKDF_SESSION_ID, (void *)session_id1,
        sizeof(session_id1));
    params[3] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
                                                 (char *)"A", 0);
    params[4] = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kctx, out, sizeof(out), params) == 1) {
        PRINTERR("Derive without xcghash unexpectedly succeeded\n");
        exit(EXIT_FAILURE);
    }
    ERR_clear_error();

    /* 5. Missing session_id */
    EVP_KDF_CTX_reset(kctx);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                 (char *)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                  (void *)key1, sizeof(key1));
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SSHKDF_XCGHASH, (void *)xcghash1, sizeof(xcghash1));
    params[3] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
                                                 (char *)"A", 0);
    params[4] = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kctx, out, sizeof(out), params) == 1) {
        PRINTERR("Derive without session_id unexpectedly succeeded\n");
        exit(EXIT_FAILURE);
    }
    ERR_clear_error();

    /* 6. Missing type */
    EVP_KDF_CTX_reset(kctx);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                 (char *)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                  (void *)key1, sizeof(key1));
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SSHKDF_XCGHASH, (void *)xcghash1, sizeof(xcghash1));
    params[3] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SSHKDF_SESSION_ID, (void *)session_id1,
        sizeof(session_id1));
    params[4] = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kctx, out, sizeof(out), params) == 1) {
        PRINTERR("Derive without type unexpectedly succeeded\n");
        exit(EXIT_FAILURE);
    }
    ERR_clear_error();

    /* 7. Invalid digest name */
    EVP_KDF_CTX_reset(kctx);
    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, (char *)"INVALID_DIGEST_NAME", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params) == 1) {
        PRINTERR("Setting invalid digest unexpectedly succeeded\n");
        exit(EXIT_FAILURE);
    }
    ERR_clear_error();

    /* 8. Invalid type strings: "AA", "a", "" */
    const char *bad_types[] = { "AA", "a", "", "1", "@" };
    for (size_t i = 0; i < sizeof(bad_types) / sizeof(bad_types[0]); i++) {
        EVP_KDF_CTX_reset(kctx);
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
                                                     (char *)bad_types[i], 0);
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_KDF_CTX_set_params(kctx, params) == 1) {
            PRINTERR("Setting invalid type '%s' unexpectedly succeeded\n",
                     bad_types[i]);
            exit(EXIT_FAILURE);
        }
        ERR_clear_error();
    }

    /* 2. Invalid type character (e.g. 'G') */
    EVP_KDF_CTX_reset(kctx);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                 (char *)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                  (void *)key1, sizeof(key1));
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SSHKDF_XCGHASH, (void *)xcghash1, sizeof(xcghash1));
    params[3] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SSHKDF_SESSION_ID, (void *)session_id1,
        sizeof(session_id1));
    params[4] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
                                                 (char *)"G", 0);
    params[5] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out, sizeof(out), params) == 1) {
        PRINTERR("Derive with invalid type 'G' unexpectedly succeeded\n");
        exit(EXIT_FAILURE);
    }
    ERR_clear_error();

    /* 3. Output length 0 */
    EVP_KDF_CTX_reset(kctx);
    params[4] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
                                                 (char *)"A", 0);
    if (EVP_KDF_derive(kctx, out, 0, params) == 1) {
        PRINTERR("Derive with length 0 unexpectedly succeeded\n");
        exit(EXIT_FAILURE);
    }
    ERR_clear_error();

    /* 4. Output buffer NULL */
    if (EVP_KDF_derive(kctx, NULL, sizeof(out), params) == 1) {
        PRINTERR("Derive with NULL output buffer unexpectedly succeeded\n");
        exit(EXIT_FAILURE);
    }
    ERR_clear_error();

    EVP_KDF_CTX_free(kctx);
}

int main(int argc, char *argv[])
{
    OSSL_LIB_CTX *def_libctx = NULL;
    OSSL_LIB_CTX *p11_libctx = NULL;
    OSSL_PROVIDER *def_prov = NULL;
    OSSL_PROVIDER *p11_def_prov = NULL;
    OSSL_PROVIDER *p11_prov = NULL;
    EVP_KDF *kdf = NULL;

#if CAN_LOAD_PKCS11_PROVIDER
    def_libctx = util_load_default_libctx(&def_prov);
    p11_libctx = util_load_pkcs11_libctx(&p11_def_prov, &p11_prov, NULL);
#else
    PRINTERR("OSSL_PROVIDER_load_ex() not available in this version\n");
    exit(77);
#endif

    kdf = EVP_KDF_fetch(p11_libctx, "SSHKDF", "provider=pkcs11");
    if (!kdf) {
        PRINTERROSSL("EVP_KDF_fetch for SSHKDF failed!\n");
        exit(EXIT_FAILURE);
    }

    test_classic_interface(def_libctx, kdf);

#if defined(OSSL_FUNC_KDF_DERIVE_SKEY)
    test_skey_interface(def_libctx, p11_libctx, kdf);
#endif

    test_params_and_reset(def_libctx, kdf);
    test_negative_cases(kdf);

    EVP_KDF_free(kdf);
    OSSL_PROVIDER_unload(p11_prov);
    OSSL_PROVIDER_unload(p11_def_prov);
    OSSL_LIB_CTX_free(p11_libctx);
    OSSL_PROVIDER_unload(def_prov);
    OSSL_LIB_CTX_free(def_libctx);

    PRINTERR("ALL A-OK!\n");
    exit(EXIT_SUCCESS);
}
