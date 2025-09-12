/* Copyright (C) 2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include "util.h"

#if defined(OSSL_FUNC_KDF_DERIVE_SKEY)
static EVP_SKEY *import_skey(EVP_SKEYMGMT *skeymgmt, const unsigned char *key,
                             size_t keylen)
{
    EVP_SKEY *skey = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES,
                                                  (void *)key, keylen);
    params[1] = OSSL_PARAM_construct_end();

    skey = EVP_SKEY_import_SKEYMGMT(NULL, skeymgmt,
                                    OSSL_SKEYMGMT_SELECT_SECRET_KEY, params);
    if (!skey) {
        fprintf(stderr, "EVP_SKEY_import_SKEYMGMT failed!\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }
    return skey;
}

struct hkdf_test_vector {
    const char *name;
    const char *digest;
    const unsigned char *ikm;
    size_t ikm_len;
    const unsigned char *salt;
    size_t salt_len;
    const unsigned char *info;
    size_t info_len;
    const char *mode;
    size_t out_len;
    const unsigned char *expected;
};

/* Test vectors from RFC 5869 Appendix A.1 */
static const unsigned char ikm_sha256_1[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
static const unsigned char salt_sha256_1[] = { 0x00, 0x01, 0x02, 0x03, 0x04,
                                               0x05, 0x06, 0x07, 0x08, 0x09,
                                               0x0a, 0x0b, 0x0c };
static const unsigned char info_sha256_1[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
                                               0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
static const unsigned char prk_sha256_1[] = {
    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f,
    0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f,
    0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
};
static const unsigned char okm_sha256_1[] = {
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
    0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
    0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
    0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
};

/* Test vectors generated for absent salt */
static const unsigned char ikm_sha256_2[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
static const unsigned char prk_sha256_2[] = {
    0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16, 0x7f, 0x33, 0xa9,
    0x1d, 0x6f, 0x64, 0x8b, 0xdf, 0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb,
    0x63, 0x77, 0xac, 0x43, 0x4c, 0x1c, 0x29, 0x3c, 0xcb, 0x04
};
static const unsigned char okm_sha256_2[] = {
    0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80,
    0x2a, 0x06, 0x3c, 0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1,
    0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d, 0x9d,
    0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8
};
static const struct hkdf_test_vector tests[] = {
    /* SHA256 with salt tests */
    { "SHA256, salt, EXTRACT_AND_EXPAND", "SHA256", ikm_sha256_1,
      sizeof(ikm_sha256_1), salt_sha256_1, sizeof(salt_sha256_1), info_sha256_1,
      sizeof(info_sha256_1), "EXTRACT_AND_EXPAND", sizeof(okm_sha256_1),
      okm_sha256_1 },
    { "SHA256, salt, EXTRACT_ONLY", "SHA256", ikm_sha256_1,
      sizeof(ikm_sha256_1), salt_sha256_1, sizeof(salt_sha256_1), NULL, 0,
      "EXTRACT_ONLY", sizeof(prk_sha256_1), prk_sha256_1 },
    { "SHA256, salt, EXPAND_ONLY", "SHA256", prk_sha256_1, sizeof(prk_sha256_1),
      NULL, 0, info_sha256_1, sizeof(info_sha256_1), "EXPAND_ONLY",
      sizeof(okm_sha256_1), okm_sha256_1 },

    /* SHA256 without salt tests */
    { "SHA256, no salt, EXTRACT_AND_EXPAND", "SHA256", ikm_sha256_2,
      sizeof(ikm_sha256_2), NULL, 0, NULL, 0, "EXTRACT_AND_EXPAND",
      sizeof(okm_sha256_2), okm_sha256_2 },
    { "SHA256, no salt, EXTRACT_ONLY", "SHA256", ikm_sha256_2,
      sizeof(ikm_sha256_2), NULL, 0, NULL, 0, "EXTRACT_ONLY",
      sizeof(prk_sha256_2), prk_sha256_2 },
    { "SHA256, no salt, EXPAND_ONLY", "SHA256", prk_sha256_2,
      sizeof(prk_sha256_2), NULL, 0, NULL, 0, "EXPAND_ONLY",
      sizeof(okm_sha256_2), okm_sha256_2 },
};

static void test_hkdf(void)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    OSSL_PARAM params[5], *p;
    size_t i;
    EVP_SKEY *ikm_skey;
    EVP_SKEY *out_skey;
    EVP_SKEYMGMT *skeymgmt;
    int failed_tests;

    kdf = EVP_KDF_fetch(NULL, "HKDF", "provider=pkcs11");
    if (!kdf) {
        fprintf(stderr, "EVP_KDF_fetch for HKDF failed!\n");
        ossl_err_print();
        exit(EXIT_FAILURE);
    }

    skeymgmt = EVP_SKEYMGMT_fetch(NULL, "GENERIC-SECRET", "provider=pkcs11");
    if (!skeymgmt) {
        fprintf(stderr, "EVP_SKEYMGMT_fetch for GENERIC-SECRET failed!\n");
        ossl_err_print();
        EVP_KDF_free(kdf);
        exit(EXIT_FAILURE);
    }

    failed_tests = sizeof(tests) / sizeof(tests[0]);
    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        fprintf(stdout, "Testing HKDF: %s ... \n", tests[i].name);

        kctx = EVP_KDF_CTX_new(kdf);
        if (!kctx) {
            fprintf(stderr, "EVP_KDF_CTX_new failed for test '%s'!\n",
                    tests[i].name);
            ossl_err_print();
            exit(EXIT_FAILURE);
        }

        ikm_skey = import_skey(skeymgmt, tests[i].ikm, tests[i].ikm_len);
        if (EVP_KDF_CTX_set_SKEY(kctx, ikm_skey, NULL) <= 0) {
            fprintf(stderr, "EVP_KDF_CTX_set_SKEY failed for test '%s'!\n",
                    tests[i].name);
            ossl_err_print();
            EVP_SKEY_free(ikm_skey);
            exit(EXIT_FAILURE);
        }
        EVP_SKEY_free(ikm_skey);

        p = params;
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                (char *)tests[i].digest,
                                                strlen(tests[i].digest));
        *p++ = OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_MODE, (char *)tests[i].mode, strlen(tests[i].mode));
        if (tests[i].salt) {
            *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SALT, (void *)tests[i].salt, tests[i].salt_len);
        }
        if (tests[i].info) {
            *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_INFO, (void *)tests[i].info, tests[i].info_len);
        }
        *p = OSSL_PARAM_construct_end();

        out_skey = EVP_KDF_derive_SKEY(kctx, skeymgmt, "GENERIC-SECRET", NULL,
                                       tests[i].out_len, params);
        if (out_skey == NULL) {
            fprintf(stderr, "EVP_KDF_derive_SKEY failed for test '%s'!\n",
                    tests[i].name);
            ossl_err_print();
            exit(EXIT_FAILURE);
        }

        {
            const unsigned char *derived_key = NULL;
            size_t derived_key_len = 0;

            if (!EVP_SKEY_get0_raw_key(out_skey, &derived_key,
                                       &derived_key_len)) {
                fprintf(stderr, "EVP_SKEY_get0_raw_key failed for test '%s'!\n",
                        tests[i].name);
                ossl_err_print();
                continue;
            }

            if (derived_key_len != tests[i].out_len) {
                fprintf(stderr, "Output length mismatch for test '%s'!\n",
                        tests[i].name);
                EVP_SKEY_free(out_skey);
                continue;
            }

            if (memcmp(derived_key, tests[i].expected, tests[i].out_len) != 0) {
                fprintf(stderr, "Output mismatch for test '%s'!\n",
                        tests[i].name);
                continue;
            }
            EVP_SKEY_free(out_skey);
            failed_tests--;
        }

        EVP_KDF_CTX_free(kctx);
    }

    EVP_SKEYMGMT_free(skeymgmt);
    EVP_KDF_free(kdf);

    if (failed_tests != 0) {
        fprintf(stderr, "Failed %d tests!\n", failed_tests);
        exit(EXIT_FAILURE);
    }
}
#endif

int main(int argc, char *argv[])
{
#if defined(OSSL_FUNC_KDF_DERIVE_SKEY)
    test_hkdf();
#endif
    exit(EXIT_SUCCESS);
}
