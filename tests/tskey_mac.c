/* Copyright 2026 NXP
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

#if defined(OSSL_FUNC_MAC_INIT_SKEY)

struct hmac_test_vector {
    const char *name;
    const char *digest;
    const unsigned char *ikm;
    size_t ikm_len;
    const unsigned char *input;
    size_t input_len;

    const unsigned char *expected;
    size_t out_len;
};

static const unsigned char ikm_tc1[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
};

static const unsigned char input_tc1[] = {
    0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65,
};

unsigned char expected_sha224[] = {
    0x89, 0x6f, 0xb1, 0x12, 0x8a, 0xbb, 0xdf, 0x19, 0x68, 0x32,
    0x10, 0x7c, 0xd4, 0x9d, 0xf3, 0x3f, 0x47, 0xb4, 0xb1, 0x16,
    0x99, 0x12, 0xba, 0x4f, 0x53, 0x68, 0x4b, 0x22,
};

static const unsigned char expected_sha256[] = {
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf,
    0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83,
    0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
};

static const unsigned char expected_sha384[] = {
    0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62, 0x6b, 0x08, 0x25, 0xf4,
    0xab, 0x46, 0x90, 0x7f, 0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6,
    0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb, 0xc5, 0x9c, 0xfa, 0xea, 0x9e, 0xa9,
    0x07, 0x6e, 0xde, 0x7f, 0x4a, 0xf1, 0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6
};

static const unsigned char expected_sha512[] = {
    0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4,
    0x24, 0x1a, 0x1d, 0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e,
    0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde, 0xda,
    0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b, 0x27, 0x4e,
    0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1,
    0x70, 0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54
};

static struct hmac_test_vector hmac_tests[] = {
    { "HMAC", "SHA224", ikm_tc1, sizeof(ikm_tc1), input_tc1, sizeof(input_tc1),
      expected_sha224 },
    { "HMAC", "SHA256", ikm_tc1, sizeof(ikm_tc1), input_tc1, sizeof(input_tc1),
      expected_sha256 },
    { "HMAC", "SHA384", ikm_tc1, sizeof(ikm_tc1), input_tc1, sizeof(input_tc1),
      expected_sha384 },
    { "HMAC", "SHA512", ikm_tc1, sizeof(ikm_tc1), input_tc1, sizeof(input_tc1),
      expected_sha512 },
};

static int test_mac_sign(struct hmac_test_vector *tv, bool skey)
{
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    EVP_SKEY *skey_obj = NULL;
    int status = EXIT_FAILURE;

    unsigned char output[EVP_MAX_MD_SIZE] = { 0 };

    mac = EVP_MAC_fetch(NULL, tv->name, "provider=pkcs11");
    if (!mac) {
        fprintf(stderr, "EVP_MAC_fetch() failed\n");
        goto end;
    }
    mctx = EVP_MAC_CTX_new(mac);
    if (!mctx) {
        fprintf(stderr, "EVP_MAC_CTX_new() failed\n");
        goto end;
    }

    OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string(
                                OSSL_MAC_PARAM_DIGEST, (char *)tv->digest, 0),
                            OSSL_PARAM_construct_end() };

    if (skey) {
        skey_obj = EVP_SKEY_import_raw_key(NULL, "GENERIC-SECRET",
                                           (unsigned char *)tv->ikm,
                                           tv->ikm_len, "provider=pkcs11");
        if (!skey_obj) {
            fprintf(stderr, "EVP_SKEY_import_raw_key failed!\n");
            goto end;
        }
        if (!EVP_MAC_init_SKEY(mctx, skey_obj, params)) {
            fprintf(stderr, "EVP_MAC_init_SKEY() failed\n");
            goto end;
        };
    } else {
        if (!EVP_MAC_init(mctx, tv->ikm, tv->ikm_len, params)) {
            fprintf(stderr, "EVP_MAC_init() failed\n");
            goto end;
        };
    }

    if (!EVP_MAC_update(mctx, tv->input, tv->input_len)
        || !EVP_MAC_final(mctx, output, &tv->out_len, sizeof(output))) {
        fprintf(stderr, "EVP_MAC_update/final() failed\n");
        goto end;
    }

    if (memcmp(output, tv->expected, tv->out_len) != 0) {
        fprintf(stderr, "Output mismatch for %s %s!\n", tv->name, tv->digest);
        goto end;
    }

    fprintf(stderr, "test_mac_sign %s: OK!\n", (skey) ? "SKEY" : "Legacy");
    status = EXIT_SUCCESS;

end:
    if (skey_obj) {
        EVP_SKEY_free(skey_obj);
    }
    if (mctx) {
        EVP_MAC_CTX_free(mctx);
    }
    if (mac) {
        EVP_MAC_free(mac);
    }

    return status;
}
#endif

int main(int argc, char *argv[])
{
    int status = EXIT_SUCCESS;

#if defined(OSSL_FUNC_MAC_INIT_SKEY)
    for (size_t i = 0; i < sizeof(hmac_tests) / sizeof(hmac_tests[0]); i++) {
        status = test_mac_sign(&hmac_tests[i], true);
        if (status == EXIT_FAILURE) {
            return status;
        }
        status = test_mac_sign(&hmac_tests[i], false);
        if (status == EXIT_FAILURE) {
            return status;
        }
    }
#endif

    return status;
}
