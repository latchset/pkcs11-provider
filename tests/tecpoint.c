/* Copyright (C) 2026 Mounir IDRASSI
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>

#include "../src/obj/ec_point.h"

static int failures;

static void expect_success(const char *name, CK_KEY_TYPE key_type,
                           CK_ULONG expected_size, const unsigned char *input,
                           size_t input_len, const unsigned char *expected,
                           size_t expected_len)
{
    CK_ATTRIBUTE attr = { CKA_EC_POINT, (void *)input, input_len };
    unsigned char *decoded = NULL;
    size_t decoded_len = 0;
    CK_RV ret;

    ret = p11prov_decode_ec_point_value(key_type, expected_size, &attr,
                                        &decoded, &decoded_len);
    if (ret != CKR_OK) {
        fprintf(stderr, "%s: decode failed with 0x%lx\n", name, ret);
        failures++;
        return;
    }
    if (decoded_len != expected_len
        || memcmp(decoded, expected, expected_len) != 0) {
        fprintf(stderr, "%s: decoded value does not match\n", name);
        failures++;
    }
    OPENSSL_free(decoded);
}

static void expect_failure(const char *name, CK_KEY_TYPE key_type,
                           CK_ULONG expected_size, const unsigned char *input,
                           size_t input_len, CK_RV expected_ret)
{
    CK_ATTRIBUTE attr = { CKA_EC_POINT, (void *)input, input_len };
    unsigned char *decoded = NULL;
    size_t decoded_len = 0;
    CK_RV ret;

    ret = p11prov_decode_ec_point_value(key_type, expected_size, &attr,
                                        &decoded, &decoded_len);
    if (ret != expected_ret || decoded != NULL || decoded_len != 0) {
        fprintf(stderr, "%s: got 0x%lx, expected 0x%lx\n", name, ret,
                expected_ret);
        failures++;
    }
    OPENSSL_free(decoded);
}

int main(void)
{
    /* Public keys generated from deterministic private-key test vectors. */
    const unsigned char raw_x25519[] = {
        0x04, 0x1e, 0xf8, 0x1d, 0x4b, 0xf2, 0x30, 0xd8, 0xa8, 0x31, 0x9a,
        0x07, 0x50, 0x62, 0xbb, 0xeb, 0x66, 0x6b, 0xe7, 0x3c, 0x7c, 0xac,
        0x92, 0x05, 0x43, 0xd8, 0x58, 0x01, 0x95, 0xa9, 0xa6, 0x35,
    };
    const unsigned char raw_ed25519[] = {
        0x04, 0x1e, 0x8c, 0xf3, 0xd8, 0xe3, 0x29, 0xb7, 0xed, 0x76, 0x6f,
        0x98, 0x7e, 0x64, 0x5e, 0x49, 0xb5, 0xf7, 0xdc, 0x8e, 0x3f, 0xb6,
        0x60, 0x63, 0xe7, 0xd3, 0xfd, 0x57, 0x97, 0xaa, 0xb1, 0x07,
    };
    unsigned char der_wrapped[34];
    unsigned char der_trailing[35];
    unsigned char der_short[33];
    const unsigned char traditional_der[] = { 0x04, 0x03, 0x04, 0x01, 0x02 };
    const unsigned char traditional_point[] = { 0x04, 0x01, 0x02 };
    const unsigned char traditional_raw[] = { 0x05, 0x01, 0x02 };

    /* Each raw key is also a complete 30-byte DER OCTET STRING. */
    expect_success("raw X25519 DER collision", CKK_EC_MONTGOMERY,
                   sizeof(raw_x25519), raw_x25519, sizeof(raw_x25519),
                   raw_x25519, sizeof(raw_x25519));
    expect_success("raw Ed25519 DER collision", CKK_EC_EDWARDS,
                   sizeof(raw_ed25519), raw_ed25519, sizeof(raw_ed25519),
                   raw_ed25519, sizeof(raw_ed25519));

    der_wrapped[0] = 0x04;
    der_wrapped[1] = sizeof(raw_x25519);
    memcpy(&der_wrapped[2], raw_x25519, sizeof(raw_x25519));
    expect_success("DER OCTET STRING-wrapped X25519", CKK_EC_MONTGOMERY,
                   sizeof(raw_x25519), der_wrapped, sizeof(der_wrapped),
                   raw_x25519, sizeof(raw_x25519));

    memcpy(der_trailing, der_wrapped, sizeof(der_wrapped));
    der_trailing[sizeof(der_trailing) - 1] = 0;
    expect_failure("DER with trailing data", CKK_EC_MONTGOMERY,
                   sizeof(raw_x25519), der_trailing, sizeof(der_trailing),
                   CKR_KEY_INDIGESTIBLE);

    der_short[0] = 0x04;
    der_short[1] = sizeof(raw_x25519) - 1;
    memcpy(&der_short[2], raw_x25519, sizeof(raw_x25519) - 1);
    expect_failure("DER with short point", CKK_EC_MONTGOMERY,
                   sizeof(raw_x25519), der_short, sizeof(der_short),
                   CKR_KEY_INDIGESTIBLE);

    expect_failure("unsupported key type", CKK_RSA, sizeof(raw_x25519),
                   raw_x25519, sizeof(raw_x25519), CKR_KEY_TYPE_INCONSISTENT);

    expect_success("traditional EC DER", CKK_EC, sizeof(traditional_point),
                   traditional_der, sizeof(traditional_der), traditional_point,
                   sizeof(traditional_point));
    expect_failure("traditional EC raw", CKK_EC, sizeof(traditional_raw),
                   traditional_raw, sizeof(traditional_raw),
                   CKR_KEY_INDIGESTIBLE);

    return failures == 0 ? 0 : 1;
}
