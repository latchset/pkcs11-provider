/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <openssl/prov_ssl.h>

/* NIST EC */
unsigned int p224_group_id = 0x0015;
unsigned int p224_secbits = 112;
int p224_mintls = TLS1_VERSION;
int p224_maxtls = TLS1_2_VERSION;
int p224_mindtls = DTLS1_VERSION;
int p224_maxdtls = DTLS1_2_VERSION;

unsigned int p256_group_id = 0x0017;
unsigned int p256_secbits = 128;
int p256_mintls = TLS1_VERSION;
int p256_maxtls = 0;
int p256_mindtls = DTLS1_VERSION;
int p256_maxdtls = 0;

unsigned int p384_group_id = 0x0018;
unsigned int p384_secbits = 192;
int p384_mintls = TLS1_VERSION;
int p384_maxtls = 0;
int p384_mindtls = DTLS1_VERSION;
int p384_maxdtls = 0;

unsigned int p521_group_id = 0x0019;
unsigned int p521_secbits = 256;
int p521_mintls = TLS1_VERSION;
int p521_maxtls = 0;
int p521_mindtls = DTLS1_VERSION;
int p521_maxdtls = 0;

/* DH */
unsigned int ffdhe2048_group_id = 0x0100;
unsigned int ffdhe2048_secbits = 112;
int ffdhe2048_mintls = TLS1_3_VERSION;
int ffdhe2048_maxtls = 0;
int ffdhe2048_mindtls = -1;
int ffdhe2048_maxdtls = -1;

unsigned int ffdhe3072_group_id = 0x0101;
unsigned int ffdhe3072_secbits = 128;
int ffdhe3072_mintls = TLS1_3_VERSION;
int ffdhe3072_maxtls = 0;
int ffdhe3072_mindtls = -1;
int ffdhe3072_maxdtls = -1;

unsigned int ffdhe4096_group_id = 0x0102;
unsigned int ffdhe4096_secbits = 128;
int ffdhe4096_mintls = TLS1_3_VERSION;
int ffdhe4096_maxtls = 0;
int ffdhe4096_mindtls = -1;
int ffdhe4096_maxdtls = -1;

unsigned int ffdhe6144_group_id = 0x0103;
unsigned int ffdhe6144_secbits = 128;
int ffdhe6144_mintls = TLS1_3_VERSION;
int ffdhe6144_maxtls = 0;
int ffdhe6144_mindtls = -1;
int ffdhe6144_maxdtls = -1;

unsigned int ffdhe8192_group_id = 0x0104;
unsigned int ffdhe8192_secbits = 192;
int ffdhe8192_mintls = TLS1_3_VERSION;
int ffdhe8192_maxtls = 0;
int ffdhe8192_mindtls = -1;
int ffdhe8192_maxdtls = -1;

#define TLS_PARAMS_ENTRY(name, realname, algorithm, group_id, secbits, mintls, \
                         maxtls, mindtls, maxdtls) \
    { \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, (void *)name, \
                               sizeof(name)), \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, \
                                   (void *)realname, sizeof(realname)), \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, \
                                   (void *)algorithm, sizeof(algorithm)), \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, &group_id), \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, \
                            &secbits), \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, &mintls), \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, &maxtls), \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, &mindtls), \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, &maxdtls), \
            OSSL_PARAM_END \
    }

struct {
    const char *name;
    const OSSL_PARAM list[10];
} tls_params[] = {
    {
        "secp224r1",
        TLS_PARAMS_ENTRY("secp224r1", "secp224r1", "EC", p224_group_id,
                         p224_secbits, p224_mintls, p224_maxtls, p224_mindtls,
                         p224_maxdtls),
    },
    /* alias */
    {
        "P-224",
        TLS_PARAMS_ENTRY("P-224", "secp224r1", "EC", p224_group_id,
                         p224_secbits, p224_mintls, p224_maxtls, p224_mindtls,
                         p224_maxdtls),
    },
    {
        "secp256r1",
        TLS_PARAMS_ENTRY("secp256r1", "secp256r1", "EC", p256_group_id,
                         p256_secbits, p256_mintls, p256_maxtls, p256_mindtls,
                         p256_maxdtls),
    },
    /* alias */
    {
        "P-256",
        TLS_PARAMS_ENTRY("P-256", "secp256r1", "EC", p256_group_id,
                         p256_secbits, p256_mintls, p256_maxtls, p256_mindtls,
                         p256_maxdtls),
    },
    {
        "secp384r1",
        TLS_PARAMS_ENTRY("secp384r1", "secp384r1", "EC", p384_group_id,
                         p384_secbits, p384_mintls, p384_maxtls, p384_mindtls,
                         p384_maxdtls),
    },
    /* alias */
    {
        "P-384",
        TLS_PARAMS_ENTRY("P-384", "secp384r1", "EC", p384_group_id,
                         p384_secbits, p384_mintls, p384_maxtls, p384_mindtls,
                         p384_maxdtls),
    },
    {
        "secp521r1",
        TLS_PARAMS_ENTRY("secp521r1", "secp521r1", "EC", p521_group_id,
                         p521_secbits, p521_mintls, p521_maxtls, p521_mindtls,
                         p521_maxdtls),
    },
    /* alias */
    {
        "P-521",
        TLS_PARAMS_ENTRY("P-521", "secp521r1", "EC", p521_group_id,
                         p521_secbits, p521_mintls, p521_maxtls, p521_mindtls,
                         p521_maxdtls),
    },
    {
        "ffdhe2048",
        TLS_PARAMS_ENTRY("ffdhe2048", "ffdhe2048", "DH", ffdhe2048_group_id,
                         ffdhe2048_secbits, ffdhe2048_mintls, ffdhe2048_maxtls,
                         ffdhe2048_mindtls, ffdhe2048_maxdtls),
    },
    {
        "ffdhe3072",
        TLS_PARAMS_ENTRY("ffdhe3072", "ffdhe3072", "DH", ffdhe3072_group_id,
                         ffdhe3072_secbits, ffdhe3072_mintls, ffdhe3072_maxtls,
                         ffdhe3072_mindtls, ffdhe3072_maxdtls),
    },
    {
        "ffdhe4096",
        TLS_PARAMS_ENTRY("ffdhe4096", "ffdhe4096", "DH", ffdhe4096_group_id,
                         ffdhe4096_secbits, ffdhe4096_mintls, ffdhe4096_maxtls,
                         ffdhe4096_mindtls, ffdhe4096_maxdtls),
    },
    {
        "ffdhe6144",
        TLS_PARAMS_ENTRY("ffdhe6144", "ffdhe6144", "DH", ffdhe6144_group_id,
                         ffdhe6144_secbits, ffdhe6144_mintls, ffdhe6144_maxtls,
                         ffdhe6144_mindtls, ffdhe6144_maxdtls),
    },
    {
        "ffdhe8192",
        TLS_PARAMS_ENTRY("ffdhe8192", "ffdhe8192", "DH", ffdhe8192_group_id,
                         ffdhe8192_secbits, ffdhe8192_mintls, ffdhe8192_maxtls,
                         ffdhe8192_mindtls, ffdhe8192_maxdtls),
    },
};

int tls_group_capabilities(OSSL_CALLBACK *cb, void *arg)
{
    for (size_t i = 0; i < sizeof(tls_params) / sizeof(*tls_params); i++) {
        int ret = cb(tls_params[i].list, arg);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    return RET_OSSL_OK;
}
