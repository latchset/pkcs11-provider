/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#define EXIT_TEST_SKIPPED 77

int main(int argc, char *argv[])
{
    unsigned char osslout[EVP_MAX_MD_SIZE];
    unsigned char pk11out[EVP_MAX_MD_SIZE];
    unsigned int ossllen;
    unsigned int pk11len;
    bool pk11_tested = false;
    const char *propq = "provider=pkcs11";
    const char *digests[] = { "sha1",       "sha224",   "sha256",
                              "sha384",     "sha512",   "sha512-224",
                              "sha512-256", "sha3-224", "sha3-256",
                              "sha3-384",   "sha3-512", NULL };
    const char *data = "Digest This!";
    int ret;

    for (int i = 0; digests[i] != NULL; i++) {
        const char *digest = digests[i];
        const OSSL_PROVIDER *pk11prov;
        const char *provname;
        EVP_MD *osslmd;
        EVP_MD *pk11md;

        osslmd = EVP_MD_fetch(NULL, digest, NULL);
        if (!osslmd) {
            fprintf(stderr, "%s: Failed to fetch openssl EVP_MD\n", digest);
            exit(EXIT_FAILURE);
        }
        pk11md = EVP_MD_fetch(NULL, digest, propq);
        if (!pk11md) {
            fprintf(stderr, "%s: Unsupported by pkcs11 token\n", digest);
            EVP_MD_free(osslmd);
            continue;
        }
        pk11prov = EVP_MD_get0_provider(pk11md);
        provname = OSSL_PROVIDER_get0_name(pk11prov);

        if (strcmp(provname, "pkcs11") != 0) {
            fprintf(stderr, "%s: Not a pkcs11 method, provider=%s\n", digest,
                    provname);
            EVP_MD_free(osslmd);
            EVP_MD_free(pk11md);
            continue;
        }

        ret = EVP_Digest(data, sizeof(data), osslout, &ossllen, osslmd, NULL);
        if (ret != 1) {
            fprintf(stderr, "%s: Failed to generate openssl digest\n", digest);
            exit(EXIT_FAILURE);
        }

        ret = EVP_Digest(data, sizeof(data), pk11out, &pk11len, pk11md, NULL);
        if (ret != 1) {
            fprintf(stderr, "%s: Failed to generate pkcs11 digest\n", digest);
            exit(EXIT_FAILURE);
        }

        if (ossllen != pk11len || memcmp(osslout, pk11out, ossllen) != 0) {
            fprintf(stderr, "%s: Digests do not match!\n", digest);
            exit(EXIT_FAILURE);
        }

        pk11_tested = true;

        EVP_MD_free(osslmd);
        EVP_MD_free(pk11md);
    }

    if (!pk11_tested) {
        fprintf(stderr, "No digest available for testing pkcs11 provider\n");
        exit(EXIT_TEST_SKIPPED);
    }

    exit(EXIT_SUCCESS);
}
