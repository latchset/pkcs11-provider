#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
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

// TODO: add paddings
int main(int argc, char *argv[])
{
    char *label;
    unsigned char id[16];
    char idhex[16 * 3 + 1];
    char *uri;
    size_t rsa_bits = 1024;
    const char *key_usage = "digitalSignature";
    OSSL_PARAM params[4];
    int miniid;
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key = NULL;
    // SHA-256 hash of "Plaintext Data"
    const unsigned char md[] = {
        0xac, 0x26, 0x5c, 0x10, 0x09, 0xf8, 0xf4, 0xdf, 0x05, 0xf4, 0x25,
        0x18, 0x86, 0x92, 0x33, 0x5c, 0x2f, 0x9e, 0x9a, 0xe3, 0xdb, 0x44,
        0xc4, 0xa9, 0x12, 0xfd, 0xa5, 0x07, 0x7e, 0xd4, 0xe1, 0x76
    };
    unsigned char *sig;
    size_t siglen;
    int ret;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=pkcs11");
    if (ctx == NULL) {
        fprintf(stderr, "Failed to init PKEY context for generate\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_keygen_init(ctx);
    if (ret != 1) {
        fprintf(stderr, "Failed to init keygen\n");
        exit(EXIT_FAILURE);
    }

    ret = RAND_bytes(id, 16);
    if (ret != 1) {
        fprintf(stderr, "Failed to generate key id\n");
        exit(EXIT_FAILURE);
    }
    miniid = (id[0] << 24) + (id[1] << 16) + (id[2] << 8) + id[3];
    ret = asprintf(&label, "Test-RSA-gen-%08x", miniid);
    if (ret == -1) {
        fprintf(stderr, "Failed to make label\n");
        exit(EXIT_FAILURE);
    }
    hexify(idhex, id, 16);
    ret = asprintf(&uri, "pkcs11:object=%s;id=%s", label, idhex);
    if (ret == -1) {
        fprintf(stderr, "Failed to compose PKCS#11 URI\n");
        exit(EXIT_FAILURE);
    }
    params[0] = OSSL_PARAM_construct_utf8_string("pkcs11_uri", uri, 0);
    params[1] = OSSL_PARAM_construct_utf8_string("pkcs11_key_usage",
                                                 (char *)key_usage, 0);
    params[2] =
        OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_BITS, &rsa_bits);
    params[3] = OSSL_PARAM_construct_end();
    ret = EVP_PKEY_CTX_set_params(ctx, params);
    if (ret != 1) {
        fprintf(stderr, "Failed to set params\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_generate(ctx, &key);
    if (ret != 1) {
        fprintf(stderr, "Failed to generate key\n");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=pkcs11");
    if (ctx == NULL) {
        fprintf(stderr, "Failed to init PKEY context for sign\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_sign_init(ctx);
    if (ret != 1) {
        fprintf(stderr, "Failed to init sign\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_sign(ctx, NULL, &siglen, md, sizeof(md) / sizeof(*md));
    if (ret != 1) {
        fprintf(stderr, "Failed to determine buffer length\n");
        exit(EXIT_FAILURE);
    }
    sig = OPENSSL_malloc(siglen);
    if (sig == NULL) {
        fprintf(stderr, "Failed to malloc memory for buffer\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_sign(ctx, sig, &siglen, md, sizeof(md) / sizeof(*md));
    if (ret != 1) {
        fprintf(stderr, "Failed to sign\n");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=pkcs11");
    if (ctx == NULL) {
        fprintf(stderr, "Failed to init PKEY context for verify\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_verify_init(ctx);
    if (ret != 1) {
        fprintf(stderr, "Failed to init verify\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_verify(ctx, sig, siglen, md, sizeof(md) / sizeof(*md));
    if (ret != 1) {
        fprintf(stderr, "Failed to verify\n");
        exit(EXIT_FAILURE);
    }

    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    exit(EXIT_SUCCESS);
}
