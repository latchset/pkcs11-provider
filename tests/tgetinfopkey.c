#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    BIO *mem;
    int maxlen = 4000;
    char buf[maxlen];
    const char pub_part[] = "type=public";
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

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        fprintf(stderr, "Failed to init BIO\n");
        exit(EXIT_FAILURE);
    }

    ret = EVP_PKEY_print_public(mem, key, 0, NULL);
    if (ret != 1) {
        fprintf(stderr, "Failed to print public key\n");
        exit(EXIT_FAILURE);
    }

    memset(buf, 0x00, maxlen);
    BIO_read(mem, buf, maxlen);
    if (strstr(buf, pub_part) == NULL) {
        fprintf(stderr, "Incorrect information about the public key\n");
        exit(EXIT_FAILURE);
    }

    BIO_free(mem);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    exit(EXIT_SUCCESS);
}
