/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _DIGESTS_H
#define _DIGESTS_H

/* Digests */
#define DISPATCH_DIGEST_COMMON_FN(name) \
    DECL_DISPATCH_FUNC(digest, p11prov_digest, name)
#define DISPATCH_DIGEST_COMMON(NAME, name) \
    { \
        OSSL_FUNC_DIGEST_##NAME, (void (*)(void))p11prov_digest_##name \
    }
#define DISPATCH_DIGEST_FN(type, name) \
    DECL_DISPATCH_FUNC(digest, p11prov_##type, name)
#define DISPATCH_DIGEST_ELEM(digest, NAME, name) \
    { \
        OSSL_FUNC_DIGEST_##NAME, (void (*)(void))p11prov_##digest##_##name \
    }
extern const OSSL_DISPATCH p11prov_sha1_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha224_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha256_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha384_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha512_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha512_224_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha512_256_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha3_224_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha3_256_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha3_384_digest_functions[];
extern const OSSL_DISPATCH p11prov_sha3_512_digest_functions[];

#define P11PROV_NAMES_SHA1 "SHA1:SHA-1:SSL3-SHA1:1.3.14.3.2.26"
#define P11PROV_DESCS_SHA1 "PKCS11 SHA1 Implementation"
#define P11PROV_NAMES_SHA2_224 "SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4"
#define P11PROV_DESCS_SHA2_224 "PKCS11 SHA2-224 Implementation"
#define P11PROV_NAMES_SHA2_256 "SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1"
#define P11PROV_DESCS_SHA2_256 "PKCS11 SHA2-256 Implementation"
#define P11PROV_NAMES_SHA2_384 "SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2"
#define P11PROV_DESCS_SHA2_384 "PKCS11 SHA2-384 Implementation"
#define P11PROV_NAMES_SHA2_512 "SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3"
#define P11PROV_DESCS_SHA2_512 "PKCS11 SHA2-512 Implementation"
#define P11PROV_NAMES_SHA2_512_224 \
    "SHA2-512/224:SHA-512/224:SHA512-224:2.16.840.1.101.3.4.2.5"
#define P11PROV_DESCS_SHA2_512_224 "PKCS11 SHA2-512/224 Implementation"
#define P11PROV_NAMES_SHA2_512_256 \
    "SHA2-512/256:SHA-512/256:SHA512-256:2.16.840.1.101.3.4.2.6"
#define P11PROV_DESCS_SHA2_512_256 "PKCS11 SHA2-512/224 Implementation"
#define P11PROV_NAMES_SHA3_224 "SHA3-224:2.16.840.1.101.3.4.2.7"
#define P11PROV_DESCS_SHA3_224 "PKCS11 SHA3-224 Implementation"
#define P11PROV_NAMES_SHA3_256 "SHA3-256:2.16.840.1.101.3.4.2.8"
#define P11PROV_DESCS_SHA3_256 "PKCS11 SHA3-256 Implementation"
#define P11PROV_NAMES_SHA3_384 "SHA3-384:2.16.840.1.101.3.4.2.9"
#define P11PROV_DESCS_SHA3_384 "PKCS11 SHA3-384 Implementation"
#define P11PROV_NAMES_SHA3_512 "SHA3-512:2.16.840.1.101.3.4.2.10"
#define P11PROV_DESCS_SHA3_512 "PKCS11 SHA3-512 Implementation"

CK_RV p11prov_digest_get_block_size(CK_MECHANISM_TYPE digest,
                                    size_t *block_size);
CK_RV p11prov_digest_get_digest_size(CK_MECHANISM_TYPE digest,
                                     size_t *digest_size);
CK_RV p11prov_digest_get_name(CK_MECHANISM_TYPE digest, const char **name);
CK_RV p11prov_digest_get_by_name(const char *name, CK_MECHANISM_TYPE *digest);

#endif /* _DIGESTS_H */
