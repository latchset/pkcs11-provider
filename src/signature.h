/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _SIGNATURE_H
#define _SIGNATURE_H

/* common sig functions */
#define DISPATCH_SIG_FN(name) DECL_DISPATCH_FUNC(signature, p11prov_sig, name)
#define DISPATCH_SIG_ELEM(prefix, NAME, name) \
    { \
        OSSL_FUNC_SIGNATURE_##NAME, (void (*)(void))p11prov_##prefix##_##name \
    }

/* rsa sig functions */
#define DISPATCH_RSASIG_FN(name) \
    DECL_DISPATCH_FUNC(signature, p11prov_rsasig, name)
extern const OSSL_DISPATCH p11prov_rsa_signature_functions[];
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
extern const OSSL_DISPATCH p11prov_rsa_sha1_signature_functions[];
extern const OSSL_DISPATCH p11prov_rsa_sha224_signature_functions[];
extern const OSSL_DISPATCH p11prov_rsa_sha256_signature_functions[];
extern const OSSL_DISPATCH p11prov_rsa_sha384_signature_functions[];
extern const OSSL_DISPATCH p11prov_rsa_sha512_signature_functions[];
extern const OSSL_DISPATCH p11prov_rsa_sha3_224_signature_functions[];
extern const OSSL_DISPATCH p11prov_rsa_sha3_256_signature_functions[];
extern const OSSL_DISPATCH p11prov_rsa_sha3_384_signature_functions[];
extern const OSSL_DISPATCH p11prov_rsa_sha3_512_signature_functions[];
#endif

/* ecdsa sig functions */
#define DISPATCH_ECDSA_FN(name) \
    DECL_DISPATCH_FUNC(signature, p11prov_ecdsa, name)
extern const OSSL_DISPATCH p11prov_ecdsa_signature_functions[];
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
extern const OSSL_DISPATCH p11prov_ecdsa_sha1_signature_functions[];
extern const OSSL_DISPATCH p11prov_ecdsa_sha224_signature_functions[];
extern const OSSL_DISPATCH p11prov_ecdsa_sha256_signature_functions[];
extern const OSSL_DISPATCH p11prov_ecdsa_sha384_signature_functions[];
extern const OSSL_DISPATCH p11prov_ecdsa_sha512_signature_functions[];
extern const OSSL_DISPATCH p11prov_ecdsa_sha3_224_signature_functions[];
extern const OSSL_DISPATCH p11prov_ecdsa_sha3_256_signature_functions[];
extern const OSSL_DISPATCH p11prov_ecdsa_sha3_384_signature_functions[];
extern const OSSL_DISPATCH p11prov_ecdsa_sha3_512_signature_functions[];
#endif

/* eddsa sig functions */
#define DISPATCH_EDDSA_FN(name) \
    DECL_DISPATCH_FUNC(signature, p11prov_eddsa, name)
extern const OSSL_DISPATCH p11prov_eddsa_signature_functions[];

CK_MECHANISM_TYPE p11prov_digest_to_rsapss_mech(CK_MECHANISM_TYPE digest);

#endif /* _SIGNATURE_H */
