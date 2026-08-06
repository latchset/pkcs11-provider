/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _SIG_INTERNAL_H
#define _SIG_INTERNAL_H

#include "sig/signature.h"

struct p11prov_sig_ctx;
typedef struct p11prov_sig_ctx P11PROV_SIG_CTX;

enum instance {
    ED_Unset = 0,
    ED_25519,
    ED_25519_ph,
    ED_25519_ctx,
    ED_448,
    ED_448_ph,
};

typedef CK_RV(p11prov_sig_operate_t)(P11PROV_SIG_CTX *sigctx,
                                     unsigned char *sig, size_t *siglen,
                                     size_t sigsize, unsigned char *tbs,
                                     size_t tbslen);

struct p11prov_sig_ctx {
    P11PROV_CTX *provctx;
    char *properties;

    P11PROV_OBJ *key;

    CK_MECHANISM_TYPE mechtype;
    CK_MECHANISM_TYPE digest;

    CK_FLAGS operation;
    P11PROV_SESSION *session;
    enum { SESS_UNUSED = 0, SESS_INITIALIZED, SESS_FINALIZED } session_state;

    CK_RSA_PKCS_PSS_PARAMS pss_params;

    /* EdDSA param data */
    enum instance instance;
    CK_EDDSA_PARAMS eddsa_params;
    CK_BBOOL use_eddsa_params;

    /* ML-DSA & SLH-DSA param data */
    CK_ML_DSA_PARAMETER_SET_TYPE mldsa_paramset;
    CK_SLH_DSA_PARAMETER_SET_TYPE slhdsa_paramset;
    CK_SIGN_ADDITIONAL_CONTEXT additional_context;

    /* Signature to be verified, used by verify_message_final() */
    unsigned char *signature;
    size_t signature_len;

    /* Whether this is a digest operation */
    bool digest_op;

    /* the mechanism structure passed to the driver */
    CK_MECHANISM mechanism;

    /* If not NULL this indicates that the requested mechanism to calculate
     * digest+signature (C_SignUpdate/C_VerifyUpdate) is not supported by
     * the token, so we try to fall back to calculating the digest
     * separately and then applying a raw signature on the result. */
    EVP_MD_CTX *fallback_digest;
    p11prov_sig_operate_t *fallback_operate;

    /* Whether C_VerifySignature* APIs are in use */
    bool verify_signature;
};

P11PROV_SIG_CTX *p11prov_sig_newctx(P11PROV_CTX *ctx, CK_MECHANISM_TYPE type,
                                    const char *properties);
void *p11prov_sig_dupctx(void *ctx);
void p11prov_sig_freectx(void *ctx);

CK_RV p11prov_sig_op_init(void *ctx, void *provkey, CK_FLAGS operation,
                          const char *digest);
CK_RV p11prov_sig_operate(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                          size_t *siglen, size_t sigsize, unsigned char *tbs,
                          size_t tbslen);
int p11prov_sig_digest_update(P11PROV_SIG_CTX *sigctx, unsigned char *data,
                              size_t datalen);
int p11prov_sig_digest_final(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                             size_t *siglen, size_t sigsize);

#define DER_SEQUENCE 0x30
#define DER_OBJECT 0x06
#define DER_NULL 0x05
#define DER_OCTET_STRING 0x04
#define DER_INTEGER 0x02

/* iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) */
#define DER_RSADSI_PKCS1 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01
#define DER_RSADSI_PKCS1_LEN 0x08

/* iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4) */
#define DER_ANSIX962_SIG 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04
#define DER_ANSIX962_SIG_LEN 0x06

/* ... ansi-x962(10045) signatures(4) ecdsa-with-SHA2(3) */
#define DER_ANSIX962_SHA2_SIG DER_ANSIX962_SIG, 0x03
#define DER_ANSIX962_SHA2_SIG_LEN (DER_ANSIX962_SIG_LEN + 1)

/* joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3)
 * nistAlgorithms(4) */
#define DER_NIST_ALGS 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04
#define DER_NIST_ALGS_LEN 0x07

/* ... csor(3) nistAlgorithms(4) hashalgs(2) */
#define DER_NIST_HASHALGS DER_NIST_ALGS, 0x02
#define DER_NIST_HASHALGS_LEN (DER_NIST_ALGS_LEN + 1)

/* ... csor(3) nistAlgorithms(4) sigAlgs(3) */
#define DER_NIST_SIGALGS DER_NIST_ALGS, 0x03
#define DER_NIST_SIGALGS_LEN (DER_NIST_ALGS_LEN + 1)

#define DISPATCH_SIG_ELEM(prefix, NAME, name) \
    { OSSL_FUNC_SIGNATURE_##NAME, (void (*)(void))p11prov_##prefix##_##name }

extern const OSSL_DISPATCH p11prov_rsa_functions[];
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
extern const OSSL_DISPATCH p11prov_rsa_sha1_functions[];
extern const OSSL_DISPATCH p11prov_rsa_sha224_functions[];
extern const OSSL_DISPATCH p11prov_rsa_sha256_functions[];
extern const OSSL_DISPATCH p11prov_rsa_sha384_functions[];
extern const OSSL_DISPATCH p11prov_rsa_sha512_functions[];
extern const OSSL_DISPATCH p11prov_rsa_sha3_224_functions[];
extern const OSSL_DISPATCH p11prov_rsa_sha3_256_functions[];
extern const OSSL_DISPATCH p11prov_rsa_sha3_384_functions[];
extern const OSSL_DISPATCH p11prov_rsa_sha3_512_functions[];
#endif
extern const OSSL_DISPATCH p11prov_ecdsa_functions[];
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
extern const OSSL_DISPATCH p11prov_ecdsa_sha1_functions[];
extern const OSSL_DISPATCH p11prov_ecdsa_sha224_functions[];
extern const OSSL_DISPATCH p11prov_ecdsa_sha256_functions[];
extern const OSSL_DISPATCH p11prov_ecdsa_sha384_functions[];
extern const OSSL_DISPATCH p11prov_ecdsa_sha512_functions[];
extern const OSSL_DISPATCH p11prov_ecdsa_sha3_224_functions[];
extern const OSSL_DISPATCH p11prov_ecdsa_sha3_256_functions[];
extern const OSSL_DISPATCH p11prov_ecdsa_sha3_384_functions[];
extern const OSSL_DISPATCH p11prov_ecdsa_sha3_512_functions[];
#endif
extern const OSSL_DISPATCH p11prov_ed25519_functions[];
extern const OSSL_DISPATCH p11prov_ed448_functions[];
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
extern const OSSL_DISPATCH p11prov_ed25519ph_functions[];
extern const OSSL_DISPATCH p11prov_ed25519ctx_functions[];
extern const OSSL_DISPATCH p11prov_ed448ph_functions[];
#endif
extern const OSSL_DISPATCH p11prov_mldsa_44_functions[];
extern const OSSL_DISPATCH p11prov_mldsa_65_functions[];
extern const OSSL_DISPATCH p11prov_mldsa_87_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_sha2_128s_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_shake_128s_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_sha2_128f_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_shake_128f_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_sha2_192s_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_shake_192s_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_sha2_192f_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_shake_192f_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_sha2_256s_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_shake_256s_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_sha2_256f_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_shake_256f_functions[];

#endif /* _SIG_INTERNAL_H */
