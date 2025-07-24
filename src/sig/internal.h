/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _SIG_INTERNAL_H
#define _SIG_INTERNAL_H

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

    CK_RSA_PKCS_PSS_PARAMS pss_params;

    /* EdDSA param data */
    enum instance instance;
    CK_EDDSA_PARAMS eddsa_params;
    CK_BBOOL use_eddsa_params;

    /* ML-DSA param data */
    CK_ML_DSA_PARAMETER_SET_TYPE mldsa_paramset;
    CK_SIGN_ADDITIONAL_CONTEXT mldsa_params;

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

#endif /* _SIG_INTERNAL_H */
