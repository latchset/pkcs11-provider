/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/ec.h"
#include "openssl/sha.h"

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
    CK_EDDSA_PARAMS eddsa_params;
    CK_BBOOL use_eddsa_params;

    /* If not NULL this indicates that the requested mechanism to calculate
     * digest+signature (C_SignUpdate/C_VerifyUpdate) is not supported by
     * the token, so we try to fall back to calculating the digest
     * separately and then applying a raw signature on the result. */
    EVP_MD_CTX *mechanism_fallback;
};
typedef struct p11prov_sig_ctx P11PROV_SIG_CTX;

DISPATCH_SIG_FN(freectx);
DISPATCH_SIG_FN(dupctx);

static P11PROV_SIG_CTX *p11prov_sig_newctx(P11PROV_CTX *ctx,
                                           CK_MECHANISM_TYPE type,
                                           const char *properties)
{
    P11PROV_SIG_CTX *sigctx;

    sigctx = OPENSSL_zalloc(sizeof(P11PROV_SIG_CTX));
    if (sigctx == NULL) {
        return NULL;
    }

    sigctx->provctx = ctx;

    if (properties) {
        sigctx->properties = OPENSSL_strdup(properties);
        if (sigctx->properties == NULL) {
            OPENSSL_free(sigctx);
            return NULL;
        }
    }

    sigctx->mechtype = type;

    return sigctx;
}

static void *p11prov_sig_dupctx(void *ctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    P11PROV_SIG_CTX *newctx;
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    CK_BYTE_PTR state = NULL;
    CK_ULONG state_len;
    bool reqlogin = false;
    CK_RV ret;

    if (sigctx == NULL) {
        return NULL;
    }

    P11PROV_debug("Duplicating context %p", ctx);

    switch (sigctx->operation) {
    case CKF_SIGN:
        reqlogin = true;
        /* fallthrough */
    case CKF_VERIFY:
        slotid = p11prov_obj_get_slotid(sigctx->key);
        handle = p11prov_obj_get_handle(sigctx->key);
        break;
    default:
        return NULL;
    }

    newctx = p11prov_sig_newctx(sigctx->provctx, sigctx->mechtype,
                                sigctx->properties);
    if (newctx == NULL) {
        return NULL;
    }

    newctx->key = p11prov_obj_ref(sigctx->key);
    newctx->mechtype = sigctx->mechtype;
    newctx->digest = sigctx->digest;
    newctx->pss_params = sigctx->pss_params;
    newctx->operation = sigctx->operation;

    newctx->eddsa_params = sigctx->eddsa_params;
    if (sigctx->eddsa_params.pContextData) {
        newctx->eddsa_params.pContextData =
            OPENSSL_memdup(sigctx->eddsa_params.pContextData,
                           sigctx->eddsa_params.ulContextDataLen);
    }
    newctx->use_eddsa_params = sigctx->use_eddsa_params;

    if (sigctx->mechanism_fallback) {
        int err;
        newctx->mechanism_fallback = EVP_MD_CTX_new();
        if (!newctx->mechanism_fallback) {
            p11prov_sig_freectx(newctx);
            return NULL;
        }
        err = EVP_MD_CTX_copy_ex(newctx->mechanism_fallback,
                                 sigctx->mechanism_fallback);
        if (err != RET_OSSL_OK) {
            p11prov_sig_freectx(newctx);
            return NULL;
        }
    }

    if (sigctx->session == NULL) {
        return newctx;
    }

    /* This is not really funny. OpenSSL by default assumes contexts with
     * operations in flight can be easily duplicated, with all the
     * cryptographic status and then both contexts can keep going
     * independently. We'll try here, but on failure we just 'move' the
     * session to the new context (because that's what OpenSSL seem to
     * prefer to use after duplication) and hope for the best. */

    newctx->session = sigctx->session;
    sigctx->session = NULL;

    if (slotid != CK_UNAVAILABLE_INFORMATION && handle != CK_INVALID_HANDLE) {
        CK_SESSION_HANDLE newsess = p11prov_session_handle(newctx->session);
        CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;

        /* NOTE: most tokens will probably return errors trying to do this on
         * sign sessions. If GetOperationState fails we don't try to duplicate
         * the context and just return. */
        ret = p11prov_GetOperationState(sigctx->provctx, newsess, NULL_PTR,
                                        &state_len);
        if (ret != CKR_OK) {
            goto done;
        }
        state = OPENSSL_malloc(state_len);
        if (state == NULL) {
            goto done;
        }

        ret = p11prov_GetOperationState(sigctx->provctx, newsess, state,
                                        &state_len);
        if (ret != CKR_OK) {
            goto done;
        }

        ret = p11prov_get_session(sigctx->provctx, &slotid, NULL, NULL,
                                  sigctx->mechtype, NULL, NULL, reqlogin, false,
                                  &sigctx->session);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret,
                          "Failed to open session on slot %lu", slotid);
            goto done;
        }
        sess = p11prov_session_handle(sigctx->session);

        ret = p11prov_SetOperationState(sigctx->provctx, sess, state, state_len,
                                        handle, handle);
        if (ret != CKR_OK) {
            p11prov_return_session(sigctx->session);
            sigctx->session = NULL;
        }
    }

done:
    OPENSSL_free(state);
    return newctx;
}

static void p11prov_sig_freectx(void *ctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    if (sigctx == NULL) {
        return;
    }

    OPENSSL_clear_free(sigctx->eddsa_params.pContextData,
                       sigctx->eddsa_params.ulContextDataLen);
    p11prov_return_session(sigctx->session);
    EVP_MD_CTX_free(sigctx->mechanism_fallback);
    p11prov_obj_free(sigctx->key);
    OPENSSL_free(sigctx->properties);
    OPENSSL_clear_free(sigctx, sizeof(P11PROV_SIG_CTX));
}

#define DER_SEQUENCE 0x30
#define DER_OBJECT 0x06
#define DER_NULL 0x05
#define DER_OCTET_STRING 0x04

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

/* clang-format off */
#define DEFINE_DER_DIGESTINFO(name, alg_id, digest_size) \
    static const unsigned char der_digestinfo_##name[] = { \
        DER_SEQUENCE, DER_NIST_HASHALGS_LEN+9+digest_size, \
          DER_SEQUENCE, DER_NIST_HASHALGS_LEN+5, \
            DER_OBJECT, DER_NIST_HASHALGS_LEN+1, DER_NIST_HASHALGS, alg_id, \
            DER_NULL, 0, \
          DER_OCTET_STRING, digest_size \
    };

#define DEFINE_DER_SEQ_SHA(bits, rsa_algid, ecdsa_algid, digestinfo_algid) \
    static const unsigned char der_rsa_sha##bits[] = { \
        DER_SEQUENCE, DER_RSADSI_PKCS1_LEN+5, \
            DER_OBJECT, DER_RSADSI_PKCS1_LEN+1, DER_RSADSI_PKCS1, rsa_algid, \
            DER_NULL, 0, \
    }; \
    static const unsigned char der_ecdsa_sha##bits[] = { \
        DER_SEQUENCE, DER_ANSIX962_SHA2_SIG_LEN+3, \
            DER_OBJECT, DER_ANSIX962_SHA2_SIG_LEN+1, DER_ANSIX962_SHA2_SIG, ecdsa_algid, \
    }; \
    DEFINE_DER_DIGESTINFO(sha##bits, digestinfo_algid, bits/8)

#define DEFINE_DER_SEQ_SHA3(bits, rsa_algid, ecdsa_algid, digestinfo_algid) \
    static const unsigned char der_rsa_sha3_##bits[] = { \
        DER_SEQUENCE, DER_NIST_SIGALGS_LEN+5, \
            DER_OBJECT, DER_NIST_SIGALGS_LEN+1, DER_NIST_SIGALGS, rsa_algid, \
            DER_NULL, 0 \
    }; \
    static const unsigned char der_ecdsa_sha3_##bits[] = { \
        DER_SEQUENCE, DER_NIST_SIGALGS_LEN+3, \
            DER_OBJECT, DER_NIST_SIGALGS_LEN+1, DER_NIST_SIGALGS, ecdsa_algid \
    }; \
    DEFINE_DER_DIGESTINFO(sha3_##bits, digestinfo_algid, bits/8)

static const unsigned char der_rsa_sha1[] = {
    DER_SEQUENCE, DER_RSADSI_PKCS1_LEN+5,
        DER_OBJECT, DER_RSADSI_PKCS1_LEN+1, DER_RSADSI_PKCS1, 0x05,
        DER_NULL, 0
};
static const unsigned char der_ecdsa_sha1[] = {
    DER_SEQUENCE, DER_ANSIX962_SIG_LEN+3,
        DER_OBJECT, DER_ANSIX962_SIG_LEN+1, DER_ANSIX962_SIG, 0x01
};
/* iso(1) org(3) oiw(14) secsig(3) algorithms(2) hashAlgorithmIdentifier(26) */
static const unsigned char der_digestinfo_sha1[] = {
    DER_SEQUENCE, 0x0d + SHA_DIGEST_LENGTH,
        DER_SEQUENCE, 0x09,
        DER_OBJECT, 0x05, 1 * 40 + 3, 14, 3, 2, 26,
        DER_NULL, 0x00,
    DER_OCTET_STRING, SHA_DIGEST_LENGTH
};
/* clang-format on */

DEFINE_DER_SEQ_SHA(512, 0x0D, 0x04, 0x03);
DEFINE_DER_SEQ_SHA(384, 0x0C, 0x03, 0x02);
DEFINE_DER_SEQ_SHA(256, 0x0B, 0x02, 0x01);
DEFINE_DER_SEQ_SHA(224, 0x0E, 0x01, 0x04);

DEFINE_DER_SEQ_SHA3(512, 0x10, 0x0C, 0x0A);
DEFINE_DER_SEQ_SHA3(384, 0x0F, 0x0B, 0x09);
DEFINE_DER_SEQ_SHA3(256, 0x0E, 0x0A, 0x08);
DEFINE_DER_SEQ_SHA3(224, 0x0D, 0x09, 0x07);

#define DM_ELEM_SHA(bits) \
    { \
        .digest = CKM_SHA##bits, .pkcs_mech = CKM_SHA##bits##_RSA_PKCS, \
        .pkcs_pss = CKM_SHA##bits##_RSA_PKCS_PSS, \
        .ecdsa_mech = CKM_ECDSA_SHA##bits, .mgf = CKG_MGF1_SHA##bits, \
        .der_rsa_algorithm_id = der_rsa_sha##bits, \
        .der_rsa_algorithm_id_len = sizeof(der_rsa_sha##bits), \
        .der_ecdsa_algorithm_id = der_ecdsa_sha##bits, \
        .der_ecdsa_algorithm_id_len = sizeof(der_ecdsa_sha##bits), \
        .der_digestinfo = der_digestinfo_sha##bits, \
        .der_digestinfo_len = sizeof(der_digestinfo_sha##bits), \
    }
#define DM_ELEM_SHA3(bits) \
    { \
        .digest = CKM_SHA3_##bits, .pkcs_mech = CKM_SHA3_##bits##_RSA_PKCS, \
        .pkcs_pss = CKM_SHA3_##bits##_RSA_PKCS_PSS, \
        .ecdsa_mech = CKM_ECDSA_SHA3_##bits, .mgf = CKG_MGF1_SHA3_##bits, \
        .der_rsa_algorithm_id = der_rsa_sha3_##bits, \
        .der_rsa_algorithm_id_len = sizeof(der_rsa_sha3_##bits), \
        .der_ecdsa_algorithm_id = der_ecdsa_sha3_##bits, \
        .der_ecdsa_algorithm_id_len = sizeof(der_ecdsa_sha3_##bits), \
        .der_digestinfo = der_digestinfo_sha3_##bits, \
        .der_digestinfo_len = sizeof(der_digestinfo_sha3_##bits), \
    }

/* only the ones we can support */
struct p11prov_mech {
    CK_MECHANISM_TYPE digest;
    CK_MECHANISM_TYPE pkcs_mech;
    CK_MECHANISM_TYPE pkcs_pss;
    CK_MECHANISM_TYPE ecdsa_mech;
    CK_RSA_PKCS_MGF_TYPE mgf;
    const unsigned char *der_rsa_algorithm_id;
    int der_rsa_algorithm_id_len;
    const unsigned char *der_ecdsa_algorithm_id;
    int der_ecdsa_algorithm_id_len;
    const unsigned char *der_digestinfo;
    int der_digestinfo_len;
};
typedef struct p11prov_mech P11PROV_MECH;

static const P11PROV_MECH mech_map[] = {
    DM_ELEM_SHA3(256),
    DM_ELEM_SHA3(512),
    DM_ELEM_SHA3(384),
    DM_ELEM_SHA3(224),
    DM_ELEM_SHA(256),
    DM_ELEM_SHA(512),
    DM_ELEM_SHA(384),
    DM_ELEM_SHA(224),
    { CKM_SHA_1, CKM_SHA1_RSA_PKCS, CKM_SHA1_RSA_PKCS_PSS, CKM_ECDSA_SHA1,
      CKG_MGF1_SHA1, der_rsa_sha1, sizeof(der_rsa_sha1), der_ecdsa_sha1,
      sizeof(der_ecdsa_sha1), der_digestinfo_sha1,
      sizeof(der_digestinfo_sha1) },
    { CK_UNAVAILABLE_INFORMATION, 0, 0, 0, 0, 0, 0, 0, 0 },
};

#define DER_ED25519_OID 0x06, 0x03, 0x2B, 0x65, 0x70
#define DER_ED25519_OID_LEN 0x05
static const unsigned char der_ed25519_algorithm_id[] = { DER_SEQUENCE,
                                                          DER_ED25519_OID_LEN,
                                                          DER_ED25519_OID };
#define DER_ED448_OID 0x06, 0x03, 0x2B, 0x65, 0x71
#define DER_ED448_OID_LEN 0x05
static const unsigned char der_ed448_algorithm_id[] = { DER_SEQUENCE,
                                                        DER_ED448_OID_LEN,
                                                        DER_ED448_OID };

static CK_RV p11prov_mech_by_mechanism(CK_MECHANISM_TYPE mechanism,
                                       const P11PROV_MECH **mech)
{
    for (int i = 0; mech_map[i].digest != CK_UNAVAILABLE_INFORMATION; i++) {
        if (mech_map[i].digest == mechanism) {
            *mech = &mech_map[i];
            return CKR_OK;
        }
    }
    return CKR_MECHANISM_INVALID;
}

static CK_RV p11prov_mech_by_mgf(CK_RSA_PKCS_MGF_TYPE mgf,
                                 const P11PROV_MECH **mech)
{
    for (int i = 0; mech_map[i].digest != CK_UNAVAILABLE_INFORMATION; i++) {
        if (mech_map[i].mgf == mgf) {
            *mech = &mech_map[i];
            return CKR_OK;
        }
    }
    return CKR_MECHANISM_INVALID;
}

static const char *p11prov_sig_mgf_name(CK_RSA_PKCS_MGF_TYPE mgf)
{
    const P11PROV_MECH *mech = NULL;
    const char *digest_name;
    CK_RV rv;

    rv = p11prov_mech_by_mgf(mgf, &mech);
    if (rv != CKR_OK) {
        return NULL;
    }

    rv = p11prov_digest_get_name(mech->digest, &digest_name);
    if (rv != CKR_OK) {
        return NULL;
    }

    return digest_name;
}

static CK_RSA_PKCS_MGF_TYPE p11prov_sig_map_mgf(const char *digest_name)
{
    CK_MECHANISM_TYPE digest;
    const P11PROV_MECH *mech = NULL;
    CK_RV rv;

    rv = p11prov_digest_get_by_name(digest_name, &digest);
    if (rv != CKR_OK) {
        return CK_UNAVAILABLE_INFORMATION;
    }

    rv = p11prov_mech_by_mechanism(digest, &mech);
    if (rv != CKR_OK) {
        return CK_UNAVAILABLE_INFORMATION;
    }

    return mech->mgf;
}

static CK_RV p11prov_sig_pss_restrictions(P11PROV_SIG_CTX *sigctx,
                                          CK_MECHANISM *mechanism)
{
    CK_ATTRIBUTE *allowed_mechs =
        p11prov_obj_get_attr(sigctx->key, CKA_ALLOWED_MECHANISMS);

    if (allowed_mechs) {
        CK_ATTRIBUTE_TYPE *mechs = (CK_ATTRIBUTE_TYPE *)allowed_mechs->pValue;
        int num_mechs = allowed_mechs->ulValueLen / sizeof(CK_MECHANISM_TYPE);
        bool allowed = false;

        if (num_mechs == 0) {
            /* It makes no sense to return 0 allowed mechanisms for a key,
             * this just means the token is bogus, let's ignore the check
             * and try the operation and see what happens */
            P11PROV_debug("Buggy CKA_ALLOWED_MECHANISMS implementation");
            return CKR_OK;
        }

        for (int i = 0; i < num_mechs; i++) {
            if (mechs[i] == mechanism->mechanism) {
                allowed = true;
                break;
            }
        }

        if (allowed) {
            return CKR_OK;
        }

        P11PROV_raise(sigctx->provctx, CKR_ACTION_PROHIBITED,
                      "mechanism not allowed with this key");
        return CKR_ACTION_PROHIBITED;
    }

    /* there are no restrictions on this key */
    return CKR_OK;
}

/* fixates pss_params based on defaults if values are not set */
static CK_RV pss_defaults(P11PROV_SIG_CTX *sigctx, CK_MECHANISM *mechanism,
                          bool set_mech)
{
    const P11PROV_MECH *mech;
    CK_RV ret;

    ret = p11prov_mech_by_mechanism(sigctx->digest, &mech);
    if (ret != CKR_OK) {
        return ret;
    }
    sigctx->pss_params.hashAlg = mech->digest;
    if (sigctx->pss_params.mgf == 0) {
        sigctx->pss_params.mgf = mech->mgf;
    }
    if (sigctx->pss_params.sLen == 0) {
        /* default to digest size if not set */
        size_t size;
        ret = p11prov_digest_get_digest_size(mech->digest, &size);
        if (ret != CKR_OK) {
            return ret;
        }
        sigctx->pss_params.sLen = size;
    }

    mechanism->pParameter = &sigctx->pss_params;
    mechanism->ulParameterLen = sizeof(sigctx->pss_params);

    if (set_mech) {
        mechanism->mechanism = mech->pkcs_pss;
    }

    return CKR_OK;
}

static int p11prov_sig_set_mechanism(P11PROV_SIG_CTX *sigctx, bool digest_sign,
                                     CK_MECHANISM *mechanism)
{
    int result = CKR_DATA_INVALID;

    mechanism->mechanism = sigctx->mechtype;
    mechanism->pParameter = NULL;
    mechanism->ulParameterLen = 0;

    switch (sigctx->mechtype) {
    case CKM_RSA_PKCS:
        if (digest_sign) {
            const P11PROV_MECH *mech;
            result = p11prov_mech_by_mechanism(sigctx->digest, &mech);
            if (result == CKR_OK) {
                mechanism->mechanism = mech->pkcs_mech;
            }
        } else {
            result = CKR_OK;
        }
        break;
    case CKM_RSA_X_509:
        break;
    case CKM_RSA_PKCS_PSS:
        result = pss_defaults(sigctx, mechanism, digest_sign);
        if (result == CKR_OK && digest_sign) {
            result = p11prov_sig_pss_restrictions(sigctx, mechanism);
        }
        break;
    case CKM_ECDSA:
        if (digest_sign) {
            const P11PROV_MECH *mech;
            result = p11prov_mech_by_mechanism(sigctx->digest, &mech);
            if (result == CKR_OK) {
                mechanism->mechanism = mech->ecdsa_mech;
            }
        } else {
            result = CKR_OK;
        }
        break;
    case CKM_EDDSA:
        if (sigctx->use_eddsa_params == CK_TRUE) {
            mechanism->pParameter = &sigctx->eddsa_params;
            mechanism->ulParameterLen = sizeof(sigctx->eddsa_params);
        }
        result = CKR_OK;
    }

    if (result == CKR_OK) {
        P11PROV_debug_mechanism(sigctx->provctx,
                                p11prov_obj_get_slotid(sigctx->key),
                                mechanism->mechanism);
    }
    return result;
}

static CK_RV p11prov_sig_get_sig_size(void *ctx, size_t *siglen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_KEY_TYPE type = p11prov_obj_get_key_type(sigctx->key);
    CK_ULONG size = p11prov_obj_get_key_size(sigctx->key);

    if (type == CK_UNAVAILABLE_INFORMATION) {
        return CKR_KEY_NEEDED;
    }
    if (size == CK_UNAVAILABLE_INFORMATION) {
        return CKR_KEY_NEEDED;
    }

    switch (type) {
    case CKK_RSA:
        *siglen = size;
        break;
    case CKK_EC:
        /* add room for ECDSA Signature DER overhead */
        *siglen = 3 + (size + 4) * 2;
        break;
    case CKK_EC_EDWARDS:
        if (size == ED25519_BYTE_SIZE) {
            *siglen = ED25519_SIG_SIZE;
        } else if (size == ED448_BYTE_SIZE) {
            *siglen = ED448_SIG_SIZE;
        } else {
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        break;
    default:
        return CKR_KEY_TYPE_INCONSISTENT;
    }
    return CKR_OK;
}

static int p11prov_rsasig_set_pss_saltlen_from_digest(void *ctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    size_t digest_size;
    CK_RV rv;

    if (sigctx->digest == 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "Can only be set if Digest was set first.");
        return RET_OSSL_ERR;
    }

    rv = p11prov_digest_get_digest_size(sigctx->digest, &digest_size);
    if (rv != CKR_OK) {
        P11PROV_raise(sigctx->provctx, rv, "Unavailable digest");
        return RET_OSSL_ERR;
    }

    sigctx->pss_params.sLen = digest_size;
    return RET_OSSL_OK;
}

static int p11prov_rsasig_set_pss_saltlen_max(void *ctx, bool max_to_digest)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    size_t digest_size;
    CK_ULONG key_size;
    CK_ULONG key_bit_size;
    CK_RV rv;

    if (sigctx->digest == 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "Can only be set if Digest was set first.");
        return RET_OSSL_ERR;
    }

    rv = p11prov_digest_get_digest_size(sigctx->digest, &digest_size);
    if (rv != CKR_OK) {
        P11PROV_raise(sigctx->provctx, rv, "Unavailable digest");
        return RET_OSSL_ERR;
    }

    key_size = p11prov_obj_get_key_size(sigctx->key);
    if (key_size == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(sigctx->provctx, rv, "Unavailable key");
        return RET_OSSL_ERR;
    }
    key_bit_size = p11prov_obj_get_key_bit_size(sigctx->key);
    if (key_bit_size == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(sigctx->provctx, rv, "Unavailable key");
        return RET_OSSL_ERR;
    }

    /* from openssl */
    sigctx->pss_params.sLen = key_size - digest_size - 2;
    if ((key_bit_size & 0x07) == 1) {
        sigctx->pss_params.sLen -= 1;
    }
    if (max_to_digest && sigctx->pss_params.sLen > digest_size) {
        sigctx->pss_params.sLen = digest_size;
    }
    return RET_OSSL_OK;
}

static CK_RV p11prov_sig_op_init(void *ctx, void *provkey, CK_FLAGS operation,
                                 const char *digest)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)provkey;
    CK_OBJECT_CLASS class;
    CK_RV ret;

    ret = p11prov_ctx_status(sigctx->provctx);
    if (ret != CKR_OK) {
        return ret;
    }

    sigctx->key = p11prov_obj_ref(key);
    if (sigctx->key == NULL) {
        return CKR_KEY_NEEDED;
    }
    class = p11prov_obj_get_class(sigctx->key);
    switch (operation) {
    case CKF_SIGN:
        if (class != CKO_PRIVATE_KEY) {
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        break;
    case CKF_VERIFY:
        if (class != CKO_PUBLIC_KEY) {
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        break;
    default:
        return CKR_GENERAL_ERROR;
    }
    sigctx->operation = operation;

    if (digest) {
        ret = p11prov_digest_get_by_name(digest, &sigctx->digest);
        if (ret != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return ret;
        }
    }

    return CKR_OK;
}

static CK_RV mech_fallback_init(P11PROV_SIG_CTX *sigctx, CK_SLOT_ID slotid)
{
    const OSSL_PROVIDER *prov;
    void *provctx;
    const char *digest;
    EVP_MD *md = NULL;
    OSSL_LIB_CTX *libctx;
    const OSSL_PARAM *pparams = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_ulong(P11PROV_PARAM_SLOT_ID, &slotid),
        OSSL_PARAM_construct_end(),
    };
    CK_RV ret;
    int err;

    P11PROV_debug("Enable fallback for mechanism %lx", sigctx->mechtype);

    ret = p11prov_digest_get_name(sigctx->digest, &digest);
    if (ret != CKR_OK) {
        P11PROV_raise(sigctx->provctx, ret, "Failed to get name for digest %lx",
                      sigctx->digest);
        goto done;
    }

    libctx = p11prov_ctx_get_libctx(sigctx->provctx);
    /* FIXME: should we add sigctx->properties here ? (ex: fips=yes) */
    /* try to keep digest on token but allow default (via "?") to provide
     * digests. */
    md = EVP_MD_fetch(libctx, digest, "?" P11PROV_DEFAULT_PROPERTIES);
    if (!md) {
        ret = CKR_GENERAL_ERROR;
        P11PROV_raise(sigctx->provctx, ret,
                      "Failed to get context for EVP digest '%s'", digest);
        goto done;
    }

    sigctx->mechanism_fallback = EVP_MD_CTX_new();
    if (!sigctx->mechanism_fallback) {
        ret = CKR_HOST_MEMORY;
        P11PROV_raise(sigctx->provctx, ret, "Failed to init fallback context");
        goto done;
    }

    /* if it is us, set a slot preference */
    prov = EVP_MD_get0_provider(md);
    if (prov) {
        provctx = OSSL_PROVIDER_get0_provider_ctx(prov);
        if (provctx == sigctx->provctx) {
            pparams = params;
        }
    }

    err = EVP_DigestInit_ex2(sigctx->mechanism_fallback, md, pparams);
    if (err != RET_OSSL_OK) {
        ret = CKR_GENERAL_ERROR;
        P11PROV_raise(sigctx->provctx, ret, "Failed to init EVP digest");
        goto done;
    }

    /* done */
    ret = CKR_OK;

done:
    EVP_MD_free(md);
    return ret;
}

static CK_RV p11prov_sig_operate_init(P11PROV_SIG_CTX *sigctx, bool digest_op,
                                      P11PROV_SESSION **_session)
{
    P11PROV_SESSION *session = NULL;
    CK_OBJECT_HANDLE handle;
    CK_MECHANISM mechanism;
    CK_SESSION_HANDLE sess;
    CK_SLOT_ID slotid;
    bool reqlogin = false;
    bool always_auth = false;
    CK_RV ret;

    P11PROV_debug("called (sigctx=%p, digest_op=%s)", sigctx,
                  digest_op ? "true" : "false");

    ret = p11prov_ctx_status(sigctx->provctx);
    if (ret != CKR_OK) {
        return ret;
    }

    handle = p11prov_obj_get_handle(sigctx->key);
    if (handle == CK_INVALID_HANDLE) {
        P11PROV_raise(sigctx->provctx, CKR_KEY_HANDLE_INVALID,
                      "Provided key has invalid handle");
        return CKR_KEY_HANDLE_INVALID;
    }
    slotid = p11prov_obj_get_slotid(sigctx->key);
    if (slotid == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(sigctx->provctx, CKR_SLOT_ID_INVALID,
                      "Provided key has invalid slot");
        return CKR_SLOT_ID_INVALID;
    }

    ret = p11prov_sig_set_mechanism(sigctx, digest_op, &mechanism);
    if (ret != CKR_OK) {
        return ret;
    }

    if (sigctx->operation == CKF_SIGN) {
        reqlogin = true;
    }

    ret = p11prov_get_session(sigctx->provctx, &slotid, NULL, NULL,
                              mechanism.mechanism, NULL, NULL, reqlogin, false,
                              &session);
    switch (ret) {
    case CKR_OK:
        sess = p11prov_session_handle(session);

        if (sigctx->operation == CKF_SIGN) {
            ret = p11prov_SignInit(sigctx->provctx, sess, &mechanism, handle);
        } else {
            ret = p11prov_VerifyInit(sigctx->provctx, sess, &mechanism, handle);
        }
        break;
    case CKR_MECHANISM_INVALID:
        if (!digest_op || mechanism.mechanism == sigctx->mechtype) {
            /* Even the raw signature mechanism is not supported */
            P11PROV_raise(sigctx->provctx, ret,
                          "Unsupported mechanism family %lx for slot %lu",
                          sigctx->mechtype, slotid);
            goto done;
        }

        slotid = p11prov_obj_get_slotid(sigctx->key);

        ret = mech_fallback_init(sigctx, slotid);
        goto done;
        break;
    default:
        P11PROV_raise(sigctx->provctx, ret,
                      "Failed to open session on slot %lu", slotid);
        goto done;
    }

    if (reqlogin) {
        always_auth =
            p11prov_obj_get_bool(sigctx->key, CKA_ALWAYS_AUTHENTICATE, false);
    }

    if (always_auth) {
        ret = p11prov_context_specific_login(session, NULL, NULL, NULL);
    }

done:
    if (ret != CKR_OK) {
        p11prov_return_session(session);
    } else {
        *_session = session;
    }
    return ret;
}

static CK_RV p11prov_sig_operate(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                                 size_t *siglen, size_t sigsize,
                                 unsigned char *tbs, size_t tbslen)
{
    P11PROV_SESSION *session;
    CK_SESSION_HANDLE sess;
    CK_ULONG sig_size = sigsize;
    CK_RV ret;
    /* The 64 is the largest possible der_digestinfo prefix encoding */
    unsigned char data[EVP_MAX_MD_SIZE + 64];

    if (sig == NULL) {
        if (sigctx->operation == CKF_VERIFY) {
            return CKR_ARGUMENTS_BAD;
        }
        if (siglen == NULL) {
            return CKR_ARGUMENTS_BAD;
        }
        return p11prov_sig_get_sig_size(sigctx, siglen);
    }

    if (sigctx->operation == CKF_SIGN && sigctx->mechtype == CKM_RSA_X_509) {
        /* some tokens allow raw signatures on any data size.
         * Enforce data size is the same as modulus as that is
         * what OpenSSL expects and does internally in rsa_sign
         * when there is no padding. */
        if (tbslen < sigsize) {
            ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE);
            return CKR_DATA_LEN_RANGE;
        }
    }

    if (sigctx->mechtype == CKM_RSA_PKCS && sigctx->digest != 0) {
        const P11PROV_MECH *mech = NULL;
        size_t digest_size = 0;

        ret = p11prov_mech_by_mechanism(sigctx->digest, &mech);
        if (ret != CKR_OK) {
            ERR_raise(ERR_LIB_RSA, PROV_R_INVALID_DIGEST);
            return ret;
        }
        ret = p11prov_digest_get_digest_size(sigctx->digest, &digest_size);
        if (ret != CKR_OK) {
            ERR_raise(ERR_LIB_RSA, PROV_R_INVALID_DIGEST);
            return ret;
        }
        if (tbslen != digest_size
            || tbslen + mech->der_digestinfo_len >= sizeof(data)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
            return ret;
        }
        memcpy(data, mech->der_digestinfo, mech->der_digestinfo_len);
        memcpy(data + mech->der_digestinfo_len, tbs, tbslen);
        tbs = data;
        tbslen += mech->der_digestinfo_len;
    }

    ret = p11prov_sig_operate_init(sigctx, false, &session);
    if (ret != CKR_OK) {
        return ret;
    }
    sess = p11prov_session_handle(session);

    if (sigctx->operation == CKF_SIGN) {
        ret = p11prov_Sign(sigctx->provctx, sess, tbs, tbslen, sig, &sig_size);
    } else {
        ret = p11prov_Verify(sigctx->provctx, sess, tbs, tbslen, sig, sigsize);
    }
    if (ret == CKR_OK) {
        if (siglen) {
            *siglen = sig_size;
        }
    }

    p11prov_return_session(session);
    if (tbs == data) {
        OPENSSL_cleanse(data, sizeof(data));
    }
    return ret;
}

static int p11prov_sig_digest_update(P11PROV_SIG_CTX *sigctx,
                                     unsigned char *data, size_t datalen)
{
    CK_SESSION_HANDLE sess;
    CK_RV ret;

    if (!sigctx->mechanism_fallback && !sigctx->session) {
        ret = p11prov_sig_operate_init(sigctx, true, &sigctx->session);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    if (sigctx->mechanism_fallback) {
        return EVP_DigestUpdate(sigctx->mechanism_fallback, data, datalen);
    }

    if (!sigctx->session) {
        return RET_OSSL_ERR;
    }

    /* we have an initialized session */
    sess = p11prov_session_handle(sigctx->session);
    if (sigctx->operation == CKF_SIGN) {
        ret = p11prov_SignUpdate(sigctx->provctx, sess, data, datalen);
    } else {
        ret = p11prov_VerifyUpdate(sigctx->provctx, sess, data, datalen);
    }
    if (ret != CKR_OK) {
        p11prov_return_session(sigctx->session);
        sigctx->session = NULL;
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static CK_RV mech_fallback_final(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                                 size_t *siglen, size_t sigsize, size_t mdsize)
{
    P11PROV_SIG_CTX *subctx = NULL;
    CK_BYTE digest[mdsize];
    unsigned int digest_len = mdsize;
    CK_OBJECT_HANDLE handle;
    int err;
    CK_RV ret;

    err = EVP_DigestFinal_ex(sigctx->mechanism_fallback, digest, &digest_len);
    if (err != RET_OSSL_OK) {
        ret = CKR_GENERAL_ERROR;
        P11PROV_raise(sigctx->provctx, ret, "EVP_DigestFinal_ex() failed");
        goto done;
    }
    if (digest_len != mdsize) {
        ret = CKR_GENERAL_ERROR;
        P11PROV_raise(sigctx->provctx, ret, "Inconsistent digest size");
        goto done;
    }

    handle = p11prov_obj_get_handle(sigctx->key);
    if (handle == CK_INVALID_HANDLE) {
        ret = CKR_KEY_HANDLE_INVALID;
        P11PROV_raise(sigctx->provctx, ret, "Provided key has invalid handle");
        goto done;
    }

    subctx = p11prov_sig_newctx(sigctx->provctx, sigctx->mechtype,
                                sigctx->properties);
    if (!subctx) {
        ret = CKR_HOST_MEMORY;
        goto done;
    }

    ret = p11prov_sig_op_init(subctx, sigctx->key, sigctx->operation, NULL);
    if (ret != CKR_OK) {
        P11PROV_raise(sigctx->provctx, ret, "Failed to setup sigver fallback");
        goto done;
    }

    ret = p11prov_sig_operate(subctx, sig, siglen, sigsize, digest, mdsize);
    if (ret != CKR_OK) {
        P11PROV_raise(sigctx->provctx, ret, "Failure in sigver fallback");
        goto done;
    }

done:
    p11prov_sig_freectx(subctx);
    return ret;
}

static int p11prov_sig_digest_final(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                                    size_t *siglen, size_t sigsize)
{
    CK_SESSION_HANDLE sess;
    CK_ULONG sig_size = sigsize;
    int result = RET_OSSL_ERR;
    CK_RV ret;

    if (sig == NULL) {
        if (sigctx->operation == CKF_VERIFY) {
            goto done;
        }
        if (siglen == NULL) {
            goto done;
        }
        ret = p11prov_sig_get_sig_size(sigctx, siglen);
        if (ret == CKR_OK) {
            result = RET_OSSL_OK;
        }
        return result;
    }

    if (sigctx->mechanism_fallback) {
        size_t mdsize;
        ret = p11prov_digest_get_digest_size(sigctx->digest, &mdsize);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret,
                          "Unexpected get_digest_size error");
            goto done;
        }

        ret = mech_fallback_final(sigctx, sig, siglen, sigsize, mdsize);
        if (ret == CKR_OK) {
            result = RET_OSSL_OK;
        }
        goto done;
    }

    if (!sigctx->session) {
        goto done;
    }

    sess = p11prov_session_handle(sigctx->session);
    if (sigctx->operation == CKF_SIGN) {
        ret = p11prov_SignFinal(sigctx->provctx, sess, sig, &sig_size);
    } else {
        ret = p11prov_VerifyFinal(sigctx->provctx, sess, sig, sigsize);
    }
    if (ret == CKR_OK) {
        if (siglen) {
            *siglen = sig_size;
        }
        result = RET_OSSL_OK;
    }

done:
    p11prov_return_session(sigctx->session);
    sigctx->session = NULL;
    return result;
}

DISPATCH_RSASIG_FN(newctx);
DISPATCH_RSASIG_FN(sign_init);
DISPATCH_RSASIG_FN(sign);
DISPATCH_RSASIG_FN(verify_init);
DISPATCH_RSASIG_FN(verify);
DISPATCH_RSASIG_FN(digest_sign_init);
DISPATCH_RSASIG_FN(digest_sign_update);
DISPATCH_RSASIG_FN(digest_sign_final);
DISPATCH_RSASIG_FN(digest_verify_init);
DISPATCH_RSASIG_FN(digest_verify_update);
DISPATCH_RSASIG_FN(digest_verify_final);
DISPATCH_RSASIG_FN(get_ctx_params);
DISPATCH_RSASIG_FN(set_ctx_params);
DISPATCH_RSASIG_FN(gettable_ctx_params);
DISPATCH_RSASIG_FN(settable_ctx_params);

static void *p11prov_rsasig_newctx(void *provctx, const char *properties)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_SIG_CTX *sigctx;

    /* PKCS1.5 is the default, PSS set via padding params */
    sigctx = p11prov_sig_newctx(ctx, CKM_RSA_PKCS, properties);
    if (sigctx == NULL) {
        return NULL;
    }

    return sigctx;
}

static int p11prov_rsasig_sign_init(void *ctx, void *provkey,
                                    const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("rsa sign init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_rsasig_set_ctx_params(ctx, params);
}

static int p11prov_rsasig_sign(void *ctx, unsigned char *sig, size_t *siglen,
                               size_t sigsize, const unsigned char *tbs,
                               size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("rsa sign (ctx=%p)", ctx);

    ret =
        p11prov_sig_operate(sigctx, sig, siglen, sigsize, (void *)tbs, tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_rsasig_verify_init(void *ctx, void *provkey,
                                      const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("rsa verify init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_rsasig_set_ctx_params(ctx, params);
}

static int p11prov_rsasig_verify(void *ctx, const unsigned char *sig,
                                 size_t siglen, const unsigned char *tbs,
                                 size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("rsa verify (ctx=%p)", ctx);

    ret = p11prov_sig_operate(sigctx, (void *)sig, NULL, siglen, (void *)tbs,
                              tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_rsasig_digest_sign_init(void *ctx, const char *digest,
                                           void *provkey,
                                           const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("rsa digest sign init (ctx=%p, digest=%s, key=%p, params=%p)",
                  ctx, digest ? digest : "<NULL>", provkey, params);

    /* use a default of sha2 256 if not provided */
    if (!digest) {
        digest = "sha256";
    }

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, digest);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_rsasig_set_ctx_params(ctx, params);
}

static int p11prov_rsasig_digest_sign_update(void *ctx,
                                             const unsigned char *data,
                                             size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("rsa digest sign update (ctx=%p, data=%p, datalen=%zu)", ctx,
                  data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_rsasig_digest_sign_final(void *ctx, unsigned char *sig,
                                            size_t *siglen, size_t sigsize)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    /* the siglen might be uninitialized when called from openssl */
    *siglen = 0;

    P11PROV_debug(
        "rsa digest sign final (ctx=%p, sig=%p, siglen=%zu, "
        "sigsize=%zu)",
        ctx, sig, *siglen, sigsize);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_final(sigctx, sig, siglen, sigsize);
}

static int p11prov_rsasig_digest_verify_init(void *ctx, const char *digest,
                                             void *provkey,
                                             const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("rsa digest verify init (ctx=%p, key=%p, params=%p)", ctx,
                  provkey, params);

    /* use a default of sha2 256 if not provided */
    if (!digest) {
        digest = "sha256";
    }

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, digest);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_rsasig_set_ctx_params(ctx, params);
}

static int p11prov_rsasig_digest_verify_update(void *ctx,
                                               const unsigned char *data,
                                               size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("rsa digest verify update (ctx=%p, data=%p, datalen=%zu)",
                  ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_rsasig_digest_verify_final(void *ctx,
                                              const unsigned char *sig,
                                              size_t siglen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("rsa digest verify final (ctx=%p, sig=%p, siglen=%zu)", ctx,
                  sig, siglen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_final(sigctx, (void *)sig, NULL, siglen);
}

static struct {
    CK_MECHANISM_TYPE type;
    int ossl_id;
    const char *string;
} padding_map[] = {
    { CKM_RSA_X_509, RSA_NO_PADDING, OSSL_PKEY_RSA_PAD_MODE_NONE },
    { CKM_RSA_PKCS, RSA_PKCS1_PADDING, OSSL_PKEY_RSA_PAD_MODE_PKCSV15 },
    { CKM_RSA_X9_31, RSA_X931_PADDING, OSSL_PKEY_RSA_PAD_MODE_X931 },
    { CKM_RSA_PKCS_PSS, RSA_PKCS1_PSS_PADDING, OSSL_PKEY_RSA_PAD_MODE_PSS },
    { CK_UNAVAILABLE_INFORMATION, 0, NULL },
};

static int p11prov_rsasig_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    OSSL_PARAM *p;
    int ret;

    /* todo sig params:
        OSSL_SIGNATURE_PARAM_ALGORITHM_ID
     */

    P11PROV_debug("rsasig get ctx params (ctx=%p, params=%p)", ctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p) {
        const P11PROV_MECH *mech = NULL;
        CK_RV result;

        switch (sigctx->mechtype) {
        case CKM_RSA_PKCS:
            result = p11prov_mech_by_mechanism(sigctx->digest, &mech);
            if (result != CKR_OK) {
                P11PROV_raise(
                    sigctx->provctx, result,
                    "Failed to get digest for signature algorithm ID");
                return RET_OSSL_ERR;
            }
            ret = OSSL_PARAM_set_octet_string(p, mech->der_rsa_algorithm_id,
                                              mech->der_rsa_algorithm_id_len);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
            break;
        case CKM_RSA_X_509:
            return RET_OSSL_ERR;
        case CKM_RSA_PKCS_PSS:
            /* TODO */
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p) {
        const char *digest;
        CK_RV rv;

        rv = p11prov_digest_get_name(sigctx->digest, &digest);
        if (rv != CKR_OK) {
            P11PROV_raise(sigctx->provctx, rv, "Unavailable digest name");
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_utf8_string(p, digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p) {
        ret = RET_OSSL_ERR;
        for (int i = 0; padding_map[i].string != NULL; i++) {
            if (padding_map[i].type == sigctx->mechtype) {
                switch (p->data_type) {
                case OSSL_PARAM_INTEGER:
                    ret = OSSL_PARAM_set_int(p, padding_map[i].ossl_id);
                    break;
                case OSSL_PARAM_UTF8_STRING:
                    ret = OSSL_PARAM_set_utf8_string(p, padding_map[i].string);
                    break;
                }
                break;
            }
        }
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p) {
        const char *digest = NULL;
        CK_RV rv = CKR_GENERAL_ERROR;

        if (sigctx->pss_params.mgf != 0) {
            digest = p11prov_sig_mgf_name(sigctx->pss_params.mgf);
        } else {
            const P11PROV_MECH *pssmech;
            rv = p11prov_mech_by_mechanism(sigctx->mechtype, &pssmech);
            if (rv == CKR_OK) {
                rv = p11prov_digest_get_name(pssmech->digest, &digest);
                if (rv != CKR_OK) {
                    digest = NULL;
                }
            }
        }
        if (!digest) {
            P11PROV_raise(sigctx->provctx, rv, "Failed to get digest for MGF1");
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_utf8_string(p, digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

/* only available in recent OpenSSL 3.0.x headers */
#ifndef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
#define RSA_PSS_SALTLEN_AUTO_DIGEST_MAX -4
#endif
#ifndef OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX
#define OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX "auto-digestmax"
#endif

static int rsasig_set_saltlen(P11PROV_SIG_CTX *sigctx, int saltlen)
{
    if (saltlen >= 0) {
        sigctx->pss_params.sLen = saltlen;
        return RET_OSSL_OK;
    }
    if (saltlen == RSA_PSS_SALTLEN_DIGEST) {
        return p11prov_rsasig_set_pss_saltlen_from_digest(sigctx);
    }
    if (saltlen == RSA_PSS_SALTLEN_AUTO || saltlen == RSA_PSS_SALTLEN_MAX) {
        return p11prov_rsasig_set_pss_saltlen_max(sigctx, false);
    }
    if (saltlen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX) {
        return p11prov_rsasig_set_pss_saltlen_max(sigctx, true);
    }
    return RET_OSSL_ERR;
}

static int p11prov_rsasig_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("rsasig set ctx params (ctx=%p, params=%p)", sigctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p) {
        const char *digest = NULL;
        CK_RV rv;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        P11PROV_debug("Set OSSL_SIGNATURE_PARAM_DIGEST to %s", digest);

        rv = p11prov_digest_get_by_name(digest, &sigctx->digest);
        if (rv != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p) {
        CK_MECHANISM_TYPE mechtype = CK_UNAVAILABLE_INFORMATION;
        if (p->data_type == OSSL_PARAM_INTEGER) {
            int pad_mode;
            /* legacy pad mode number */
            ret = OSSL_PARAM_get_int(p, &pad_mode);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
            P11PROV_debug("Set OSSL_SIGNATURE_PARAM_PAD_MODE to %d", pad_mode);
            for (int i = 0; padding_map[i].string != NULL; i++) {
                if (padding_map[i].ossl_id == pad_mode) {
                    mechtype = padding_map[i].type;
                    break;
                }
            }
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            P11PROV_debug("Set OSSL_SIGNATURE_PARAM_PAD_MODE to %s",
                          p->data ? (const char *)p->data : "<NULL>");
            if (p->data) {
                for (int i = 0; padding_map[i].string != NULL; i++) {
                    if (strcmp(p->data, padding_map[i].string) == 0) {
                        mechtype = padding_map[i].type;
                        break;
                    }
                }
            }
        } else {
            return RET_OSSL_ERR;
        }
        if (mechtype == CK_UNAVAILABLE_INFORMATION) {
            ERR_raise(ERR_LIB_PROV, PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
            return RET_OSSL_ERR;
        }

        if (mechtype == CKM_RSA_PKCS_PSS) {
            /* some modules do not support PSS so we need to return
             * an error early if we try to select this. Unfortunately
             * although openssl has separate keymgmt for PKCS vs PSS
             * padding, it consider RSA always capable to be performed
             * regardless, and this is not the case in PKCS#11 */
            CK_RV rv;

            rv = p11prov_check_mechanism(sigctx->provctx,
                                         p11prov_obj_get_slotid(sigctx->key),
                                         CKM_RSA_PKCS_PSS);
            if (rv != CKR_OK) {
                P11PROV_raise(sigctx->provctx, rv,
                              "CKM_RSA_PKCS_PSS unavailable");
                return RET_OSSL_ERR;
            }
        }

        sigctx->mechtype = mechtype;

        P11PROV_debug_mechanism(sigctx->provctx,
                                p11prov_obj_get_slotid(sigctx->key),
                                sigctx->mechtype);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p) {
        int saltlen;
        if (sigctx->mechtype != CKM_RSA_PKCS_PSS) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "Can only be set if PSS Padding was first set.");
            return RET_OSSL_ERR;
        }

        if (p->data_type == OSSL_PARAM_INTEGER) {
            /* legacy saltlen number */
            ret = OSSL_PARAM_get_int(p, &saltlen);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
            P11PROV_debug("Set OSSL_SIGNATURE_PARAM_PSS_SALTLEN to %d",
                          saltlen);
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            P11PROV_debug("Set OSSL_SIGNATURE_PARAM_PSS_SALTLEN to %s",
                          p->data ? (const char *)p->data : "<NULL>");
            if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0) {
                saltlen = RSA_PSS_SALTLEN_DIGEST;
            } else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0) {
                saltlen = RSA_PSS_SALTLEN_MAX;
            } else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0) {
                saltlen = RSA_PSS_SALTLEN_AUTO;
            } else if (strcmp(p->data,
                              OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX)
                       == 0) {
                saltlen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
            } else {
                saltlen = atoi(p->data);
            }
        } else {
            return RET_OSSL_ERR;
        }
        ret = rsasig_set_saltlen(sigctx, saltlen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p) {
        const char *digest = NULL;
        ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        P11PROV_debug("Set OSSL_SIGNATURE_PARAM_MGF1_DIGEST to %s", digest);

        sigctx->pss_params.mgf = p11prov_sig_map_mgf(digest);
        if (sigctx->pss_params.mgf == CK_UNAVAILABLE_INFORMATION) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MGF1_MD);
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_rsasig_gettable_ctx_params(void *ctx,
                                                            void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *p11prov_rsasig_settable_ctx_params(void *ctx,
                                                            void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        /* TODO: support rsa_padding_mode */
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_rsa_signature_functions[] = {
    DISPATCH_SIG_ELEM(rsasig, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(rsasig, SIGN_INIT, sign_init),
    DISPATCH_SIG_ELEM(rsasig, SIGN, sign),
    DISPATCH_SIG_ELEM(rsasig, VERIFY_INIT, verify_init),
    DISPATCH_SIG_ELEM(rsasig, VERIFY, verify),
    DISPATCH_SIG_ELEM(rsasig, DIGEST_SIGN_INIT, digest_sign_init),
    DISPATCH_SIG_ELEM(rsasig, DIGEST_SIGN_UPDATE, digest_sign_update),
    DISPATCH_SIG_ELEM(rsasig, DIGEST_SIGN_FINAL, digest_sign_final),
    DISPATCH_SIG_ELEM(rsasig, DIGEST_VERIFY_INIT, digest_verify_init),
    DISPATCH_SIG_ELEM(rsasig, DIGEST_VERIFY_UPDATE, digest_verify_update),
    DISPATCH_SIG_ELEM(rsasig, DIGEST_VERIFY_FINAL, digest_verify_final),
    DISPATCH_SIG_ELEM(rsasig, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(rsasig, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(rsasig, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(rsasig, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};

DISPATCH_ECDSA_FN(newctx);
DISPATCH_ECDSA_FN(sign_init);
DISPATCH_ECDSA_FN(sign);
DISPATCH_ECDSA_FN(verify_init);
DISPATCH_ECDSA_FN(verify);
DISPATCH_ECDSA_FN(digest_sign_init);
DISPATCH_ECDSA_FN(digest_sign_update);
DISPATCH_ECDSA_FN(digest_sign_final);
DISPATCH_ECDSA_FN(digest_verify_init);
DISPATCH_ECDSA_FN(digest_verify_update);
DISPATCH_ECDSA_FN(digest_verify_final);
DISPATCH_ECDSA_FN(get_ctx_params);
DISPATCH_ECDSA_FN(set_ctx_params);
DISPATCH_ECDSA_FN(gettable_ctx_params);
DISPATCH_ECDSA_FN(settable_ctx_params);

static void *p11prov_ecdsa_newctx(void *provctx, const char *properties)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_SIG_CTX *sigctx;

    sigctx = p11prov_sig_newctx(ctx, CKM_ECDSA, properties);
    if (sigctx == NULL) {
        return NULL;
    }

    return sigctx;
}

static int p11prov_ecdsa_sign_init(void *ctx, void *provkey,
                                   const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("ecdsa sign init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_ecdsa_set_ctx_params(ctx, params);
}

/* The raw signature is concatenated r | s padded to the field sizes */
#define P11PROV_MAX_RAW_ECC_SIG_SIZE (2 * (OPENSSL_ECC_MAX_FIELD_BITS + 7) / 8)

static int convert_ecdsa_raw_to_der(const unsigned char *raw, size_t rawlen,
                                    unsigned char *der, size_t *derlen,
                                    size_t dersize)
{
    const CK_ULONG fieldlen = rawlen / 2;
    ECDSA_SIG *ecdsasig;
    BIGNUM *r, *s;
    int ret = RET_OSSL_ERR;

    ecdsasig = ECDSA_SIG_new();
    if (ecdsasig == NULL) {
        return RET_OSSL_ERR;
    }

    r = BN_bin2bn(&raw[0], fieldlen, NULL);
    s = BN_bin2bn(&raw[fieldlen], fieldlen, NULL);
    ret = ECDSA_SIG_set0(ecdsasig, r, s);
    if (ret == RET_OSSL_OK) {
        *derlen = i2d_ECDSA_SIG(ecdsasig, NULL);
        if (*derlen <= dersize) {
            i2d_ECDSA_SIG(ecdsasig, &der);
            ret = RET_OSSL_OK;
        }
    } else {
        BN_clear_free(r);
        BN_clear_free(s);
    }

    ECDSA_SIG_free(ecdsasig);
    return ret;
}

static int convert_ecdsa_der_to_raw(const unsigned char *der, size_t derlen,
                                    unsigned char *raw, size_t rawlen,
                                    CK_ULONG fieldlen)
{
    ECDSA_SIG *ecdsasig;
    const BIGNUM *r, *s;

    if (fieldlen == CK_UNAVAILABLE_INFORMATION) {
        return RET_OSSL_ERR;
    }
    if (rawlen < 2 * fieldlen) {
        return RET_OSSL_ERR;
    }

    ecdsasig = d2i_ECDSA_SIG(NULL, &der, derlen);
    if (ecdsasig == NULL) {
        return RET_OSSL_ERR;
    }

    ECDSA_SIG_get0(ecdsasig, &r, &s);
    BN_bn2binpad(r, &raw[0], fieldlen);
    BN_bn2binpad(s, &raw[fieldlen], fieldlen);
    ECDSA_SIG_free(ecdsasig);
    return RET_OSSL_OK;
}

static int p11prov_ecdsa_sign(void *ctx, unsigned char *sig, size_t *siglen,
                              size_t sigsize, const unsigned char *tbs,
                              size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    unsigned char raw[P11PROV_MAX_RAW_ECC_SIG_SIZE];
    size_t rawlen;
    CK_RV ret;
    int err;

    P11PROV_debug("ecdsa sign (ctx=%p)", ctx);
    if (sig == NULL || sigsize == 0) {
        ret = p11prov_sig_operate(sigctx, 0, siglen, 0, (void *)tbs, tbslen);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        return RET_OSSL_OK;
    }

    ret = p11prov_sig_operate(sigctx, raw, &rawlen, sizeof(raw), (void *)tbs,
                              tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    err = convert_ecdsa_raw_to_der(raw, rawlen, sig, siglen, sigsize);
    OPENSSL_cleanse(raw, rawlen);
    return err;
}

static int p11prov_ecdsa_verify_init(void *ctx, void *provkey,
                                     const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("ecdsa verify init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_ecdsa_set_ctx_params(ctx, params);
}

static int p11prov_ecdsa_verify(void *ctx, const unsigned char *sig,
                                size_t siglen, const unsigned char *tbs,
                                size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    unsigned char raw[P11PROV_MAX_RAW_ECC_SIG_SIZE];
    CK_ULONG flen = p11prov_obj_get_key_size(sigctx->key);
    CK_RV ret;
    int err;

    P11PROV_debug("ecdsa verify (ctx=%p)", ctx);

    err = convert_ecdsa_der_to_raw(sig, siglen, raw, sizeof(raw), flen);
    if (err != RET_OSSL_OK) {
        return err;
    }

    ret = p11prov_sig_operate(sigctx, (void *)raw, NULL, 2 * flen, (void *)tbs,
                              tbslen);
    OPENSSL_cleanse(raw, 2 * flen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_ecdsa_digest_sign_init(void *ctx, const char *digest,
                                          void *provkey,
                                          const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug(
        "ecdsa digest sign init (ctx=%p, digest=%s, key=%p, params=%p)", ctx,
        digest ? digest : "<NULL>", provkey, params);

    /* use a default of sha2 256 if not provided */
    if (!digest) {
        digest = "sha256";
    }

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, digest);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_ecdsa_set_ctx_params(ctx, params);
}

static int p11prov_ecdsa_digest_sign_update(void *ctx,
                                            const unsigned char *data,
                                            size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("ecdsa digest sign update (ctx=%p, data=%p, datalen=%zu)",
                  ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_ecdsa_digest_sign_final(void *ctx, unsigned char *sig,
                                           size_t *siglen, size_t sigsize)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    unsigned char raw[P11PROV_MAX_RAW_ECC_SIG_SIZE];
    size_t rawlen = 0;
    int ret;

    /* the siglen might be uninitialized when called from openssl */
    *siglen = 0;

    P11PROV_debug(
        "ecdsa digest sign final (ctx=%p, sig=%p, siglen=%zu, "
        "sigsize=%zu)",
        ctx, sig, *siglen, sigsize);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }
    if (sig == NULL || sigsize == 0) {
        return p11prov_sig_digest_final(sigctx, 0, siglen, 0);
    }

    ret = p11prov_sig_digest_final(sigctx, raw, &rawlen, sizeof(raw));
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    ret = convert_ecdsa_raw_to_der(raw, rawlen, sig, siglen, sigsize);
    OPENSSL_cleanse(raw, rawlen);
    return ret;
}

static int p11prov_ecdsa_digest_verify_init(void *ctx, const char *digest,
                                            void *provkey,
                                            const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("ecdsa digest verify init (ctx=%p, key=%p, params=%p)", ctx,
                  provkey, params);

    /* use a default of sha2 256 if not provided */
    if (!digest) {
        digest = "sha256";
    }

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, digest);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_ecdsa_set_ctx_params(ctx, params);
}

static int p11prov_ecdsa_digest_verify_update(void *ctx,
                                              const unsigned char *data,
                                              size_t datalen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    P11PROV_debug("ecdsa digest verify update (ctx=%p, data=%p, datalen=%zu)",
                  ctx, data, datalen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    return p11prov_sig_digest_update(sigctx, (void *)data, datalen);
}

static int p11prov_ecdsa_digest_verify_final(void *ctx,
                                             const unsigned char *sig,
                                             size_t siglen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    unsigned char raw[P11PROV_MAX_RAW_ECC_SIG_SIZE];
    CK_ULONG flen;
    int ret;

    P11PROV_debug("ecdsa digest verify final (ctx=%p, sig=%p, siglen=%zu)", ctx,
                  sig, siglen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    flen = p11prov_obj_get_key_size(sigctx->key);

    ret = convert_ecdsa_der_to_raw(sig, siglen, raw, sizeof(raw), flen);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    ret = p11prov_sig_digest_final(sigctx, (void *)raw, NULL, 2 * flen);
    OPENSSL_cleanse(raw, 2 * flen);
    return ret;
}

static int p11prov_ecdsa_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    OSSL_PARAM *p;
    int ret;

    /* todo sig params:
        OSSL_SIGNATURE_PARAM_ALGORITHM_ID
     */

    P11PROV_debug("ecdsa get ctx params (ctx=%p, params=%p)", ctx, params);

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p) {
        const P11PROV_MECH *mech = NULL;
        CK_RV result;

        switch (sigctx->mechtype) {
        case CKM_ECDSA:
            result = p11prov_mech_by_mechanism(sigctx->digest, &mech);
            if (result != CKR_OK) {
                P11PROV_raise(
                    sigctx->provctx, result,
                    "Failed to get digest for signature algorithm ID");
                return RET_OSSL_ERR;
            }
            ret = OSSL_PARAM_set_octet_string(p, mech->der_ecdsa_algorithm_id,
                                              mech->der_ecdsa_algorithm_id_len);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
            break;
        default:
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p) {
        size_t digest_size;
        CK_RV rv;

        rv = p11prov_digest_get_digest_size(sigctx->digest, &digest_size);
        if (rv != CKR_OK) {
            P11PROV_raise(sigctx->provctx, rv, "Unavailable digest size");
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_size_t(p, digest_size);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p) {
        const char *digest;
        CK_RV rv;

        rv = p11prov_digest_get_name(sigctx->digest, &digest);
        if (rv != CKR_OK) {
            P11PROV_raise(sigctx->provctx, rv, "Unavailable digest name");
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_utf8_string(p, digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

static int p11prov_ecdsa_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("ecdsa set ctx params (ctx=%p, params=%p)", sigctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p) {
        const char *digest = NULL;
        CK_RV rv;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        P11PROV_debug("Set OSSL_SIGNATURE_PARAM_DIGEST to %s", digest);

        rv = p11prov_digest_get_by_name(digest, &sigctx->digest);
        if (rv != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_ecdsa_gettable_ctx_params(void *ctx,
                                                           void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *p11prov_ecdsa_settable_ctx_params(void *ctx,
                                                           void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_ecdsa_signature_functions[] = {
    DISPATCH_SIG_ELEM(ecdsa, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(ecdsa, SIGN_INIT, sign_init),
    DISPATCH_SIG_ELEM(ecdsa, SIGN, sign),
    DISPATCH_SIG_ELEM(ecdsa, VERIFY_INIT, verify_init),
    DISPATCH_SIG_ELEM(ecdsa, VERIFY, verify),
    DISPATCH_SIG_ELEM(ecdsa, DIGEST_SIGN_INIT, digest_sign_init),
    DISPATCH_SIG_ELEM(ecdsa, DIGEST_SIGN_UPDATE, digest_sign_update),
    DISPATCH_SIG_ELEM(ecdsa, DIGEST_SIGN_FINAL, digest_sign_final),
    DISPATCH_SIG_ELEM(ecdsa, DIGEST_VERIFY_INIT, digest_verify_init),
    DISPATCH_SIG_ELEM(ecdsa, DIGEST_VERIFY_UPDATE, digest_verify_update),
    DISPATCH_SIG_ELEM(ecdsa, DIGEST_VERIFY_FINAL, digest_verify_final),
    DISPATCH_SIG_ELEM(ecdsa, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(ecdsa, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(ecdsa, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(ecdsa, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};

DISPATCH_EDDSA_FN(newctx);
DISPATCH_EDDSA_FN(digest_sign_init);
DISPATCH_EDDSA_FN(digest_sign);
DISPATCH_EDDSA_FN(digest_verify_init);
DISPATCH_EDDSA_FN(digest_verify);
DISPATCH_EDDSA_FN(get_ctx_params);
DISPATCH_EDDSA_FN(set_ctx_params);
DISPATCH_EDDSA_FN(gettable_ctx_params);
DISPATCH_EDDSA_FN(settable_ctx_params);

static void *p11prov_eddsa_newctx(void *provctx, const char *properties)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;

    return p11prov_sig_newctx(ctx, CKM_EDDSA, properties);
}

static int p11prov_eddsa_digest_sign_init(void *ctx, const char *digest,
                                          void *provkey,
                                          const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug(
        "eddsa digest sign init (ctx=%p, digest=%s, key=%p, params=%p)", ctx,
        digest ? digest : "<NULL>", provkey, params);

    if (digest != NULL && digest[0] != '\0') {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
        return RET_OSSL_ERR;
    }

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, digest);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_eddsa_set_ctx_params(ctx, params);
}

static int p11prov_eddsa_digest_sign(void *ctx, unsigned char *sig,
                                     size_t *siglen, size_t sigsize,
                                     const unsigned char *tbs, size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("eddsa digest sign (ctx=%p, tbs=%p, tbslen=%zu)", ctx, tbs,
                  tbslen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    ret =
        p11prov_sig_operate(sigctx, sig, siglen, sigsize, (void *)tbs, tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_eddsa_digest_verify_init(void *ctx, const char *digest,
                                            void *provkey,
                                            const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("eddsa digest verify init (ctx=%p, key=%p, params=%p)", ctx,
                  provkey, params);

    if (digest != NULL && digest[0] != '\0') {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
        return RET_OSSL_ERR;
    }

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, digest);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_eddsa_set_ctx_params(ctx, params);
}

static int p11prov_eddsa_digest_verify(void *ctx, const unsigned char *sig,
                                       size_t siglen, const unsigned char *tbs,
                                       size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("eddsa digest verify (ctx=%p, tbs=%p, tbslen=%zu)", ctx, tbs,
                  tbslen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_sig_operate(sigctx, (void *)sig, NULL, siglen, (void *)tbs,
                              tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_eddsa_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    OSSL_PARAM *p;
    int ret = RET_OSSL_OK;

    /* todo sig params:
        OSSL_SIGNATURE_PARAM_ALGORITHM_ID
     */

    P11PROV_debug("eddsa get ctx params (ctx=%p, params=%p)", ctx, params);

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p) {
        if (sigctx->mechtype != CKM_EDDSA) {
            return RET_OSSL_ERR;
        }
        CK_ULONG size = p11prov_obj_get_key_bit_size(sigctx->key);
        switch (size) {
        case ED25519_BIT_SIZE:
            ret = OSSL_PARAM_set_octet_string(p, der_ed25519_algorithm_id,
                                              sizeof(der_ed25519_algorithm_id));
            break;
        case ED448_BIT_SIZE:
            ret = OSSL_PARAM_set_octet_string(p, der_ed448_algorithm_id,
                                              sizeof(der_ed448_algorithm_id));
            break;
        default:
            return RET_OSSL_ERR;
        }
    }

    return ret;
}

#ifndef OSSL_SIGNATURE_PARAM_INSTANCE
#define OSSL_SIGNATURE_PARAM_INSTANCE "instance"
#endif
#ifndef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
#define OSSL_SIGNATURE_PARAM_CONTEXT_STRING "context-string"
#endif
static int p11prov_eddsa_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("eddsa set ctx params (ctx=%p, params=%p)", sigctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_INSTANCE);
    if (p) {
        const char *instance = NULL;
        bool matched = false;
        CK_ULONG size;

        ret = OSSL_PARAM_get_utf8_string_ptr(p, &instance);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        P11PROV_debug("Set OSSL_SIGNATURE_PARAM_INSTANCE to %s", instance);

        size = p11prov_obj_get_key_bit_size(sigctx->key);
        if (size != ED25519_BIT_SIZE && size != ED448_BIT_SIZE) {
            P11PROV_raise(sigctx->provctx, CKR_KEY_TYPE_INCONSISTENT,
                          "Invalid EdDSA key size %lu", size);
            return RET_OSSL_ERR;
        }
        if (size == ED25519_BIT_SIZE) {
            if (OPENSSL_strcasecmp(instance, "Ed25519") == 0) {
                matched = true;
                sigctx->use_eddsa_params = CK_FALSE;
            } else if (OPENSSL_strcasecmp(instance, "Ed25519ph") == 0) {
                matched = true;
                sigctx->use_eddsa_params = CK_TRUE;
                sigctx->eddsa_params.phFlag = CK_TRUE;
            } else if (OPENSSL_strcasecmp(instance, "Ed25519ctx") == 0) {
                matched = true;
                sigctx->use_eddsa_params = CK_TRUE;
                sigctx->eddsa_params.phFlag = CK_FALSE;
            }
        } else if (size == ED448_BIT_SIZE) {
            if (OPENSSL_strcasecmp(instance, "Ed448") == 0) {
                matched = true;
                sigctx->use_eddsa_params = CK_TRUE;
                sigctx->eddsa_params.phFlag = CK_FALSE;
            } else if (OPENSSL_strcasecmp(instance, "Ed448ph") == 0) {
                matched = true;
                sigctx->use_eddsa_params = CK_TRUE;
                sigctx->eddsa_params.phFlag = CK_TRUE;
            }
        }
        if (!matched) {
            P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                          "Invalid instance");
            return RET_OSSL_ERR;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p) {
        size_t datalen;
        OPENSSL_clear_free(sigctx->eddsa_params.pContextData,
                           sigctx->eddsa_params.ulContextDataLen);
        sigctx->eddsa_params.pContextData = NULL;
        ret = OSSL_PARAM_get_octet_string(
            p, (void **)&sigctx->eddsa_params.pContextData, 0, &datalen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        sigctx->eddsa_params.ulContextDataLen = datalen;
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_eddsa_gettable_ctx_params(void *ctx,
                                                           void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *p11prov_eddsa_settable_ctx_params(void *ctx,
                                                           void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_eddsa_signature_functions[] = {
    DISPATCH_SIG_ELEM(eddsa, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(eddsa, DIGEST_SIGN_INIT, digest_sign_init),
    DISPATCH_SIG_ELEM(eddsa, DIGEST_SIGN, digest_sign),
    DISPATCH_SIG_ELEM(eddsa, DIGEST_VERIFY_INIT, digest_verify_init),
    DISPATCH_SIG_ELEM(eddsa, DIGEST_VERIFY, digest_verify),
    DISPATCH_SIG_ELEM(eddsa, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(eddsa, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(eddsa, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(eddsa, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};

CK_MECHANISM_TYPE p11prov_digest_to_rsapss_mech(CK_MECHANISM_TYPE digest)
{
    const P11PROV_MECH *mech = NULL;
    CK_RV rv;

    rv = p11prov_mech_by_mechanism(digest, &mech);
    if (rv == CKR_OK) {
        return mech->pkcs_pss;
    }

    return CK_UNAVAILABLE_INFORMATION;
}
