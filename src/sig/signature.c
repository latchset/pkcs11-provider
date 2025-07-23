/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "sig/internal.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/sha.h"

/* clang-format off */
#define DEFINE_DER_DIGESTINFO(name, alg_id, digest_size) \
    static const unsigned char der_digestinfo_##name[] = { \
        DER_SEQUENCE, DER_NIST_HASHALGS_LEN+9+digest_size, \
          DER_SEQUENCE, DER_NIST_HASHALGS_LEN+5, \
            DER_OBJECT, DER_NIST_HASHALGS_LEN+1, DER_NIST_HASHALGS, alg_id, \
            DER_NULL, 0, \
          DER_OCTET_STRING, digest_size \
    };

#define DEFINE_DER_RSA_PSS_PARAMS(name, obj_base, obj_alg, obj_len, digest_len) \
    static const unsigned char der_rsa_pss_params_##name[] = { \
        DER_SEQUENCE, 25 + DER_RSASSA_PSS_LEN + DER_MGF1_LEN + obj_len + obj_len, \
            DER_OBJECT, DER_RSASSA_PSS_LEN, DER_RSASSA_PSS, \
            DER_SEQUENCE, 21 + DER_MGF1_LEN + obj_len + obj_len, \
                0xA0, 4 + obj_len, \
                    DER_SEQUENCE, 2 + obj_len, \
                        DER_OBJECT, obj_len, obj_base, obj_alg, \
                0xA1, 8 + DER_MGF1_LEN + obj_len, \
                    DER_SEQUENCE, 6 + DER_MGF1_LEN + obj_len, \
                        DER_OBJECT, DER_MGF1_LEN, DER_MGF1, \
                        DER_SEQUENCE, 2 + obj_len, \
                            DER_OBJECT, obj_len, obj_base, obj_alg, \
                0xA2, 3, \
                    DER_INTEGER, 1, digest_len, \
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
    DEFINE_DER_DIGESTINFO(sha##bits, digestinfo_algid, bits/8) \
    DEFINE_DER_RSA_PSS_PARAMS(sha##bits, DER_NIST_HASHALGS, digestinfo_algid, \
        DER_NIST_HASHALGS_LEN+1, SHA##bits##_DIGEST_LENGTH)

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
    DEFINE_DER_DIGESTINFO(sha3_##bits, digestinfo_algid, bits/8) \
    DEFINE_DER_RSA_PSS_PARAMS(sha3_##bits, DER_NIST_HASHALGS, digestinfo_algid, \
        DER_NIST_HASHALGS_LEN+1, SHA##bits##_DIGEST_LENGTH)

/* ... pkcs(1) 10 (id-RSASSA-PSS) */
#define DER_RSASSA_PSS DER_RSADSI_PKCS1, 0x0A
#define DER_RSASSA_PSS_LEN (DER_RSADSI_PKCS1_LEN + 1)

/* ... pkcs(1) 8 (id-RSASSA-PSS) */
#define DER_MGF1 DER_RSADSI_PKCS1, 0x08
#define DER_MGF1_LEN (DER_RSADSI_PKCS1_LEN + 1)

static const unsigned char der_rsa_sha1[] = {
    DER_SEQUENCE, DER_RSADSI_PKCS1_LEN+5,
        DER_OBJECT, DER_RSADSI_PKCS1_LEN+1, DER_RSADSI_PKCS1, 0x05,
        DER_NULL, 0
};

static const unsigned char der_ecdsa_sha1[] = {
    DER_SEQUENCE, DER_ANSIX962_SIG_LEN+3,
        DER_OBJECT, DER_ANSIX962_SIG_LEN+1, DER_ANSIX962_SIG, 0x01
};

/* iso(1) org(3) oiw(14) secsig(3) algorithms(2) */
#define DER_SECSIG_ALGO 1 * 40 + 3, 14, 3, 2
#define DER_SECSIG_ALGO_LEN 4
/* iso(1) org(3) oiw(14) secsig(3) algorithms(2) hashAlgorithmIdentifier(26) */
#define ID_SHA1 DER_SECSIG_ALGO, 26
#define ID_SHA1_LEN DER_SECSIG_ALGO_LEN+1
static const unsigned char der_digestinfo_sha1[] = {
    DER_SEQUENCE, 0x0d + SHA_DIGEST_LENGTH,
        DER_SEQUENCE, 0x09,
        DER_OBJECT, ID_SHA1_LEN, ID_SHA1,
        DER_NULL, 0x00,
    DER_OCTET_STRING, SHA_DIGEST_LENGTH
};

DEFINE_DER_RSA_PSS_PARAMS(sha1, DER_SECSIG_ALGO, 26, DER_SECSIG_ALGO_LEN, SHA_DIGEST_LENGTH);
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
        .digest = CKM_SHA##bits, \
        .pkcs_mech = CKM_SHA##bits##_RSA_PKCS, \
        .pkcs_pss = CKM_SHA##bits##_RSA_PKCS_PSS, \
        .ecdsa_mech = CKM_ECDSA_SHA##bits, \
        .mgf = CKG_MGF1_SHA##bits, \
        .der_rsa_algorithm_id = der_rsa_sha##bits, \
        .der_rsa_algorithm_id_len = sizeof(der_rsa_sha##bits), \
        .der_ecdsa_algorithm_id = der_ecdsa_sha##bits, \
        .der_ecdsa_algorithm_id_len = sizeof(der_ecdsa_sha##bits), \
        .der_digestinfo = der_digestinfo_sha##bits, \
        .der_digestinfo_len = sizeof(der_digestinfo_sha##bits), \
        .der_rsa_pss_params = der_rsa_pss_params_sha##bits, \
        .der_rsa_pss_params_len = sizeof(der_rsa_pss_params_sha##bits), \
    }
#define DM_ELEM_SHA3(bits) \
    { \
        .digest = CKM_SHA3_##bits, \
        .pkcs_mech = CKM_SHA3_##bits##_RSA_PKCS, \
        .pkcs_pss = CKM_SHA3_##bits##_RSA_PKCS_PSS, \
        .ecdsa_mech = CKM_ECDSA_SHA3_##bits, \
        .mgf = CKG_MGF1_SHA3_##bits, \
        .der_rsa_algorithm_id = der_rsa_sha3_##bits, \
        .der_rsa_algorithm_id_len = sizeof(der_rsa_sha3_##bits), \
        .der_ecdsa_algorithm_id = der_ecdsa_sha3_##bits, \
        .der_ecdsa_algorithm_id_len = sizeof(der_ecdsa_sha3_##bits), \
        .der_digestinfo = der_digestinfo_sha3_##bits, \
        .der_digestinfo_len = sizeof(der_digestinfo_sha3_##bits), \
        .der_rsa_pss_params = der_rsa_pss_params_sha3_##bits, \
        .der_rsa_pss_params_len = sizeof(der_rsa_pss_params_sha3_##bits), \
    }

static const P11PROV_MECH mech_map[] = {
    DM_ELEM_SHA3(256),
    DM_ELEM_SHA3(512),
    DM_ELEM_SHA3(384),
    DM_ELEM_SHA3(224),
    DM_ELEM_SHA(256),
    DM_ELEM_SHA(512),
    DM_ELEM_SHA(384),
    DM_ELEM_SHA(224),
    {
        CKM_SHA_1,
        CKM_SHA1_RSA_PKCS,
        CKM_SHA1_RSA_PKCS_PSS,
        CKM_ECDSA_SHA1,
        CKG_MGF1_SHA1,
        der_rsa_sha1,
        sizeof(der_rsa_sha1),
        der_ecdsa_sha1,
        sizeof(der_ecdsa_sha1),
        der_digestinfo_sha1,
        sizeof(der_digestinfo_sha1),
        der_rsa_pss_params_sha1,
        sizeof(der_rsa_pss_params_sha1),
    },
    { CK_UNAVAILABLE_INFORMATION, 0, 0, 0, 0, 0, 0, 0, 0 },
};

P11PROV_SIG_CTX *p11prov_sig_newctx(P11PROV_CTX *ctx, CK_MECHANISM_TYPE type,
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
    sigctx->mechanism.mechanism = CK_UNAVAILABLE_INFORMATION;

    return sigctx;
}

void *p11prov_sig_dupctx(void *ctx)
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

    if (sigctx->signature) {
        newctx->signature =
            OPENSSL_memdup(sigctx->signature, sigctx->signature_len);
        if (newctx->signature == NULL) {
            p11prov_sig_freectx(newctx);
            return NULL;
        }
        newctx->signature_len = sigctx->signature_len;
    }

    newctx->digest_op = sigctx->digest_op;

    if (sigctx->fallback_digest) {
        int err;
        newctx->fallback_digest = EVP_MD_CTX_new();
        if (!newctx->fallback_digest) {
            p11prov_sig_freectx(newctx);
            return NULL;
        }
        err = EVP_MD_CTX_copy_ex(newctx->fallback_digest,
                                 sigctx->fallback_digest);
        if (err != RET_OSSL_OK) {
            p11prov_sig_freectx(newctx);
            return NULL;
        }
    }

    newctx->fallback_operate = sigctx->fallback_operate;

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

void p11prov_sig_freectx(void *ctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    if (sigctx == NULL) {
        return;
    }

    OPENSSL_clear_free(sigctx->eddsa_params.pContextData,
                       sigctx->eddsa_params.ulContextDataLen);
    OPENSSL_free(sigctx->signature);
    p11prov_return_session(sigctx->session);
    EVP_MD_CTX_free(sigctx->fallback_digest);
    p11prov_obj_free(sigctx->key);
    OPENSSL_free(sigctx->properties);
    OPENSSL_clear_free(sigctx, sizeof(P11PROV_SIG_CTX));
}

CK_RV p11prov_mech_by_mechanism(CK_MECHANISM_TYPE mechanism,
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

CK_RV p11prov_mech_by_mgf(CK_RSA_PKCS_MGF_TYPE mgf, const P11PROV_MECH **mech)
{
    for (int i = 0; mech_map[i].digest != CK_UNAVAILABLE_INFORMATION; i++) {
        if (mech_map[i].mgf == mgf) {
            *mech = &mech_map[i];
            return CKR_OK;
        }
    }
    return CKR_MECHANISM_INVALID;
}

CK_RV p11prov_sig_op_init(void *ctx, void *provkey, CK_FLAGS operation,
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

    class = p11prov_obj_get_class(key);
    switch (operation) {
    case CKF_SIGN:
        if (class != CKO_PRIVATE_KEY) {
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        break;
    case CKF_VERIFY:
        if (class != CKO_PUBLIC_KEY) {
            key = p11prov_obj_get_associated(key);
            if (!key || p11prov_obj_get_class(key) != CKO_PUBLIC_KEY) {
                return CKR_KEY_TYPE_INCONSISTENT;
            }
        }
        break;
    default:
        return CKR_GENERAL_ERROR;
    }
    sigctx->key = p11prov_obj_ref(key);
    if (sigctx->key == NULL) {
        return CKR_KEY_NEEDED;
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

    sigctx->fallback_digest = EVP_MD_CTX_new();
    if (!sigctx->fallback_digest) {
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

    err = EVP_DigestInit_ex2(sigctx->fallback_digest, md, pparams);
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
    CK_SESSION_HANDLE sess;
    CK_SLOT_ID slotid;
    bool reqlogin = false;
    bool always_auth = false;
    CK_RV ret;

    P11PROV_debug("called (sigctx=%p, digest_op=%s)", sigctx,
                  digest_op ? "true" : "false");

    P11PROV_debug_mechanism(sigctx->provctx,
                            p11prov_obj_get_slotid(sigctx->key),
                            sigctx->mechanism.mechanism);

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

    if (sigctx->operation == CKF_SIGN) {
        reqlogin = true;
    }

    ret = p11prov_get_session(sigctx->provctx, &slotid, NULL, NULL,
                              sigctx->mechanism.mechanism, NULL, NULL, reqlogin,
                              false, &session);
    switch (ret) {
    case CKR_OK:
        sess = p11prov_session_handle(session);

        if (sigctx->operation == CKF_SIGN) {
            ret = p11prov_SignInit(sigctx->provctx, sess, &sigctx->mechanism,
                                   handle);
        } else {
            ret = p11prov_VerifyInit(sigctx->provctx, sess, &sigctx->mechanism,
                                     handle);
        }
        break;
    case CKR_MECHANISM_INVALID:
        if (!digest_op || sigctx->mechanism.mechanism == sigctx->mechtype) {
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

CK_RV p11prov_sig_operate(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                          size_t *siglen, size_t sigsize, unsigned char *tbs,
                          size_t tbslen)
{
    P11PROV_SESSION *session;
    CK_SESSION_HANDLE sess;
    CK_ULONG sig_size = sigsize;
    CK_RV ret;

    if (sig == NULL) {
        return CKR_ARGUMENTS_BAD;
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
    return ret;
}

int p11prov_sig_digest_update(P11PROV_SIG_CTX *sigctx, unsigned char *data,
                              size_t datalen)
{
    CK_SESSION_HANDLE sess;
    CK_RV ret;

    if (!sigctx->fallback_digest && !sigctx->session) {
        ret = p11prov_sig_operate_init(sigctx, true, &sigctx->session);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
    }

    if (sigctx->fallback_digest) {
        return EVP_DigestUpdate(sigctx->fallback_digest, data, datalen);
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
    const char *digest_name = NULL;
    int err;
    CK_RV ret;

    err = EVP_DigestFinal_ex(sigctx->fallback_digest, digest, &digest_len);
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

    ret = p11prov_digest_get_name(sigctx->digest, &digest_name);
    if (ret != CKR_OK) {
        P11PROV_raise(sigctx->provctx, ret, "Failed to get digest name");
        goto done;
    }

    ret = p11prov_sig_op_init(subctx, sigctx->key, sigctx->operation,
                              digest_name);
    if (ret != CKR_OK) {
        P11PROV_raise(sigctx->provctx, ret, "Failed to setup sigver fallback");
        goto done;
    }

    if (sigctx->fallback_operate) {
        ret = sigctx->fallback_operate(subctx, sig, siglen, sigsize, digest,
                                       mdsize);
    } else {
        ret = p11prov_sig_operate(subctx, sig, siglen, sigsize, digest, mdsize);
    }
    if (ret != CKR_OK) {
        P11PROV_raise(sigctx->provctx, ret, "Failure in sigver fallback");
        goto done;
    }

done:
    p11prov_sig_freectx(subctx);
    return ret;
}

int p11prov_sig_digest_final(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                             size_t *siglen, size_t sigsize)
{
    CK_SESSION_HANDLE sess;
    CK_ULONG sig_size = sigsize;
    int result = RET_OSSL_ERR;
    CK_RV ret;

    if (sig == NULL) {
        goto done;
    }
    if (sigctx->operation == CKF_VERIFY && sigsize == 0) {
        goto done;
    }

    if (sigctx->fallback_digest) {
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
