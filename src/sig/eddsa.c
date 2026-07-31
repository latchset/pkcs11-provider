/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "sig/internal.h"
#include <string.h>
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/err.h"

DISPATCH_EDDSA_FN(newctx);
DISPATCH_EDDSA_FN(digest_sign_init);
DISPATCH_EDDSA_FN(sign);
DISPATCH_EDDSA_FN(digest_verify_init);
DISPATCH_EDDSA_FN(verify);
DISPATCH_EDDSA_FN(get_ctx_params);
DISPATCH_EDDSA_FN(set_ctx_params);
DISPATCH_EDDSA_FN(gettable_ctx_params);
DISPATCH_EDDSA_FN(settable_ctx_params);

static CK_RV p11prov_eddsa_set_mechanism(P11PROV_SIG_CTX *sigctx)
{
    sigctx->mechanism.mechanism = sigctx->mechtype;
    sigctx->mechanism.pParameter = NULL;
    sigctx->mechanism.ulParameterLen = 0;

    switch (sigctx->mechtype) {
    case CKM_EDDSA:
        if (sigctx->use_eddsa_params == CK_TRUE) {
            sigctx->mechanism.pParameter = &sigctx->eddsa_params;
            sigctx->mechanism.ulParameterLen = sizeof(sigctx->eddsa_params);
        }
        break;
    default:
        return CKR_DATA_INVALID;
    }

    return CKR_OK;
}

static CK_RV p11prov_eddsa_sig_size(P11PROV_SIG_CTX *sigctx, size_t *siglen)
{
    CK_KEY_TYPE type = p11prov_obj_get_key_type(sigctx->key);
    if (type == CKK_EC_EDWARDS) {
        CK_ULONG size = p11prov_obj_get_key_size(sigctx->key);
        if (size == ED25519_BYTE_SIZE) {
            *siglen = ED25519_SIG_SIZE;
            return CKR_OK;
        } else if (size == ED448_BYTE_SIZE) {
            *siglen = ED448_SIG_SIZE;
            return CKR_OK;
        } else {
            return CKR_KEY_TYPE_INCONSISTENT;
        }
    }
    return CKR_KEY_INDIGESTIBLE;
}

static void *p11prov_eddsa_newctx(void *provctx, const char *properties)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;

    return p11prov_sig_newctx(ctx, CKM_EDDSA, properties);
}

static CK_RV p11prov_eddsa_init_instance(void *vctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)vctx;
    CK_ULONG size;
    CK_RV ret;

    if (sigctx->instance != ED_Unset) {
        return CKR_OK;
    }

    size = p11prov_obj_get_key_bit_size(sigctx->key);
    if (size == ED25519_BIT_SIZE) {
        sigctx->instance = ED_25519;
        ret = CKR_OK;
    } else if (size == ED448_BIT_SIZE) {
        sigctx->instance = ED_448;
        ret = CKR_OK;
    } else {
        ret = CKR_KEY_TYPE_INCONSISTENT;
        P11PROV_raise(sigctx->provctx, ret, "Invalid EdDSA key size %lu", size);
    }
    return ret;
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

    ret = p11prov_eddsa_init_instance(ctx);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_eddsa_set_ctx_params(ctx, params);
}

static int p11prov_eddsa_sign(void *ctx, unsigned char *sig, size_t *siglen,
                              size_t sigsize, const unsigned char *tbs,
                              size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("eddsa sign (ctx=%p, tbs=%p, tbslen=%zu)", ctx, tbs, tbslen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    if (sig == NULL) {
        if (siglen == 0) {
            return RET_OSSL_ERR;
        }
        ret = p11prov_eddsa_sig_size(sigctx, siglen);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        return RET_OSSL_OK;
    }

    ret = p11prov_eddsa_set_mechanism(sigctx);
    if (ret != CKR_OK) {
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

    ret = p11prov_eddsa_init_instance(ctx);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_eddsa_set_ctx_params(ctx, params);
}

static int p11prov_eddsa_verify(void *ctx, const unsigned char *sig,
                                size_t siglen, const unsigned char *tbs,
                                size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("eddsa verify (ctx=%p, tbs=%p, tbslen=%zu)", ctx, tbs,
                  tbslen);

    if (sigctx == NULL) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_eddsa_set_mechanism(sigctx);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    ret = p11prov_sig_operate(sigctx, (void *)sig, NULL, siglen, (void *)tbs,
                              tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

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

static int p11prov_eddsa_instance_to_params(void *vctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)vctx;

    switch (sigctx->instance) {
    case ED_25519:
        sigctx->use_eddsa_params = CK_FALSE;
        break;
    case ED_25519_ph:
        sigctx->use_eddsa_params = CK_TRUE;
        sigctx->eddsa_params.phFlag = CK_TRUE;
        break;
    case ED_25519_ctx:
        sigctx->use_eddsa_params = CK_TRUE;
        sigctx->eddsa_params.phFlag = CK_FALSE;
        break;
    case ED_448:
        sigctx->use_eddsa_params = CK_TRUE;
        sigctx->eddsa_params.phFlag = CK_FALSE;
        break;
    case ED_448_ph:
        sigctx->use_eddsa_params = CK_TRUE;
        sigctx->eddsa_params.phFlag = CK_TRUE;
        break;
    default:
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
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

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_INSTANCE);
    if (p) {
        const char *instance;
        ret = OSSL_PARAM_get_utf8_string_ptr(p, &instance);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        P11PROV_debug("Set OSSL_SIGNATURE_PARAM_INSTANCE to %s", instance);
        if (OPENSSL_strcasecmp(instance, "Ed25519") == 0) {
            sigctx->instance = ED_25519;
        } else if (OPENSSL_strcasecmp(instance, "Ed25519ph") == 0) {
            sigctx->instance = ED_25519_ph;
        } else if (OPENSSL_strcasecmp(instance, "Ed25519ctx") == 0) {
            sigctx->instance = ED_25519_ctx;
        } else if (OPENSSL_strcasecmp(instance, "Ed448") == 0) {
            sigctx->instance = ED_448;
        } else if (OPENSSL_strcasecmp(instance, "Ed448ph") == 0) {
            sigctx->instance = ED_448_ph;
        } else {
            P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                          "Invalid instance %s", instance);
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

    return p11prov_eddsa_instance_to_params(ctx);
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

static int p11prov_ed25519_digest_sign_init(void *vctx, const char *digest,
                                            void *provkey,
                                            const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)vctx;
    sigctx->instance = ED_25519;
    return p11prov_eddsa_digest_sign_init(vctx, digest, provkey, params);
}

static int p11prov_ed25519_digest_verify_init(void *vctx, const char *digest,
                                              void *provkey,
                                              const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)vctx;
    sigctx->instance = ED_25519;
    return p11prov_eddsa_digest_verify_init(vctx, digest, provkey, params);
}

static int p11prov_ed448_digest_sign_init(void *vctx, const char *digest,
                                          void *provkey,
                                          const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)vctx;
    sigctx->instance = ED_448;
    return p11prov_eddsa_digest_sign_init(vctx, digest, provkey, params);
}

static int p11prov_ed448_digest_verify_init(void *vctx, const char *digest,
                                            void *provkey,
                                            const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)vctx;
    sigctx->instance = ED_448;
    return p11prov_eddsa_digest_verify_init(vctx, digest, provkey, params);
}

#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
static int p11prov_ed25519_sign_message_init(void *vctx, void *provkey,
                                             const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)vctx;
    sigctx->instance = ED_25519;
    return p11prov_eddsa_digest_sign_init(vctx, NULL, provkey, params);
}

static int p11prov_ed25519ph_sign_message_init(void *vctx, void *provkey,
                                               const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)vctx;
    sigctx->instance = ED_25519_ph;
    return p11prov_eddsa_digest_sign_init(vctx, NULL, provkey, params);
}

static int p11prov_ed25519ctx_sign_message_init(void *vctx, void *provkey,
                                                const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)vctx;
    sigctx->instance = ED_25519_ctx;
    return p11prov_eddsa_digest_sign_init(vctx, NULL, provkey, params);
}

static int p11prov_ed448_sign_message_init(void *vctx, void *provkey,
                                           const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)vctx;
    sigctx->instance = ED_448;
    return p11prov_eddsa_digest_sign_init(vctx, NULL, provkey, params);
}

static int p11prov_ed448ph_sign_message_init(void *vctx, void *provkey,
                                             const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)vctx;
    sigctx->instance = ED_448_ph;
    return p11prov_eddsa_digest_sign_init(vctx, NULL, provkey, params);
}

static int p11prov_ed25519_verify_message_init(void *vctx, void *provkey,
                                               const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)vctx;
    sigctx->instance = ED_25519;
    return p11prov_eddsa_digest_verify_init(vctx, NULL, provkey, params);
}

static int p11prov_ed25519ph_verify_message_init(void *vctx, void *provkey,
                                                 const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)vctx;
    sigctx->instance = ED_25519_ph;
    return p11prov_eddsa_digest_verify_init(vctx, NULL, provkey, params);
}

static int p11prov_ed25519ctx_verify_message_init(void *vctx, void *provkey,
                                                  const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)vctx;
    sigctx->instance = ED_25519_ctx;
    return p11prov_eddsa_digest_verify_init(vctx, NULL, provkey, params);
}

static int p11prov_ed448_verify_message_init(void *vctx, void *provkey,
                                             const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)vctx;
    sigctx->instance = ED_448;
    return p11prov_eddsa_digest_verify_init(vctx, NULL, provkey, params);
}

static int p11prov_ed448ph_verify_message_init(void *vctx, void *provkey,
                                               const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)vctx;
    sigctx->instance = ED_448_ph;
    return p11prov_eddsa_digest_verify_init(vctx, NULL, provkey, params);
}

static const char **p11prov_ed25519_query_key_types(void)
{
    static const char *keytypes[] = { P11PROV_NAME_ED25519, NULL };

    return keytypes;
}

static const char **p11prov_ed448_query_key_types(void)
{
    static const char *keytypes[] = { P11PROV_NAME_ED448, NULL };

    return keytypes;
}
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */

const OSSL_DISPATCH p11prov_ed25519_signature_functions[] = {
    DISPATCH_SIG_ELEM(eddsa, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(ed25519, DIGEST_SIGN_INIT, digest_sign_init),
    DISPATCH_SIG_ELEM(ed25519, DIGEST_VERIFY_INIT, digest_verify_init),
    DISPATCH_SIG_ELEM(eddsa, DIGEST_SIGN, sign),
    DISPATCH_SIG_ELEM(eddsa, DIGEST_VERIFY, verify),
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
    DISPATCH_SIG_ELEM(ed25519, SIGN_MESSAGE_INIT, sign_message_init),
    DISPATCH_SIG_ELEM(ed25519, VERIFY_MESSAGE_INIT, verify_message_init),
    DISPATCH_SIG_ELEM(eddsa, SIGN, sign),
    DISPATCH_SIG_ELEM(eddsa, VERIFY, verify),
    DISPATCH_SIG_ELEM(ed25519, QUERY_KEY_TYPES, query_key_types),
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */
    DISPATCH_SIG_ELEM(eddsa, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(eddsa, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(eddsa, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(eddsa, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_ed448_signature_functions[] = {
    DISPATCH_SIG_ELEM(eddsa, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(ed448, DIGEST_SIGN_INIT, digest_sign_init),
    DISPATCH_SIG_ELEM(ed448, DIGEST_VERIFY_INIT, digest_verify_init),
    DISPATCH_SIG_ELEM(eddsa, DIGEST_SIGN, sign),
    DISPATCH_SIG_ELEM(eddsa, DIGEST_VERIFY, verify),
#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
    DISPATCH_SIG_ELEM(ed448, SIGN_MESSAGE_INIT, sign_message_init),
    DISPATCH_SIG_ELEM(ed448, VERIFY_MESSAGE_INIT, verify_message_init),
    DISPATCH_SIG_ELEM(eddsa, SIGN, sign),
    DISPATCH_SIG_ELEM(eddsa, VERIFY, verify),
    DISPATCH_SIG_ELEM(ed448, QUERY_KEY_TYPES, query_key_types),
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */
    DISPATCH_SIG_ELEM(eddsa, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(eddsa, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(eddsa, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(eddsa, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};

#if defined(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT)
const OSSL_DISPATCH p11prov_ed25519ph_signature_functions[] = {
    DISPATCH_SIG_ELEM(eddsa, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(ed25519ph, SIGN_MESSAGE_INIT, sign_message_init),
    DISPATCH_SIG_ELEM(ed25519ph, VERIFY_MESSAGE_INIT, verify_message_init),
    DISPATCH_SIG_ELEM(eddsa, SIGN, sign),
    DISPATCH_SIG_ELEM(eddsa, VERIFY, verify),
    DISPATCH_SIG_ELEM(ed25519, QUERY_KEY_TYPES, query_key_types),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_ed25519ctx_signature_functions[] = {
    DISPATCH_SIG_ELEM(eddsa, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(ed25519ctx, SIGN_MESSAGE_INIT, sign_message_init),
    DISPATCH_SIG_ELEM(ed25519ctx, VERIFY_MESSAGE_INIT, verify_message_init),
    DISPATCH_SIG_ELEM(eddsa, SIGN, sign),
    DISPATCH_SIG_ELEM(eddsa, VERIFY, verify),
    DISPATCH_SIG_ELEM(ed25519, QUERY_KEY_TYPES, query_key_types),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_ed448ph_signature_functions[] = {
    DISPATCH_SIG_ELEM(eddsa, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(ed448ph, SIGN_MESSAGE_INIT, sign_message_init),
    DISPATCH_SIG_ELEM(ed448ph, VERIFY_MESSAGE_INIT, verify_message_init),
    DISPATCH_SIG_ELEM(eddsa, SIGN, sign),
    DISPATCH_SIG_ELEM(eddsa, VERIFY, verify),
    DISPATCH_SIG_ELEM(ed448, QUERY_KEY_TYPES, query_key_types),
    { 0, NULL },
};
#endif /* OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT */
