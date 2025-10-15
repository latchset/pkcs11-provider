/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "obj/internal.h"
#include "platform/endian.h"

#define MAX_KEY_ATTRS 2
static CK_RV get_all_from_cert(P11PROV_OBJ *crt, CK_ATTRIBUTE *attrs, int num)
{
    OSSL_PARAM params[MAX_KEY_ATTRS + 1] = { 0 };
    CK_ATTRIBUTE_TYPE types[MAX_KEY_ATTRS];
    CK_ATTRIBUTE *type;
    CK_ATTRIBUTE *value;
    const unsigned char *val;
    X509 *x509 = NULL;
    EVP_PKEY *pkey;
    int attrnum = 0;
    int ret;
    CK_RV rv;

    /* if CKA_CERTIFICATE_TYPE is not present assume CKC_X_509 */
    type = p11prov_obj_get_attr(crt, CKA_CERTIFICATE_TYPE);
    if (type) {
        CK_CERTIFICATE_TYPE crt_type = CKC_X_509;
        if (type->ulValueLen != sizeof(CK_CERTIFICATE_TYPE)
            || memcmp(type->pValue, &crt_type, type->ulValueLen) != 0) {
            return CKR_OBJECT_HANDLE_INVALID;
        }
    }

    value = p11prov_obj_get_attr(crt, CKA_VALUE);
    if (!value) {
        return CKR_GENERAL_ERROR;
    }

    val = value->pValue;
    x509 = d2i_X509(NULL, &val, value->ulValueLen);
    if (!x509) {
        return CKR_GENERAL_ERROR;
    }

    pkey = X509_get0_pubkey(x509);
    if (!pkey) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    if (EVP_PKEY_is_a(pkey, "RSA")) {
        for (int i = 0; i < num; i++) {
            switch (attrs[i].type) {
            case CKA_MODULUS:
                types[attrnum] = CKA_MODULUS;
                params[attrnum] =
                    OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0);
                attrnum++;
                break;
            case CKA_PUBLIC_EXPONENT:
                types[attrnum] = CKA_PUBLIC_EXPONENT;
                params[attrnum] =
                    OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0);
                attrnum++;
                break;
            }
        }
    } else if (EVP_PKEY_is_a(pkey, "EC")) {
        for (int i = 0; i < num; i++) {
            switch (attrs[i].type) {
            case CKA_P11PROV_CURVE_NAME:
                types[attrnum] = CKA_P11PROV_CURVE_NAME;
                params[attrnum] = OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0);
                attrnum++;
                break;
            case CKA_P11PROV_PUB_KEY:
                types[attrnum] = CKA_P11PROV_PUB_KEY;
                params[attrnum] = OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_PUB_KEY, NULL, 0);
                attrnum++;
                break;
            }
        }
    } else if (EVP_PKEY_is_a(pkey, ED25519) || EVP_PKEY_is_a(pkey, ED448)) {
        for (int i = 0; i < num; i++) {
            switch (attrs[i].type) {
            case CKA_P11PROV_PUB_KEY:
                types[attrnum] = CKA_P11PROV_PUB_KEY;
                params[attrnum] = OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_PUB_KEY, NULL, 0);
                attrnum++;
                break;
            }
        }
    } else {
        rv = CKR_OBJECT_HANDLE_INVALID;
        goto done;
    }
    if (attrnum == 0) {
        rv = CKR_ARGUMENTS_BAD;
        goto done;
    }
    params[attrnum] = OSSL_PARAM_construct_end();

    ret = EVP_PKEY_get_params(pkey, params);
    if (ret != RET_OSSL_OK) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }
    ret = OSSL_PARAM_modified(params);
    if (ret != RET_OSSL_OK) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    for (int i = 0; i < attrnum; i++) {
        if (params[i].return_size == 0) {
            rv = CKR_GENERAL_ERROR;
            goto done;
        }
        /* allocate one more byte as null terminator to avoid buffer overruns
         * when this is converted to the OSSL_PARAM as utf8 string */
        params[i].data = OPENSSL_zalloc(params[i].return_size + 1);
        if (!params[i].data) {
            rv = CKR_HOST_MEMORY;
            goto done;
        }
        params[i].data_size = params[i].return_size;
        params[i].return_size = OSSL_PARAM_UNMODIFIED;
    }

    ret = EVP_PKEY_get_params(pkey, params);
    if (ret != RET_OSSL_OK) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }
    ret = OSSL_PARAM_modified(params);
    if (ret != RET_OSSL_OK) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    for (int i = 0; i < num; i++) {
        bool found = false;
        for (int j = 0; j < attrnum; j++) {
            if (attrs[i].type == types[j]) {
                if (!params[j].data) {
                    rv = CKR_GENERAL_ERROR;
                    goto done;
                }
                attrs[i].pValue = params[j].data;
                attrs[i].ulValueLen = params[j].data_size;
                params[j].data = NULL;
                found = true;
                break;
            }
        }
        if (!found) {
            rv = CKR_ARGUMENTS_BAD;
            goto done;
        }
    }

    rv = CKR_OK;

done:
    /* just in case caller didn't fetch all */
    for (int i = 0; i < attrnum; i++) {
        OPENSSL_free(params[i].data);
    }
    if (rv != CKR_OK) {
        for (int i = 0; i < num; i++) {
            OPENSSL_free(attrs[i].pValue);
            attrs[i].pValue = NULL;
            attrs[i].ulValueLen = 0;
        }
    }
    X509_free(x509);
    return rv;
}

static CK_RV get_all_attrs(P11PROV_OBJ *obj, CK_ATTRIBUTE *attrs, int num)
{
    CK_ATTRIBUTE *res[num];
    CK_RV rv;

    for (int i = 0; i < num; i++) {
        res[i] = p11prov_obj_get_attr(obj, attrs[i].type);
        if (!res[i]) {
            return CKR_CANCEL;
        }
    }

    for (int i = 0; i < num; i++) {
        rv = p11prov_copy_attr(&attrs[i], res[i]);
        if (rv != CKR_OK) {
            for (i--; i >= 0; i--) {
                OPENSSL_free(attrs[i].pValue);
                attrs[i].ulValueLen = 0;
                attrs[i].pValue = NULL;
            }
            return rv;
        }
    }
    return CKR_OK;
}

static CK_RV get_public_attrs(P11PROV_OBJ *obj, CK_ATTRIBUTE *attrs, int num)
{
    P11PROV_OBJ *tmp = NULL;
    CK_RV rv;

    P11PROV_debug("Get Public Attributes (obj=%p, atrs=%p, num=%d)", obj, attrs,
                  num);

    /* we couldn't get all of them, start fallback logic */
    switch (obj->class) {
    case CKO_PUBLIC_KEY:
    case CKO_SECRET_KEY:
        return get_all_attrs(obj, attrs, num);
    case CKO_PRIVATE_KEY:
        rv = get_all_attrs(obj, attrs, num);
        if (rv == CKR_OK) {
            return rv;
        }
        /* public attributes unavailable, try to find public key */
        tmp = p11prov_obj_find_associated(obj, CKO_PUBLIC_KEY);
        if (tmp) {
            rv = get_all_attrs(tmp, attrs, num);
            p11prov_obj_free(tmp);
            return rv;
        }
        /* no public key, try to find certificate */
        tmp = p11prov_obj_find_associated(obj, CKO_CERTIFICATE);
        if (tmp) {
            rv = get_all_from_cert(tmp, attrs, num);
            p11prov_obj_free(tmp);
            return rv;
        }
        break;
    case CKO_CERTIFICATE:
        return get_all_from_cert(obj, attrs, num);
    default:
        break;
    }

    return CKR_CANCEL;
}

/* Tokens return data in bigendian order, while openssl
 * wants it in host order, so we may need to fix the
 * endianness of the buffer.
 * Src and Dest, can be the same area, but not partially
 * overlapping memory areas */

#define RSA_PUB_ATTRS 2
static int p11prov_obj_export_public_rsa_key(P11PROV_OBJ *obj,
                                             OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    CK_ATTRIBUTE attrs[RSA_PUB_ATTRS] = { 0 };
    OSSL_PARAM params[RSA_PUB_ATTRS + 2];
    CK_RV rv;
    int ret, n = 0;

    if (p11prov_obj_get_key_type(obj) != CKK_RSA) {
        return RET_OSSL_ERR;
    }

    attrs[0].type = CKA_MODULUS;
    attrs[1].type = CKA_PUBLIC_EXPONENT;

    rv = get_public_attrs(obj, attrs, RSA_PUB_ATTRS);
    if (rv != CKR_OK) {
        P11PROV_raise(obj->ctx, rv, "Failed to get public key attributes");
        return RET_OSSL_ERR;
    }

    byteswap_buf(attrs[0].pValue, attrs[0].pValue, attrs[0].ulValueLen);
    params[n++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N,
                                          attrs[0].pValue, attrs[0].ulValueLen);
    byteswap_buf(attrs[1].pValue, attrs[1].pValue, attrs[1].ulValueLen);
    params[n++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E,
                                          attrs[1].pValue, attrs[1].ulValueLen);
    /* TODO: Add RSA-PSS restrictions if there is only one allowed mechanisms.
     * The PKCS#11 specification is not compatible with what OpenSSL expects
     * (unless we would have just one mechanisms specified in
     * ALLOWED_MECHANISMS) so its better to not add any restrictions now. */
#if 0
    if (p11prov_obj_is_rsa_pss(obj)) {
        params[n++] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_RSA_MASKGENFUNC, (char *)SN_mgf1, strlen(SN_mgf1));
        /* TODO other restrictions */
    }
#endif
    params[n++] = OSSL_PARAM_construct_end();

    ret = cb_fn(params, cb_arg);

    for (int i = 0; i < RSA_PUB_ATTRS; i++) {
        OPENSSL_free(attrs[i].pValue);
    }
    return ret;
}

const char *p11prov_obj_get_ec_group_name(P11PROV_OBJ *obj)
{
    CK_ATTRIBUTE *attr;

    attr = p11prov_obj_get_attr(obj, CKA_P11PROV_CURVE_NAME);
    if (!attr) {
        /* this should never happen */
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Failed to get curve name");
        return NULL;
    }

    return (const char *)attr->pValue;
}

bool p11prov_obj_get_ec_compressed(P11PROV_OBJ *obj)
{
    CK_ATTRIBUTE *pub_key;
    uint8_t *buf;

    pub_key = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY);
    if (!pub_key) {
        obj = p11prov_obj_get_associated(obj);
        if (obj) {
            pub_key = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY);
        }
        if (!pub_key) {
            return false;
        }
    }
    buf = pub_key->pValue;

    return (buf[0] & 0x01) == 0x01;
}

static int ossl_param_construct_bn(P11PROV_CTX *provctx, OSSL_PARAM *param,
                                   const char *key, const BIGNUM *val)
{
    size_t bsize;
    void *buf;

    if (BN_is_negative(val)) {
        P11PROV_raise(provctx, CKR_GENERAL_ERROR,
                      "Negative big numbers are unsupported for %s", key);
        return 0;
    }

    bsize = (size_t)BN_num_bytes(val);
    /* We make sure that at least one byte is used, so zero is properly set */
    if (bsize == 0) {
        bsize++;
    }

    buf = OPENSSL_malloc(bsize);
    if (buf == NULL) {
        P11PROV_raise(provctx, CKR_HOST_MEMORY, "Allocating data for %s", key);
        return 0;
    }

    if (BN_bn2nativepad(val, buf, bsize) < 0) {
        return 0;
    }

    *param = OSSL_PARAM_construct_BN(key, buf, bsize);
    return 1;
}

static int ec_group_explicit_to_params(P11PROV_OBJ *obj, const EC_GROUP *group,
                                       OSSL_PARAM *params, int *nparam,
                                       BN_CTX *bnctx)
{
    int fid;
    const char *field_type;
    BIGNUM *p, *a, *b;
    const BIGNUM *order, *cofactor;
    const EC_POINT *generator;
    point_conversion_form_t genform;
    size_t bsize;
    void *buf;
    unsigned char *seed;
    size_t seed_len;

    fid = EC_GROUP_get_field_type(group);
    if (fid == NID_X9_62_prime_field) {
        field_type = SN_X9_62_prime_field;
    } else if (fid == NID_X9_62_characteristic_two_field) {
        field_type = SN_X9_62_characteristic_two_field;
    } else {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid EC field");
        return RET_OSSL_ERR;
    }

    params[(*nparam)++] = OSSL_PARAM_construct_utf8_string(
        OSSL_PKEY_PARAM_EC_FIELD_TYPE, (char *)field_type, 0);

    p = BN_CTX_get(bnctx);
    a = BN_CTX_get(bnctx);
    b = BN_CTX_get(bnctx);
    if (b == NULL) {
        return RET_OSSL_ERR;
    }

    if (!EC_GROUP_get_curve(group, p, a, b, bnctx)) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid curve");
        return RET_OSSL_ERR;
    }

    if (!ossl_param_construct_bn(obj->ctx, &params[(*nparam)++],
                                 OSSL_PKEY_PARAM_EC_P, p)
        || !ossl_param_construct_bn(obj->ctx, &params[(*nparam)++],
                                    OSSL_PKEY_PARAM_EC_A, a)
        || !ossl_param_construct_bn(obj->ctx, &params[(*nparam)++],
                                    OSSL_PKEY_PARAM_EC_B, b)) {
        return RET_OSSL_ERR;
    }

    order = EC_GROUP_get0_order(group);
    if (order == NULL) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid group order");
        return RET_OSSL_ERR;
    }
    if (!ossl_param_construct_bn(obj->ctx, &params[(*nparam)++],
                                 OSSL_PKEY_PARAM_EC_ORDER, order)) {
        return RET_OSSL_ERR;
    }

    generator = EC_GROUP_get0_generator(group);
    genform = EC_GROUP_get_point_conversion_form(group);
    if (generator == NULL) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid group generator");
        return RET_OSSL_ERR;
    }
    bsize = EC_POINT_point2oct(group, generator, genform, NULL, 0, bnctx);
    buf = OPENSSL_malloc(bsize);
    if (buf == NULL) {
        return RET_OSSL_ERR;
    }
    bsize = EC_POINT_point2oct(group, generator, genform, buf, bsize, bnctx);
    params[(*nparam)++] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_EC_GENERATOR, buf, bsize);

    cofactor = EC_GROUP_get0_cofactor(group);
    if (cofactor == NULL) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid group cofactor");
        return RET_OSSL_ERR;
    }
    if (!ossl_param_construct_bn(obj->ctx, &params[(*nparam)++],
                                 OSSL_PKEY_PARAM_EC_COFACTOR, cofactor)) {
        return RET_OSSL_ERR;
    }

    seed = EC_GROUP_get0_seed(group);
    seed_len = EC_GROUP_get_seed_len(group);
    if (seed != NULL && seed_len > 0) {
        params[(*nparam)++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_EC_SEED, seed, seed_len);
    }

    return RET_OSSL_OK;
}

/* Common:
 *   CKA_P11PROV_PUB_KEY     -> OSSL_PKEY_PARAM_PUB_KEY
 * Named curves:
 *   CKA_P11PROV_CURVE_NAME  -> OSSL_PKEY_PARAM_GROUP_NAME
 * Explicit curves:
 *   CKA_EC_PARAMS           -> OSSL_PKEY_PARAM_EC_FIELD_TYPE,
 *                              OSSL_PKEY_PARAM_EC_A,
 *                              OSSL_PKEY_PARAM_EC_B,
 *                              OSSL_PKEY_PARAM_EC_P,
 *                              OSSL_PKEY_PARAM_EC_GENERATOR,
 *                              OSSL_PKEY_PARAM_EC_ORDER,
 *                              OSSL_PKEY_PARAM_EC_COFACTOR,
 *                              OSSL_PKEY_PARAM_EC_SEED
 */
#define EC_MAX_PUB_ATTRS 2
#define EC_MAX_OSSL_PARAMS 9
static int p11prov_obj_export_public_ec_key(P11PROV_OBJ *obj, bool params_only,
                                            OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    CK_ATTRIBUTE attrs[EC_MAX_PUB_ATTRS] = { 0 };
    OSSL_PARAM params[EC_MAX_OSSL_PARAMS + 1] = { 0 };
    CK_KEY_TYPE key_type;
    int pub_key_attr = 0;
    int nattr = 0;
    int nparam = 0;
    CK_RV rv;
    int ret;
    EC_GROUP *group = NULL;
    int curve_nid = NID_undef;

    key_type = p11prov_obj_get_key_type(obj);
    switch (key_type) {
    case CKK_EC:
        attrs[0].type = CKA_P11PROV_CURVE_NID;
        rv = get_public_attrs(obj, attrs, 1);
        if (rv != CKR_OK) {
            P11PROV_raise(obj->ctx, rv, "Failed to get EC key curve nid");
            return RET_OSSL_ERR;
        }
        curve_nid = *(int *)attrs[0].pValue;
        OPENSSL_free(attrs[0].pValue);
        if (curve_nid == NID_undef) {
            attrs[0].type = CKA_EC_PARAMS;
        } else {
            attrs[0].type = CKA_P11PROV_CURVE_NAME;
        }
        nattr = 1;
        break;
    case CKK_EC_EDWARDS:
        break;
    default:
        return RET_OSSL_ERR;
    }

    if (!params_only) {
        pub_key_attr = nattr;
        attrs[nattr].type = CKA_P11PROV_PUB_KEY;
        nattr++;
    }

    rv = get_public_attrs(obj, attrs, nattr);
    if (rv != CKR_OK) {
        P11PROV_raise(obj->ctx, rv, "Failed to get public key attributes");
        return RET_OSSL_ERR;
    }

    if (!params_only) {
        params[nparam] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, attrs[pub_key_attr].pValue,
            attrs[pub_key_attr].ulValueLen);
        nparam++;
    }
    if (key_type == CKK_EC) {
        if (curve_nid == NID_undef) {
            BN_CTX *bnctx;

            /* in d2i functions 'in' is overwritten to return the remainder of
             * the buffer after parsing, so we always need to avoid passing in
             * our pointer holders, to avoid having them clobbered */
            const unsigned char *val = attrs[0].pValue;
            group = d2i_ECPKParameters(NULL, &val, attrs[0].ulValueLen);
            if (group == NULL) {
                ret = RET_OSSL_ERR;
                goto done;
            }
            bnctx = BN_CTX_new_ex(p11prov_ctx_get_libctx(obj->ctx));
            if (bnctx == NULL) {
                ret = RET_OSSL_ERR;
                goto done;
            }
            BN_CTX_start(bnctx);
            ret =
                ec_group_explicit_to_params(obj, group, params, &nparam, bnctx);
            BN_CTX_end(bnctx);
            BN_CTX_free(bnctx);
            if (ret != RET_OSSL_OK) {
                goto done;
            }
        } else {
            params[nparam] = OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_GROUP_NAME, attrs[0].pValue,
                attrs[0].ulValueLen);
            nparam++;
        }
    }
    params[nparam] = OSSL_PARAM_construct_end();

    ret = cb_fn(params, cb_arg);

done:
    /* must be freed after callback */
    EC_GROUP_free(group);
    for (int i = 0; i < nparam; i++) {
        if (strcmp(params[i].key, OSSL_PKEY_PARAM_PUB_KEY)
            && strcmp(params[i].key, OSSL_PKEY_PARAM_GROUP_NAME)
            && strcmp(params[i].key, OSSL_PKEY_PARAM_EC_FIELD_TYPE)) {
            OPENSSL_free(params[i].data);
        }
    }
    for (int i = 0; i < nattr; i++) {
        OPENSSL_free(attrs[i].pValue);
    }
    return ret;
}

#define MLDSA_PUB_ATTRS 1
static int p11prov_obj_export_public_mldsa_key(P11PROV_OBJ *obj,
                                               OSSL_CALLBACK *cb_fn,
                                               void *cb_arg)
{
    CK_ATTRIBUTE attrs[MLDSA_PUB_ATTRS] = { { 0 } };
    OSSL_PARAM params[MLDSA_PUB_ATTRS + 1];
    CK_RV rv;
    int ret, n = 0;

    if (p11prov_obj_get_key_type(obj) != CKK_ML_DSA) {
        return RET_OSSL_ERR;
    }

    attrs[0].type = CKA_VALUE;

    rv = get_public_attrs(obj, attrs, MLDSA_PUB_ATTRS);
    if (rv != CKR_OK) {
        P11PROV_raise(obj->ctx, rv, "Failed to get public key attributes");
        return RET_OSSL_ERR;
    }

    params[n++] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY, attrs[0].pValue, attrs[0].ulValueLen);
    params[n++] = OSSL_PARAM_construct_end();

    ret = cb_fn(params, cb_arg);

    for (int i = 0; i < MLDSA_PUB_ATTRS; i++) {
        OPENSSL_free(attrs[i].pValue);
    }
    return ret;
}

#define MLKEM_PUB_ATTRS 1
static int p11prov_obj_export_public_mlkem_key(P11PROV_OBJ *obj,
                                               OSSL_CALLBACK *cb_fn,
                                               void *cb_arg)
{
    CK_ATTRIBUTE attrs[MLKEM_PUB_ATTRS] = { { 0 } };
    OSSL_PARAM params[MLKEM_PUB_ATTRS + 1];
    CK_RV rv;
    int ret, n = 0;

    if (p11prov_obj_get_key_type(obj) != CKK_ML_KEM) {
        return RET_OSSL_ERR;
    }

    attrs[0].type = CKA_VALUE;

    rv = get_public_attrs(obj, attrs, MLKEM_PUB_ATTRS);
    if (rv != CKR_OK) {
        P11PROV_raise(obj->ctx, rv, "Failed to get public key attributes");
        return RET_OSSL_ERR;
    }

    params[n++] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY, attrs[0].pValue, attrs[0].ulValueLen);
    params[n++] = OSSL_PARAM_construct_end();

    ret = cb_fn(params, cb_arg);

    for (int i = 0; i < MLKEM_PUB_ATTRS; i++) {
        OPENSSL_free(attrs[i].pValue);
    }
    return ret;
}

int p11prov_obj_export_public_key(P11PROV_OBJ *obj, CK_KEY_TYPE key_type,
                                  bool search_related, bool params_only,
                                  OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    if (obj == NULL) {
        return RET_OSSL_ERR;
    }

    if (obj->class != CKO_PRIVATE_KEY && obj->class != CKO_PUBLIC_KEY) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid Object Class");
        return RET_OSSL_ERR;
    }

    if (key_type != CK_UNAVAILABLE_INFORMATION) {
        if (key_type != obj->data.key.type) {
            P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid Key Type");
            return RET_OSSL_ERR;
        }
    }

    if (!search_related && obj->class != CKO_PUBLIC_KEY) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Not a public Key");
        return RET_OSSL_ERR;
    }

    switch (obj->data.key.type) {
    case CKK_RSA:
        return p11prov_obj_export_public_rsa_key(obj, cb_fn, cb_arg);
    case CKK_EC:
    case CKK_EC_EDWARDS:
        return p11prov_obj_export_public_ec_key(obj, params_only, cb_fn,
                                                cb_arg);
    case CKK_ML_DSA:
        return p11prov_obj_export_public_mldsa_key(obj, cb_fn, cb_arg);
    case CKK_ML_KEM:
        return p11prov_obj_export_public_mlkem_key(obj, cb_fn, cb_arg);
    default:
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Unsupported key type");
        return RET_OSSL_ERR;
    }
}

bool p11prov_obj_is_rsa_pss(P11PROV_OBJ *obj)
{
    CK_BBOOL token_supports_allowed_mechs = CK_TRUE;
    CK_ATTRIBUTE *am = NULL;
    CK_MECHANISM_TYPE *allowed;
    P11PROV_OBJ *priv = NULL;
    int am_nmechs;
    CK_RV ret;

    /* If the token does not support this attribute, do not even try to figure
     * out the subtype. */
    ret = p11prov_token_sup_attr(obj->ctx, obj->slotid, GET_ATTR,
                                 CKA_ALLOWED_MECHANISMS,
                                 &token_supports_allowed_mechs);
    if (ret != CKR_OK) {
        P11PROV_raise(obj->ctx, ret, "Failed to probe quirk");
    } else if (token_supports_allowed_mechs == CK_FALSE) {
        return false;
    }

    am = p11prov_obj_get_attr(obj, CKA_ALLOWED_MECHANISMS);
    if (am == NULL || am->ulValueLen == 0) {
        /* The ALLOWED_MECHANISMS should be on both of the keys. But more
         * commonly they are available only on the private key. Check if we
         * have a priv key associated to this pub key and if so, use that one.
         * TODO we can try also certificate restrictions
         */
        if (obj->class == CKO_PRIVATE_KEY) {
            /* no limitations */
            return false;
        }

        /* Try to find private key */
        priv = p11prov_obj_find_associated(obj, CKO_PRIVATE_KEY);
        if (priv == NULL) {
            return false;
        }

        am = p11prov_obj_get_attr(priv, CKA_ALLOWED_MECHANISMS);
        if (am == NULL || am->ulValueLen == 0) {
            /* no limitations */
            p11prov_obj_free(priv);
            return false;
        }
    }
    allowed = (CK_MECHANISM_TYPE *)am->pValue;
    am_nmechs = am->ulValueLen / sizeof(CK_MECHANISM_TYPE);
    for (int i = 0; i < am_nmechs; i++) {
        bool found = false;
        for (int j = 0; j < P11PROV_N_RSAPSS_MECHS; j++) {
            if (allowed[i] == p11prov_rsapss_mechs[j]) {
                found = true;
                break;
            }
        }
        if (!found) {
            /* this is not a RSA-PSS mechanism. We can not enforce any
             * limitations */
            p11prov_obj_free(priv);
            return false;
        }
    }
    /* all allowed mechanisms fit into the list of RSA-PSS ones */
    p11prov_obj_free(priv);
    return true;
}

int p11prov_obj_get_ed_pub_key(P11PROV_OBJ *obj, CK_ATTRIBUTE **pub)
{
    CK_ATTRIBUTE *a;

    P11PROV_debug("get ed pubkey %p", obj);

    if (!obj) {
        return RET_OSSL_ERR;
    }

    if (obj->class != CKO_PRIVATE_KEY && obj->class != CKO_PUBLIC_KEY) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid Object Class");
        return RET_OSSL_ERR;
    }

    if (obj->data.key.type != CKK_EC_EDWARDS) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Unsupported key type");
        return RET_OSSL_ERR;
    }

    /* check if we have a pub key associated to a private key */
    if (obj->class == CKO_PRIVATE_KEY) {
        P11PROV_OBJ *pobj = p11prov_obj_get_associated(obj);
        if (pobj && pobj->class == CKO_PUBLIC_KEY) {
            /* replace obj with the public one */
            obj = pobj;
        }
    }

    /* See if we have cached attributes first */
    a = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY);
    if (!a) {
        return RET_OSSL_ERR;
    }

    if (pub) {
        *pub = a;
    }
    return RET_OSSL_OK;
}

int p11prov_obj_get_ec_public_x_y(P11PROV_OBJ *obj, CK_ATTRIBUTE **pub_x,
                                  CK_ATTRIBUTE **pub_y)
{
    const unsigned char *val;
    void *tmp_ptr;
    CK_ATTRIBUTE *ec_params;
    CK_ATTRIBUTE *pub_key;
    EC_POINT *pub_point = NULL;
    EC_GROUP *group = NULL;
    CK_ATTRIBUTE *a_x;
    CK_ATTRIBUTE *a_y;
    BN_CTX *bnctx = NULL;
    BIGNUM *x;
    BIGNUM *y;
    int len;
    int ret;

    if (!obj) {
        return RET_OSSL_ERR;
    }

    if (obj->class != CKO_PRIVATE_KEY && obj->class != CKO_PUBLIC_KEY) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Invalid Object Class");
        return RET_OSSL_ERR;
    }

    if (obj->data.key.type != CKK_EC) {
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Unsupported key type");
        return RET_OSSL_ERR;
    }

    /* check if we have a pub key associated to a private key */
    if (obj->class == CKO_PRIVATE_KEY) {
        P11PROV_OBJ *pub = p11prov_obj_get_associated(obj);
        if (pub && pub->class == CKO_PUBLIC_KEY) {
            /* replace obj with the public one */
            obj = pub;
        }
    }

    /* See if we have cached attributes first */
    a_x = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY_X);
    a_y = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY_Y);
    if (a_x && a_y) {
        if (pub_x) {
            *pub_x = a_x;
        }
        if (pub_y) {
            *pub_y = a_y;
        }
        return RET_OSSL_OK;
    }

    ec_params = p11prov_obj_get_attr(obj, CKA_EC_PARAMS);
    if (!ec_params) {
        return RET_OSSL_ERR;
    }
    pub_key = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY);
    if (!pub_key) {
        return RET_OSSL_ERR;
    }

    bnctx = BN_CTX_new();
    if (!bnctx) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    /* prevent modification of the attribute pointer */
    val = ec_params->pValue;
    group = d2i_ECPKParameters(NULL, &val, ec_params->ulValueLen);
    if (!group) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    x = BN_CTX_get(bnctx);
    y = BN_CTX_get(bnctx);
    if (!y) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    pub_point = EC_POINT_new(group);
    if (!pub_point) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    ret = EC_POINT_oct2point(group, pub_point, pub_key->pValue,
                             pub_key->ulValueLen, bnctx);
    if (ret != RET_OSSL_OK) {
        goto done;
    }

    ret = EC_POINT_get_affine_coordinates(group, pub_point, x, y, bnctx);
    if (ret != RET_OSSL_OK) {
        goto done;
    }

    /* cache values */
    tmp_ptr =
        OPENSSL_realloc(obj->attrs, sizeof(CK_ATTRIBUTE) * (obj->numattrs + 2));
    if (!tmp_ptr) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    obj->attrs = tmp_ptr;

    /* do x */
    a_x = &obj->attrs[obj->numattrs];
    a_x->type = CKA_P11PROV_PUB_KEY_X;
    a_x->ulValueLen = BN_num_bytes(x);
    a_x->pValue = OPENSSL_malloc(a_x->ulValueLen);
    if (!a_x->pValue) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    len = BN_bn2nativepad(x, a_x->pValue, a_x->ulValueLen);
    if (len == -1) {
        OPENSSL_free(a_x->pValue);
        ret = RET_OSSL_ERR;
        goto done;
    }
    obj->numattrs++;

    /* do y */
    a_y = &obj->attrs[obj->numattrs];
    a_y->type = CKA_P11PROV_PUB_KEY_Y;
    a_y->ulValueLen = BN_num_bytes(y);
    a_y->pValue = OPENSSL_malloc(a_y->ulValueLen);
    if (!a_y->pValue) {
        OPENSSL_free(a_y->pValue);
        ret = RET_OSSL_ERR;
        goto done;
    }
    len = BN_bn2nativepad(y, a_y->pValue, a_y->ulValueLen);
    if (len == -1) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    obj->numattrs++;

    if (pub_x) {
        *pub_x = a_x;
    }
    if (pub_y) {
        *pub_y = a_y;
    }

    ret = RET_OSSL_OK;

done:
    EC_POINT_free(pub_point);
    EC_GROUP_free(group);
    BN_CTX_free(bnctx);
    return ret;
}

CK_RV decode_ec_point(CK_KEY_TYPE key_type, CK_ATTRIBUTE *attr,
                      struct data_buffer *ec_point)
{
    ASN1_OCTET_STRING *octet;
    const unsigned char *val;
    CK_RV ret = CKR_GENERAL_ERROR;
    int err;

    /* in d2i functions 'in' is overwritten to return the remainder of
     * the buffer after parsing, so we always need to avoid passing in
     * our pointer holders, to avoid having them clobbered */
    val = attr->pValue;
    octet = d2i_ASN1_OCTET_STRING(NULL, (const unsigned char **)&val,
                                  attr->ulValueLen);
    if (!octet) {
        /* 3.1 spec says CKA_EC_POINT is not DER encoded for Edwards and
         * Montgomery curves so do not fail in that case and just take
         * the value as is */
        if (key_type == CKK_EC) {
            return CKR_KEY_INDIGESTIBLE;
        } else {
            octet = ASN1_OCTET_STRING_new();
            if (!octet) {
                return CKR_HOST_MEMORY;
            }
            /* makes a copy of the value */
            err = ASN1_OCTET_STRING_set(octet, attr->pValue, attr->ulValueLen);
            if (err != RET_OSSL_OK) {
                ret = CKR_HOST_MEMORY;
                goto done;
            }
        }
    }

    ec_point->data = octet->data;
    ec_point->length = octet->length;

    /* moved octet data, do not free it */
    octet->data = NULL;
    octet->length = 0;

    ret = CKR_OK;
done:
    ASN1_OCTET_STRING_free(octet);
    return ret;
}

CK_ATTRIBUTE *p11prov_obj_get_ec_public_raw(P11PROV_OBJ *key)
{
    CK_ATTRIBUTE *pub_key;

    if (!key) {
        return NULL;
    }

    if (key->data.key.type != CKK_EC) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR, "Unsupported key type");
        return NULL;
    }

    if (key->class != CKO_PRIVATE_KEY && key->class != CKO_PUBLIC_KEY) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR, "Invalid Object Class");
        return NULL;
    }

    /* check if we have a pub key associated to a private key */
    if (key->class == CKO_PRIVATE_KEY) {
        P11PROV_OBJ *pub = p11prov_obj_get_associated(key);
        if (pub && pub->class == CKO_PUBLIC_KEY) {
            /* replace obj with the public one */
            key = pub;
        }
    }

    pub_key = p11prov_obj_get_attr(key, CKA_P11PROV_PUB_KEY);
    if (!pub_key) {
        CK_ATTRIBUTE *ec_point;

        ec_point = p11prov_obj_get_attr(key, CKA_EC_POINT);
        if (ec_point) {
            struct data_buffer data = { 0 };
            void *tmp_ptr;
            CK_RV ret;

            ret = decode_ec_point(key->data.key.type, ec_point, &data);
            if (ret != CKR_OK) {
                P11PROV_raise(key->ctx, ret, "Failed to decode EC_POINT");
                return NULL;
            }

            tmp_ptr = OPENSSL_realloc(key->attrs, sizeof(CK_ATTRIBUTE)
                                                      * (key->numattrs + 1));
            if (!tmp_ptr) {
                P11PROV_raise(key->ctx, CKR_HOST_MEMORY,
                              "Failed to allocate memory key attributes");
                OPENSSL_free(data.data);
                return NULL;
            }
            key->attrs = tmp_ptr;

            /* takes the data allocated in data */
            CKATTR_ASSIGN(key->attrs[key->numattrs], CKA_P11PROV_PUB_KEY,
                          data.data, data.length);
            key->numattrs++;

            pub_key = &key->attrs[key->numattrs - 1];
        }
    }

    if (!pub_key) {
        P11PROV_debug("ECC Public Point not found");
    }
    return pub_key;
}
CK_RV p11prov_obj_set_ec_encoded_public_key(P11PROV_OBJ *key,
                                            const void *pubkey,
                                            size_t pubkey_len)
{
    CK_RV rv;
    CK_ATTRIBUTE *pub;
    CK_ATTRIBUTE *ecpoint;
    CK_ATTRIBUTE new_pub;
    ASN1_OCTET_STRING oct;
    unsigned char *der = NULL;
    int add_attrs = 0;
    int len;

    if (key->handle != CK_P11PROV_IMPORTED_HANDLE) {
        /*
         * not a mock object, cannot set public key to a token object backed by
         * an actual handle.
         */
        /* not matching, error out */
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Cannot change public key of a token object");
        return CKR_KEY_INDIGESTIBLE;
    }

    switch (key->data.key.type) {
    case CKK_EC:
    case CKK_EC_EDWARDS:
        /* if class is still "domain parameters" convert it to
         * a public key */
        if (key->class == CKO_DOMAIN_PARAMETERS) {
            key->class = CKO_PUBLIC_KEY;
        } else if (key->class != CKO_PUBLIC_KEY) {
            /* check that this is a public key */
            P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                          "Invalid Key type, not a public key");
            return CKR_KEY_INDIGESTIBLE;
        }
        break;
    default:
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Invalid Key type, not an EC/ED key");
        return CKR_KEY_INDIGESTIBLE;
    }

    pub = p11prov_obj_get_attr(key, CKA_P11PROV_PUB_KEY);
    if (!pub) {
        add_attrs += 1;
    }

    ecpoint = p11prov_obj_get_attr(key, CKA_EC_POINT);
    if (!ecpoint) {
        add_attrs += 1;
    }

    if (add_attrs > 0) {
        void *ptr = OPENSSL_realloc(
            key->attrs, sizeof(CK_ATTRIBUTE) * (key->numattrs + add_attrs));
        if (!ptr) {
            P11PROV_raise(key->ctx, CKR_HOST_MEMORY,
                          "Failed to store key public key");
            return CKR_HOST_MEMORY;
        }
        key->attrs = ptr;
    }

    if (!pub) {
        pub = &key->attrs[key->numattrs];
        key->numattrs += 1;
    } else {
        OPENSSL_free(pub->pValue);
    }
    /* always memset as realloc does not guarantee zeroed data */
    memset(pub, 0, sizeof(CK_ATTRIBUTE));

    if (!ecpoint) {
        ecpoint = &key->attrs[key->numattrs];
        key->numattrs += 1;
    } else {
        OPENSSL_free(ecpoint->pValue);
    }
    /* always memset as realloc does not guarantee zeroed data */
    memset(ecpoint, 0, sizeof(CK_ATTRIBUTE));

    new_pub.type = CKA_P11PROV_PUB_KEY;
    new_pub.pValue = (CK_VOID_PTR)pubkey;
    new_pub.ulValueLen = (CK_ULONG)pubkey_len;
    rv = p11prov_copy_attr(pub, &new_pub);
    if (rv != CKR_OK) {
        return rv;
    }

    oct.data = (unsigned char *)pubkey;
    oct.length = (int)pubkey_len;
    oct.flags = 0;

    len = i2d_ASN1_OCTET_STRING(&oct, &der);
    if (len < 0) {
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Failure to encode EC point to DER");
        return CKR_KEY_INDIGESTIBLE;
    }
    ecpoint->type = CKA_EC_POINT;
    ecpoint->pValue = der;
    ecpoint->ulValueLen = len;

    return CKR_OK;
}

static int cmp_bn_attr(P11PROV_OBJ *key1, P11PROV_OBJ *key2,
                       CK_ATTRIBUTE_TYPE attr)
{
    BIGNUM *bx1;
    BIGNUM *bx2;
    CK_ATTRIBUTE *x1, *x2;
    int rc = RET_OSSL_ERR;

    /* is BN ?*/
    if (attr != CKA_MODULUS && attr != CKA_PUBLIC_EXPONENT) {
        return rc;
    }

    x1 = p11prov_obj_get_attr(key1, attr);
    x2 = p11prov_obj_get_attr(key2, attr);

    if (!x1 || !x2) {
        return rc;
    }

    bx1 = BN_native2bn(x1->pValue, x1->ulValueLen, NULL);
    bx2 = BN_native2bn(x2->pValue, x2->ulValueLen, NULL);

    if (BN_cmp(bx1, bx2) == 0) {
        rc = RET_OSSL_OK;
    }

    BN_free(bx1);
    BN_free(bx2);

    return rc;
}

static int cmp_attr(P11PROV_OBJ *key1, P11PROV_OBJ *key2,
                    CK_ATTRIBUTE_TYPE attr)
{
    CK_ATTRIBUTE *x1, *x2;

    x1 = p11prov_obj_get_attr(key1, attr);
    x2 = p11prov_obj_get_attr(key2, attr);
    if (!x1 || !x2) {
        return RET_OSSL_ERR;
    }
    if (x1->ulValueLen != x2->ulValueLen) {
        return RET_OSSL_ERR;
    }
    if (memcmp(x1->pValue, x2->pValue, x1->ulValueLen) != 0) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int cmp_public_key_values(P11PROV_OBJ *pub_key1, P11PROV_OBJ *pub_key2)
{
    int ret;

    switch (pub_key1->data.key.type) {
    case CKK_RSA:
        /* pub_key1 pub_key2 could be CKO_PRIVATE_KEY here but
         * nevertheless contain these two attributes */
        ret = cmp_bn_attr(pub_key1, pub_key2, CKA_MODULUS);
        if (ret == RET_OSSL_ERR) {
            break;
        }
        ret = cmp_bn_attr(pub_key1, pub_key2, CKA_PUBLIC_EXPONENT);
        break;
    case CKK_EC:
    case CKK_EC_EDWARDS:
        ret = cmp_attr(pub_key1, pub_key2, CKA_P11PROV_PUB_KEY);
        break;
    case CKK_ML_DSA:
        ret = cmp_attr(pub_key1, pub_key2, CKA_VALUE);
        break;
    case CKK_ML_KEM:
        ret = cmp_attr(pub_key1, pub_key2, CKA_VALUE);
        break;
    default:
        ret = RET_OSSL_ERR;
    }

    return ret;
}

static int match_key_with_cert(P11PROV_OBJ *priv_key, P11PROV_OBJ *pub_key)
{
    P11PROV_OBJ *cert;
    CK_ATTRIBUTE attrs[2] = { 0 };
    CK_ATTRIBUTE *x;
    int num = 0;
    int ret = RET_OSSL_ERR;

    cert = p11prov_obj_find_associated(priv_key, CKO_CERTIFICATE);
    if (!cert) {
        P11PROV_raise(priv_key->ctx, CKR_GENERAL_ERROR,
                      "Could not find associated certificate object");
        return RET_OSSL_ERR;
    }

    switch (pub_key->data.key.type) {
    case CKK_RSA:
        attrs[0].type = CKA_MODULUS;
        attrs[1].type = CKA_PUBLIC_EXPONENT;
        num = 2;
        break;
    case CKK_EC:
    case CKK_EC_EDWARDS:
        attrs[0].type = CKA_P11PROV_PUB_KEY;
        num = 1;
        break;
    }

    ret = get_all_from_cert(cert, attrs, num);
    if (ret != CKR_OK) {
        P11PROV_raise(priv_key->ctx, ret,
                      "Failed to get public attrs from cert");
        ret = RET_OSSL_ERR;
        goto done;
    }

    switch (pub_key->data.key.type) {
    case CKK_RSA:
        x = p11prov_obj_get_attr(pub_key, CKA_MODULUS);
        if (!x || x->ulValueLen != attrs[0].ulValueLen
            || memcmp(x->pValue, attrs[0].pValue, x->ulValueLen) != 0) {
            ret = RET_OSSL_ERR;
            goto done;
        }

        x = p11prov_obj_get_attr(pub_key, CKA_PUBLIC_EXPONENT);
        if (!x || x->ulValueLen != attrs[1].ulValueLen
            || memcmp(x->pValue, attrs[1].pValue, x->ulValueLen) != 0) {
            ret = RET_OSSL_ERR;
            goto done;
        }

        ret = RET_OSSL_OK;
        break;
    case CKK_EC:
    case CKK_EC_EDWARDS:
        x = p11prov_obj_get_attr(pub_key, CKA_P11PROV_PUB_KEY);
        if (!x || x->ulValueLen != attrs[0].ulValueLen
            || memcmp(x->pValue, attrs[0].pValue, x->ulValueLen) != 0) {
            ret = RET_OSSL_ERR;
            goto done;
        }

        ret = RET_OSSL_OK;
        break;
    }

done:
    for (int i = 0; i < num; i++) {
        OPENSSL_free(attrs[i].pValue);
    }
    p11prov_obj_free(cert);
    return ret;
}

static int match_public_keys(P11PROV_OBJ *key1, P11PROV_OBJ *key2)
{
    P11PROV_OBJ *pub_key, *assoc_pub_key;
    P11PROV_OBJ *priv_key;
    int ret = RET_OSSL_ERR;

    /* avoid round-trip to HSM if keys have enough
     * attributes to do the logical comparison
     * CKK_RSA: MODULUS / PUBLIC_EXPONENT
     * CKK_EC: EC_POINT
     */
    ret = cmp_public_key_values(key1, key2);
    if (ret != RET_OSSL_ERR) {
        return ret;
    }

    /* one of the keys or both are private */
    if (key1->class == CKO_PUBLIC_KEY && key2->class == CKO_PRIVATE_KEY) {
        pub_key = key1;
        priv_key = key2;
    } else if (key1->class == CKO_PRIVATE_KEY
               && key2->class == CKO_PUBLIC_KEY) {
        pub_key = key2;
        priv_key = key1;
    } else {
        P11PROV_debug("We can't really match private keys");
        return RET_OSSL_ERR;
    }

    assoc_pub_key = p11prov_obj_find_associated(priv_key, CKO_PUBLIC_KEY);
    if (!assoc_pub_key) {
        P11PROV_raise(priv_key->ctx, CKR_GENERAL_ERROR,
                      "Could not find associated public key object");

        /* some tokens only store the public key in a cert and not in a
         * separate public key object */
        return match_key_with_cert(priv_key, pub_key);
    }

    if (assoc_pub_key->data.key.type != pub_key->data.key.type) {
        goto done;
    }

    ret = cmp_public_key_values(pub_key, assoc_pub_key);

done:
    p11prov_obj_free(assoc_pub_key);

    return ret;
}

static int p11prov_obj_get_ed_nid(CK_ATTRIBUTE *ecp)
{
    const unsigned char *val = ecp->pValue;
    ASN1_OBJECT *obj = d2i_ASN1_OBJECT(NULL, &val, ecp->ulValueLen);
    if (obj) {
        int nid = OBJ_obj2nid(obj);
        ASN1_OBJECT_free(obj);
        if (nid != NID_undef) {
            return nid;
        }
    }

    /* it might be the parameters are encoded printable string
     * for EdDSA which OpenSSL does not understand */
    if (ecp->ulValueLen == ED25519_EC_PARAMS_LEN
        && memcmp(ecp->pValue, ed25519_ec_params, ED25519_EC_PARAMS_LEN) == 0) {
        return NID_ED25519;
    } else if (ecp->ulValueLen == ED448_EC_PARAMS_LEN
               && memcmp(ecp->pValue, ed448_ec_params, ED448_EC_PARAMS_LEN)
                      == 0) {
        return NID_ED448;
    }
    return NID_undef;
}

int p11prov_obj_key_cmp(P11PROV_OBJ *key1, P11PROV_OBJ *key2, CK_KEY_TYPE type,
                        int cmp_type)
{
    int ret;

    /* immediate shortcircuit if it is the same handle */
    if (key1->slotid == key2->slotid && key1->handle == key2->handle) {
        return RET_OSSL_OK;
    }

    if (key1->class != CKO_PRIVATE_KEY && key1->class != CKO_PUBLIC_KEY) {
        /* not a key at all */
        return RET_OSSL_ERR;
    }
    if (key2->class != CKO_PRIVATE_KEY && key2->class != CKO_PUBLIC_KEY) {
        /* not a key at all */
        return RET_OSSL_ERR;
    }

    if (type != CK_UNAVAILABLE_INFORMATION && type != key1->data.key.type) {
        return RET_OSSL_ERR;
    }

    if (key1->data.key.type != key2->data.key.type) {
        return RET_OSSL_ERR;
    }

    if (key1->data.key.bit_size != key2->data.key.bit_size) {
        return RET_OSSL_ERR;
    }

    if (cmp_type & OBJ_CMP_KEY_PRIVATE) {
        if (key1->class != key2->class) {
            /* can't have private with differing key types */
            return RET_OSSL_ERR;
        }
        if (key1->class != CKO_PRIVATE_KEY) {
            return RET_OSSL_ERR;
        }
    }

    switch (key1->data.key.type) {
    case CKK_RSA:
        if (cmp_type & OBJ_CMP_KEY_PRIVATE) {
            /* unfortunately we can't really read private attributes
             * and there is no comparison function in the PKCS11 API.
             * Generally you do not have 2 identical keys stored in to two
             * separate objects so the initial shortcircuit that matches if
             * slotid/handle are identical will often cover this. When that
             * fails we have no option but to fail for now. */
            P11PROV_debug("We can't really match private keys");
            /* OTOH if modulus and exponent match either this is a broken key
             * or the private key must also match */
            cmp_type = OBJ_CMP_KEY_PUBLIC;
        }
        break;

    case CKK_EC:
        ret = cmp_attr(key1, key2, CKA_EC_PARAMS);
        if (ret != RET_OSSL_OK) {
            /* If EC_PARAMS do not match it may be due to encoding.
             * Fall back to slower conversions and compare via EC_GROUP */
            CK_ATTRIBUTE *ec_p;
            const unsigned char *val;
            EC_GROUP *group1 = NULL;
            EC_GROUP *group2 = NULL;
            BN_CTX *bnctx = NULL;

            ec_p = p11prov_obj_get_attr(key1, CKA_EC_PARAMS);
            if (!ec_p) {
                ret = RET_OSSL_ERR;
                goto out;
            }
            val = ec_p->pValue;
            group1 = d2i_ECPKParameters(NULL, &val, ec_p->ulValueLen);
            if (!group1) {
                ret = RET_OSSL_ERR;
                goto out;
            }

            ec_p = p11prov_obj_get_attr(key2, CKA_EC_PARAMS);
            if (!ec_p) {
                ret = RET_OSSL_ERR;
                goto out;
            }
            val = ec_p->pValue;
            group2 = d2i_ECPKParameters(NULL, &val, ec_p->ulValueLen);
            if (!group2) {
                ret = RET_OSSL_ERR;
                goto out;
            }

            bnctx = BN_CTX_new_ex(p11prov_ctx_get_libctx(key1->ctx));
            if (!bnctx) {
                ret = RET_OSSL_ERR;
                goto out;
            }

            ret = EC_GROUP_cmp(group1, group2, bnctx);
            if (ret == 0) {
                ret = RET_OSSL_OK;
            } else {
                ret = RET_OSSL_ERR;
            }

        out:
            EC_GROUP_free(group1);
            EC_GROUP_free(group2);
            BN_CTX_free(bnctx);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
        }
        if (cmp_type & OBJ_CMP_KEY_PRIVATE) {
            /* unfortunately we can't really read private attributes
             * and there is no comparison function in the PKCS11 API.
             * Generally you do not have 2 identical keys stored in to two
             * separate objects so the initial shortcircuit that matches if
             * slotid/handle are identical will often cover this. When that
             * fails we have no option but to fail for now. */
            P11PROV_debug("We can't really match private keys");
            /* OTOH if group and pub point match either this is a broken key
             * or the private key must also match */
            cmp_type = OBJ_CMP_KEY_PUBLIC;
        }
        break;
    case CKK_EC_EDWARDS:
        /* The EdDSA params can be encoded as printable string, which is
         * not recognized by OpenSSL and does not have respective EC_GROUP */
        ret = cmp_attr(key1, key2, CKA_EC_PARAMS);
        if (ret != RET_OSSL_OK) {
            /* If EC_PARAMS do not match it may be due to encoding. */
            CK_ATTRIBUTE *ec_p;
            int nid1;
            int nid2;

            ec_p = p11prov_obj_get_attr(key1, CKA_EC_PARAMS);
            if (!ec_p) {
                return RET_OSSL_ERR;
            }
            nid1 = p11prov_obj_get_ed_nid(ec_p);
            if (nid1 == NID_undef) {
                return RET_OSSL_ERR;
            }

            ec_p = p11prov_obj_get_attr(key2, CKA_EC_PARAMS);
            if (!ec_p) {
                return RET_OSSL_ERR;
            }
            nid2 = p11prov_obj_get_ed_nid(ec_p);
            if (nid2 == NID_undef) {
                return RET_OSSL_ERR;
            }
            if (nid1 != nid2) {
                return RET_OSSL_ERR;
            }
        }
        if (cmp_type & OBJ_CMP_KEY_PRIVATE) {
            /* unfortunately we can't really read private attributes
             * and there is no comparison function in the PKCS11 API.
             * Generally you do not have 2 identical keys stored in to two
             * separate objects so the initial shortcircuit that matches if
             * slotid/handle are identical will often cover this. When that
             * fails we have no option but to fail for now. */
            P11PROV_debug("We can't really match private keys");
            /* OTOH if group and pub point match either this is a broken key
             * or the private key must also match */
            cmp_type = OBJ_CMP_KEY_PUBLIC;
        }
        break;

    case CKK_ML_DSA:
        /* The parameter set maps to the specific key bit length that was
         * compared already. If the bit size matches, the param set matches. */
        if (cmp_type & OBJ_CMP_KEY_PRIVATE) {
            /* unfortunately we can't really read private attributes
             * and there is no comparison function in the PKCS11 API.
             * Generally you do not have 2 identical keys stored in to two
             * separate objects so the initial shortcircuit that matches if
             * slotid/handle are identical will often cover this. When that
             * fails we have no option but to fail for now. */
            P11PROV_debug("We can't really match private keys");
            /* OTOH if param set and pub value match either this is a broken key
             * or the private key must also match */
            cmp_type = OBJ_CMP_KEY_PUBLIC;
        }
        break;

    case CKK_ML_KEM:
        /* The parameter set maps to the specific key bit length that was
         * compared already. If the bit size matches, the param set matches. */
        if (cmp_type & OBJ_CMP_KEY_PRIVATE) {
            /* unfortunately we can't really read private attributes
             * and there is no comparison function in the PKCS11 API.
             * Generally you do not have 2 identical keys stored in to two
             * separate objects so the initial shortcircuit that matches if
             * slotid/handle are identical will often cover this. When that
             * fails we have no option but to fail for now. */
            P11PROV_debug("We can't really match private keys");
            /* OTOH if param set and pub value match either this is a broken key
             * or the private key must also match */
            cmp_type = OBJ_CMP_KEY_PUBLIC;
        }
        break;

    default:
        return RET_OSSL_ERR;
    }

    if (cmp_type & OBJ_CMP_KEY_PUBLIC) {
        ret = match_public_keys(key1, key2);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    /* if nothing fails it is a match */
    return RET_OSSL_OK;
}
