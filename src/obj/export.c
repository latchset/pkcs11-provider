/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "obj/internal.h"
#include "platform/endian.h"

#define MAX_KEY_ATTRS 2
CK_RV get_attrs_from_cert(P11PROV_OBJ *crt, CK_ATTRIBUTE *attrs, int num)
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
    CK_RV rv = CKR_OK;
    int i;

    for (i = 0; i < num; i++) {
        CK_ATTRIBUTE *a = p11prov_obj_get_attr(obj, attrs[i].type);
        if (a) {
            rv = p11prov_copy_attr(&attrs[i], a);
        } else {
            attrs[i].pValue = NULL;
            rv = CKR_CANCEL;
        }
        if (rv != CKR_OK) {
            for (; i >= 0; i--) {
                OPENSSL_free(attrs[i].pValue);
                attrs[i].ulValueLen = 0;
                attrs[i].pValue = NULL;
            }
            break;
        }
    }

    return rv;
}

static CK_RV get_attrs_from_pkeyinfo(P11PROV_OBJ *key, CK_ATTRIBUTE *attrs,
                                     int num)
{
    CK_ATTRIBUTE pubattrs[2] = { 0 };
    CK_ATTRIBUTE *pkeyinfo;
    CK_RV rv = CKR_GENERAL_ERROR;

    pkeyinfo = p11prov_obj_get_attr(key, CKA_PUBLIC_KEY_INFO);
    if (!pkeyinfo) {
        return CKR_GENERAL_ERROR;
    }

    switch (key->data.key.type) {
    case CKK_RSA:
        rv = rsa_pkeyinfo_to_attrs(pkeyinfo, pubattrs);
        if (rv != CKR_OK) {
            return rv;
        }
        break;
    case CKK_EC:
    case CKK_EC_EDWARDS:
    case CKK_EC_MONTGOMERY:
        pubattrs[0].type = CKA_P11PROV_PUB_KEY;
        rv = p11prov_pkeyinfo_to_pubkey(pkeyinfo, &pubattrs[0]);
        if (rv != CKR_OK) {
            return rv;
        }
        break;
    case CKK_ML_DSA:
    case CKK_ML_KEM:
        pubattrs[0].type = CKA_VALUE;
        rv = p11prov_pkeyinfo_to_pubkey(pkeyinfo, &pubattrs[0]);
        if (rv != CKR_OK) {
            return rv;
        }
        break;
    default:
        return CKR_KEY_INDIGESTIBLE;
    }

    for (int i = 0; i < num; i++) {
        bool found = false;
        for (int j = 0; j < 2; j++) {
            if (attrs[i].type == pubattrs[j].type) {
                attrs[i].pValue = pubattrs[j].pValue;
                pubattrs[j].pValue = NULL;
                attrs[i].ulValueLen = pubattrs[j].ulValueLen;
                found = true;
                break;
            }
        }
        if (!found) {
            rv = CKR_GENERAL_ERROR;
            goto done;
        }
    }

    rv = CKR_OK;
done:
    /* remove any leftover */
    for (int i = 0; i < 2; i++) {
        OPENSSL_free(pubattrs[i].pValue);
    }
    if (rv != CKR_OK) {
        for (int i = 0; i < num; i++) {
            OPENSSL_free(attrs[i].pValue);
            attrs[i].pValue = NULL;
            attrs[i].ulValueLen = 0;
        }
    }
    return rv;
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
        /* check if we can get public attrs from CKA_PUBLIC_KEY_INFO */
        rv = get_attrs_from_pkeyinfo(obj, attrs, num);
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
            rv = get_attrs_from_cert(tmp, attrs, num);
            p11prov_obj_free(tmp);
            return rv;
        }
        break;
    case CKO_CERTIFICATE:
        return get_attrs_from_cert(obj, attrs, num);
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

static int ec_group_explicit_to_params(P11PROV_CTX *ctx, const EC_GROUP *group,
                                       OSSL_PARAM *params, int *nparam)
{
    int fid;
    char *field_type;
    BIGNUM *p, *a, *b;
    const BIGNUM *order, *cofactor;
    const EC_POINT *generator;
    point_conversion_form_t genform;
    size_t bsize;
    void *buf;
    unsigned char *seed;
    size_t seed_len;
    BN_CTX *bnctx;
    int ret;

    bnctx = BN_CTX_new_ex(p11prov_ctx_get_libctx(ctx));
    if (bnctx == NULL) {
        return RET_OSSL_ERR;
    }
    BN_CTX_start(bnctx);

    fid = EC_GROUP_get_field_type(group);
    if (fid == NID_X9_62_prime_field) {
        field_type = OPENSSL_strdup(SN_X9_62_prime_field);
    } else if (fid == NID_X9_62_characteristic_two_field) {
        field_type = OPENSSL_strdup(SN_X9_62_characteristic_two_field);
    } else {
        P11PROV_raise(ctx, CKR_GENERAL_ERROR, "Invalid EC field");
        ret = RET_OSSL_ERR;
        goto done;
    }

    params[(*nparam)++] = OSSL_PARAM_construct_utf8_string(
        OSSL_PKEY_PARAM_EC_FIELD_TYPE, field_type, 0);

    p = BN_CTX_get(bnctx);
    a = BN_CTX_get(bnctx);
    b = BN_CTX_get(bnctx);
    if (b == NULL) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    if (!EC_GROUP_get_curve(group, p, a, b, bnctx)) {
        P11PROV_raise(ctx, CKR_GENERAL_ERROR, "Invalid curve");
        ret = RET_OSSL_ERR;
        goto done;
    }

    if (!ossl_param_construct_bn(ctx, &params[(*nparam)++],
                                 OSSL_PKEY_PARAM_EC_P, p)
        || !ossl_param_construct_bn(ctx, &params[(*nparam)++],
                                    OSSL_PKEY_PARAM_EC_A, a)
        || !ossl_param_construct_bn(ctx, &params[(*nparam)++],
                                    OSSL_PKEY_PARAM_EC_B, b)) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    order = EC_GROUP_get0_order(group);
    if (order == NULL) {
        P11PROV_raise(ctx, CKR_GENERAL_ERROR, "Invalid group order");
        ret = RET_OSSL_ERR;
        goto done;
    }
    if (!ossl_param_construct_bn(ctx, &params[(*nparam)++],
                                 OSSL_PKEY_PARAM_EC_ORDER, order)) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    generator = EC_GROUP_get0_generator(group);
    genform = EC_GROUP_get_point_conversion_form(group);
    if (generator == NULL) {
        P11PROV_raise(ctx, CKR_GENERAL_ERROR, "Invalid group generator");
        ret = RET_OSSL_ERR;
        goto done;
    }
    bsize = EC_POINT_point2oct(group, generator, genform, NULL, 0, bnctx);
    buf = OPENSSL_malloc(bsize);
    if (buf == NULL) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    bsize = EC_POINT_point2oct(group, generator, genform, buf, bsize, bnctx);
    params[(*nparam)++] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_EC_GENERATOR, buf, bsize);

    cofactor = EC_GROUP_get0_cofactor(group);
    if (cofactor == NULL) {
        P11PROV_raise(ctx, CKR_GENERAL_ERROR, "Invalid group cofactor");
        ret = RET_OSSL_ERR;
        goto done;
    }
    if (!ossl_param_construct_bn(ctx, &params[(*nparam)++],
                                 OSSL_PKEY_PARAM_EC_COFACTOR, cofactor)) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    seed = EC_GROUP_get0_seed(group);
    seed_len = EC_GROUP_get_seed_len(group);
    if (seed != NULL && seed_len > 0) {
        void *seed_copy = OPENSSL_memdup(seed, seed_len);
        if (!seed_copy) {
            ret = RET_OSSL_ERR;
            goto done;
        }
        params[(*nparam)++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_EC_SEED, seed_copy, seed_len);
    }

    ret = RET_OSSL_OK;

done:
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);
    return ret;
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

/* assumes CK_ECC only */
static int ec_export_params(P11PROV_OBJ *obj, OSSL_PARAM *params, int *nparams)
{
    CK_ATTRIBUTE attr = { 0 };
    EC_GROUP *group = NULL;
    CK_RV rv;
    int ret;

    attr.type = CKA_EC_PARAMS;
    rv = get_public_attrs(obj, &attr, 1);
    if (rv == CKR_OK) {
        /* in d2i functions 'in' is overwritten to return the remainder of
         * the buffer after parsing, so we always need to avoid passing in
         * our pointer holders, to avoid having them clobbered */
        const unsigned char *val = attr.pValue;
        group = d2i_ECPKParameters(NULL, &val, attr.ulValueLen);
        if (group == NULL) {
            ret = RET_OSSL_ERR;
            goto done;
        }
        ret = ec_group_explicit_to_params(obj->ctx, group, params, nparams);
        if (ret != RET_OSSL_OK) {
            goto done;
        }
    } else {
        attr.type = CKA_P11PROV_CURVE_NAME;
        rv = get_public_attrs(obj, &attr, 1);
        if (rv != CKR_OK) {
            P11PROV_raise(obj->ctx, rv, "Failed to get EC parameters");
            ret = RET_OSSL_ERR;
            goto done;
        }
        params[*nparams] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, attr.pValue, attr.ulValueLen);
        attr.pValue = NULL; /* steal it, will be freed by caller */
        *nparams += 1;
    }
    ret = RET_OSSL_OK;

done:
    EC_GROUP_free(group);
    OPENSSL_free(attr.pValue);
    return ret;
}

int p11prov_obj_export_params(P11PROV_OBJ *obj, OSSL_CALLBACK *cb_fn,
                              void *cb_arg)
{
    OSSL_PARAM params[EC_MAX_OSSL_PARAMS + 1] = { 0 };
    int nparam = 0;
    int ret;

    if (!obj) {
        return RET_OSSL_ERR;
    }

    if (obj->data.key.type != CKK_EC) {
        /* nothing to export, we must call the callback
         * with an empty array, to make OpenSSL happy */
        return cb_fn(params, cb_arg);
    }

    ret = ec_export_params(obj, params, &nparam);
    if (ret != RET_OSSL_OK) {
        goto done;
    }

    params[nparam] = OSSL_PARAM_construct_end();

    ret = cb_fn(params, cb_arg);

done:
    for (int i = 0; i < nparam; i++) {
        OPENSSL_free(params[i].data);
    }
    return ret;
}

static int p11prov_obj_export_public_ec_key(P11PROV_OBJ *obj,
                                            OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    OSSL_PARAM params[EC_MAX_OSSL_PARAMS + 1] = { 0 };
    int nparam = 0;
    CK_RV rv;
    int ret;

    CK_ATTRIBUTE attr = { CKA_P11PROV_PUB_KEY, NULL, 0 };
    rv = get_public_attrs(obj, &attr, 1);
    if (rv != CKR_OK) {
        P11PROV_raise(obj->ctx, rv, "Failed to get EC public key");
        ret = RET_OSSL_ERR;
        goto done;
    }

    /* transfers memory ownership of attr.pValue */
    params[nparam] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY, attr.pValue, attr.ulValueLen);
    nparam++;

    if (obj->data.key.type == CKK_EC) {
        ret = ec_export_params(obj, params, &nparam);
        if (ret != RET_OSSL_OK) {
            goto done;
        }
    }

    params[nparam] = OSSL_PARAM_construct_end();

    ret = cb_fn(params, cb_arg);

done:
    for (int i = 0; i < nparam; i++) {
        OPENSSL_free(params[i].data);
    }
    return ret;
}

static int p11prov_obj_export_public_ml_key(P11PROV_OBJ *obj,
                                            OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    CK_ATTRIBUTE attrs[1] = { { 0 } };
    OSSL_PARAM params[2];
    CK_RV rv;
    int ret, n = 0;

    attrs[0].type = CKA_VALUE;

    rv = get_public_attrs(obj, attrs, 1);
    if (rv != CKR_OK) {
        P11PROV_raise(obj->ctx, rv, "Failed to get public key attributes");
        return RET_OSSL_ERR;
    }

    params[n++] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY, attrs[0].pValue, attrs[0].ulValueLen);
    params[n++] = OSSL_PARAM_construct_end();

    ret = cb_fn(params, cb_arg);

    OPENSSL_free(attrs[0].pValue);
    return ret;
}

int p11prov_obj_export_public_key(P11PROV_OBJ *obj, CK_KEY_TYPE key_type,
                                  bool search_related, OSSL_CALLBACK *cb_fn,
                                  void *cb_arg)
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
    case CKK_EC_MONTGOMERY:
        return p11prov_obj_export_public_ec_key(obj, cb_fn, cb_arg);
    case CKK_ML_DSA:
    case CKK_ML_KEM:
        return p11prov_obj_export_public_ml_key(obj, cb_fn, cb_arg);
    default:
        P11PROV_raise(obj->ctx, CKR_GENERAL_ERROR, "Unsupported key type");
        return RET_OSSL_ERR;
    }
}
