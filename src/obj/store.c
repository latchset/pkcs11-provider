/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "obj/internal.h"
#include "platform/endian.h"

#define MAX_ATTRS_SIZE 4
struct pool_find_ctx {
    CK_KEY_TYPE type;
    CK_OBJECT_CLASS class;
    CK_ULONG key_size;
    CK_ULONG bit_size;
    CK_ULONG param_set;
    CK_ATTRIBUTE attrs[MAX_ATTRS_SIZE];
    int numattrs;
    P11PROV_OBJ *found;
};

static bool pool_find_callback(void *pctx, P11PROV_OBJ_POOL *pool)
{
    struct pool_find_ctx *ctx = (struct pool_find_ctx *)pctx;

    ctx->found =
        p11prov_obj_pool_find(pool, ctx->class, ctx->type, ctx->param_set,
                              ctx->bit_size, ctx->attrs, ctx->numattrs);

    return (ctx->found != NULL);
}

static CK_RV param_to_attr(P11PROV_CTX *ctx, const OSSL_PARAM params[],
                           const char *param_key, CK_ATTRIBUTE *dst,
                           CK_ATTRIBUTE_TYPE type, bool byteswap)
{
    const OSSL_PARAM *p;
    CK_ATTRIBUTE tmp;
    CK_RV rv;

    p = OSSL_PARAM_locate_const(params, param_key);
    if (!p) {
        P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s", param_key);
        return CKR_KEY_INDIGESTIBLE;
    }
    tmp.type = type;
    tmp.ulValueLen = p->data_size;
    tmp.pValue = p->data;
    rv = p11prov_copy_attr(dst, &tmp);
    if (rv != CKR_OK) {
        P11PROV_raise(ctx, CKR_HOST_MEMORY, "No space for %s", param_key);
        return CKR_HOST_MEMORY;
    }
    if (byteswap) {
        byteswap_buf(dst->pValue, dst->pValue, dst->ulValueLen);
    }
    return CKR_OK;
}

static CK_RV prep_rsa_find(P11PROV_CTX *ctx, const OSSL_PARAM params[],
                           struct pool_find_ctx *findctx)
{
    data_buffer digest_data[5];
    data_buffer digest = { 0 };
    const OSSL_PARAM *p;
    size_t key_size;
    CK_RV rv;

    if (findctx->numattrs != MAX_ATTRS_SIZE) {
        return CKR_ARGUMENTS_BAD;
    }
    findctx->numattrs = 0;

    switch (findctx->class) {
    case CKO_PUBLIC_KEY:
        rv = param_to_attr(ctx, params, OSSL_PKEY_PARAM_RSA_N,
                           &findctx->attrs[0], CKA_MODULUS, true);
        if (rv != CKR_OK) {
            return rv;
        }
        findctx->numattrs++;
        key_size = findctx->attrs[0].ulValueLen;

        rv = param_to_attr(ctx, params, OSSL_PKEY_PARAM_RSA_E,
                           &findctx->attrs[1], CKA_PUBLIC_EXPONENT, true);
        if (rv != CKR_OK) {
            return rv;
        }
        findctx->numattrs++;
        break;
    case CKO_PRIVATE_KEY:
        /* A Token would never allow us to search by private exponent,
         * so we store a hash of the private key in CKA_ID */

        /* prefix */
        digest_data[0].data = (uint8_t *)"PrivKey";
        digest_data[0].length = 7;

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_RSA_N);
            return CKR_KEY_INDIGESTIBLE;
        }
        digest_data[1].data = p->data;
        digest_data[1].length = p->data_size;
        key_size = p->data_size;

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_RSA_E);
            return CKR_KEY_INDIGESTIBLE;
        }
        digest_data[2].data = p->data;
        digest_data[2].length = p->data_size;

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_RSA_D);
            return CKR_KEY_INDIGESTIBLE;
        }
        digest_data[3].data = p->data;
        digest_data[3].length = p->data_size;

        digest_data[4].data = NULL;

        rv = p11prov_digest_util(ctx, "sha256", NULL, digest_data, &digest);

        if (rv != CKR_OK) {
            return rv;
        }
        findctx->attrs[0].type = CKA_ID;
        findctx->attrs[0].pValue = digest.data;
        findctx->attrs[0].ulValueLen = digest.length;
        findctx->numattrs++;

        break;
    default:
        return CKR_GENERAL_ERROR;
    }

    findctx->key_size = key_size;
    findctx->bit_size = key_size * 8;

    return CKR_OK;
}

/* P-521 ~ 133 bytes, this should suffice */
#define MAX_EC_PUB_KEY_SIZE 150
static CK_RV prep_ec_find(P11PROV_CTX *ctx, const OSSL_PARAM params[],
                          struct pool_find_ctx *findctx)
{
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BN_CTX *bn_ctx = NULL;

    OSSL_PARAM tmp;
    const OSSL_PARAM *p;
    OSSL_PARAM pub_key[2] = { 0 };
    uint8_t pub_data[MAX_EC_PUB_KEY_SIZE];

    data_buffer digest_data[5];
    data_buffer digest = { 0 };

    const char *curve_name = NULL;
    int curve_nid;
    unsigned char *ecparams = NULL;
    int len, i;
    CK_RV rv;

    if (findctx->numattrs != MAX_ATTRS_SIZE) {
        return CKR_ARGUMENTS_BAD;
    }
    findctx->numattrs = 0;

    group = EC_GROUP_new_from_params(params, p11prov_ctx_get_libctx(ctx), NULL);
    if (!group) {
        P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Unable to decode ec group");
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    curve_nid = EC_GROUP_get_curve_name(group);
    if (curve_nid != NID_undef) {
        curve_name = OSSL_EC_curve_nid2name(curve_nid);
        if (!curve_name) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Unknown curve");
            rv = CKR_KEY_INDIGESTIBLE;
            goto done;
        }
    }

    len = i2d_ECPKParameters(group, &ecparams);
    if (len < 0) {
        P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Failed to encode EC params");
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    switch (findctx->class) {
    case CKO_PUBLIC_KEY:
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_PUB_KEY);
            EC_GROUP_free(group);
            rv = CKR_KEY_INDIGESTIBLE;
            goto done;
        }

        /* Providers may export in any format - OpenSSL < 3.0.8
         * ignores the "point-format" OSSL_PARAM and unconditionally uses
         * compressed format:
         * - https://github.com/openssl/openssl/pull/16624
         * - https://github.com/openssl/openssl/issues/16595
         *
         * Convert from compressed to uncompressed if necessary
         */
        if (((char *)p->data)[0] == '\x02' || ((char *)p->data)[0] == '\x03') {
            int ret, plen;

            P11PROV_debug(
                "OpenSSL 3.0.7 BUG - received compressed EC public key");
            pub_key[0].key = OSSL_PKEY_PARAM_PUB_KEY;
            pub_key[0].data_type = p->data_type;
            pub_key[0].data = pub_data;

            point = EC_POINT_new(group);
            bn_ctx = BN_CTX_new();
            ret =
                EC_POINT_oct2point(group, point, p->data, p->data_size, bn_ctx);
            if (!ret) {
                rv = CKR_KEY_INDIGESTIBLE;
                goto done;
            }

            plen = EC_POINT_point2oct(
                group, point, POINT_CONVERSION_UNCOMPRESSED, pub_key[0].data,
                MAX_EC_PUB_KEY_SIZE, bn_ctx);
            if (!plen) {
                rv = CKR_KEY_INDIGESTIBLE;
                goto done;
            }

            pub_key[0].data_size = plen;
            rv = param_to_attr(ctx, pub_key, OSSL_PKEY_PARAM_PUB_KEY,
                               &findctx->attrs[0], CKA_P11PROV_PUB_KEY, false);
            if (rv != CKR_OK) {
                goto done;
            }
        } else {
            rv = param_to_attr(ctx, params, OSSL_PKEY_PARAM_PUB_KEY,
                               &findctx->attrs[0], CKA_P11PROV_PUB_KEY, false);
            if (rv != CKR_OK) {
                goto done;
            }
        }

        findctx->numattrs++;

        break;
    case CKO_PRIVATE_KEY:
        /* A Token would never allow us to search by private exponent,
         * so we store a hash of the private key in CKA_ID */
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_PRIV_KEY);
            return CKR_KEY_INDIGESTIBLE;
        }

        i = 0;

        /* prefix */
        digest_data[i].data = (uint8_t *)"PrivKey";
        digest_data[i].length = 7;
        i++;

        if (curve_name) {
            digest_data[i].data = (uint8_t *)curve_name;
            digest_data[i].length = strlen(curve_name);
            i++;
        }

        digest_data[i].data = ecparams;
        digest_data[i].length = len;
        i++;

        digest_data[i].data = p->data;
        digest_data[i].length = p->data_size;
        i++;

        digest_data[i].data = NULL;

        rv = p11prov_digest_util(ctx, "sha256", NULL, digest_data, &digest);
        if (rv != CKR_OK) {
            return rv;
        }
        findctx->attrs[0].type = CKA_ID;
        findctx->attrs[0].pValue = digest.data;
        findctx->attrs[0].ulValueLen = digest.length;
        findctx->numattrs++;

        break;
    default:
        return CKR_GENERAL_ERROR;
    }

    /* common params */
    tmp.key = "EC Params";
    tmp.data = ecparams;
    tmp.data_size = len;
    rv = param_to_attr(ctx, &tmp, tmp.key, &findctx->attrs[findctx->numattrs],
                       CKA_EC_PARAMS, false);
    if (rv != CKR_OK) {
        goto done;
    }
    findctx->numattrs++;

    tmp.key = "EC Group";
    tmp.data = &curve_nid;
    tmp.data_size = sizeof(curve_nid);
    rv = param_to_attr(ctx, &tmp, tmp.key, &findctx->attrs[findctx->numattrs],
                       CKA_P11PROV_CURVE_NID, false);
    if (rv != CKR_OK) {
        goto done;
    }
    findctx->numattrs++;

    if (curve_name) {
        tmp.key = "EC Curve Name";
        tmp.data = (void *)curve_name;
        tmp.data_size = strlen(curve_name) + 1;
        rv = param_to_attr(ctx, &tmp, tmp.key,
                           &findctx->attrs[findctx->numattrs],
                           CKA_P11PROV_CURVE_NAME, false);
        if (rv != CKR_OK) {
            goto done;
        }
        findctx->numattrs++;
    }

    findctx->bit_size = EC_GROUP_order_bits(group);
    findctx->key_size = (findctx->bit_size + 7) / 8;
    rv = CKR_OK;

done:
    OPENSSL_free(ecparams);
    EC_GROUP_free(group);
    EC_POINT_free(point);
    BN_CTX_free(bn_ctx);
    return rv;
}

static CK_RV prep_ed_find(P11PROV_CTX *ctx, const OSSL_PARAM params[],
                          struct pool_find_ctx *findctx)
{
    OSSL_PARAM tmp;
    const OSSL_PARAM *p;

    data_buffer digest_data[4];
    data_buffer digest = { 0 };

    const unsigned char *ecparams = NULL;
    int len, i;
    CK_RV rv;

    if (findctx->numattrs != MAX_ATTRS_SIZE) {
        return CKR_ARGUMENTS_BAD;
    }
    findctx->numattrs = 0;

    switch (findctx->class) {
    case CKO_PUBLIC_KEY:
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_PUB_KEY);
            rv = CKR_KEY_INDIGESTIBLE;
            goto done;
        }

        if (p->data_size == ED25519_BYTE_SIZE) {
            ecparams = ed25519_ec_params;
            len = ED25519_EC_PARAMS_LEN;
            findctx->bit_size = ED25519_BIT_SIZE;
            findctx->key_size = ED25519_BYTE_SIZE;
        } else if (p->data_size == ED448_BYTE_SIZE) {
            ecparams = ed448_ec_params;
            len = ED448_EC_PARAMS_LEN;
            findctx->bit_size = ED448_BIT_SIZE;
            findctx->key_size = ED448_BYTE_SIZE;
        } else {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE,
                          "Public key of unknown length %lu", p->data_size);
            rv = CKR_KEY_INDIGESTIBLE;
            goto done;
        }

        rv = param_to_attr(ctx, params, OSSL_PKEY_PARAM_PUB_KEY,
                           &findctx->attrs[0], CKA_P11PROV_PUB_KEY, false);
        if (rv != CKR_OK) {
            goto done;
        }

        findctx->numattrs++;

        break;
    case CKO_PRIVATE_KEY:
        /* A Token would never allow us to search by private exponent,
         * so we store a hash of the private key in CKA_ID */
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_PRIV_KEY);
            return CKR_KEY_INDIGESTIBLE;
        }

        i = 0;

        if (p->data_size == ED25519_BYTE_SIZE) {
            ecparams = ed25519_ec_params;
            len = ED25519_EC_PARAMS_LEN;
            findctx->bit_size = ED25519_BIT_SIZE;
            findctx->key_size = ED25519_BYTE_SIZE;
        } else if (p->data_size == ED448_BYTE_SIZE) {
            ecparams = ed448_ec_params;
            len = ED448_EC_PARAMS_LEN;
            findctx->bit_size = ED448_BIT_SIZE;
            findctx->key_size = ED448_BYTE_SIZE;
        } else {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE,
                          "Private key of unknown length %lu", p->data_size);
            rv = CKR_KEY_INDIGESTIBLE;
            goto done;
        }

        /* prefix */
        digest_data[i].data = (uint8_t *)"PrivKey";
        digest_data[i].length = 7;
        i++;

        digest_data[i].data = (CK_BYTE *)ecparams;
        digest_data[i].length = len;
        i++;

        digest_data[i].data = p->data;
        digest_data[i].length = p->data_size;
        i++;

        digest_data[i].data = NULL;

        rv = p11prov_digest_util(ctx, "sha256", NULL, digest_data, &digest);
        if (rv != CKR_OK) {
            return rv;
        }
        findctx->attrs[0].type = CKA_ID;
        findctx->attrs[0].pValue = digest.data;
        findctx->attrs[0].ulValueLen = digest.length;
        findctx->numattrs++;

        break;
    default:
        return CKR_GENERAL_ERROR;
    }

    /* common params */
    tmp.key = "EC Params";
    tmp.data = (CK_BYTE *)ecparams;
    tmp.data_size = len;
    rv = param_to_attr(ctx, &tmp, tmp.key, &findctx->attrs[findctx->numattrs],
                       CKA_EC_PARAMS, false);
    if (rv != CKR_OK) {
        goto done;
    }
    findctx->numattrs++;
    rv = CKR_OK;

done:
    return rv;
}

static CK_RV prep_mldsa_find(P11PROV_CTX *ctx, const OSSL_PARAM params[],
                             struct pool_find_ctx *findctx)
{
    data_buffer digest_data[4];
    data_buffer digest = { 0 };
    const OSSL_PARAM *p;
    CK_RV rv;
    int i;

    if (findctx->numattrs != MAX_ATTRS_SIZE) {
        return CKR_ARGUMENTS_BAD;
    }
    findctx->numattrs = 0;

    switch (findctx->param_set) {
    case CKP_ML_DSA_44:
        findctx->key_size = ML_DSA_44_PK_SIZE;
        break;
    case CKP_ML_DSA_65:
        findctx->key_size = ML_DSA_65_PK_SIZE;
        break;
    case CKP_ML_DSA_87:
        findctx->key_size = ML_DSA_87_PK_SIZE;
        break;
    default:
        return CKR_KEY_INDIGESTIBLE;
    }

    switch (findctx->class) {
    case CKO_PUBLIC_KEY:
        rv = param_to_attr(ctx, params, OSSL_PKEY_PARAM_PUB_KEY,
                           &findctx->attrs[0], CKA_VALUE, false);
        if (rv != CKR_OK) {
            return rv;
        }
        findctx->numattrs++;
        if (findctx->key_size != findctx->attrs[0].ulValueLen) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE,
                          "Unexpected public key size %lu (expected %lu)",
                          findctx->attrs[0].ulValueLen, findctx->key_size);
            return CKR_KEY_INDIGESTIBLE;
        }
        break;
    case CKO_PRIVATE_KEY:
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_PRIV_KEY);
            return CKR_KEY_INDIGESTIBLE;
        }

        i = 0;
        /* prefix */
        digest_data[i].data = (uint8_t *)"PrivKey";
        digest_data[i].length = 7;
        i++;

        digest_data[i].data = p->data;
        digest_data[i].length = p->data_size;
        i++;

        digest_data[i].data = NULL;

        rv = p11prov_digest_util(ctx, "sha256", NULL, digest_data, &digest);
        if (rv != CKR_OK) {
            return rv;
        }
        findctx->attrs[0].type = CKA_ID;
        findctx->attrs[0].pValue = digest.data;
        findctx->attrs[0].ulValueLen = digest.length;
        findctx->numattrs++;
        break;
    default:
        return CKR_GENERAL_ERROR;
    }

    /* common params */
    findctx->attrs[findctx->numattrs].type = CKA_PARAMETER_SET;
    findctx->attrs[findctx->numattrs].pValue =
        OPENSSL_malloc(sizeof(findctx->param_set));
    if (!findctx->attrs[findctx->numattrs].pValue) {
        return CKR_HOST_MEMORY;
    }
    memcpy(findctx->attrs[findctx->numattrs].pValue, &findctx->param_set,
           sizeof(findctx->param_set));
    findctx->attrs[findctx->numattrs].ulValueLen = sizeof(findctx->param_set);
    findctx->numattrs++;

    findctx->bit_size = findctx->key_size * 8;

    return CKR_OK;
}

static CK_RV prep_mlkem_find(P11PROV_CTX *ctx, const OSSL_PARAM params[],
                             struct pool_find_ctx *findctx)
{
    data_buffer digest_data[4];
    data_buffer digest = { 0 };
    const OSSL_PARAM *p;
    CK_RV rv;
    int i;

    if (findctx->numattrs != MAX_ATTRS_SIZE) {
        return CKR_ARGUMENTS_BAD;
    }
    findctx->numattrs = 0;

    switch (findctx->param_set) {
    case CKP_ML_KEM_512:
        findctx->key_size = ML_KEM_512_PK_SIZE;
        break;
    case CKP_ML_KEM_768:
        findctx->key_size = ML_KEM_768_PK_SIZE;
        break;
    case CKP_ML_KEM_1024:
        findctx->key_size = ML_KEM_1024_PK_SIZE;
        break;
    default:
        return CKR_KEY_INDIGESTIBLE;
    }

    switch (findctx->class) {
    case CKO_PUBLIC_KEY:
        rv = param_to_attr(ctx, params, OSSL_PKEY_PARAM_PUB_KEY,
                           &findctx->attrs[0], CKA_VALUE, false);
        if (rv != CKR_OK) {
            return rv;
        }
        findctx->numattrs++;
        if (findctx->key_size != findctx->attrs[0].ulValueLen) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE,
                          "Unexpected public key size %lu (expected %lu)",
                          findctx->attrs[0].ulValueLen, findctx->key_size);
            return CKR_KEY_INDIGESTIBLE;
        }
        break;
    case CKO_PRIVATE_KEY:
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (!p) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Missing %s",
                          OSSL_PKEY_PARAM_PRIV_KEY);
            return CKR_KEY_INDIGESTIBLE;
        }

        i = 0;
        /* prefix */
        digest_data[i].data = (uint8_t *)"PrivKey";
        digest_data[i].length = 7;
        i++;

        digest_data[i].data = p->data;
        digest_data[i].length = p->data_size;
        i++;

        digest_data[i].data = NULL;

        rv = p11prov_digest_util(ctx, "sha256", NULL, digest_data, &digest);
        if (rv != CKR_OK) {
            return rv;
        }
        findctx->attrs[0].type = CKA_ID;
        findctx->attrs[0].pValue = digest.data;
        findctx->attrs[0].ulValueLen = digest.length;
        findctx->numattrs++;
        break;
    default:
        return CKR_GENERAL_ERROR;
    }

    /* common params */
    findctx->attrs[findctx->numattrs].type = CKA_PARAMETER_SET;
    findctx->attrs[findctx->numattrs].pValue =
        OPENSSL_malloc(sizeof(findctx->param_set));
    if (!findctx->attrs[findctx->numattrs].pValue) {
        return CKR_HOST_MEMORY;
    }
    memcpy(findctx->attrs[findctx->numattrs].pValue, &findctx->param_set,
           sizeof(findctx->param_set));
    findctx->attrs[findctx->numattrs].ulValueLen = sizeof(findctx->param_set);
    findctx->numattrs++;

    findctx->bit_size = findctx->key_size * 8;

    return CKR_OK;
}

static CK_RV return_dup_key(P11PROV_OBJ *dst, P11PROV_OBJ *src)
{
    CK_RV rv;

    P11PROV_debug("duplicating obj key (dst=%p, src=%p, handle=%lu, "
                  "slotid=%lu, raf=%d, numattrs=%d)",
                  dst, src, src->handle, src->slotid, src->raf, src->numattrs);

    dst->slotid = src->slotid;
    dst->handle = src->handle;
    dst->class = src->class;
    dst->cka_copyable = src->cka_copyable;
    dst->cka_token = src->cka_token;
    dst->data.key = src->data.key;

    /* Free existing attributes if any */
    for (int i = 0; i < dst->numattrs; i++) {
        OPENSSL_free(dst->attrs[i].pValue);
    }
    OPENSSL_free(dst->attrs);

    dst->attrs = OPENSSL_zalloc(sizeof(CK_ATTRIBUTE) * src->numattrs);
    if (!dst->attrs) {
        rv = CKR_HOST_MEMORY;
        P11PROV_raise(dst->ctx, rv, "Failed allocation");
        return rv;
    }
    dst->numattrs = 0;
    for (int i = 0; i < src->numattrs; i++) {
        rv = p11prov_copy_attr(&dst->attrs[i], &src->attrs[i]);
        if (rv != CKR_OK) {
            rv = CKR_HOST_MEMORY;
            P11PROV_raise(dst->ctx, rv, "Failed attr copy");
            return rv;
        }
        dst->numattrs++;
    }

    return CKR_OK;
}

static CK_RV fix_ec_key_import(P11PROV_OBJ *key, int allocattrs)
{
    CK_ATTRIBUTE *pub;
    ASN1_OCTET_STRING oct;
    unsigned char *der = NULL;
    int len;

    if (key->numattrs >= allocattrs) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR,
                      "Too many attributes?? %d >= %d", key->numattrs,
                      allocattrs);
        return CKR_GENERAL_ERROR;
    }

    pub = p11prov_obj_get_attr(key, CKA_P11PROV_PUB_KEY);
    if (!pub) {
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE, "No public key found");
        return CKR_KEY_INDIGESTIBLE;
    }

    oct.data = pub->pValue;
    oct.length = pub->ulValueLen;
    oct.flags = 0;

    len = i2d_ASN1_OCTET_STRING(&oct, &der);
    if (len < 0) {
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Failure to encode EC point to DER");
        return CKR_KEY_INDIGESTIBLE;
    }
    key->attrs[key->numattrs].type = CKA_EC_POINT;
    key->attrs[key->numattrs].pValue = der;
    key->attrs[key->numattrs].ulValueLen = len;
    key->numattrs++;

    P11PROV_debug("fixing EC key %p import", key);

    return CKR_OK;
}

static CK_RV p11prov_obj_import_public_key(P11PROV_OBJ *key, CK_KEY_TYPE type,
                                           const OSSL_PARAM params[])
{
    P11PROV_CTX *ctx;
    struct pool_find_ctx findctx = {
        .type = type,
        .class = CKO_PUBLIC_KEY,
        .bit_size = 0,
        .param_set = CK_UNAVAILABLE_INFORMATION,
        .attrs = { { 0 } },
        .numattrs = MAX_ATTRS_SIZE,
        .found = NULL,
    };
    int allocattrs = 0;
    CK_RV rv;

    ctx = p11prov_obj_get_prov_ctx(key);
    if (!ctx) {
        return CKR_GENERAL_ERROR;
    }

    switch (type) {
    case CKK_RSA:
        P11PROV_debug("obj import of RSA public key %p", key);
        rv = prep_rsa_find(ctx, params, &findctx);
        if (rv != CKR_OK) {
            goto done;
        }
        allocattrs = RSA_ATTRS_NUM;
        break;

    case CKK_EC:
        P11PROV_debug("obj import of EC public key %p", key);
        rv = prep_ec_find(ctx, params, &findctx);
        if (rv != CKR_OK) {
            goto done;
        }
        allocattrs = EC_ATTRS_NUM;
        break;

    case CKK_EC_EDWARDS:
        P11PROV_debug("obj import of ED public key %p", key);
        rv = prep_ed_find(ctx, params, &findctx);
        if (rv != CKR_OK) {
            goto done;
        }
        allocattrs = EC_ATTRS_NUM;
        break;
    case CKK_ML_DSA:
        P11PROV_debug("obj import of ML-DSA public key %p", key);
        findctx.param_set = key->data.key.param_set;
        rv = prep_mldsa_find(ctx, params, &findctx);
        if (rv != CKR_OK) {
            goto done;
        }
        allocattrs = MLDSA_ATTRS_NUM;
        break;

    case CKK_ML_KEM:
        P11PROV_debug("obj import of ML-KEM public key %p", key);
        findctx.param_set = key->data.key.param_set;
        rv = prep_mlkem_find(ctx, params, &findctx);
        if (rv != CKR_OK) {
            goto done;
        }
        allocattrs = MLKEM_ATTRS_NUM;
        break;

    default:
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Unsupported key type: %08lx", type);
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    if (allocattrs < findctx.numattrs) {
        allocattrs = findctx.numattrs;
    }

    /* A common case with openssl is the request to import a key we already
     * actually have on the token. This happens because OpenSSL is greedy
     * and tries to export keys to its default provider before it even knows
     * what kind of operation it needs to do. Sometimes the operation ends up
     * being something that needs to be performed on the token. So try to see
     * if we already have this key */
    rv = p11prov_slot_find_obj_pool(ctx, pool_find_callback, &findctx);
    if (rv != CKR_OK) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR, "Failed to search pools");
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    if (findctx.found) {
        rv = return_dup_key(key, findctx.found);
        goto done;
    }

    /*
     * FIXME:
     * For things like ECDH we can get away with a mock object that just holds
     * data for now, but is not backed by an actual handle and key in the token.
     * Once this is not sufficient, we'll probably need to change functions to
     * pass in a valid session when requesting a handle from an object, so that
     * the key can be imported on the fly in the correct slot at the time the
     * operation needs to be performed.
     */
    P11PROV_debug("public key %p not found in the pool - using mock", key);

    /* move data */
    key->class = findctx.class;
    key->data.key.type = findctx.type;
    key->data.key.size = findctx.key_size;
    key->data.key.bit_size = findctx.bit_size;
    key->data.key.param_set = findctx.param_set;
    key->attrs = OPENSSL_malloc(sizeof(CK_ATTRIBUTE) * allocattrs);
    if (!key->attrs) {
        P11PROV_raise(key->ctx, CKR_HOST_MEMORY, "Failed allocation");
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    for (int i = 0; i < findctx.numattrs; i++) {
        key->attrs[i] = findctx.attrs[i];
        findctx.attrs[i].pValue = NULL;
    }
    key->numattrs = findctx.numattrs;
    findctx.numattrs = 0;

    if (type == CKK_EC || type == CKK_EC_EDWARDS) {
        rv = fix_ec_key_import(key, allocattrs);
    }

done:
    for (int i = 0; i < findctx.numattrs; i++) {
        OPENSSL_free(findctx.attrs[i].pValue);
    }
    return rv;
}

static CK_RV p11prov_store_rsa_public_key(P11PROV_OBJ *key)
{
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_false = CK_FALSE;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &key->class, sizeof(CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &key->data.key.type, sizeof(CK_KEY_TYPE) },
        /* we allow all operations as we do not know what is
         * the purpose of this key at import time */
        { CKA_ENCRYPT, &val_true, sizeof(val_true) },
        { CKA_VERIFY, &val_true, sizeof(val_true) },
        { CKA_WRAP, &val_true, sizeof(val_true) },
        /* public key part */
        { CKA_MODULUS, NULL, 0 }, /* 5 */
        { CKA_PUBLIC_EXPONENT, NULL, 0 }, /* 6 */
        /* TODO RSA PSS Params */
        { CKA_TOKEN, &val_false, sizeof(val_false) },
    };
    int na = sizeof(template) / sizeof(CK_ATTRIBUTE);
    CK_ATTRIBUTE *a;
    P11PROV_SLOTS_CTX *slots = NULL;
    CK_SLOT_ID slot = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SESSION *session = NULL;
    CK_RV rv = CKR_GENERAL_ERROR;

    a = p11prov_obj_get_attr(key, CKA_MODULUS);
    if (!a) {
        return CKR_GENERAL_ERROR;
    }
    template[5].pValue = a->pValue;
    template[5].ulValueLen = a->ulValueLen;

    a = p11prov_obj_get_attr(key, CKA_PUBLIC_EXPONENT);
    if (!a) {
        return CKR_GENERAL_ERROR;
    }
    template[6].pValue = a->pValue;
    template[6].ulValueLen = a->ulValueLen;

    slots = p11prov_ctx_get_slots(key->ctx);
    if (!slots) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    slot = p11prov_get_default_slot(slots);
    if (slot == CK_UNAVAILABLE_INFORMATION) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rv = p11prov_get_session(key->ctx, &slot, NULL, key->refresh_uri,
                             CK_UNAVAILABLE_INFORMATION, NULL, NULL, false,
                             true, &session);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_CreateObject(key->ctx, p11prov_session_handle(session),
                              template, na, &key->handle);
    if (rv != CKR_OK) {
        goto done;
    }

    key->slotid = slot;

    rv = CKR_OK;

done:
    if (rv == CKR_OK) {
        /* we just created an ephemeral key on this session, ensure the
         * session is not closed until the key goes away */
        p11prov_obj_set_session_ref(key, session);
    }
    p11prov_return_session(session);
    return rv;
}

static CK_RV p11prov_store_ec_public_key(P11PROV_OBJ *key)
{
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_false = CK_FALSE;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &key->class, sizeof(CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &key->data.key.type, sizeof(CK_KEY_TYPE) },
        /* we allow all operations as we do not know what is
         * the purpose of this key at import time */
        { CKA_DERIVE, &val_true, sizeof(val_true) },
        { CKA_VERIFY, &val_true, sizeof(val_true) },
        /* public part */
        { CKA_EC_PARAMS, NULL, 0 }, /* 4 */
        { CKA_EC_POINT, NULL, 0 }, /* 5 */
        { CKA_TOKEN, &val_false, sizeof(val_false) },
    };
    int na = sizeof(template) / sizeof(CK_ATTRIBUTE);
    CK_ATTRIBUTE *a;
    P11PROV_SLOTS_CTX *slots = NULL;
    CK_SLOT_ID slot = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SESSION *session = NULL;
    CK_RV rv = CKR_GENERAL_ERROR;

    a = p11prov_obj_get_attr(key, CKA_EC_PARAMS);
    if (!a) {
        return CKR_GENERAL_ERROR;
    }
    template[4].pValue = a->pValue;
    template[4].ulValueLen = a->ulValueLen;

    a = p11prov_obj_get_attr(key, CKA_EC_POINT);
    if (!a) {
        return CKR_GENERAL_ERROR;
    }
    template[5].pValue = a->pValue;
    template[5].ulValueLen = a->ulValueLen;

    slots = p11prov_ctx_get_slots(key->ctx);
    if (!slots) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    slot = p11prov_get_default_slot(slots);
    if (slot == CK_UNAVAILABLE_INFORMATION) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rv = p11prov_get_session(key->ctx, &slot, NULL, key->refresh_uri,
                             CK_UNAVAILABLE_INFORMATION, NULL, NULL, false,
                             true, &session);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_CreateObject(key->ctx, p11prov_session_handle(session),
                              template, na, &key->handle);
    if (rv != CKR_OK) {
        goto done;
    }

    key->slotid = slot;
    rv = CKR_OK;

done:
    if (rv == CKR_OK) {
        /* we just created an ephemeral key on this session, ensure the
         * session is not closed until the key goes away */
        p11prov_obj_set_session_ref(key, session);
    }
    p11prov_return_session(session);
    return rv;
}

static CK_RV p11prov_store_mldsa_public_key(P11PROV_OBJ *key)
{
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_false = CK_FALSE;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &key->class, sizeof(CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &key->data.key.type, sizeof(CK_KEY_TYPE) },
        { CKA_VERIFY, &val_true, sizeof(val_true) },
        /* public key part */
        { CKA_PARAMETER_SET, NULL, 0 },
        { CKA_VALUE, NULL, 0 },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
    };
    int na = sizeof(template) / sizeof(CK_ATTRIBUTE);
    CK_ATTRIBUTE *a;
    P11PROV_SLOTS_CTX *slots = NULL;
    CK_SLOT_ID slot = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SESSION *session = NULL;
    CK_RV rv = CKR_GENERAL_ERROR;

    a = p11prov_obj_get_attr(key, CKA_PARAMETER_SET);
    if (!a) {
        return CKR_GENERAL_ERROR;
    }
    template[3].pValue = a->pValue;
    template[3].ulValueLen = a->ulValueLen;

    a = p11prov_obj_get_attr(key, CKA_VALUE);
    if (!a) {
        return CKR_GENERAL_ERROR;
    }
    template[4].pValue = a->pValue;
    template[4].ulValueLen = a->ulValueLen;

    slots = p11prov_ctx_get_slots(key->ctx);
    if (!slots) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    slot = p11prov_get_default_slot(slots);
    if (slot == CK_UNAVAILABLE_INFORMATION) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rv = p11prov_get_session(key->ctx, &slot, NULL, key->refresh_uri,
                             CK_UNAVAILABLE_INFORMATION, NULL, NULL, false,
                             true, &session);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_CreateObject(key->ctx, p11prov_session_handle(session),
                              template, na, &key->handle);
    if (rv != CKR_OK) {
        goto done;
    }

    key->slotid = slot;

    rv = CKR_OK;

done:
    if (rv == CKR_OK) {
        /* we just created an ephemeral key on this session, ensure the
        * session is not closed until the key goes away */
        p11prov_obj_set_session_ref(key, session);
    }
    p11prov_return_session(session);
    return rv;
}

static CK_RV p11prov_store_mlkem_public_key(P11PROV_OBJ *key)
{
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_false = CK_FALSE;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &key->class, sizeof(CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &key->data.key.type, sizeof(CK_KEY_TYPE) },
        { CKA_ENCAPSULATE, &val_true, sizeof(val_true) },
        /* public key part */
        { CKA_PARAMETER_SET, NULL, 0 },
        { CKA_VALUE, NULL, 0 },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
    };
    int na = sizeof(template) / sizeof(CK_ATTRIBUTE);
    CK_ATTRIBUTE *a;
    P11PROV_SLOTS_CTX *slots = NULL;
    CK_SLOT_ID slot = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SESSION *session = NULL;
    CK_RV rv = CKR_GENERAL_ERROR;

    a = p11prov_obj_get_attr(key, CKA_PARAMETER_SET);
    if (!a) {
        return CKR_GENERAL_ERROR;
    }
    template[3].pValue = a->pValue;
    template[3].ulValueLen = a->ulValueLen;

    a = p11prov_obj_get_attr(key, CKA_VALUE);
    if (!a) {
        return CKR_GENERAL_ERROR;
    }
    template[4].pValue = a->pValue;
    template[4].ulValueLen = a->ulValueLen;

    slots = p11prov_ctx_get_slots(key->ctx);
    if (!slots) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    slot = p11prov_get_default_slot(slots);
    if (slot == CK_UNAVAILABLE_INFORMATION) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rv = p11prov_get_session(key->ctx, &slot, NULL, key->refresh_uri,
                             CK_UNAVAILABLE_INFORMATION, NULL, NULL, false,
                             true, &session);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_CreateObject(key->ctx, p11prov_session_handle(session),
                              template, na, &key->handle);
    if (rv != CKR_OK) {
        goto done;
    }

    key->slotid = slot;

    rv = CKR_OK;

done:
    if (rv == CKR_OK) {
        /* we just created an ephemeral key on this session, ensure the
        * session is not closed until the key goes away */
        p11prov_obj_set_session_ref(key, session);
    }
    p11prov_return_session(session);
    return rv;
}

CK_RV p11prov_obj_store_public_key(P11PROV_OBJ *key)
{
    int rv;

    P11PROV_debug("Store imported public key=%p", key);

    if (key->class != CKO_PUBLIC_KEY) {
        P11PROV_raise(key->ctx, CKR_OBJECT_HANDLE_INVALID, "Invalid key type");
        return CKR_OBJECT_HANDLE_INVALID;
    }

    switch (key->data.key.type) {
    case CKK_RSA:
        rv = p11prov_store_rsa_public_key(key);
        break;
    case CKK_EC:
    case CKK_EC_EDWARDS:
        rv = p11prov_store_ec_public_key(key);
        break;
    case CKK_ML_DSA:
        rv = p11prov_store_mldsa_public_key(key);
        break;
    case CKK_ML_KEM:
        rv = p11prov_store_mlkem_public_key(key);
        break;

    default:
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR,
                      "Unsupported key type: %08lx, should NOT happen",
                      key->data.key.type);
        rv = CKR_GENERAL_ERROR;
    }

    if (rv == CKR_OK) {
        /* this is a real object now, add it to the pool, but do not
         * fail if the operation goes haywire for some reason */
        (void)obj_add_to_pool(key);
    }

    return rv;
}

static CK_RV get_bn(const OSSL_PARAM *p, CK_ATTRIBUTE *attr)
{
    BIGNUM *bn = NULL;
    int bnlen;
    int err = 0;
    CK_RV ret;

    if (p == NULL) {
        return CKR_KEY_INDIGESTIBLE;
    }

    /* FIXME: investigate if this needs to be done in constant time
     * See BN_FLG_CONSTTIME */

    err = OSSL_PARAM_get_BN(p, &bn);
    if (err != RET_OSSL_OK) {
        return CKR_KEY_INDIGESTIBLE;
    }

    bnlen = BN_num_bytes(bn);
    attr->pValue = OPENSSL_malloc(bnlen);
    if (!attr->pValue) {
        ret = CKR_HOST_MEMORY;
        goto done;
    }
    attr->ulValueLen = BN_bn2bin(bn, attr->pValue);
    if (attr->ulValueLen == 0 || attr->ulValueLen > bnlen) {
        attr->ulValueLen = bnlen;
        ret = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    ret = CKR_OK;

done:
    if (ret != CKR_OK) {
        OPENSSL_clear_free(attr->pValue, bnlen);
        attr->pValue = NULL;
    }
    BN_free(bn);
    return ret;
}

static CK_RV p11prov_store_rsa_private_key(P11PROV_OBJ *key,
                                           struct pool_find_ctx *findctx,
                                           const OSSL_PARAM params[])
{
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_false = CK_FALSE;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &findctx->class, sizeof(CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &findctx->type, sizeof(CK_KEY_TYPE) },
        { CKA_ID, findctx->attrs[0].pValue,
          findctx->attrs[0].ulValueLen }, /* 2 */
        { CKA_SENSITIVE, &val_true, sizeof(val_true) },
        { CKA_EXTRACTABLE, &val_false, sizeof(val_false) },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
        /* we allow all operations as we do not know what is
         * the purpose of this key at import time */
        { CKA_DECRYPT, &val_true, sizeof(val_true) },
        { CKA_SIGN, &val_true, sizeof(val_true) },
        { CKA_UNWRAP, &val_true, sizeof(val_true) },
        /* public key part */
        { CKA_MODULUS, NULL, 0 }, /* 9 */
        { CKA_PUBLIC_EXPONENT, NULL, 0 }, /* 10 */
        /* private key part */
        { CKA_PRIVATE_EXPONENT, NULL, 0 },
        { CKA_PRIME_1, NULL, 0 }, /* optional from here */
        { CKA_PRIME_2, NULL, 0 },
        { CKA_EXPONENT_1, NULL, 0 },
        { CKA_EXPONENT_2, NULL, 0 },
        { CKA_COEFFICIENT, NULL, 0 },
        /* TODO RSA PSS Params */
    };
    int na = 9; /* minimum will be 12, up to 17 */
    const char *required[] = {
        OSSL_PKEY_PARAM_RSA_N,
        OSSL_PKEY_PARAM_RSA_E,
        OSSL_PKEY_PARAM_RSA_D,
    };
    const char *optional[] = {
        OSSL_PKEY_PARAM_RSA_FACTOR1,      OSSL_PKEY_PARAM_RSA_FACTOR2,
        OSSL_PKEY_PARAM_RSA_EXPONENT1,    OSSL_PKEY_PARAM_RSA_EXPONENT2,
        OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
    };
    const OSSL_PARAM *p;
    P11PROV_SLOTS_CTX *slots = NULL;
    CK_SLOT_ID slot = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SESSION *session = NULL;
    CK_RV rv = CKR_GENERAL_ERROR;

    /* required params */
    for (int i = 0; i < 3; i++) {
        p = OSSL_PARAM_locate_const(params, required[i]);
        rv = get_bn(p, &template[na]);
        if (rv != CKR_OK) {
            goto done;
        }
        na++;
    }

    /* optional */
    for (int i = 0; i < 5; i++) {
        p = OSSL_PARAM_locate_const(params, optional[i]);
        if (p) {
            rv = get_bn(p, &template[na]);
            if (rv == CKR_OK) {
                na++;
            }
        } else {
            /* we must have all or none of the optional,
             * if any is missing we pretend none of them were given */
            for (; i >= 0; i--) {
                na--;
                OPENSSL_clear_free(template[na].pValue,
                                   template[na].ulValueLen);
            }
            break;
        }
    }

    slots = p11prov_ctx_get_slots(key->ctx);
    if (!slots) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    slot = p11prov_get_default_slot(slots);
    if (slot == CK_UNAVAILABLE_INFORMATION) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rv = p11prov_get_session(key->ctx, &slot, NULL, key->refresh_uri,
                             CK_UNAVAILABLE_INFORMATION, NULL, NULL, false,
                             true, &session);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_CreateObject(key->ctx, p11prov_session_handle(session),
                              template, na, &key->handle);
    if (rv != CKR_OK) {
        goto done;
    }

    key->slotid = slot;
    key->class = findctx->class;
    key->data.key.type = findctx->type;
    key->data.key.size = findctx->key_size;
    key->data.key.bit_size = findctx->bit_size;
    key->attrs = OPENSSL_zalloc(sizeof(CK_ATTRIBUTE) * 3);
    if (!key->attrs) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    key->numattrs = 0;
    /* cka_id */
    rv = p11prov_copy_attr(&key->attrs[key->numattrs], &template[2]);
    if (rv != CKR_OK) {
        goto done;
    }
    key->numattrs += 1;
    /* steal modulus */
    key->attrs[key->numattrs] = template[9];
    template[9].pValue = NULL;
    key->numattrs += 1;
    /* steal public exponent */
    key->attrs[key->numattrs] = template[10];
    template[10].pValue = NULL;
    key->numattrs += 1;

    rv = CKR_OK;

done:
    if (rv == CKR_OK) {
        /* we just created an ephemeral key on this session, ensure the
        * session is not closed until the key goes away */
        p11prov_obj_set_session_ref(key, session);
    }
    p11prov_return_session(session);
    for (int i = 9; i < na; i++) {
        OPENSSL_clear_free(template[i].pValue, template[i].ulValueLen);
    }
    return rv;
}

static CK_RV p11prov_store_ec_private_key(P11PROV_OBJ *key,
                                          struct pool_find_ctx *findctx,
                                          const OSSL_PARAM params[])
{
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_false = CK_FALSE;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &findctx->class, sizeof(CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &findctx->type, sizeof(CK_KEY_TYPE) },
        { CKA_ID, findctx->attrs[0].pValue,
          findctx->attrs[0].ulValueLen }, /* 2 */
        { CKA_SENSITIVE, &val_true, sizeof(val_true) },
        { CKA_EXTRACTABLE, &val_false, sizeof(val_false) },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
        /* we allow all operations as we do not know what is
         * the purpose of this key at import time */
        { CKA_DERIVE, &val_true, sizeof(val_true) },
        { CKA_SIGN, &val_true, sizeof(val_true) },
        /* public part */
        { CKA_EC_PARAMS, findctx->attrs[1].pValue,
          findctx->attrs[1].ulValueLen }, /* 8 */
        /* private key part */
        { CKA_VALUE, NULL, 0 }, /* 9 */
    };
    int na = 10;
    const OSSL_PARAM *p;
    P11PROV_SLOTS_CTX *slots = NULL;
    CK_SLOT_ID slot = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SESSION *session = NULL;
    CK_RV rv = CKR_GENERAL_ERROR;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    rv = get_bn(p, &template[9]);
    if (rv != CKR_OK) {
        goto done;
    }

    slots = p11prov_ctx_get_slots(key->ctx);
    if (!slots) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    slot = p11prov_get_default_slot(slots);
    if (slot == CK_UNAVAILABLE_INFORMATION) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rv = p11prov_get_session(key->ctx, &slot, NULL, key->refresh_uri,
                             CK_UNAVAILABLE_INFORMATION, NULL, NULL, false,
                             true, &session);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_CreateObject(key->ctx, p11prov_session_handle(session),
                              template, na, &key->handle);
    if (rv != CKR_OK) {
        goto done;
    }

    key->slotid = slot;
    key->class = findctx->class;
    key->data.key.type = findctx->type;
    key->data.key.size = findctx->key_size;
    key->data.key.bit_size = findctx->bit_size;
    key->attrs = OPENSSL_zalloc(sizeof(CK_ATTRIBUTE) * findctx->numattrs);
    if (!key->attrs) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    key->numattrs = 0;
    for (int i = 0; i < findctx->numattrs; i++) {
        rv = p11prov_copy_attr(&key->attrs[i], &findctx->attrs[i]);
        if (rv != CKR_OK) {
            rv = CKR_HOST_MEMORY;
            P11PROV_raise(key->ctx, rv, "Failed attr copy");
            goto done;
        }
        key->numattrs++;
    }

    rv = CKR_OK;

done:
    if (rv == CKR_OK) {
        /* we just created an ephemeral key on this session, ensure the
        * session is not closed until the key goes away */
        p11prov_obj_set_session_ref(key, session);
    }
    p11prov_return_session(session);
    OPENSSL_clear_free(template[9].pValue, template[9].ulValueLen);
    return rv;
}

#ifndef OSSL_PKEY_PARAM_ML_DSA_SEED
#define OSSL_PKEY_PARAM_ML_DSA_SEED "seed"
#endif

static CK_RV p11prov_store_mldsa_private_key(P11PROV_OBJ *key,
                                             struct pool_find_ctx *findctx,
                                             const OSSL_PARAM params[])
{
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_false = CK_FALSE;
    const OSSL_PARAM *p;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &findctx->class, sizeof(CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &findctx->type, sizeof(CK_KEY_TYPE) },
        { CKA_ID, findctx->attrs[0].pValue, findctx->attrs[0].ulValueLen },
        { CKA_PARAMETER_SET, findctx->attrs[1].pValue,
          findctx->attrs[1].ulValueLen },
        { CKA_SENSITIVE, &val_true, sizeof(val_true) },
        { CKA_EXTRACTABLE, &val_false, sizeof(val_false) },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
        { CKA_SIGN, &val_true, sizeof(val_true) },
        /* private key part */
        { CKA_VALUE, NULL, 0 },
        { CKA_SEED, NULL, 0 },
    };
    int na = (sizeof(template) / sizeof(CK_ATTRIBUTE)) - 2;
    P11PROV_SLOTS_CTX *slots = NULL;
    CK_SLOT_ID slot = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SESSION *session = NULL;
    CK_RV rv = CKR_GENERAL_ERROR;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (!p) {
        return CKR_KEY_INDIGESTIBLE;
    }
    template[na].pValue = p->data;
    template[na].ulValueLen = p->data_size;
    na++;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED);
    if (p) {
        template[na].pValue = p->data;
        template[na].ulValueLen = p->data_size;
        na++;
    }

    slots = p11prov_ctx_get_slots(key->ctx);
    if (!slots) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    slot = p11prov_get_default_slot(slots);
    if (slot == CK_UNAVAILABLE_INFORMATION) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rv = p11prov_get_session(key->ctx, &slot, NULL, key->refresh_uri,
                             CK_UNAVAILABLE_INFORMATION, NULL, NULL, false,
                             true, &session);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_CreateObject(key->ctx, p11prov_session_handle(session),
                              template, na, &key->handle);
    if (rv != CKR_OK) {
        goto done;
    }

    key->slotid = slot;
    key->class = findctx->class;
    key->data.key.type = findctx->type;
    key->data.key.size = findctx->key_size;
    key->data.key.bit_size = findctx->bit_size;
    key->data.key.param_set = findctx->param_set;
    key->attrs = OPENSSL_zalloc(sizeof(CK_ATTRIBUTE) * findctx->numattrs);
    if (!key->attrs) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    key->numattrs = 0;
    for (int i = 0; i < findctx->numattrs; i++) {
        rv = p11prov_copy_attr(&key->attrs[i], &findctx->attrs[i]);
        if (rv != CKR_OK) {
            rv = CKR_HOST_MEMORY;
            P11PROV_raise(key->ctx, rv, "Failed attr copy");
            goto done;
        }
        key->numattrs++;
    }
    rv = CKR_OK;

done:
    if (rv == CKR_OK) {
        /* we just created an ephemeral key on this session, ensure the
        * session is not closed until the key goes away */
        p11prov_obj_set_session_ref(key, session);
    }
    p11prov_return_session(session);
    return rv;
}

static CK_RV p11prov_store_mlkem_private_key(P11PROV_OBJ *key,
                                             struct pool_find_ctx *findctx,
                                             const OSSL_PARAM params[])
{
    CK_BBOOL val_true = CK_TRUE;
    CK_BBOOL val_false = CK_FALSE;
    const OSSL_PARAM *p;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &findctx->class, sizeof(CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &findctx->type, sizeof(CK_KEY_TYPE) },
        { CKA_ID, findctx->attrs[0].pValue, findctx->attrs[0].ulValueLen },
        { CKA_PARAMETER_SET, findctx->attrs[1].pValue,
          findctx->attrs[1].ulValueLen },
        { CKA_SENSITIVE, &val_true, sizeof(val_true) },
        { CKA_EXTRACTABLE, &val_false, sizeof(val_false) },
        { CKA_TOKEN, &val_false, sizeof(val_false) },
        { CKA_DECAPSULATE, &val_true, sizeof(val_true) },
        /* private key part */
        { CKA_VALUE, NULL, 0 },
    };
    int na = sizeof(template) / sizeof(CK_ATTRIBUTE);
    P11PROV_SLOTS_CTX *slots = NULL;
    CK_SLOT_ID slot = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SESSION *session = NULL;
    CK_RV rv = CKR_GENERAL_ERROR;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (!p) {
        return CKR_KEY_INDIGESTIBLE;
    }
    template[na - 1].pValue = p->data;
    template[na - 1].ulValueLen = p->data_size;

    slots = p11prov_ctx_get_slots(key->ctx);
    if (!slots) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    slot = p11prov_get_default_slot(slots);
    if (slot == CK_UNAVAILABLE_INFORMATION) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rv = p11prov_get_session(key->ctx, &slot, NULL, key->refresh_uri,
                             CK_UNAVAILABLE_INFORMATION, NULL, NULL, false,
                             true, &session);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_CreateObject(key->ctx, p11prov_session_handle(session),
                              template, na, &key->handle);
    if (rv != CKR_OK) {
        goto done;
    }

    key->slotid = slot;
    key->class = findctx->class;
    key->data.key.type = findctx->type;
    key->data.key.size = findctx->key_size;
    key->data.key.bit_size = findctx->bit_size;
    key->data.key.param_set = findctx->param_set;
    key->attrs = OPENSSL_zalloc(sizeof(CK_ATTRIBUTE) * findctx->numattrs);
    if (!key->attrs) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    key->numattrs = 0;
    for (int i = 0; i < findctx->numattrs; i++) {
        rv = p11prov_copy_attr(&key->attrs[i], &findctx->attrs[i]);
        if (rv != CKR_OK) {
            rv = CKR_HOST_MEMORY;
            P11PROV_raise(key->ctx, rv, "Failed attr copy");
            goto done;
        }
        key->numattrs++;
    }
    rv = CKR_OK;

done:
    if (rv == CKR_OK) {
        /* we just created an ephemeral key on this session, ensure the
        * session is not closed until the key goes away */
        p11prov_obj_set_session_ref(key, session);
    }
    p11prov_return_session(session);
    return rv;
}

static CK_RV p11prov_obj_import_private_key(P11PROV_OBJ *key, CK_KEY_TYPE type,
                                            const OSSL_PARAM params[])
{
    P11PROV_CTX *ctx;
    struct pool_find_ctx findctx = {
        .type = type,
        .class = CKO_PRIVATE_KEY,
        .param_set = CK_UNAVAILABLE_INFORMATION,
        .attrs = { { 0 } },
        .numattrs = MAX_ATTRS_SIZE,
        .found = NULL,
    };
    CK_RV rv;

    ctx = p11prov_obj_get_prov_ctx(key);
    if (!ctx) {
        return CKR_GENERAL_ERROR;
    }

    switch (type) {
    case CKK_RSA:
        rv = prep_rsa_find(ctx, params, &findctx);
        if (rv != CKR_OK) {
            goto done;
        }
        break;

    case CKK_EC:
        rv = prep_ec_find(ctx, params, &findctx);
        if (rv != CKR_OK) {
            goto done;
        }
        break;

    case CKK_EC_EDWARDS:
        rv = prep_ed_find(ctx, params, &findctx);
        if (rv != CKR_OK) {
            goto done;
        }
        break;
    case CKK_ML_DSA:
        findctx.param_set = key->data.key.param_set;
        rv = prep_mldsa_find(ctx, params, &findctx);
        if (rv != CKR_OK) {
            goto done;
        }
        break;
    case CKK_ML_KEM:
        findctx.param_set = key->data.key.param_set;
        rv = prep_mlkem_find(ctx, params, &findctx);
        if (rv != CKR_OK) {
            goto done;
        }
        break;

    default:
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Unsupported key type: %08lx", type);
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    /* The only case for private keys is an application loading a key from
     * a file or other mean and then asking (explicitly or implicitly) a
     * pkcs11-provider mechanism to use it. There is no other case because
     * tokens do not allow to export private keys.
     *
     * However we may have had the request to load this key before so we
     * still need to check if we have previously uploaded this key as a
     * session key before. If not we will compute a hash of the private
     * key to store in CKA_ID for future lockup and store it in the token
     * on the long lived login session.
     */
    rv = p11prov_slot_find_obj_pool(ctx, pool_find_callback, &findctx);
    if (rv != CKR_OK) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR, "Failed to search pools");
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    if (findctx.found) {
        rv = return_dup_key(key, findctx.found);
        goto done;
    }

    /*
     * No cached object found, create a session key on the login session so
     * that its handle will live long enough for multiple operations.
     */

    switch (type) {
    case CKK_RSA:
        rv = p11prov_store_rsa_private_key(key, &findctx, params);
        break;
    case CKK_EC:
    case CKK_EC_EDWARDS:
        rv = p11prov_store_ec_private_key(key, &findctx, params);
        break;
    case CKK_ML_DSA:
        rv = p11prov_store_mldsa_private_key(key, &findctx, params);
        break;
    case CKK_ML_KEM:
        rv = p11prov_store_mlkem_private_key(key, &findctx, params);
        break;

    default:
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR,
                      "Unsupported key type: %08lx, should NOT happen", type);
        rv = CKR_GENERAL_ERROR;
    }

done:
    for (int i = 0; i < findctx.numattrs; i++) {
        OPENSSL_free(findctx.attrs[i].pValue);
    }
    return rv;
}

static CK_RV import_ec_params(P11PROV_OBJ *key, const OSSL_PARAM params[])
{
    P11PROV_CTX *ctx;
    EC_GROUP *group = NULL;
    const char *curve_name = NULL;
    int curve_nid;
    unsigned char *ecparams = NULL;
    CK_ATTRIBUTE *cka_ec_params;
    CK_ATTRIBUTE *cka_nid;
    CK_ATTRIBUTE *cka_name;
    CK_ATTRIBUTE tmp;
    int add_attrs = 0;
    int len;
    CK_RV rv;

    ctx = p11prov_obj_get_prov_ctx(key);
    if (!ctx) {
        return CKR_GENERAL_ERROR;
    }

    group = EC_GROUP_new_from_params(params, p11prov_ctx_get_libctx(ctx), NULL);
    if (!group) {
        P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Unable to decode ec group");
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    curve_nid = EC_GROUP_get_curve_name(group);
    if (curve_nid != NID_undef) {
        curve_name = OSSL_EC_curve_nid2name(curve_nid);
        if (!curve_name) {
            P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Unknown curve");
            rv = CKR_KEY_INDIGESTIBLE;
            goto done;
        }
    }

    len = i2d_ECPKParameters(group, &ecparams);
    if (len < 0) {
        P11PROV_raise(ctx, CKR_KEY_INDIGESTIBLE, "Failed to encode EC params");
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    cka_ec_params = p11prov_obj_get_attr(key, CKA_EC_PARAMS);
    if (!cka_ec_params) {
        add_attrs += 1;
    }

    cka_nid = p11prov_obj_get_attr(key, CKA_P11PROV_CURVE_NID);
    if (!cka_nid) {
        add_attrs += 1;
    }

    cka_name = p11prov_obj_get_attr(key, CKA_P11PROV_CURVE_NAME);
    if (!cka_name && curve_name) {
        add_attrs += 1;
    }

    if (add_attrs > 0) {
        void *tmp_ptr;
        tmp_ptr = OPENSSL_realloc(
            key->attrs, sizeof(CK_ATTRIBUTE) * (key->numattrs + add_attrs));
        if (!tmp_ptr) {
            rv = CKR_HOST_MEMORY;
            goto done;
        }
        key->attrs = tmp_ptr;
    }

    /* EC Params */
    if (cka_ec_params) {
        OPENSSL_free(cka_ec_params->pValue);
    } else {
        cka_ec_params = &key->attrs[key->numattrs];
        key->numattrs++;
    }
    cka_ec_params->type = CKA_EC_PARAMS;
    cka_ec_params->pValue = ecparams;
    ecparams = NULL;
    cka_ec_params->ulValueLen = len;

    /* Curve Nid */
    if (cka_nid) {
        OPENSSL_free(cka_nid->pValue);
    } else {
        cka_nid = &key->attrs[key->numattrs];
        key->numattrs++;
    }
    cka_nid->pValue = NULL;
    tmp.type = CKA_P11PROV_CURVE_NID;
    tmp.pValue = &curve_nid;
    tmp.ulValueLen = sizeof(curve_nid);
    rv = p11prov_copy_attr(cka_nid, &tmp);
    if (rv != CKR_OK) {
        goto done;
    }

    /* Curve name */
    if (cka_name) {
        OPENSSL_free(cka_name->pValue);
        cka_name->type = CK_UNAVAILABLE_INFORMATION;
        cka_name->pValue = NULL;
        cka_name->ulValueLen = 0;
    }
    if (curve_name) {
        if (!cka_name) {
            cka_name = &key->attrs[key->numattrs];
            key->numattrs++;
        }
        tmp.type = CKA_P11PROV_CURVE_NAME;
        tmp.pValue = (void *)curve_name;
        tmp.ulValueLen = strlen(curve_name) + 1;
        rv = p11prov_copy_attr(cka_name, &tmp);
        if (rv != CKR_OK) {
            goto done;
        }
    }

    /* This is geneally the first call when importing keys from OpenSSL,
     * so ensure the other common object parameters are correct as well */
    key->data.key.type = CKK_EC;
    key->data.key.bit_size = EC_GROUP_order_bits(group);
    key->data.key.size = (key->data.key.bit_size + 7) / 8;

done:
    OPENSSL_free(ecparams);
    EC_GROUP_free(group);
    return rv;
}

static CK_RV p11prov_obj_set_domain_params(P11PROV_OBJ *key, CK_KEY_TYPE type,
                                           const OSSL_PARAM params[])
{
    switch (type) {
    case CKK_EC:
        /* EC_PARAMS */
        return import_ec_params(key, params);

    default:
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Unsupported key type: %08lx", type);
        return CKR_KEY_INDIGESTIBLE;
    }
}

CK_RV p11prov_obj_import_key(P11PROV_OBJ *key, CK_KEY_TYPE type,
                             CK_OBJECT_CLASS class,
                             CK_ML_DSA_PARAMETER_SET_TYPE param_set,
                             const OSSL_PARAM params[])
{
    /* This operation available only on new objects, can't import over an
     * existing one */
    if (key->class != CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(key->ctx, CKR_ARGUMENTS_BAD, "Non empty object");
        return CKR_ARGUMENTS_BAD;
    }

    if (type == CKK_ML_DSA || type == CKM_ML_KEM) {
        key->data.key.param_set = param_set;
    }

    switch (class) {
    case CKO_PUBLIC_KEY:
        key->class = CKO_PUBLIC_KEY;
        return p11prov_obj_import_public_key(key, type, params);
    case CKO_PRIVATE_KEY:
        key->class = CKO_PRIVATE_KEY;
        return p11prov_obj_import_private_key(key, type, params);
    case CKO_DOMAIN_PARAMETERS:
        key->class = CKO_DOMAIN_PARAMETERS;
        return p11prov_obj_set_domain_params(key, type, params);
    default:
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Invalid object class or key type");
        return CKR_KEY_INDIGESTIBLE;
    }
}

#if SKEY_SUPPORT

static CK_RV p11prov_store_aes_key(P11PROV_CTX *provctx, P11PROV_OBJ **ret,
                                   const unsigned char *secret,
                                   size_t secretlen, char *label,
                                   CK_FLAGS usage, bool session_key)
{
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_SLOT_ID slot = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SLOTS_CTX *slots = NULL;
    P11PROV_SESSION *session = NULL;
    CK_OBJECT_HANDLE key_handle;
    CK_BBOOL tokenobj = false;
    P11PROV_OBJ *obj;
    CK_RV rv;
    CK_ATTRIBUTE tmpl[12] = {
        { CKA_TOKEN, &tokenobj, sizeof(tokenobj) },
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_VALUE, (void *)secret, secretlen },
        { 0 },
    };
    size_t tmax = sizeof(tmpl) / sizeof(CK_ATTRIBUTE);
    size_t tsize = 4;

    P11PROV_debug("Creating secret key (%p[%zu]), token: %b, flags: %x", secret,
                  secretlen, !session_key, usage);

    /* Make it a token (permanent) object if necessary */
    if (!session_key) {
        tokenobj = true;
    }

    if (usage) {
        rv = p11prov_usage_to_template(tmpl, &tsize, tmax, usage);
        if (rv != CKR_OK) {
            P11PROV_raise(provctx, rv, "Failed to set key usage");
            return CKR_GENERAL_ERROR;
        }
    } else {
        rv = CKR_ARGUMENTS_BAD;
        P11PROV_raise(provctx, rv, "No key usage specified");
        return CKR_GENERAL_ERROR;
    }

    slots = p11prov_ctx_get_slots(provctx);
    if (!slots) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    slot = p11prov_get_default_slot(slots);
    if (slot == CK_UNAVAILABLE_INFORMATION) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rv = p11prov_get_session(provctx, &slot, NULL, NULL,
                             CK_UNAVAILABLE_INFORMATION, NULL, NULL, true, true,
                             &session);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_CreateObject(provctx, p11prov_session_handle(session), tmpl,
                              tsize, &key_handle);
    if (rv != CKR_OK) {
        goto done;
    }

    obj = p11prov_obj_new(provctx, slot, key_handle, key_class);
    if (obj == NULL) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    obj->data.key.type = key_type;
    obj->data.key.bit_size = secretlen * 8;
    obj->data.key.size = secretlen;

    *ret = obj;
    rv = CKR_OK;

done:
    if (rv == CKR_OK && session_key) {
        /* we just created an ephemeral key on this session, ensure the
        * session is not closed until the key goes away */
        p11prov_obj_set_session_ref(obj, session);
    }
    p11prov_return_session(session);
    return rv;
}

static CK_RV p11prov_store_generic_secret_key(P11PROV_CTX *provctx,
                                              P11PROV_OBJ **ret,
                                              const unsigned char *secret,
                                              size_t secretlen, char *label,
                                              CK_FLAGS usage, bool session_key)
{
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_SLOT_ID slot = CK_UNAVAILABLE_INFORMATION;
    P11PROV_SLOTS_CTX *slots = NULL;
    P11PROV_SESSION *session = NULL;
    CK_OBJECT_HANDLE key_handle;
    CK_BBOOL tokenobj = false;
    P11PROV_OBJ *obj;
    CK_RV rv;
    CK_ATTRIBUTE tmpl[12] = {
        { CKA_TOKEN, &tokenobj, sizeof(tokenobj) },
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_VALUE, (void *)secret, secretlen },
        { 0 },
    };
    size_t tmax = sizeof(tmpl) / sizeof(CK_ATTRIBUTE);
    size_t tsize = 4;

    P11PROV_debug("Creating secret key (%p[%zu]), token: %b, flags: %x", secret,
                  secretlen, !session_key, usage);

    /* Make it a token (permanent) object if necessary */
    if (!session_key) {
        tokenobj = true;
    }

    if (usage) {
        rv = p11prov_usage_to_template(tmpl, &tsize, tmax, usage);
        if (rv != CKR_OK) {
            P11PROV_raise(provctx, rv, "Failed to set key usage");
            return CKR_GENERAL_ERROR;
        }
    } else {
        rv = CKR_ARGUMENTS_BAD;
        P11PROV_raise(provctx, rv, "No key usage specified");
        return CKR_GENERAL_ERROR;
    }

    slots = p11prov_ctx_get_slots(provctx);
    if (!slots) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    slot = p11prov_get_default_slot(slots);
    if (slot == CK_UNAVAILABLE_INFORMATION) {
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    rv = p11prov_get_session(provctx, &slot, NULL, NULL,
                             CK_UNAVAILABLE_INFORMATION, NULL, NULL, true, true,
                             &session);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = p11prov_CreateObject(provctx, p11prov_session_handle(session), tmpl,
                              tsize, &key_handle);
    if (rv != CKR_OK) {
        goto done;
    }

    obj = p11prov_obj_new(provctx, slot, key_handle, key_class);
    if (obj == NULL) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    obj->data.key.type = key_type;
    obj->data.key.bit_size = secretlen * 8;
    obj->data.key.size = secretlen;

    *ret = obj;
    rv = CKR_OK;

done:
    if (rv == CKR_OK && session_key) {
        /* we just created an ephemeral key on this session, ensure the
        * session is not closed until the key goes away */
        p11prov_obj_set_session_ref(obj, session);
    }
    p11prov_return_session(session);
    return rv;
}

P11PROV_OBJ *p11prov_obj_import_secret_key(P11PROV_CTX *ctx, CK_KEY_TYPE type,
                                           const unsigned char *key,
                                           size_t keylen)
{
    CK_RV rv = CKR_KEY_INDIGESTIBLE;
    P11PROV_OBJ *obj = NULL;
    CK_FLAGS usage = CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY
                     | CKF_WRAP | CKF_UNWRAP | CKF_DERIVE;

    /* TODO: cache find, see other key types */

    switch (type) {
    case CKK_AES:
        rv = p11prov_store_aes_key(ctx, &obj, key, keylen, NULL, usage, true);
        if (rv != CKR_OK) {
            P11PROV_raise(ctx, rv, "Failed to import");
            goto done;
        }
        break;
    case CKK_GENERIC_SECRET:
        rv = p11prov_store_generic_secret_key(ctx, &obj, key, keylen, NULL,
                                              usage, true);
        if (rv != CKR_OK) {
            P11PROV_raise(ctx, rv, "Failed to import");
            goto done;
        }
        break;

    default:
        P11PROV_raise(ctx, rv, "Unsupported key type: %08lx", type);
        goto done;
    }

done:
    if (rv != CKR_OK) {
        p11prov_obj_free(obj);
        obj = NULL;
    }
    return obj;
}

#endif /* SKEY_SUPPORT */
