/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "obj/internal.h"

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

static int prep_get_pub_key(P11PROV_OBJ **obj, CK_KEY_TYPE type)
{
    P11PROV_OBJ *key;

    if (!obj || !*obj) {
        return RET_OSSL_ERR;
    }

    key = *obj;

    if (key->class != CKO_PRIVATE_KEY && key->class != CKO_PUBLIC_KEY) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR, "Invalid Object Class");
        return RET_OSSL_ERR;
    }

    if (key->data.key.type != type) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR, "Unsupported key type");
        return RET_OSSL_ERR;
    }

    /* check if we have a pub key associated to a private key */
    if (key->class == CKO_PRIVATE_KEY) {
        P11PROV_OBJ *pobj = p11prov_obj_get_associated(key);
        if (pobj && pobj->class == CKO_PUBLIC_KEY) {
            /* replace obj with the public one */
            *obj = pobj;
        }
    }

    return RET_OSSL_OK;
}

int p11prov_obj_get_ed_pub_key(P11PROV_OBJ *obj, CK_ATTRIBUTE **pub)
{
    CK_ATTRIBUTE *a;
    int ret;

    P11PROV_debug("get ed pubkey %p", obj);

    ret = prep_get_pub_key(&obj, CKK_EC_EDWARDS);
    if (ret != RET_OSSL_OK) {
        return ret;
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

    ret = prep_get_pub_key(&obj, CKK_EC);
    if (ret != RET_OSSL_OK) {
        return ret;
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
    if (!x || !y) {
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
    int err;

    err = prep_get_pub_key(&key, CKK_EC);
    if (err != RET_OSSL_OK) {
        return NULL;
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

    ret = get_attrs_from_cert(cert, attrs, num);
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
    case CKK_ML_DSA:
    case CKK_ML_KEM:
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
        break;

    default:
        return RET_OSSL_ERR;
    }

    if (cmp_type & OBJ_CMP_KEY_PRIVATE) {
        /* unfortunately we can't really read private attributes
         * and there is no comparison function in the PKCS11 API.
         * Generally you do not have 2 identical keys stored in to two
         * separate objects so the initial shortcircuit that matches if
         * slotid/handle are identical will often cover this. When that
         * fails we have no option but to fail for now. */
        P11PROV_debug("We can't really match private keys");
        /* internally match_public_keys() optimizes for checking public
         * values if present on the private key, and falls back to fetching
         * an associated public key if that fails. Note that should both
         * keys be private this will fail as match_public_keys() only handle
         * the case where one of the two keys is private. That is all openssl
         * needs anyway, it never has any reason to try to match two private
         * keys so this is fine. */
        cmp_type = OBJ_CMP_KEY_PUBLIC;
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
