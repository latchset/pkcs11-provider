/* Copyright (C) 2026 Mounir IDRASSI
   SPDX-License-Identifier: Apache-2.0 */

#include <limits.h>
#include <stdbool.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>

#include "ec_point.h"

CK_RV p11prov_decode_ec_point_value(CK_KEY_TYPE key_type,
                                    CK_ULONG expected_size,
                                    const CK_ATTRIBUTE *attr,
                                    unsigned char **decoded,
                                    size_t *decoded_len)
{
    ASN1_OCTET_STRING *octet = NULL;
    const unsigned char *value;
    const unsigned char *value_end;
    const unsigned char *point = NULL;
    size_t point_len = 0;
    int asn1_len;
    bool is_ecx;
    CK_RV ret = CKR_KEY_INDIGESTIBLE;

    if (attr == NULL || decoded == NULL || decoded_len == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    *decoded = NULL;
    *decoded_len = 0;

    is_ecx = key_type == CKK_EC_EDWARDS || key_type == CKK_EC_MONTGOMERY;
    if (key_type != CKK_EC && !is_ecx) {
        return CKR_KEY_TYPE_INCONSISTENT;
    }
    if (is_ecx
        && (expected_size == 0
            || expected_size == CK_UNAVAILABLE_INFORMATION)) {
        return CKR_KEY_INDIGESTIBLE;
    }

    if (attr->pValue == NULL || attr->ulValueLen == 0
        || attr->ulValueLen > (CK_ULONG)LONG_MAX) {
        return CKR_KEY_INDIGESTIBLE;
    }

    /*
     * PKCS#11 3.1 and later specify raw CKA_EC_POINT values for Edwards and
     * Montgomery keys. Check the expected raw size before trying DER because
     * arbitrary public-key bytes can accidentally form a valid DER prefix.
     */
    if (is_ecx && attr->ulValueLen == expected_size) {
        point = attr->pValue;
        point_len = attr->ulValueLen;
        goto done;
    }

    value = attr->pValue;
    value_end = value + attr->ulValueLen;
    octet = d2i_ASN1_OCTET_STRING(NULL, &value, (long)attr->ulValueLen);
    if (octet == NULL || (is_ecx && value != value_end)) {
        goto done;
    }

    asn1_len = ASN1_STRING_length(octet);
    if (asn1_len <= 0) {
        goto done;
    }
    point_len = (size_t)asn1_len;

    /*
     * Retain compatibility with modules that DER OCTET STRING-wrap ECX
     * points, but reject a decoded value that does not match the selected
     * curve.
     */
    if (is_ecx && point_len != expected_size) {
        goto done;
    }
    point = ASN1_STRING_get0_data(octet);

done:
    if (point != NULL) {
        *decoded = OPENSSL_memdup(point, point_len);
        if (*decoded == NULL) {
            ret = CKR_HOST_MEMORY;
        } else {
            *decoded_len = point_len;
            ret = CKR_OK;
        }
    }
    ASN1_OCTET_STRING_free(octet);
    return ret;
}
