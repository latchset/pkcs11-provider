/* Copyright (C) 2026 Mounir IDRASSI
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _OBJ_EC_POINT_H_
#define _OBJ_EC_POINT_H_

#include <stddef.h>

#include "pkcs11.h"

CK_RV p11prov_decode_ec_point_value(CK_KEY_TYPE key_type,
                                    CK_ULONG expected_size,
                                    const CK_ATTRIBUTE *attr,
                                    unsigned char **decoded,
                                    size_t *decoded_len);

#endif /* _OBJ_EC_POINT_H_ */
