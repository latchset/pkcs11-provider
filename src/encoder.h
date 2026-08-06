/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _ENCODER_H
#define _ENCODER_H


CK_RV rsa_pkeyinfo_to_attrs(CK_ATTRIBUTE *pkeyinfo, CK_ATTRIBUTE *attrs);
CK_RV p11prov_register_encoders(P11PROV_CTX *ctx, bool fips_property,
                                bool encode_pkey_as_pk11_uri);

#endif /* _ENCODER_H */
