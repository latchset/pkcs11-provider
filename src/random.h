/* Copyright (C) 2023 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _PKCS11_RANDOM_H
#define _PKCS11_RANDOM_H

CK_RV p11prov_register_random(P11PROV_CTX *ctx, bool fips_property);

#endif /* _PKCS11_RANDOM_H */
