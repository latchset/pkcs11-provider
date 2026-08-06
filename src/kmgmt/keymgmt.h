/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _KEYMGMT_H
#define _KEYMGMT_H

#define P11PROV_N_RSAPSS_MECHS 10
extern const CK_MECHANISM_TYPE p11prov_rsapss_mechs[P11PROV_N_RSAPSS_MECHS];

CK_RV p11prov_register_kmgmt(P11PROV_CTX *ctx, bool fips_property);

#endif /* _KEYMGMT_H */
