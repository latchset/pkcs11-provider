/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _SKEYMGMT_H
#define _SKEYMGMT_H

CK_RV p11prov_register_skmgmt(P11PROV_CTX *ctx, bool fips_property);

#endif /* _SKEYMGMT_H */
