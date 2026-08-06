/* Copyright (C) 2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _KEM_H
#define _KEM_H

CK_RV p11prov_register_kems(P11PROV_CTX *ctx, bool mechs[TBID_SIZE],
                            bool fips_property);

#endif /* _KEM_H */
