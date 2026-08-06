/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _ASYM_CIPH_H
#define _ASYM_CIPH_H

CK_RV p11prov_register_asym_ciphers(P11PROV_CTX *ctx, bool mechs[TBID_SIZE],
                                    bool fips_property);

#endif /* _ASYM_CIPH_H */
