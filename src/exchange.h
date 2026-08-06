/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _EXCHANGE_H
#define _EXCHANGE_H

CK_RV p11prov_register_keyexch(P11PROV_CTX *ctx, bool mechs[TBID_SIZE],
                               bool fips_property);

#endif /* _EXCHANGE_H */
