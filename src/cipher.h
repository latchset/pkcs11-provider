/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   Copyright 2025 NXP
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _CIPHER_H
#define _CIPHER_H

CK_RV p11prov_register_ciphers(P11PROV_CTX *ctx, bool mechs[TBID_SIZE],
                               bool fips_property);

#endif /* _CIPHER_H */
