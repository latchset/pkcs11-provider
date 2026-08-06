/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _DECODER_H
#define _DECODER_H

CK_RV p11prov_register_decoders(P11PROV_CTX *ctx, bool fips_property);

#endif /* _DECODER_H */
