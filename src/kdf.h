/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _KDF_H
#define _KDF_H

extern const void *p11prov_hkdf_static_ctx;
extern const OSSL_DISPATCH p11prov_hkdf_functions[];
extern const OSSL_DISPATCH p11prov_sshkdf_functions[];

CK_RV p11prov_register_kdfs(P11PROV_CTX *ctx, bool mechs[TBID_SIZE],
                            bool fips_property);

#endif /* _KDF_H */
