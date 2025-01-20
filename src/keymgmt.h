/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _KEYMGMT_H
#define _KEYMGMT_H

/* keymgmt */

#define P11PROV_N_RSAPSS_MECHS 10
extern const CK_MECHANISM_TYPE p11prov_rsapss_mechs[P11PROV_N_RSAPSS_MECHS];

#define DISPATCH_KEYMGMT_FN(type, name) \
    DECL_DISPATCH_FUNC(keymgmt, p11prov_##type, name)
#define DISPATCH_KEYMGMT_ELEM(type, NAME, name) \
    { \
        OSSL_FUNC_KEYMGMT_##NAME, (void (*)(void))p11prov_##type##_##name \
    }
extern const OSSL_DISPATCH p11prov_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_rsapss_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_ec_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_hkdf_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_ed25519_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_ed448_keymgmt_functions[];

#endif /* _KEYMGMT_H */
