/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _EXCHANGE_H
#define _EXCHANGE_H

/* ecdh derivation */
#define DISPATCH_KEYEXCH_FN(prefix, name) \
    DECL_DISPATCH_FUNC(keyexch, p11prov_##prefix, name)
#define DISPATCH_KEYEXCH_ELEM(prefix, NAME, name) \
    { OSSL_FUNC_KEYEXCH_##NAME, (void (*)(void))p11prov_##prefix##_##name }
extern const OSSL_DISPATCH p11prov_ecdh_exchange_functions[];
extern const OSSL_DISPATCH p11prov_x25519_exchange_functions[];
extern const OSSL_DISPATCH p11prov_x448_exchange_functions[];

/* HKDF exchange fns */
#define DISPATCH_EXCHHKDF_FN(name) \
    DECL_DISPATCH_FUNC(keyexch, p11prov_exch_hkdf, name)
#define DISPATCH_EXCHHKDF_ELEM(prefix, NAME, name) \
    { \
        OSSL_FUNC_KEYEXCH_##NAME, (void (*)(void))p11prov_##prefix##_##name \
    }
extern const OSSL_DISPATCH p11prov_hkdf_exchange_functions[];

#endif /* _EXCHANGE_H */
