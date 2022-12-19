/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _EXCHANGE_H
#define _EXCHANGE_H

/* ecdh derivation */
#define DISPATCH_ECDH_FN(name) DECL_DISPATCH_FUNC(keyexch, p11prov_ecdh, name)
#define DISPATCH_ECDH_ELEM(prefix, NAME, name) \
    { \
        OSSL_FUNC_KEYEXCH_##NAME, (void (*)(void))p11prov_##prefix##_##name \
    }
extern const OSSL_DISPATCH p11prov_ecdh_exchange_functions[];

/* HKDF exchange fns */
#define DISPATCH_EXCHHKDF_FN(name) \
    DECL_DISPATCH_FUNC(keyexch, p11prov_exch_hkdf, name)
#define DISPATCH_EXCHHKDF_ELEM(prefix, NAME, name) \
    { \
        OSSL_FUNC_KEYEXCH_##NAME, (void (*)(void))p11prov_##prefix##_##name \
    }
extern const OSSL_DISPATCH p11prov_hkdf_exchange_functions[];

#endif /* _EXCHANGE_H */
