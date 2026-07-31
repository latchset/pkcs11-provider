/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _KDF_H
#define _KDF_H

/* HKDF kdf fns */
#define DISPATCH_HKDF_FN(name) DECL_DISPATCH_FUNC(kdf, p11prov_hkdf, name)
#define DISPATCH_HKDF_ELEM(prefix, NAME, name) \
    { \
        OSSL_FUNC_KDF_##NAME, (void (*)(void))p11prov_##prefix##_##name \
    }
extern const void *p11prov_hkdf_static_ctx;
extern const OSSL_DISPATCH p11prov_hkdf_kdf_functions[];
extern const OSSL_DISPATCH p11prov_tls13_kdf_functions[];

#endif /* _KDF_H */
