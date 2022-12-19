/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _STORE_H
#define _STORE_H

#define DISPATCH_STORE_FN(name) DECL_DISPATCH_FUNC(store, p11prov_store, name)
#define DISPATCH_STORE_ELEM(NAME, name) \
    { \
        OSSL_FUNC_STORE_##NAME, (void (*)(void))p11prov_store_##name \
    }
extern const OSSL_DISPATCH p11prov_store_functions[];

#endif /* _STORE_H */
