/* Copyright (C) 2023 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _PKCS11_RANDOM_H
#define _PKCS11_RANDOM_H

#define DISPATCH_RAND_FN(name) DECL_DISPATCH_FUNC(rand, p11prov_rand, name)
#define DISPATCH_RAND_ELEM(prefix, NAME, name) \
    { \
        OSSL_FUNC_RAND_##NAME, (void (*)(void))p11prov_##prefix##_##name \
    }
extern const OSSL_DISPATCH p11prov_rand_functions[];

CK_RV p11prov_check_random(P11PROV_CTX *ctx);

#endif /* _PKCS11_RANDOM_H */
