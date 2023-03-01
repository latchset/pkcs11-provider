/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _SIGNATURE_H
#define _SIGNATURE_H

/* common sig functions */
#define DISPATCH_SIG_FN(name) DECL_DISPATCH_FUNC(signature, p11prov_sig, name)
#define DISPATCH_SIG_ELEM(prefix, NAME, name) \
    { \
        OSSL_FUNC_SIGNATURE_##NAME, (void (*)(void))p11prov_##prefix##_##name \
    }

/* rsa sig functions */
#define DISPATCH_RSASIG_FN(name) \
    DECL_DISPATCH_FUNC(signature, p11prov_rsasig, name)
extern const OSSL_DISPATCH p11prov_rsa_signature_functions[];

/* ecdsa sig functions */
#define DISPATCH_ECDSA_FN(name) \
    DECL_DISPATCH_FUNC(signature, p11prov_ecdsa, name)
extern const OSSL_DISPATCH p11prov_ecdsa_signature_functions[];

/* eddsa sig functions */
#define DISPATCH_EDDSA_FN(name) \
    DECL_DISPATCH_FUNC(signature, p11prov_eddsa, name)
extern const OSSL_DISPATCH p11prov_eddsa_signature_functions[];

#endif /* _SIGNATURE_H */
