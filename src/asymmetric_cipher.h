/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _ASYM_CIPH_H
#define _ASYM_CIPH_H

/* rsa encrypt/decrypt */
#define DISPATCH_RSAENC_FN(name) \
    DECL_DISPATCH_FUNC(asym_cipher, p11prov_rsaenc, name)
#define DISPATCH_RSAENC_ELEM(NAME, name) \
    { \
        OSSL_FUNC_ASYM_CIPHER_##NAME, (void (*)(void))p11prov_rsaenc_##name \
    }
extern const OSSL_DISPATCH p11prov_rsa_asym_cipher_functions[];

#endif /* _ASYM_CIPH_H */
