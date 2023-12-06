/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _DECODER_H
#define _DECODER_H

#include <openssl/core.h>

#define RET_OSSL_CARRY_ON_DECODING 1
#define RET_OSSL_STOP_DECODING 0

/* DECODERs */
#define DISPATCH_TEXT_DECODER_FN(type, name) \
    static OSSL_FUNC_DECODER_##name##_fn p11prov_##type##_DECODER_##name##_text
#define DISPATCH_TEXT_DECODER_ELEM(NAME, type, name) \
    { \
        OSSL_FUNC_DECODER_##NAME, \
            (void (*)(void))p11prov_##type##_DECODER_##name \
    }
#define DISPATCH_BASE_DECODER_FN(name) \
    DECL_DISPATCH_FUNC(DECODER, p11prov_decoder_, name)
#define DISPATCH_BASE_DECODER_ELEM(NAME, name) \
    { \
        OSSL_FUNC_DECODER_##NAME, (void (*)(void))p11prov_decoder_##name \
    }
#define DISPATCH_DECODER_FN(type, structure, format, name) \
    DECL_DISPATCH_FUNC(DECODER, \
                       p11prov_##type##_decoder_##structure##_##format, name)
#define DISPATCH_DECODER_ELEM(NAME, type, structure, format, name) \
    { \
        OSSL_FUNC_DECODER_##NAME, \
            (void (*)( \
                void))p11prov_##type##_decoder_##structure##_##format##_##name \
    }
extern const OSSL_DISPATCH p11prov_der_decoder_p11prov_rsa_functions[];
extern const OSSL_DISPATCH p11prov_der_decoder_p11prov_ec_functions[];
extern const OSSL_DISPATCH p11prov_pem_decoder_p11prov_der_functions[];

#endif /* _DECODER_H */
