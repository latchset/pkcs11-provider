/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _DECODER_H
#define _DECODER_H

#include <openssl/core.h>

#define RET_OSSL_CARRY_ON_DECODING 1
#define RET_OSSL_STOP_DECODING 0

/* DECODERs */
#define DISPATCH_BASE_DECODER_ELEM(NAME, name) \
    { \
        OSSL_FUNC_DECODER_##NAME, (void (*)(void))p11prov_decoder_##name \
    }
#define DISPATCH_DECODER_ELEM(NAME, type, structure, format, name) \
    { \
        OSSL_FUNC_DECODER_##NAME, \
            (void (*)( \
                void))p11prov_##type##_decoder_##structure##_##format##_##name \
    }
#define DISPATCH_DECODER_FN_LIST(type, structure, format) \
    const OSSL_DISPATCH \
        p11prov_##type##_decoder_##structure##_##format##_functions[] = { \
            DISPATCH_BASE_DECODER_ELEM(NEWCTX, newctx), \
            DISPATCH_BASE_DECODER_ELEM(FREECTX, freectx), \
            DISPATCH_DECODER_ELEM(DECODE, type, structure, format, decode), \
            { 0, NULL } \
        };
#define P11PROV_DER_COMMON_DECODE_FN(FORMAT_NAME, format) \
    static int p11prov_der_decoder_p11prov_##format##_decode( \
        void *inctx, OSSL_CORE_BIO *cin, int selection, \
        OSSL_CALLBACK *object_cb, void *object_cbarg, \
        OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg) \
    { \
        return p11prov_der_decoder_p11prov_obj_decode( \
            FORMAT_NAME, inctx, cin, selection, object_cb, object_cbarg, \
            pw_cb, pw_cbarg); \
    }

extern const OSSL_DISPATCH p11prov_pem_decoder_p11prov_der_functions[];
extern const OSSL_DISPATCH p11prov_der_decoder_p11prov_rsa_functions[];
extern const OSSL_DISPATCH p11prov_der_decoder_p11prov_ec_functions[];
extern const OSSL_DISPATCH p11prov_der_decoder_p11prov_ed25519_functions[];
extern const OSSL_DISPATCH p11prov_der_decoder_p11prov_ed448_functions[];

#endif /* _DECODER_H */
