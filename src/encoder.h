/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _ENCODER_H
#define _ENCODER_H

/* Encoders */
#define DISPATCH_TEXT_ENCODER_FN(type, name) \
    static OSSL_FUNC_encoder_##name##_fn p11prov_##type##_encoder_##name##_text
#define DISPATCH_TEXT_ENCODER_ELEM(NAME, type, name) \
    { \
        OSSL_FUNC_ENCODER_##NAME, \
            (void (*)(void))p11prov_##type##_encoder_##name \
    }
#define DISPATCH_BASE_ENCODER_FN(name) \
    DECL_DISPATCH_FUNC(encoder, p11prov_encoder, name)
#define DISPATCH_BASE_ENCODER_ELEM(NAME, name) \
    { \
        OSSL_FUNC_ENCODER_##NAME, (void (*)(void))p11prov_encoder_##name \
    }
#define DISPATCH_ENCODER_FN(type, structure, format, name) \
    DECL_DISPATCH_FUNC(encoder, \
                       p11prov_##type##_encoder_##structure##_##format, name)
#define DISPATCH_ENCODER_ELEM(NAME, type, structure, format, name) \
    { \
        OSSL_FUNC_ENCODER_##NAME, \
            (void (*)( \
                void))p11prov_##type##_encoder_##structure##_##format##_##name \
    }
extern const OSSL_DISPATCH p11prov_rsa_encoder_text_functions[];
extern const OSSL_DISPATCH p11prov_rsa_encoder_pkcs1_der_functions[];
extern const OSSL_DISPATCH p11prov_rsa_encoder_pkcs1_pem_functions[];
extern const OSSL_DISPATCH p11prov_rsa_encoder_spki_der_functions[];
extern const OSSL_DISPATCH p11prov_rsa_encoder_spki_pem_functions[];
extern const OSSL_DISPATCH p11prov_rsa_encoder_priv_key_info_pem_functions[];
extern const OSSL_DISPATCH p11prov_ec_encoder_text_functions[];
extern const OSSL_DISPATCH p11prov_ec_encoder_pkcs1_der_functions[];
extern const OSSL_DISPATCH p11prov_ec_encoder_pkcs1_pem_functions[];
extern const OSSL_DISPATCH p11prov_ec_encoder_spki_der_functions[];
extern const OSSL_DISPATCH p11prov_ec_encoder_priv_key_info_pem_functions[];
extern const OSSL_DISPATCH
    p11prov_ec_edwards_encoder_priv_key_info_pem_functions[];
extern const OSSL_DISPATCH p11prov_ec_edwards_encoder_text_functions[];
extern const OSSL_DISPATCH p11prov_mldsa_encoder_pkcs1_der_functions[];
extern const OSSL_DISPATCH p11prov_mldsa_encoder_pkcs1_pem_functions[];
extern const OSSL_DISPATCH p11prov_mldsa_encoder_spki_der_functions[];
extern const OSSL_DISPATCH p11prov_mldsa_encoder_spki_pem_functions[];
extern const OSSL_DISPATCH p11prov_mldsa_encoder_priv_key_info_pem_functions[];
extern const OSSL_DISPATCH p11prov_mldsa_encoder_text_functions[];
extern const OSSL_DISPATCH p11prov_mlkem_encoder_pkcs1_der_functions[];
extern const OSSL_DISPATCH p11prov_mlkem_encoder_pkcs1_pem_functions[];
extern const OSSL_DISPATCH p11prov_mlkem_encoder_spki_der_functions[];
extern const OSSL_DISPATCH p11prov_mlkem_encoder_spki_pem_functions[];
extern const OSSL_DISPATCH p11prov_mlkem_encoder_priv_key_info_pem_functions[];
extern const OSSL_DISPATCH p11prov_mlkem_encoder_text_functions[];

#endif /* _ENCODER_H */
