/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _CIPHER_H
#define _CIPHER_H

#define MODE_modes_mask 0x00FF
#define MODE_flags_mask 0xFF00

#define MODE_flag_aead 0x0100
#define MODE_flag_custom_iv 0x0200
#define MODE_flag_cts 0x0400
#define MODE_flag_tls1_mb 0x0800
#define MODE_flag_rand_key 0x1000

#define MODE_ecb 0x01
#define MODE_cbc 0x02
#define MODE_ofb 0x04
#define MODE_cfb 0x08
#define MODE_cfb1 MODE_cfb
#define MODE_cfb8 MODE_cfb
#define MODE_ctr 0x10
#define MODE_cts MODE_flag_cts | MODE_cbc

#define DISPATCH_CIPHER_FN(alg, name) \
    DECL_DISPATCH_FUNC(cipher, p11prov_##alg, name)

#define DISPATCH_TABLE_CIPHER_FN(cipher, size, mode, mechanism) \
    static void *p11prov_##cipher##size##mode##_newctx(void *provctx) \
    { \
        return p11prov_cipher_newctx(provctx, size, mechanism); \
    } \
    static int p11prov_##cipher##size##mode##_get_params(OSSL_PARAM params[]) \
    { \
        return p11prov_##cipher##_get_params(params, size, MODE_##mode, \
                                             mechanism); \
    } \
    const OSSL_DISPATCH p11prov_##cipher##size##mode##_cipher_functions[] = { \
        { OSSL_FUNC_CIPHER_NEWCTX, \
          (void (*)(void))p11prov_##cipher##size##mode##_newctx }, \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))p11prov_cipher_freectx }, \
        { OSSL_FUNC_CIPHER_DUPCTX, \
          (void (*)(void))p11prov_##cipher##_dupctx }, \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, \
          (void (*)(void))p11prov_cipher_encrypt_init }, \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, \
          (void (*)(void))p11prov_cipher_decrypt_init }, \
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))p11prov_cipher_update }, \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))p11prov_cipher_final }, \
        { OSSL_FUNC_CIPHER_CIPHER, \
          (void (*)(void))p11prov_##cipher##_cipher }, \
        { OSSL_FUNC_CIPHER_GET_PARAMS, \
          (void (*)(void))p11prov_##cipher##size##mode##_get_params }, \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, \
          (void (*)(void))p11prov_##cipher##_get_ctx_params }, \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, \
          (void (*)(void))p11prov_##cipher##_set_ctx_params }, \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, \
          (void (*)(void))p11prov_cipher_gettable_params }, \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, \
          (void (*)(void))p11prov_##cipher##_gettable_ctx_params }, \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, \
          (void (*)(void))p11prov_##cipher##_settable_ctx_params }, \
        { OSSL_FUNC_CIPHER_ENCRYPT_SKEY_INIT, \
          (void (*)(void))p11prov_cipher_encrypt_skey_init }, \
        { OSSL_FUNC_CIPHER_DECRYPT_SKEY_INIT, \
          (void (*)(void))p11prov_cipher_decrypt_skey_init }, \
        OSSL_DISPATCH_END \
    };

extern const OSSL_DISPATCH p11prov_aes128ecb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192ecb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256ecb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128cbc_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192cbc_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256cbc_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128ofb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192ofb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256ofb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128cfb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192cfb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256cfb_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128cfb1_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192cfb1_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256cfb1_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128cfb8_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192cfb8_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256cfb8_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128ctr_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192ctr_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256ctr_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes128cts_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes192cts_cipher_functions[];
extern const OSSL_DISPATCH p11prov_aes256cts_cipher_functions[];

#endif /* _CIPHER_H */
