/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "kmgmt/keymgmt.h"

struct key_generator {
    P11PROV_CTX *provctx;

    CK_KEY_TYPE type;

    P11PROV_URI *uri;
    char *key_usage;

    CK_MECHANISM mechanism;

    union {
        struct {
            CK_ULONG modulus_bits;
            CK_BYTE exponent[8];
            CK_ULONG exponent_size;
            CK_MECHANISM_TYPE *allowed_types;
            CK_ULONG allowed_types_size;
        } rsa;
        struct {
            const CK_BYTE *ec_params;
            CK_ULONG ec_params_size;
            bool paramgen;
        } ec;
        struct {
            CK_ML_DSA_PARAMETER_SET_TYPE param_set;
        } mldsa;
        struct {
            CK_ML_KEM_PARAMETER_SET_TYPE param_set;
        } mlkem;
        struct {
            CK_SLH_DSA_PARAMETER_SET_TYPE param_set;
        } slhdsa;
    } data;

    OSSL_CALLBACK *cb_fn;
    void *cb_arg;
};

struct key_generator *p11prov_kmgmt_gen_init(void *provctx, CK_KEY_TYPE type,
                                             CK_MECHANISM_TYPE mech);
int p11prov_kmgmt_gen_set_params(struct key_generator *ctx,
                                 const OSSL_PARAM params[]);
CK_RV p11prov_kmgmt_gen_callback(void *cbarg);

/* Common attributes that may currently be added to the templates
 * CKA_ID
 * CKA_LABEL
 */
#define COMMON_TMPL_SIZE 2
#define DISCARD_CONST(x) (void *)(x)

int p11prov_kmgmt_gen(struct key_generator *ctx, CK_ATTRIBUTE *pubkey_template,
                      CK_ATTRIBUTE *privkey_template, int pubtsize,
                      int privtsize, OSSL_CALLBACK *cb_fn, void *cb_arg,
                      void **key);
int p11prov_kmgmt_match(const void *keydata1, const void *keydata2,
                        CK_KEY_TYPE type, int selection);
int p11prov_kmgmt_get_params(void *keydata, OSSL_PARAM params[]);

void p11prov_kmgmt_gen_cleanup(struct key_generator *ctx);

void *p11prov_kmgmt_new(void *provctx, CK_KEY_TYPE type);
void p11prov_kmgmt_free(void *key);
void *p11prov_kmgmt_load(const void *ref, size_t ref_sz, CK_KEY_TYPE type);
int p11prov_kmgmt_has(const void *keydata, int selection);

int p11prov_kmgmt_import(CK_KEY_TYPE type, CK_ULONG param_set,
                         const char *priv_param_name, void *keydata,
                         int selection, const OSSL_PARAM params[]);
int p11prov_kmgmt_export(void *keydata, int selection, OSSL_CALLBACK *cb_fn,
                         void *cb_arg);

#define DISPATCH_KEYMGMT_FN(type, name) \
    DECL_DISPATCH_FUNC(keymgmt, p11prov_##type, name)
#define DISPATCH_KEYMGMT_ELEM(type, NAME, name) \
    { OSSL_FUNC_KEYMGMT_##NAME, (void (*)(void))p11prov_##type##_##name }

extern const OSSL_DISPATCH p11prov_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_rsapss_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_ec_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_hkdf_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_ed25519_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_ed448_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_x25519_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_x448_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_mldsa44_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_mldsa65_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_mldsa87_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_mlkem512_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_mlkem768_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_mlkem1024_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_sha2_128s_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_sha2_128f_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_sha2_192s_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_sha2_192f_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_sha2_256s_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_sha2_256f_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_shake_128s_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_shake_128f_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_shake_192s_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_shake_192f_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_shake_256s_keymgmt_functions[];
extern const OSSL_DISPATCH p11prov_slhdsa_shake_256f_keymgmt_functions[];
