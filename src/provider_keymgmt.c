/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

#include "provider.h"

static OSSL_FUNC_keymgmt_new_fn p11prov_rsa_new;
static OSSL_FUNC_keymgmt_gen_init_fn p11prov_rsa_gen_init;
static OSSL_FUNC_keymgmt_gen_fn p11prov_rsa_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn p11prov_rsa_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn p11prov_rsa_load;
static OSSL_FUNC_keymgmt_free_fn p11prov_rsa_free;
static OSSL_FUNC_keymgmt_has_fn p11prov_rsa_has;
static OSSL_FUNC_keymgmt_import_fn p11prov_rsa_import;
static OSSL_FUNC_keymgmt_import_types_fn p11prov_rsa_import_types;
static OSSL_FUNC_keymgmt_export_fn p11prov_rsa_export;
static OSSL_FUNC_keymgmt_export_types_fn p11prov_rsa_export_types;
static OSSL_FUNC_keymgmt_query_operation_name_fn p11prov_rsa_query_operation_name;
static OSSL_FUNC_keymgmt_get_params_fn p11prov_rsa_get_params;

static void *p11prov_rsa_new(void *provctx)
{
    p11prov_debug("new\n");
    return NULL;
}

static void *p11prov_rsa_gen_init(void *provctx, int selection,
                          const OSSL_PARAM params[])
{
    p11prov_debug("gen_init\n");
    return NULL;
}

static void *p11prov_rsa_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    p11prov_debug("gen %p %p %p\n", genctx, osslcb, cbarg);
    return NULL;
}
static void p11prov_rsa_gen_cleanup(void *genctx)
{
    p11prov_debug("gen_cleanup %p\n", genctx);
}

static void p11prov_rsa_free(void *key)
{
    p11prov_debug("free %p\n", key);
    p11prov_object_free((P11PROV_OBJECT *)key);
}

static void *p11prov_rsa_load(const void *reference, size_t reference_sz)
{
    P11PROV_OBJECT *obj = NULL;

    p11prov_debug("load %p, %ld\n", reference, reference_sz);

    if (!reference || reference_sz != sizeof(obj))
        return NULL;

    /* the contents of the reference is the address to our object */
    obj = (P11PROV_OBJECT *)reference;

    return obj;
}

static int p11prov_rsa_has(const void *keydata, int selection)
{
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)keydata;

    p11prov_debug("has %p %d\n", obj, selection);

    if (obj == NULL) return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (!p11prov_object_check_key(obj, true)) return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (!p11prov_object_check_key(obj, false)) return 0;
    }

    return 1;
}

static int p11prov_rsa_import(void *keydata, int selection,
                              const OSSL_PARAM params[])
{
    p11prov_debug("import %p\n", keydata);
    return 0;
}

static int p11prov_rsa_export(void *keydata, int selection,
                      OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)keydata;

    p11prov_debug("export %p\n", keydata);

    if (obj == NULL) return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return p11prov_object_export_public_rsa_key(obj, cb_fn, cb_arg);
    }

    return 0;
}

static const OSSL_PARAM p11prov_rsa_key_types[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *p11prov_rsa_import_types(int selection)
{
    p11prov_debug("import types\n");
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return p11prov_rsa_key_types;
    return NULL;
}

static const OSSL_PARAM *p11prov_rsa_export_types(int selection)
{
    p11prov_debug("export types\n");
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return p11prov_rsa_key_types;
    return NULL;
}

static const char *p11prov_rsa_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
        return P11PROV_NAMES_RSA;
    default:
        return "RSA";
    }
}

static int p11prov_rsa_secbits(int bits)
{
    /* common values from various NIST documents */
    switch (bits) {
    case 2048:
        return 112;
    case 3072:
        return 128;
    case 4096:
        return 152;
    case 6144:
        return 176;
    case 7680:
        return 192;
    case 8192:
        return 200;
    case 15360:
        return 256;
    }

    /* TODO: do better calculations,
     * see ossl_ifc_ffc_compute_security_bits() */
    if (bits > 15360) return 256;
    if (bits > 8192) return 200;
    if (bits > 7680) return 192;
    if (bits > 6144) return 176;
    if (bits > 4096) return 152;
    if (bits > 3072) return 128;
    if (bits > 2048) return 112;
    if (bits < 2048) return 0;
}

static int p11prov_rsa_get_params(void *keydata, OSSL_PARAM params[])
{
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)keydata;
    CK_ATTRIBUTE *modulus;
    P11PROV_KEY *key;
    OSSL_PARAM *p;
    int ret;

    p11prov_debug("get_params %p\n", keydata);

    if (obj == NULL) return 0;

    key = p11prov_object_get_key(obj, false);
    if (key == NULL) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    modulus = p11prov_key_attr(key, CKA_MODULUS);
    if (modulus == NULL) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p) {
        /* TODO: may want to try to get CKA_MODULUS_BITS,
         * and fallback only if unavailable */
        ret = OSSL_PARAM_set_int(p, modulus->ulValueLen * 8);
        if (ret != RET_OSSL_OK) goto done;
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p) {
        /* TODO: as above, plus use log() for intermediate values */
        int secbits = p11prov_rsa_secbits(modulus->ulValueLen * 8);
        ret = OSSL_PARAM_set_int(p, secbits);
        if (ret != RET_OSSL_OK) goto done;
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p) {
        ret = OSSL_PARAM_set_int(p, modulus->ulValueLen);
        if (ret != RET_OSSL_OK) goto done;
    }

    ret = RET_OSSL_OK;
done:
    p11prov_key_free(key);
    return ret;
}

static const OSSL_PARAM *p11prov_rsa_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        /* OSSL_PKEY_PARAM_DEFAULT_DIGEST,
         * OSSL_PKEY_PARAM_RSA_N,
         * OSSL_PKEY_PARAM_RSA_E, */
        OSSL_PARAM_END
    };
    return params;
}


const OSSL_DISPATCH p11prov_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))p11prov_rsa_new },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))p11prov_rsa_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))p11prov_rsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))p11prov_rsa_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))p11prov_rsa_load },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))p11prov_rsa_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))p11prov_rsa_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))p11prov_rsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))p11prov_rsa_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))p11prov_rsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))p11prov_rsa_export_types },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        (void(*)(void))p11prov_rsa_query_operation_name },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))p11prov_rsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        (void (*) (void))p11prov_rsa_gettable_params },
    { 0, NULL }
};
