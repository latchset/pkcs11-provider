/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

#include "provider.h"

DISPATCH_RSAKM_FN(new);
DISPATCH_RSAKM_FN(gen_init);
DISPATCH_RSAKM_FN(gen);
DISPATCH_RSAKM_FN(gen_cleanup);
DISPATCH_RSAKM_FN(load);
DISPATCH_RSAKM_FN(free);
DISPATCH_RSAKM_FN(has);
DISPATCH_RSAKM_FN(import);
DISPATCH_RSAKM_FN(import_types);
DISPATCH_RSAKM_FN(export);
DISPATCH_RSAKM_FN(export_types);
DISPATCH_RSAKM_FN(query_operation_name);
DISPATCH_RSAKM_FN(get_params);
DISPATCH_RSAKM_FN(gettable_params);

static void *p11prov_rsakm_new(void *provctx)
{
    p11prov_debug("new\n");
    return NULL;
}

static void *p11prov_rsakm_gen_init(void *provctx, int selection,
                                    const OSSL_PARAM params[])
{
    p11prov_debug("gen_init\n");
    return NULL;
}

static void *p11prov_rsakm_gen(void *genctx,
                               OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    p11prov_debug("gen %p %p %p\n", genctx, cb_fn, cb_arg);
    return NULL;
}
static void p11prov_rsakm_gen_cleanup(void *genctx)
{
    p11prov_debug("gen_cleanup %p\n", genctx);
}

static void p11prov_rsakm_free(void *key)
{
    p11prov_debug("free %p\n", key);
    p11prov_object_free((P11PROV_OBJECT *)key);
}

static void *p11prov_rsakm_load(const void *reference, size_t reference_sz)
{
    P11PROV_OBJECT *obj = NULL;

    p11prov_debug("load %p, %ld\n", reference, reference_sz);

    if (!reference || reference_sz != sizeof(obj))
        return NULL;

    /* the contents of the reference is the address to our object */
    obj = (P11PROV_OBJECT *)reference;

    return obj;
}

static int p11prov_rsakm_has(const void *keydata, int selection)
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

static int p11prov_rsakm_import(void *keydata, int selection,
                                const OSSL_PARAM params[])
{
    p11prov_debug("import %p\n", keydata);
    return 0;
}

static int p11prov_rsakm_export(void *keydata, int selection,
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

static const OSSL_PARAM p11prov_rsakm_key_types[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *p11prov_rsakm_import_types(int selection)
{
    p11prov_debug("import types\n");
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return p11prov_rsakm_key_types;
    return NULL;
}

static const OSSL_PARAM *p11prov_rsakm_export_types(int selection)
{
    p11prov_debug("export types\n");
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return p11prov_rsakm_key_types;
    return NULL;
}

static const char *p11prov_rsakm_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
    case OSSL_OP_ASYM_CIPHER:
        return P11PROV_NAMES_RSA;
    default:
        return "RSA";
    }
}

static int p11prov_rsakm_secbits(int bits)
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

static int p11prov_rsakm_get_params(void *keydata, OSSL_PARAM params[])
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
        int secbits = p11prov_rsakm_secbits(modulus->ulValueLen * 8);
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

static const OSSL_PARAM *p11prov_rsakm_gettable_params(void *provctx)
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
    DISPATCH_RSAKM_ELEM(NEW, new),
    DISPATCH_RSAKM_ELEM(GEN_INIT, gen_init),
    DISPATCH_RSAKM_ELEM(GEN, gen),
    DISPATCH_RSAKM_ELEM(GEN_CLEANUP, gen_cleanup),
    DISPATCH_RSAKM_ELEM(LOAD, load),
    DISPATCH_RSAKM_ELEM(FREE, free),
    DISPATCH_RSAKM_ELEM(HAS, has),
    DISPATCH_RSAKM_ELEM(IMPORT, import),
    DISPATCH_RSAKM_ELEM(IMPORT_TYPES, import_types),
    DISPATCH_RSAKM_ELEM(EXPORT, export),
    DISPATCH_RSAKM_ELEM(EXPORT_TYPES, export_types),
    DISPATCH_RSAKM_ELEM(QUERY_OPERATION_NAME, query_operation_name),
    DISPATCH_RSAKM_ELEM(GET_PARAMS, get_params),
    DISPATCH_RSAKM_ELEM(GETTABLE_PARAMS, gettable_params),
    { 0, NULL }
};
