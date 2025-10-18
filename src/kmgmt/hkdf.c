/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"

DISPATCH_KEYMGMT_FN(hkdf, new);
DISPATCH_KEYMGMT_FN(hkdf, free);
DISPATCH_KEYMGMT_FN(hkdf, query_operation_name);
DISPATCH_KEYMGMT_FN(hkdf, has);

const void *p11prov_hkdf_static_ctx = NULL;

static void *p11prov_hkdf_new(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    CK_RV ret;

    P11PROV_debug("hkdf keymgmt new");

    ret = p11prov_ctx_status(ctx);
    if (ret != CKR_OK) {
        return NULL;
    }

    return (void *)&p11prov_hkdf_static_ctx;
}

static void p11prov_hkdf_free(void *kdfdata)
{
    P11PROV_debug("hkdf keymgmt free %p", kdfdata);

    if (kdfdata != &p11prov_hkdf_static_ctx) {
        P11PROV_debug("Invalid HKDF Keymgmt context: %p != %p", kdfdata,
                      &p11prov_hkdf_static_ctx);
    }
}

static const char *p11prov_hkdf_query_operation_name(int operation_id)
{
    P11PROV_debug("hkdf keymgmt query op name %d", operation_id);

    return P11PROV_NAME_HKDF;
}

static int p11prov_hkdf_has(const void *kdfdata, int selection)
{
    P11PROV_debug("hkdf keymgmt has");
    if (kdfdata != &p11prov_hkdf_static_ctx) {
        P11PROV_debug("Invalid HKDF Keymgmt context: %p != %p", kdfdata,
                      &p11prov_hkdf_static_ctx);
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

const OSSL_DISPATCH p11prov_hkdf_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(hkdf, NEW, new),
    DISPATCH_KEYMGMT_ELEM(hkdf, FREE, free),
    DISPATCH_KEYMGMT_ELEM(hkdf, QUERY_OPERATION_NAME, query_operation_name),
    DISPATCH_KEYMGMT_ELEM(hkdf, HAS, has),
    { 0, NULL },
};
