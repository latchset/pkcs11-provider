/* Copyright 2026 NXP
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"

DISPATCH_KEYMGMT_FN(tls1_prf, new);
DISPATCH_KEYMGMT_FN(tls1_prf, free);
DISPATCH_KEYMGMT_FN(tls1_prf, query_operation_name);
DISPATCH_KEYMGMT_FN(tls1_prf, has);

const void *p11prov_tls1_prf_static_ctx = NULL;

static void *p11prov_tls1_prf_new(void *provctx)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    CK_RV ret;

    P11PROV_debug("tls1_prf keymgmt new");

    ret = p11prov_ctx_status(ctx);
    if (ret != CKR_OK) {
        return NULL;
    }

    return (void *)&p11prov_tls1_prf_static_ctx;
}

static void p11prov_tls1_prf_free(void *kdfdata)
{
    P11PROV_debug("tls1_prf keymgmt free %p", kdfdata);

    if (kdfdata != &p11prov_tls1_prf_static_ctx) {
        P11PROV_debug("Invalid TLS1-PRF Keymgmt context: %p != %p", kdfdata,
                      &p11prov_tls1_prf_static_ctx);
    }
}

static const char *p11prov_tls1_prf_query_operation_name(int operation_id)
{
    P11PROV_debug("tls1_prf keymgmt query op name %d", operation_id);

    return P11PROV_NAMES_TLS1_PRF;
}

static int p11prov_tls1_prf_has(const void *kdfdata, int selection)
{
    P11PROV_debug("tls1_prf keymgmt has");

    if (kdfdata != &p11prov_tls1_prf_static_ctx) {
        P11PROV_debug("Invalid TLS1-PRF Keymgmt context: %p != %p", kdfdata,
                      &p11prov_tls1_prf_static_ctx);
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

const OSSL_DISPATCH p11prov_tls1_prf_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(tls1_prf, NEW, new),
    DISPATCH_KEYMGMT_ELEM(tls1_prf, FREE, free),
    DISPATCH_KEYMGMT_ELEM(tls1_prf, QUERY_OPERATION_NAME, query_operation_name),
    DISPATCH_KEYMGMT_ELEM(tls1_prf, HAS, has),
    { 0, NULL },
};
