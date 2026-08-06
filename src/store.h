/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _STORE_H
#define _STORE_H

int p11prov_store_direct_fetch(void *provctx, const char *uri,
                               OSSL_CALLBACK *object_cb, void *object_cbarg,
                               OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg);

CK_RV p11prov_register_store(P11PROV_CTX *ctx, bool fips_property);

#endif /* _STORE_H */
