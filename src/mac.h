// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2025 NXP
 */

#ifndef _MAC_H
#define _MAC_H

/* MAC fns */
#define DISPATCH_HMAC_FN(name) DECL_DISPATCH_FUNC(kdf, p11prov_hmac, name)
#define DISPATCH_MAC_ELEM(prefix, NAME, name) \
    { \
        OSSL_FUNC_MAC_##NAME, (void (*)(void))p11prov_##prefix##_##name \
    }
extern const OSSL_DISPATCH p11prov_hmac_mac_functions[];

#endif /* _MAC_H */
