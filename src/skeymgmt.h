/* Copyright (C) 2024 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _SKEYMGMT_H
#define _SKEYMGMT_H

/* keymgmt */
#define DISPATCH_SKEYMGMT_FN(type, name) \
    DECL_DISPATCH_FUNC(skeymgmt, p11prov_##type, name)
#define DISPATCH_SKEYMGMT_ELEM(type, NAME, name) \
    { OSSL_FUNC_SKEYMGMT_##NAME, (void (*)(void))p11prov_##type##_##name }
extern const OSSL_DISPATCH p11prov_aes_skeymgmt_functions[];

#endif /* _SKEYMGMT_H */
