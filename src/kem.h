/* Copyright (C) 2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _KEM_H
#define _KEM_H

#include "provider.h"

/* ml-kem kem */
#define DISPATCH_MLKEM_FN(name) DECL_DISPATCH_FUNC(kem, p11prov_mlkem, name)
#define DISPATCH_MLKEM_ELEM(prefix, NAME, name) \
    { OSSL_FUNC_KEM_##NAME, (void (*)(void))p11prov_##prefix##_##name }
extern const OSSL_DISPATCH p11prov_mlkem_kem_functions[];

#endif /* _KEM_H */
