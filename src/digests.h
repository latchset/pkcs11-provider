/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _DIGESTS_H
#define _DIGESTS_H

CK_RV p11prov_digest_get_block_size(CK_MECHANISM_TYPE digest,
                                    size_t *block_size);
CK_RV p11prov_digest_get_digest_size(CK_MECHANISM_TYPE digest,
                                     size_t *digest_size);
CK_RV p11prov_digest_get_name(CK_MECHANISM_TYPE digest, const char **name);
CK_RV p11prov_digest_get_by_name(const char *name, CK_MECHANISM_TYPE *digest);

CK_RV p11prov_register_digests(P11PROV_CTX *ctx, bool mechs[TBID_SIZE],
                               bool fips_property);

#endif /* _DIGESTS_H */
