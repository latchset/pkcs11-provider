/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _P11PROV_PKCS11_H_
#define _P11PROV_PKCS11_H_

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#define NULL_PTR NULL

/* Unfortunately the newer OASIS PKCS#11 specification (v2.40 and later) state
 * in §2.1 causing confusion (and incompatility if honored on UNIX):
 *   Cryptoki structures are packed to occupy as little space as is possible.
 *   Cryptoki structures SHALL be packed with 1-byte alignment.
 *
 * The earlier PKCS#11 v2.30 wording is:
 *   Cryptoki structures are packed to occupy as little space as is possible.
 *   In particular, on the Windows platforms, Cryptoki structures should be packed
 *   with 1-byte alignment. In a UNIX environment, it may or may not be necessary
 *   (or even possible) to alter the byte-alignment of structures.
 *
 * Thus, use default alignment for Crypto structures for Linux. This is also
 * the defacto standard among all other users and implementations of PKCS#11.
 */
#include "oasis/pkcs11.h"

#endif /* P11PROV_PKCS11_H_ */
