/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

#ifndef _P11PROV_PKCS11_H_
#define _P11PROV_PKCS11_H_

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#define NULL_PTR NULL

/*
 * The spec syas we should use packing arounf these files,
 * and suggest a packing of 1 byte. HOwever if the following
 *   #pragma pack(push, 1)
 *   #pragma pack(pop)
 * are used around the oasis header file, all structures are
 * incorrectly aligned and loading a module leads to segfaults
 * as function pointers point to the wrong memory locations
 * within the binary structure rreturned by c_get_function_list
 */
#include "oasis/pkcs11.h"

#endif /* P11PROV_PKCS11_H_ */
