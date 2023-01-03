/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <dlfcn.h>

/* Wrapper Interface on top of PKCS#11 interfaces.
 * This allows us to support multiple versions of PKCS#11 drivers
 * at runtime by emulating or returning the proper error if a 3.0
 * only function is used on a 2.40 token. */

/* This structure is effectively equivalent to CK_FUNCTION_LIST_3_0
 * however we list only the symbols we are actually using in the
 * code plus flags */
struct p11prov_interface {
    CK_VERSION version;
    CK_FLAGS flags;
    CK_C_Initialize Initialize;
    CK_C_Finalize Finalize;
    CK_C_GetInfo GetInfo;
    CK_C_GetFunctionList GetFunctionList;
    CK_C_GetSlotList GetSlotList;
    CK_C_GetSlotInfo GetSlotInfo;
    CK_C_GetTokenInfo GetTokenInfo;
    CK_C_GetMechanismList GetMechanismList;
    CK_C_GetMechanismInfo GetMechanismInfo;
    CK_C_OpenSession OpenSession;
    CK_C_CloseSession CloseSession;
    CK_C_GetSessionInfo GetSessionInfo;
    CK_C_GetOperationState GetOperationState;
    CK_C_SetOperationState SetOperationState;
    CK_C_Login Login;
    CK_C_CreateObject CreateObject;
    CK_C_CopyObject CopyObject;
    CK_C_DestroyObject DestroyObject;
    CK_C_GetAttributeValue GetAttributeValue;
    CK_C_SetAttributeValue SetAttributeValue;
    CK_C_FindObjectsInit FindObjectsInit;
    CK_C_FindObjects FindObjects;
    CK_C_FindObjectsFinal FindObjectsFinal;
    CK_C_EncryptInit EncryptInit;
    CK_C_Encrypt Encrypt;
    CK_C_DecryptInit DecryptInit;
    CK_C_Decrypt Decrypt;
    CK_C_DigestInit DigestInit;
    CK_C_DigestUpdate DigestUpdate;
    CK_C_DigestFinal DigestFinal;
    CK_C_SignInit SignInit;
    CK_C_Sign Sign;
    CK_C_SignUpdate SignUpdate;
    CK_C_SignFinal SignFinal;
    CK_C_VerifyInit VerifyInit;
    CK_C_Verify Verify;
    CK_C_VerifyUpdate VerifyUpdate;
    CK_C_VerifyFinal VerifyFinal;
    CK_C_GenerateKeyPair GenerateKeyPair;
    CK_C_DeriveKey DeriveKey;
    CK_C_GenerateRandom GenerateRandom;
    CK_C_GetInterface GetInterface;
};

#include "interface.gen.c"

static CK_RV p11prov_NO_GetInterface(CK_UTF8CHAR_PTR pInterfaceName,
                                     CK_VERSION_PTR pVersion,
                                     CK_INTERFACE_PTR_PTR ppInterface,
                                     CK_FLAGS flags)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

#define ASSIGN_FN(name) intf->name = list.fns->C_##name
#define ASSIGN_FN_3_0(name) intf->name = list.fns_3_0->C_##name
static void populate_interface(P11PROV_INTERFACE *intf, CK_INTERFACE *ck_intf)
{
    union {
        CK_FUNCTION_LIST_PTR fns;
        CK_FUNCTION_LIST_3_0_PTR fns_3_0;
    } list;

    list.fns = (CK_FUNCTION_LIST_PTR)ck_intf->pFunctionList;
    P11PROV_debug("Populating Interfaces with '%s', version %d.%d\n",
                  ck_intf->pInterfaceName, list.fns->version.major,
                  list.fns->version.minor);

    intf->version = list.fns->version;
    intf->flags = ck_intf->flags;
    ASSIGN_FN(Initialize);
    ASSIGN_FN(Finalize);
    ASSIGN_FN(GetInfo);
    ASSIGN_FN(GetMechanismList);
    ASSIGN_FN(GetFunctionList);
    ASSIGN_FN(GetSlotList);
    ASSIGN_FN(GetSlotInfo);
    ASSIGN_FN(GetTokenInfo);
    ASSIGN_FN(GetMechanismList);
    ASSIGN_FN(GetMechanismInfo);
    ASSIGN_FN(OpenSession);
    ASSIGN_FN(CloseSession);
    ASSIGN_FN(GetSessionInfo);
    ASSIGN_FN(GetOperationState);
    ASSIGN_FN(SetOperationState);
    ASSIGN_FN(Login);
    ASSIGN_FN(CreateObject);
    ASSIGN_FN(CopyObject);
    ASSIGN_FN(DestroyObject);
    ASSIGN_FN(GetAttributeValue);
    ASSIGN_FN(SetAttributeValue);
    ASSIGN_FN(FindObjectsInit);
    ASSIGN_FN(FindObjects);
    ASSIGN_FN(FindObjectsFinal);
    ASSIGN_FN(EncryptInit);
    ASSIGN_FN(Encrypt);
    ASSIGN_FN(DecryptInit);
    ASSIGN_FN(Decrypt);
    ASSIGN_FN(DigestInit);
    ASSIGN_FN(DigestUpdate);
    ASSIGN_FN(DigestFinal);
    ASSIGN_FN(SignInit);
    ASSIGN_FN(Sign);
    ASSIGN_FN(SignUpdate);
    ASSIGN_FN(SignFinal);
    ASSIGN_FN(VerifyInit);
    ASSIGN_FN(Verify);
    ASSIGN_FN(VerifyUpdate);
    ASSIGN_FN(VerifyFinal);
    ASSIGN_FN(GenerateKeyPair);
    ASSIGN_FN(DeriveKey);
    ASSIGN_FN(GenerateRandom);
    ASSIGN_FN_3_0(GetInterface);
}

CK_RV p11prov_interface_init(void *dlhandle, P11PROV_INTERFACE **interface,
                             CK_FLAGS *interface_flags)
{
    /* Try to get 3.0 interface by default */
    P11PROV_INTERFACE *intf;
    CK_VERSION version = { 3, 0 };
    CK_INTERFACE *ck_interface;
    CK_RV ret;

    intf = OPENSSL_zalloc(sizeof(struct p11prov_interface));
    if (!intf) {
        return CKR_HOST_MEMORY;
    }

    ret = CKR_FUNCTION_NOT_SUPPORTED;
    intf->GetInterface = dlsym(dlhandle, "C_GetInterface");
    if (!intf->GetInterface) {
        char *err = dlerror();
        P11PROV_debug("dlsym() failed: %s", err);
        intf->GetInterface = p11prov_NO_GetInterface;
    }

    ret = intf->GetInterface(NULL, &version, &ck_interface, 0);
    if (ret != CKR_OK && ret != CKR_FUNCTION_NOT_SUPPORTED) {
        /* retry without asking for specific version */
        ret = intf->GetInterface(NULL, NULL, &ck_interface, 0);
    }
    if (ret == CKR_FUNCTION_NOT_SUPPORTED) {
        /* assume fallback to 2.40 */
        static CK_INTERFACE deflt = {
            .pInterfaceName = (CK_UTF8CHAR_PTR) "Internal defaults",
            .flags = 0,
        };

        intf->GetFunctionList = dlsym(dlhandle, "C_GetFunctionList");
        if (intf->GetFunctionList) {
            ret = intf->GetFunctionList(
                (CK_FUNCTION_LIST_PTR_PTR)&deflt.pFunctionList);
            if (ret == CKR_OK) {
                ck_interface = &deflt;
            }
        } else {
            char *err = dlerror();
            P11PROV_debug("dlsym() failed: %s", err);
            ret = CKR_GENERAL_ERROR;
        }
    }
    if (ret == CKR_OK) {
        populate_interface(intf, ck_interface);
        *interface = intf;
        *interface_flags = intf->flags;
    } else {
        OPENSSL_free(intf);
    }
    return ret;
}

void p11prov_interface_free(P11PROV_INTERFACE *interface)
{
    OPENSSL_free(interface);
}
