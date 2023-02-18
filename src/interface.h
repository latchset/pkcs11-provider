/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _INTERFACE_H
#define _INTERFACE_H

/* interface declarations for PKCS#11 wrapper functions */
CK_RV p11prov_module_new(P11PROV_CTX *ctx, const char *path,
                         const char *init_args, P11PROV_MODULE **_mctx);
CK_RV p11prov_module_init(P11PROV_MODULE *mctx);
P11PROV_INTERFACE *p11prov_module_get_interface(P11PROV_MODULE *mctx);
void p11prov_module_free(P11PROV_MODULE *mctx);
CK_RV p11prov_Initialize(P11PROV_CTX *ctx, CK_VOID_PTR pInitArgs);
CK_RV p11prov_Finalize(P11PROV_CTX *ctx, CK_VOID_PTR pReserved);
CK_RV p11prov_GetInfo(P11PROV_CTX *ctx, CK_INFO_PTR pInfo);
CK_RV p11prov_GetInterface(P11PROV_CTX *ctx, CK_UTF8CHAR_PTR pInterfaceName,
                           CK_VERSION_PTR pVersion,
                           CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags);
CK_RV p11prov_GetFunctionList(P11PROV_CTX *ctx,
                              CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
CK_RV p11prov_GetSlotList(P11PROV_CTX *ctx, CK_BBOOL tokenPresent,
                          CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
CK_RV p11prov_GetSlotInfo(P11PROV_CTX *ctx, CK_SLOT_ID slotID,
                          CK_SLOT_INFO_PTR pInfo);
CK_RV p11prov_GetTokenInfo(P11PROV_CTX *ctx, CK_SLOT_ID slotID,
                           CK_TOKEN_INFO_PTR pInfo);
CK_RV p11prov_GetMechanismList(P11PROV_CTX *ctx, CK_SLOT_ID slotID,
                               CK_MECHANISM_TYPE_PTR pMechanismList,
                               CK_ULONG_PTR pulCount);

CK_RV p11prov_GetMechanismInfo(P11PROV_CTX *ctx, CK_SLOT_ID slotID,
                               CK_MECHANISM_TYPE type,
                               CK_MECHANISM_INFO_PTR pInfo);
CK_RV p11prov_OpenSession(P11PROV_CTX *ctx, CK_SLOT_ID slotID, CK_FLAGS flags,
                          CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                          CK_SESSION_HANDLE_PTR phSession);
CK_RV p11prov_CloseSession(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession);
CK_RV p11prov_GetSessionInfo(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                             CK_SESSION_INFO_PTR pInfo);
CK_RV p11prov_GetOperationState(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                                CK_BYTE_PTR pOperationState,
                                CK_ULONG_PTR pulOperationStateLen);
CK_RV p11prov_SetOperationState(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                                CK_BYTE_PTR pOperationState,
                                CK_ULONG ulOperationStateLen,
                                CK_OBJECT_HANDLE hEncryptionKey,
                                CK_OBJECT_HANDLE hAuthenticationKey);
CK_RV p11prov_Login(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                    CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin,
                    CK_ULONG ulPinLen);
CK_RV p11prov_CreateObject(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                           CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                           CK_OBJECT_HANDLE_PTR phObject);
CK_RV p11prov_CopyObject(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                         CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                         CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);
CK_RV p11prov_DestroyObject(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                            CK_OBJECT_HANDLE hObject);
CK_RV p11prov_GetAttributeValue(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                                CK_OBJECT_HANDLE hObject,
                                CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV p11prov_SetAttributeValue(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                                CK_OBJECT_HANDLE hObject,
                                CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV p11prov_FindObjectsInit(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                              CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV p11prov_FindObjects(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                          CK_OBJECT_HANDLE_PTR phObject,
                          CK_ULONG ulMaxObjectCount,
                          CK_ULONG_PTR pulObjectCount);
CK_RV p11prov_FindObjectsFinal(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession);
CK_RV p11prov_EncryptInit(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV p11prov_Encrypt(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                      CK_BYTE_PTR pEncryptedData,
                      CK_ULONG_PTR pulEncryptedDataLen);
CK_RV p11prov_DecryptInit(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV p11prov_Decrypt(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                      CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
CK_RV p11prov_DigestInit(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                         CK_MECHANISM_PTR pMechanism);
CK_RV p11prov_DigestUpdate(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                           CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
CK_RV p11prov_DigestFinal(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
CK_RV p11prov_SignInit(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                       CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV p11prov_Sign(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                   CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                   CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
CK_RV p11prov_SignUpdate(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
CK_RV p11prov_SignFinal(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
CK_RV p11prov_VerifyInit(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                         CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV p11prov_Verify(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                     CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
CK_RV p11prov_VerifyUpdate(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                           CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
CK_RV p11prov_VerifyFinal(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
CK_RV p11prov_GenerateKeyPair(
    P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
CK_RV p11prov_DeriveKey(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                        CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
                        CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
                        CK_OBJECT_HANDLE_PTR phKey);
CK_RV p11prov_GenerateRandom(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                             CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen);

#endif /* _INTERFACE_H */
