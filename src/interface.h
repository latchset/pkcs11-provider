/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _INTERFACE_H
#define _INTERFACE_H

#if P11PROV_ADDRESS_SANITIZER
/* address sanitizer does not play well with the RTLD_DEEPBIND */
#define P11PROV_DLOPEN_FLAGS RTLD_NOW | RTLD_LOCAL
#else
#define P11PROV_DLOPEN_FLAGS RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND
#endif

/* interface declarations for PKCS#11 wrapper functions */
CK_RV p11prov_module_new(P11PROV_CTX *ctx, const char *path,
                         const char *init_args, P11PROV_MODULE **_mctx);
CK_RV p11prov_module_init(P11PROV_MODULE *mctx);
P11PROV_INTERFACE *p11prov_module_get_interface(P11PROV_MODULE *mctx);
void p11prov_module_free(P11PROV_MODULE *mctx);
void p11prov_module_mark_reinit(P11PROV_MODULE *mctx);
CK_RV p11prov_module_reinit(P11PROV_MODULE *mctx);
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
CK_RV p11prov_EncryptUpdate(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                            CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG_PTR pulEncryptedPartLen);
CK_RV p11prov_EncryptFinal(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                           CK_BYTE_PTR pLastEncryptedPart,
                           CK_ULONG_PTR pulLastEncryptedPartLen);
CK_RV p11prov_DecryptInit(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV p11prov_Decrypt(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                      CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
CK_RV p11prov_DecryptUpdate(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                            CK_ULONG_PTR pulPartLen);
CK_RV p11prov_DecryptFinal(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                           CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
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
CK_RV p11prov_GenerateKey(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                          CK_OBJECT_HANDLE_PTR phKey);
CK_RV p11prov_GenerateKeyPair(
    P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
CK_RV p11prov_DeriveKey(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                        CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
                        CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
                        CK_OBJECT_HANDLE_PTR phKey);
CK_RV p11prov_SeedRandom(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR SeedData, CK_ULONG ulSeedLen);
CK_RV p11prov_GenerateRandom(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                             CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen);
CK_RV p11prov_SessionCancel(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                            CK_FLAGS flags);
CK_RV p11prov_EncapsulateKey(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                             CK_MECHANISM_PTR pMechanism,
                             CK_OBJECT_HANDLE hPublicKey,
                             CK_ATTRIBUTE_PTR pTemplate,
                             CK_ULONG ulAttributeCount, CK_BYTE_PTR pCiphertext,
                             CK_ULONG_PTR pulCiphertextLen,
                             CK_OBJECT_HANDLE_PTR phKey);
CK_RV p11prov_DecapsulateKey(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                             CK_MECHANISM_PTR pMechanism,
                             CK_OBJECT_HANDLE hPrivateKey,
                             CK_ATTRIBUTE_PTR pTemplate,
                             CK_ULONG ulAttributeCount, CK_BYTE_PTR pCiphertext,
                             CK_ULONG ulCiphertextLen,
                             CK_OBJECT_HANDLE_PTR phKey);

/* Special side-channel free path against PKCS#1 1.5 side channel leaking */
CK_RV side_channel_free_Decrypt(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                                CK_BYTE_PTR pEncryptedData,
                                CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                                CK_ULONG_PTR pulDataLen);

CK_INFO p11prov_module_ck_info(P11PROV_MODULE *mctx);

/* The following defines are needed for a generic mask for any of the functions
 * we generate via interface.pre, however there is no need to assign a blocking
 * value until we'll have a configuration option that allows to set blocks, so
 * most of these are defined to 0 which won't block anything.
 * Additionally we reserve the lower 4 bits to future "group" blocking. For
 * example we may introduce a way to block all the PCS#11 v3 function calls to
 * simulate a 2.40 token */
#define P11PROV_BLOCK_Initialize 0b0000000000000000
#define P11PROV_BLOCK_Finalize 0b0000000000000000
#define P11PROV_BLOCK_GetInfo 0b0000000000000000
#define P11PROV_BLOCK_GetFunctionList 0b0000000000000000
#define P11PROV_BLOCK_GetSlotList 0b0000000000000000
#define P11PROV_BLOCK_GetSlotInfo 0b0000000000000000
#define P11PROV_BLOCK_GetTokenInfo 0b0000000000000000
#define P11PROV_BLOCK_GetMechanismList 0b0000000000000000
#define P11PROV_BLOCK_GetMechanismInfo 0b0000000000000000
#define P11PROV_BLOCK_OpenSession 0b0000000000000000
#define P11PROV_BLOCK_CloseSession 0b0000000000000000
#define P11PROV_BLOCK_GetSessionInfo 0b0000000000000000
#define P11PROV_BLOCK_GetOperationState 0b0000000000001000
#define P11PROV_BLOCK_SetOperationState 0b0000000000001000
#define P11PROV_BLOCK_Login 0b0000000000000000
#define P11PROV_BLOCK_Logout 0b0000000000000000
#define P11PROV_BLOCK_CreateObject 0b0000000000000000
#define P11PROV_BLOCK_CopyObject 0b0000000000000000
#define P11PROV_BLOCK_DestroyObject 0b0000000000000000
#define P11PROV_BLOCK_GetAttributeValue 0b0000000000000000
#define P11PROV_BLOCK_SetAttributeValue 0b0000000000000000
#define P11PROV_BLOCK_FindObjectsInit 0b0000000000000000
#define P11PROV_BLOCK_FindObjects 0b0000000000000000
#define P11PROV_BLOCK_FindObjectsFinal 0b0000000000000000
#define P11PROV_BLOCK_EncryptInit 0b0000000000000000
#define P11PROV_BLOCK_Encrypt 0b0000000000000000
#define P11PROV_BLOCK_EncryptUpdate 0b0000000000000000
#define P11PROV_BLOCK_EncryptFinal 0b0000000000000000
#define P11PROV_BLOCK_DecryptInit 0b0000000000000000
#define P11PROV_BLOCK_Decrypt 0b0000000000000000
#define P11PROV_BLOCK_DecryptUpdate 0b0000000000000000
#define P11PROV_BLOCK_DecryptFinal 0b0000000000000000
#define P11PROV_BLOCK_DigestInit 0b0000000000000000
#define P11PROV_BLOCK_Digest 0b0000000000000000
#define P11PROV_BLOCK_DigestUpdate 0b0000000000000000
#define P11PROV_BLOCK_DigestKey 0b0000000000000000
#define P11PROV_BLOCK_DigestFinal 0b0000000000000000
#define P11PROV_BLOCK_SignInit 0b0000000000000000
#define P11PROV_BLOCK_Sign 0b0000000000000000
#define P11PROV_BLOCK_SignUpdate 0b0000000000000000
#define P11PROV_BLOCK_SignFinal 0b0000000000000000
#define P11PROV_BLOCK_VerifyInit 0b0000000000000000
#define P11PROV_BLOCK_Verify 0b0000000000000000
#define P11PROV_BLOCK_VerifyUpdate 0b0000000000000000
#define P11PROV_BLOCK_VerifyFinal 0b0000000000000000
#define P11PROV_BLOCK_GenerateKey 0b0000000000000000
#define P11PROV_BLOCK_GenerateKeyPair 0b0000000000000000
#define P11PROV_BLOCK_DeriveKey 0b0000000000000000
#define P11PROV_BLOCK_SeedRandom 0b0000000000000000
#define P11PROV_BLOCK_GenerateRandom 0b0000000000000000
/* 3.x  functions: */
#define P11PROV_BLOCK_GetInterface 0b0000000000000000
#define P11PROV_BLOCK_SessionCancel 0b0000000000000000
#define P11PROV_BLOCK_EncapsulateKey 0b0000000000000000
#define P11PROV_BLOCK_DecapsulateKey 0b0000000000000000

#endif /* _INTERFACE_H */
