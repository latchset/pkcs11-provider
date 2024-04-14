/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <dlfcn.h>
#include <string.h>

/* Wrapper Interface on top of PKCS#11 interfaces.
 * This allows us to support multiple versions of PKCS#11 drivers
 * at runtime by emulating or returning the proper error if a 3.0
 * only function is used on a 2.40 token. */

struct p11prov_module_ctx {
    P11PROV_CTX *provctx;

    char *path;
    char *init_args;

    void *dlhandle;
    P11PROV_INTERFACE *interface;

    CK_INFO ck_info;

    pthread_mutex_t lock;
    bool initialized;
    bool reinit;
};

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
    CK_C_SeedRandom SeedRandom;
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
    P11PROV_debug("Populating Interfaces with '%s', version %d.%d",
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
    ASSIGN_FN(SeedRandom);
    ASSIGN_FN(GenerateRandom);
    if (intf->version.major == 3) {
        ASSIGN_FN_3_0(GetInterface);
    }
}

static CK_RV p11prov_interface_init(P11PROV_MODULE *mctx)
{
    /* Try to get 3.0 interface by default */
    P11PROV_INTERFACE *intf;
    CK_UTF8CHAR_PTR intf_name = (CK_UTF8CHAR_PTR) "PKCS 11";
    CK_VERSION version = { 3, 0 };
    CK_INTERFACE *ck_interface;
    CK_RV ret;

    intf = OPENSSL_zalloc(sizeof(struct p11prov_interface));
    if (!intf) {
        return CKR_HOST_MEMORY;
    }

    intf->GetInterface = dlsym(mctx->dlhandle, "C_GetInterface");
    if (!intf->GetInterface) {
        char *err = dlerror();
        P11PROV_debug(
            "C_GetInterface() not available. Falling back to "
            "C_GetFunctionList(): %s",
            err);
        intf->GetInterface = p11prov_NO_GetInterface;
    }

    ret = intf->GetInterface(intf_name, &version, &ck_interface, 0);
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

        intf->GetFunctionList = dlsym(mctx->dlhandle, "C_GetFunctionList");
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
        mctx->interface = intf;
    } else {
        OPENSSL_free(intf);
    }
    return ret;
}

CK_RV p11prov_module_new(P11PROV_CTX *ctx, const char *path,
                         const char *init_args, P11PROV_MODULE **_mctx)
{
    struct p11prov_module_ctx *mctx;
    const char *env_module;
    CK_RV ret;

    mctx = OPENSSL_zalloc(sizeof(struct p11prov_module_ctx));
    if (!mctx) {
        return CKR_HOST_MEMORY;
    }
    mctx->provctx = ctx;

    /* The environment variable has the highest precedence */
    env_module = getenv("PKCS11_PROVIDER_MODULE");
    if (env_module && *env_module) {
        mctx->path = OPENSSL_strdup(env_module);
    } else if (path) {
        mctx->path = OPENSSL_strdup(path);
    } else {
        /* If the module is not specified in the configuration file,
         * use the p11-kit proxy  */
#ifdef DEFAULT_PKCS11_MODULE
        mctx->path = OPENSSL_strdup(DEFAULT_PKCS11_MODULE);
#else
        P11PROV_raise(ctx, CKR_ARGUMENTS_BAD, "No PKCS#11 module specified.");
        p11prov_module_free(mctx);
        return CKR_ARGUMENTS_BAD;
#endif
    }
    if (!mctx->path) {
        p11prov_module_free(mctx);
        return CKR_HOST_MEMORY;
    }

    if (init_args) {
        mctx->init_args = OPENSSL_strdup(init_args);
        if (!mctx->init_args) {
            p11prov_module_free(mctx);
            return CKR_HOST_MEMORY;
        }
    }

    ret = MUTEX_INIT(mctx);
    if (ret != CKR_OK) {
        p11prov_module_free(mctx);
        return ret;
    }

    *_mctx = mctx;
    return CKR_OK;
}

#if !defined(RTLD_DEEPBIND)
#define RTLD_DEEPBIND 0
#endif

CK_RV p11prov_module_init(P11PROV_MODULE *mctx)
{
    P11PROV_SLOTS_CTX *slots;
    CK_C_INITIALIZE_ARGS args = { 0 };
    CK_RV ret;

    if (!mctx) {
        return CKR_GENERAL_ERROR;
    }

    ret = MUTEX_LOCK(mctx);
    if (ret != CKR_OK) {
        return ret;
    }

    /* LOCKED SECTION ------------- */
    if (mctx->initialized) {
        ret = CKR_OK;
        goto done;
    }

    P11PROV_debug("PKCS#11: Initializing the module: %s", mctx->path);

    dlerror();

    mctx->dlhandle = dlopen(mctx->path, P11PROV_DLOPEN_FLAGS);
    if (!mctx->dlhandle) {
        char *err = dlerror();
        ret = CKR_GENERAL_ERROR;
        P11PROV_debug("dlopen(%s) failed: %s", mctx->path, err);
        goto done;
    }

    ret = p11prov_interface_init(mctx);
    if (ret != CKR_OK) {
        goto done;
    }

    args.flags = CKF_OS_LOCKING_OK;
    args.pReserved = (void *)mctx->init_args;
    ret = p11prov_Initialize(mctx->provctx, &args);
    if (ret && ret != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        goto done;
    }

    ret = p11prov_GetInfo(mctx->provctx, &mctx->ck_info);
    if (ret) {
        goto done;
    }
    trim(mctx->ck_info.manufacturerID);
    trim(mctx->ck_info.libraryDescription);
    P11PROV_debug("Module Info: ck_ver:%d.%d lib: '%s' '%s' ver:%d.%d",
                  (int)mctx->ck_info.cryptokiVersion.major,
                  (int)mctx->ck_info.cryptokiVersion.minor,
                  mctx->ck_info.manufacturerID,
                  mctx->ck_info.libraryDescription,
                  (int)mctx->ck_info.libraryVersion.major,
                  (int)mctx->ck_info.libraryVersion.minor);

    ret = p11prov_init_slots(mctx->provctx, &slots);
    if (ret) {
        goto done;
    }

    p11prov_ctx_set_slots(mctx->provctx, slots);

    ret = CKR_OK;

done:
    (void)MUTEX_UNLOCK(mctx);
    /* ------------- LOCKED SECTION */
    return ret;
}

P11PROV_INTERFACE *p11prov_module_get_interface(P11PROV_MODULE *mctx)
{
    if (!mctx) {
        return NULL;
    }
    return mctx->interface;
}

void p11prov_module_free(P11PROV_MODULE *mctx)
{
    if (!mctx) {
        return;
    }

    if (mctx->dlhandle) {
        p11prov_Finalize(mctx->provctx, NULL);
        dlclose(mctx->dlhandle);
    }
    OPENSSL_free(mctx->interface);
    OPENSSL_free(mctx->path);
    OPENSSL_free(mctx->init_args);
    OPENSSL_free(mctx);
}

/* should only be called by the fork handler */
void p11prov_module_mark_reinit(P11PROV_MODULE *mctx)
{
    mctx->reinit = true;
}

CK_RV p11prov_module_reinit(P11PROV_MODULE *mctx)
{
    CK_C_INITIALIZE_ARGS args = { 0 };
    CK_INFO ck_info = { 0 };
    CK_RV ret;

    if (!mctx) {
        return CKR_GENERAL_ERROR;
    }

    ret = MUTEX_LOCK(mctx);
    if (ret != CKR_OK) {
        return ret;
    }

    /* LOCKED SECTION ------------- */
    if (!mctx->reinit) {
        /* another thread already did it */
        goto done;
    }

    P11PROV_debug("PKCS#11: Re-initializing the module: %s", mctx->path);

    (void)p11prov_Finalize(mctx->provctx, NULL);

    args.flags = CKF_OS_LOCKING_OK;
    args.pReserved = (void *)mctx->init_args;
    ret = p11prov_Initialize(mctx->provctx, &args);
    if (ret == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        ret = CKR_OK;
    }
    if (ret != CKR_OK) {
        P11PROV_debug("PKCS#11: Re-init failed: %lx", ret);
        goto done;
    }

    /* clear reinit flag as we just did re-initialize */
    mctx->reinit = false;

    ret = p11prov_GetInfo(mctx->provctx, &ck_info);
    if (ret != CKR_OK) {
        goto done;
    }
    trim(ck_info.manufacturerID);
    trim(ck_info.libraryDescription);

    if (ck_info.cryptokiVersion.major != mctx->ck_info.cryptokiVersion.major
        || ck_info.cryptokiVersion.minor != mctx->ck_info.cryptokiVersion.minor
        || strncmp((const char *)ck_info.manufacturerID,
                   (const char *)mctx->ck_info.manufacturerID, 32)
               != 0
        || ck_info.flags != mctx->ck_info.flags
        || strncmp((const char *)ck_info.libraryDescription,
                   (const char *)mctx->ck_info.libraryDescription, 32)
               != 0
        || ck_info.libraryVersion.major != mctx->ck_info.libraryVersion.major
        || ck_info.libraryVersion.minor != mctx->ck_info.libraryVersion.minor) {
        P11PROV_debug("PKCS#11: Re-init module mismatch");
        P11PROV_debug("Original Info: ck_ver:%d.%d lib: '%s' '%s' ver:%d.%d",
                      (int)mctx->ck_info.cryptokiVersion.major,
                      (int)mctx->ck_info.cryptokiVersion.minor,
                      mctx->ck_info.manufacturerID,
                      mctx->ck_info.libraryDescription,
                      (int)mctx->ck_info.libraryVersion.major,
                      (int)mctx->ck_info.libraryVersion.minor);
        P11PROV_debug("Recovered Info: ck_ver:%d.%d lib: '%s' '%s' ver:%d.%d",
                      (int)ck_info.cryptokiVersion.major,
                      (int)ck_info.cryptokiVersion.minor,
                      ck_info.manufacturerID, ck_info.libraryDescription,
                      (int)ck_info.libraryVersion.major,
                      (int)ck_info.libraryVersion.minor);
        ret = CKR_GENERAL_ERROR;
    }

done:
    (void)MUTEX_UNLOCK(mctx);
    /* ------------- LOCKED SECTION */
    return ret;
}

/* This is needed to avoid side channels in the PKCS 1.5 decryption case */
CK_RV side_channel_free_Decrypt(P11PROV_CTX *ctx, CK_SESSION_HANDLE hSession,
                                CK_BYTE_PTR pEncryptedData,
                                CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                                CK_ULONG_PTR pulDataLen)
{
    P11PROV_INTERFACE *intf = p11prov_ctx_get_interface(ctx);
    CK_RV ret = CKR_GENERAL_ERROR;
    if (!intf) {
        P11PROV_raise(ctx, ret, "Can't get module interfaces");
        return ret;
    }
    P11PROV_debug("Calling C_Decrypt");
    /* Must not add any conditionals based on return value, so we just return
     * straight */
    return intf->Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData,
                         pulDataLen);
}

CK_INFO p11prov_module_ck_info(P11PROV_MODULE *mctx)
{
    return mctx->ck_info;
}
