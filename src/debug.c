/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

/* for strndup we need to define POSIX_C_SOURCE */
#define _POSIX_C_SOURCE 200809L
#include "provider.h"
#include <string.h>

int debug_level = -1;
FILE *stddebug = NULL;

/* this function relies on being called by P11PROV_debug, after
 * an __atomic_compare_exchange_n sets debug_lazy_init to -1,
 * This allows only 1 thread to ever init, as any other thread
 * would see debugging as disabled. This means some debugging may
 * be lost but will not risk multiplt thread stopming on each
 * other to open the debug file */
void p11prov_debug_init(void)
{
    /* The ',' character should not be used in the path as it will
     * break tokenization, we do not provide any escaping, kiss */
    const char *env = getenv("PKCS11_PROVIDER_DEBUG");
    const char *next;
    char fname[1024];
    int dbg_level = 0;
    int orig;
    if (env) {
        do {
            next = strchr(env, ',');
            if (strncmp(env, "file:", 5) == 0) {
                int len;
                if (stddebug != NULL && stddebug != stderr) {
                    fclose(stddebug);
                }
                if (next) {
                    len = next - env - 5;
                } else {
                    len = strlen(env + 5);
                }
                memcpy(fname, env + 5, len);
                fname[len] = '\0';
                stddebug = fopen(fname, "a");
                if (stddebug == NULL) {
                    goto done;
                }
            } else if (strncmp(env, "level:", 6) == 0) {
                dbg_level = atoi(env + 6);
            }
            if (next) {
                env = next + 1;
            }
        } while (next);

        if (dbg_level < 1) {
            dbg_level = 1;
        }
        if (stddebug == NULL) {
            stddebug = stderr;
        }
    }

done:
    /* set value to debug_level atomically */
    __atomic_exchange(&debug_level, &dbg_level, &orig, __ATOMIC_SEQ_CST);
}

void p11prov_debug(const char *file, int line, const char *func,
                   const char *fmt, ...)
{
    const char newline[] = "\n";
    va_list args;

    if (file) {
        fprintf(stddebug, "[%s:%d] ", file, line);
    }
    if (func) {
        fprintf(stddebug, "%s(): ", func);
    }
    va_start(args, fmt);
    vfprintf(stddebug, fmt, args);
    va_end(args);
    fwrite(newline, 1, 1, stddebug);
    fflush(stddebug);
}

struct ckmap {
    CK_ULONG value;
    const char *name;
};
extern struct ckmap mechanism_names[];
extern struct ckmap mechanism_flags[];

void p11prov_debug_mechanism(P11PROV_CTX *ctx, CK_SLOT_ID slotid,
                             CK_MECHANISM_TYPE type)
{
    CK_MECHANISM_INFO info = { 0 };
    const char *mechname = "UNKNOWN";
    CK_RV ret;

    if (debug_level < 1) {
        return;
    }

    for (int i = 0; mechanism_names[i].name != NULL; i++) {
        if (type == mechanism_names[i].value) {
            mechname = mechanism_names[i].name;
        }
    }

    ret = p11prov_GetMechanismInfo(ctx, slotid, type, &info);
    if (ret != CKR_OK) {
        p11prov_debug(NULL, 0, NULL,
                      "C_GetMechanismInfo for %s(%lu) failed %lu", mechname,
                      type, ret);
    } else {
        p11prov_debug(NULL, 0, NULL,
                      "Mechanism Info:\n"
                      "  name: %s (%lu):\n"
                      "  min key length: %lu\n"
                      "  max key length: %lu\n"
                      "  flags (%#08lx):\n",
                      mechname, type, info.ulMinKeySize, info.ulMaxKeySize,
                      info.flags);
        for (int i = 0; mechanism_flags[i].name != NULL; i++) {
            if (info.flags & mechanism_flags[i].value) {
                p11prov_debug(NULL, 0, NULL, "    %-25s (%#08lx)",
                              mechanism_flags[i].name,
                              mechanism_flags[i].value);
            }
        }
    }
}

extern struct ckmap token_flags[];

static void p11prov_debug_token_info(CK_TOKEN_INFO *info)
{
    p11prov_debug(NULL, 0, NULL,
                  "Token Info:\n"
                  "  Label:            [%.32s]\n"
                  "  Manufacturer ID:  [%.32s]\n"
                  "  Model:            [%.16s]\n"
                  "  Serial Number:    [%.16s]\n"
                  "  Flags (%#08lx):\n",
                  info->label, info->manufacturerID, info->model,
                  info->serialNumber, info->flags);
    for (int i = 0; token_flags[i].name != NULL; i++) {
        if (info->flags & token_flags[i].value) {
            p11prov_debug(NULL, 0, NULL, "    %-35s (%#08lx)",
                          token_flags[i].name, token_flags[i].value);
        }
    }
    p11prov_debug(NULL, 0, NULL,
                  "  Session Count      Max: %3lu  Current: %3lu\n"
                  "  R/W Session Count  Max: %3lu  Current: %3lu\n"
                  "  Pin Len Range: %lu-%lu\n"
                  "  Public  Memory  Total: %6lu  Free: %6lu\n"
                  "  Private Memory  Total: %6lu  Free: %6lu\n"
                  "  Hardware Version: %d.%d\n"
                  "  Firmware Version: %d.%d\n"
                  "  UTC Time: [%.16s]\n",
                  info->ulMaxSessionCount, info->ulSessionCount,
                  info->ulMaxRwSessionCount, info->ulRwSessionCount,
                  info->ulMinPinLen, info->ulMaxPinLen,
                  info->ulTotalPublicMemory, info->ulFreePublicMemory,
                  info->ulTotalPrivateMemory, info->ulFreePrivateMemory,
                  info->hardwareVersion.major, info->hardwareVersion.minor,
                  info->firmwareVersion.major, info->firmwareVersion.minor,
                  info->utcTime);
}

extern struct ckmap slot_flags[];
extern struct ckmap profile_ids[];

void p11prov_debug_slot(P11PROV_CTX *ctx, CK_SLOT_ID slotid, CK_SLOT_INFO *slot,
                        CK_TOKEN_INFO *token, CK_MECHANISM_TYPE *mechs,
                        CK_ULONG mechs_num, CK_ULONG *profiles)
{
    p11prov_debug(NULL, 0, NULL,
                  "Slot Info:\n"
                  "  ID: %lu\n"
                  "  Description:      [%.64s]\n"
                  "  Manufacturer ID:  [%.32s]\n"
                  "  Flags (%#08lx):\n",
                  slotid, slot->slotDescription, slot->manufacturerID,
                  slot->flags);
    for (int i = 0; slot_flags[i].name != NULL; i++) {
        if (slot->flags & slot_flags[i].value) {
            p11prov_debug(NULL, 0, NULL, "    %-25s (%#08lx)",
                          slot_flags[i].name, slot_flags[i].value);
        }
    }
    p11prov_debug(NULL, 0, NULL,
                  "  Hardware Version: %d.%d\n"
                  "  Firmware Version: %d.%d\n",
                  slot->hardwareVersion.major, slot->hardwareVersion.minor,
                  slot->firmwareVersion.major, slot->firmwareVersion.minor);
    if (slot->flags & CKF_TOKEN_PRESENT) {
        p11prov_debug_token_info(token);
    }

    if (debug_level > 1) {
        for (CK_ULONG i = 0; i < mechs_num; i++) {
            p11prov_debug_mechanism(ctx, slotid, mechs[i]);
        }
    }

    if (profiles[0] != CKP_INVALID_ID) {
        p11prov_debug(NULL, 0, NULL, "  Available profiles:\n");
        for (int c = 0; c < 5; c++) {
            for (int i = 0; profile_ids[i].name != NULL; i++) {
                if (profiles[c] == slot_flags[i].value) {
                    p11prov_debug(NULL, 0, NULL, "    %-35s (%#08lx)",
                                  profile_ids[i].name, profile_ids[i].value);
                }
            }
        }
    } else {
        p11prov_debug(NULL, 0, NULL, "  No profiles specified\n");
    }
}

#define MECH_ENTRY(_m) \
    { \
        _m, #_m \
    }
struct ckmap mechanism_names[] = {
    MECH_ENTRY(CKM_RSA_PKCS_KEY_PAIR_GEN),
    MECH_ENTRY(CKM_RSA_PKCS),
    MECH_ENTRY(CKM_RSA_9796),
    MECH_ENTRY(CKM_RSA_X_509),
    MECH_ENTRY(CKM_MD2_RSA_PKCS),
    MECH_ENTRY(CKM_MD5_RSA_PKCS),
    MECH_ENTRY(CKM_SHA1_RSA_PKCS),
    MECH_ENTRY(CKM_RIPEMD128_RSA_PKCS),
    MECH_ENTRY(CKM_RIPEMD160_RSA_PKCS),
    MECH_ENTRY(CKM_RSA_PKCS_OAEP),
    MECH_ENTRY(CKM_RSA_X9_31_KEY_PAIR_GEN),
    MECH_ENTRY(CKM_RSA_X9_31),
    MECH_ENTRY(CKM_SHA1_RSA_X9_31),
    MECH_ENTRY(CKM_RSA_PKCS_PSS),
    MECH_ENTRY(CKM_SHA1_RSA_PKCS_PSS),
    MECH_ENTRY(CKM_DSA_KEY_PAIR_GEN),
    MECH_ENTRY(CKM_DSA),
    MECH_ENTRY(CKM_DSA_SHA1),
    MECH_ENTRY(CKM_DSA_SHA224),
    MECH_ENTRY(CKM_DSA_SHA256),
    MECH_ENTRY(CKM_DSA_SHA384),
    MECH_ENTRY(CKM_DSA_SHA512),
    MECH_ENTRY(CKM_DSA_SHA3_224),
    MECH_ENTRY(CKM_DSA_SHA3_256),
    MECH_ENTRY(CKM_DSA_SHA3_384),
    MECH_ENTRY(CKM_DSA_SHA3_512),
    MECH_ENTRY(CKM_DH_PKCS_KEY_PAIR_GEN),
    MECH_ENTRY(CKM_DH_PKCS_DERIVE),
    MECH_ENTRY(CKM_X9_42_DH_KEY_PAIR_GEN),
    MECH_ENTRY(CKM_X9_42_DH_DERIVE),
    MECH_ENTRY(CKM_X9_42_DH_HYBRID_DERIVE),
    MECH_ENTRY(CKM_X9_42_MQV_DERIVE),
    MECH_ENTRY(CKM_SHA256_RSA_PKCS),
    MECH_ENTRY(CKM_SHA384_RSA_PKCS),
    MECH_ENTRY(CKM_SHA512_RSA_PKCS),
    MECH_ENTRY(CKM_SHA256_RSA_PKCS_PSS),
    MECH_ENTRY(CKM_SHA384_RSA_PKCS_PSS),
    MECH_ENTRY(CKM_SHA512_RSA_PKCS_PSS),
    MECH_ENTRY(CKM_SHA224_RSA_PKCS),
    MECH_ENTRY(CKM_SHA224_RSA_PKCS_PSS),
    MECH_ENTRY(CKM_SHA512_224),
    MECH_ENTRY(CKM_SHA512_224_HMAC),
    MECH_ENTRY(CKM_SHA512_224_HMAC_GENERAL),
    MECH_ENTRY(CKM_SHA512_224_KEY_DERIVATION),
    MECH_ENTRY(CKM_SHA512_256),
    MECH_ENTRY(CKM_SHA512_256_HMAC),
    MECH_ENTRY(CKM_SHA512_256_HMAC_GENERAL),
    MECH_ENTRY(CKM_SHA512_256_KEY_DERIVATION),
    MECH_ENTRY(CKM_SHA512_T),
    MECH_ENTRY(CKM_SHA512_T_HMAC),
    MECH_ENTRY(CKM_SHA512_T_HMAC_GENERAL),
    MECH_ENTRY(CKM_SHA512_T_KEY_DERIVATION),
    MECH_ENTRY(CKM_SHA3_256_RSA_PKCS),
    MECH_ENTRY(CKM_SHA3_384_RSA_PKCS),
    MECH_ENTRY(CKM_SHA3_512_RSA_PKCS),
    MECH_ENTRY(CKM_SHA3_256_RSA_PKCS_PSS),
    MECH_ENTRY(CKM_SHA3_384_RSA_PKCS_PSS),
    MECH_ENTRY(CKM_SHA3_512_RSA_PKCS_PSS),
    MECH_ENTRY(CKM_SHA3_224_RSA_PKCS),
    MECH_ENTRY(CKM_SHA3_224_RSA_PKCS_PSS),
    MECH_ENTRY(CKM_RC2_KEY_GEN),
    MECH_ENTRY(CKM_RC2_ECB),
    MECH_ENTRY(CKM_RC2_CBC),
    MECH_ENTRY(CKM_RC2_MAC),
    MECH_ENTRY(CKM_RC2_MAC_GENERAL),
    MECH_ENTRY(CKM_RC2_CBC_PAD),
    MECH_ENTRY(CKM_RC4_KEY_GEN),
    MECH_ENTRY(CKM_RC4),
    MECH_ENTRY(CKM_DES_KEY_GEN),
    MECH_ENTRY(CKM_DES_ECB),
    MECH_ENTRY(CKM_DES_CBC),
    MECH_ENTRY(CKM_DES_MAC),
    MECH_ENTRY(CKM_DES_MAC_GENERAL),
    MECH_ENTRY(CKM_DES_CBC_PAD),
    MECH_ENTRY(CKM_DES2_KEY_GEN),
    MECH_ENTRY(CKM_DES3_KEY_GEN),
    MECH_ENTRY(CKM_DES3_ECB),
    MECH_ENTRY(CKM_DES3_CBC),
    MECH_ENTRY(CKM_DES3_MAC),
    MECH_ENTRY(CKM_DES3_MAC_GENERAL),
    MECH_ENTRY(CKM_DES3_CBC_PAD),
    MECH_ENTRY(CKM_DES3_CMAC_GENERAL),
    MECH_ENTRY(CKM_DES3_CMAC),
    MECH_ENTRY(CKM_CDMF_KEY_GEN),
    MECH_ENTRY(CKM_CDMF_ECB),
    MECH_ENTRY(CKM_CDMF_CBC),
    MECH_ENTRY(CKM_CDMF_MAC),
    MECH_ENTRY(CKM_CDMF_MAC_GENERAL),
    MECH_ENTRY(CKM_CDMF_CBC_PAD),
    MECH_ENTRY(CKM_DES_OFB64),
    MECH_ENTRY(CKM_DES_OFB8),
    MECH_ENTRY(CKM_DES_CFB64),
    MECH_ENTRY(CKM_DES_CFB8),
    MECH_ENTRY(CKM_MD2),
    MECH_ENTRY(CKM_MD2_HMAC),
    MECH_ENTRY(CKM_MD2_HMAC_GENERAL),
    MECH_ENTRY(CKM_MD5),
    MECH_ENTRY(CKM_MD5_HMAC),
    MECH_ENTRY(CKM_MD5_HMAC_GENERAL),
    MECH_ENTRY(CKM_SHA_1),
    MECH_ENTRY(CKM_SHA_1_HMAC),
    MECH_ENTRY(CKM_SHA_1_HMAC_GENERAL),
    MECH_ENTRY(CKM_RIPEMD128),
    MECH_ENTRY(CKM_RIPEMD128_HMAC),
    MECH_ENTRY(CKM_RIPEMD128_HMAC_GENERAL),
    MECH_ENTRY(CKM_RIPEMD160),
    MECH_ENTRY(CKM_RIPEMD160_HMAC),
    MECH_ENTRY(CKM_RIPEMD160_HMAC_GENERAL),
    MECH_ENTRY(CKM_SHA256),
    MECH_ENTRY(CKM_SHA256_HMAC),
    MECH_ENTRY(CKM_SHA256_HMAC_GENERAL),
    MECH_ENTRY(CKM_SHA224),
    MECH_ENTRY(CKM_SHA224_HMAC),
    MECH_ENTRY(CKM_SHA224_HMAC_GENERAL),
    MECH_ENTRY(CKM_SHA384),
    MECH_ENTRY(CKM_SHA384_HMAC),
    MECH_ENTRY(CKM_SHA384_HMAC_GENERAL),
    MECH_ENTRY(CKM_SHA512),
    MECH_ENTRY(CKM_SHA512_HMAC),
    MECH_ENTRY(CKM_SHA512_HMAC_GENERAL),
    MECH_ENTRY(CKM_SECURID_KEY_GEN),
    MECH_ENTRY(CKM_SECURID),
    MECH_ENTRY(CKM_HOTP_KEY_GEN),
    MECH_ENTRY(CKM_HOTP),
    MECH_ENTRY(CKM_ACTI),
    MECH_ENTRY(CKM_ACTI_KEY_GEN),
    MECH_ENTRY(CKM_SHA3_256),
    MECH_ENTRY(CKM_SHA3_256_HMAC),
    MECH_ENTRY(CKM_SHA3_256_HMAC_GENERAL),
    MECH_ENTRY(CKM_SHA3_256_KEY_GEN),
    MECH_ENTRY(CKM_SHA3_224),
    MECH_ENTRY(CKM_SHA3_224_HMAC),
    MECH_ENTRY(CKM_SHA3_224_HMAC_GENERAL),
    MECH_ENTRY(CKM_SHA3_224_KEY_GEN),
    MECH_ENTRY(CKM_SHA3_384),
    MECH_ENTRY(CKM_SHA3_384_HMAC),
    MECH_ENTRY(CKM_SHA3_384_HMAC_GENERAL),
    MECH_ENTRY(CKM_SHA3_384_KEY_GEN),
    MECH_ENTRY(CKM_SHA3_512),
    MECH_ENTRY(CKM_SHA3_512_HMAC),
    MECH_ENTRY(CKM_SHA3_512_HMAC_GENERAL),
    MECH_ENTRY(CKM_SHA3_512_KEY_GEN),
    MECH_ENTRY(CKM_CAST_KEY_GEN),
    MECH_ENTRY(CKM_CAST_ECB),
    MECH_ENTRY(CKM_CAST_CBC),
    MECH_ENTRY(CKM_CAST_MAC),
    MECH_ENTRY(CKM_CAST_MAC_GENERAL),
    MECH_ENTRY(CKM_CAST_CBC_PAD),
    MECH_ENTRY(CKM_CAST3_KEY_GEN),
    MECH_ENTRY(CKM_CAST3_ECB),
    MECH_ENTRY(CKM_CAST3_CBC),
    MECH_ENTRY(CKM_CAST3_MAC),
    MECH_ENTRY(CKM_CAST3_MAC_GENERAL),
    MECH_ENTRY(CKM_CAST3_CBC_PAD),
    MECH_ENTRY(CKM_CAST128_KEY_GEN),
    MECH_ENTRY(CKM_CAST128_ECB),
    MECH_ENTRY(CKM_CAST128_CBC),
    MECH_ENTRY(CKM_CAST128_MAC),
    MECH_ENTRY(CKM_CAST128_MAC_GENERAL),
    MECH_ENTRY(CKM_CAST128_CBC_PAD),
    MECH_ENTRY(CKM_RC5_KEY_GEN),
    MECH_ENTRY(CKM_RC5_ECB),
    MECH_ENTRY(CKM_RC5_CBC),
    MECH_ENTRY(CKM_RC5_MAC),
    MECH_ENTRY(CKM_RC5_MAC_GENERAL),
    MECH_ENTRY(CKM_RC5_CBC_PAD),
    MECH_ENTRY(CKM_IDEA_KEY_GEN),
    MECH_ENTRY(CKM_IDEA_ECB),
    MECH_ENTRY(CKM_IDEA_CBC),
    MECH_ENTRY(CKM_IDEA_MAC),
    MECH_ENTRY(CKM_IDEA_MAC_GENERAL),
    MECH_ENTRY(CKM_IDEA_CBC_PAD),
    MECH_ENTRY(CKM_GENERIC_SECRET_KEY_GEN),
    MECH_ENTRY(CKM_CONCATENATE_BASE_AND_KEY),
    MECH_ENTRY(CKM_CONCATENATE_BASE_AND_DATA),
    MECH_ENTRY(CKM_CONCATENATE_DATA_AND_BASE),
    MECH_ENTRY(CKM_XOR_BASE_AND_DATA),
    MECH_ENTRY(CKM_EXTRACT_KEY_FROM_KEY),
    MECH_ENTRY(CKM_SSL3_PRE_MASTER_KEY_GEN),
    MECH_ENTRY(CKM_SSL3_MASTER_KEY_DERIVE),
    MECH_ENTRY(CKM_SSL3_KEY_AND_MAC_DERIVE),
    MECH_ENTRY(CKM_SSL3_MASTER_KEY_DERIVE_DH),
    MECH_ENTRY(CKM_TLS_PRE_MASTER_KEY_GEN),
    MECH_ENTRY(CKM_TLS_MASTER_KEY_DERIVE),
    MECH_ENTRY(CKM_TLS_KEY_AND_MAC_DERIVE),
    MECH_ENTRY(CKM_TLS_MASTER_KEY_DERIVE_DH),
    MECH_ENTRY(CKM_TLS_PRF),
    MECH_ENTRY(CKM_SSL3_MD5_MAC),
    MECH_ENTRY(CKM_SSL3_SHA1_MAC),
    MECH_ENTRY(CKM_MD5_KEY_DERIVATION),
    MECH_ENTRY(CKM_MD2_KEY_DERIVATION),
    MECH_ENTRY(CKM_SHA1_KEY_DERIVATION),
    MECH_ENTRY(CKM_SHA256_KEY_DERIVATION),
    MECH_ENTRY(CKM_SHA384_KEY_DERIVATION),
    MECH_ENTRY(CKM_SHA512_KEY_DERIVATION),
    MECH_ENTRY(CKM_SHA224_KEY_DERIVATION),
    MECH_ENTRY(CKM_SHA3_256_KEY_DERIVATION),
    MECH_ENTRY(CKM_SHA3_224_KEY_DERIVATION),
    MECH_ENTRY(CKM_SHA3_384_KEY_DERIVATION),
    MECH_ENTRY(CKM_SHA3_512_KEY_DERIVATION),
    MECH_ENTRY(CKM_SHAKE_128_KEY_DERIVATION),
    MECH_ENTRY(CKM_SHAKE_256_KEY_DERIVATION),
    MECH_ENTRY(CKM_PBE_MD2_DES_CBC),
    MECH_ENTRY(CKM_PBE_MD5_DES_CBC),
    MECH_ENTRY(CKM_PBE_MD5_CAST_CBC),
    MECH_ENTRY(CKM_PBE_MD5_CAST3_CBC),
    MECH_ENTRY(CKM_PBE_MD5_CAST128_CBC),
    MECH_ENTRY(CKM_PBE_SHA1_CAST128_CBC),
    MECH_ENTRY(CKM_PBE_SHA1_RC4_128),
    MECH_ENTRY(CKM_PBE_SHA1_RC4_40),
    MECH_ENTRY(CKM_PBE_SHA1_DES3_EDE_CBC),
    MECH_ENTRY(CKM_PBE_SHA1_DES2_EDE_CBC),
    MECH_ENTRY(CKM_PBE_SHA1_RC2_128_CBC),
    MECH_ENTRY(CKM_PBE_SHA1_RC2_40_CBC),
    MECH_ENTRY(CKM_PKCS5_PBKD2),
    MECH_ENTRY(CKM_PBA_SHA1_WITH_SHA1_HMAC),
    MECH_ENTRY(CKM_WTLS_PRE_MASTER_KEY_GEN),
    MECH_ENTRY(CKM_WTLS_MASTER_KEY_DERIVE),
    MECH_ENTRY(CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC),
    MECH_ENTRY(CKM_WTLS_PRF),
    MECH_ENTRY(CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE),
    MECH_ENTRY(CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE),
    MECH_ENTRY(CKM_TLS12_MAC),
    MECH_ENTRY(CKM_TLS12_KDF),
    MECH_ENTRY(CKM_TLS12_MASTER_KEY_DERIVE),
    MECH_ENTRY(CKM_TLS12_KEY_AND_MAC_DERIVE),
    MECH_ENTRY(CKM_TLS12_MASTER_KEY_DERIVE_DH),
    MECH_ENTRY(CKM_TLS12_KEY_SAFE_DERIVE),
    MECH_ENTRY(CKM_TLS_MAC),
    MECH_ENTRY(CKM_TLS_KDF),
    MECH_ENTRY(CKM_KEY_WRAP_LYNKS),
    MECH_ENTRY(CKM_KEY_WRAP_SET_OAEP),
    MECH_ENTRY(CKM_CMS_SIG),
    MECH_ENTRY(CKM_KIP_DERIVE),
    MECH_ENTRY(CKM_KIP_WRAP),
    MECH_ENTRY(CKM_KIP_MAC),
    MECH_ENTRY(CKM_CAMELLIA_KEY_GEN),
    MECH_ENTRY(CKM_CAMELLIA_ECB),
    MECH_ENTRY(CKM_CAMELLIA_CBC),
    MECH_ENTRY(CKM_CAMELLIA_MAC),
    MECH_ENTRY(CKM_CAMELLIA_MAC_GENERAL),
    MECH_ENTRY(CKM_CAMELLIA_CBC_PAD),
    MECH_ENTRY(CKM_CAMELLIA_ECB_ENCRYPT_DATA),
    MECH_ENTRY(CKM_CAMELLIA_CBC_ENCRYPT_DATA),
    MECH_ENTRY(CKM_CAMELLIA_CTR),
    MECH_ENTRY(CKM_ARIA_KEY_GEN),
    MECH_ENTRY(CKM_ARIA_ECB),
    MECH_ENTRY(CKM_ARIA_CBC),
    MECH_ENTRY(CKM_ARIA_MAC),
    MECH_ENTRY(CKM_ARIA_MAC_GENERAL),
    MECH_ENTRY(CKM_ARIA_CBC_PAD),
    MECH_ENTRY(CKM_ARIA_ECB_ENCRYPT_DATA),
    MECH_ENTRY(CKM_ARIA_CBC_ENCRYPT_DATA),
    MECH_ENTRY(CKM_SEED_KEY_GEN),
    MECH_ENTRY(CKM_SEED_ECB),
    MECH_ENTRY(CKM_SEED_CBC),
    MECH_ENTRY(CKM_SEED_MAC),
    MECH_ENTRY(CKM_SEED_MAC_GENERAL),
    MECH_ENTRY(CKM_SEED_CBC_PAD),
    MECH_ENTRY(CKM_SEED_ECB_ENCRYPT_DATA),
    MECH_ENTRY(CKM_SEED_CBC_ENCRYPT_DATA),
    MECH_ENTRY(CKM_SKIPJACK_KEY_GEN),
    MECH_ENTRY(CKM_SKIPJACK_ECB64),
    MECH_ENTRY(CKM_SKIPJACK_CBC64),
    MECH_ENTRY(CKM_SKIPJACK_OFB64),
    MECH_ENTRY(CKM_SKIPJACK_CFB64),
    MECH_ENTRY(CKM_SKIPJACK_CFB32),
    MECH_ENTRY(CKM_SKIPJACK_CFB16),
    MECH_ENTRY(CKM_SKIPJACK_CFB8),
    MECH_ENTRY(CKM_SKIPJACK_WRAP),
    MECH_ENTRY(CKM_SKIPJACK_PRIVATE_WRAP),
    MECH_ENTRY(CKM_SKIPJACK_RELAYX),
    MECH_ENTRY(CKM_KEA_KEY_PAIR_GEN),
    MECH_ENTRY(CKM_KEA_KEY_DERIVE),
    MECH_ENTRY(CKM_KEA_DERIVE),
    MECH_ENTRY(CKM_FORTEZZA_TIMESTAMP),
    MECH_ENTRY(CKM_BATON_KEY_GEN),
    MECH_ENTRY(CKM_BATON_ECB128),
    MECH_ENTRY(CKM_BATON_ECB96),
    MECH_ENTRY(CKM_BATON_CBC128),
    MECH_ENTRY(CKM_BATON_COUNTER),
    MECH_ENTRY(CKM_BATON_SHUFFLE),
    MECH_ENTRY(CKM_BATON_WRAP),
    MECH_ENTRY(CKM_EC_KEY_PAIR_GEN),
    MECH_ENTRY(CKM_ECDSA),
    MECH_ENTRY(CKM_ECDSA_SHA1),
    MECH_ENTRY(CKM_ECDSA_SHA224),
    MECH_ENTRY(CKM_ECDSA_SHA256),
    MECH_ENTRY(CKM_ECDSA_SHA384),
    MECH_ENTRY(CKM_ECDSA_SHA512),
    MECH_ENTRY(CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS),
    MECH_ENTRY(CKM_ECDH1_DERIVE),
    MECH_ENTRY(CKM_ECDH1_COFACTOR_DERIVE),
    MECH_ENTRY(CKM_ECMQV_DERIVE),
    MECH_ENTRY(CKM_ECDH_AES_KEY_WRAP),
    MECH_ENTRY(CKM_RSA_AES_KEY_WRAP),
    MECH_ENTRY(CKM_JUNIPER_KEY_GEN),
    MECH_ENTRY(CKM_JUNIPER_ECB128),
    MECH_ENTRY(CKM_JUNIPER_CBC128),
    MECH_ENTRY(CKM_JUNIPER_COUNTER),
    MECH_ENTRY(CKM_JUNIPER_SHUFFLE),
    MECH_ENTRY(CKM_JUNIPER_WRAP),
    MECH_ENTRY(CKM_FASTHASH),
    MECH_ENTRY(CKM_AES_XTS),
    MECH_ENTRY(CKM_AES_XTS_KEY_GEN),
    MECH_ENTRY(CKM_AES_KEY_GEN),
    MECH_ENTRY(CKM_AES_ECB),
    MECH_ENTRY(CKM_AES_CBC),
    MECH_ENTRY(CKM_AES_MAC),
    MECH_ENTRY(CKM_AES_MAC_GENERAL),
    MECH_ENTRY(CKM_AES_CBC_PAD),
    MECH_ENTRY(CKM_AES_CTR),
    MECH_ENTRY(CKM_AES_GCM),
    MECH_ENTRY(CKM_AES_CCM),
    MECH_ENTRY(CKM_AES_CTS),
    MECH_ENTRY(CKM_AES_CMAC),
    MECH_ENTRY(CKM_AES_CMAC_GENERAL),
    MECH_ENTRY(CKM_AES_XCBC_MAC),
    MECH_ENTRY(CKM_AES_XCBC_MAC_96),
    MECH_ENTRY(CKM_AES_GMAC),
    MECH_ENTRY(CKM_BLOWFISH_KEY_GEN),
    MECH_ENTRY(CKM_BLOWFISH_CBC),
    MECH_ENTRY(CKM_TWOFISH_KEY_GEN),
    MECH_ENTRY(CKM_TWOFISH_CBC),
    MECH_ENTRY(CKM_BLOWFISH_CBC_PAD),
    MECH_ENTRY(CKM_TWOFISH_CBC_PAD),
    MECH_ENTRY(CKM_DES_ECB_ENCRYPT_DATA),
    MECH_ENTRY(CKM_DES_CBC_ENCRYPT_DATA),
    MECH_ENTRY(CKM_DES3_ECB_ENCRYPT_DATA),
    MECH_ENTRY(CKM_DES3_CBC_ENCRYPT_DATA),
    MECH_ENTRY(CKM_AES_ECB_ENCRYPT_DATA),
    MECH_ENTRY(CKM_AES_CBC_ENCRYPT_DATA),
    MECH_ENTRY(CKM_GOSTR3410_KEY_PAIR_GEN),
    MECH_ENTRY(CKM_GOSTR3410),
    MECH_ENTRY(CKM_GOSTR3410_WITH_GOSTR3411),
    MECH_ENTRY(CKM_GOSTR3410_KEY_WRAP),
    MECH_ENTRY(CKM_GOSTR3410_DERIVE),
    MECH_ENTRY(CKM_GOSTR3411),
    MECH_ENTRY(CKM_GOSTR3411_HMAC),
    MECH_ENTRY(CKM_GOST28147_KEY_GEN),
    MECH_ENTRY(CKM_GOST28147_ECB),
    MECH_ENTRY(CKM_GOST28147),
    MECH_ENTRY(CKM_GOST28147_MAC),
    MECH_ENTRY(CKM_GOST28147_KEY_WRAP),
    MECH_ENTRY(CKM_CHACHA20_KEY_GEN),
    MECH_ENTRY(CKM_CHACHA20),
    MECH_ENTRY(CKM_POLY1305_KEY_GEN),
    MECH_ENTRY(CKM_POLY1305),
    MECH_ENTRY(CKM_DSA_PARAMETER_GEN),
    MECH_ENTRY(CKM_DH_PKCS_PARAMETER_GEN),
    MECH_ENTRY(CKM_X9_42_DH_PARAMETER_GEN),
    MECH_ENTRY(CKM_DSA_PROBABILISTIC_PARAMETER_GEN),
    MECH_ENTRY(CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN),
    MECH_ENTRY(CKM_DSA_FIPS_G_GEN),
    MECH_ENTRY(CKM_AES_OFB),
    MECH_ENTRY(CKM_AES_CFB64),
    MECH_ENTRY(CKM_AES_CFB8),
    MECH_ENTRY(CKM_AES_CFB128),
    MECH_ENTRY(CKM_AES_CFB1),
    MECH_ENTRY(CKM_AES_KEY_WRAP),
    MECH_ENTRY(CKM_AES_KEY_WRAP_PAD),
    MECH_ENTRY(CKM_AES_KEY_WRAP_KWP),
    MECH_ENTRY(CKM_RSA_PKCS_TPM_1_1),
    MECH_ENTRY(CKM_RSA_PKCS_OAEP_TPM_1_1),
    MECH_ENTRY(CKM_SHA_1_KEY_GEN),
    MECH_ENTRY(CKM_SHA224_KEY_GEN),
    MECH_ENTRY(CKM_SHA256_KEY_GEN),
    MECH_ENTRY(CKM_SHA384_KEY_GEN),
    MECH_ENTRY(CKM_SHA512_KEY_GEN),
    MECH_ENTRY(CKM_SHA512_224_KEY_GEN),
    MECH_ENTRY(CKM_SHA512_256_KEY_GEN),
    MECH_ENTRY(CKM_SHA512_T_KEY_GEN),
    MECH_ENTRY(CKM_NULL),
    MECH_ENTRY(CKM_BLAKE2B_160),
    MECH_ENTRY(CKM_BLAKE2B_160_HMAC),
    MECH_ENTRY(CKM_BLAKE2B_160_HMAC_GENERAL),
    MECH_ENTRY(CKM_BLAKE2B_160_KEY_DERIVE),
    MECH_ENTRY(CKM_BLAKE2B_160_KEY_GEN),
    MECH_ENTRY(CKM_BLAKE2B_256),
    MECH_ENTRY(CKM_BLAKE2B_256_HMAC),
    MECH_ENTRY(CKM_BLAKE2B_256_HMAC_GENERAL),
    MECH_ENTRY(CKM_BLAKE2B_256_KEY_DERIVE),
    MECH_ENTRY(CKM_BLAKE2B_256_KEY_GEN),
    MECH_ENTRY(CKM_BLAKE2B_384),
    MECH_ENTRY(CKM_BLAKE2B_384_HMAC),
    MECH_ENTRY(CKM_BLAKE2B_384_HMAC_GENERAL),
    MECH_ENTRY(CKM_BLAKE2B_384_KEY_DERIVE),
    MECH_ENTRY(CKM_BLAKE2B_384_KEY_GEN),
    MECH_ENTRY(CKM_BLAKE2B_512),
    MECH_ENTRY(CKM_BLAKE2B_512_HMAC),
    MECH_ENTRY(CKM_BLAKE2B_512_HMAC_GENERAL),
    MECH_ENTRY(CKM_BLAKE2B_512_KEY_DERIVE),
    MECH_ENTRY(CKM_BLAKE2B_512_KEY_GEN),
    MECH_ENTRY(CKM_SALSA20),
    MECH_ENTRY(CKM_CHACHA20_POLY1305),
    MECH_ENTRY(CKM_SALSA20_POLY1305),
    MECH_ENTRY(CKM_X3DH_INITIALIZE),
    MECH_ENTRY(CKM_X3DH_RESPOND),
    MECH_ENTRY(CKM_X2RATCHET_INITIALIZE),
    MECH_ENTRY(CKM_X2RATCHET_RESPOND),
    MECH_ENTRY(CKM_X2RATCHET_ENCRYPT),
    MECH_ENTRY(CKM_X2RATCHET_DECRYPT),
    MECH_ENTRY(CKM_XEDDSA),
    MECH_ENTRY(CKM_HKDF_DERIVE),
    MECH_ENTRY(CKM_HKDF_DATA),
    MECH_ENTRY(CKM_HKDF_KEY_GEN),
    MECH_ENTRY(CKM_SALSA20_KEY_GEN),
    MECH_ENTRY(CKM_ECDSA_SHA3_224),
    MECH_ENTRY(CKM_ECDSA_SHA3_256),
    MECH_ENTRY(CKM_ECDSA_SHA3_384),
    MECH_ENTRY(CKM_ECDSA_SHA3_512),
    MECH_ENTRY(CKM_EC_EDWARDS_KEY_PAIR_GEN),
    MECH_ENTRY(CKM_EC_MONTGOMERY_KEY_PAIR_GEN),
    MECH_ENTRY(CKM_EDDSA),
    MECH_ENTRY(CKM_SP800_108_COUNTER_KDF),
    MECH_ENTRY(CKM_SP800_108_FEEDBACK_KDF),
    MECH_ENTRY(CKM_SP800_108_DOUBLE_PIPELINE_KDF),
    { 0, NULL },
};

struct ckmap mechanism_flags[] = {
    MECH_ENTRY(CKF_HW),
    MECH_ENTRY(CKF_MESSAGE_ENCRYPT),
    MECH_ENTRY(CKF_MESSAGE_DECRYPT),
    MECH_ENTRY(CKF_MESSAGE_SIGN),
    MECH_ENTRY(CKF_MESSAGE_VERIFY),
    MECH_ENTRY(CKF_MULTI_MESSAGE),
    MECH_ENTRY(CKF_FIND_OBJECTS),
    MECH_ENTRY(CKF_ENCRYPT),
    MECH_ENTRY(CKF_DECRYPT),
    MECH_ENTRY(CKF_DIGEST),
    MECH_ENTRY(CKF_SIGN),
    MECH_ENTRY(CKF_SIGN_RECOVER),
    MECH_ENTRY(CKF_VERIFY),
    MECH_ENTRY(CKF_VERIFY_RECOVER),
    MECH_ENTRY(CKF_GENERATE),
    MECH_ENTRY(CKF_GENERATE_KEY_PAIR),
    MECH_ENTRY(CKF_WRAP),
    MECH_ENTRY(CKF_UNWRAP),
    MECH_ENTRY(CKF_DERIVE),
    MECH_ENTRY(CKF_EC_F_P),
    MECH_ENTRY(CKF_EC_F_2M),
    MECH_ENTRY(CKF_EC_ECPARAMETERS),
    MECH_ENTRY(CKF_EC_OID),
    MECH_ENTRY(CKF_EC_UNCOMPRESS),
    MECH_ENTRY(CKF_EC_COMPRESS),
    MECH_ENTRY(CKF_EC_CURVENAME),
    { 0, NULL },
};

struct ckmap token_flags[] = {
    MECH_ENTRY(CKF_RNG),
    MECH_ENTRY(CKF_WRITE_PROTECTED),
    MECH_ENTRY(CKF_LOGIN_REQUIRED),
    MECH_ENTRY(CKF_USER_PIN_INITIALIZED),
    MECH_ENTRY(CKF_RESTORE_KEY_NOT_NEEDED),
    MECH_ENTRY(CKF_CLOCK_ON_TOKEN),
    MECH_ENTRY(CKF_PROTECTED_AUTHENTICATION_PATH),
    MECH_ENTRY(CKF_DUAL_CRYPTO_OPERATIONS),
    MECH_ENTRY(CKF_TOKEN_INITIALIZED),
    MECH_ENTRY(CKF_SECONDARY_AUTHENTICATION),
    MECH_ENTRY(CKF_USER_PIN_COUNT_LOW),
    MECH_ENTRY(CKF_USER_PIN_FINAL_TRY),
    MECH_ENTRY(CKF_USER_PIN_LOCKED),
    MECH_ENTRY(CKF_USER_PIN_TO_BE_CHANGED),
    MECH_ENTRY(CKF_SO_PIN_COUNT_LOW),
    MECH_ENTRY(CKF_SO_PIN_FINAL_TRY),
    MECH_ENTRY(CKF_SO_PIN_LOCKED),
    MECH_ENTRY(CKF_SO_PIN_TO_BE_CHANGED),
    MECH_ENTRY(CKF_ERROR_STATE),
    { 0, NULL },
};

struct ckmap slot_flags[] = {
    MECH_ENTRY(CKF_TOKEN_PRESENT),
    MECH_ENTRY(CKF_REMOVABLE_DEVICE),
    MECH_ENTRY(CKF_HW_SLOT),
    { 0, NULL },
};

struct ckmap profile_ids[] = {
    MECH_ENTRY(CKP_INVALID_ID),
    MECH_ENTRY(CKP_BASELINE_PROVIDER),
    MECH_ENTRY(CKP_EXTENDED_PROVIDER),
    MECH_ENTRY(CKP_AUTHENTICATION_TOKEN),
    MECH_ENTRY(CKP_PUBLIC_CERTIFICATES_TOKEN),
    MECH_ENTRY(CKP_VENDOR_DEFINED),
    { 0, NULL },
};
