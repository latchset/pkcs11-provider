/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _UTIL_H
#define _UTIL_H

#define CKATTR_ASSIGN(x, _a, _b, _c) \
    do { \
        x.type = (_a); \
        x.pValue = (void *)(_b); \
        x.ulValueLen = (_c); \
    } while (0)

/* Utilities to fetch objects from tokens */
struct fetch_attrs {
    CK_ATTRIBUTE attr;
    bool allocate;
    bool required;
};
#define FA_SET_BUF_VAL(x, n, _t, _v, _l, _r) \
    do { \
        CKATTR_ASSIGN(x[n].attr, _t, _v, _l); \
        x[n].allocate = false; \
        x[n].required = _r; \
        n++; \
    } while (0)

#define FA_SET_BUF_ALLOC(x, n, _t, _r) \
    do { \
        CKATTR_ASSIGN(x[n].attr, _t, NULL, 0); \
        x[n].allocate = true; \
        x[n].required = _r; \
        n++; \
    } while (0)

#define FA_SET_VAR_VAL(x, n, _t, _v, _r) \
    do { \
        CKATTR_ASSIGN(x[n].attr, _t, (CK_BYTE *)&(_v), sizeof(_v)); \
        x[n].allocate = false; \
        x[n].required = _r; \
        n++; \
    } while (0)

#define FA_GET_LEN(x, n, _l) (_l) = x[n].attr.ulValueLen

CK_RV p11prov_fetch_attributes(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                               CK_OBJECT_HANDLE object,
                               struct fetch_attrs *attrs,
                               unsigned long attrnums);
void p11prov_move_alloc_attrs(struct fetch_attrs *attrs, int num,
                              CK_ATTRIBUTE *ck_attrs, int *retnum);
void p11prov_fetch_attrs_free(struct fetch_attrs *attrs, int num);

#define MAX_PIN_LENGTH 32
int parse_ulong(P11PROV_CTX *ctx, const char *str, size_t len, void **output);
P11PROV_URI *p11prov_parse_uri(P11PROV_CTX *ctx, const char *uri);
char *p11prov_key_to_uri(P11PROV_CTX *ctx, P11PROV_OBJ *key);
void p11prov_uri_free(P11PROV_URI *parsed_uri);
CK_OBJECT_CLASS p11prov_uri_get_class(P11PROV_URI *uri);
void p11prov_uri_set_class(P11PROV_URI *uri, CK_OBJECT_CLASS class);
CK_ATTRIBUTE p11prov_uri_get_id(P11PROV_URI *uri);
CK_RV p11prov_uri_set_id(P11PROV_URI *uri, CK_ATTRIBUTE *id);
CK_ATTRIBUTE p11prov_uri_get_label(P11PROV_URI *uri);
CK_RV p11prov_uri_set_label(P11PROV_URI *uri, CK_ATTRIBUTE *label);
char *p11prov_uri_get_serial(P11PROV_URI *uri);
char *p11prov_uri_get_pin(P11PROV_URI *uri);
CK_SLOT_ID p11prov_uri_get_slot_id(P11PROV_URI *uri);
void p11prov_uri_set_slot_id(P11PROV_URI *uri, CK_SLOT_ID slot_id);
P11PROV_URI *p11prov_copy_uri(P11PROV_URI *uri);
CK_RV p11prov_uri_match_token(P11PROV_URI *uri, CK_SLOT_ID slot_id,
                              CK_SLOT_INFO *slot, CK_TOKEN_INFO *token);
int p11prov_get_pin(P11PROV_CTX *ctx, const char *in, char **out);
bool cyclewait_with_timeout(uint64_t max_wait, uint64_t interval,
                            uint64_t *start_time);
CK_RV p11prov_copy_attr(CK_ATTRIBUTE *dst, CK_ATTRIBUTE *src);
bool p11prov_x509_names_are_equal(CK_ATTRIBUTE *a, CK_ATTRIBUTE *b);
char *p11prov_alloc_sprintf(int size_hint, const char *format, ...);

void trim_padded_field(CK_UTF8CHAR *field, ssize_t n);
#define trim(x) trim_padded_field(x, sizeof(x))

CK_RV p11prov_mutex_init(P11PROV_CTX *provctx, pthread_mutex_t *lock,
                         const char *obj, const char *file, int line,
                         const char *func);
CK_RV p11prov_mutex_lock(P11PROV_CTX *provctx, pthread_mutex_t *lock,
                         const char *obj, const char *file, int line,
                         const char *func);
CK_RV p11prov_mutex_unlock(P11PROV_CTX *provctx, pthread_mutex_t *lock,
                           const char *obj, const char *file, int line,
                           const char *func);
CK_RV p11prov_mutex_destroy(P11PROV_CTX *provctx, pthread_mutex_t *lock,
                            const char *obj, const char *file, int line,
                            const char *func);
#define MUTEX_INIT(obj) \
    p11prov_mutex_init((obj)->provctx, &(obj)->lock, #obj, OPENSSL_FILE, \
                       OPENSSL_LINE, OPENSSL_FUNC)
#define MUTEX_LOCK(obj) \
    p11prov_mutex_lock((obj)->provctx, &(obj)->lock, #obj, OPENSSL_FILE, \
                       OPENSSL_LINE, OPENSSL_FUNC)
#define MUTEX_UNLOCK(obj) \
    p11prov_mutex_unlock((obj)->provctx, &(obj)->lock, #obj, OPENSSL_FILE, \
                         OPENSSL_LINE, OPENSSL_FUNC)
#define MUTEX_DESTROY(obj) \
    p11prov_mutex_destroy((obj)->provctx, &(obj)->lock, #obj, OPENSSL_FILE, \
                          OPENSSL_LINE, OPENSSL_FUNC)

void p11prov_force_rwlock_reinit(pthread_rwlock_t *lock);

static inline CK_ULONG constant_equal(CK_ULONG a, CK_ULONG b)
{
    return ((a ^ b) - 1U) >> (sizeof(CK_ULONG) * 8 - 1);
}

static inline int constant_select_int(CK_ULONG cond, int a, int b)
{
    volatile unsigned int A = (unsigned int)a;
    volatile unsigned int B = (unsigned int)b;
    volatile unsigned int mask = -(unsigned int)cond;

    return (int)((A & mask) | (B & ~mask));
}

static inline void constant_select_buf(CK_ULONG cond, CK_ULONG size,
                                       unsigned char *dst, unsigned char *a,
                                       unsigned char *b)
{
    for (int i = 0; i < size; i++) {
        volatile unsigned char A = a[i];
        volatile unsigned char B = b[i];
        volatile unsigned char mask = -(unsigned char)cond;
        dst[i] = ((A & mask) | (B & ~mask));
    }
}

struct data_buffer {
    uint8_t *data;
    size_t length;
};
typedef struct data_buffer data_buffer;

CK_RV p11prov_digest_util(P11PROV_CTX *provctx, const char *digest,
                          const char *properties, data_buffer data[],
                          data_buffer *output);

#endif /* _UTIL_H */
