/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _UTIL_H
#define _UTIL_H

/* Utilities to fetch objects from tokens */
struct fetch_attrs {
    CK_ATTRIBUTE_TYPE type;
    CK_BYTE **value_ptr;
    CK_ULONG *value_len_ptr;
    bool allocate;
    bool required;

    /* auxiliary members to make life easier */
    CK_BYTE *value;
    CK_ULONG value_len;
};
#define FA_SET_BUF_VAL(x, n, _t, _v, _l, _a, _r) \
    do { \
        x[n].type = _t; \
        x[n].value_ptr = (CK_BYTE_PTR *)&_v; \
        x[n].value_len_ptr = &_l; \
        x[n].allocate = _a; \
        x[n].required = _r; \
        x[n].value = NULL; \
        x[n].value_len = 0; \
        n++; \
    } while (0)

#define FA_SET_BUF_ALLOC(x, n, _t, _r) \
    do { \
        x[n].type = _t; \
        x[n].value = NULL; \
        x[n].value_len = 0; \
        x[n].value_ptr = &x[n].value; \
        x[n].value_len_ptr = &x[n].value_len; \
        x[n].allocate = true; \
        x[n].required = _r; \
        n++; \
    } while (0)

#define FA_SET_VAR_VAL(x, n, _t, _v, _r) \
    do { \
        x[n].type = _t; \
        x[n].value = (CK_BYTE *)&_v; \
        x[n].value_len = sizeof(_v); \
        x[n].value_ptr = &x[n].value; \
        x[n].value_len_ptr = &x[n].value_len; \
        x[n].allocate = false; \
        x[n].required = _r; \
        n++; \
    } while (0)

#define FA_GET_VAL(x, n) *x[n].value_ptr
#define FA_GET_LEN(x, n) *x[n].value_len_ptr

#define CKATTR_ASSIGN(x, _a, _b, _c) \
    do { \
        x.type = (_a); \
        x.pValue = (void *)(_b); \
        x.ulValueLen = (_c); \
    } while (0)

#define CKATTR_SET(x, y) \
    do { \
        x.type = y.type; \
        x.pValue = *y.value_ptr; \
        x.ulValueLen = *y.value_len_ptr; \
    } while (0)

#define CKATTR_MOVE(x, y) \
    do { \
        x.type = y.type; \
        x.pValue = *y.value_ptr; \
        x.ulValueLen = *y.value_len_ptr; \
        *y.value_ptr = NULL; \
        *y.value_len_ptr = 0; \
    } while (0)

CK_RV p11prov_fetch_attributes(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                               CK_OBJECT_HANDLE object,
                               struct fetch_attrs *attrs,
                               unsigned long attrnums);
void p11prov_move_alloc_attrs(struct fetch_attrs *attrs, int num,
                              CK_ATTRIBUTE *ck_attrs, int *retnum);
void p11prov_fetch_attrs_free(struct fetch_attrs *attrs, int num);

#define MAX_PIN_LENGTH 32
P11PROV_URI *p11prov_parse_uri(P11PROV_CTX *ctx, const char *uri);
void p11prov_uri_free(P11PROV_URI *parsed_uri);
CK_OBJECT_CLASS p11prov_uri_get_class(P11PROV_URI *uri);
CK_ATTRIBUTE p11prov_uri_get_id(P11PROV_URI *uri);
CK_ATTRIBUTE p11prov_uri_get_label(P11PROV_URI *uri);
char *p11prov_uri_get_serial(P11PROV_URI *uri);
char *p11prov_uri_get_pin(P11PROV_URI *uri);
CK_RV p11prov_uri_match_token(P11PROV_URI *uri, CK_TOKEN_INFO *token);
int p11prov_get_pin(const char *in, char **out);
bool cyclewait_with_timeout(uint64_t max_wait, uint64_t interval,
                            uint64_t *start_time);
#define GET_ATTR 0
#define SET_ATTR 1
CK_RV p11prov_token_sup_attr(P11PROV_CTX *ctx, CK_SLOT_ID id, int action,
                             CK_ATTRIBUTE_TYPE attr, CK_BBOOL *data);
CK_RV p11prov_copy_attr(CK_ATTRIBUTE *dst, CK_ATTRIBUTE *src);
bool p11prov_x509_names_are_equal(CK_ATTRIBUTE *a, CK_ATTRIBUTE *b);
char *p11prov_alloc_sprintf(int size_hint, const char *format, ...);

#endif /* _UTIL_H */
