/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "platform/endian.h"
#include <openssl/bn.h>
#include <openssl/x509.h>

CK_RV p11prov_fetch_attributes(P11PROV_CTX *ctx, P11PROV_SESSION *session,
                               CK_OBJECT_HANDLE object,
                               struct fetch_attrs *attrs,
                               unsigned long attrnums)
{
    CK_SESSION_HANDLE sess = p11prov_session_handle(session);
    CK_ATTRIBUTE q[attrnums];
    CK_ATTRIBUTE r[attrnums];
    CK_RV ret;

    for (size_t i = 0; i < attrnums; i++) {
        q[i] = attrs[i].attr;
    }

    /* try one shot, then fallback to individual calls if that fails */
    ret = p11prov_GetAttributeValue(ctx, sess, object, q, attrnums);
    if (ret == CKR_OK) {
        unsigned long retrnums = 0;
        for (size_t i = 0; i < attrnums; i++) {
            if (q[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                /* This can't happen according to the algorithm described
                 * in the spec when the call returns CKR_OK. */
                return CKR_GENERAL_ERROR;
            }
            if (attrs[i].allocate) {
                /* always allocate one more, so that zero terminated strings
                 * work automatically */
                q[i].pValue = OPENSSL_zalloc(q[i].ulValueLen + 1);
                if (!q[i].pValue) {
                    return CKR_HOST_MEMORY;
                }
                /* add to re-request list */
                r[retrnums] = q[i];
                retrnums++;
            }
            /* always return data to caller so memory can be properly freed if
             * necessary */
            attrs[i].attr = q[i];
        }
        if (retrnums > 0) {
            ret = p11prov_GetAttributeValue(ctx, sess, object, r, retrnums);
        }
    } else if (attrnums > 1
               && (ret == CKR_ATTRIBUTE_SENSITIVE
                   || ret == CKR_ATTRIBUTE_TYPE_INVALID)) {
        P11PROV_debug("Querying attributes one by one");
        /* go one by one as this PKCS11 does not have some attributes
         * and does not handle it gracefully */
        for (size_t i = 0; i < attrnums; i++) {
            if (attrs[i].allocate) {
                ret = p11prov_GetAttributeValue(ctx, sess, object,
                                                &attrs[i].attr, 1);
                if (ret != CKR_OK) {
                    if (attrs[i].required) {
                        return ret;
                    }
                } else {
                    attrs[i].attr.pValue =
                        OPENSSL_zalloc(attrs[i].attr.ulValueLen + 1);
                    if (!attrs[i].attr.pValue) {
                        return CKR_HOST_MEMORY;
                    }
                }
            }
            ret =
                p11prov_GetAttributeValue(ctx, sess, object, &attrs[i].attr, 1);
            if (ret != CKR_OK) {
                if (attrs[i].required) {
                    return ret;
                } else {
                    if (attrs[i].allocate && attrs[i].attr.pValue) {
                        OPENSSL_free(attrs[i].attr.pValue);
                        attrs[i].attr.pValue = NULL;
                        attrs[i].attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    }
                }
            }
            P11PROV_debug("Attribute| type:0x%08lX value:%p, len:%lu",
                          attrs[i].attr.type, attrs[i].attr.pValue,
                          attrs[i].attr.ulValueLen);
        }
        ret = CKR_OK;
    }
    return ret;
}

void p11prov_move_alloc_attrs(struct fetch_attrs *attrs, int num,
                              CK_ATTRIBUTE *ck_attrs, int *ck_num)
{
    int c = *ck_num;
    for (int i = 0; i < num; i++) {
        if (attrs[i].allocate && attrs[i].attr.pValue) {
            ck_attrs[c] = attrs[i].attr;
            c++;
            /* clear moved values for good measure */
            attrs[i].attr.pValue = NULL;
            attrs[i].attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
        }
    }
    *ck_num = c;
}

void p11prov_fetch_attrs_free(struct fetch_attrs *attrs, int num)
{
    for (int i = 0; i < num; i++) {
        if (attrs[i].allocate) {
            OPENSSL_free(attrs[i].attr.pValue);
        }
    }
}

struct p11prov_uri {
    char *model;
    char *manufacturer;
    char *token;
    char *serial;
    CK_ATTRIBUTE id;
    CK_ATTRIBUTE label;
    char *pin;
    CK_OBJECT_CLASS class;
};

static int hex_to_byte(const char *in, unsigned char *byte)
{
    char c[2], s;
    int i = 0;

    for (i = 0; i < 2; i++) {
        s = in[i];
        if ('0' <= s && s <= '9') {
            c[i] = s - '0';
        } else if ('a' <= s && s <= 'f') {
            c[i] = s - 'a' + 10;
        } else if ('A' <= s && s <= 'F') {
            c[i] = s - 'A' + 10;
        } else {
            return EINVAL;
        }
    }
    *byte = (c[0] << 4) | c[1];
    return 0;
}

static int parse_attr(const char *str, size_t len, unsigned char **output,
                      size_t *outlen)
{
    unsigned char *out;
    size_t index = 0;
    int ret;

    out = OPENSSL_malloc(len + 1);
    if (out == NULL) {
        return ENOMEM;
    }

    while (*str && len > 0) {
        if (*str == '%') {
            char hex[3] = { 0 };
            if (len < 3) {
                ret = EINVAL;
                goto done;
            }
            hex[0] = str[1];
            hex[1] = str[2];
            ret = hex_to_byte(hex, &out[index]);
            if (ret != 0) {
                goto done;
            }

            index++;
            str += 3;
            len -= 3;
        } else {
            out[index] = *str;
            index++;
            str++;
            len--;
        }
    }

    out[index] = '\0';
    ret = 0;

done:
    if (ret != 0) {
        OPENSSL_free(out);
    } else {
        *output = out;
        *outlen = index;
    }
    return ret;
}

static int get_pin_file(const char *str, size_t len, char **output,
                        size_t *outlen)
{
    char pin[MAX_PIN_LENGTH + 1];
    char *pinfile;
    char *filename;
    BIO *fp;
    int ret;

    ret = parse_attr(str, len, (unsigned char **)&pinfile, outlen);
    if (ret != 0) {
        return ret;
    }

    if (strncmp((const char *)pinfile, "file:", 5) == 0) {
        filename = pinfile + 5;
    } else if (*pinfile == '|') {
        ret = EINVAL;
        goto done;
    } else {
        /* missing 'file:' is accepted */
        filename = pinfile;
    }

    fp = BIO_new_file(filename, "r");
    if (fp == NULL) {
        P11PROV_debug("Failed to get pin from %s", filename);
        ret = ENOENT;
        goto done;
    }
    ret = BIO_gets(fp, pin, MAX_PIN_LENGTH);
    if (ret <= 0) {
        P11PROV_debug("Failed to get pin from %s (%d)", filename, ret);
        ret = EINVAL;
        BIO_free(fp);
        goto done;
    }
    BIO_free(fp);

    /* files may contain newlines, remove any control character at the end */
    for (int i = ret - 1; i >= 0; i--) {
        if (pin[i] == '\n' || pin[i] == '\r') {
            pin[i] = '\0';
        } else {
            break;
        }
    }

    *output = OPENSSL_strdup(pin);
    if (*output == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = 0;
done:
    OPENSSL_free(pinfile);
    return ret;
}

P11PROV_URI *p11prov_parse_uri(P11PROV_CTX *ctx, const char *uri)
{
    struct p11prov_uri *u;
    const char *p, *end;
    int ret;

    P11PROV_debug("ctx=%p uri=%s)", ctx, uri);

    u = OPENSSL_zalloc(sizeof(struct p11prov_uri));
    if (u == NULL) {
        return NULL;
    }
    u->class = CK_UNAVAILABLE_INFORMATION;

    if (strncmp(uri, "pkcs11:", 7) != 0) {
        p11prov_uri_free(u);
        return NULL;
    }

    p = uri + 7;
    while (p) {
        size_t outlen;
        unsigned char **ptr;
        size_t *ptrlen;
        size_t len;
        bool id_fill = false, label_fill = false;

        end = strpbrk(p, ";?&");
        if (end) {
            len = end - p;
        } else {
            len = strlen(p);
        }

        ptr = NULL;
        ptrlen = &outlen;

        if (strncmp(p, "model=", 6) == 0) {
            p += 6;
            len -= 6;
            ptr = (unsigned char **)&u->model;
        } else if (strncmp(p, "manufacturer=", 13) == 0) {
            p += 13;
            len -= 13;
            ptr = (unsigned char **)&u->manufacturer;
        } else if (strncmp(p, "token=", 6) == 0) {
            p += 6;
            len -= 6;
            ptr = (unsigned char **)&u->token;
        } else if (strncmp(p, "serial=", 7) == 0) {
            p += 7;
            len -= 7;
            ptr = (unsigned char **)&u->serial;
        } else if (strncmp(p, "id=", 3) == 0) {
            p += 3;
            len -= 3;
            ptr = (unsigned char **)&u->id.pValue;
            id_fill = true;
        } else if (strncmp(p, "object=", 7) == 0) {
            p += 7;
            len -= 7;
            ptr = (unsigned char **)&u->label.pValue;
            label_fill = true;
        } else if (strncmp(p, "pin-value=", 10) == 0) {
            p += 10;
            len -= 10;
            ptr = (unsigned char **)&u->pin;
        } else if (strncmp(p, "pin-source=", 11) == 0) {
            p += 11;
            len -= 11;
            ret = get_pin_file(p, len, &u->pin, ptrlen);
            if (ret != 0) {
                goto done;
            }
        } else if (strncmp(p, "type=", 5) == 0
                   || strncmp(p, "object-type=", 12) == 0) {
            p += 4;
            if (*p == '=') {
                p++;
                len -= 5;
            } else {
                p += 8;
                len -= 12;
            }
            if (len == 4 && strncmp(p, "cert", 4) == 0) {
                u->class = CKO_CERTIFICATE;
            } else if (len == 6 && strncmp(p, "public", 6) == 0) {
                u->class = CKO_PUBLIC_KEY;
            } else if (len == 7 && strncmp(p, "private", 7) == 0) {
                u->class = CKO_PRIVATE_KEY;
            } else if (len == 6 && strncmp(p, "secret", 6) == 0) {
                u->class = CKO_SECRET_KEY;
            } else {
                P11PROV_raise(ctx, CKR_ARGUMENTS_BAD,
                              "Unknown object type [%.*s]", (int)len, p);
                ret = EINVAL;
                goto done;
            }
        } else {
            P11PROV_debug("Ignoring unknown pkcs11 URI attribute");
        }

        if (ptr) {
            ret = parse_attr(p, len, ptr, ptrlen);
            if (ret != 0) {
                goto done;
            }
            if (id_fill) {
                u->id.type = CKA_ID;
                u->id.ulValueLen = outlen;
            }
            if (label_fill) {
                u->label.type = CKA_LABEL;
                u->label.ulValueLen = outlen;
            }
        }

        if (end) {
            p = end + 1;
        } else {
            p = NULL;
        }
    }

    ret = 0;
done:
    if (ret != 0) {
        p11prov_uri_free(u);
        return NULL;
    }
    return u;
}

void p11prov_uri_free(P11PROV_URI *uri)
{
    if (uri == NULL) {
        return;
    }

    OPENSSL_free(uri->model);
    OPENSSL_free(uri->manufacturer);
    OPENSSL_free(uri->token);
    OPENSSL_free(uri->serial);
    OPENSSL_free(uri->id.pValue);
    if (uri->pin) {
        OPENSSL_clear_free(uri->pin, strlen(uri->pin));
    }
    OPENSSL_clear_free(uri, sizeof(struct p11prov_uri));
}

CK_OBJECT_CLASS p11prov_uri_get_class(P11PROV_URI *uri)
{
    return uri->class;
}

CK_ATTRIBUTE p11prov_uri_get_id(P11PROV_URI *uri)
{
    return uri->id;
}

CK_ATTRIBUTE p11prov_uri_get_label(P11PROV_URI *uri)
{
    return uri->label;
}

char *p11prov_uri_get_serial(P11PROV_URI *uri)
{
    return uri->serial;
}

char *p11prov_uri_get_pin(P11PROV_URI *uri)
{
    return uri->pin;
}

CK_RV p11prov_uri_match_token(P11PROV_URI *uri, CK_TOKEN_INFO *token)
{
    if (uri->model
        && strncmp(uri->model, (const char *)token->model, 16) != 0) {
        return CKR_CANCEL;
    }
    if (uri->manufacturer
        && strncmp(uri->manufacturer, (const char *)token->manufacturerID, 32)
               != 0) {
        return CKR_CANCEL;
    }
    if (uri->token
        && strncmp(uri->token, (const char *)token->label, 32) != 0) {
        return CKR_CANCEL;
    }
    if (uri->serial
        && strncmp(uri->serial, (const char *)token->serialNumber, 16) != 0) {
        return CKR_CANCEL;
    }

    return CKR_OK;
}

int p11prov_get_pin(const char *in, char **out)
{
    size_t outlen;

    if (strncmp(in, "file:", 5) == 0) {
        return get_pin_file(in, strlen(in), out, &outlen);
    }

    *out = OPENSSL_strdup(in);
    if (!*out) {
        return ENOMEM;
    }

    return 0;
}

/* Calculates the start time and then nano-sleeps by 'interval' time.
 * On the first invocation the content of start_time must be 0.
 * The content of start_time must not be altered outside this function after
 * the first invocation.
 * This function does not guarantee each sleep is 'interval' long.
 *
 * Returns true if max_wait has not been reached yet.
 * Returns false on an error or if max_wait is exceeded.
 */
bool cyclewait_with_timeout(uint64_t max_wait, uint64_t interval,
                            uint64_t *start_time)
{
#define NANOS_SEC 1000000000
    uint64_t current_time;
    struct timespec ts;
    int ret;

    ret = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (ret != 0) {
        return false;
    }

    current_time = ts.tv_sec * NANOS_SEC + ts.tv_nsec;
    if (*start_time == 0) {
        *start_time = current_time;
    } else {
        if (current_time > *start_time + max_wait) {
            return false;
        }
    }

    ts.tv_sec = interval / NANOS_SEC;
    ts.tv_nsec = interval % NANOS_SEC;
    ret = nanosleep(&ts, NULL);
    if (ret != 0 && ret != EINTR) {
        return false;
    }

    return true;
}

void byteswap_buf(unsigned char *src, unsigned char *dest, size_t len)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    int s = 0;
    int e = len - 1;
    unsigned char sb;
    unsigned char eb;

    while (e >= s) {
        sb = src[s];
        eb = src[e];
        dest[s] = eb;
        dest[e] = sb;
        s++;
        e--;
    }
#else
    memmove(dest, src, len);
#endif
}

CK_RV p11prov_token_sup_attr(P11PROV_CTX *ctx, CK_SLOT_ID id, int action,
                             CK_ATTRIBUTE_TYPE attr, CK_BBOOL *data)
{
    CK_ULONG data_size = sizeof(CK_BBOOL);
    void *data_ptr = &data;
    char alloc_name[32];
    const char *name;
    int err;

    switch (attr) {
    case CKA_ALLOWED_MECHANISMS:
        name = "sup_attr_CKA_ALLOWED_MECHANISMS";
        break;
    default:
        err = snprintf(alloc_name, 32, "sup_attr_%016lx", attr);
        if (err < 0 || err >= 32) {
            return CKR_HOST_MEMORY;
        }
        name = alloc_name;
    }

    switch (action) {
    case GET_ATTR:
        return p11prov_ctx_get_quirk(ctx, id, name, data_ptr, &data_size);
    case SET_ATTR:
        return p11prov_ctx_set_quirk(ctx, id, name, data, data_size);
    default:
        return CKR_ARGUMENTS_BAD;
    }
}

CK_RV p11prov_copy_attr(CK_ATTRIBUTE *dst, CK_ATTRIBUTE *src)
{
    if (src->ulValueLen) {
        dst->pValue = OPENSSL_malloc(src->ulValueLen);
        if (!dst->pValue) {
            return CKR_HOST_MEMORY;
        }
        memcpy(dst->pValue, src->pValue, src->ulValueLen);
        dst->ulValueLen = src->ulValueLen;
    }
    dst->type = src->type;

    return CKR_OK;
}

bool p11prov_x509_names_are_equal(CK_ATTRIBUTE *a, CK_ATTRIBUTE *b)
{
    const unsigned char *val;
    X509_NAME *xa;
    X509_NAME *xb;
    int cmp;

    /* d2i function modify the val pointer */
    val = a->pValue;
    xa = d2i_X509_NAME(NULL, &val, a->ulValueLen);
    if (!xa) {
        return false;
    }
    val = b->pValue;
    xb = d2i_X509_NAME(NULL, &val, b->ulValueLen);
    if (!xb) {
        X509_NAME_free(xa);
        return false;
    }

    cmp = X509_NAME_cmp(xa, xb);

    X509_NAME_free(xa);
    X509_NAME_free(xb);
    return cmp == 0;
}

char *p11prov_alloc_sprintf(int size_hint, const char *format, ...)
{
    char *buf = NULL;
    va_list args;
    int repeat = 1;
    int ret;

again:
    if (repeat-- < 0) {
        ret = -1;
        goto done;
    }

    if (size_hint) {
        buf = OPENSSL_malloc(size_hint);
    }

    va_start(args, format);
    ret = vsnprintf(buf, size_hint, format, args);
    va_end(args);

    if (ret >= size_hint) {
        size_hint = ret + 1;
        OPENSSL_free(buf);
        buf = NULL;
        goto again;
    }

done:
    if (ret < 0) {
        OPENSSL_free(buf);
        buf = NULL;
    } else if (size_hint > ret + 1) {
        buf = OPENSSL_realloc(buf, ret + 1);
    }
    return buf;
}

void trim_padded_field(CK_UTF8CHAR *field, ssize_t n)
{
    for (; n > 0 && field[n - 1] == ' '; n--) {
        field[n - 1] = 0;
    }
}

#define MUTEX_RAISE_ERROR(_errstr) \
    P11PROV_raise(provctx, ret, "%s %s mutex (errno=%d)", _errstr, obj, err); \
    P11PROV_debug("Called from [%s:%d]%s()", file, line, func)

CK_RV p11prov_mutex_init(P11PROV_CTX *provctx, pthread_mutex_t *lock,
                         const char *obj, const char *file, int line,
                         const char *func)
{
    CK_RV ret = CKR_OK;
    int err;

    err = pthread_mutex_init(lock, NULL);
    if (err != 0) {
        err = errno;
        ret = CKR_CANT_LOCK;
        MUTEX_RAISE_ERROR("Failed to init");
    }
    return ret;
}

CK_RV p11prov_mutex_lock(P11PROV_CTX *provctx, pthread_mutex_t *lock,
                         const char *obj, const char *file, int line,
                         const char *func)
{
    CK_RV ret = CKR_OK;
    int err;

    err = pthread_mutex_lock(lock);
    if (err != 0) {
        err = errno;
        ret = CKR_CANT_LOCK;
        MUTEX_RAISE_ERROR("Failed to lock");
    }
    return ret;
}

CK_RV p11prov_mutex_unlock(P11PROV_CTX *provctx, pthread_mutex_t *lock,
                           const char *obj, const char *file, int line,
                           const char *func)
{
    CK_RV ret = CKR_OK;
    int err;

    err = pthread_mutex_unlock(lock);
    if (err != 0) {
        err = errno;
        ret = CKR_CANT_LOCK;
        MUTEX_RAISE_ERROR("Failed to unlock");
    }
    return ret;
}

CK_RV p11prov_mutex_destroy(P11PROV_CTX *provctx, pthread_mutex_t *lock,
                            const char *obj, const char *file, int line,
                            const char *func)
{
    CK_RV ret = CKR_OK;
    int err;

    err = pthread_mutex_destroy(lock);
    if (err != 0) {
        err = errno;
        ret = CKR_CANT_LOCK;
        MUTEX_RAISE_ERROR("Failed to destroy");
    }
    return ret;
}

void p11prov_force_rwlock_reinit(pthread_rwlock_t *lock)
{
    pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
    memcpy(lock, &rwlock, sizeof(rwlock));
}
