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
        P11PROV_debug("Fetching attributes (%d): 0x%08lx", (int)i,
                      attrs[i].attr.type);
        q[i] = attrs[i].attr;
    }

    /* error stack mark so we can avoid returning bogus errors */
    p11prov_set_error_mark(ctx);

    /* try one shot, then fallback to individual calls if that fails */
    ret = p11prov_GetAttributeValue(ctx, sess, object, q, attrnums);
    if (ret == CKR_OK) {
        unsigned long retrnums = 0;
        for (size_t i = 0; i < attrnums; i++) {
            if (q[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                /* This can't happen according to the algorithm described
                 * in the spec when the call returns CKR_OK. */
                ret = CKR_GENERAL_ERROR;
                P11PROV_raise(ctx, ret, "Failed to get attributes");
                goto done;
            }
            if (attrs[i].allocate) {
                /* always allocate one more, so that zero terminated strings
                 * work automatically */
                q[i].pValue = OPENSSL_zalloc(q[i].ulValueLen + 1);
                if (!q[i].pValue) {
                    ret = CKR_HOST_MEMORY;
                    P11PROV_raise(ctx, ret, "Failed to get attributes");
                    goto done;
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
            P11PROV_debug("(Re)Fetching %lu attributes", retrnums);
            ret = p11prov_GetAttributeValue(ctx, sess, object, r, retrnums);
        }
        for (size_t i = 0; i < attrnums; i++) {
            P11PROV_debug("Attribute| type:0x%08lX value:%p, len:%lu",
                          attrs[i].attr.type, attrs[i].attr.pValue,
                          attrs[i].attr.ulValueLen);
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
                        ret = CKR_HOST_MEMORY;
                        P11PROV_raise(ctx, ret, "Failed to get attributes");
                        goto done;
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
done:
    if (ret == CKR_OK) {
        /* if there was any error, remove it, as we got success */
        p11prov_pop_error_to_mark(ctx);
    } else {
        /* otherwise clear the mark and leave errors on the stack */
        p11prov_clear_last_error_mark(ctx);
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

#define ATTR_library_description "library-description"
#define ATTR_library_manufacturer "library-manufacturer"
#define ATTR_library_version "library-version"
#define ATTR_token "token"
#define ATTR_manufacturer "manufacturer"
#define ATTR_model "model"
#define ATTR_serial "serial"
#define ATTR_slot_description "slot-description"
#define ATTR_slot_id "slot-id"
#define ATTR_slot_manufacturer "slot-manufacturer"
#define ATTR_id "id"
#define ATTR_object "object"
#define ATTR_type "type"

#define TYPE_data "data"
#define TYPE_cert "cert"
#define TYPE_public "public"
#define TYPE_private "private"
#define TYPE_secret_key "secret-key"

struct p11prov_uri {
    /* CK_INFO attributes */
    char *library_description;
    char *library_manufacturer;
    CK_VERSION library_version;
    /* CK_TOKEN_INFO attributes */
    char *token;
    char *manufacturer;
    char *model;
    char *serial;
    /* CK_SLOT_INFO attributes */
    char *slot_description;
    CK_SLOT_ID slot_id;
    char *slot_manufacturer;
    /* object attributes */
    CK_ATTRIBUTE id;
    CK_ATTRIBUTE object;
    CK_OBJECT_CLASS type;
    /* pin */
    char *pin;
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

static int parse_attr(const char *str, size_t len, uint8_t **output,
                      size_t *outlen)
{
    uint8_t *out;
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
        if (outlen) {
            *outlen = index;
        }
    }
    return ret;
}

static int get_pin_file(P11PROV_CTX *ctx, const char *str, size_t len,
                        void **output)
{
    char pin[MAX_PIN_LENGTH + 1];
    char *pinfile;
    char *filename;
    BIO *fp;
    int ret;

    ret = parse_attr(str, len, (uint8_t **)&pinfile, NULL);
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

#define COPY_STRUCT_MEMBER(dst, src, _name) \
    if ((src)->_name) { \
        (dst)->_name = OPENSSL_strdup((src)->_name); \
        if (!(dst)->_name) { \
            p11prov_uri_free((dst)); \
            return NULL; \
        } \
    }

static void p11prov_uri_free_int(P11PROV_URI *uri)
{
    OPENSSL_free(uri->library_manufacturer);
    OPENSSL_free(uri->library_description);
    OPENSSL_free(uri->token);
    OPENSSL_free(uri->manufacturer);
    OPENSSL_free(uri->model);
    OPENSSL_free(uri->serial);
    OPENSSL_free(uri->slot_description);
    OPENSSL_free(uri->slot_manufacturer);
    OPENSSL_free(uri->id.pValue);
    OPENSSL_free(uri->object.pValue);
    if (uri->pin) {
        OPENSSL_clear_free(uri->pin, strlen(uri->pin));
    }
}

static int parse_utf8str(P11PROV_CTX *ctx, const char *str, size_t len,
                         void **output)
{
    CK_UTF8CHAR *outstr;
    size_t outlen;
    size_t chklen;
    int ret;

    ret = parse_attr(str, len, &outstr, &outlen);
    if (ret != 0) {
        return ret;
    }

    chklen = strlen((const char *)outstr);
    if (outlen != chklen) {
        P11PROV_raise(ctx, CKR_ARGUMENTS_BAD,
                      "Failed to parse [%.*s] as a string", (int)len, str);
        OPENSSL_free(outstr);
        return EINVAL;
    }
    P11PROV_debug("String [%.*s] -> [%s]", (int)len, str, outstr);
    *output = outstr;
    return 0;
}

static int parse_ck_attribute(P11PROV_CTX *ctx, const char *str, size_t len,
                              void **output)
{
    CK_ATTRIBUTE *cka = (CK_ATTRIBUTE *)output;
    CK_UTF8CHAR *outstr;
    size_t outlen;
    int ret;

    switch (cka->type) {
    case CKA_LABEL:
        ret = parse_utf8str(ctx, str, len, (void **)&outstr);
        if (ret != 0) {
            return ret;
        }
        cka->pValue = outstr;
        cka->ulValueLen = strlen((const char *)outstr);
        break;
    case CKA_ID:
        ret = parse_attr(str, len, &outstr, &outlen);
        if (ret != 0) {
            P11PROV_raise(ctx, CKR_ARGUMENTS_BAD,
                          "Failed to parse CKA_ID: [%.*s]", (int)len, str);
            return ret;
        }
        cka->pValue = outstr;
        cka->ulValueLen = outlen;
        break;
    default:
        return EINVAL;
    }

    return 0;
}

static int parse_class(P11PROV_CTX *ctx, const char *str, size_t len,
                       void **output)
{
    CK_OBJECT_CLASS *class = (CK_OBJECT_CLASS *)output;
    char *typestr;
    int ret;

    ret = parse_utf8str(ctx, str, len, (void **)&typestr);
    if (ret != 0) {
        return ret;
    }

    if (strcmp(typestr, TYPE_data) == 0) {
        *class = CKO_DATA;
    } else if (strcmp(typestr, TYPE_cert) == 0) {
        *class = CKO_CERTIFICATE;
    } else if (strcmp(typestr, TYPE_public) == 0) {
        *class = CKO_PUBLIC_KEY;
    } else if (strcmp(typestr, TYPE_private) == 0) {
        *class = CKO_PRIVATE_KEY;
    } else if (strcmp(typestr, TYPE_secret_key) == 0) {
        *class = CKO_SECRET_KEY;
    } else {
        P11PROV_raise(ctx, CKR_ARGUMENTS_BAD, "Unknown object type [%.*s]",
                      (int)len, str);
        ret = EINVAL;
    }

    OPENSSL_free(typestr);
    return ret;
}

static int parse_version(P11PROV_CTX *ctx, const char *str, size_t len,
                         void **output)
{
    CK_VERSION *ver = (CK_VERSION *)output;
    const char *sep;
    CK_ULONG val;
    int ret;

    if (len < 3 || len > 7) {
        ret = EINVAL;
        goto done;
    }
    sep = strchr(str, '.');
    if (!sep) {
        ret = EINVAL;
        goto done;
    }

    /* major */
    ret = parse_ulong(ctx, str, (sep - str), (void **)&val);
    if (ret != 0) {
        goto done;
    }
    if (val > 255) {
        ret = EINVAL;
        goto done;
    }
    ver->major = val;

    /* minor */
    sep++;
    ret = parse_ulong(ctx, sep, len - (sep - str), (void **)&val);
    if (ret != 0) {
        goto done;
    }
    if (val > 255) {
        ret = EINVAL;
        goto done;
    }
    ver->minor = val;

    ret = 0;

done:
    if (ret != 0) {
        P11PROV_raise(ctx, CKR_ARGUMENTS_BAD, "Value not a version [%.*s]",
                      (int)len, str);
    }
    return ret;
}

int parse_ulong(P11PROV_CTX *ctx, const char *str, size_t len, void **output)
{
    CK_ULONG *val = (CK_ULONG *)output;
    char *endptr;
    int ret;

    errno = 0;
    endptr = NULL;
    *val = strtoul(str, &endptr, 10);
    if (errno != 0) {
        ret = errno;
        goto done;
    }
    if (endptr != str + len) {
        ret = EINVAL;
        goto done;
    }
    ret = 0;

done:
    if (ret != 0) {
        P11PROV_raise(ctx, CKR_ARGUMENTS_BAD, "Invalid numeric value [%.*s]",
                      (int)len, str);
    }
    return ret;
}

#define DECL_ATTR_COMP(u_attr, handler) \
    { \
        ATTR_##u_attr, sizeof(ATTR_##u_attr) - 1, handler, (void **)&u.u_attr \
    }

struct uri_components {
    const char *attr;
    size_t attrlen;
    int (*handler)(P11PROV_CTX *, const char *, size_t, void **);
    void **output;
};

P11PROV_URI *p11prov_parse_uri(P11PROV_CTX *ctx, const char *uri)
{
    struct p11prov_uri u = {
        .type = CK_UNAVAILABLE_INFORMATION,
        .slot_id = CK_UNAVAILABLE_INFORMATION,
        .id = { .type = CKA_ID },
        .object = { .type = CKA_LABEL },
    };
    struct uri_components ucmap[] = {
        DECL_ATTR_COMP(library_description, parse_utf8str),
        DECL_ATTR_COMP(library_manufacturer, parse_utf8str),
        DECL_ATTR_COMP(library_version, parse_version),
        DECL_ATTR_COMP(token, parse_utf8str),
        DECL_ATTR_COMP(manufacturer, parse_utf8str),
        DECL_ATTR_COMP(model, parse_utf8str),
        DECL_ATTR_COMP(serial, parse_utf8str),
        DECL_ATTR_COMP(slot_description, parse_utf8str),
        DECL_ATTR_COMP(slot_id, parse_ulong),
        DECL_ATTR_COMP(slot_manufacturer, parse_utf8str),
        DECL_ATTR_COMP(id, parse_ck_attribute),
        DECL_ATTR_COMP(object, parse_ck_attribute),
        DECL_ATTR_COMP(type, parse_class),
        { "pin-value", sizeof("pin-value") - 1, parse_utf8str,
          (void **)&u.pin },
        { "pin-source", sizeof("pin-source") - 1, get_pin_file,
          (void **)&u.pin },
        { "object-type", sizeof("object-type") - 1, parse_class,
          (void **)&u.type },
        { NULL, 0, NULL, NULL }
    };
    const char *p, *end;
    int ret;

    P11PROV_debug("ctx=%p uri=%s)", ctx, uri);

    if (strncmp(uri, "pkcs11:", 7) != 0) {
        return NULL;
    }

    p = uri + 7;
    while (p) {
        size_t len;

        end = strpbrk(p, ";?&");
        if (end) {
            len = end - p;
        } else {
            len = strlen(p);
        }

        for (int i = 0; ucmap[i].attr != NULL; i++) {
            if (strncmp(p, ucmap[i].attr, ucmap[i].attrlen) == 0
                && p[ucmap[i].attrlen] == '=') {
                p += ucmap[i].attrlen + 1;
                len -= ucmap[i].attrlen + 1;
                ret = ucmap[i].handler(ctx, p, len, ucmap[i].output);
                if (ret != 0) {
                    goto done;
                }
                break;
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
    if (ret == 0) {
        struct p11prov_uri *mu;
        mu = OPENSSL_malloc(sizeof(struct p11prov_uri));
        if (mu) {
            *mu = u;
        } else {
            p11prov_uri_free_int(&u);
        }
        return mu;
    }
    return NULL;
}

static void byte_to_hex(uint8_t c, char *out, bool bin, int *written)
{
    if (bin || c < '\'' || c == '/' || c == ';' || c == '?' || c > '~') {
        (void)snprintf(out, 4, "%%%02X", (unsigned int)c);
        *written = 3;
        return;
    }

    *out = c;
    *written = 1;
}

static char *uri_component(const char *name, const char *val, size_t vlen,
                           size_t *clen)
{
    size_t max_size;
    size_t name_len;
    size_t val_len = vlen;
    size_t ci;
    bool bin = false;
    char *c;

    if (!name || !val) {
        return NULL;
    }

    name_len = strlen(name);
    if (name_len == 2) {
        /* id */
        bin = true;
    }

    if (val_len == 0) {
        val_len = strlen(val);
    }

    max_size = name_len + 1 + val_len * 3 + 2;
    c = OPENSSL_malloc(max_size);
    if (!c) {
        return NULL;
    }

    memcpy(c, name, name_len);
    c[name_len] = '=';

    ci = name_len + 1;
    for (size_t vi = 0; vi < val_len; vi++) {
        int inc = 0;
        byte_to_hex(val[vi], c + ci, bin, &inc);
        ci += inc;
    }
    c[ci] = ';';
    c[ci + 1] = '\0';

    *clen = ci;
    return c;
}

char *p11prov_key_to_uri(P11PROV_CTX *ctx, P11PROV_OBJ *key)
{
    P11PROV_SLOTS_CTX *slots;
    P11PROV_SLOT *slot;
    CK_TOKEN_INFO *token;
    CK_ATTRIBUTE *cka_label;
    CK_ATTRIBUTE *cka_id;
    CK_OBJECT_CLASS class;
    CK_SLOT_ID slot_id;
    const char *type;
    char *model = NULL;
    char *manufacturer = NULL;
    char *serial = NULL;
    char *token_label = NULL;
    char *object = NULL;
    char *id = NULL;
    char *uri = NULL;
    size_t clen = 0;
    size_t size_hint = 0;
    CK_RV ret;

    class = p11prov_obj_get_class(key);
    slot_id = p11prov_obj_get_slotid(key);
    cka_id = p11prov_obj_get_attr(key, CKA_ID);
    cka_label = p11prov_obj_get_attr(key, CKA_LABEL);

    switch (class) {
    case CKO_DATA:
        type = TYPE_data;
        break;
    case CKO_CERTIFICATE:
        type = TYPE_cert;
        break;
    case CKO_PUBLIC_KEY:
        type = TYPE_public;
        break;
    case CKO_PRIVATE_KEY:
        type = TYPE_private;
        break;
    case CKO_SECRET_KEY:
        type = TYPE_secret_key;
        break;
    default:
        return NULL;
    }

    ret = p11prov_take_slots(ctx, &slots);
    if (ret != CKR_OK) {
        return NULL;
    }

    slot = p11prov_get_slot_by_id(slots, slot_id);
    if (!slot) {
        goto done;
    }

    token = p11prov_slot_get_token(slot);

    if (token->model[0] != 0) {
        const char *str = (const char *)token->model;
        int len = strnlen(str, 16);
        clen = 0;
        model = uri_component(ATTR_model, str, len, &clen);
        size_hint += clen;
    }
    if (token->manufacturerID[0] != 0) {
        const char *str = (const char *)token->manufacturerID;
        int len = strnlen(str, 32);
        clen = 0;
        manufacturer = uri_component(ATTR_manufacturer, str, len, &clen);
        size_hint += clen;
    }
    if (token->serialNumber[0] != 0) {
        const char *str = (const char *)token->serialNumber;
        int len = strnlen(str, 16);
        clen = 0;
        serial = uri_component(ATTR_serial, str, len, &clen);
        size_hint += clen;
    }
    if (token->label[0] != 0) {
        const char *str = (const char *)token->label;
        int len = strnlen(str, 32);
        clen = 0;
        token_label = uri_component(ATTR_token, str, len, &clen);
        size_hint += clen;
    }
    if (cka_id && cka_id->ulValueLen > 0) {
        clen = 0;
        id = uri_component(ATTR_id, (const char *)cka_id->pValue,
                           cka_id->ulValueLen, &clen);
        size_hint += clen;
    }
    if (cka_label && cka_label->ulValueLen > 0) {
        clen = 0;
        object = uri_component(ATTR_object, (const char *)cka_label->pValue,
                               cka_label->ulValueLen, &clen);
        size_hint += clen;
    }

    size_hint += sizeof("pkcs11:") + sizeof("type=") + strlen(type);

    uri = p11prov_alloc_sprintf(
        size_hint, "pkcs11:%s%s%s%s%s%stype=%s", model ? model : "",
        manufacturer ? manufacturer : "", serial ? serial : "",
        token_label ? token_label : "", id ? id : "", object ? object : "",
        type);

done:
    OPENSSL_free(model);
    OPENSSL_free(manufacturer);
    OPENSSL_free(serial);
    OPENSSL_free(token_label);
    OPENSSL_free(id);
    OPENSSL_free(object);
    p11prov_return_slots(slots);
    return uri;
}

void p11prov_uri_free(P11PROV_URI *uri)
{
    if (uri == NULL) {
        return;
    }

    p11prov_uri_free_int(uri);

    OPENSSL_clear_free(uri, sizeof(struct p11prov_uri));
}

CK_OBJECT_CLASS p11prov_uri_get_class(P11PROV_URI *uri)
{
    return uri->type;
}

void p11prov_uri_set_class(P11PROV_URI *uri, CK_OBJECT_CLASS class)
{
    uri->type = class;
}

CK_ATTRIBUTE p11prov_uri_get_id(P11PROV_URI *uri)
{
    return uri->id;
}

CK_RV p11prov_uri_set_id(P11PROV_URI *uri, CK_ATTRIBUTE *id)
{
    OPENSSL_free(uri->id.pValue);
    return p11prov_copy_attr(&uri->id, id);
}

CK_ATTRIBUTE p11prov_uri_get_label(P11PROV_URI *uri)
{
    return uri->object;
}

CK_RV p11prov_uri_set_label(P11PROV_URI *uri, CK_ATTRIBUTE *label)
{
    OPENSSL_free(uri->object.pValue);
    return p11prov_copy_attr(&uri->object, label);
}

char *p11prov_uri_get_serial(P11PROV_URI *uri)
{
    return uri->serial;
}

char *p11prov_uri_get_pin(P11PROV_URI *uri)
{
    return uri->pin;
}

CK_SLOT_ID p11prov_uri_get_slot_id(P11PROV_URI *uri)
{
    return uri->slot_id;
}

void p11prov_uri_set_slot_id(P11PROV_URI *uri, CK_SLOT_ID slot_id)
{
    uri->slot_id = slot_id;
}

P11PROV_URI *p11prov_copy_uri(P11PROV_URI *uri)
{
    P11PROV_URI *cu;
    CK_RV rv;

    cu = OPENSSL_zalloc(sizeof(P11PROV_URI));
    if (!cu) {
        return NULL;
    }

    COPY_STRUCT_MEMBER(cu, uri, library_manufacturer)
    COPY_STRUCT_MEMBER(cu, uri, library_description)
    COPY_STRUCT_MEMBER(cu, uri, token)
    COPY_STRUCT_MEMBER(cu, uri, manufacturer)
    COPY_STRUCT_MEMBER(cu, uri, model)
    COPY_STRUCT_MEMBER(cu, uri, serial)
    COPY_STRUCT_MEMBER(cu, uri, slot_description)
    COPY_STRUCT_MEMBER(cu, uri, slot_manufacturer)
    COPY_STRUCT_MEMBER(cu, uri, pin)

    rv = p11prov_copy_attr(&cu->id, &uri->id);
    if (rv != CKR_OK) {
        p11prov_uri_free(cu);
        return NULL;
    }

    rv = p11prov_copy_attr(&cu->object, &uri->object);
    if (rv != CKR_OK) {
        p11prov_uri_free(cu);
        return NULL;
    }

    cu->library_version = uri->library_version;
    cu->slot_id = uri->slot_id;
    cu->type = uri->type;

    return cu;
}

CK_RV p11prov_uri_match_token(P11PROV_URI *uri, CK_SLOT_ID slot_id,
                              CK_SLOT_INFO *slot, CK_TOKEN_INFO *token)
{
    if (uri->slot_id != CK_UNAVAILABLE_INFORMATION && uri->slot_id != slot_id) {
        return CKR_CANCEL;
    }

    if (uri->slot_description
        && strncmp(uri->slot_description, (const char *)slot->slotDescription,
                   64)
               != 0) {
        return CKR_CANCEL;
    }

    if (uri->slot_manufacturer
        && strncmp(uri->slot_manufacturer, (const char *)slot->manufacturerID,
                   32)
               != 0) {
        return CKR_CANCEL;
    }

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

int p11prov_get_pin(P11PROV_CTX *ctx, const char *in, char **out)
{
    if (strncmp(in, "file:", 5) == 0) {
        return get_pin_file(ctx, in, strlen(in), (void **)out);
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

CK_RV p11prov_copy_attr(CK_ATTRIBUTE *dst, CK_ATTRIBUTE *src)
{
    if (src->ulValueLen) {
        dst->pValue = OPENSSL_malloc(src->ulValueLen);
        if (!dst->pValue) {
            return CKR_HOST_MEMORY;
        }
        memcpy(dst->pValue, src->pValue, src->ulValueLen);
    } else {
        dst->pValue = NULL;
    }
    dst->ulValueLen = src->ulValueLen;
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
