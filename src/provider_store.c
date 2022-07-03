/* Copyright (c) 2022 Simo Sorce <simo@redhat.com> - see COPYING */

#include "provider.h"
#include <string.h>

struct p11prov_uri {
    char *model;
    char *manufacturer;
    char *token;
    char *serial;
    char *object;
    unsigned char *id;
    size_t id_len;
    char *pin;
    CK_OBJECT_CLASS class;
};

struct p11prov_key {
    CK_SLOT_ID slotid;
    CK_OBJECT_HANDLE handle;
    CK_KEY_TYPE type;

    bool private;
    unsigned char *id;
    unsigned long id_len;
    char *label;
    CK_BBOOL always_auth;

    CK_ATTRIBUTE *attrs;
    unsigned long numattrs;

    int refcnt;
};

struct p11prov_object {
    PROVIDER_CTX *provctx;
    struct p11prov_uri *parsed_uri;
    int loaded;
    struct p11prov_key *key;

    int refcnt;
};

static void p11prov_uri_free(struct p11prov_uri *parsed_uri)
{
    if (parsed_uri == NULL) return;

    OPENSSL_free(parsed_uri->model);
    OPENSSL_free(parsed_uri->manufacturer);
    OPENSSL_free(parsed_uri->token);
    OPENSSL_free(parsed_uri->serial);
    OPENSSL_free(parsed_uri->object);
    OPENSSL_free(parsed_uri->id);
    if (parsed_uri->pin) {
        OPENSSL_clear_free(parsed_uri->pin, strlen(parsed_uri->pin));
    }
    OPENSSL_clear_free(parsed_uri, sizeof(struct p11prov_uri));
}

static P11PROV_KEY *p11prov_key_new(void)
{
    P11PROV_KEY *key;

    key = OPENSSL_zalloc(sizeof(P11PROV_KEY));
    if (!key) return NULL;

    key->refcnt = 1;

    return key;
}

static P11PROV_KEY *p11prov_key_ref(P11PROV_KEY *key)
{
    if (key &&
        __atomic_fetch_add(&key->refcnt, 1, __ATOMIC_ACQ_REL) > 0) {
        return key;
    }

    return NULL;
}

void p11prov_key_free(P11PROV_KEY *key)
{
    p11prov_debug("key free (%p)\n", key);

    if (key == NULL) return;
    if (__atomic_sub_fetch(&key->refcnt, 1, __ATOMIC_ACQ_REL) != 0) {
        p11prov_debug("key free: reference held\n");
        return;
    }

    OPENSSL_free(key->id);
    OPENSSL_free(key->label);

    for (int i = 0; i < key->numattrs; i++) {
        OPENSSL_free(key->attrs[i].pValue);
    }
    OPENSSL_free(key->attrs);

    OPENSSL_clear_free(key, sizeof(P11PROV_KEY));
}

static P11PROV_OBJECT *p11prov_object_ref(P11PROV_OBJECT *obj)
{
    if (obj &&
        __atomic_fetch_add(&obj->refcnt, 1, __ATOMIC_ACQ_REL) > 0) {
        return obj;
    }

    return NULL;
}

void p11prov_object_free(P11PROV_OBJECT *obj)
{
    p11prov_debug("object free (%p)\n", obj);

    if (obj == NULL) return;
    if (__atomic_sub_fetch(&obj->refcnt, 1, __ATOMIC_ACQ_REL) != 0) {
        p11prov_debug("object free: reference held\n");
        return;
    }

    p11prov_uri_free(obj->parsed_uri);
    p11prov_key_free(obj->key);

    OPENSSL_clear_free(obj, sizeof(P11PROV_OBJECT));
}

bool p11prov_object_check_key(P11PROV_OBJECT *obj, bool need_private)
{
    if (need_private) {
        return obj->key && obj->key->private;
    }
    return obj->key != NULL;
}

P11PROV_KEY *p11prov_object_get_key(P11PROV_OBJECT *obj)
{
    return p11prov_key_ref(obj->key);
}

CK_ATTRIBUTE *p11prov_key_attr(P11PROV_KEY *key, CK_ATTRIBUTE_TYPE type)
{
    if (!key) return NULL;

    for (int i = 0; i < key->numattrs; i++) {
        if (key->attrs[i].type == type) {
            return &key->attrs[i];
        }
    }

    return NULL;
}

CK_SLOT_ID p11prov_key_slotid(P11PROV_KEY *key)
{
    if (key) return key->slotid;
    return CK_UNAVAILABLE_INFORMATION;
}

CK_OBJECT_HANDLE p11prov_key_hanlde(P11PROV_KEY *key)
{
    if (key) return key->handle;
    return CK_UNAVAILABLE_INFORMATION;
}

int p11prov_object_export_public_rsa_key(P11PROV_OBJECT *obj,
                                         OSSL_CALLBACK *cb_fn, void *cb_arg)
{
    OSSL_PARAM params[3] = { { 0 }, { 0 }, OSSL_PARAM_construct_end() };
    int pidx = 0;
    int ret = 0;

    if (!obj->key || obj->key->type != CKK_RSA) return RET_OSSL_ERR;

    for (int i = 0; i < obj->key->numattrs; i++) {
        switch (obj->key->attrs[i].type) {
        case CKA_MODULUS:
            params[0] = OSSL_PARAM_construct_BN(
                            OSSL_PKEY_PARAM_RSA_N,
                            obj->key->attrs[i].pValue,
                            obj->key->attrs[i].ulValueLen);
            break;
        case CKA_PUBLIC_EXPONENT:
            params[1] = OSSL_PARAM_construct_BN(
                            OSSL_PKEY_PARAM_RSA_E,
                            obj->key->attrs[i].pValue,
                            obj->key->attrs[i].ulValueLen);
            break;
        default:
            continue;
        }
    }
    if (!params[0].key || !params[1].key) return RET_OSSL_ERR;

    return cb_fn(params, cb_arg);
}

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

static int parse_attr(const char *str, size_t len,
                      unsigned char **output, size_t *outlen)
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
            if (ret != 0) goto done;

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

#define MAX_PIN_LENGTH 32
static int get_pin(const char *str, size_t len,
                   char **output, size_t *outlen)
{
    char pin[MAX_PIN_LENGTH+1];
    char *pinfile;
    char *filename;
    BIO *fp;
    int ret;

    ret = parse_attr(str, len, (unsigned char **)&pinfile, outlen);
    if (ret != 0) return ret;

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
        p11prov_debug("Failed to get pin from %s\n", filename);
        ret = ENOENT;
        goto done;
    }
    ret = BIO_gets(fp, pin, MAX_PIN_LENGTH);
    if (ret <= 0) {
        p11prov_debug("Failed to get pin from %s (%d)\n", filename, ret);
        ret = EINVAL;
        BIO_free(fp);
        goto done;
    }
    BIO_free(fp);

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

static int parse_uri(struct p11prov_uri *u, const char *uri)
{
    const char *p, *end;
    int ret;

    if (strncmp(uri, "pkcs11:", 7) != 0) {
        return EINVAL;
    }

    p = uri + 7;
    while (p) {
        size_t outlen;
        unsigned char **ptr;
        size_t *ptrlen;
        size_t len;

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
            ptr = (unsigned char **)&u->object;
        } else if (strncmp(p, "id=", 3) == 0) {
            p += 3;
            len -= 3;
            ptr = &u->id;
            ptrlen = &u->id_len;
        } else if (strncmp(p, "pin-value=", 10) == 0) {
            p += 10;
            len -= 10;
            ptr = (unsigned char **)&u->pin;
        } else if (strncmp(p, "pin-source=", 11) == 0) {
            p += 11;
            len -= 11;
            ret = get_pin(p, len, &u->pin, ptrlen);
            if (ret != 0) goto done;
        } else if (strncmp(p, "type=", 5) == 0 ||
                   strncmp(p, "object-type=", 12) == 0) {
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
            } else {
                p11prov_debug("Unknown object type\n");
                ret = EINVAL;
                goto done;
            }
        } else {
            p11prov_debug("Ignoring unkown pkcs11 URI attribute\n");
        }

        if (ptr) {
            ret = parse_attr(p, len, ptr, ptrlen);
            if (ret != 0) goto done;
        }

        if (end) {
            p = end + 1;
        } else {
            p = NULL;
        }
    }

    ret = 0;
done:
    return ret;
}

struct fetch_attrs {
    CK_ATTRIBUTE_TYPE type;
    unsigned char **value;
    unsigned long *value_len;
    bool allocate;
    bool required;
};
#define FA_ASSIGN_ALL(x, _a, _b, _c, _d, _e) \
    do { \
        x.type = _a; \
        x.value = (unsigned char **)_b; \
        x.value_len = _c; \
        x.allocate = _d; \
        x.required = _e; \
    } while(0)

#define FA_RETURN_VAL(x, _a, _b) \
    do { \
        *x.value = _a; \
        *x.value_len = _b; \
    } while(0)

#define FA_RETURN_LEN(x, _a) *x.value_len = _a

#define CKATTR_ASSIGN_ALL(x, _a, _b, _c) \
    do { \
        x.type = _a; \
        x.pValue = (void *)_b; \
        x.ulValueLen = _c; \
    } while(0)

static int object_fetch_attributes(CK_FUNCTION_LIST *f,
                                   CK_SESSION_HANDLE session,
                                   CK_OBJECT_HANDLE object,
                                   struct fetch_attrs *attrs,
                                   unsigned long attrnums)
{
    CK_ATTRIBUTE q[attrnums];
    CK_ATTRIBUTE r[attrnums];
    int ret;

    for (int i = 0; i < attrnums; i++) {
        if (attrs[i].allocate) {
            CKATTR_ASSIGN_ALL(q[i], attrs[i].type, NULL, 0);
        } else {
            CKATTR_ASSIGN_ALL(q[i], attrs[i].type,
                              *attrs[i].value,
                              *attrs[i].value_len);
        }
    }

    /* try one shot, then fallback to individual calls if that fails */
    ret = f->C_GetAttributeValue(session, object, q, attrnums);
    if (ret == CKR_OK) {
        unsigned long retrnums = 0;
        for (int i = 0; i < attrnums; i++) {
            if (q[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                if (attrs[i].required) {
                    return -ENOENT;
                }
                FA_RETURN_LEN(attrs[i], 0);
                continue;
            }
            if (attrs[i].allocate) {
                /* allways allocate and zero one more, so that
                 * zero terminated strings work automatically */
                char *a = OPENSSL_zalloc(q[i].ulValueLen + 1);
                if (a == NULL) return -ENOMEM;
                FA_RETURN_VAL(attrs[i], a, q[i].ulValueLen);

                CKATTR_ASSIGN_ALL(r[retrnums], attrs[i].type,
                                  *attrs[i].value,
                                  *attrs[i].value_len);
                retrnums++;
            } else {
                FA_RETURN_LEN(attrs[i], q[i].ulValueLen);
            }
        }
        if (retrnums > 0) {
            ret = f->C_GetAttributeValue(session, object, r, retrnums);
        }
    } else if (ret == CKR_ATTRIBUTE_SENSITIVE ||
               ret == CKR_ATTRIBUTE_TYPE_INVALID) {
        p11prov_debug("Quering attributes one by one\n");
        /* go one by one as this PKCS11 does not have some attributes
         * and does not handle it gracefully */
        for (int i = 0; i < attrnums; i++) {
            if (attrs[i].allocate) {
                CKATTR_ASSIGN_ALL(q[0], attrs[i].type, NULL, 0);
                ret = f->C_GetAttributeValue(session, object, q, 1);
                if (ret != CKR_OK) {
                    if (attrs[i].required) return ret;
                } else {
                    char *a = OPENSSL_zalloc(q[0].ulValueLen + 1);
                    if (a == NULL) return -ENOMEM;
                    FA_RETURN_VAL(attrs[i], a, q[0].ulValueLen);
                }
            }
            CKATTR_ASSIGN_ALL(r[0], attrs[i].type,
                              *attrs[i].value,
                              *attrs[i].value_len);
            ret = f->C_GetAttributeValue(session, object, r, 1);
            if (ret != CKR_OK) {
                if (r[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                    FA_RETURN_LEN(attrs[i], 0);
                }
                if (attrs[i].required) return ret;
            }
        }
        ret = CKR_OK;
    }
    return ret;
}

static P11PROV_KEY *find_key(CK_FUNCTION_LIST *f, CK_SLOT_ID slotid,
                             CK_OBJECT_CLASS class,
                             const unsigned char *id, size_t id_len,
                             const char *label);

static int fetch_rsa_key(CK_FUNCTION_LIST *f,
                         CK_OBJECT_CLASS class,
                         CK_SESSION_HANDLE session,
                         CK_OBJECT_HANDLE object,
                         P11PROV_KEY *key)
{
    struct fetch_attrs attrs[2];
    unsigned long n_len = 0, e_len = 0;
    CK_BYTE *n = NULL, *e = NULL;
    int ret;

    FA_ASSIGN_ALL(attrs[0], CKA_MODULUS, &n, &n_len, true, true);
    FA_ASSIGN_ALL(attrs[1], CKA_PUBLIC_EXPONENT, &e, &e_len, true, false);
    ret = object_fetch_attributes(f, session, object, attrs, 2);
    if (ret != CKR_OK) return ret;

    if (e_len == 0) {
        OPENSSL_free(n);
        if (class == CKO_PRIVATE_KEY) {
            P11PROV_KEY *pubkey;
            /* let's try to see if there is a public key */
            pubkey = find_key(f, key->slotid, CKO_PUBLIC_KEY,
                              key->id, key->id_len, key->label);
            if (pubkey) {
                key->attrs = pubkey->attrs;
                key->numattrs = pubkey->numattrs;
                pubkey->attrs = NULL;
                pubkey->numattrs = 0;
                return 0;
            }
            p11prov_key_free(pubkey);
        }
        return -EINVAL;
    }

    key->attrs = OPENSSL_zalloc(2 * sizeof(CK_ATTRIBUTE));
    CKATTR_ASSIGN_ALL(key->attrs[0], CKA_MODULUS, n, n_len);
    CKATTR_ASSIGN_ALL(key->attrs[1], CKA_PUBLIC_EXPONENT, e, e_len);
    key->numattrs = 2;

    return 0;
}

/* TODO: may want to have a hashmap with cached keys */
static P11PROV_KEY *object_handle_to_key(CK_FUNCTION_LIST *f,
                                         CK_SLOT_ID slotid,
                                         CK_OBJECT_CLASS class,
                                         CK_SESSION_HANDLE session,
                                         CK_OBJECT_HANDLE object)
{
    P11PROV_KEY *key;
    unsigned long key_type_len = sizeof(CKA_KEY_TYPE);
    unsigned long label_len;
    struct fetch_attrs attrs[4];
    unsigned long attrnums = 3;
    unsigned long aa_len = 0;
    int ret;

    key = p11prov_key_new();
    if (key == NULL) return NULL;

    FA_ASSIGN_ALL(attrs[0], CKA_KEY_TYPE,
                  &key->type, &key_type_len, false, true);
    FA_ASSIGN_ALL(attrs[1], CKA_ID,
                  &key->id, &key->id_len, true, false);
    FA_ASSIGN_ALL(attrs[2], CKA_LABEL,
                  &key->label, &label_len, true, false);
    if (class == CKO_PRIVATE_KEY) {
        aa_len = sizeof(CK_BBOOL);
        FA_ASSIGN_ALL(attrs[3], CKA_ALWAYS_AUTHENTICATE,
                      &key->always_auth, &aa_len, false, false);
        attrnums = 4;
    }
    /* TODO: fetch also other attributes as specified in
     * Spev v3 - 4.9 Private key objects  ?? */

    ret = object_fetch_attributes(f, session, object, attrs, attrnums);
    if (ret != CKR_OK) {
        p11prov_debug("Failed to query object attributes (%d)\n", ret);
        p11prov_key_free(key);
        return NULL;
    }

    key->slotid = slotid;
    key->handle = object;

    if (class == CKO_PRIVATE_KEY) {
        key->private = true;
        if (aa_len == 0) {
            p11prov_debug("Missing CKA_ALWAYS_AUTHENTICATE attribute\n");
        }
    }

    switch (key->type) {
    case CKK_RSA:
        ret = fetch_rsa_key(f, class, session, object, key);
        if (ret != CKR_OK) {
            p11prov_key_free(key);
            return NULL;
        }
        break;
    default:
        /* unknown key type, we can't handle it */
        p11prov_debug("Unsupported key type (%d)\n", key->type);
        p11prov_key_free(key);
        return NULL;
    }

    return key;
}

static P11PROV_KEY *find_key(CK_FUNCTION_LIST *f, CK_SLOT_ID slotid,
                             CK_OBJECT_CLASS class,
                             const unsigned char *id, size_t id_len,
                             const char *label)
{
    CK_SESSION_HANDLE session;
    CK_ATTRIBUTE template[3] = {
        { CKA_CLASS, &class, sizeof(class) },
    };
    CK_ULONG tsize = 1;
    CK_ULONG objcount;
    P11PROV_KEY *key = NULL;
    int ret;

    if (f == NULL) return NULL;

    ret = f->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (ret != CKR_OK) {
        p11prov_debug("OpenSession failed %d\n", ret);
        /* TODO: Err message */
        return NULL;
    }

    if (id_len) {
        CKATTR_ASSIGN_ALL(template[tsize], CKA_ID,
                          id, id_len);
        tsize++;
    }
    if (label) {
        CKATTR_ASSIGN_ALL(template[tsize], CKA_LABEL,
                          label, strlen(label));
        tsize++;
    }

    ret = f->C_FindObjectsInit(session, template, tsize);
    if (ret == CKR_OK) {
        do {
            CK_OBJECT_HANDLE object;
            /* TODO: pull multiple objects at once to reduce roundtrips */
            ret = f->C_FindObjects(session, &object, 1, &objcount);
            if (ret != CKR_OK) break;

            key = object_handle_to_key(f, slotid, class, session, object);

            /* we'll get the first that parses fine */
            if (key) break;

        } while (objcount > 0);

        (void)f->C_FindObjectsFinal(session);
    }

    if (ret != CKR_OK) {
        /* TODO: Err message */
        p11prov_debug("Failed to search keys\n");
    }

    ret = f->C_CloseSession(session);
    if (ret != CKR_OK) {
        p11prov_debug("Failed to close session (%d)\n", ret);
    }

    return key;
}

static OSSL_FUNC_store_open_fn p11prov_object_open;
static OSSL_FUNC_store_attach_fn p11prov_object_attach;
static OSSL_FUNC_store_load_fn p11prov_object_load;
static OSSL_FUNC_store_eof_fn p11prov_object_eof;
static OSSL_FUNC_store_close_fn p11prov_object_close;
static OSSL_FUNC_store_export_object_fn p11prov_object_export;

static void *p11prov_object_open(void *provctx, const char *uri)
{
    PROVIDER_CTX *ctx = (PROVIDER_CTX *)provctx;
    P11PROV_OBJECT *obj;
    int ret;

    p11prov_debug("object open (%p, %s)\n", ctx, uri);

    obj = OPENSSL_zalloc(sizeof(P11PROV_OBJECT));
    if (obj == NULL) return NULL;

    obj->parsed_uri = OPENSSL_zalloc(sizeof(struct p11prov_uri));
    if (obj->parsed_uri == NULL) {
        p11prov_object_free(obj);
        return NULL;
    }

    ret = parse_uri(obj->parsed_uri, uri);
    if (ret != 0) {
        p11prov_object_free(obj);
        return NULL;
    }

    obj->provctx = ctx;
    obj->refcnt = 1;

    return obj;
}

static void *p11prov_object_attach(void *provctx, OSSL_CORE_BIO *in)
{
    PROVIDER_CTX *ctx = (PROVIDER_CTX *)provctx;

    p11prov_debug("object attach (%p, %p)\n", ctx, in);

    return NULL;
}

static int p11prov_object_load(void *ctx,
                               OSSL_CALLBACK *object_cb, void *object_cbarg,
                               OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)ctx;
    struct p11prov_slot *slots = NULL;
    int nslots = 0;

    p11prov_debug("object load (%p)\n", obj);

    nslots = provider_ctx_lock_slots(obj->provctx, &slots);

    for (int i = 0; i < nslots; i++) {
	CK_TOKEN_INFO token;

        /* ignore slots that are not initialized */
        if (slots[i].slot.flags & CKF_TOKEN_PRESENT == 0) continue;
        if (slots[i].token.flags & CKF_TOKEN_INITIALIZED == 0) continue;

        token = slots[i].token;

        /* skip slots that do not match */
        if (obj->parsed_uri->model &&
            strncmp(obj->parsed_uri->model, token.model, 16) != 0)
            continue;
        if (obj->parsed_uri->manufacturer &&
            strncmp(obj->parsed_uri->manufacturer,
                    token.manufacturerID, 32) != 0)
            continue;
        if (obj->parsed_uri->token &&
            strncmp(obj->parsed_uri->token, token.label, 32) != 0)
            continue;
        if (obj->parsed_uri->serial &&
            strncmp(obj->parsed_uri->serial, token.serialNumber, 16) != 0)
            continue;

        /* FIXME: handle login required */
        if (token.flags & CKF_LOGIN_REQUIRED) continue;

        /* match class */
        if (obj->parsed_uri->class == CKO_CERTIFICATE) {
            /* not yet */
            continue;
        } else if (obj->parsed_uri->class == CKO_PUBLIC_KEY ||
                   obj->parsed_uri->class == CKO_PRIVATE_KEY) {
            CK_FUNCTION_LIST *f = provider_ctx_fns(obj->provctx);
            obj->key = find_key(f, slots[i].id,
                                obj->parsed_uri->class,
                                obj->parsed_uri->id,
                                obj->parsed_uri->id_len,
                                obj->parsed_uri->object);
        }
        /* for keys return on first match */
        if (obj->key) break;
    }

    provider_ctx_unlock_slots(obj->provctx, &slots);

    obj->loaded = 1;

    if (obj->key) {
        OSSL_PARAM params[4];
        int object_type = OSSL_OBJECT_PKEY;
        char *type;

        params[0] = OSSL_PARAM_construct_int(
                        OSSL_OBJECT_PARAM_TYPE, &object_type);

        /* we only support RSA so far */
        switch (obj->key->type) {
        case CKK_RSA:
            /* we have to handle private keys as our own type,
             * while we can let openssl import public keys and
             * deal with them in the default provider */
            if (obj->key->private) type = P11PROV_NAMES_RSA;
            else type = "RSA";
            break;
        default:
            return RET_OSSL_ERR;
        }
        params[1] = OSSL_PARAM_construct_utf8_string(
                        OSSL_OBJECT_PARAM_DATA_TYPE, type, 0);

        /* giving away the object by reference */
        params[2] = OSSL_PARAM_construct_octet_string(
                        OSSL_OBJECT_PARAM_REFERENCE,
                        p11prov_object_ref(obj), sizeof(obj));
        params[3] = OSSL_PARAM_construct_end();

        return object_cb(params, object_cbarg);
    }

    return RET_OSSL_ERR;
}

static int p11prov_object_eof(void *ctx)
{
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)ctx;

    p11prov_debug("object eof (%p)\n", obj);

    return obj->loaded?1:0;
}

static int p11prov_object_close(void *ctx)
{
    P11PROV_OBJECT *obj = (P11PROV_OBJECT *)ctx;

    p11prov_debug("object close (%p)\n", obj);

    if (obj == NULL) return 0;

    p11prov_object_free(obj);
    return 1;
}

static int p11prov_set_ctx_params(void *loaderctx, const OSSL_PARAM params[])
{
    p11prov_debug("set ctx params (%p, %p)\n", loaderctx, params);

    return 1;
}

static int p11prov_object_export(void *loaderctx, const void *reference,
                                 size_t reference_sz, OSSL_CALLBACK *cb_fn,
                                 void *cb_arg)
{
    P11PROV_OBJECT *obj = NULL;

    p11prov_debug("object export %p, %ld\n", reference, reference_sz);

    if (!reference || reference_sz != sizeof(obj))
        return 0;

    /* the contents of the reference is the address to our object */
    obj = (P11PROV_OBJECT *)reference;

    /* we can only export public bits, so that's all we do */
    return p11prov_object_export_public_rsa_key(obj, cb_fn, cb_arg);
}


const OSSL_DISPATCH p11prov_object_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN, (void(*)(void))p11prov_object_open },
    { OSSL_FUNC_STORE_ATTACH, (void(*)(void))p11prov_object_attach },
    { OSSL_FUNC_STORE_LOAD, (void(*)(void))p11prov_object_load },
    { OSSL_FUNC_STORE_EOF, (void(*)(void))p11prov_object_eof },
    { OSSL_FUNC_STORE_CLOSE, (void(*)(void))p11prov_object_close },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS, (void(*)(void))p11prov_set_ctx_params },
    { OSSL_FUNC_STORE_EXPORT_OBJECT, (void(*)(void))p11prov_object_export },
    { 0, NULL }
};

