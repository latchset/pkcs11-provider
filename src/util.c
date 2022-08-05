/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include <string.h>

int p11prov_fetch_attributes(CK_FUNCTION_LIST *f, CK_SESSION_HANDLE session,
                             CK_OBJECT_HANDLE object, struct fetch_attrs *attrs,
                             unsigned long attrnums)
{
    CK_ATTRIBUTE q[attrnums];
    CK_ATTRIBUTE r[attrnums];
    int ret;

    for (size_t i = 0; i < attrnums; i++) {
        if (attrs[i].allocate) {
            CKATTR_ASSIGN_ALL(q[i], attrs[i].type, NULL, 0);
        } else {
            CKATTR_ASSIGN_ALL(q[i], attrs[i].type, *attrs[i].value,
                              *attrs[i].value_len);
        }
    }

    /* try one shot, then fallback to individual calls if that fails */
    ret = f->C_GetAttributeValue(session, object, q, attrnums);
    if (ret == CKR_OK) {
        unsigned long retrnums = 0;
        for (size_t i = 0; i < attrnums; i++) {
            if (q[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                if (attrs[i].required) {
                    return -ENOENT;
                }
                FA_RETURN_LEN(attrs[i], 0);
                continue;
            }
            if (attrs[i].allocate) {
                /* always allocate and zero one more, so that
                 * zero terminated strings work automatically */
                uint8_t *a = OPENSSL_zalloc(q[i].ulValueLen + 1);
                if (a == NULL) {
                    return -ENOMEM;
                }
                FA_RETURN_VAL(attrs[i], a, q[i].ulValueLen);

                CKATTR_ASSIGN_ALL(r[retrnums], attrs[i].type, *attrs[i].value,
                                  *attrs[i].value_len);
                retrnums++;
            } else {
                FA_RETURN_LEN(attrs[i], q[i].ulValueLen);
            }
        }
        if (retrnums > 0) {
            ret = f->C_GetAttributeValue(session, object, r, retrnums);
        }
    } else if (ret == CKR_ATTRIBUTE_SENSITIVE
               || ret == CKR_ATTRIBUTE_TYPE_INVALID) {
        p11prov_debug("Quering attributes one by one\n");
        /* go one by one as this PKCS11 does not have some attributes
         * and does not handle it gracefully */
        for (size_t i = 0; i < attrnums; i++) {
            if (attrs[i].allocate) {
                CKATTR_ASSIGN_ALL(q[0], attrs[i].type, NULL, 0);
                ret = f->C_GetAttributeValue(session, object, q, 1);
                if (ret != CKR_OK) {
                    if (attrs[i].required) {
                        return ret;
                    }
                } else {
                    uint8_t *a = OPENSSL_zalloc(q[0].ulValueLen + 1);
                    if (a == NULL) {
                        return -ENOMEM;
                    }
                    FA_RETURN_VAL(attrs[i], a, q[0].ulValueLen);
                }
            }
            CKATTR_ASSIGN_ALL(r[0], attrs[i].type, *attrs[i].value,
                              *attrs[i].value_len);
            ret = f->C_GetAttributeValue(session, object, r, 1);
            if (ret != CKR_OK) {
                if (r[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                    FA_RETURN_LEN(attrs[i], 0);
                }
                if (attrs[i].required) {
                    return ret;
                }
            }
            p11prov_debug("Attribute| type:%lu value:%p, len:%lu\n",
                          attrs[i].type, *attrs[i].value, *attrs[i].value_len);
        }
        ret = CKR_OK;
    }
    return ret;
}

struct p11prov_uri {
    char *model;
    char *manufacturer;
    char *token;
    char *serial;
    char *object;
    CK_ATTRIBUTE id;
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

    /* files may contain newlines, remove any control chracter at the end */
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

P11PROV_URI *p11prov_parse_uri(const char *uri)
{
    struct p11prov_uri *u;
    const char *p, *end;
    int ret;

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
        bool id_fill = false;

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
            ptr = (unsigned char **)&u->id.pValue;
            id_fill = true;
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
            } else if (len == 7 && strncmp(p, "secret", 7) == 0) {
                u->class = CKO_SECRET_KEY;
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
            if (ret != 0) {
                goto done;
            }
            if (id_fill) {
                u->id.type = CKA_ID;
                u->id.ulValueLen = outlen;
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
    OPENSSL_free(uri->object);
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

char *p11prov_uri_get_object(P11PROV_URI *uri)
{
    return uri->object;
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

static CK_RV match_token(CK_TOKEN_INFO *token, P11PROV_URI *uri)
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

static CK_RV token_login(P11PROV_CTX *provctx, CK_SLOT_ID slotid,
                         P11PROV_URI *uri, OSSL_PASSPHRASE_CALLBACK *pw_cb,
                         void *pw_cbarg)
{
    CK_SESSION_HANDLE s;
    CK_FUNCTION_LIST *f;
    char cb_pin[MAX_PIN_LENGTH + 1] = { 0 };
    size_t cb_pin_len = 0;
    CK_UTF8CHAR_PTR pin = NULL;
    CK_ULONG pinlen = 0;
    CK_RV ret;

    ret = p11prov_ctx_get_login_session(provctx, &s);
    if (ret != CKR_OK) {
        return ret;
    }
    if (s != CK_INVALID_HANDLE) {
        /* we already have a login_session */
        return CKR_OK;
    }

    f = p11prov_ctx_fns(provctx);
    if (f == NULL) {
        return CKR_FUNCTION_FAILED;
    }
    if (uri->pin) {
        pin = (CK_UTF8CHAR_PTR)uri->pin;
    } else {
        pin = p11prov_ctx_pin(provctx);
    }
    if (pin) {
        pinlen = strlen((const char *)pin);
    } else if (pw_cb) {
        const char *info = "PKCS#11 Token";
        OSSL_PARAM params[2] = {
            OSSL_PARAM_DEFN(OSSL_PASSPHRASE_PARAM_INFO, OSSL_PARAM_UTF8_STRING,
                            (void *)info, sizeof(info)),
            OSSL_PARAM_END,
        };
        ret = pw_cb(cb_pin, sizeof(cb_pin), &cb_pin_len, params, pw_cbarg);
        if (ret != RET_OSSL_OK) {
            return CKR_GENERAL_ERROR;
        }

        pin = (CK_UTF8CHAR_PTR)cb_pin;
        pinlen = cb_pin_len;
    } else {
        return CKR_GENERAL_ERROR;
    }

    ret = f->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL, &s);
    if (ret != CKR_OK) {
        P11PROV_raise(provctx, ret, "Failed to open session on slot %lu",
                      slotid);
        goto done;
    }

    /* Supports only USER login sessions for now */
    ret = f->C_Login(s, CKU_USER, pin, pinlen);
    if (ret != CKR_OK && ret != CKR_USER_ALREADY_LOGGED_IN) {
        int retc;
        P11PROV_raise(provctx, ret, "Error returned by C_Login");
        retc = f->C_CloseSession(s);
        if (retc != CKR_OK) {
            P11PROV_raise(provctx, retc, "Failed to close session %lu", s);
        }
        goto done;
    }

    ret = p11prov_ctx_set_login_session(provctx, s);
done:
    OPENSSL_cleanse(cb_pin, cb_pin_len);
    return ret;
}

CK_RV p11prov_get_session(P11PROV_CTX *provctx, CK_SLOT_ID *slotid,
                          CK_SLOT_ID *next_slotid, P11PROV_URI *uri,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
                          CK_SESSION_HANDLE *session)
{
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_SLOT_ID id = *slotid;
    CK_FUNCTION_LIST *f;
    struct p11prov_slot *slots = NULL;
    int nslots = 0;
    int i;
    CK_RV ret = CKR_CANCEL;

    nslots = p11prov_ctx_lock_slots(provctx, &slots);

    for (i = 0; i < nslots; i++) {
        if (id != CK_UNAVAILABLE_INFORMATION && id != slots[i].id) {
            continue;
        }

        /* ignore slots that are not initialized */
        if ((slots[i].slot.flags & CKF_TOKEN_PRESENT) == 0) {
            continue;
        }
        if ((slots[i].token.flags & CKF_TOKEN_INITIALIZED) == 0) {
            continue;
        }

        id = slots[i].id;
        ret = CKR_OK;

        if (uri) {
            CK_TOKEN_INFO token = slots[i].token;

            /* skip slots that do not match */
            ret = match_token(&token, uri);
            if (ret == CKR_CANCEL) {
                continue;
            }
            if (ret == CKR_OK && (token.flags & CKF_LOGIN_REQUIRED)) {
                ret = token_login(provctx, id, uri, pw_cb, pw_cbarg);
            }
        }
        break;
    }

    if (ret == CKR_OK) {
        /* Found a slot, return it and the next slot to the caller for
         * continuation if the current slot does not yield the desired
         * results */
        *slotid = id;
        if (next_slotid) {
            if (i + 1 < nslots) {
                *next_slotid = slots[i + 1].id;
            } else {
                *next_slotid = CK_UNAVAILABLE_INFORMATION;
            }
        }
    } else {
        *next_slotid = CK_UNAVAILABLE_INFORMATION;
    }

    p11prov_ctx_unlock_slots(provctx, &slots);

    if (ret != CKR_OK) {
        return ret;
    }

    f = p11prov_ctx_fns(provctx);
    if (f == NULL) {
        return CKR_GENERAL_ERROR;
    }

    ret = f->C_OpenSession(id, CKF_SERIAL_SESSION, NULL, NULL, &sess);
    if (ret != CKR_OK) {
        P11PROV_raise(provctx, ret, "Failed to open session on slot %lu", id);
        return ret;
    }
    *session = sess;
    return CKR_OK;
}

void p11prov_put_session(P11PROV_CTX *provctx, CK_SESSION_HANDLE session)
{
    CK_FUNCTION_LIST *f;
    CK_RV ret;

    f = p11prov_ctx_fns(provctx);
    if (f == NULL) {
        return;
    }

    ret = f->C_CloseSession(session);
    if (ret != CKR_OK) {
        P11PROV_raise(provctx, ret, "Failed to close session %lu", session);
    }
}
