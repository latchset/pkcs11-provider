/* Copyright (C) 2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/ui.h>
#include "util.h"

struct ui_data {
    bool nopin;
};

static int ui_read_string(UI *ui, UI_STRING *uis)
{
    struct ui_data *user_data;
    const char *pinvalue;
    enum UI_string_types type;

    user_data = (struct ui_data *)UI_get0_user_data(ui);
    if (user_data->nopin) {
        fprintf(stderr, "Unexpected request for PIN value");
        exit(EXIT_FAILURE);
    }

    pinvalue = getenv("PINVALUE");
    if (!pinvalue) {
        fprintf(stderr, "PINVALUE not defined\n");
        exit(EXIT_FAILURE);
    }

    type = UI_get_string_type(uis);
    switch (type) {
    case UIT_PROMPT:
        fprintf(stderr, "Prompt: \"%s\"\n", UI_get0_output_string(uis));
        fprintf(stderr, "Returning: %s\n", pinvalue);
        UI_set_result(ui, uis, pinvalue);
        return 1;
    default:
        fprintf(stderr, "Unexpected UI type: %d\n", (int)type);
        exit(EXIT_FAILURE);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    struct ui_data user_data = { 0 };
    UI_METHOD *ui_method = NULL;
    X509 *cert = NULL;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s [certuri] <nopin>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (argc > 2) {
        if (strcmp(argv[2], "nopin")) {
            fprintf(stderr, "Invalid argument: '%s'\n", argv[2]);
            fprintf(stderr, "Usage: %s [certuri] <nopin>\n", argv[0]);
            exit(EXIT_FAILURE);
        } else {
            user_data.nopin = true;
        }
    }

    ui_method = UI_create_method("Load cert test");
    if (!ui_method) {
        fprintf(stderr, "Failed to set up UI_METHOD\n");
        exit(EXIT_FAILURE);
    }
    (void)UI_method_set_reader(ui_method, ui_read_string);

    cert = load_cert(argv[1], ui_method, &user_data);

    fprintf(stderr, "Cert load successfully\n");

    X509_free(cert);
    exit(EXIT_SUCCESS);
}
