/* Copyright (C) 2023 Jakub Jelen <jjelen@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>

extern int dlclose(void *handle);

int dlclose(void *handle)
{
    return 0;
}
