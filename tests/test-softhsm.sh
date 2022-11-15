#!/bin/bash -e
# Copyright (C) 2022 Jakub Jelen <jjelen@redhat.com>
# SPDX-License-Identifier: Apache-2.0

source ./tmp.softhsm/testvars
# The SoftHSM does not work directly with openssl applications because
# of problematic initialization/cleanups
./softhsm-proxy.sh ./test.sh
