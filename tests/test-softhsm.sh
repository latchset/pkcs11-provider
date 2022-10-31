#!/bin/bash -e
# Copyright (C) 2022 Jakub Jelen <jjelen@redhat.com>
# SPDX-License-Identifier: Apache-2.0

# The SoftHSM does not work directly with openssl applications because
# of problematic initialization/cleanups
TEST_SETUP_USE_PROXY=1
source $SOURCE_PATH/tests/setup-softhsm.sh
source $SOURCE_PATH/tests/test.sh
