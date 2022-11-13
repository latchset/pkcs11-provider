#!/bin/bash -e
# Copyright (C) 2022 Jakub Jelen <jjelen@redhat.com>
# SPDX-License-Identifier: Apache-2.0

SOURCE_PATH=${SOURCE_PATH:-..}

TEST_SETUP_SKIP_KEYS=1
source $SOURCE_PATH/tests/setup-softokn.sh
./tdigests
