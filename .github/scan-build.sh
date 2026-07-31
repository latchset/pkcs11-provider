#!/bin/sh
scan-build --html-title="PKCS#11 Provider ($GITHUB_SHA)" \
           --keep-cc \
           --status-bugs \
           --keep-going \
           "$@"
