#!/bin/bash -e

cd "$MESON_DIST_ROOT"

# Remove the submodules
rm -rf tlsfuzzer python-ecdsa tlslite-ng
