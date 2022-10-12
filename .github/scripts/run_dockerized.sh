#!/bin/bash -ex

COMPILER=${COMPILER:-gcc}

docker run \
       -v $(pwd):/tmp/build \
       -w /tmp/build \
       -e COMPILER=$COMPILER \
       $DISTRO /bin/bash -ex ./.github/scripts/ci.sh
