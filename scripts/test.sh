#!/bin/bash

# Builds and tests inside the official Erlang image, so nothing has to be
# installed locally beyond docker.
#
#   ./scripts/test.sh                        # the OTP floor
#   OTP_IMAGE=erlang:29 ./scripts/test.sh    # any other release in the matrix
#   ./scripts/test.sh dialyzer               # or any other rebar3 command
#
# The working tree is mounted READ ONLY and copied inside, so _build, the hex
# cache and root-owned artifacts stay in the container rather than landing in
# the repo. Any _build that DID land in the repo is dropped from the copy: a
# stale one carries beams that rebar3 keeps rather than rebuilds, and the suite
# then passes against code that is no longer there.

set -euo pipefail

cd "$(dirname "$0")/.."

OTP_IMAGE="${OTP_IMAGE:-erlang:27}"
CMD="${*:-eunit}"

docker run --rm \
    -v "$PWD:/src:ro" \
    -e HOME=/tmp \
    -e LANG=C.UTF-8 \
    "$OTP_IMAGE" sh -euc "
        cp -R /src /w
        cd /w
        rm -rf _build
        rebar3 ${CMD}
    "
