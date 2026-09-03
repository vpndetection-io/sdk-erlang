#!/bin/bash

# Publishes the package to Hex from inside the official Erlang image, so a
# release needs nothing installed locally beyond docker and works identically on
# any machine. The release workflow does the same steps on a tag; this is the
# manual path for a first release or when Actions is not an option.
#
#   HEX_API_KEY=... ./scripts/publish.sh            # publish
#   HEX_API_KEY=... DRY_RUN=1 ./scripts/publish.sh  # rehearse
#
# Create the key on hex.pm under Dashboard -> Keys with the `api:write`
# permission. It must work WITHOUT an interactive confirmation, which is what
# --yes covers here.
#
# --repo hexpm is REQUIRED, not decoration: without it rebar3_hex takes a code
# path that never merges the environment into the repo config, so HEX_API_KEY is
# ignored and the run fails with "No write key found for user. Be sure to
# authenticate first with: rebar3 hex user auth".
#
# Every release needs the key. Unlike npm, PyPI, RubyGems and crates.io, hex.pm
# publishes no OIDC/trusted-publishing path, so there is no credential-free
# option to graduate to once the package exists.

set -euo pipefail

cd "$(dirname "$0")/.."

OTP_IMAGE="${OTP_IMAGE:-erlang:27}"
DRY_RUN="${DRY_RUN:-}"

publish_args="--yes"
if [ -n "$DRY_RUN" ] ; then
    publish_args="$publish_args --dry-run"
else
    : "${HEX_API_KEY:?set HEX_API_KEY to a hex.pm key with api:write}"
fi

# The working tree is mounted READ ONLY and copied inside, so _build, the hex
# cache and root-owned artifacts stay in the container rather than landing in
# the repo.
docker run --rm \
    -v "$PWD:/src:ro" \
    -e HOME=/tmp \
    -e LANG=C.UTF-8 \
    -e HEX_API_KEY="${HEX_API_KEY:-}" \
    "$OTP_IMAGE" sh -euc "
        cp -R /src /w
        cd /w
        rebar3 eunit
        rebar3 as publish hex publish --repo hexpm ${publish_args}
    "
