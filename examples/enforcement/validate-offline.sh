#!/bin/sh
# Offline validator for the synthetic killed controlled-enforcement example.
set -eu

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT INT TERM

install -d -m 0700 "$temporary/kill"
trust_root=$(CDPATH= cd -- "$temporary/kill" && pwd -P)
printf 'bypass\n' >"$trust_root/state"
chmod 0600 "$trust_root/state"
TRUST_ROOT="$trust_root" perl -pe '
  BEGIN {
    $quoted = $ENV{TRUST_ROOT};
    $quoted =~ s/([\\"])/\\$1/g;
    $quoted = qq{"$quoted"};
  }
  s/__TRUST_ROOT__/$quoted/g;
' "$here/enforcement.killed.yaml" >"$temporary/enforcement.yaml"

grep -Fq 'authorization_path: private/authorization/synthetic-support-chat.json' \
  "$temporary/enforcement.yaml"
test ! -e "$temporary/private/authorization/synthetic-support-chat.json"

binary=${BOWLINE_BIN:-bowline}
"$binary" kill bypass --enforcement "$temporary/enforcement.yaml"
test "$(sed -n '1p' "$trust_root/state")" = bypass
test ! -e "$temporary/private/authorization/synthetic-support-chat.json"
printf '%s\n' 'synthetic enforcement offline validation: PASS'
