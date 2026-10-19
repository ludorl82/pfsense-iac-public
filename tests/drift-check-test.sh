#!/bin/sh
# Tests for scripts/pfsense-drift-check.sh — its three verdicts, and what
# reaches Kuma for each.
#
#   sh tests/drift-check-test.sh
#
# What has to be true, and why:
#   * identical -> 0 and an "up" heartbeat.
#   * different -> 1 and a "down" naming the SECTIONS that differ — and never
#     a value from them: that message ends up in Kuma and on a phone.
#   * ssh failure, empty export, truncated export -> 2 and NO heartbeat.
#     Cannot check is not drifted; the monitor fires on the missing beat.
# Nothing touches the network: ssh and curl are stubs on PATH.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/pfdrift-test.XXXXXX"); trap 'rm -rf "$T"' EXIT
pass=0; fail=0
ok()  { printf '  ok    %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  FAIL  %s\n        %s\n' "$1" "$2"; fail=$((fail+1)); }

# a copy of the repo with a small declared config
mkdir -p "$T/repo/config" "$T/repo/router" "$T/repo/scripts" "$T/bin"
cp "$REPO/scripts/pfsense-drift-check.sh" "$REPO/scripts/sections-diff.py" "$T/repo/scripts/"
: > "$T/repo/router/known_hosts"
cat > "$T/repo/config/config.xml" <<'X'
<?xml version="1.0"?>
<pfsense>
	<system><hostname>router</hostname></system>
	<unbound><hosts><host>bob</host><ip>192.0.2.5</ip></hosts></unbound>
	<filter><rule><descr>allow lan</descr></rule></filter>
</pfsense>
X
cat > "$T/bin/ssh" <<'X'
#!/bin/sh
[ -n "${STUB_FAIL:-}" ] && exit 255
cat "$STUB_EXPORT"
X
cat > "$T/bin/curl" <<'X'
#!/bin/sh
for a in "$@"; do printf '%s\n' "$a"; done >> "$STUB_PUSHES"
X
chmod +x "$T/bin/ssh" "$T/bin/curl"

run() { # run <export-file> -> sets RC, OUT, PUSH
  : > "$T/pushes"
  OUT=$(PATH="$T/bin:$PATH" STUB_EXPORT="$1" STUB_PUSHES="$T/pushes" STUB_FAIL="${2:-}" \
        KUMA_PUSH_URL="https://kuma.example/api/push/x" PFSENSE_KEY=/dev/null \
        sh "$T/repo/scripts/pfsense-drift-check.sh" 2>&1); RC=$?
  PUSH=$(cat "$T/pushes")
}

echo "pfsense-drift-check.sh"

cp "$T/repo/config/config.xml" "$T/same.xml"; run "$T/same.xml"
[ $RC = 0 ] && echo "$PUSH" | grep -q "status=up" && ok "identical -> 0, up" || bad "identical -> 0, up" "rc=$RC push=$PUSH"

sed 's#192.0.2.5#192.0.2.99#' "$T/repo/config/config.xml" > "$T/dns.xml"; run "$T/dns.xml"
[ $RC = 1 ] && echo "$PUSH" | grep -q "status=down" && echo "$PUSH" | grep -q "unbound" \
  && ok "a changed host override -> 1, down, names 'unbound'" || bad "changed -> 1" "rc=$RC push=$PUSH"
echo "$PUSH" | grep -q "192.0.2.99" && bad "the Kuma message carries no value" "leaked: $PUSH" || ok "the Kuma message carries no value"
echo "$PUSH" | grep -q "filter\|system" && bad "only the changed section is named" "$PUSH" || ok "only the changed section is named"

sed 's#<filter>.*</filter>##' "$T/repo/config/config.xml" > "$T/gone.xml"; run "$T/gone.xml"
[ $RC = 1 ] && echo "$PUSH" | grep -q "filter" && ok "a section that disappeared is named" || bad "a section that disappeared is named" "rc=$RC push=$PUSH"

run "$T/same.xml" fail
[ $RC = 2 ] && [ -z "$PUSH" ] && ok "ssh fails -> 2, no heartbeat" || bad "ssh fails -> 2, no heartbeat" "rc=$RC push=$PUSH"

: > "$T/empty.xml"; run "$T/empty.xml"
[ $RC = 2 ] && [ -z "$PUSH" ] && ok "empty export -> 2, no heartbeat" || bad "empty export -> 2" "rc=$RC push=$PUSH"

head -n 3 "$T/repo/config/config.xml" > "$T/trunc.xml"; run "$T/trunc.xml"
[ $RC = 2 ] && [ -z "$PUSH" ] && ok "truncated export -> 2, no heartbeat" || bad "truncated export -> 2" "rc=$RC push=$PUSH"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
