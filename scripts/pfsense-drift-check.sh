#!/bin/sh
# Does router run the configuration committed in this repo?
#
# Run by the Cronicle event "pfsense-iac Drift Check" (a six-line bootstrap
# that clones this repo and execs this script), in the Cronicle pod — POSIX
# sh on purpose, that pod is Alpine and has no bash.
#
# The router side is a forced command: the `pfsense-drift` key on `admin` can
# only run router/export-config.php, which prints the configuration already
# normalised and REDACTED. Secrets never leave the router, not even to here.
#
# Verdicts, and what each one pushes to Kuma:
#   0  identical to config/config.xml          -> up
#   1  differs                                 -> down, with the NAMES of the
#                                                 sections that differ, never
#                                                 their content
#   2  could not compare (ssh failed, empty or -> nothing pushed: "cannot
#      malformed export)                          check" is not "drifted", and
#                                                 the monitor fires on the
#                                                 missing heartbeat instead
#
# Environment (the Cronicle event supplies these; nothing secret is in git):
#   KUMA_PUSH_URL   push monitor. Absent -> no heartbeat, said out loud.
#   PFSENSE_KEY     private half of the pfsense-drift key
#   PFSENSE_HOST    default router.lab.example
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
KEY=${PFSENSE_KEY:-/keys/pfsense-drift/id_ed25519}
HOST=${PFSENSE_HOST:-router.lab.example}
KUMA_PUSH_URL=${KUMA_PUSH_URL:-}
DECLARED="$ROOT/config/config.xml"

push() { # push <up|down> <msg>
  [ -n "$KUMA_PUSH_URL" ] || { echo "pfsense-drift: no KUMA_PUSH_URL — no heartbeat pushed"; return 0; }
  curl -fsSk -G "$KUMA_PUSH_URL" --data-urlencode "status=$1" --data-urlencode "msg=$2" >/dev/null \
    || echo "pfsense-drift: kuma push failed (non-fatal)"
}

live=$(mktemp "${TMPDIR:-/tmp}/pfsense-live.XXXXXX")
trap 'rm -f "$live"' EXIT

# The host key is pinned in the repo: an export that came from anything else
# is not an answer about router.
if ! ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=15 \
        -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$ROOT/router/known_hosts" \
        "admin@$HOST" export > "$live" 2>/dev/null; then
  echo "pfsense-drift: could not export from $HOST — no verdict"
  exit 2
fi
# An empty or truncated export must not read as "everything changed".
if [ ! -s "$live" ] || ! grep -q '</pfsense>' "$live"; then
  echo "pfsense-drift: export from $HOST is empty or truncated — no verdict"
  exit 2
fi

if cmp -s "$live" "$DECLARED"; then
  echo "pfsense-drift: router matches config/config.xml"
  push up "router matches git"
  exit 0
fi

changed=$(python3 "$HERE/sections-diff.py" "$DECLARED" "$live" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
[ -n "$changed" ] || changed="(unparseable — see a manual export)"
echo "pfsense-drift: DRIFT in sections: $changed"
push down "pfsense drift: $changed differ from git — run scripts/pull-config.sh"
exit 1
