#!/bin/sh
# Make the lists router's data/*.yaml declares equal on the router:
# host overrides, DHCP mappings, aliases, rules, NAT, gateways, static routes.
#
#   scripts/pfsense-apply.sh            check: print what would change, write nothing
#   scripts/pfsense-apply.sh --apply    apply, then record the result in git
#
# Run by hand from the console, on an up-to-date cp-1 — the blast radius is
# the whole house (DNS for every .lab.example name, every DHCP lease), so a
# human presses the button. Before an apply: close pfSense UI tabs (a stale
# tab reverted months of work on one form submit, 2026-07-11) and keep
# net-cfgs/router-config-restore.md open.
#
# Every apply is CONFIRMED: the router arms a rollback (ROLLBACK_SECS, default
# 120 s) before this script returns; this script then opens a NEW ssh session
# and checks DNS and the internet from the console. Only if all of that works
# does it confirm. If the change cut the console off, nothing confirms and the
# router puts its previous lists back by itself.
#
# Refuses to write when:
#   * the router differs from config/config.xml — someone changed it by hand;
#     a whole-list apply would silently undo that. Run pull-config.sh first.
#   * /root/scripts/data.php on the router is not router/data.php — run
#     scripts/install-router.sh.
#   * the data does not lint, or (apply) cp-1 is not clean and pushed.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
KEY=${ADMIN_KEY:-$HOME/.ssh/id_ed25519_console}
HOST=${PFSENSE_HOST:-router.lab.example}
MODE=check; [ "${1:-}" = "--apply" ] && MODE=apply
cd "$ROOT"

pf() {
  ssh -4 -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 \
      -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$ROOT/router/known_hosts" "admin@$HOST" "$@"
}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/pfsense-apply.XXXXXX"); trap 'rm -rf "$tmp"' EXIT

if [ "$MODE" = apply ]; then
  [ "$(git branch --show-current)" = cp-1 ] || { echo "apply: not on cp-1" >&2; exit 1; }
  [ -z "$(git status --porcelain)" ] || { echo "apply: working tree not clean" >&2; exit 1; }
  git fetch -q origin cp-1
  [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/cp-1)" ] || { echo "apply: cp-1 is not origin/cp-1 — pull first" >&2; exit 1; }
fi

python3 scripts/pfsense_data.py to-json > "$tmp/want.json"

want_sum=$(sha256sum router/data.php | cut -c1-64)
have_sum=$(pf "sha256 -q /root/scripts/data.php" 2>/dev/null || true)
[ "$want_sum" = "$have_sum" ] || { echo "router/data.php on router is not this repo's — run scripts/install-router.sh" >&2; exit 1; }

pf /usr/local/bin/php /root/scripts/export-config.php > "$tmp/live.xml"
if ! cmp -s "$tmp/live.xml" config/config.xml; then
  echo "router differs from config/config.xml in: $(python3 scripts/sections-diff.py config/config.xml "$tmp/live.xml" | tr '\n' ' ')" >&2
  echo "Someone changed it outside git. Run scripts/pull-config.sh and merge that first." >&2
  exit 1
fi

rev=$(git rev-parse --short HEAD)
if [ "$MODE" = check ]; then
  pf /usr/local/bin/php /root/scripts/data.php check < "$tmp/want.json"
  exit 0
fi

SECS=${ROLLBACK_SECS:-120}
pf /usr/local/bin/php /root/scripts/data.php apply "$rev" "$SECS" < "$tmp/want.json" | tee "$tmp/out"
grep -q '^applied:' "$tmp/out" || exit 0      # "no change"
token=$(sed -n 's/^confirm-token: //p' "$tmp/out")
[ -n "$token" ] || { echo "apply: no confirm token — the router will roll back in ${SECS}s" >&2; exit 2; }

# Is the house still working, seen from here, over a connection opened AFTER
# the change? Each pf call is a new ssh session.
healthy=1
pf true || { echo "health: new ssh session to $HOST FAILED" >&2; healthy=0; }
for n in bob.lab.example router.lab.example; do
  [ -n "$(dig +short +time=3 +tries=2 "$n" @"${RESOLVER:-192.0.2.254}")" ] || { echo "health: $n does not resolve" >&2; healthy=0; }
done
ping -c 2 -W 3 1.1.1.1 >/dev/null 2>&1 || { echo "health: no internet (1.1.1.1)" >&2; healthy=0; }

if [ "$healthy" = 1 ] && pf /usr/local/bin/php /root/scripts/data.php confirm "$token"; then
  :
else
  echo "NOT confirmed — router rolls back by itself ${SECS}s after the apply." >&2
  echo "Check afterwards: ssh admin@$HOST php /root/scripts/data.php status $token" >&2
  exit 1
fi

# Record what the router now runs. data/*.yaml already says it; config.xml
# follows so the drift check stays green. Straight to cp-1: the change was
# reviewed as data in its PR, this commit is the router's receipt.
pf /usr/local/bin/php /root/scripts/export-config.php > "$tmp/live.xml"
[ -s "$tmp/live.xml" ] && grep -q '</pfsense>' "$tmp/live.xml" || { echo "apply: post-apply export failed — run pull-config.sh" >&2; exit 2; }
cp "$tmp/live.xml" config/config.xml
git add config/config.xml
git commit -q -m "config: router after applying data/ at $rev"
git push -q origin cp-1
echo "config/config.xml updated and pushed"
