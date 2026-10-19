#!/bin/sh
# Bring config/config.xml up to what router runs now, as a pull request.
#
#   scripts/pull-config.sh [branch-name]
#
# For the console, after the drift check went red because of a change made in
# the web UI. Merging the PR it opens is the statement "that change was meant";
# closing it means "put the router back". Nothing is pushed to cp-1 directly.
#
# It uses the console key (ADMIN_KEY), which is a full login, and runs the same
# router/export-config.php the forced pfsense-drift key runs — so what lands in
# git is redacted on the router, exactly as the check sees it.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
KEY=${ADMIN_KEY:-$HOME/.ssh/id_ed25519_console}
HOST=${PFSENSE_HOST:-router.lab.example}
BRANCH=${1:-pull-config-$(date -u +%Y%m%d-%H%M)}
cd "$ROOT"

[ -z "$(git status --porcelain)" ] || { echo "pull-config: working tree not clean" >&2; exit 1; }
git fetch -q origin cp-1
git switch -q -c "$BRANCH" origin/cp-1

live=$(mktemp "${TMPDIR:-/tmp}/pfsense-pull.XXXXXX"); trap 'rm -f "$live"' EXIT
ssh -4 -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$ROOT/router/known_hosts" \
    "admin@$HOST" /usr/local/bin/php /root/scripts/export-config.php > "$live"
[ -s "$live" ] && grep -q '</pfsense>' "$live" || { echo "pull-config: empty or truncated export" >&2; exit 2; }

if cmp -s "$live" config/config.xml; then
  echo "pull-config: router already matches git — nothing to do"
  git switch -q cp-1 2>/dev/null || true; git branch -q -D "$BRANCH"
  exit 0
fi
changed=$(python3 scripts/sections-diff.py config/config.xml "$live" | tr '\n' ' ' | sed 's/ $//')
cp "$live" config/config.xml
# data/*.yaml follows too: if the hand change touched a list git owns, the
# next pfsense-apply.sh must not undo it.
ssh -4 -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$ROOT/router/known_hosts" \
    "admin@$HOST" /usr/local/bin/php /root/scripts/data.php dump | python3 scripts/pfsense_data.py to-yaml
git add config/config.xml data/
git commit -q -m "config: router changed outside git ($changed)"
git push -q -u origin "$BRANCH"
gh pr create --base cp-1 --head "$BRANCH" \
  --title "config: router changed outside git ($changed)" \
  --body "The drift check saw router differ from \`config/config.xml\` in: **$changed**.

This PR takes the router's current (redacted) export as the declared state.
- **Merge** if the change was meant — the check goes green on its next run.
- **Close** if it was not, and undo it on the router.

Review the diff: secrets appear only as \`REDACTED:sha256:…\`; a changed fingerprint means that secret was rotated."
