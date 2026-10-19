#!/bin/sh
# Prove the phase 3 write path on the real router with throwaway changes, and
# leave it exactly as git says. Run by hand from the console, on cp-1, with
# the router matching git (pfsense-apply.sh prints "no change").
#
#   A  filter: alias zz_test + a DISABLED block rule using it, confirmed apply;
#      the reload must declare the alias table; then removed.
#   B  rollback: a throwaway alias applied and NOT confirmed (30 s timer);
#      the router must restore its lists by itself.
#   C  routing: the static route's description changed, confirmed; then back.
# Ends by checking the export is byte-identical to config/config.xml.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd); cd "$ROOT"
KEY=${ADMIN_KEY:-$HOME/.ssh/id_ed25519_console}; HOST=${PFSENSE_HOST:-router.lab.example}
pf() { ssh -4 -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 \
          -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$ROOT/router/known_hosts" "admin@$HOST" "$@"; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
ok=0; bad=0
res() { if [ "$1" = 0 ]; then echo "  ok    $2"; ok=$((ok+1)); else echo "  FAIL  $2"; bad=$((bad+1)); fi; }
health() { pf true && [ -n "$(dig +short +time=3 +tries=2 bob.lab.example @192.0.2.254)" ] && ping -c1 -W3 1.1.1.1 >/dev/null 2>&1; }
apply() { # apply <json> <secs> <confirm:yes|no> -> sets TOKEN
  pf /usr/local/bin/php /root/scripts/data.php apply prove "$2" < "$1" > "$tmp/out"; cat "$tmp/out" | sed 's/^/        /'
  TOKEN=$(sed -n 's/^confirm-token: //p' "$tmp/out")
  [ "$3" = yes ] && health && pf /usr/local/bin/php /root/scripts/data.php confirm "$TOKEN" >/dev/null
}

python3 scripts/pfsense_data.py to-json > "$tmp/base.json" || exit 1
pf /usr/local/bin/php /root/scripts/export-config.php | cmp -s - config/config.xml || { echo "router differs from git — stop"; exit 1; }
[ "$(pf /usr/local/bin/php /root/scripts/data.php check < "$tmp/base.json")" = "no change" ] || { echo "check is not 'no change' — stop"; exit 1; }

echo "A  alias + disabled rule"
TR=$(date +%s)
python3 - "$tmp/base.json" "$TR" > "$tmp/a.json" <<'PY'
import json, sys, copy
d = json.load(open(sys.argv[1]))
d["aliases"].append({"name": "zz_test", "type": "host", "address": "192.0.2.1", "descr": "pfsense-iac proof, remove", "detail": ""})
r = copy.deepcopy(d["rules"][-1])
r.update({"tracker": sys.argv[2], "type": "block", "descr": "pfsense-iac proof, remove", "disabled": "", "source": {"address": "zz_test"}})
d["rules"].append(r)
print(json.dumps(d))
PY
apply "$tmp/a.json" 120 yes; res $? "applied and confirmed after a health check over a new session"
[ "$(pf /usr/local/bin/php /root/scripts/data.php status "$TOKEN")" = confirmed ]; res $? "router says confirmed"
# pf keeps only tables an ENABLED rule references (unused aliases such as
# portecles are declared and dropped too), so the proof of the reload is the
# generated ruleset, not `pfctl -t`.
pf "grep -A1 '^table <zz_test>' /tmp/rules.debug" | grep -q 192.0.2.1; res $? "the filter reload declared table zz_test"
[ "$(pf "pfctl -sr | grep -c 'pfsense-iac proof'")" = 0 ]; res $? "the disabled rule is not loaded"
apply "$tmp/base.json" 120 yes; res $? "removed, confirmed"
[ "$(pf "grep -c '^table <zz_test>' /tmp/rules.debug")" = 0 ]; res $? "table zz_test gone from the ruleset"

echo "B  unconfirmed apply rolls itself back"
python3 -c "import json,sys;d=json.load(open('$tmp/base.json'));d['aliases'].append({'name':'zz_rollback','type':'host','address':'192.0.2.2','descr':'','detail':''});print(json.dumps(d))" > "$tmp/b.json"
apply "$tmp/b.json" 30 no
[ "$(pf /usr/local/bin/php /root/scripts/data.php status "$TOKEN")" = pending ]; res $? "pending right after apply"
echo "        waiting 45 s for the router's own rollback…"; sleep 45
[ "$(pf /usr/local/bin/php /root/scripts/data.php status "$TOKEN")" = rolled-back ]; res $? "router says rolled-back"
[ "$(pf /usr/local/bin/php /root/scripts/data.php check < "$tmp/base.json")" = "no change" ]; res $? "lists back to git"
! pf /usr/local/bin/php /root/scripts/data.php confirm "$TOKEN" 2>/dev/null; res $? "a late confirm is refused"

echo "C  static route description"
routes_before=$(pf "netstat -rn | wc -l")
python3 -c "import json;d=json.load(open('$tmp/base.json'));d['routes'][0]['descr']=(d['routes'][0].get('descr') or '')+' [proof]';print(json.dumps(d))" > "$tmp/c.json"
apply "$tmp/c.json" 120 yes; res $? "applied and confirmed"
[ "$(pf "netstat -rn | wc -l")" = "$routes_before" ]; res $? "routing table the same size"
apply "$tmp/base.json" 120 yes; res $? "reverted, confirmed"

pf /usr/local/bin/php /root/scripts/export-config.php | cmp -s - config/config.xml; res $? "router export byte-identical to git"
printf '\n%d passed, %d failed\n' "$ok" "$bad"
[ "$bad" = 0 ]
