#!/bin/sh
# Tests for scripts/pfsense_data.py lint: the committed data passes, and the
# traps it exists for are caught.   sh tests/data-lint-test.sh
set -u
R=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/pfdata-test.XXXXXX"); trap 'rm -rf "$T"' EXIT
pass=0; fail=0
mk() { rm -rf "$T/r"; mkdir -p "$T/r/scripts" "$T/r/data"; cp "$R/scripts/pfsense_data.py" "$T/r/scripts/"; cp "$R/data/"*.yaml "$T/r/data/"; }
expect() { # expect <0|1> <name>
  python3 "$T/r/scripts/pfsense_data.py" lint >/dev/null 2>"$T/err"; rc=$?
  if [ "$rc" = "$1" ]; then echo "  ok    $2"; pass=$((pass+1)); else echo "  FAIL  $2 (rc=$rc) $(cat "$T/err")"; fail=$((fail+1)); fi
}
echo "pfsense_data.py lint"
mk; expect 0 "the committed data lints"
mk; printf -- '- host: "zz"\n  domain: "lab.example"\n  ip:\n  - "192.0.2.250"\n' >> "$T/r/data/dns.yaml"; expect 0 "a well-formed new name passes"
mk; printf -- '- host: "zz"\n  domain: "lab.example"\n  ip:\n  - 192.0.2.250\n  descr: 12:30:45\n' >> "$T/r/data/dns.yaml"; expect 1 "an unquoted base-60 value is refused"
mk; printf -- '- host: "zz"\n  domain: "lab.example"\n  ip:\n  - "192.0.2.250"\n  - "2001:db8:50:a::99"\n' >> "$T/r/data/dns.yaml"; expect 1 "A and AAAA in one entry are refused"
mk; sed -n '5,9p' "$T/r/data/dns.yaml" >> "$T/r/data/dns.yaml"; expect 1 "a duplicate record is refused"
mk; sed -i '0,/ipaddr: "203.0.113.35"/s//ipaddr: "203.0.113.34"/' "$T/r/data/dhcp.yaml"; expect 1 "one IPv4 reserved twice is refused"
mk; sed -i '0,/mac: "/s//mac: "zz/' "$T/r/data/dhcp.yaml"; expect 1 "a malformed mac is refused"
mk; python3 - "$T/r/data/firewall.yaml" <<'PY'
import sys,yaml; p=sys.argv[1]; head=open(p).read().split("aliases:")[0]; d=yaml.safe_load(open(p))
del d["rules"][0]["tracker"]; open(p,"w").write(head+yaml.safe_dump(d,sort_keys=False))
PY
expect 1 "a rule without a tracker is refused"
mk; python3 - "$T/r/data/routing.yaml" <<'PY'
import sys,yaml; p=sys.argv[1]; d=yaml.safe_load(open(p)); d["gateways"][0]["password"]="x"; open(p,"w").write(yaml.safe_dump(d,sort_keys=False))
PY
expect 1 "a secret-named field in data/ is refused"
mk; python3 - "$T/r/data/firewall.yaml" <<'PY'
import sys,yaml; p=sys.argv[1]; d=yaml.safe_load(open(p)); d["rules"][1]["tracker"]=d["rules"][0]["tracker"]; open(p,"w").write(yaml.safe_dump(d,sort_keys=False))
PY
expect 1 "two rules with one tracker are refused"
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
