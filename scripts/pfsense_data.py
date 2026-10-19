#!/usr/bin/env python3
"""data/*.yaml <-> the JSON router/data.php speaks.

    pfsense_data.py to-yaml  < dump.json      writes data/*.yaml
    pfsense_data.py to-json                   prints data/*.yaml as data.php input
    pfsense_data.py lint                      checks data/*.yaml, exit 1 on error

Every scalar in the data must be a STRING. YAML 1.1 reads an unquoted
02:00:00:00:00:1d as a base-60 integer, so a MAC or an address typed without
quotes is refused rather than silently turned into a number.
"""
import ipaddress, json, pathlib, re, sys
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
DNS, DHCP = ROOT / "data/dns.yaml", ROOT / "data/dhcp.yaml"
# The phase 3 lists, by file. Entries are pfSense's own arrays minus the
# created/updated stamps; an empty string is MEANING there (`disabled: ""`
# is a disabled rule, `any: ""` is "any"), so it is kept.
RAW_FILES = {
    "firewall.yaml": ("aliases", "rules"),
    "nat.yaml": ("nat.portforward", "nat.outbound"),
    "routing.yaml": ("gateways", "routes"),
}
EMPTYABLE = {"nat.portforward", "nat.outbound", "routes"}   # as in router/data.php
RAW_HEAD = {
    "firewall.yaml": """\
# Firewall aliases and rules on router. `rules` is in pfSense's order,
# and ORDER IS THE POLICY: the first matching rule wins. Each rule's key is
# its `tracker` — a new rule needs a unique one (e.g. `date +%s`).
# Empty strings are meaning here: `disabled: ""` disables, `any: ""` is any.
""",
    "nat.yaml": """\
# Port forwards (pfSense « NAT > Port Forward ») and outbound NAT rules
# (« NAT > Outbound », mode hybrid — the mode itself is only watched).
""",
    "routing.yaml": """\
# Gateways (and their monitor IPs) and static routes on router.
# Not here on purpose: VLANs and WireGuard — a bad change there cuts the
# console off the router, which is the path apply and its rollback use.
""",
}

DNS_HEAD = """\
# Unbound host overrides on router — pfSense « DNS Resolver > Host Overrides ».
# One entry per record: the A and the AAAA of a name are two entries.
# Applied by scripts/pfsense-apply.sh (router/data.php); the WHOLE list is
# owned: a name removed here is removed from the router.
"""
DHCP_HEAD = """\
# Kea static mappings on router — pfSense « DHCP Server > Static Mappings ».
# Keys are pfSense interface names: dhcp4.<if> is DHCPv4 (keyed by mac),
# dhcp6.<if> is DHCPv6 (keyed by duid). Only interfaces whose DHCP server is
# enabled and already has mappings are owned. Applied by scripts/pfsense-apply.sh;
# the WHOLE list is owned: an entry removed here is removed from the router.
"""

class Q(str): pass
yaml.SafeDumper.add_representer(Q, lambda d, v: d.represent_scalar("tag:yaml.org,2002:str", v, style='"'))

def quoted(x):
    if isinstance(x, dict): return {k: quoted(v) for k, v in x.items()}
    if isinstance(x, list): return [quoted(v) for v in x]
    return Q(x)

def dump(obj):
    return yaml.safe_dump(quoted(obj), sort_keys=False, allow_unicode=True, width=1000)

def to_yaml():
    d = json.load(sys.stdin)
    DNS.parent.mkdir(exist_ok=True)
    DNS.write_text(DNS_HEAD + dump(d.pop("dns")))
    for f, secs in RAW_FILES.items():
        part = {s: d.pop(s) for s in secs if s in d}
        path = ROOT / "data" / f
        if part: path.write_text(RAW_HEAD[f] + dump(part))
        elif path.exists(): path.unlink()
    DHCP.write_text(DHCP_HEAD + dump(d))

def load():
    d = {"dns": yaml.safe_load(DNS.read_text()), **yaml.safe_load(DHCP.read_text())}
    for f in RAW_FILES:
        path = ROOT / "data" / f
        if path.exists(): d.update(yaml.safe_load(path.read_text()) or {})
    return d

SECRET_NAME = re.compile(r"(password|passwd|secret|psk|apikey|api_key|token|bindpw|privatekey|presharedkey|prv)$", re.I)

def raw_key(s, e):
    ep = lambda x: "any" if isinstance(x, dict) and "any" in x else (x or {}).get("address", (x or {}).get("network", "")) if isinstance(x, dict) else ""
    if s == "aliases": return e.get("name", "").lower()
    if s == "rules": return e.get("tracker", "")
    if s == "gateways": return e.get("name", "").lower()
    if s == "routes": return e.get("network", "").lower()
    if s == "nat.portforward": return "|".join([e.get("interface", ""), e.get("protocol", ""), ep(e.get("destination")), (e.get("destination") or {}).get("port", "")])
    if s == "nat.outbound": return "|".join([e.get("interface", ""), ep(e.get("source")), ep(e.get("destination"))])

def errors(d):
    err = []
    def scalars(where, x):
        if isinstance(x, dict):
            for k, v in x.items(): scalars(f"{where}.{k}", v)
        elif isinstance(x, list):
            for i, v in enumerate(x): scalars(f"{where}[{i}]", v)
        elif not isinstance(x, str):
            err.append(f"{where}: {x!r} is not a string — quote it")
    for s, entries in d.items():
        raw = s in {x for v in RAW_FILES.values() for x in v}
        if not raw and not re.fullmatch(r"dns|dhcp[46]\.[a-z0-9_]+", s): err.append(f"{s}: unknown list"); continue
        if not isinstance(entries, list): err.append(f"{s}: must be a list"); continue
        if not entries and s not in EMPTYABLE: err.append(f"{s}: must not be empty"); continue
        seen = set()
        for i, e in enumerate(entries):
            w = f"{s}[{i}]"
            scalars(w, e)
            if err and err[-1].startswith(w): continue
            if raw:
                def names(x, where):
                    if isinstance(x, dict):
                        for k, v in x.items():
                            if SECRET_NAME.search(k): err.append(f"{where}.{k}: a secret-named field has no place in data/")
                            names(v, f"{where}.{k}")
                    elif isinstance(x, list):
                        for v in x: names(v, where)
                names(e, w)
                key = raw_key(s, e)
                if not key or key.startswith("|"): err.append(f"{w}: no key ({'tracker' if s == 'rules' else 'name/interface/network'})"); continue
                if s == "rules":
                    if e.get("type") not in ("pass", "block", "reject"): err.append(f"{w}: type must be pass, block or reject")
                    if not e.get("interface"): err.append(f"{w}: missing interface")
                    if not re.fullmatch(r"[0-9]+", key): err.append(f"{w}: tracker must be digits")
                if s == "aliases" and not re.fullmatch(r"[A-Za-z0-9_]{1,31}", e.get("name", "")): err.append(f"{w}: alias name must be [A-Za-z0-9_], 31 max")
            elif s == "dns":
                for f in ("host", "domain", "ip"):
                    if f not in e: err.append(f"{w}: missing {f}")
                try: fams = {ipaddress.ip_address(a).version for a in e.get("ip", [])}
                except ValueError as x: err.append(f"{w}: {x}"); continue
                if len(fams) != 1: err.append(f"{w}: ip must be one family (A and AAAA are separate entries)"); continue
                key = f"{e.get('host')}.{e.get('domain')}/{'AAAA' if 6 in fams else 'A'}".lower()
            elif s.startswith("dhcp4"):
                if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", e.get("mac", "")): err.append(f"{w}: bad or missing mac"); continue
                try: ipaddress.IPv4Address(e.get("ipaddr", ""))
                except ValueError: err.append(f"{w}: bad or missing ipaddr")
                key = e["mac"]
            else:
                if not e.get("duid"): err.append(f"{w}: missing duid"); continue
                try: ipaddress.IPv6Address(e.get("ipaddrv6", ""))
                except ValueError: err.append(f"{w}: bad or missing ipaddrv6")
                key = e["duid"].lower()
            if key in seen: err.append(f"{w}: duplicate {key}")
            seen.add(key)
    for s in [k for k in d if k.startswith("dhcp4")]:
        ips = [e.get("ipaddr") for e in d[s] if isinstance(e, dict)]
        for ip in {x for x in ips if ips.count(x) > 1}: err.append(f"{s}: {ip} reserved twice")
    return err

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "to-yaml": return to_yaml()
    d = load(); err = errors(d)
    for e in err: print("  " + e, file=sys.stderr)
    if cmd == "lint":
        print(f"data lint: {sum(len(v) for v in d.values() if isinstance(v, list))} entries, {len(err)} errors")
        sys.exit(1 if err else 0)
    if cmd == "to-json":
        if err: sys.exit(1)
        print(json.dumps(d, ensure_ascii=False)); return
    sys.exit(__doc__)

main()
