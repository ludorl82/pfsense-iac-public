#!/usr/bin/env python3
"""The committed config/config.xml carries no secret value.

The redaction runs on the router; this is the second lock, on what actually
reached git. It reads the two name patterns out of router/export-config.php
(one list, not two that drift apart) and fails if any element they name holds
anything but nothing or a REDACTED fingerprint — including inside a secret
element's children, which the exporter redacts wholesale.

    python3 tests/committed-config-test.py [config.xml]
"""
import re, sys, pathlib
import xml.etree.ElementTree as ET

root = pathlib.Path(__file__).resolve().parent.parent
php = (root / "router/export-config.php").read_text()
pats = [re.compile(re.search(r"const %s = '/(.*?)/i';" % n, php).group(1), re.I)
        for n in ("SECRET", "SECRET_PART")]
secret = lambda tag: any(p.search(tag) for p in pats)   # SECRET is anchored itself

path = sys.argv[1] if len(sys.argv) > 1 else root / "config/config.xml"
tree = ET.parse(path)
bad, checked = [], 0

def walk(el, trail, inside):
    global checked
    here = inside or secret(el.tag)
    text = (el.text or "").strip()
    if here and len(el) == 0:
        checked += 1
        if text and not re.fullmatch(r"REDACTED:sha256:[0-9a-f]{12}", text):
            bad.append("/".join(trail + [el.tag]))
    for c in el:
        walk(c, trail + [el.tag], here)

walk(tree.getroot(), [], False)
for b in bad:
    print("  UNREDACTED  " + b)          # the path only, never the value
print(f"{checked} secret-named elements checked, {len(bad)} unredacted")
sys.exit(1 if bad or checked == 0 else 0)
