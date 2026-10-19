#!/usr/bin/env python3
"""Which top-level sections of two pfSense exports differ — names only.

    sections-diff.py <declared.xml> <live.xml>

Prints one section name per line (e.g. `unbound`, `dhcpd`, `filter`), in the
order they appear in the live export, then any section present only in the
declared file. Values are never printed: this output goes into a Kuma
message, and a Kuma message is not where the router's configuration belongs,
redacted or not.
"""
import sys
import xml.etree.ElementTree as ET


def sections(path):
    root = ET.parse(path).getroot()
    out = {}
    for child in root:
        # the same tag can appear several times at the top (pfSense repeats
        # <ca>, <cert>); compare the whole group
        out.setdefault(child.tag, []).append(ET.tostring(child))
    return out


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    declared, live = sections(argv[1]), sections(argv[2])
    changed = [t for t in live if declared.get(t) != live[t]]
    changed += [t for t in declared if t not in live]
    for t in changed:
        print(t)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
