# pfsense-iac

`router` (pfSense Plus on an SG-1100) under version control. **Private — never
published**: even redacted, this is the whole network's map.

## Phase 1 — read-only mirror + drift check (now)

- `router/export-config.php` — installed on router as `/root/scripts/export-config.php`.
  Prints the live configuration, normalised (no `<revision>`) and **redacted on the
  router**: every secret becomes `REDACTED:sha256:<12 hex>`, so a rotation shows in a
  diff and the value never leaves the box.
- `config/config.xml` — the declared state: that export, committed.
- `scripts/pfsense-drift-check.sh` — run each morning by the Cronicle event
  « pfsense-iac Drift Check » (chained after « nixos-iac Drift Check »). Uses the
  `pfsense-drift` key, a forced command on `admin` that can only run the export.
  Kuma up if identical, down naming the **sections** that differ (never their
  content), no heartbeat at all when it cannot compare (exit 2).
- `scripts/pull-config.sh` — from the console, after a red: takes the router's
  export as the new declared state and opens a PR. **Merge = the change was meant;
  close = undo it on the router.**
- `router/known_hosts` — router's host key, pinned.

Tests: `php tests/redact-test.php`, `php tests/data-test.php`,
`sh tests/drift-check-test.sh`, `sh tests/data-lint-test.sh`,
`python3 tests/committed-config-test.py` (the second lock: no secret value in
what reached git). CI runs them all.

## Phases 2–3 — git writes the lists (since 2026-09-27)

| File | Lists | Key |
|---|---|---|
| `data/dns.yaml` | Unbound host overrides (A and AAAA are separate entries) | name.domain/A\|AAAA |
| `data/dhcp.yaml` | Kea static mappings (`dhcp4.lan` by mac, `dhcp6.opt2` by duid) | mac / duid |
| `data/firewall.yaml` | aliases; **rules, in order — order is the policy** | name; `tracker` |
| `data/nat.yaml` | port forwards; outbound NAT rules | if\|proto\|dst\|port; if\|src\|dst |
| `data/routing.yaml` | gateways (with monitor IPs); static routes | name; network |

**Each list is owned whole**: an entry removed here is removed from the
router. Nothing outside these lists is touched. **Not owned, on purpose:
VLANs and WireGuard** — a bad change there cuts the console off the router,
which is the path apply and its rollback depend on. The drift check still
watches them, and the outbound NAT *mode* (hybrid).

In the phase 3 files an entry is pfSense's own array minus its
`created`/`updated` stamps, and **empty strings are meaning**:
`disabled: ""` is a disabled rule, `any: ""` is "any". A new rule needs a
unique numeric `tracker` (`date +%s`).

To change something:

1. Edit `data/*.yaml` in a PR. CI lints it (every value quoted; no
   secret-named field; rules have a tracker and a type). Paste
   `scripts/pfsense-apply.sh` (check mode, from the console) into the PR.
2. Merge, then on the console, on an up-to-date cp-1:
   `scripts/pfsense-apply.sh --apply`.

**Every apply is confirmed.** The router arms a rollback before the script
returns (`ROLLBACK_SECS`, default 120 s). The script then opens a *new* ssh
session and checks DNS and the internet from the console; only then does it
confirm. If the change cut the console off, nothing confirms and the router
restores its previous lists by itself (`data.php status <token>` says which).
After a confirmed apply the script commits the router's new `config/config.xml`
to cp-1, so the drift check stays green.

`pfsense-apply.sh` refuses to write if the router has drifted from
`config/config.xml` (a hand change would be undone — run `pull-config.sh`
first), or if `/root/scripts/data.php` is not this repo's (`scripts/install-router.sh`).
The router side is `router/data.php`, using pfSense's own `config_set_path` +
`write_config` + `services_dhcpd_configure` / `services_unbound_configure` /
`setup_gateways_monitor` + `system_routing_configure` / `/etc/rc.filter_configure_sync`.

Why not Ansible `pfsensible.core` as first planned: `pfsense_dns_resolver`
rewrites every Unbound setting to its own defaults and refuses IPv6 overrides
(14 of ours), and `pfsense_dhcp_static` cannot remove what git no longer declares.

Proven 2026-09-27 on a throwaway `zz-test` name + Kea reservation: applied,
Unbound answered, Kea's generated config carried it; removed, and the router's
export came back byte-identical to git. Phase 3's own proofs (alias + disabled
rule, an unconfirmed apply rolling itself back, a route change) are
`scripts/prove.sh`.

## Later

VLANs and WireGuard stay manual (see above). See `net-cfgs/backlog.md`.
Restoring the router is not this repo's job: the encrypted S3 backup
(`config_backup_s3.php`, 02:45) and `net-cfgs/router-config-restore.md` are.
