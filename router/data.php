<?php
/*
 * pfsense-iac phase 2 — the lists git owns, and nothing else.
 *
 * Installed as /root/scripts/data.php on router. Run through the console
 * key by scripts/pfsense-apply.sh; never by the pfsense-drift key, whose forced
 * command is the export.
 *
 *   php data.php dump                 print the owned lists as JSON
 *   php data.php check < JSON         print what apply would change, write nothing
 *   php data.php apply REV SECS < JSON
 *                                     make the owned lists equal to JSON, reload,
 *                                     and arm a rollback that fires in SECS
 *                                     unless `confirm` arrives first
 *   php data.php confirm TOKEN        keep what apply did
 *   php data.php status TOKEN         pending | confirmed | rolled-back
 *   php data.php rollback TOKEN       (the armed timer runs this)
 *
 * Owned lists (and only those — every other setting is left as it is):
 *   dns             unbound/hosts            key host.domain/A|AAAA   compact
 *   dhcp4.IF        dhcpd/IF/staticmap (Kea) key mac                  compact
 *   dhcp6.IF        dhcpdv6/IF/staticmap     key duid                 compact
 *   aliases         aliases/alias            key name                 raw
 *   rules           filter/rule              key tracker              raw  (ORDER = policy)
 *   nat.portforward nat/rule                 key if|proto|dst|port    raw
 *   nat.outbound    nat/outbound/rule        key if|src|dst           raw
 *   gateways        gateways/gateway_item    key name                 raw
 *   routes          staticroutes/route       key network              raw
 * A list is owned when it exists and is non-empty on the router; the
 * EMPTYABLE ones (port forwards, outbound NAT, routes) always are. VLANs and
 * WireGuard are deliberately NOT owned: a bad VLAN change cuts the console
 * off the router, which is the path this script and its rollback use.
 *
 * Why not pfsensible.core: pfsense_dns_resolver rewrites EVERY Unbound
 * setting to its own defaults and refuses IPv6 host overrides (14 of ours
 * have one), and pfsense_dhcp_static cannot remove what git no longer
 * declares. This replaces whole lists through config_set_path() +
 * write_config() + the *_configure() pfSense's own pages call.
 *
 * compact: an entry lists only its non-empty fields. An entry that already
 * exists (same key) keeps its field order and every field git does not
 * mention is emptied; a new entry is built on a blanked copy of an existing
 * one, so it has the shape pfSense's pages write.
 * raw: an entry is pfSense's own array minus `created`/`updated` — empty
 * values are kept, because there presence is meaning (`disabled: ""` is a
 * disabled rule, `any: ""` is "any"). Those two stamps are carried over from
 * the router, and a changed or new entry is stamped pfsense-iac@REV.
 */
if (getenv('PFSENSE_DATA_LIB_ONLY') !== '1') {
    require_once("config.inc");
    require_once("functions.inc");
}

const RAW = [
    'aliases'         => 'aliases/alias',
    'rules'           => 'filter/rule',
    'nat.portforward' => 'nat/rule',
    'nat.outbound'    => 'nat/outbound/rule',
    'gateways'        => 'gateways/gateway_item',
    'routes'          => 'staticroutes/route',
];
const VOLATILE = ['created', 'updated'];
// Lists git may legitimately empty — and therefore owned even when empty on
// the router, or declaring `[]` would read as an unknown list. The others
// (names, leases, aliases, rules, gateways) refuse to be emptied: an empty
// one is far likelier to be a broken file than a wish.
const EMPTYABLE = ['nat.portforward', 'nat.outbound', 'routes'];

function paths() {
    $p = ['dns' => 'unbound/hosts'];
    foreach (['dhcp4' => 'dhcpd', 'dhcp6' => 'dhcpdv6'] as $s => $root) {
        foreach (config_get_path($root, []) as $if => $cfg) {
            if (is_array($cfg) && isset($cfg['enable']) && !empty($cfg['staticmap'])) {
                $p["$s.$if"] = "$root/$if/staticmap";
            }
        }
    }
    foreach (RAW as $s => $path) if (in_array($s, EMPTYABLE) || !empty(config_get_path($path, []))) $p[$s] = $path;
    return $p;
}

function is_raw($section) { return isset(RAW[$section]); }

function endpoint($x) {
    if (!is_array($x)) return '';
    if (array_key_exists('any', $x)) return 'any';
    return ($x['address'] ?? $x['network'] ?? '') . (isset($x['not']) ? '!' : '');
}

function key_of($section, $e) {
    switch ($section) {
    case 'dns':
        // A and AAAA for one name are two separate overrides in pfSense
        $ip = is_array($e['ip'] ?? '') ? implode(',', $e['ip']) : ($e['ip'] ?? '');
        return strtolower(($e['host'] ?? '') . '.' . ($e['domain'] ?? '')) . (strpos($ip, ':') !== false ? '/AAAA' : '/A');
    case 'aliases':  return strtolower($e['name'] ?? '');
    case 'rules':    return (string)($e['tracker'] ?? '');
    case 'gateways': return strtolower($e['name'] ?? '');
    case 'routes':   return strtolower($e['network'] ?? '');
    case 'nat.portforward':
        if (($e['interface'] ?? '') === '') return '';
        return implode('|', [$e['interface'], $e['protocol'] ?? '', endpoint($e['destination'] ?? null), $e['destination']['port'] ?? '']);
    case 'nat.outbound':
        if (($e['interface'] ?? '') === '') return '';
        return implode('|', [$e['interface'], endpoint($e['source'] ?? null), endpoint($e['destination'] ?? null)]);
    }
    if (strpos($section, 'dhcp4') === 0) return strtolower($e['mac'] ?? '');
    return strtolower($e['duid'] ?? '');
}

function compact_entry($section, $e) {
    if (is_raw($section)) return array_diff_key($e, array_flip(VOLATILE));
    $out = [];
    foreach ($e as $k => $v) {
        if ($section === 'dns' && $k === 'ip') { $out['ip'] = explode(',', $v); continue; }
        if ($section === 'dns' && $k === 'aliases') {
            if (is_array($v) && !empty($v['item'])) $out['aliases'] = array_values($v['item']);
            continue;
        }
        if ($v === '' || $v === [] || $v === null) continue;
        $out[$k] = $v;
    }
    return $out;
}

function full_entry($section, $c, $base, $stamp = null) {
    if (is_raw($section)) {
        if ($base !== null && json_encode(compact_entry($section, $base)) === json_encode($c)) return $base;
        $e = $c;
        foreach (VOLATILE as $v) {
            if ($base !== null && isset($base[$v])) $e[$v] = ($v === 'updated' && $stamp) ? $stamp : $base[$v];
            elseif ($base === null && $stamp) $e[$v] = $stamp;
        }
        return $e;
    }
    $e = $base;
    foreach ($e as $k => $v) {
        if (is_array($v) && $k !== 'aliases') unset($e[$k]); else $e[$k] = '';
    }
    foreach ($c as $k => $v) {
        if ($section === 'dns' && $k === 'ip') { $e['ip'] = implode(',', $v); continue; }
        if ($section === 'dns' && $k === 'aliases') { $e['aliases'] = ['item' => $v]; continue; }
        $e[$k] = $v;
    }
    return $e;
}

function blank($e) {
    foreach ($e as $k => $v) $e[$k] = is_array($v) && $k !== 'aliases' ? $v : '';
    return $e;
}

function die_msg($m) { fwrite(STDERR, "data.php: $m\n"); exit(2); }

/*
 * The plan, pure: current lists + wanted lists -> what changes. Throws on
 * anything it will not do. No pfSense call in here, so CI can run it.
 */
function plan($cur, $want, $stamp = null) {
    foreach (array_keys($want) as $s) if (!array_key_exists($s, $cur)) throw new Exception("unknown list '$s' (owned: " . implode(', ', array_keys($cur)) . ")");
    foreach (array_keys($cur) as $s) if (!array_key_exists($s, $want)) throw new Exception("list '$s' missing from input — every owned list must be declared");
    $new = []; $lines = [];
    foreach ($cur as $s => $list_cur) {
        if (!is_array($want[$s])) throw new Exception("'$s' is not a list");
        if (count($want[$s]) === 0 && !in_array($s, EMPTYABLE)) throw new Exception("refusing to empty '$s'");
        $byKey = [];
        foreach ($list_cur as $e) $byKey[key_of($s, $e)] = $e;
        $seen = []; $list = []; $mine = [];
        foreach ($want[$s] as $c) {
            $k = key_of($s, $c);
            if ($k === '' || $k[0] === '.' || $k[0] === '/') throw new Exception("an entry in '$s' has no key");
            if (isset($seen[$k])) throw new Exception("duplicate key '$k' in '$s'");
            $seen[$k] = true;
            $list[] = full_entry($s, $c, $byKey[$k] ?? (is_raw($s) ? null : blank($list_cur[0])), $stamp);
            if (!isset($byKey[$k])) { $mine[] = "  + $s $k"; continue; }
            $before = compact_entry($s, $byKey[$k]);
            foreach (array_unique(array_merge(array_keys($before), array_keys($c))) as $f) {
                $a = json_encode($before[$f] ?? null, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                $b = json_encode($c[$f] ?? null, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                if ($a !== $b) $mine[] = "  ~ $s $k $f: $a -> $b";
            }
        }
        foreach ($list_cur as $e) { $k = key_of($s, $e); if (!isset($seen[$k])) $mine[] = "  - $s $k"; }
        if ($list === $list_cur) continue;
        if (!$mine) $mine[] = "  ~ $s (order only)";
        $new[$s] = $list; $lines = array_merge($lines, $mine);
    }
    return [$new, $lines];
}

function group_of($s) {
    if ($s === 'dns') return 'unbound';
    if (strpos($s, 'dhcp') === 0) return 'dhcp';
    if ($s === 'gateways' || $s === 'routes') return 'routing';
    return 'filter';
}

function reload($sections) {
    $g = array_flip(array_map('group_of', $sections));
    if (isset($g['dhcp'])) { services_dhcpd_configure(); clear_subsystem_dirty('dhcpd'); }
    if (isset($g['dhcp']) || isset($g['unbound'])) {
        services_unbound_configure();      // also for DHCP: Unbound registers static mappings
        system_resolvconf_generate();
        clear_subsystem_dirty('unbound');
    }
    if (isset($g['routing'])) {
        setup_gateways_monitor();
        system_routing_configure();
        clear_subsystem_dirty('staticroutes');
    }
    if (isset($g['routing']) || isset($g['filter'])) {
        // filter_configure_sync() from a bare script dies on a missing
        // include (2026-09-27); the rc script is what pfSense itself runs.
        mwexec('/etc/rc.filter_configure_sync');
        foreach (['filter', 'aliases', 'natconf'] as $d) clear_subsystem_dirty($d);
    }
}

const STATE = '/root/pfsense-iac';

function token_ok($t) { return preg_match('/^[0-9a-zA-Z._-]{4,80}$/', $t) === 1; }

function main($argv) {
    $mode = $argv[1] ?? '';

    if ($mode === 'confirm' || $mode === 'status' || $mode === 'rollback') {
        $t = $argv[2] ?? '';
        if (!token_ok($t)) die_msg("bad token");
        $rb = STATE . "/rollback-$t.json"; $ok = STATE . "/confirmed-$t"; $done = STATE . "/rolled-back-$t";
        if ($mode === 'status') {
            echo file_exists($done) ? "rolled-back\n" : (file_exists($ok) ? "confirmed\n" : (file_exists($rb) ? "pending\n" : "unknown\n"));
            return 0;
        }
        if ($mode === 'confirm') {
            if (file_exists($done)) die_msg("too late: $t was already rolled back");
            if (!file_exists($rb)) die_msg("no pending apply $t");
            touch($ok); echo "confirmed $t\n"; return 0;
        }
        // rollback: the armed timer
        if (file_exists($ok) || file_exists($done) || !file_exists($rb)) return 0;
        $saved = json_decode(file_get_contents($rb), true);
        foreach ($saved['lists'] as $s => $list) config_set_path($saved['paths'][$s], $list);
        write_config("pfsense-iac: ROLLBACK of $t (apply not confirmed)");
        reload(array_keys($saved['lists']));
        touch($done);
        log_error("pfsense-iac: apply $t was not confirmed — rolled back " . implode(', ', array_keys($saved['lists'])));
        return 0;
    }

    $paths = paths();
    $cur = [];
    foreach ($paths as $s => $p) $cur[$s] = config_get_path($p, []);

    if ($mode === 'dump') {
        $out = [];
        foreach ($cur as $s => $list) $out[$s] = array_map(function ($e) use ($s) { return compact_entry($s, $e); }, $list);
        echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
        return 0;
    }
    if ($mode !== 'check' && $mode !== 'apply') die_msg("usage: data.php dump|check|apply REV SECS|confirm T|status T");

    $want = json_decode(stream_get_contents(STDIN), true);
    if (!is_array($want)) die_msg("stdin is not a JSON object");
    $who = preg_replace('/[^0-9a-zA-Z._-]/', '', $argv[2] ?? '') ?: 'unknown';
    $stamp = ['time' => (string)time(), 'username' => "pfsense-iac@$who"];
    try { [$new, $lines] = plan($cur, $want, $stamp); } catch (Exception $e) { die_msg($e->getMessage()); }

    if (!$new) { echo "no change\n"; return 0; }
    echo implode("\n", $lines), "\n";
    if ($mode === 'check') return 0;

    $secs = (int)($argv[3] ?? 0);
    if ($secs < 30 || $secs > 900) die_msg("apply needs a rollback delay of 30-900 s");
    $t = $who . '-' . bin2hex(random_bytes(4));
    @mkdir(STATE, 0700, true);
    $saved = ['paths' => [], 'lists' => []];
    foreach (array_keys($new) as $s) { $saved['paths'][$s] = $paths[$s]; $saved['lists'][$s] = $cur[$s]; }
    file_put_contents(STATE . "/rollback-$t.json", json_encode($saved));

    foreach ($new as $s => $list) config_set_path($paths[$s], $list);
    write_config("pfsense-iac: " . implode(', ', array_keys($new)) . " from git ($who, rollback $t in {$secs}s unless confirmed)");
    reload(array_keys($new));
    // The timer outlives this ssh session (daemon(8) detaches it).
    mwexec("/usr/sbin/daemon -f /bin/sh -c " . escapeshellarg("sleep $secs; /usr/local/bin/php /root/scripts/data.php rollback $t"));
    echo "applied: ", implode(', ', array_keys($new)), "\n";
    echo "confirm-token: $t\n";
    return 0;
}

if (getenv('PFSENSE_DATA_LIB_ONLY') !== '1') exit(main($argv));
