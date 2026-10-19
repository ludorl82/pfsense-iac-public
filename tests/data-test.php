<?php
// Tests for router/data.php's pure half: keys, compact <-> full, and plan().
//   php tests/data-test.php
// What has to be true:
//   * a dump fed back is "no change" — the first apply must not touch anything;
//   * A and AAAA of one name are two entries, not a duplicate;
//   * an existing entry keeps its field order and pfSense-only fields;
//   * removals, additions, field changes and pure reorders are all reported;
//   * it refuses an empty list, a missing or unknown list, a duplicate.
putenv('PFSENSE_DATA_LIB_ONLY=1');
require __DIR__ . '/../router/data.php';
$pass = 0; $fail = 0;
function t($name, $ok, $detail = '') { global $pass, $fail; if ($ok) { echo "  ok    $name\n"; $pass++; } else { echo "  FAIL  $name\n        $detail\n"; $fail++; } }
function throws($f) { try { $f(); return null; } catch (Exception $e) { return $e->getMessage(); } }

$sm = function ($mac, $ip, $extra = []) {
    return array_merge(['mac' => $mac, 'cid' => '', 'ipaddr' => $ip, 'hostname' => '', 'descr' => '', 'filename' => '', 'numberoptions' => ''], $extra);
};
$cur = [
  'dns' => [
    ['host' => 'bob', 'domain' => 'lab.example', 'ip' => '192.0.2.129', 'descr' => 'A', 'aliases' => ''],
    ['host' => 'bob', 'domain' => 'lab.example', 'ip' => '2001:db8:50:a::81', 'descr' => 'AAAA', 'aliases' => ''],
    ['host' => 'stella', 'domain' => 'lab.example', 'ip' => '192.0.2.140', 'descr' => '',
     'aliases' => ['item' => [['host' => 'serveur', 'domain' => 'lab.example', 'description' => 'legacy']]]],
  ],
  'dhcp4.lan' => [
    $sm('02:00:00:00:00:1e', '203.0.113.34', ['cid' => 'home-device-01']),
    $sm('02:00:00:00:00:1f', '203.0.113.35', ['dnsserver' => ['203.0.113.254']]),
  ],
];
$dump = [];
foreach ($cur as $s => $l) $dump[$s] = array_map(function ($e) use ($s) { return compact_entry($s, $e); }, $l);
$dump = json_decode(json_encode($dump), true);   // what actually crosses the wire

echo "data.php\n";
[$new, $lines] = plan($cur, $dump);
t("a dump fed back is no change", $new === [] && $lines === [], json_encode($lines));
t("A and AAAA of one name are distinct keys", key_of('dns', $cur['dns'][0]) !== key_of('dns', $cur['dns'][1]));
t("aliases survive compact -> full", full_entry('dns', $dump['dns'][2], $cur['dns'][2]) === $cur['dns'][2]);
t("dnsserver list survives compact -> full", full_entry('dhcp4.lan', $dump['dhcp4.lan'][1], $cur['dhcp4.lan'][1]) === $cur['dhcp4.lan'][1]);

$w = $dump; $w['dns'][] = ['host' => 'zz-test', 'domain' => 'lab.example', 'ip' => ['192.0.2.250']];
[$new, $lines] = plan($cur, $w);
t("an added name is reported", in_array("  + dns zz-test.lab.example/A", $lines), json_encode($lines));
$added = end($new['dns']);
t("a new entry gets pfSense's shape", array_keys($added) === ['host', 'domain', 'ip', 'descr', 'aliases'] && $added['aliases'] === '', json_encode($added));
t("the other lists are left alone", !isset($new['dhcp4.lan']));

$w = $dump; array_shift($w['dhcp4.lan']);
[$new, $lines] = plan($cur, $w);
t("a removed mapping is reported", $lines === ["  - dhcp4.lan 02:00:00:00:00:1e"], json_encode($lines));

$w = $dump; unset($w['dhcp4.lan'][1]['dnsserver']); $w['dhcp4.lan'][1]['hostname'] = 'pixel';
[$new, $lines] = plan($cur, $w);
t("field changes are reported", in_array('  ~ dhcp4.lan 02:00:00:00:00:1f dnsserver: ["203.0.113.254"] -> null', $lines) && in_array('  ~ dhcp4.lan 02:00:00:00:00:1f hostname: null -> "pixel"', $lines), json_encode($lines));
t("a field git drops is removed, order kept", array_keys($new['dhcp4.lan'][1]) === array_keys($sm('', '')), json_encode(array_keys($new['dhcp4.lan'][1])));

$w = $dump; $w['dns'] = array_reverse($w['dns']);
[$new, $lines] = plan($cur, $w);
t("a pure reorder is still a change", $lines === ["  ~ dns (order only)"], json_encode($lines));

$w = $dump; $w['dns'] = [];
t("refuses to empty a list", strpos((string)throws(function () use ($cur, $w) { plan($cur, $w); }), 'refusing to empty') !== false);
$w = $dump; unset($w['dhcp4.lan']);
t("refuses a missing list", strpos((string)throws(function () use ($cur, $w) { plan($cur, $w); }), 'missing') !== false);
$w = $dump; $w['dhcp4.opt9'] = [$dump['dhcp4.lan'][0]];
t("refuses an unknown list", strpos((string)throws(function () use ($cur, $w) { plan($cur, $w); }), 'unknown list') !== false);
$w = $dump; $w['dhcp4.lan'][] = $dump['dhcp4.lan'][0];
t("refuses a duplicate", strpos((string)throws(function () use ($cur, $w) { plan($cur, $w); }), 'duplicate') !== false);

// ---- raw lists (phase 3)
$rule = function ($tr, $extra = []) {
    return array_merge(['id' => '', 'tracker' => $tr, 'type' => 'pass', 'interface' => 'opt2', 'ipprotocol' => 'inet',
        'source' => ['any' => ''], 'destination' => ['network' => 'opt2', 'port' => '443'], 'descr' => "r$tr",
        'updated' => ['time' => '100', 'username' => 'admin'], 'created' => ['time' => '100', 'username' => 'admin']], $extra);
};
$rcur = ['rules' => [$rule('1'), $rule('2', ['disabled' => '']), $rule('3')],
         'nat.outbound' => [['source' => ['network' => '192.0.2.0/23'], 'interface' => 'opt1', 'destination' => ['network' => '198.51.100.0/24'], 'nonat' => '', 'created' => ['time' => '5', 'username' => 'x']]]];
$rdump = [];
foreach ($rcur as $s => $l) $rdump[$s] = array_map(function ($e) use ($s) { return compact_entry($s, $e); }, $l);
$rdump = json_decode(json_encode($rdump), true);
$stamp = ['time' => '999', 'username' => 'pfsense-iac@abc'];

[$new, $lines] = plan($rcur, $rdump, $stamp);
t("raw: a dump fed back is no change", $new === [] && $lines === [], json_encode($lines));
t("raw: the dump carries no created/updated", !isset($rdump['rules'][0]['updated']) && !isset($rdump['rules'][0]['created']));
t("raw: an empty flag survives (disabled rule stays disabled)", array_key_exists('disabled', $rdump['rules'][1]) && $rdump['rules'][1]['disabled'] === '');
t("raw: any:'' survives", $rdump['rules'][0]['source'] === ['any' => '']);

$w = $rdump; $w['rules'] = [$rdump['rules'][1], $rdump['rules'][0], $rdump['rules'][2]];
[$new, $lines] = plan($rcur, $w, $stamp);
t("raw: moving a rule is a change (order is policy)", $lines === ["  ~ rules (order only)"] && $new['rules'][0] === $rcur['rules'][1], json_encode($lines));

$w = $rdump; unset($w['rules'][1]['disabled']);
[$new, $lines] = plan($rcur, $w, $stamp);
t("raw: enabling a rule is reported", in_array('  ~ rules 2 disabled: "" -> null', $lines), json_encode($lines));
t("raw: a changed rule keeps created, gets a new updated", $new['rules'][1]['created'] === $rcur['rules'][1]['created'] && $new['rules'][1]['updated'] === $stamp);
t("raw: untouched rules are byte-identical", $new['rules'][0] === $rcur['rules'][0] && $new['rules'][2] === $rcur['rules'][2]);

$w = $rdump; $w['rules'][] = compact_entry('rules', $rule('4'));
[$new, $lines] = plan($rcur, $w, $stamp);
t("raw: a new rule is added last and stamped", in_array("  + rules 4", $lines) && end($new['rules'])['created'] === $stamp, json_encode($lines));

$w = $rdump; $x = compact_entry('rules', $rule('9')); unset($x['tracker']); $w['rules'][] = $x;
t("raw: a rule without tracker is refused", strpos((string)throws(function () use ($rcur, $w, $stamp) { plan($rcur, $w, $stamp); }), 'no key') !== false);

$w = $rdump; $w['nat.outbound'][0]['descr'] = 'x';
[$new, $lines] = plan($rcur, $w, $stamp);
t("raw: outbound NAT keyed by if|src|dst", in_array('  ~ nat.outbound opt1|192.0.2.0/23|198.51.100.0/24 descr: null -> "x"', $lines), json_encode($lines));
t("raw: stamps only what the entry had (no updated invented)", !isset($new['nat.outbound'][0]['updated']) && $new['nat.outbound'][0]['created'] === $rcur['nat.outbound'][0]['created']);

$ecur = ['dns' => $cur['dns'], 'nat.portforward' => [['interface' => 'wan', 'protocol' => 'tcp', 'destination' => ['network' => 'wanip', 'port' => '443'], 'target' => 'automatron', 'created' => ['time' => '1', 'username' => 'x']]]];
$ew = ['dns' => $dump['dns'], 'nat.portforward' => []];
[$new, $lines] = plan($ecur, $ew, $stamp);
t("an emptyable list (port forwards) can be emptied", $new === ['nat.portforward' => []] && $lines === ["  - nat.portforward wan|tcp|wanip|443"], json_encode($lines));
[$new, $lines] = plan(['dns' => $cur['dns'], 'nat.portforward' => []], $ew, $stamp);
t("an empty emptyable list declared empty is no change", $new === [] && $lines === []);
$w = $dump; $w['aliases'] = [];
t("aliases still refuse to be emptied", strpos((string)throws(function () use ($w) { plan(['aliases' => [['name' => 'a', 'type' => 'host', 'address' => '192.0.2.4']]], ['aliases' => []]); }), 'refusing to empty') !== false);

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
