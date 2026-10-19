<?php
// Tests for router/export-config.php's redaction — the one thing that must
// never be wrong, because it is what keeps secrets on the router.
//
//   php tests/redact-test.php
//
// Runs anywhere PHP runs: PFSENSE_EXPORT_LIB_ONLY loads the functions without
// config.inc, which only exists on pfSense.
putenv('PFSENSE_EXPORT_LIB_ONLY=1');
require __DIR__ . '/../router/export-config.php';

$pass = 0; $fail = 0;
function check($name, $ok) { global $pass, $fail; echo ($ok ? "  ok    " : "  FAIL  ") . "$name\n"; $ok ? $pass++ : $fail++; }

$wg  = 'aB3dEfGhIjKlMnOpQrStUvWxYz0123456789+/abcd=';
$fix = [
  'system' => ['user' => [['name' => 'admin', 'bcrypt-hash' => '$2y$10$abcdefghijklmnopqrstuv', 'descr' => 'Admin']],
               'device_key' => 'netgate-device-key-0000000000000000'],
  'cert'   => [['descr' => 'webgui', 'crt' => 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t', 'prv' => 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t']],
  'installedpackages' => ['wireguard' => ['tunnels' => ['item' => [['privatekey' => $wg, 'publickey' => 'PUBLICKEYvisible000000000000000000000000000=']]],
                                          'peers' => ['item' => [['presharedkey' => '', 'publickey' => 'PEERpub']]]]],
  'snmpd'  => ['rocommunity' => 'public'],
  'ipsec'  => ['client' => ['pre-shared-key' => 'correct horse battery staple']],
  'dyndnses' => ['dyndns' => [['username' => 'u', 'password' => 'hunter2hunter2']]],
];
$red = $fix; redact($red);
$flat = serialize($red);

foreach (['$2y$10$abcdefghijklmnopqrstuv', 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t', $wg, 'correct horse battery staple', 'hunter2hunter2', 'netgate-device-key-0000000000000000'] as $secret)
  check('no raw secret left: ' . substr($secret, 0, 12) . '…', strpos($flat, $secret) === false);
check('WireGuard private key becomes a fingerprint', $red['installedpackages']['wireguard']['tunnels']['item'][0]['privatekey'] === fp($wg));
check('fingerprint format is REDACTED:sha256:<12 hex>', (bool)preg_match('/^REDACTED:sha256:[0-9a-f]{12}$/', fp('x')));
check('same value, same fingerprint (a quiet night stays quiet)', fp($wg) === fp($wg));
check('changed value, different fingerprint (a rotation shows up)', fp($wg) !== fp($wg . 'X'));
check('SNMP community is redacted, even the default', strpos($red['snmpd']['rocommunity'], 'REDACTED:') === 0);
check('public key stays readable', $red['installedpackages']['wireguard']['tunnels']['item'][0]['publickey'] === 'PUBLICKEYvisible000000000000000000000000000=');
check('certificate (public) stays readable', $red['cert'][0]['crt'] === 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t');
check('descriptions and usernames stay readable', $red['system']['user'][0]['descr'] === 'Admin' && $red['dyndnses']['dyndns'][0]['username'] === 'u');
check('an empty secret stays empty (nothing to hide, nothing to diff)', $red['installedpackages']['wireguard']['peers']['item'][0]['presharedkey'] === '');

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
