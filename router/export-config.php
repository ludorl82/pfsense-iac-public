<?php
/*
 * The forced command of the `pfsense-drift` key: print pfSense's configuration,
 * normalised and REDACTED, and nothing else.
 *
 * Installed at /root/scripts/export-config.php on router. The key that runs
 * it can read this output and cannot open a shell, so the secrets in
 * config.xml never leave the router — not even towards the drift check.
 *
 * WHAT IS REDACTED. Every value whose element name says it is a secret —
 * certificate private keys (<prv>), WireGuard keys, pre-shared keys, password
 * hashes, and anything named pass/secret/psk/token/apikey/bindpw. Each becomes
 * REDACTED:sha256:<12 hex> of its value: a rotated secret still shows up as a
 * diff, its value never does. Twelve hex of a SHA-256 is a fingerprint, not a
 * way back — and every value hashed here is either random key material or
 * already a hash. Two names are here for a different reason: <device_key>
 * (the unit's identity towards Netgate's services) and the SNMP communities —
 * today's is the default "public", but a changed one would be a credential.
 *
 * WHAT IS NORMALISED. <revision> changes on every save (time, description,
 * user) and would make every night a diff. It is dropped. Nothing is sorted:
 * the order of firewall rules is part of their meaning.
 *
 * Loaded through config.inc and written back out with pfSense's own
 * dump_xml_config(), never read or edited as raw text — the same rule as every
 * write to this box.
 */
const SECRET = '/^(prv|privatekey|presharedkey|pre-shared-key|psk|bcrypt-hash|sha512-hash|md5-hash|nt-hash|password|passwd|pass|pwd|passphrase|secret|shared_key|tls|bindpw|ldap_bindpw|radius_secret|apikey|api_key|token|auth_key|authkey|device_key|rocommunity|rwcommunity|community)$/i';
const SECRET_PART = '/(password|passwd|secret|psk|apikey|api_key|token|bindpw|privatekey|presharedkey)/i';

function redact(&$node) {
    foreach ($node as $k => &$v) {
        $name = is_string($k) ? $k : '';
        if (is_array($v)) {
            if ($name !== '' && (preg_match(SECRET, $name) || preg_match(SECRET_PART, $name))) {
                // a secret stored as a list of values: fingerprint each
                array_walk_recursive($v, function (&$x) { if (is_string($x) && $x !== '') $x = fp($x); });
            } else {
                redact($v);
            }
        } elseif (is_string($v) && $v !== '' && $name !== '' &&
                  (preg_match(SECRET, $name) || preg_match(SECRET_PART, $name))) {
            $v = fp($v);
        }
    }
}
function fp($value) { return 'REDACTED:sha256:' . substr(hash('sha256', $value), 0, 12); }

// The functions above are pure and are what tests/redact-test.php exercises,
// on a CI runner that has no pfSense. Everything that needs the router is below.
if (getenv('PFSENSE_EXPORT_LIB_ONLY') !== '1') {
    require_once("config.inc");
    require_once("xmlparse.inc");
    $c = config_get_path('', []);
    unset($c['revision']);
    redact($c);
    echo dump_xml_config($c, g_get('xml_rootobj'));
}
