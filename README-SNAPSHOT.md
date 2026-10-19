# Sanitized snapshot

A **sanitized, read-only snapshot** of the private repository that puts my
pfSense router under version control, published as a companion to the
infrastructure-as-code writing on [labodeludo.dev](https://labodeludo.dev/).
Its siblings: [nixos-iac-public](https://github.com/ludorl82/nixos-iac-public),
[k3s-iac-public](https://github.com/ludorl82/k3s-iac-public),
[aws-iac-public](https://github.com/ludorl82/aws-iac-public),
[cloudflare-iac-public](https://github.com/ludorl82/cloudflare-iac-public).

## What is fictional

Every domain, every IP address (RFC 5737 / RFC 3849 / 198.18.0.0/15, last
octet kept), every MAC and DUID, every lab hostname (the same aliases as the
sibling repos). **The home network's devices are all `home-device-NN`**: they
are a real household's, and their names said so. Certificates, SSH and
WireGuard public keys, and the router's host key are removed or fake. Secrets
were never in the private repo either — the router redacts them before its
configuration leaves it — and their fingerprints are dropped here.

## What is real

Every comment, the code (`router/*.php` runs on the router; `scripts/` on the
console and in Cronicle), the tests, the shape of the configuration, and the
firewall policy itself.

Published to be read, not deployed. It is not kept in sync with the private
original.
