#!/bin/sh
# Install the router side of this repo on router, from the console:
# router/export-config.php (the drift check's forced command) and
# router/data.php (pfsense-apply.sh). Prints each file's sha256 as installed.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
KEY=${ADMIN_KEY:-$HOME/.ssh/id_ed25519_console}
HOST=${PFSENSE_HOST:-router.lab.example}
for f in export-config.php data.php; do
  ssh -4 -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
      -o UserKnownHostsFile="$ROOT/router/known_hosts" "admin@$HOST" \
      "cat > /root/scripts/$f.new && chmod 700 /root/scripts/$f.new && mv /root/scripts/$f.new /root/scripts/$f && echo \"$f \$(sha256 -q /root/scripts/$f)\"" \
      < "$ROOT/router/$f"
done
