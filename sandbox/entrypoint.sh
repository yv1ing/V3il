#!/bin/sh
set -eu

mkdir -p /home/v3il-deception /opt/deception /run/v3il /srv /var/lib/v3il/telemetry /var/www
chown 0:10001 /run/v3il
chmod 0750 /run/v3il
chmod 0700 /var/lib/v3il/telemetry

echo "v3il deception runtime starting"
exec /usr/local/bin/sandbox-proxy
