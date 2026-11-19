#!/bin/sh
# Sandbox start-up. If started as root (routed topology), point the default
# route at the gateway - on a VM this is your netplan/DHCP config - then drop
# to the unprivileged agent user with every capability removed for good.
set -eu
if [ "$(id -u)" = 0 ]; then
  if [ -n "${GATEWAY_IP:-}" ]; then
    ip route replace default via "$GATEWAY_IP"
  fi
  exec env -u GATEWAY_IP setpriv --reuid=agent --regid=agent --init-groups \
       --inh-caps=-all --bounding-set=-all "$@"
fi
exec "$@"
