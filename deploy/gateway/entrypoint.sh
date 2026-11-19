#!/bin/sh
# secretproxy gateway container: install the egress rules, start the allowlist
# DNS resolver, then run the proxy as the unprivileged mitm user (uid 10001).
#
# Started as root (Docker): applies the rules itself, then drops privileges.
# Started as uid 10001 (Kubernetes sidecar): the rules come from an init
# container; this only starts DNS + the proxy.
#
# Environment:
#   MODE           local  : sandbox shares this network namespace (sidecar / pod)
#                  routed : sandboxes use this host as their default gateway. Run with
#                           --network host on a gateway VM, or on a Docker network.
#   SANDBOX_IFACE  routed: interface facing the sandbox network (e.g. eth1), or
#   SANDBOX_SUBNET routed: ...the subnet, to look the interface up
#   SANDBOX_USERS  local: users to confine (default: everyone except the proxy)
#   DNS_ALLOWLIST  1 (default) = only domains in config.yaml resolve; 0 = all names
#   ALLOW_DNS      0 disables DNS for the sandbox entirely (default 1)
#   DNS_PORT       local: port of the local allowlist resolver (default 5353)
#   DNS_UPSTREAM   resolver(s) to forward allowed names to, space-separated
#                  (default: the nameservers in /etc/resolv.conf)
#   UPSTREAM_CA    optional CA bundle for verifying upstream servers (default: certifi)
#   CONFIG         default /etc/secretproxy/config.yaml
#   CONFDIR        CA directory from `secretproxy gen-ca`, default /home/mitm/.mitmproxy
set -eu

export MODE="${MODE:-local}" PROXY_USER=mitm PROXY_PORT="${PROXY_PORT:-8080}"
# Same config.yaml as a systemd install: file:${CREDENTIALS_DIRECTORY}/<name>
# resolves to the mounted secret files here.
export CREDENTIALS_DIRECTORY="${CREDENTIALS_DIRECTORY:-/run/secrets}"
CONFIG="${CONFIG:-/etc/secretproxy/config.yaml}"
CONFDIR="${CONFDIR:-/home/mitm/.mitmproxy}"
ALLOW_DNS="${ALLOW_DNS:-1}"
[ "$MODE" != local ] || [ "$ALLOW_DNS" != 1 ] || export DNS_PORT="${DNS_PORT:-5353}"
IS_ROOT=0; [ "$(id -u)" != 0 ] || IS_ROOT=1

[ -e "$CONFIG" ] || { echo "secretproxy: config $CONFIG not found (mount it)" >&2; exit 1; }

if [ "$IS_ROOT" = 1 ]; then
  egress-rules.sh apply
else
  echo "secretproxy: running as uid $(id -u); egress rules must come from an init container"
fi

LISTEN=127.0.0.1
[ "$MODE" != routed ] || LISTEN=0.0.0.0   # PREROUTING REDIRECT delivers to the sandbox-facing address

if [ "$ALLOW_DNS" = 1 ]; then
  UPSTREAMS="${DNS_UPSTREAM:-$(awk '$1 == "nameserver" {print $2}' /etc/resolv.conf)}"
  [ -n "$UPSTREAMS" ] || { echo "secretproxy: no DNS upstream; set DNS_UPSTREAM" >&2; exit 1; }
  set -- -c "$CONFIG"
  for s in $UPSTREAMS; do set -- "$@" --upstream "$s"; done
  [ "${DNS_ALLOWLIST:-1}" = 1 ] || set -- "$@" --allow-all
  if [ "$MODE" = routed ]; then
    IFACE=$(egress-rules.sh iface)
    set -- "$@" --interface "$IFACE"
    WHERE="$IFACE:53"; LISTEN_OPTS=""
  else
    WHERE="127.0.0.1:$DNS_PORT"; LISTEN_OPTS="--listen-address=127.0.0.1 --port=$DNS_PORT"
  fi
  CONF="${TMPDIR:-/tmp}/secretproxy-dnsmasq.conf"
  secretproxy dns-config "$@" > "$CONF"
  # As root, dnsmasq drops to the proxy user: in local mode that uid is exempt from
  # the redirect, so its upstream queries leave while the sandbox's are captured.
  USER_OPTS="--pid-file="
  [ "$IS_ROOT" = 0 ] || USER_OPTS="--user=mitm --group=mitm --pid-file="
  # shellcheck disable=SC2086
  dnsmasq --conf-file="$CONF" $LISTEN_OPTS $USER_OPTS
  echo "secretproxy: DNS for the sandbox on $WHERE -> $UPSTREAMS (allowlist ${DNS_ALLOWLIST:-1})"
fi

set -- -c "$CONFIG" --confdir "$CONFDIR" --listen-host "$LISTEN" --port "$PROXY_PORT"
[ -z "${UPSTREAM_CA:-}" ] || set -- "$@" --upstream-ca "$UPSTREAM_CA"
if [ "$IS_ROOT" = 1 ]; then
  exec setpriv --reuid=mitm --regid=mitm --init-groups --inh-caps=-all \
    env HOME=/home/mitm secretproxy run "$@"
fi
exec secretproxy run "$@"
