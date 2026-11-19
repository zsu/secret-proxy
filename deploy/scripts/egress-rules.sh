#!/bin/sh
# secretproxy egress rules: force a sandbox's traffic through the transparent proxy.
#
#   egress-rules.sh apply    install or refresh the rules (idempotent, safe to re-run)
#   egress-rules.sh show     print the current secretproxy rules with packet counters
#   egress-rules.sh iface    print the sandbox-facing interface (routed mode)
#   egress-rules.sh clear    remove the rules. Maintenance only: in local mode this
#                            gives confined users direct internet access again.
#
# Settings come from the environment (for systemd: /etc/secretproxy/gateway.env):
#
#   MODE            local  : the sandbox runs on THIS host / in this network namespace.
#                            Rules go in OUTPUT and match processes by user.
#                   routed : the sandbox is another VM or container whose default route
#                            points at this host. Rules go in PREROUTING/INPUT/FORWARD.
#   PROXY_PORT      transparent listener port of `secretproxy run` (default 8080)
#   PROXY_USER      user the proxy runs as (default secretproxy)
#   SANDBOX_USERS   local mode: space-separated users to confine, e.g. "agent".
#                   Empty = every user except PROXY_USER (right for a dedicated
#                   container netns / Kubernetes pod, wrong for a whole VM: it would
#                   confine root/apt too).
#   DNS_PORT        local mode: redirect confined DNS (udp/tcp 53, any resolver) to
#                   this local port, where an allowlisting dnsmasq runs as PROXY_USER.
#                   Empty = confined users can't resolve except via loopback resolvers.
#   SANDBOX_IFACE   routed mode: interface facing the sandbox network, e.g. eth1
#   SANDBOX_SUBNET  routed mode: alternative to SANDBOX_IFACE; the interface that
#                   routes this subnet is used (needs the interface to be up)
#   ALLOW_DNS       routed mode: 1 (default) lets the sandbox query DNS on this host
#
# Everything the rules don't redirect to the proxy is REJECTed, so a missing or
# stopped proxy fails closed. Direct connections to the proxy port that did not
# come through the redirect are refused too: placeholders are not secret, so
# nobody may talk to the proxy except via the redirect.
set -eu

ACTION=${1:-apply}
MODE=${MODE:-local}
PORT=${PROXY_PORT:-8080}
PROXY_USER=${PROXY_USER:-secretproxy}
ALLOW_DNS=${ALLOW_DNS:-1}

die() { echo "egress-rules: $*" >&2; exit 1; }
families() { echo iptables; if command -v ip6tables >/dev/null 2>&1; then echo ip6tables; fi; }

hook()     { "$1" -t "$2" -C "$3" -j "$4" 2>/dev/null || "$1" -t "$2" -I "$3" 1 -j "$4"; }
unhook()   { while "$1" -t "$2" -D "$3" -j "$4" 2>/dev/null; do :; done; }
newchain() { "$1" -t "$2" -N "$3" 2>/dev/null || "$1" -t "$2" -F "$3"; }
delchain() { "$1" -t "$2" -F "$3" 2>/dev/null || true; "$1" -t "$2" -X "$3" 2>/dev/null || true; }

sandbox_iface() {
  if [ -n "${SANDBOX_IFACE:-}" ]; then echo "$SANDBOX_IFACE"; return; fi
  [ -n "${SANDBOX_SUBNET:-}" ] || die "routed mode needs SANDBOX_IFACE or SANDBOX_SUBNET"
  i=$(ip -o route show "$SANDBOX_SUBNET" | awk '{for (n = 1; n < NF; n++) if ($n == "dev") { print $(n + 1); exit }}')
  [ -n "$i" ] || die "no interface routes $SANDBOX_SUBNET (is it up?)"
  echo "$i"
}

clear_all() {
  for ipt in $(families); do
    unhook "$ipt" nat OUTPUT SP_NAT;     unhook "$ipt" nat PREROUTING SP_NAT
    unhook "$ipt" filter OUTPUT SP_FILTER; unhook "$ipt" filter INPUT SP_FILTER
    unhook "$ipt" filter FORWARD SP_FORWARD
    delchain "$ipt" nat SP_NAT; delchain "$ipt" filter SP_FILTER; delchain "$ipt" filter SP_FORWARD
  done
}

# Append a rule once per confined identity (local mode).
confined() {
  ipt=$1 table=$2 chain=$3; shift 3
  if [ -n "${SANDBOX_USERS:-}" ]; then
    for u in $SANDBOX_USERS; do
      "$ipt" -t "$table" -A "$chain" -m owner --uid-owner "$(id -u "$u")" "$@"
    done
  else
    "$ipt" -t "$table" -A "$chain" -m owner ! --uid-owner "$PROXY_UID" "$@"
  fi
}

apply_local() {
  PROXY_UID=$(id -u "$PROXY_USER" 2>/dev/null) || die "user $PROXY_USER does not exist"
  for u in ${SANDBOX_USERS:-}; do
    id -u "$u" >/dev/null 2>&1 || die "sandbox user $u does not exist"
    [ "$(id -u "$u")" != "$PROXY_UID" ] || die "sandbox user must differ from PROXY_USER"
  done
  for ipt in $(families); do
    unhook "$ipt" nat PREROUTING SP_NAT; unhook "$ipt" filter INPUT SP_FILTER
    unhook "$ipt" filter FORWARD SP_FORWARD; delchain "$ipt" filter SP_FORWARD
    newchain "$ipt" nat SP_NAT
    newchain "$ipt" filter SP_FILTER
    # 80/443 from confined users -> the proxy.
    confined "$ipt" nat SP_NAT -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports "$PORT"
    # DNS from confined users -> the local allowlist resolver, whatever server they asked.
    if [ -n "${DNS_PORT:-}" ]; then
      confined "$ipt" nat SP_NAT -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
      confined "$ipt" nat SP_NAT -p tcp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
    fi
    # Nobody talks to the proxy port directly (only via the redirect above).
    "$ipt" -A SP_FILTER -o lo -p tcp --dport "$PORT" -m conntrack ! --ctstate DNAT -j REJECT
    # Redirected connections (and Docker's DNS DNAT to 127.0.0.11). Matched by
    # conntrack state: with nf_tables the filter chain may still see the
    # pre-redirect output interface, so "-o lo" alone is not enough.
    confined "$ipt" filter SP_FILTER -m conntrack --ctstate DNAT -j ACCEPT
    confined "$ipt" filter SP_FILTER -o lo -j ACCEPT
    confined "$ipt" filter SP_FILTER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    confined "$ipt" filter SP_FILTER -j REJECT   # other ports, UDP (QUIC), ICMP, ...
    hook "$ipt" nat OUTPUT SP_NAT
    hook "$ipt" filter OUTPUT SP_FILTER
  done
  echo "egress-rules: local mode, proxy user $PROXY_USER, confined: ${SANDBOX_USERS:-everyone else}, port $PORT, dns ${DNS_PORT:-off}"
}

apply_routed() {
  IFACE=$(sandbox_iface)
  for ipt in $(families); do
    unhook "$ipt" nat OUTPUT SP_NAT; unhook "$ipt" filter OUTPUT SP_FILTER
    newchain "$ipt" nat SP_NAT
    newchain "$ipt" filter SP_FILTER
    newchain "$ipt" filter SP_FORWARD
    # 80/443 arriving from the sandbox network -> the proxy (whatever the destination IP).
    "$ipt" -t nat -A SP_NAT -i "$IFACE" -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports "$PORT"
    # INPUT: from any interface, the proxy port only accepts redirected connections.
    "$ipt" -A SP_FILTER -p tcp --dport "$PORT" -m conntrack ! --ctstate DNAT -j REJECT
    "$ipt" -A SP_FILTER -i "$IFACE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    "$ipt" -A SP_FILTER -i "$IFACE" -p tcp --dport "$PORT" -j ACCEPT
    if [ "$ALLOW_DNS" = 1 ]; then
      "$ipt" -A SP_FILTER -i "$IFACE" -p udp --dport 53 -j ACCEPT
      "$ipt" -A SP_FILTER -i "$IFACE" -p tcp --dport 53 -j ACCEPT
    fi
    "$ipt" -A SP_FILTER -i "$IFACE" -j REJECT   # SSH, other services on this host, ...
    # Never route sandbox traffic anywhere (also if ip_forward gets switched on).
    "$ipt" -A SP_FORWARD -i "$IFACE" -j REJECT
    "$ipt" -A SP_FORWARD -o "$IFACE" -j REJECT
    hook "$ipt" nat PREROUTING SP_NAT
    hook "$ipt" filter INPUT SP_FILTER
    hook "$ipt" filter FORWARD SP_FORWARD
  done
  fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)
  [ "$fwd" = 0 ] || echo "egress-rules: note: net.ipv4.ip_forward=1 is not needed; 0 makes a missing rule fail closed" >&2
  echo "egress-rules: routed mode, sandbox interface $IFACE, port $PORT, dns $ALLOW_DNS"
}

show() {
  for ipt in $(families); do
    for spec in "nat SP_NAT" "filter SP_FILTER" "filter SP_FORWARD"; do
      set -- $spec
      echo "== $ipt -t $1 $2"
      "$ipt" -t "$1" -L "$2" -v -n 2>/dev/null || echo "(not present)"
    done
  done
}

[ "$(id -u)" = 0 ] || [ "$ACTION" = iface ] || die "must run as root"
case "$ACTION" in
  apply)
    case "$MODE" in
      local) apply_local ;;
      routed) apply_routed ;;
      *) die "MODE must be local or routed, got '$MODE'" ;;
    esac ;;
  show) show ;;
  iface) sandbox_iface ;;
  clear) clear_all; echo "egress-rules: removed" ;;
  *) die "usage: $0 apply|show|iface|clear" ;;
esac
