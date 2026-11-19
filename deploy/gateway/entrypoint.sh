#!/bin/sh
# Force all egress of this network namespace (shared with the sandbox) through
# mitmproxy, then drop root and run the proxy as the only uid allowed out.
set -eu

PROXY_USER=mitm
PROXY_UID=$(id -u "$PROXY_USER")
PORT=8080

for ipt in iptables ip6tables; do
  # Anything on 80/443 not owned by the proxy user goes to the transparent listener.
  "$ipt" -t nat -A OUTPUT -p tcp -m owner ! --uid-owner "$PROXY_UID" \
         -m multiport --dports 80,443 -j REDIRECT --to-ports "$PORT"
  # Connections the nat rule above rewrote (and Docker's DNS DNAT to 127.0.0.11).
  # Matched by conntrack state: with the nf_tables backend the filter chain may
  # still see the pre-redirect output interface, so "-o lo" alone is not enough.
  "$ipt" -A OUTPUT -m conntrack --ctstate DNAT -j ACCEPT
  "$ipt" -A OUTPUT -o lo -j ACCEPT
  "$ipt" -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  "$ipt" -A OUTPUT -m owner --uid-owner "$PROXY_UID" -j ACCEPT   # only the proxy reaches the network
  "$ipt" -A OUTPUT -j REJECT                             # other TCP ports, all UDP (QUIC), ICMP...
done
echo "secretproxy: egress rules installed (proxy uid $PROXY_UID, port $PORT)"

mkdir -p /home/mitm/.mitmproxy
chown -R "$PROXY_USER:$PROXY_USER" /home/mitm 2>/dev/null || true  # bind mounts may refuse chown

exec setpriv --reuid="$PROXY_USER" --regid="$PROXY_USER" --init-groups --inh-caps=-all \
  env HOME=/home/mitm mitmdump \
    --mode transparent --listen-host 127.0.0.1 --listen-port "$PORT" \
    -s /opt/secretproxy/addon_entry.py \
    --set confdir=/home/mitm/.mitmproxy \
    --set secretproxy_config=/etc/secretproxy/config.yaml \
    --set ssl_verify_upstream_trusted_ca=/etc/secretproxy/upstream-ca.pem \
    --set connection_strategy=lazy \
    --set flow_detail=0
