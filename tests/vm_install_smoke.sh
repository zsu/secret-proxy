#!/bin/sh
# Smoke test of the native gateway-VM install (README "Topology A"), run inside an
# Ubuntu 24.04 container:
#
#   docker run --rm --cap-add NET_ADMIN -v "$PWD:/src:ro" ubuntu:24.04 sh /src/tests/vm_install_smoke.sh
#
# Executes the README's install commands, verifies the systemd units, applies the
# routed egress rules on a dummy eth1 and starts the proxy as the service user.
# Not covered here: netplan, sysctl, a real boot, real client VMs.
set -eu
step() { printf '\n=== %s\n' "$*"; }
export DEBIAN_FRONTEND=noninteractive

step "1. OS packages"
apt-get update -qq
apt-get install -y -qq python3-venv iptables dnsmasq iproute2 systemd sudo >/dev/null
echo 'DNSMASQ_EXCEPT="lo"' >> /etc/default/dnsmasq
cp -r /src /tmp/secret-proxy && rm -rf /tmp/secret-proxy/.venv /tmp/secret-proxy/deploy/runtime
cd /tmp/secret-proxy

step "4. service user and directories"
useradd --system --home-dir /var/lib/secretproxy --shell /usr/sbin/nologin secretproxy
install -d -o secretproxy -g secretproxy -m 0700 /var/lib/secretproxy
install -d -o root -g secretproxy -m 0750 /etc/secretproxy
install -d -o secretproxy -g secretproxy -m 0750 /var/log/secretproxy

step "5. install the code"
python3 -m venv /opt/secretproxy/venv
/opt/secretproxy/venv/bin/pip install -q /tmp/secret-proxy
install -m 0755 deploy/scripts/egress-rules.sh /opt/secretproxy/egress-rules.sh

step "6. CA"
sudo -u secretproxy /opt/secretproxy/venv/bin/secretproxy gen-ca /var/lib/secretproxy/ca
ls -l /var/lib/secretproxy/ca

step "7. config (example placeholders replaced, one file credential)"
install -m 0644 deploy/vm/gateway.env.example /etc/secretproxy/gateway.env
install -m 0640 -o root -g secretproxy deploy/vm/config.example.yaml /etc/secretproxy/config.yaml
for n in openai anthropic github; do
  sed -i "s/sp_${n}_REPLACE-with-new-placeholder/$(/opt/secretproxy/venv/bin/secretproxy new-placeholder $n)/" \
    /etc/secretproxy/config.yaml
done
if grep -v '^[[:space:]]*#' /etc/secretproxy/config.yaml | grep -q REPLACE; then
  echo "placeholder left"; exit 1
fi
# Stand-in for /run/credentials/secretproxy.service (systemd-creds needs a booted systemd).
CRED=/run/credentials/secretproxy.service
install -d -o root -g secretproxy -m 0750 "$CRED"
for n in openai anthropic github vault_token; do
  printf 'test-%s-value' "$n" > "$CRED/$n"; chgrp secretproxy "$CRED/$n"; chmod 0640 "$CRED/$n"
done

step "8. check (as the service user, secrets resolved, values never printed)"
sudo -u secretproxy env CREDENTIALS_DIRECTORY="$CRED" \
  /opt/secretproxy/venv/bin/secretproxy check -c /etc/secretproxy/config.yaml || true
sudo -u secretproxy env CREDENTIALS_DIRECTORY="$CRED" \
  /opt/secretproxy/venv/bin/secretproxy check -c /etc/secretproxy/config.yaml \
  | grep -q "ok    openai" || { echo "openai credential did not resolve"; exit 1; }

step "9. DNS allowlist"
/opt/secretproxy/venv/bin/secretproxy dns-config -c /etc/secretproxy/config.yaml \
  --interface eth1 --upstream 1.1.1.1 --upstream 9.9.9.9 > /etc/dnsmasq.d/secretproxy.conf
cat /etc/dnsmasq.d/secretproxy.conf
dnsmasq --test --conf-file=/etc/dnsmasq.d/secretproxy.conf

step "10. systemd units"
install -m 0644 deploy/vm/secretproxy.service deploy/vm/secretproxy-egress.service /etc/systemd/system/
systemd-analyze verify /etc/systemd/system/secretproxy-egress.service /etc/systemd/system/secretproxy.service

step "egress rules (routed) on a dummy eth1"
ip link add eth1 type dummy && ip addr add 10.88.0.2/24 dev eth1 && ip link set eth1 up
set -a; . /etc/secretproxy/gateway.env; set +a
/opt/secretproxy/egress-rules.sh apply
/opt/secretproxy/egress-rules.sh apply   # idempotent
/opt/secretproxy/egress-rules.sh show | grep -E "REDIRECT|REJECT|ACCEPT" | head -20
[ "$(iptables -t nat -S PREROUTING | grep -c SP_NAT)" = 1 ] || { echo "hook duplicated"; exit 1; }

step "start the proxy as the service user (same command as the unit)"
sudo -u secretproxy env CREDENTIALS_DIRECTORY="$CRED" HOME=/var/lib/secretproxy \
  /opt/secretproxy/venv/bin/secretproxy run -c /etc/secretproxy/config.yaml \
  --confdir /var/lib/secretproxy/ca --listen-host 0.0.0.0 --port 8080 > /tmp/proxy.log 2>&1 &
for i in $(seq 1 30); do
  if grep -q "listening at" /tmp/proxy.log; then break; fi; sleep 1
done
cat /tmp/proxy.log
grep -q "listening at" /tmp/proxy.log || { echo "proxy did not start"; exit 1; }
grep -q "test-openai-value" /tmp/proxy.log && { echo "secret value leaked to log"; exit 1; }

step "SMOKE TEST PASSED"
