# secret-proxy: transparent secret injection for agent sandboxes

The agent and the apps it runs only ever hold **placeholders** such as
`sp_openai_7c1d…`. A gateway outside the sandbox intercepts every outbound
connection at the network layer. It decrypts TLS only for hosts that have a
secret bound to them, and swaps placeholder → real value there and nowhere else.
Real values never enter the sandbox, and any value an upstream echoes back is
redacted to its placeholder before the response reaches the agent.

The app needs **no proxy settings and no code changes**. It only has to trust the
gateway's CA certificate, which is installed once in the sandbox image or VM.

It is a mitmproxy addon (`src/secretproxy/`) plus iptables rules
(`deploy/scripts/egress-rules.sh`) and an allowlisting DNS resolver.

## Contents

- [How it works](#how-it-works) · [How it knows what to replace](#how-it-knows-what-to-replace)
- [Security model](#security-model)
- [Choose a deployment](#choose-a-deployment)
- [Topology A: dedicated gateway VM (recommended)](#topology-a-dedicated-gateway-vm-recommended)
- [Topology B: gateway as a container on the gateway VM](#topology-b-gateway-as-a-container-on-the-gateway-vm)
- [Topology C: proxy and client app on the same VM](#topology-c-proxy-and-client-app-on-the-same-vm)
- [Topology D: Kubernetes](#topology-d-kubernetes)
- [Configure secrets](#configure-secrets)
- [Client trust: making apps accept the proxy CA](#client-trust-making-apps-accept-the-proxy-ca)
- [Config reference](#config-reference)
- [Operations](#operations)
- [Troubleshooting](#troubleshooting)
- [Development and tests](#development-and-tests)
- [Project layout](#project-layout) · [Prior art](#prior-art) · [Limitations](#limitations)

## How it works

```
 client VM / sandbox (agent, no secrets)          gateway (proxy, secrets, CA key)
 ┌────────────────────────────────┐              ┌──────────────────────────────────────────┐
 │ curl https://api.openai.com    │   default    │ egress rules (iptables)                  │
 │  -H "Authorization: Bearer     │   route /    │   tcp 80,443 from the sandbox → :8080    │
 │      sp_openai_7c1d…"          │   shared     │   dns 53 → allowlist resolver            │
 │                                │   netns      │   everything else → REJECT               │
 │ env: OPENAI_API_KEY=sp_…       │ ───────────► │                                          │
 │ trusts the proxy CA            │              │ secretproxy run (mitmproxy, no privileges)│
 │ NO proxy settings              │              │  1. original destination + TLS SNI       │
 └────────────────────────────────┘              │  2. inject/intercept → decrypt (our CA)  │
                                                 │     tunnel → pass through, not decrypted │
                                                 │     deny → refused                       │
                                                 │  3. placeholder → real value, only for   │
                                                 │     the bound host/path/method, else 403 │
                                                 │  4. connect to the SNI *name* (resolved  │
                                                 │     by the gateway), verify upstream TLS │
                                                 │  5. redact real values in the response   │
                                                 └───────────────────┬──────────────────────┘
                                                                     ▼ real TLS
                                                              api.openai.com
```

1. **Network, not configuration.** The sandbox's only way out is the gateway. In
   the VM topology the sandbox's default route points at the gateway VM. In
   container and pod topologies the sandbox shares the gateway's network
   namespace. Either way, every TCP connection on port 80 or 443 is redirected
   to the proxy, every DNS query goes to an allowlisting resolver, and
   everything else is rejected: other ports, UDP (so QUIC falls back to TCP),
   ICMP and raw IPs. An app cannot opt out, because there is no other route.
2. **Per-connection decision.** The proxy reads the original destination and the
   TLS SNI, then sorts each host into one of four classes:
   - **inject:** a secret is bound to the host. Decrypted, placeholders swapped.
   - **intercept:** decrypted and checked, never injected.
   - **tunnel:** passed through without decryption. Suits package registries and apps that pin certificates.
   - **deny:** refused. This is the default.
3. **Trust.** Decrypting HTTPS requires the client to trust the gateway's CA.
   This is OS or image setup, like a corporate TLS-inspection root, not app
   configuration. The CA *private key* never leaves the gateway.

### How it knows what to replace

It searches for **placeholders**, not for keys or particular header names. It
never enumerates environment variables or Vault looking for values. For every
request to a host it decrypts:

1. **The placeholder list comes from `config.yaml`.** Each secret entry pairs a
   placeholder (e.g. `sp_openai_5c0f…`) with a source and a binding.
2. **Search.** It checks every header value, the user:password inside
   `Authorization: Basic base64(…)`, the URL path, the query string, and the
   body (only for secrets that allow `body`). Matching is an exact substring
   match. Placeholders are long random strings, and config validation rejects
   one that is a substring of another, so there are no false matches.
3. **Check the binding.** A found placeholder is swapped only when the request
   matches that secret's `hosts`, `paths`, `methods` and https, and the
   location is listed in its `substitute`. Otherwise → `403`, and nothing goes
   upstream.
4. **Swap.** The real value is fetched *by secret name* from that entry's
   `value` source (cached for `ttl`) and written in place: as-is in headers,
   URL-encoded in the path or query, JSON- or form-escaped in bodies.
5. **`set_header` is the exception:** no search. It sets a named header on every
   request matching the binding, so the app sends nothing at all.

Two safety scans run as well: outbound requests are checked for *real* values
headed to an unbound host (→ `403`), and responses are scrubbed of real values
(→ placeholder).

## Security model

| Attack from inside the sandbox | What stops it |
|---|---|
| Read env, files, `/proc`, memory | Only placeholders exist there. Secrets, the CA key and the proxy run on another VM, or in another container's filesystem and PID namespace. |
| Root on the client VM, change routes or firewall | Topology A: the client VM's only network is isolated at the hypervisor or cloud level, and its only member is the gateway. There is no other path out. |
| Send the placeholder to `evil.com` to have it swapped | Placeholders are swapped only for their bound host, path, method and `https`. Anywhere else → `403`, and nothing goes upstream. |
| Use an allowed name with an attacker's IP (`curl --resolve`) | The gateway ignores the client's IP choice. It connects to the SNI *name*, resolves it itself, and verifies the upstream certificate. |
| SNI says `api.x`, `Host` header says `evil` | Mismatch → `403`. |
| Make the API echo the key back | Responses are redacted: headers, bodies (raw, URL-encoded, JSON-escaped, base64), streamed chunks, gzip/brotli, WebSocket frames. |
| Exfiltrate over other ports, UDP, ICMP | Rejected by the egress rules. |
| Exfiltrate through DNS (`<data>.attacker.com`) | The resolver only answers domains in the config. Other names are refused and never forwarded. |
| Connect to the proxy port directly with a placeholder | Refused: the port only accepts connections that arrived through the redirect. Placeholders are not secret, so this matters. |
| Use the proxy's host as a stepping stone (SSH, other services) | Routed mode rejects all other traffic from the sandbox network to the gateway. |
| Read logs | The audit log records secret *names*, never values, and request URLs are not printed. |

**What it cannot stop:** the agent *using* a secret against the host it is bound
to. That is the point of the binding. Limit the damage with `paths`, `methods`,
read-only or least-privilege keys, and short-lived credentials.

**Fail closed everywhere:**
- a stopped proxy means refused connections, never direct access
- an unresolvable secret means `502`, never a request without it
- the gateway forwards nothing (`ip_forward=0`), so a missing rule blocks traffic rather than opening it

## Choose a deployment

| | Isolation | Survives agent root on the client? | Use when |
|---|---|---|---|
| **A. Gateway VM + client VM(s)** (native install) | Separate machines, network isolated at the hypervisor or cloud | **Yes** | Production. **Recommended.** |
| **B. Gateway VM running the gateway container** | Same as A | Yes | You prefer shipping the gateway as an image |
| **C. Same VM, client app as another user** | Linux users + iptables on one host | **No.** Root can read secrets and flush rules | Single box, trusted that the agent never gets root |
| **D. Kubernetes** (sidecar per pod) | Containers in one pod, separate filesystems and PID namespaces | No for container escape; yes for in-container root without capabilities | Running many sandboxes on a cluster |
| Docker demo (`deploy/docker-compose*.yml`) | Containers | n/a | Trying it out, tests |

Why A is the default: the agent's machine holds nothing worth stealing, and its
network has no route except through the gateway. Even full root on the client
VM gains nothing. The gateway VM runs no agent code and needs no inbound access
except SSH from your admin network.

Why native over Docker on the gateway VM: Docker turns on IP forwarding and
rewrites iptables, which works against a firewall appliance, and it adds a root
daemon. Topology B is fine if your platform standard is containers. The image
runs with a minimal capability set and the same rules.

---

## Topology A: dedicated gateway VM (recommended)

```
             internet
                │
        eth0 (uplink, DHCP)
        ┌───────┴────────┐
        │   gateway VM   │  secretproxy + egress rules + dnsmasq
        └───────┬────────┘
        eth1 10.88.0.2/24
                │   isolated network: no internet, no other hosts
     ┌──────────┼──────────┐
  client VM  client VM   ...     each: one NIC, 10.88.0.x, default route + DNS = 10.88.0.2
```

### A1. Create the networks

The client VMs' *only* NIC must be on a network that nothing else is on except
the gateway's `eth1`. That is what makes the isolation hold even against root on
a client.

| Platform | Isolated network | Gateway VM NICs |
|---|---|---|
| Hyper-V | Private virtual switch | Default/External switch (eth0) + the private switch (eth1) |
| VirtualBox | "Internal Network" | NAT or Bridged (eth0) + Internal Network (eth1) |
| VMware | LAN segment or host-only network without NAT | NAT/Bridged (eth0) + the segment (eth1) |
| KVM/libvirt | Isolated network (no `<forward>`) | default NAT (eth0) + the isolated network (eth1) |
| AWS | Private subnet whose route table sends `0.0.0.0/0` to the gateway's ENI; no NAT gateway, no IGW route | Public-subnet ENI (eth0) + private-subnet ENI (eth1) with **source/destination check disabled** |
| Azure | Subnet with a route table `0.0.0.0/0` → next hop *Virtual appliance* = gateway's private IP | NIC in the client subnet with **IP forwarding enabled** (Azure setting; the OS keeps forwarding off) |
| GCP | VPC route `0.0.0.0/0` → next-hop-instance = gateway, with tags for client VMs | Gateway created with `--can-ip-forward` |

In the clouds, also allow inbound TCP 80/443 and UDP/TCP 53 from the client
subnet to the gateway (security group or NSG), and allow nothing else outbound
from the client subnet.

### A2. Install the gateway VM

Ubuntu 24.04 LTS or Debian 13 (mitmproxy 12 needs Python ≥ 3.12). Run as an
admin user with sudo. Copy this project to the VM first, for example with
`git clone` or `scp`, to `/tmp/secret-proxy`. Paths below assume that location.

```bash
cd /tmp/secret-proxy

# 1. Packages. DNSMASQ_EXCEPT keeps dnsmasq from becoming the VM's own resolver
#    (and from clashing with systemd-resolved on Ubuntu).
sudo apt-get update
sudo apt-get install -y python3-venv iptables dnsmasq
echo 'DNSMASQ_EXCEPT="lo"' | sudo tee -a /etc/default/dnsmasq

# 2. Network: eth0 = uplink, eth1 = 10.88.0.2/24 on the isolated network.
#    Check interface names with `ip -br link` and adjust the file first.
sudo install -m 0600 deploy/vm/netplan-gateway.yaml /etc/netplan/60-secretproxy.yaml
sudo netplan apply

# 3. The gateway never routes: forwarding off, so a missing rule fails closed.
sudo install -m 0644 deploy/vm/99-secretproxy.conf /etc/sysctl.d/99-secretproxy.conf
sudo sysctl --system

# 4. Service user and directories.
sudo useradd --system --home-dir /var/lib/secretproxy --shell /usr/sbin/nologin secretproxy
sudo install -d -o secretproxy -g secretproxy -m 0700 /var/lib/secretproxy
sudo install -d -o root -g secretproxy -m 0750 /etc/secretproxy

# 5. Code: a virtualenv owned by root (the service can't modify its own code).
sudo python3 -m venv /opt/secretproxy/venv
sudo /opt/secretproxy/venv/bin/pip install /tmp/secret-proxy
sudo install -m 0755 deploy/scripts/egress-rules.sh /opt/secretproxy/egress-rules.sh

# 6. The CA. The key stays here (0600, owned by the service user).
sudo -u secretproxy /opt/secretproxy/venv/bin/secretproxy gen-ca /var/lib/secretproxy/ca

# 7. Settings and config.
sudo install -m 0644 deploy/vm/gateway.env.example /etc/secretproxy/gateway.env
sudo install -m 0640 -o root -g secretproxy deploy/vm/config.example.yaml /etc/secretproxy/config.yaml
sudoedit /etc/secretproxy/gateway.env     # SANDBOX_IFACE=eth1 (your isolated NIC)
sudoedit /etc/secretproxy/config.yaml     # your hosts and secrets; see "Configure secrets"
```

8. **Secrets:** follow [Configure secrets](#configure-secrets). The recommended
   path is encrypted systemd credentials, about two commands per secret.

```bash
# 9. DNS allowlist for the clients: only domains in config.yaml resolve.
#    Regenerate whenever you change hosts in config.yaml.
sudo /opt/secretproxy/venv/bin/secretproxy dns-config -c /etc/secretproxy/config.yaml \
     --interface eth1 --upstream 1.1.1.1 --upstream 9.9.9.9 \
  | sudo tee /etc/dnsmasq.d/secretproxy.conf
sudo systemctl restart dnsmasq

# 10. Services: the egress rules start before networking, then the proxy.
sudo install -m 0644 deploy/vm/secretproxy-egress.service deploy/vm/secretproxy.service \
     /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now secretproxy-egress secretproxy
```

Firewall managers: disable `ufw` and `nftables.service` on the gateway, or make
sure they don't flush the ruleset. The egress rules live in their own chains
(`SP_NAT`, `SP_FILTER`, `SP_FORWARD`) hooked at the top of the built-in chains.

### A3. Verify the gateway

```bash
systemctl status secretproxy-egress secretproxy --no-pager
journalctl -u secretproxy -b | grep -E "ready|listening|WARNING"   # each secret: "secret 'x' ready"
sudo /opt/secretproxy/egress-rules.sh show                          # rules + packet counters
ss -ltnp | grep -E ':8080|:53 '                                     # proxy on :8080, dnsmasq on eth1:53
```

### A4. Set up each client VM

The client needs three things: a network that points at the gateway, trust in
the CA, and placeholders. It needs no proxy settings, no secrets and no
special software.

```bash
# 1. Network: its only NIC on the isolated network; route + DNS via the gateway.
sudo install -m 0600 netplan-client.yaml /etc/netplan/60-secretproxy.yaml   # from deploy/vm/
sudo netplan apply      # remove any other netplan file that configures this NIC

# 2. Trust the gateway CA (public certificate only). Get it from the gateway VM:
#      sudo cat /var/lib/secretproxy/ca/mitmproxy-ca-cert.pem
#    and put it on the client by image build, cloud-init or config management
#    (the client can't reach the gateway's SSH, on purpose).
sudo install -m 0644 secretproxy-ca.pem /usr/local/share/ca-certificates/secretproxy.crt
sudo update-ca-certificates
#    Runtimes with their own CA store: see "Client trust" below. For example:
echo 'NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/secretproxy.crt' | sudo tee -a /etc/environment
echo 'REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt' | sudo tee -a /etc/environment

# 3. Placeholders for the client app. Generate them on the gateway:
#      sudo /opt/secretproxy/venv/bin/secretproxy sandbox-env -c /etc/secretproxy/config.yaml
#    and put the NAME=placeholder lines into the app's environment, e.g. a
#    systemd EnvironmentFile or the agent's .env. They are not secret.

# 4. Run the agent as an unprivileged user (no sudo).
```

Verify from the client:
```bash
env | grep -i proxy                                   # nothing: the app is not proxy-aware
curl -sS https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY" | head -c 300
curl -sS https://example.com                          # refused: not allowlisted (DNS or 403)
```

On the gateway, `sudo tail -f /var/log/secretproxy/audit.jsonl` shows each
request with the secret *names* used and the decision.

## Topology B: gateway as a container on the gateway VM

The same VM layout as A (steps A1, plus A2 steps 2–3), but the gateway runs from
the image with **host networking**, so its rules apply to the VM's own
interfaces. The container runs with only `NET_ADMIN`, `NET_RAW`,
`NET_BIND_SERVICE`, `SETUID`, `SETGID` and `CHOWN`, and drops to uid 10001 for
the proxy.

```bash
cd /tmp/secret-proxy
sudo docker build -f deploy/gateway/Dockerfile -t secretproxy-gateway:latest .

# Host directories (uid/gid 10001 = the proxy user inside the image)
sudo install -d -o root -g 10001 -m 0750 /etc/secretproxy /etc/secretproxy/secrets
sudo install -d -o 10001 -g 10001 -m 0700 /var/lib/secretproxy/ca
sudo install -d -o 10001 -g 10001 -m 0750 /var/log/secretproxy
sudo docker run --rm --user 10001:10001 -v /var/lib/secretproxy/ca:/ca \
     --entrypoint secretproxy secretproxy-gateway:latest gen-ca /ca
sudo install -m 0640 -o root -g 10001 deploy/vm/config.example.yaml /etc/secretproxy/config.yaml
sudoedit /etc/secretproxy/config.yaml

# Secrets: one file per secret, referenced as file:${CREDENTIALS_DIRECTORY}/<name>
# (the container sets CREDENTIALS_DIRECTORY=/run/secrets).
read -rs KEY && printf %s "$KEY" | sudo tee /etc/secretproxy/secrets/openai >/dev/null; unset KEY
sudo chown root:10001 /etc/secretproxy/secrets/* && sudo chmod 0640 /etc/secretproxy/secrets/*

sudo docker compose -f deploy/vm/docker-compose.gateway.yml up -d
sudo docker compose -f deploy/vm/docker-compose.gateway.yml logs -f
```

The container runs dnsmasq itself with the allowlist, so don't install dnsmasq
on the host. Clients are set up exactly as in [A4](#a4-set-up-each-client-vm).
Trade-off against A: secret files are plaintext on disk (root:10001 0640), while
A keeps them encrypted at rest.

## Topology C: proxy and client app on the same VM

Use this only when the agent can never become root on that VM. Root can read
the secrets and remove the rules. The rules match the *user* the client app
runs as.

1. Do A2 steps 1, 4–7 and 10. Skip the netplan, sysctl and dnsmasq steps.
2. In `/etc/secretproxy/gateway.env` switch to the local block:
   ```
   MODE=local
   SANDBOX_USERS=agent
   LISTEN_HOST=127.0.0.1
   ```
3. Create the app's user with no sudo and no `docker` group (that group is root-equivalent):
   ```bash
   sudo useradd --create-home --shell /bin/bash agent
   ```
4. Trust the CA on this VM (A4 step 2), give the app the placeholders (A4 step 3),
   and run it as `agent` with `NoNewPrivileges`, so setuid binaries can't run as
   root. For example, as a systemd unit:
   ```ini
   [Service]
   User=agent
   NoNewPrivileges=yes
   EnvironmentFile=/etc/agent/placeholders.env
   ExecStart=/path/to/your/app
   ```
5. `sudo systemctl restart secretproxy-egress secretproxy`, then test as `agent`:
   `sudo -u agent curl -sS https://api.openai.com/...`.

Only `agent`'s traffic is confined. Root, apt and other users are unaffected. The
agent's DNS goes through the VM's normal resolver, so the DNS allowlist does not
apply in this topology. That is one more reason to prefer A.

## Topology D: Kubernetes

One sidecar per agent pod, using the Istio pattern:
- **`egress-rules`** (init container) is root with only `NET_ADMIN` and `NET_RAW`.
  It installs the pod's rules and exits: 80/443 go to the proxy, DNS goes to the
  allowlist resolver, everything else is refused.
- **`secretproxy`** (native sidecar, Kubernetes ≥ 1.29) runs as uid 10001 with no
  capabilities and a read-only root filesystem. It is the only container that
  mounts the secrets and the CA key.
- **`agent`** is your unchanged image, running as uid 1000 with no capabilities
  and no service-account token. It gets the placeholders as environment
  variables and a CA bundle mounted over the system path.
- **NetworkPolicy** adds defense in depth: ingress is denied, and egress is
  limited to cluster DNS plus public 80/443. Private ranges and cloud metadata
  are excluded.

```bash
# Build and push the gateway image; set it in deploy/k8s/agent-pod.yaml (and your agent image).
docker build -f deploy/gateway/Dockerfile -t REGISTRY/secretproxy-gateway:0.1.0 .
docker push REGISTRY/secretproxy-gateway:0.1.0

# CA (once). Secrets are created with kubectl, never committed.
secretproxy gen-ca ./ca
kubectl create namespace agents --dry-run=client -o yaml | kubectl apply -f -
kubectl -n agents create secret generic secretproxy-ca --from-file=./ca
read -rs KEY && kubectl -n agents create secret generic secretproxy-secrets \
     --from-literal=openai="$KEY"; unset KEY
#   ...or --from-file=openai=./openai.key, or sync from your secret manager with
#   External Secrets Operator / the Secrets Store CSI driver into this Secret.

# Config + placeholders (edit config.yaml first, replacing the REPLACE placeholders)
secretproxy sandbox-env -c deploy/k8s/config.yaml > deploy/k8s/placeholders.env
kubectl apply -k deploy/k8s
kubectl -n agents logs deploy/agent -c secretproxy -f      # audit trail
```

Two Kubernetes notes:
- **Pod Security:** the init container needs `NET_ADMIN`, which Pod Security
  "baseline" and "restricted" forbid. `deploy/k8s/namespace.yaml` therefore
  enforces `privileged` but warns and audits at `restricted`, in a namespace
  that holds only agent pods. To remove that exception, do the iptables setup
  from a node-level CNI plugin instead (the istio-cni approach).
- **Secrets at rest:** enable Kubernetes Secret encryption at rest (KMS) and
  RBAC-restrict `get secret` in the namespace. Better still, sync secrets from
  Vault or your cloud secret manager with the Secrets Store CSI driver.
- **uid 10001** is exempt from the rules (it is the proxy). Never run the agent
  container as 10001.

The exact pod (same users, capabilities and read-only filesystems) is modelled
in Docker by `deploy/docker-compose.pod.yml` and covered by the end-to-end tests.

---

## Configure secrets

Each secret in `config.yaml` has three parts:

1. **Where the real value comes from** (`value`, resolved only on the gateway).
2. **The placeholder** the client app uses in its place (`placeholder`, not secret).
3. **The binding**: where the swap is allowed (`hosts`, `paths`, `methods`,
   `substitute`). Outside the binding the placeholder is refused.

### Add a secret (step by step, Topology A)

```bash
SP=/opt/secretproxy/venv/bin/secretproxy

# 1. Store the value encrypted at rest (systemd credentials; TPM2-bound when the VM
#    has a TPM, otherwise bound to this VM's host key). It can't be decrypted elsewhere.
#    `read -s` keeps it out of shell history and off the screen.
sudo install -d -m 0700 /etc/secretproxy/credentials
read -rs KEY && printf %s "$KEY" \
  | sudo systemd-creds encrypt --name=openai - /etc/secretproxy/credentials/openai.cred
unset KEY

# 2. Let only the secretproxy service decrypt it (a drop-in; the shipped unit stays untouched).
sudo systemctl edit secretproxy
#    add:
#      [Service]
#      LoadCredentialEncrypted=openai:/etc/secretproxy/credentials/openai.cred

# 3. Make a placeholder and add the entry to /etc/secretproxy/config.yaml.
$SP new-placeholder openai          # -> sp_openai_5c0f…
```
```yaml
secrets:
  - name: openai
    value: file:${CREDENTIALS_DIRECTORY}/openai   # systemd decrypts it here, for this service only
    placeholder: sp_openai_5c0f…                    # from step 3
    sandbox_env: OPENAI_API_KEY                     # env var name on the client
    hosts: [api.openai.com]                         # exact host; globs: * one label, ** any
    paths: ["/v1/**"]                               # tighten to what the app needs
    methods: [GET, POST]
    substitute: [headers]                           # placeholder sent in a header
    refresh_on: [401]
```
```bash
# 4. Apply: restart (credentials are loaded at start) and check it resolved.
sudo systemctl restart secretproxy
journalctl -u secretproxy -n 50 | grep "secret 'openai'"      # -> secret 'openai' ready

# 5. If you added a new host: regenerate the DNS allowlist (A2 step 9).
# 6. Give clients the placeholder:
sudo $SP sandbox-env -c /etc/secretproxy/config.yaml           # OPENAI_API_KEY=sp_openai_5c0f…
```

The client app then sends `Authorization: Bearer sp_openai_5c0f…` exactly as it
would send a real key. The gateway swaps it on the way out to `api.openai.com`
and refuses it anywhere else.

> **The client app does not know it holds a placeholder.** You give it the
> placeholder wherever it would normally read the real key: its env var, .env
> file or config. Its code and SDK stay unchanged.

### Worked example: a data.gov API key

api.data.gov accepts the key as `?api_key=…` or as an `X-Api-Key` header.

**On the gateway:**
```bash
SP=/opt/secretproxy/venv/bin/secretproxy
read -rs KEY && printf %s "$KEY" \
  | sudo systemd-creds encrypt --name=datagov - /etc/secretproxy/credentials/datagov.cred
unset KEY
sudo systemctl edit secretproxy
#   [Service]
#   LoadCredentialEncrypted=datagov:/etc/secretproxy/credentials/datagov.cred
$SP new-placeholder datagov        # -> sp_datagov_9e41…
```
```yaml
# /etc/secretproxy/config.yaml
secrets:
  - name: datagov
    value: file:${CREDENTIALS_DIRECTORY}/datagov
    placeholder: sp_datagov_9e41…            # from new-placeholder
    sandbox_env: DATA_GOV_API_KEY
    hosts: [api.data.gov]                    # add agency hosts that take the same key, if used
    methods: [GET]                           # read-only use
    substitute: [query, headers]             # ?api_key=… and X-Api-Key: …
```
```bash
sudo systemctl restart secretproxy
journalctl -u secretproxy -n 20 | grep datagov                      # secret 'datagov' ready
# new host -> regenerate the DNS allowlist (A2 step 9), then:
sudo $SP sandbox-env -c /etc/secretproxy/config.yaml | grep DATA_GOV  # DATA_GOV_API_KEY=sp_datagov_9e41…
```

**On the client:** put `DATA_GOV_API_KEY=sp_datagov_9e41…` in the app's
environment, then use it exactly like a real key:
```bash
curl "https://api.data.gov/ed/collegescorecard/v1/schools?api_key=$DATA_GOV_API_KEY&school.name=Harvard"
curl -H "X-Api-Key: $DATA_GOV_API_KEY" "https://api.data.gov/ed/collegescorecard/v1/schools?school.name=Harvard"
```
```python
import os, requests
r = requests.get("https://api.data.gov/ed/collegescorecard/v1/schools",
                 params={"api_key": os.environ["DATA_GOV_API_KEY"], "school.name": "Harvard"})
```
The gateway rewrites `api_key=sp_datagov_9e41…` to the real key, URL-encoded,
for `GET https://api.data.gov/...` only. The same placeholder sent to any other
host, or with `POST`, gets `403`. If the response ever contains the real key,
the client sees the placeholder.

**Variant, app sends no key at all:** replace `substitute` with
`set_header: { name: X-Api-Key, format: "{}" }`. Every `GET` to `api.data.gov`
then carries the key, and the app makes plain unauthenticated calls.

### Where values can come from

`value` takes `<provider>:<reference>`, or a list of them tried in order
(fallbacks). A bare name means `env:`. In order of preference:

| Provider | Example | Best for | Notes |
|---|---|---|---|
| **systemd credential** (via `file:`) | `file:${CREDENTIALS_DIRECTORY}/openai` | Topology A | Encrypted at rest; decrypted only into the service's private `/run/credentials/secretproxy.service/`. |
| **`vault`** | `vault:secret/data/agents/github#token` | Teams with Vault | KV v2 (or v1). `providers: [{scheme: vault, options: {addr: …, token_file: …}}]`. Best: run Vault Agent with auto-auth on the gateway and point `token_file` at its token sink. Use `ttl:` to re-read. |
| **`cmd`** (any secret manager CLI) | see below | AWS / Azure / GCP / 1Password | Runs on the gateway as the `secretproxy` user with a timeout. stderr is never logged. Use the VM's cloud identity, so there's no extra credential to store. |
| **`file`** | `file:/run/secrets/openai` | Topology B, Kubernetes | Docker or Kubernetes secret files. Owner root, group = proxy user, mode 0640. |
| **`file` with `#KEY`** | `file:/etc/secretproxy/app.env#OPENAI_API_KEY` | Migrating an existing `.env` | Parses .env syntax. Plaintext on disk, so keep it 0640 root:secretproxy and never in the client's filesystem. |
| **`env`** | `env:OPENAI_API_KEY` | Development only | Visible in the process environment to root and the same user. |
| **plugin** | `providers: [{scheme: aws-sm, class: "mypkg.aws:AwsSM"}]` | Native SDK integrations | Subclass `secretproxy.providers.SecretProvider` and implement `get(ref) -> str`. |

`cmd` examples. Give the gateway VM's identity read access to *only these
secrets*:
```yaml
# AWS Secrets Manager (instance role with secretsmanager:GetSecretValue on the ARN)
value: cmd:aws secretsmanager get-secret-value --secret-id prod/openai --query SecretString --output text
# Azure Key Vault (managed identity; run `az login --identity` once as the service user)
value: cmd:az keyvault secret show --vault-name my-vault --name openai --query value -o tsv
# Google Secret Manager (VM service account with secretAccessor on the secret)
value: cmd:gcloud secrets versions access latest --secret=openai
# 1Password service account (its token is itself a systemd credential)
value: "cmd:sh -c 'OP_SERVICE_ACCOUNT_TOKEN=$(cat $CREDENTIALS_DIRECTORY/op_token) op read op://agents/openai/credential'"
```

### Binding best practices

- **One secret per API, the narrowest key the provider offers.** For example, a
  project-scoped key with read-only scopes where possible.
- **Exact hosts.** Avoid `*` patterns for injected secrets.
- **`paths` and `methods`.** For example `methods: [GET]` makes a GitHub token
  read-only regardless of its scopes.
- **Prefer `substitute: [headers]`.** Add `query` only for APIs that take keys in
  the URL. Add `body` only when unavoidable.
- **`set_header` versus `substitute`.** `substitute` swaps the placeholder only
  when the app sends it. `set_header` sets the header on *every* matching
  request, so the app sends nothing at all. Use `set_header` for tools you can't
  configure. The placeholder is still used for response redaction.
- **`ttl` and `refresh_on: [401]`** for anything that rotates.

### Rotate or remove

- **systemd credential / file:** replace the file (step 1), then
  `sudo systemctl restart secretproxy`. Clients keep the same placeholder, so
  nothing changes on their side.
- **vault / cmd with `ttl`:** rotation is picked up automatically within the TTL.
  `refresh_on: [401]` also re-fetches early when upstream rejects the old value.
  Old values stay on the redaction list until restart.
- **Remove:** delete the entry, the credential file and the `LoadCredentialEncrypted=`
  line, restart, and regenerate the DNS allowlist.

Placeholders can be rotated too: generate a new one, update config and clients.
That is useful when a placeholder appears somewhere it shouldn't.

## Client trust: making apps accept the proxy CA

Install the CA into the OS store, then cover runtimes that ship their own store.

| OS / runtime | How |
|---|---|
| Debian, Ubuntu, Alpine | copy to `/usr/local/share/ca-certificates/secretproxy.crt`, run `update-ca-certificates` |
| RHEL, Fedora, Amazon Linux | copy to `/etc/pki/ca-trust/source/anchors/secretproxy.crt`, run `update-ca-trust` |
| curl, wget, git, Go, Rust with native roots, .NET on Linux | use the OS store, nothing else needed |
| Python `requests`/`httpx`/`pip` (certifi) | `REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE` = the OS bundle (`/etc/ssl/certs/ca-certificates.crt` or `/etc/pki/tls/certs/ca-bundle.crt`) |
| Node.js | `NODE_EXTRA_CA_CERTS=/path/secretproxy.crt` (or `node --use-system-ca` on Node ≥ 23.8) |
| Java | `keytool -importcert -cacerts -alias secretproxy -file secretproxy.crt -storepass changeit -noprompt` |
| Apps pinning certificates or using bundled roots (some CLIs, mobile SDKs, Rust `webpki-roots`) | can't be decrypted: put their hosts in `tunnel:` (no injection for them) |

Set the environment variables system-wide (`/etc/environment`) or in the image,
not in the app's own config. That keeps the app unaware of the proxy.

## Config reference

```yaml
audit_log: /var/log/secretproxy/audit.jsonl   # omit to log the audit trail to stdout only
default: deny            # hosts matching nothing below: deny (recommended) | intercept
intercept: [internal.example.com]             # decrypt + check, never inject
tunnel: [pypi.org, "*.pythonhosted.org"]      # pass through, never decrypt or inject
stream_threshold: 1048576                     # bodies above this are redacted as a stream
providers:                                    # options for built-ins, or plugins
  - { scheme: vault, options: { addr: "https://vault:8200", token_file: /run/vault/token } }
  - { scheme: cmd, options: { timeout: 10 } }
secrets:
  - name: openai                       # unique; appears in logs (the value never does)
    value: ["file:${CREDENTIALS_DIRECTORY}/openai", "vault:secret/data/openai#key"]   # tried in order; quote ${…} inside [ ]
    placeholder: sp_openai_…           # >= 16 chars [A-Za-z0-9_.-], unique, from new-placeholder
    sandbox_env: OPENAI_API_KEY        # name used by `secretproxy sandbox-env`
    hosts: [api.openai.com]            # required; * = one DNS label, ** = any
    paths: ["/v1/**"]                  # default ["/**"]; * = one segment, ** = any
    methods: [GET, POST]               # default: all
    substitute: [headers, query]       # where the placeholder may appear: headers, query, path, body
    set_header: { name: Authorization, format: "Bearer {}" }   # optional: always set this header
    ttl: 3600                          # seconds a resolved value is cached (default: until restart)
    refresh_on: [401]                  # upstream statuses that drop the cached value
    redact_responses: true             # default true
```

Placeholders inside `Authorization: Basic base64(user:PLACEHOLDER)` are found and swapped too.

CLI (`/opt/secretproxy/venv/bin/secretproxy …` on a VM):

| Command | Purpose |
|---|---|
| `run -c CONFIG --confdir CA_DIR [--listen-host H] [--port P] [--upstream-ca F]` | start the proxy (what the systemd unit and the container run) |
| `check -c CONFIG [--env-file F]` | validate config and resolve every secret; prints names, never values |
| `gen-ca DIR` | create the CA (`mitmproxy-ca.pem` is private, `mitmproxy-ca-cert.pem` goes to clients) |
| `new-placeholder NAME` | random placeholder |
| `sandbox-env -c CONFIG` | `NAME=placeholder` lines for clients |
| `dns-config -c CONFIG --upstream IP [--interface IF] [--allow-all]` | dnsmasq allowlist config |

## Operations

| Task | Command |
|---|---|
| Logs | `journalctl -u secretproxy -f` |
| Audit trail | `sudo tail -f /var/log/secretproxy/audit.jsonl` (ship it to your SIEM) |
| Rules and counters | `sudo /opt/secretproxy/egress-rules.sh show` |
| Config change | edit, then `sudo systemctl restart secretproxy` (+ regenerate DNS if hosts changed) |
| Upgrade | `sudo /opt/secretproxy/venv/bin/pip install --upgrade /path/to/new/secret-proxy && sudo systemctl restart secretproxy` |
| Rotate the CA | `gen-ca` into a new dir, distribute the new cert to clients, switch `--confdir`, restart, remove the old cert from clients |
| Maintenance stop | `sudo systemctl stop secretproxy`: clients are refused (fail closed), never let through |

Keep the gateway minimal: no other services, OS security updates on, SSH only from your admin network.

## Troubleshooting

| Symptom (on the client) | Likely cause | Check |
|---|---|---|
| `SSL certificate problem: unable to get local issuer` | CA not trusted by that runtime | [Client trust](#client-trust-making-apps-accept-the-proxy-ca); `openssl s_client -connect api.openai.com:443` shows issuer `mitmproxy` |
| `403` with `{"error": "secretproxy", "reason": …}` | refused by policy; the reason says why | gateway audit log |
| `502 … secret 'x' unavailable` | provider failed (credential not loaded, Vault down, CLI error) | `journalctl -u secretproxy`; `systemctl cat secretproxy` for the `LoadCredentialEncrypted=` line |
| `Could not resolve host` | domain not in the allowlist, or DNS not reaching the gateway | regenerate `dns-config`; `resolvectl status` on the client |
| `Connection refused` at once | non-80/443 port, UDP, or the proxy is down | `systemctl status secretproxy`; that's the egress policy working |
| Connection hangs | client routing doesn't reach the gateway | `ip route` on the client; counters in `egress-rules.sh show` |
| `Host … does not match TLS SNI` | the client sent a different Host header than the TLS name | fix the client; this is blocked on purpose |
| App works for some hosts only | the others aren't in `hosts`/`intercept`/`tunnel` | add them; `default: deny` refuses the rest |

## Development and tests

```
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests -t .
```

End-to-end with real transparent interception in Docker (a fake upstream, so
nothing leaves your machine):
```
python tests/e2e_docker.py --topology local     # sidecar: = topology C / one host
python tests/e2e_docker.py --topology routed    # gateway + client on an isolated network: = topology A/B
python tests/e2e_docker.py --topology pod       # Docker model of the Kubernetes pod: = topology D
```

Native gateway install smoke test (the A2 commands in Ubuntu 24.04, `systemd-analyze verify`, rules, proxy start):
```
docker run --rm --cap-add NET_ADMIN -v "$PWD:/src:ro" ubuntu:24.04 sh /src/tests/vm_install_smoke.sh
```

## Project layout

```
secret-proxy/
├── pyproject.toml              # package metadata, dependencies, `secretproxy` CLI
├── src/secretproxy/            # the installable package
│   ├── addon.py                #   mitmproxy hooks (connect, request, response, websocket)
│   ├── rules.py                #   pure matching / substitution / redaction logic
│   ├── providers.py            #   env, file, cmd, vault + plugin loader
│   ├── dns.py                  #   DNS allowlist from the config
│   ├── config.py               #   YAML loading and validation
│   └── __main__.py             #   CLI
├── deploy/
│   ├── scripts/egress-rules.sh #   iptables rules for every topology (local | routed)
│   ├── vm/                     #   topology A/B/C: systemd units, env, netplan, sysctl, compose
│   ├── k8s/                    #   topology D: pod, NetworkPolicy, namespace, kustomization
│   ├── gateway/                #   gateway image (used by B, D and the demos)
│   └── docker-compose*.yml     #   demos / test topologies (local, routed, pod)
└── tests/
```

## Prior art

[Docker sandboxes](https://docs.docker.com/ai/sandboxes/configuration/credentials/),
[AgentConnect](https://www.agentconnect.md/docs/operate-govern/sandboxing/credential-protection)
and [agentcage](https://github.com/agentcage/agentcage) use the same pattern:
- a host-side proxy with its own CA
- a placeholder in the sandbox
- a header rewrite only for the bound host
- responses redacted
- only secret *names* logged

agentcage (Rust) is the closest open-source equivalent. The Kubernetes topology
follows Istio's init-container + sidecar interception.

## Limitations

- Apps that pin certificates must be tunnelled, which means no injection for them.
- The agent can still use a secret against its bound host. That is by design, so scope the binding.
- Body substitution is opt-in (`substitute: [body]`). Placeholders inside
  WebSocket *client* frames are not substituted, though server frames are redacted.
- Content the gateway can't read (custom encryption, archives) is not scanned
  for real values.
- Topology C and the Kubernetes topology rely on Linux users, capabilities and
  namespaces on a shared kernel. Topology A doesn't, which is why it's the
  recommendation.
