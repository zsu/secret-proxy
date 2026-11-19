# secretproxy: transparent secret injection for agent sandboxes

The agent and the apps it runs only ever hold **placeholders** such as
`sp_openai_7c1d…`. A gateway outside the sandbox intercepts every outbound
connection at the network layer. It decrypts TLS only for hosts that have a
secret bound to them, and swaps placeholder → real value there and nowhere else.
Real values never enter the sandbox, and any value an upstream echoes back is
redacted to its placeholder before the response reaches the agent.

It is a mitmproxy addon (`src/secretproxy/addon.py`) plus iptables rules
(`deploy/gateway/entrypoint.sh`). The secret logic itself (`src/secretproxy/rules.py`) is pure Python with no mitmproxy dependency.

## Project layout

```
secret-proxy/
├── pyproject.toml            # package metadata, dependencies, `secretproxy` CLI
├── src/secretproxy/          # the installable package
│   ├── addon.py              #   mitmproxy hooks (connect, request, response, websocket)
│   ├── rules.py              #   pure matching / substitution / redaction logic
│   ├── providers.py          #   env, file, cmd, vault + plugin loader
│   ├── config.py             #   YAML loading and validation
│   └── __main__.py           #   CLI: gen-ca, new-placeholder, check, sandbox-env
├── tests/                    # unit tests + Docker end-to-end test
└── deploy/                   # Docker demo: gateway, sandbox, fake upstream, config
    └── gateway/addon_entry.py  # the script mitmdump loads (-s)
```

## Prior art

[Docker sandboxes](https://docs.docker.com/ai/sandboxes/configuration/credentials/), [AgentConnect](https://www.agentconnect.md/docs/operate-govern/sandboxing/credential-protection) and [agentcage](https://github.com/agentcage/agentcage) all use the same pattern:
  - a host-side proxy with its own CA
  - a placeholder in the sandbox
  - a header rewrite only for the bound host
  - responses redacted
  - only secret *names* logged

agentcage is the closest open-source equivalent (Rust). This project is the same architecture on mitmproxy, kept small so you can read and change it.

## How every request gets intercepted, with no app changes

```
 sandbox container (uid 1000, no caps)        gateway container (owns the netns)
 ┌──────────────────────────────┐            ┌──────────────────────────────────────────┐
 │ curl https://api.openai.com  │            │ iptables nat OUTPUT:                     │
 │  -H "Authorization: Bearer   │  connect   │   tcp 80,443 from uid != mitm            │
 │      sp_openai_7c1d…"        │──────────► │   → REDIRECT :8080                       │
 │                              │            │ iptables filter OUTPUT:                  │
 │ env: OPENAI_API_KEY=sp_…     │            │   lo ok, uid mitm ok, everything else    │
 │ trusts proxy CA (image)      │            │   REJECT (other ports, UDP/QUIC, IPv6)   │
 │ NO proxy settings            │            │                                          │
 └──────────────────────────────┘            │ mitmdump --mode transparent (uid mitm)   │
                                             │  1. SO_ORIGINAL_DST + TLS SNI            │
                                             │  2. classify SNI:                        │
                                             │     inject/intercept → MITM (our CA)     │
                                             │     tunnel → pass through, not decrypted │
                                             │     deny → no connection                 │
                                             │  3. addon: placeholder → real (bound     │
                                             │     host/path/method only), else 403     │
                                             │  4. connect to the SNI name resolved by  │
                                             │     the gateway, verify upstream TLS     │
                                             │  5. redact real values in the response   │
                                             │ secrets: env / file / cmd / vault        │
                                             └───────────────────┬──────────────────────┘
                                                                 ▼ real TLS
                                                          api.openai.com
```

1. **Network, not configuration.** The sandbox shares the gateway's network namespace (sidecar pattern) or routes through it (production). Every TCP connection to port 80 or 443 is redirected to mitmproxy. Everything else is rejected: other ports, UDP (which forces QUIC back to TCP), and raw IPv6. The sandbox has no `CAP_NET_ADMIN`, so it cannot change the rules. An app cannot opt out, because there is no other route out.
2. **Per-connection decision.** mitmproxy recovers the original destination (`SO_ORIGINAL_DST`) and reads the SNI from the ClientHello. The config sorts every host into one of four classes:
   - **inject:** a secret is bound to the host. Decrypted, placeholders swapped.
   - **intercept:** decrypted and checked, never injected.
   - **tunnel:** a raw pass-through, which also suits apps that pin certificates.
   - **deny:** no connection. This is the default.
3. **Trust.** To decrypt HTTPS, the client must trust the proxy CA. The sandbox *image* installs the CA cert in the system store and sets `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS` for runtimes that ship their own store. This is the same as a corporate TLS-inspection root. It is image setup, not app configuration. The CA *private key* stays in the gateway.

## Why the agent can't get the real secret

| Attack | What stops it |
|---|---|
| Read env, files or `/proc` in the sandbox | Only placeholders are there. Secrets, the CA key and the proxy process live in the gateway's filesystem and PID namespace. |
| Send the placeholder to `evil.com` to have it swapped | Placeholders are swapped only for their bound host, path, method and `https`. Anywhere else → `403`, and nothing goes upstream. |
| Use an allowed SNI but an attacker IP (`curl --resolve`) | The gateway ignores the sandbox's IP. It connects to the SNI *name*, resolves it itself, and verifies the upstream certificate. |
| SNI says `api.x` but the `Host` header says `evil` | Mismatch → `403`. |
| Get the API to echo the key back (httpbin-style, error messages) | Response headers and bodies are redacted back to the placeholder: raw, URL-encoded, JSON-escaped and base64 forms, across stream chunks, in gzip/brotli bodies and WebSocket frames. |
| Exfiltrate over another port, UDP, DNS-over-HTTPS to an IP | iptables rejects other ports and UDP. A raw IP on 443 is classified `deny`. |
| Somehow hold a real value and send it to another host | Outbound requests are also scanned for known real values → `403`. |
| Read logs | The audit log records secret *names*, never values. `flow_detail=0` stops mitmdump printing URLs. |

What it **cannot** stop is the agent *using* a secret against its bound host. That is the purpose of the binding. Limit the damage with `paths`, `methods` and least-privilege, short-lived keys.

## Secret providers

`value` is `<scheme>:<ref>`, or a list of them tried in order. References are resolved only in the gateway. A bare name means `env:`.

| Scheme | Example | Notes |
|---|---|---|
| `env` | `env:OPENAI_API_KEY` | gateway process environment (default) |
| `file` | `file:/run/secrets/token` | whole file (Docker/K8s secrets), trailing newline stripped |
| `file` | `file:/etc/sp/app.env#OPENAI_API_KEY` | one key from a .env-format file (quotes, `export`, comments) |
| `cmd` | `cmd:op read op://vault/openai/key` | stdout of a gateway-side command, e.g. `aws secretsmanager …`, `az keyvault …`, `gcloud secrets …`, `pass`. Has a timeout; stderr is never logged. |
| `vault` | `vault:secret/data/openai#api_key` | HashiCorp Vault KV v2/v1 over HTTPS (`VAULT_ADDR`, `VAULT_TOKEN` or `token_file`) |
| plugin | `providers: [{scheme: aws-sm, class: "mypkg.aws:AwsSM", options: {…}}]` | subclass `secretproxy.providers.SecretProvider` and implement `get(ref)` |

Two behaviours apply to every provider:
- **Cache and rotation:** `ttl:` refreshes a cached value on expiry, so rotation needs no restart. `refresh_on: [401]` drops the cache when upstream rejects the credential. Old values stay on the redaction list.
- **Fail closed:** if no source resolves, the request gets a `502` and nothing is sent upstream.

## Config

```yaml
audit_log: /var/log/secretproxy/audit.jsonl
default: deny                 # or: intercept (decrypt + allow everything else, no injection)
intercept: [internal.example.com]
tunnel: [pypi.org, "*.pythonhosted.org", github.com]
providers:                    # optional: options for built-ins, or plugins
  - { scheme: vault, options: { addr: "https://vault:8200", token_file: /run/secrets/vault_token } }
secrets:
  - name: openai
    value: [vault:secret/data/openai#api_key, env:OPENAI_API_KEY]
    placeholder: sp_openai_7c1d0e5b9a2f4c38b6e1d2a3f4b5c6d7   # secretproxy new-placeholder openai
    sandbox_env: OPENAI_API_KEY                               # secretproxy sandbox-env -c …
    hosts: [api.openai.com]   # globs: * = one label, ** = any
    paths: ["/v1/**"]
    methods: [GET, POST]
    substitute: [headers, query]   # also: path, body
    # set_header: { name: Authorization, format: "Bearer {}" }  # always set it; the agent sends nothing
    ttl: 3600
    refresh_on: [401]
    redact_responses: true
```

Basic auth works too: a placeholder inside `Authorization: Basic base64(user:PH)` is found and swapped.

## Run it

Install for development (Windows, macOS or Linux):
```
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -e .
```

Unit tests:
```
python -m unittest discover -s tests -t .
```

CLI helpers (installed as `secretproxy`):
```
secretproxy check -c deploy/config.yaml     # validate config, resolve every secret (names only)
secretproxy new-placeholder openai          # random placeholder for a new secret
secretproxy sandbox-env -c deploy/config.yaml   # NAME=placeholder lines for the sandbox env
secretproxy gen-ca ./ca                     # proxy CA in mitmproxy's format
```

End-to-end, real transparent interception in Docker (fake upstream, nothing leaves your machine):
```
python tests/e2e_docker.py          # add --keep to leave the stack running
docker compose -f deploy/docker-compose.yml exec sandbox bash   # poke around as the agent
```

The e2e test checks:
- no proxy settings and no real values in the sandbox (env, `/proc`, the whole filesystem)
- each provider injects correctly
- echoed and streamed values come back redacted
- exfiltration attempts are refused, and the fake upstream's log shows they never reached it
- spoofed IPs are ignored
- tunnel hosts are not decrypted
- other ports and UDP are blocked
- the audit log contains no values

## Production topology

The Docker demo uses the sidecar layout (`network_mode: service:gateway`). For real deployments, put the gateway in a **separate VM or network namespace** that is the sandbox's only route out:
- `iptables -t nat -A PREROUTING -i <sandbox-if> -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 8080`
- `FORWARD` policy `DROP`

This is how agentcage lays it out. It also lets several sandboxes share one gateway, with a separate config or CA per tenant.

## Limitations

- Apps that pin certificates must be `tunnel`ed, which means they get no injection.
- Agent-to-bound-host misuse is possible by design. Scope the binding.
- Body substitution is opt-in (`substitute: [body]`). Placeholders inside WebSocket client frames are not substituted, though server frames are redacted.
- Encrypted or compressed formats that the gateway can't see into (custom encryption, zip uploads) are not scanned.
- On Windows/macOS hosts, transparent mode needs Linux in the gateway: Docker, a VM or WSL. mitmproxy's `local` and `wireguard` modes are alternatives for intercepting processes on a desktop.
