"""End-to-end test of the transparent path in Docker.

    python tests/e2e_docker.py [--keep]

1. Generates the proxy CA, a throwaway "public" CA + cert for the fake upstream,
   random real secrets for the three providers (file/.env, env, cmd), and the
   sandbox env file (placeholders only).
2. docker compose up --build (fakeapi, gateway, sandbox).
3. Runs tests/sandbox_probe.py inside the sandbox (plain curl/sockets, no proxy config).
4. Checks the probe output against what fakeapi actually received, the gateway
   audit log, and a scan of the sandbox filesystem + /proc for the real values.
"""
from __future__ import annotations

import argparse
import datetime as dt
import io
import json
import secrets
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from urllib.parse import quote_plus

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
RT = DEPLOY / "runtime"
COMPOSE = ["docker", "compose", "-f", str(DEPLOY / "docker-compose.yml")]


def run(args, *, input=None, check=True, cwd=ROOT, timeout=900) -> str:
    p = subprocess.run(args, cwd=cwd, input=input, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(map(str, args))} failed ({p.returncode}):\n{p.stdout}\n{p.stderr}")
    return p.stdout


# ----------------------------------------------------------------- setup


def gen_public_test_ca(outdir: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Public Test Root CA")])
    ku = dict(content_commitment=False, key_encipherment=False, data_encipherment=False,
              key_agreement=False, encipher_only=False, decipher_only=False)
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, **ku),
                         critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    names = ["api.example.test", "evil.example.test", "tunnel.example.test", "intercepted.example.test"]
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False, **ku),
                           critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    (outdir / "public-test-ca.pem").write_bytes(ca.public_bytes(pem))
    (outdir / "fakeapi.pem").write_bytes(leaf.public_bytes(pem))
    (outdir / "fakeapi.key").write_bytes(key.private_bytes(
        pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def setup() -> dict[str, str]:
    shutil.rmtree(RT, ignore_errors=True)
    for d in ("ca", "certs", "secrets"):
        (RT / d).mkdir(parents=True)
    run([sys.executable, "-m", "secretproxy", "gen-ca", str(RT / "ca")])
    gen_public_test_ca(RT / "certs")
    real = {
        "fakeapi": f"fa-REAL-{secrets.token_urlsafe(18)}/+=",
        "envtoken": f"env-REAL-{secrets.token_urlsafe(18)}",
        "cmdtoken": f"cmd-REAL-{secrets.token_urlsafe(18)}",
    }
    w = lambda p, s: p.write_text(s, encoding="utf-8", newline="\n")
    w(RT / "secrets" / "fakeapi.env", f'# gateway-only .env\nOTHER=1\nFAKEAPI_TOKEN="{real["fakeapi"]}"\n')
    w(RT / "secrets" / "cmd_token", real["cmdtoken"] + "\n")
    w(RT / "gateway.env", f"ENV_TOKEN={real['envtoken']}\n")
    w(RT / "sandbox.env",
      run([sys.executable, "-m", "secretproxy", "sandbox-env", "-c", str(DEPLOY / "config.yaml")]))
    return real


def up() -> None:
    run(COMPOSE + ["up", "-d", "--build", "--force-recreate"], timeout=1800)
    deadline = time.time() + 90
    while time.time() < deadline:
        # mitmdump listening on 127.0.0.1:8080 (0100007F:1F90, state 0A = LISTEN)?
        tcp = run(COMPOSE + ["exec", "-T", "gateway", "cat", "/proc/net/tcp"], check=False)
        if any(f[1] == "0100007F:1F90" and f[3] == "0A"
               for f in (l.split() for l in tcp.splitlines()[1:]) if len(f) > 3):
            return
        if "exited with code" in run(COMPOSE + ["ps", "-a"], check=False):
            break
        time.sleep(1)
    raise RuntimeError("gateway did not start:\n" + run(COMPOSE + ["logs", "gateway"], check=False))


# ------------------------------------------------------------------ checks


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="leave the stack running afterwards")
    args = ap.parse_args()

    real = setup()
    ph = {line.split("=", 1)[0]: line.split("=", 1)[1]
          for line in (RT / "sandbox.env").read_text().splitlines() if "=" in line}
    PH_FA, PH_ENV, PH_CMD = ph["FAKEAPI_TOKEN"], ph["ENV_TOKEN"], ph["CMD_TOKEN"]
    print("building and starting the stack ...", flush=True)
    up()
    try:
        probe = json.loads(run(COMPOSE + ["exec", "-T", "sandbox", "python3", "-"],
                               input=(ROOT / "tests" / "sandbox_probe.py").read_text()))
        upstream = [json.loads(l) for l in
                    run(COMPOSE + ["exec", "-T", "fakeapi", "cat", "/log/requests.jsonl"]).splitlines() if l]
        audit_raw = run(COMPOSE + ["exec", "-T", "gateway", "cat", "/home/mitm/audit.jsonl"], check=False)
        gateway_logs = run(COMPOSE + ["logs", "gateway"], check=False)
        proc_dump = run(COMPOSE + ["exec", "-T", "sandbox", "sh", "-c",
                                   "cat /proc/[0-9]*/environ /proc/[0-9]*/cmdline 2>/dev/null; env"],
                        check=False)
        cid = run(COMPOSE + ["ps", "-q", "sandbox"]).strip()
        fs_tar = subprocess.run(["docker", "export", cid], capture_output=True, check=True).stdout
    finally:
        if not args.keep:
            run(COMPOSE + ["down", "-v"], check=False)

    def seen(path_prefix: str, host: str = "api.example.test"):
        return [e for e in upstream if e["path"].startswith(path_prefix) and (e["host"] or "").startswith(host)]

    def H(entry, name):  # header lookup, case-insensitive (HTTP/2 lowercases names)
        return {k.lower(): v for k, v in entry["headers"].items()}.get(name.lower())

    def body_json(r):
        try:
            return json.loads(r["body"])
        except ValueError:
            return {}

    results: list[tuple[str, bool, str]] = []

    def check(name, ok, detail=""):
        results.append((name, bool(ok), detail))

    # -- transparency / isolation
    check("app sees no proxy settings", probe["proxy_env"] == {}, str(probe["proxy_env"]))
    check("sandbox env holds placeholders only",
          probe["placeholders"] == {"FAKEAPI_TOKEN": PH_FA, "ENV_TOKEN": PH_ENV, "CMD_TOKEN": PH_CMD})
    check("gateway secrets not visible in sandbox", not probe["secrets_dir_visible"])
    check("sandbox runs as unprivileged uid 1000", probe["whoami"].startswith("uid=1000"), probe["whoami"])
    check("sandbox TLS to bound host is intercepted (mitmproxy CA)",
          probe["mitm"].get("ok") and "mitmproxy" in json.dumps(probe["mitm"].get("issuer", {})),
          str(probe["mitm"]))

    # -- injection, one per provider
    h = probe["header"]
    up_h = seen("/v1/echo")
    check("file(.env) secret injected into Authorization header",
          h["code"] == "200" and any(H(e, "Authorization") == f"Bearer {real['fakeapi']}"
                                     for e in up_h), h["code"] + h["err"])
    check("echoed secret redacted in response body + headers",
          h["code"] == "200" and real["fakeapi"] not in h["body"] + h["headers"]
          and f"Bearer {PH_FA}" in h["body"] and PH_FA in h["headers"])
    q = probe["query"]
    check("query-string placeholder injected (URL-encoded)",
          q["code"] == "200" and any(f"key={quote_plus(real['fakeapi'])}" in e["path"] for e in up_h)
          and real["fakeapi"] not in q["body"] and quote_plus(real["fakeapi"]) not in q["body"])
    s = probe["set_header"]
    check("env secret force-set as X-Api-Key (agent value overwritten)",
          s["code"] == "200" and any(H(e, "X-Api-Key") == real["envtoken"] for e in seen("/env/"))
          and H(body_json(s) or {"headers": {}}, "X-Api-Key") == PH_ENV, s["code"])
    c = probe["cmd"]
    check("cmd secret injected",
          c["code"] == "200" and any(H(e, "Authorization") == real["cmdtoken"] for e in seen("/cmd/"))
          and real["cmdtoken"] not in c["body"], c["code"])
    e = probe["sse"]
    check("SSE stream redacted across chunk boundary",
          e["code"] == "200" and PH_FA in e["body"] and real["fakeapi"] not in e["body"], e["body"][:120])
    p = probe["post_json"]
    check("POST with body forwarded", p["code"] == "200" and seen("/v1/chat"), p["code"])
    sp = probe["spoofed_ip"]
    check("sandbox-chosen IP ignored; gateway resolves the bound name",
          sp["code"] == "200" and seen("/v1/spoof"), sp["code"] + sp["err"])

    # -- exfiltration / policy
    ev = probe["exfil_denied_host"]
    check("placeholder to non-allowed host refused (403), never reached upstream",
          ev["code"] == "403" and not [x for x in upstream if (x["host"] or "").startswith("evil.")], ev["body"][:120])
    ie = probe["exfil_intercepted_host"]
    check("placeholder to allowed-but-unbound host refused (403)",
          ie["code"] == "403" and "not valid" in ie["body"] and not seen("/v1/echo", "intercepted."), ie["body"][:160])
    ic = probe["intercepted_clean"]
    check("clean request to intercepted host allowed", ic["code"] == "200" and seen("/hello", "intercepted."))
    check("unbound path refused", probe["wrong_path"]["code"] == "403" and not seen("/v2/"))
    check("unbound method refused", probe["wrong_method"]["code"] == "403"
          and not [x for x in up_h if x["method"] == "DELETE"])
    check("placeholder over plain HTTP refused", probe["plain_http"]["code"] == "403", probe["plain_http"]["body"][:120])
    check("unlisted host blocked", probe["unlisted_host"]["code"] in ("403", "000"), probe["unlisted_host"]["code"])
    check("raw IP over 443 blocked", probe["raw_ip"]["code"] in ("403", "000"), probe["raw_ip"]["code"])
    t = probe["tunnel"]
    check("tunnel host passed through undecrypted (upstream's own cert)",
          t.get("ok") and t["issuer"].get("commonName") == "Public Test Root CA", str(t))
    ts = probe["tunnel_spoofed_ip"]
    check("tunnel destination pinned to SNI, not sandbox-chosen IP",
          ts.get("ok") and ts["issuer"].get("commonName") == "Public Test Root CA", str(ts))
    check("other TCP ports blocked (22)", probe["tcp_22"] != "connected", probe["tcp_22"])
    check("direct container port blocked (8443)", probe["tcp_fakeapi_8443"] != "connected",
          probe["tcp_fakeapi_8443"])
    check("UDP/QUIC blocked", probe["udp_443"] != "received", probe["udp_443"])

    # -- no value leaks anywhere the agent or logs can see
    audit = [json.loads(l) for l in audit_raw.splitlines() if l.strip()]
    values = list(real.values()) + [quote_plus(v) for v in real.values()]
    check("audit log written with decisions",
          any(a.get("decision") == "block" for a in audit) and any(a.get("secrets") for a in audit),
          f"{len(audit)} entries")
    check("audit log + gateway output contain no secret values",
          not any(v in audit_raw or v in gateway_logs for v in values))
    check("sandbox /proc + env contain no secret values", not any(v in proc_dump for v in values))
    hits = []
    with tarfile.open(fileobj=io.BytesIO(fs_tar)) as tf:
        for m in tf:
            if m.isfile() and m.size < 20_000_000:
                data = tf.extractfile(m).read()
                hits += [m.name for v in values if v.encode() in data]
    check("sandbox filesystem contains no secret values", not hits, ", ".join(hits[:5]))

    width = max(len(n) for n, _, _ in results)
    failed = 0
    for name, ok, detail in results:
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {'' if ok else detail}")
    print(f"\n{len(results) - failed}/{len(results)} checks passed")
    (RT / "e2e-report.json").write_text(json.dumps(
        {"results": [{"check": n, "ok": o, "detail": d} for n, o, d in results], "probe": probe},
        indent=2), encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
