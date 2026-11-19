"""secretproxy command line.

    secretproxy run -c config.yaml --confdir DIR [--listen-host H] [--port P] [--upstream-ca F]
                                              run the transparent proxy (mitmdump + addon)
    secretproxy gen-ca DIR                    create the proxy CA (mitmproxy format)
    secretproxy new-placeholder NAME          print a fresh random placeholder
    secretproxy check -c config.yaml [--env-file F]
                                              validate config, resolve every secret (no values printed)
    secretproxy sandbox-env -c config.yaml    print NAME=placeholder lines for the sandbox env
    secretproxy dns-config -c config.yaml --upstream IP [--interface IF] [--allow-all]
                                              print a dnsmasq allowlist config for the sandbox network
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path

from .config import ConfigError, load_config
from .providers import SecretError, SecretStore, parse_dotenv


def mitmdump_args(config: str, confdir: str, listen_host: str = "127.0.0.1", port: int = 8080,
                  upstream_ca: str | None = None, extra: list[str] | None = None) -> list[str]:
    """Arguments for mitmdump: transparent mode, our addon, safe defaults."""
    args = [
        "--mode", "transparent",
        "--listen-host", listen_host,
        "--listen-port", str(port),
        "-s", str(Path(__file__).with_name("mitm_entry.py")),
        "--set", f"confdir={confdir}",
        "--set", f"secretproxy_config={config}",
        # Connect upstream only once a request has been checked, so refused
        # requests never open a connection.
        "--set", "connection_strategy=lazy",
        # Don't print request lines: a rewritten URL can contain a real value.
        "--set", "flow_detail=0",
    ]
    if upstream_ca:
        args += ["--set", f"ssl_verify_upstream_trusted_ca={upstream_ca}"]
    return args + list(extra or [])


def _load_env_file(path: str) -> None:
    with open(path, "r", encoding="utf-8") as fh:
        for k, v in parse_dotenv(fh.read()).items():
            os.environ.setdefault(k, v)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="secretproxy")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the transparent proxy (mitmdump with the secretproxy addon)")
    r.add_argument("-c", "--config", required=True)
    r.add_argument("--confdir", required=True, help="directory holding the CA created by gen-ca")
    r.add_argument("--listen-host", default="127.0.0.1",
                   help="127.0.0.1 for local mode, 0.0.0.0 for routed mode (default 127.0.0.1)")
    r.add_argument("--port", type=int, default=8080)
    r.add_argument("--upstream-ca", help="CA bundle for verifying upstream servers (default: certifi)")
    r.add_argument("extra", nargs=argparse.REMAINDER, help="extra mitmdump arguments after --")

    g = sub.add_parser("gen-ca", help="create mitmproxy-ca.pem / mitmproxy-ca-cert.pem in DIR")
    g.add_argument("dir")
    p = sub.add_parser("new-placeholder", help="print a random placeholder for a secret")
    p.add_argument("name")
    c = sub.add_parser("check", help="validate the config and resolve every secret")
    c.add_argument("-c", "--config", required=True)
    c.add_argument("--env-file", action="append", default=[],
                   help="load KEY=VALUE lines first (e.g. the service's secrets.env)")
    s = sub.add_parser("sandbox-env", help="print NAME=placeholder lines for the sandbox")
    s.add_argument("-c", "--config", required=True)
    d = sub.add_parser("dns-config", help="print a dnsmasq config that only resolves allowed domains")
    d.add_argument("-c", "--config", required=True)
    d.add_argument("--upstream", action="append", required=True, help="resolver to forward to (repeatable)")
    d.add_argument("--interface", help="sandbox-facing interface to answer on, e.g. eth1")
    d.add_argument("--allow-all", action="store_true", help="forward every name (no allowlist)")
    args = ap.parse_args(argv)

    if args.cmd == "gen-ca":
        from mitmproxy.certs import CertStore  # only needed here

        os.makedirs(args.dir, exist_ok=True)
        CertStore.from_store(args.dir, "mitmproxy", 2048)
        print(f"CA written to {args.dir}")
        print(f"  give clients ONLY: {os.path.join(args.dir, 'mitmproxy-ca-cert.pem')}")
        print(f"  keep private:      {os.path.join(args.dir, 'mitmproxy-ca.pem')} (contains the key)")
        return 0

    if args.cmd == "new-placeholder":
        slug = "".join(ch if ch.isalnum() else "_" for ch in args.name.lower())
        print(f"sp_{slug}_{secrets.token_hex(16)}")
        return 0

    try:
        cfg = load_config(args.config)
    except (ConfigError, OSError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "run":
        from mitmproxy.tools.main import mitmdump

        # Logs and the audit trail must reach journald / docker logs immediately,
        # not when a pipe buffer fills.
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(line_buffering=True)

        extra = args.extra[1:] if args.extra[:1] == ["--"] else args.extra
        return mitmdump(mitmdump_args(args.config, args.confdir, args.listen_host, args.port,
                                      args.upstream_ca, extra)) or 0

    if args.cmd == "dns-config":
        from .dns import dnsmasq_config

        sys.stdout.write(dnsmasq_config(cfg, args.upstream, args.interface, args.allow_all))
        return 0

    if args.cmd == "sandbox-env":
        for sec in cfg.secrets:
            if sec.sandbox_env:
                print(f"{sec.sandbox_env}={sec.placeholder}")
        return 0

    for f in args.env_file:
        try:
            _load_env_file(f)
        except OSError as exc:
            print(f"cannot read {f}: {exc.strerror}", file=sys.stderr)
            return 2
    store = SecretStore(cfg.providers)
    failed = 0
    for sec in cfg.secrets:
        try:
            store.get(sec.name, sec.refs, sec.ttl)
            print(f"ok    {sec.name:<16} -> {', '.join(sec.hosts.patterns)}")
        except SecretError as exc:
            failed += 1
            print(f"FAIL  {sec.name:<16} {exc}")
    print(f"{len(cfg.secrets) - failed}/{len(cfg.secrets)} secrets resolved "
          f"(tunnel: {', '.join(cfg.tunnel.patterns) or '-'}; default: {cfg.default})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
