"""CLI helpers.

    python -m secretproxy gen-ca DIR              create the proxy CA (mitmproxy format)
    python -m secretproxy new-placeholder NAME    print a fresh random placeholder
    python -m secretproxy check -c config.yaml    validate config, resolve every secret (no values printed)
    python -m secretproxy sandbox-env -c config.yaml   print NAME=placeholder lines for the sandbox env
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys

from .config import ConfigError, load_config
from .providers import SecretError, SecretStore


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="secretproxy")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen-ca", help="create mitmproxy-ca.pem / mitmproxy-ca-cert.pem in DIR")
    g.add_argument("dir")
    p = sub.add_parser("new-placeholder", help="print a random placeholder for a secret")
    p.add_argument("name")
    for name in ("check", "sandbox-env"):
        c = sub.add_parser(name)
        c.add_argument("-c", "--config", required=True)
    args = ap.parse_args(argv)

    if args.cmd == "gen-ca":
        from mitmproxy.certs import CertStore  # only needed here

        os.makedirs(args.dir, exist_ok=True)
        CertStore.from_store(args.dir, "mitmproxy", 2048)
        print(f"CA written to {args.dir} (give the sandbox only mitmproxy-ca-cert.pem)")
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

    if args.cmd == "sandbox-env":
        for s in cfg.secrets:
            if s.sandbox_env:
                print(f"{s.sandbox_env}={s.placeholder}")
        return 0

    store = SecretStore(cfg.providers)
    failed = 0
    for s in cfg.secrets:
        try:
            store.get(s.name, s.refs, s.ttl)
            print(f"ok    {s.name}  -> {', '.join(s.hosts.patterns)}")
        except SecretError as exc:
            failed += 1
            print(f"FAIL  {s.name}: {exc}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
