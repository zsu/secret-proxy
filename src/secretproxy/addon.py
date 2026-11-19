"""mitmproxy addon: transparent secret injection.

Run (inside the gateway, after iptables redirects sandbox traffic here):

    mitmdump --mode transparent -s deploy/gateway/addon_entry.py \
        --set secretproxy_config=/etc/secretproxy/config.yaml \
        --set connection_strategy=lazy --set flow_detail=0
"""
from __future__ import annotations

import json
import logging
import sys
import threading
import time
from typing import Any

from mitmproxy import ctx, http, tls
from mitmproxy.proxy import server_hooks

from . import rules
from .config import Config, load_config
from .providers import SecretError, SecretStore

log = logging.getLogger("secretproxy")


def _strip_port(hostport: str) -> str:
    if hostport.startswith("["):
        return hostport[1 : hostport.find("]")].lower()
    return hostport.rsplit(":", 1)[0].lower() if hostport.count(":") == 1 else hostport.lower()


def _dec(b: bytes) -> str:
    return b.decode("utf-8", "surrogateescape")


def _enc(s: str) -> bytes:
    return s.encode("utf-8", "surrogateescape")


class SecretProxy:
    def __init__(self, config: Config | None = None) -> None:
        self.cfg: Config | None = None
        self.store: SecretStore | None = None
        self._audit_lock = threading.Lock()
        self._audit_fh = None
        if config is not None:
            self._install(config)

    # ----------------------------------------------------------- lifecycle

    def _install(self, cfg: Config) -> None:
        self.cfg = cfg
        self.store = SecretStore(cfg.providers)
        if self._audit_fh not in (None, sys.stdout):
            self._audit_fh.close()
        self._audit_fh = open(cfg.audit_log, "a", encoding="utf-8") if cfg.audit_log else None
        # Resolve everything once at startup so problems show up early and the
        # redactor knows every value before the first response arrives.
        for s in cfg.secrets:
            try:
                self.store.get(s.name, s.refs, s.ttl)
                log.info("secretproxy: secret %r ready", s.name)
            except SecretError as exc:
                log.warning("secretproxy: %s", exc)

    def load(self, loader) -> None:
        loader.add_option("secretproxy_config", str, "", "Path to the secretproxy YAML config.")

    def configure(self, updated) -> None:
        if "secretproxy_config" in updated and ctx.options.secretproxy_config:
            self._install(load_config(ctx.options.secretproxy_config))

    def done(self) -> None:
        if self._audit_fh:
            self._audit_fh.close()
            self._audit_fh = None

    def audit(self, **event: Any) -> None:
        event = {"ts": round(time.time(), 3), **event}
        line = json.dumps(event, separators=(",", ":"))
        if self._audit_fh:
            with self._audit_lock:
                self._audit_fh.write(line + "\n")
                self._audit_fh.flush()
        log.info("secretproxy %s", line)

    # --------------------------------------------------------- connection

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        """Tunnel-listed SNIs are passed through untouched; everything else is MITM'd."""
        assert self.cfg
        sni = (data.client_hello.sni or "").lower() or None
        if sni and self.cfg.classify(sni) == "tunnel":
            data.ignore_connection = True

    def server_connect(self, data: server_hooks.ServerConnectionHookData) -> None:
        """Last line of defence before any upstream TCP connection is opened.

        * The destination is pinned to the client's SNI (resolved by the gateway),
          so a sandbox can't pair an allowed SNI with an attacker's IP.
        * Anything that classifies as "deny" never gets a connection.
        """
        assert self.cfg
        addr = data.server.address
        if not addr:
            return
        name = (data.client.sni or data.server.sni or addr[0] or "").lower()
        cls = self.cfg.classify(name)
        if cls == "deny":
            data.server.error = "blocked by secretproxy egress policy"
            self.audit(event="connect", decision="deny", host=name, port=addr[1])
            return
        if data.client.sni and addr[0].lower() != data.client.sni.lower():
            data.server.address = (data.client.sni.lower(), addr[1])
        if cls == "tunnel":
            self.audit(event="connect", decision="tunnel", host=name, port=addr[1])

    # ------------------------------------------------------------ request

    def _view(self, flow: http.HTTPFlow) -> tuple[rules.Req | None, str]:
        r = flow.request
        host_hdr = _strip_port(r.host_header or "") if r.host_header else ""
        sni = (flow.client_conn.sni or "").lower()
        if r.scheme == "https":
            if sni and host_hdr and host_hdr != sni:
                return None, f"Host {host_hdr!r} does not match TLS SNI {sni!r}"
            host = sni or host_hdr or r.host.lower()
        else:
            host = host_hdr or r.host.lower()
        path, _, query = r.path.partition("?")
        body = r.get_content(strict=False) or b""
        return rules.Req(
            scheme=r.scheme,
            host=host,
            port=r.port,
            method=r.method,
            path=path,
            query=query,
            headers=[(_dec(k), _dec(v)) for k, v in r.headers.fields],
            body=body,
            content_type=r.headers.get("content-type", ""),
        ), ""

    def _block(self, flow: http.HTTPFlow, status: int, reason: str, **extra: Any) -> None:
        flow.response = http.Response.make(
            status,
            json.dumps({"error": "secretproxy", "reason": reason}),
            {"content-type": "application/json", "x-secretproxy": "blocked"},
        )
        flow.metadata["secretproxy"] = {"blocked": True}
        self.audit(event="request", decision="block", status=status, reason=reason,
                   method=flow.request.method, host=extra.get("host") or flow.request.pretty_host,
                   path=flow.request.path.split("?", 1)[0], **{k: v for k, v in extra.items() if k != "host"})

    def request(self, flow: http.HTTPFlow) -> None:
        assert self.cfg and self.store
        if flow.response is not None:
            return
        req, err = self._view(flow)
        if req is None:
            self._block(flow, 403, err)
            return
        outcome = rules.evaluate(self.cfg, self.store, req)
        if outcome.action == "block":
            self._block(flow, outcome.status, outcome.reason, host=req.host,
                        classification=outcome.classification)
            return

        new = outcome.request
        assert new is not None
        r = flow.request
        r.host = req.host  # connect to the name, resolved by the gateway (not the sandbox's IP)
        r.headers = http.Headers([(_enc(k), _enc(v)) for k, v in new.headers])
        r.path = new.path + (("?" + new.query) if new.query or "?" in r.path else "")
        if new.body != req.body:
            r.set_content(new.body)
        # Ask for an unencoded response so streamed bodies can be redacted.
        r.headers.pop("accept-encoding", None)
        flow.metadata["secretproxy"] = {"used": outcome.used, "host": req.host,
                                        "classification": outcome.classification}

    # ----------------------------------------------------------- response

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        assert self.cfg and self.store and flow.response
        meta = flow.metadata.get("secretproxy") or {}
        if meta.get("blocked"):
            return
        pairs = rules.redaction_pairs(self.cfg, self.store)
        resp = flow.response
        if pairs:
            resp.headers = http.Headers(
                [(k, _enc(rules.redact_text(_dec(v), pairs))) for k, v in resp.headers.fields]
            )
        ctype = resp.headers.get("content-type", "").lower()
        encoded = resp.headers.get("content-encoding", "identity").lower() not in ("", "identity")
        length = resp.headers.get("content-length")
        big = length is None or (length.isdigit() and int(length) > self.cfg.stream_threshold)
        # Stream SSE and large bodies through the chunk-safe redactor. Compressed
        # bodies stay buffered so response() can decode and redact them.
        if ("text/event-stream" in ctype or big) and not encoded:
            resp.stream = rules.StreamRedactor(pairs)

    def response(self, flow: http.HTTPFlow) -> None:
        assert self.cfg and self.store and flow.response
        meta = flow.metadata.get("secretproxy") or {}
        if meta.get("blocked"):
            return
        resp = flow.response
        if not resp.stream:
            content = resp.get_content(strict=False)
            if content:
                pairs = rules.redaction_pairs(self.cfg, self.store)
                red = rules.redact_bytes(content, pairs)
                if red != content:
                    resp.set_content(red)
        by_name = {s.name: s for s in self.cfg.secrets}
        for name in meta.get("used", []):
            if resp.status_code in by_name[name].refresh_on:
                self.store.invalidate(name)
        self.audit(event="request", decision="forward", status=resp.status_code,
                   method=flow.request.method, host=meta.get("host", flow.request.pretty_host),
                   path=flow.request.path.split("?", 1)[0], secrets=meta.get("used", []),
                   classification=meta.get("classification"), streamed=bool(resp.stream))

    def error(self, flow: http.HTTPFlow) -> None:
        self.audit(event="error", host=flow.request.pretty_host,
                   path=flow.request.path.split("?", 1)[0],
                   error=str(flow.error.msg if flow.error else "unknown"))

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        assert self.cfg and self.store and flow.websocket
        msg = flow.websocket.messages[-1]
        if msg.from_client:
            return
        pairs = rules.redaction_pairs(self.cfg, self.store)
        red = rules.redact_bytes(msg.content, pairs)
        if red != msg.content:
            msg.content = red


addons = [SecretProxy()]
