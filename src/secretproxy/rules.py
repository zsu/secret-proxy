"""Pure request/response logic: no mitmproxy imports, fully unit-testable.

``evaluate()`` takes a plain view of a request and decides, per the config:
  * block (403) when a placeholder appears where its secret is not bound,
    when a real secret value is headed somewhere it is not bound, or when
    egress to the host is denied;
  * 502 when a needed secret cannot be resolved (fail closed);
  * otherwise forward, with placeholders replaced and ``set_header`` applied.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field, replace
from urllib.parse import quote, quote_plus

from .config import Config
from .providers import SecretError, SecretStore

_BASIC_RE = re.compile(r"^(\s*Basic\s+)([A-Za-z0-9+/=_-]+)(\s*)$", re.IGNORECASE)
_BAD_HEADER_CHARS = re.compile(r"[\r\n\x00]")


@dataclass
class Req:
    scheme: str
    host: str
    port: int
    method: str
    path: str  # without the query string
    query: str  # without the leading '?'
    headers: list[tuple[str, str]]
    body: bytes = b""
    content_type: str = ""


@dataclass
class Outcome:
    action: str  # "forward" | "block"
    status: int = 200
    reason: str = ""
    used: list[str] = field(default_factory=list)
    classification: str = ""
    request: Req | None = None


# ------------------------------------------------------------------ helpers


def _basic_decode(value: str) -> tuple[str, str, str] | None:
    m = _BASIC_RE.match(value)
    if not m:
        return None
    try:
        decoded = base64.b64decode(m.group(2), validate=False).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return m.group(1), decoded, m.group(3)


def _header_texts(value: str) -> list[str]:
    b = _basic_decode(value)
    return [value, b[1]] if b else [value]


def _locations_containing(req: Req, needle: str) -> set[str]:
    """Which parts of the request contain ``needle`` (also inside Basic auth)."""
    locs: set[str] = set()
    if any(needle in t for _, v in req.headers for t in _header_texts(v)):
        locs.add("headers")
    if needle in req.path or quote(needle, safe="") in req.path:
        locs.add("path")
    if needle in req.query or quote_plus(needle) in req.query or quote(needle, safe="") in req.query:
        locs.add("query")
    if req.body and needle.encode() in req.body:
        locs.add("body")
    return locs


def _replace_header(value: str, mapping: dict[str, str]) -> str:
    b = _basic_decode(value)
    if b:
        prefix, decoded, suffix = b
        new = decoded
        for ph, real in mapping.items():
            new = new.replace(ph, real)
        if new != decoded:
            return prefix + base64.b64encode(new.encode()).decode() + suffix
    for ph, real in mapping.items():
        value = value.replace(ph, real)
    return value


def _body_encoder(content_type: str):
    ct = content_type.lower()
    if "json" in ct:
        return lambda v: json.dumps(v)[1:-1]
    if "x-www-form-urlencoded" in ct:
        return quote_plus
    return lambda v: v


# ----------------------------------------------------------------- evaluate


def evaluate(cfg: Config, store: SecretStore, req: Req) -> Outcome:
    cls = cfg.classify(req.host)
    where = f"{req.method} {req.scheme}://{req.host}{req.path}"
    if cls in ("deny", "tunnel"):
        # A "tunnel" host only reaches here over plain HTTP, which is never passed blindly.
        return Outcome("block", 403, f"egress to {req.host} is not allowed", classification=cls)

    by_name = {s.name: s for s in cfg.secrets}
    bound = {s.name for s in cfg.secrets if s.binds(req.scheme, req.host, req.path, req.method)}

    # 1. Placeholders are only valid where their secret is bound, in allowed locations.
    found: dict[str, set[str]] = {}
    for s in cfg.secrets:
        locs = _locations_containing(req, s.placeholder)
        if not locs:
            continue
        if s.name not in bound:
            return Outcome("block", 403,
                           f"placeholder for secret {s.name!r} is not valid for {where}",
                           classification=cls)
        bad = locs - s.substitute
        if bad:
            return Outcome("block", 403,
                           f"placeholder for secret {s.name!r} is not allowed in "
                           f"{', '.join(sorted(bad))}", classification=cls)
        found[s.name] = locs

    # 2. Defence in depth: a real value never goes where it is not bound.
    for name, vals in store.known_values().items():
        if name in bound:
            continue
        if any(_locations_containing(req, v) for v in vals):
            return Outcome("block", 403,
                           f"request contains the value of secret {name!r}, "
                           f"which is not bound to {where}", classification=cls)

    # 3. Resolve what we need (fail closed).
    needed = [by_name[n] for n in found]
    needed += [by_name[n] for n in sorted(bound) if by_name[n].set_header and n not in found]
    values: dict[str, str] = {}
    for s in needed:
        try:
            v = store.get(s.name, s.refs, s.ttl)
        except SecretError as exc:
            return Outcome("block", 502, str(exc), classification=cls)
        if _BAD_HEADER_CHARS.search(v) and ("headers" in found.get(s.name, ()) or s.set_header):
            return Outcome("block", 502, f"secret {s.name!r} contains control characters",
                           classification=cls)
        values[s.name] = v

    # 4. Rewrite.
    out = replace(req, headers=list(req.headers))
    hdr_map = {by_name[n].placeholder: values[n] for n, l in found.items() if "headers" in l}
    if hdr_map:
        out.headers = [(k, _replace_header(v, hdr_map)) for k, v in out.headers]
    for n, locs in found.items():
        ph, real = by_name[n].placeholder, values[n]
        if "path" in locs:
            out.path = out.path.replace(quote(ph, safe=""), ph).replace(ph, quote(real, safe=""))
        if "query" in locs:
            out.query = out.query.replace(ph, quote_plus(real))
        if "body" in locs:
            out.body = out.body.replace(ph.encode(), _body_encoder(req.content_type)(real).encode())
    for s in needed:
        if s.set_header:
            lname = s.set_header.name.lower()
            out.headers = [(k, v) for k, v in out.headers if k.lower() != lname]
            out.headers.append((s.set_header.name, s.set_header.format.format(values[s.name])))

    return Outcome("forward", used=[s.name for s in needed], classification=cls, request=out)


# ---------------------------------------------------------------- redaction


def redaction_pairs(cfg: Config, store: SecretStore) -> list[tuple[bytes, bytes]]:
    """(real, placeholder) byte pairs incl. common encodings, longest first."""
    by_name = {s.name: s for s in cfg.secrets}
    pairs: dict[bytes, bytes] = {}
    for name, vals in store.known_values().items():
        s = by_name.get(name)
        if not s or not s.redact_responses:
            continue
        ph = s.placeholder.encode()
        for v in vals:
            forms = {v, quote(v, safe=""), quote_plus(v), json.dumps(v)[1:-1],
                     base64.b64encode(v.encode()).decode().rstrip("=")}
            for form in forms:
                if len(form) >= 4:
                    pairs[form.encode()] = ph
    return sorted(pairs.items(), key=lambda kv: -len(kv[0]))


def redact_bytes(data: bytes, pairs: list[tuple[bytes, bytes]]) -> bytes:
    for real, ph in pairs:
        if real in data:
            data = data.replace(real, ph)
    return data


def redact_text(text: str, pairs: list[tuple[bytes, bytes]]) -> str:
    for real, ph in pairs:
        r = real.decode("utf-8", "surrogateescape")
        if r in text:
            text = text.replace(r, ph.decode())
    return text


class StreamRedactor:
    """Callable for ``flow.response.stream`` that redacts across chunk boundaries.

    Holds back ``max(len(form)) - 1`` bytes so a value split between chunks is
    still caught. mitmproxy calls it with ``b""`` at end of stream to flush.
    """

    def __init__(self, pairs: list[tuple[bytes, bytes]]) -> None:
        self.pairs = pairs
        self.keep = max((len(r) for r, _ in pairs), default=1) - 1
        self.buf = b""

    def __call__(self, chunk: bytes) -> bytes:
        if not self.pairs:
            return chunk
        if chunk == b"":
            out, self.buf = redact_bytes(self.buf, self.pairs), b""
            return out
        data = redact_bytes(self.buf + chunk, self.pairs)
        if len(data) <= self.keep:
            self.buf = data
            return b""
        cut = len(data) - self.keep
        self.buf = data[cut:]
        return data[:cut]
