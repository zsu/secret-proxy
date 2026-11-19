"""Config loading and validation."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from .providers import SecretProvider, build_registry

LOCATIONS = {"headers", "query", "path", "body"}
CLASSES = ("inject", "intercept", "tunnel", "deny")
PLACEHOLDER_RE = re.compile(r"^[A-Za-z0-9_.\-]{16,}$")


def glob_to_regex(pattern: str, sep: str) -> re.Pattern[str]:
    """``**`` matches anything, ``*`` matches within one segment, ``?`` one char."""
    seg = "[^.]+" if sep == "." else "[^/]*"
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append(seg)
            i += 1
        elif pattern[i] == "?":
            out.append(f"[^{re.escape(sep)}]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE if sep == "." else 0)


class GlobList:
    def __init__(self, patterns: list[str], sep: str) -> None:
        self.patterns = list(patterns)
        self._res = [glob_to_regex(p, sep) for p in patterns]

    def match(self, value: str) -> bool:
        return any(r.match(value) for r in self._res)

    def __bool__(self) -> bool:
        return bool(self.patterns)


@dataclass
class SetHeader:
    name: str
    format: str = "{}"


@dataclass
class Secret:
    name: str
    refs: list[str]
    placeholder: str
    hosts: GlobList
    paths: GlobList
    methods: set[str] | None = None
    substitute: set[str] = field(default_factory=lambda: {"headers", "query"})
    set_header: SetHeader | None = None
    redact_responses: bool = True
    ttl: float | None = None
    refresh_on: set[int] = field(default_factory=set)
    sandbox_env: str | None = None

    def binds(self, scheme: str, host: str, path: str, method: str) -> bool:
        """True when this secret may be injected into the given request."""
        return (
            scheme == "https"
            and self.hosts.match(host)
            and self.paths.match(path or "/")
            and (self.methods is None or method.upper() in self.methods)
        )


@dataclass
class Config:
    secrets: list[Secret]
    intercept: GlobList
    tunnel: GlobList
    default: str = "deny"  # what to do with hosts that match nothing: deny | intercept
    providers: dict[str, SecretProvider] = field(default_factory=dict)
    audit_log: str | None = None
    stream_threshold: int = 1 << 20

    def classify(self, host: str | None) -> str:
        if not host:
            return "deny"
        host = host.lower().rstrip(".")
        if any(s.hosts.match(host) for s in self.secrets):
            return "inject"
        if self.intercept.match(host):
            return "intercept"
        if self.tunnel.match(host):
            return "tunnel"
        return self.default


class ConfigError(ValueError):
    pass


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def parse_config(raw: dict[str, Any]) -> Config:
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")
    try:
        registry = build_registry(_as_list(raw.get("providers")))
    except (ValueError, TypeError, ImportError, AttributeError) as exc:
        raise ConfigError(f"providers: {exc}") from None

    secrets: list[Secret] = []
    names: set[str] = set()
    for i, s in enumerate(_as_list(raw.get("secrets"))):
        where = f"secrets[{i}]"
        name = s.get("name")
        if not name or name in names:
            raise ConfigError(f"{where}: 'name' is required and must be unique")
        names.add(name)
        refs = [str(r) for r in _as_list(s.get("value"))]
        if not refs:
            raise ConfigError(f"{where} ({name}): 'value' is required")
        placeholder = str(s.get("placeholder") or "")
        if not PLACEHOLDER_RE.match(placeholder) or "REPLACE" in placeholder.upper():
            raise ConfigError(
                f"{where} ({name}): 'placeholder' must be >=16 chars of [A-Za-z0-9_.-] "
                "(generate one with: python -m secretproxy new-placeholder NAME)"
            )
        hosts = [str(h).lower() for h in _as_list(s.get("hosts"))]
        if not hosts:
            raise ConfigError(f"{where} ({name}): 'hosts' is required")
        subst = {str(x) for x in _as_list(s.get("substitute", ["headers", "query"]))}
        if not subst <= LOCATIONS:
            raise ConfigError(f"{where} ({name}): substitute must be a subset of {sorted(LOCATIONS)}")
        sh = s.get("set_header")
        set_header = None
        if sh:
            if not sh.get("name"):
                raise ConfigError(f"{where} ({name}): set_header.name is required")
            fmt = str(sh.get("format", "{}"))
            if "{}" not in fmt:
                raise ConfigError(f"{where} ({name}): set_header.format must contain '{{}}'")
            set_header = SetHeader(str(sh["name"]), fmt)
        methods = {m.upper() for m in _as_list(s.get("methods"))} or None
        secrets.append(
            Secret(
                name=name,
                refs=refs,
                placeholder=placeholder,
                hosts=GlobList(hosts, "."),
                paths=GlobList([str(p) for p in _as_list(s.get("paths", ["/**"]))], "/"),
                methods=methods,
                substitute=subst,
                set_header=set_header,
                redact_responses=bool(s.get("redact_responses", True)),
                ttl=float(s["ttl"]) if s.get("ttl") is not None else None,
                refresh_on={int(c) for c in _as_list(s.get("refresh_on"))},
                sandbox_env=s.get("sandbox_env"),
            )
        )

    phs = [s.placeholder for s in secrets]
    for a in phs:
        for b in phs:
            if a is not b and a in b:
                raise ConfigError(f"placeholder {a!r} is a substring of another placeholder")

    default = raw.get("default", "deny")
    if default not in ("deny", "intercept"):
        raise ConfigError("default must be 'deny' or 'intercept'")
    return Config(
        secrets=secrets,
        intercept=GlobList([str(h).lower() for h in _as_list(raw.get("intercept"))], "."),
        tunnel=GlobList([str(h).lower() for h in _as_list(raw.get("tunnel"))], "."),
        default=default,
        providers=registry,
        audit_log=raw.get("audit_log"),
        stream_threshold=int(raw.get("stream_threshold", 1 << 20)),
    )


def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as fh:
        try:
            raw = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            where = f" (line {mark.line + 1}, column {mark.column + 1})" if mark else ""
            hint = getattr(exc, "problem", None) or "invalid YAML"
            raise ConfigError(f"{path}{where}: {hint}. Tip: quote values containing "
                              "${...} inside [ ] lists") from None
    return parse_config(raw)
