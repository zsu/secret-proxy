"""Pluggable secret providers.

A secret's ``value`` is a reference ``<scheme>:<ref>`` (or a list of them, tried
in order). References are resolved only inside the gateway process; nothing here
ever runs inside the sandbox.

Built-in schemes:
    env:NAME                 environment variable of the gateway (default scheme)
    file:/path               whole file content (Docker/K8s secret files)
    file:/path/app.env#KEY   one key from a .env-format file
    cmd:<command line>       stdout of a command run on the gateway
    vault:<path>#<field>     HashiCorp Vault KV (v2 or v1) over HTTPS

Third-party providers subclass :class:`SecretProvider` and are registered from
config with ``providers: [{scheme: x, class: "pkg.mod:Class", options: {...}}]``.

Error messages never include secret values.
"""
from __future__ import annotations

import importlib
import json
import os
import re
import shlex
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Iterable, Mapping


class SecretError(Exception):
    """A secret could not be resolved. The message never contains a value."""


class SecretProvider:
    """Base class. Subclasses set ``scheme`` and implement :meth:`get`."""

    scheme: str = ""

    def __init__(self, **options: Any) -> None:
        self.options = options

    def get(self, ref: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError


# --------------------------------------------------------------------------- env


class EnvProvider(SecretProvider):
    scheme = "env"

    def __init__(self, environ: Mapping[str, str] | None = None, **options: Any) -> None:
        super().__init__(**options)
        self.environ = environ if environ is not None else os.environ

    def get(self, ref: str) -> str:
        value = self.environ.get(ref)
        if not value:
            raise SecretError(f"environment variable {ref!r} is not set")
        return value


# -------------------------------------------------------------------------- file

_DOTENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$")
_DQ_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\", "$": "$"}


def parse_dotenv(text: str) -> dict[str, str]:
    """Parse .env content: comments, ``export``, single/double quotes, inline comments."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = _DOTENV_LINE.match(raw)
        if not m:
            continue
        key, rest = m.group(1), m.group(2).strip()
        if rest.startswith('"'):
            buf, i = [], 1
            while i < len(rest):
                ch = rest[i]
                if ch == "\\" and i + 1 < len(rest):
                    nxt = rest[i + 1]
                    buf.append(_DQ_ESCAPES.get(nxt, "\\" + nxt))
                    i += 2
                    continue
                if ch == '"':
                    break
                buf.append(ch)
                i += 1
            value = "".join(buf)
        elif rest.startswith("'"):
            end = rest.find("'", 1)
            value = rest[1:end] if end != -1 else rest[1:]
        else:
            value = re.split(r"\s+#", rest, maxsplit=1)[0].strip()
        out[key] = value
    return out


class FileProvider(SecretProvider):
    """``file:/path`` (whole file) or ``file:/path#KEY`` (.env-format lookup).

    ``${VAR}`` in the path is expanded, e.g. ``file:${CREDENTIALS_DIRECTORY}/openai``
    for systemd credentials (``LoadCredential=`` / ``LoadCredentialEncrypted=``).
    """

    scheme = "file"

    def get(self, ref: str) -> str:
        path, sep, key = ref.rpartition("#") if "#" in ref else (ref, "", "")
        unresolved = re.findall(r"\$\{(\w+)\}", path)
        missing = [v for v in unresolved if v not in os.environ]
        if missing:
            raise SecretError(f"file path uses unset variable(s) {', '.join(missing)}")
        path = os.path.expandvars(path)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            raise SecretError(f"cannot read secret file {path!r}: {exc.strerror}") from None
        if not sep:
            value = text.rstrip("\r\n")
            if not value:
                raise SecretError(f"secret file {path!r} is empty")
            return value
        values = parse_dotenv(text)
        if not values.get(key):
            raise SecretError(f"key {key!r} not found (or empty) in {path!r}")
        return values[key]


# --------------------------------------------------------------------------- cmd


class CmdProvider(SecretProvider):
    """Run a command on the gateway and use its stdout (trailing newline stripped).

    Options: ``timeout`` (seconds, default 10), ``shell`` (default False).
    """

    scheme = "cmd"

    def get(self, ref: str) -> str:
        timeout = float(self.options.get("timeout", 10))
        shell = bool(self.options.get("shell", False))
        if shell:
            args: Any = ref
        elif os.name == "nt":
            args = ref  # CreateProcess parses the command line itself
        else:
            args = shlex.split(ref)
        label = (ref.split()[0] if ref.split() else ref)[:60]
        try:
            proc = subprocess.run(
                args, shell=shell, capture_output=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired:
            raise SecretError(f"command {label!r} timed out after {timeout:g}s") from None
        except OSError as exc:
            raise SecretError(f"command {label!r} failed to start: {exc.strerror}") from None
        if proc.returncode != 0:
            # stderr is deliberately not included: it may echo sensitive data.
            raise SecretError(f"command {label!r} exited with status {proc.returncode}")
        value = proc.stdout.decode("utf-8", "replace").rstrip("\r\n")
        if not value:
            raise SecretError(f"command {label!r} printed nothing")
        return value


# ------------------------------------------------------------------------- vault


class VaultProvider(SecretProvider):
    """HashiCorp Vault KV. Ref ``<api path>#<field>``, e.g. ``secret/data/openai#api_key``.

    Options (all optional):
        addr        Vault URL (default: $VAULT_ADDR)
        token_env   env var holding the token (default: VAULT_TOKEN)
        token_file  file holding the token (takes precedence over token_env)
        namespace   X-Vault-Namespace header
        ca_file     CA bundle for Vault's TLS certificate
        timeout     seconds (default 5)
    """

    scheme = "vault"

    def _token(self) -> str:
        token_file = self.options.get("token_file")
        if token_file:
            token_file = os.path.expandvars(token_file)  # e.g. ${CREDENTIALS_DIRECTORY}/vault_token
            try:
                with open(token_file, "r", encoding="utf-8") as fh:
                    token = fh.read().strip()
            except OSError as exc:
                raise SecretError(f"cannot read Vault token file: {exc.strerror}") from None
        else:
            token = os.environ.get(self.options.get("token_env", "VAULT_TOKEN"), "")
        if not token:
            raise SecretError("no Vault token configured")
        return token

    def get(self, ref: str) -> str:
        path, sep, field = ref.partition("#")
        if not sep or not field:
            raise SecretError("vault reference must look like '<path>#<field>'")
        addr = (self.options.get("addr") or os.environ.get("VAULT_ADDR") or "").rstrip("/")
        if not addr:
            raise SecretError("no Vault address configured (options.addr or VAULT_ADDR)")
        req = urllib.request.Request(f"{addr}/v1/{path.lstrip('/')}")
        req.add_header("X-Vault-Token", self._token())
        if self.options.get("namespace"):
            req.add_header("X-Vault-Namespace", self.options["namespace"])
        context = None
        if addr.startswith("https://"):
            context = ssl.create_default_context(cafile=self.options.get("ca_file"))
        try:
            with urllib.request.urlopen(
                req, timeout=float(self.options.get("timeout", 5)), context=context
            ) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise SecretError(f"Vault returned HTTP {exc.code} for {path!r}") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise SecretError(f"Vault request for {path!r} failed: {type(exc).__name__}") from None
        data = payload.get("data") or {}
        if isinstance(data.get("data"), dict):  # KV v2 wraps the secret in data.data
            data = data["data"]
        value = data.get(field)
        if not isinstance(value, str) or not value:
            raise SecretError(f"field {field!r} not found in Vault secret {path!r}")
        return value


# ---------------------------------------------------------------------- registry

BUILTIN_PROVIDERS: dict[str, type[SecretProvider]] = {
    p.scheme: p for p in (EnvProvider, FileProvider, CmdProvider, VaultProvider)
}

_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+.-]*):(.*)$", re.DOTALL)


def load_class(path: str) -> type[SecretProvider]:
    """Import ``"package.module:ClassName"``."""
    module_name, sep, attr = path.partition(":")
    if not sep:
        raise ValueError(f"provider class must look like 'module:Class', got {path!r}")
    cls = getattr(importlib.import_module(module_name), attr)
    if not (isinstance(cls, type) and issubclass(cls, SecretProvider)):
        raise TypeError(f"{path} is not a SecretProvider subclass")
    return cls


def build_registry(specs: Iterable[Mapping[str, Any]] = ()) -> dict[str, SecretProvider]:
    """Built-in providers plus any configured ones (which may override built-ins)."""
    registry: dict[str, SecretProvider] = {s: cls() for s, cls in BUILTIN_PROVIDERS.items()}
    for spec in specs:
        scheme = spec.get("scheme")
        if not scheme or not _SCHEME_RE.match(f"{scheme}:"):
            raise ValueError(f"provider entry needs a lowercase 'scheme': {dict(spec)!r}")
        cls_path = spec.get("class")
        cls = load_class(cls_path) if cls_path else BUILTIN_PROVIDERS.get(scheme)
        if cls is None:
            raise ValueError(f"provider {scheme!r} has no 'class' and is not built in")
        registry[scheme] = cls(**dict(spec.get("options") or {}))
    return registry


def split_ref(ref: str, registry: Mapping[str, SecretProvider]) -> tuple[str, str]:
    """``"file:/x"`` -> ``("file", "/x")``; a bare name means ``env``."""
    m = _SCHEME_RE.match(ref)
    if not m:
        return "env", ref
    scheme, rest = m.group(1), m.group(2)
    if scheme not in registry:
        raise SecretError(f"unknown secret provider scheme {scheme!r}")
    return scheme, rest


class SecretStore:
    """Resolves secrets with per-secret TTL caching, fallback lists and fail-closed errors.

    It also remembers every value it has ever handed out (per secret) so responses
    can be redacted even after a rotation.
    """

    def __init__(self, registry: Mapping[str, SecretProvider], clock=time.monotonic) -> None:
        self.registry = dict(registry)
        self._clock = clock
        self._cache: dict[str, tuple[str, float]] = {}
        self._seen: dict[str, set[str]] = {}
        self._lock = threading.Lock()

    def get(self, name: str, refs: Iterable[str], ttl: float | None = None) -> str:
        with self._lock:
            hit = self._cache.get(name)
            if hit and (ttl is None or self._clock() - hit[1] < ttl):
                return hit[0]
        errors: list[str] = []
        for ref in refs:
            try:
                scheme, rest = split_ref(ref, self.registry)
                value = self.registry[scheme].get(rest)
            except SecretError as exc:
                errors.append(str(exc))
                continue
            except Exception as exc:  # third-party provider bug: still fail closed
                errors.append(f"provider error: {type(exc).__name__}")
                continue
            with self._lock:
                self._cache[name] = (value, self._clock())
                self._seen.setdefault(name, set()).add(value)
            return value
        raise SecretError(f"secret {name!r} unavailable: " + "; ".join(errors or ["no sources"]))

    def invalidate(self, name: str) -> None:
        with self._lock:
            self._cache.pop(name, None)

    def known_values(self) -> dict[str, set[str]]:
        with self._lock:
            return {k: set(v) for k, v in self._seen.items()}
