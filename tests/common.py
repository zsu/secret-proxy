"""Shared fixtures for the unit tests."""
from __future__ import annotations

from secretproxy.config import parse_config
from secretproxy.providers import EnvProvider, SecretStore

PH_API = "sp_fakeapi_0123456789abcdef0123"
PH_HDR = "sp_hdr_0123456789abcdef01234567"
PH_BODY = "sp_body_0123456789abcdef0123456"

ENV = {
    "FAKEAPI": "real-fakeapi-SECRET/+=",
    "HDR": "real-hdr-SECRET-value",
    "BODY": 'real"body\\SECRET',
}

RAW = {
    "intercept": ["other.example.test"],
    "tunnel": ["pypi.org", "*.pythonhosted.org"],
    "secrets": [
        {
            "name": "fakeapi",
            "value": ["env:NOT_SET_ANYWHERE", "env:FAKEAPI"],  # fallback list
            "placeholder": PH_API,
            "hosts": ["api.example.test"],
            "paths": ["/v1/**"],
            "methods": ["GET", "POST"],
            "substitute": ["headers", "query"],
            "sandbox_env": "FAKEAPI_TOKEN",
        },
        {
            "name": "hdr",
            "value": "HDR",  # bare name -> env
            "placeholder": PH_HDR,
            "hosts": ["api.example.test"],
            "paths": ["/env/**"],
            "set_header": {"name": "X-Api-Key", "format": "{}"},
        },
        {
            "name": "bodytok",
            "value": "env:BODY",
            "placeholder": PH_BODY,
            "hosts": ["body.example.test"],
            "substitute": ["headers", "body"],
        },
    ],
}


def make(raw=None, env=None):
    cfg = parse_config(raw or RAW)
    cfg.providers["env"] = EnvProvider(environ=dict(ENV if env is None else env))
    return cfg, SecretStore(cfg.providers)
