import base64
import json
import unittest
from urllib.parse import quote_plus

from secretproxy import rules
from secretproxy.config import ConfigError, glob_to_regex, parse_config
from secretproxy.rules import Req, StreamRedactor, evaluate, redact_bytes, redaction_pairs

from .common import ENV, PH_API, PH_BODY, PH_HDR, RAW, make


def req(host="api.example.test", path="/v1/chat", method="GET", headers=(), query="",
        body=b"", scheme="https", ctype=""):
    return Req(scheme=scheme, host=host, port=443, method=method, path=path, query=query,
               headers=list(headers), body=body, content_type=ctype)


def hdr(r, name):
    return [v for k, v in r.headers if k.lower() == name.lower()]


class GlobTests(unittest.TestCase):
    def test_host_globs(self):
        r = glob_to_regex("*.example.com", ".")
        self.assertTrue(r.match("a.example.com"))
        self.assertTrue(r.match("A.Example.COM"))
        self.assertFalse(r.match("example.com"))
        self.assertFalse(r.match("a.b.example.com"))
        self.assertTrue(glob_to_regex("**.example.com", ".").match("a.b.example.com"))

    def test_path_globs(self):
        self.assertTrue(glob_to_regex("/v1/**", "/").match("/v1/a/b"))
        self.assertFalse(glob_to_regex("/v1/**", "/").match("/v2/a"))
        self.assertTrue(glob_to_regex("/v1/*", "/").match("/v1/a"))
        self.assertFalse(glob_to_regex("/v1/*", "/").match("/v1/a/b"))


class ConfigTests(unittest.TestCase):
    def test_classify(self):
        cfg, _ = make()
        self.assertEqual(cfg.classify("api.example.test"), "inject")
        self.assertEqual(cfg.classify("other.example.test"), "intercept")
        self.assertEqual(cfg.classify("files.pythonhosted.org"), "tunnel")
        self.assertEqual(cfg.classify("evil.example.test"), "deny")
        self.assertEqual(cfg.classify(None), "deny")
        cfg.default = "intercept"
        self.assertEqual(cfg.classify("evil.example.test"), "intercept")

    def test_validation(self):
        def bad(**over):
            raw = json.loads(json.dumps(RAW))
            raw["secrets"][0].update(over)
            with self.assertRaises(ConfigError):
                parse_config(raw)

        bad(placeholder="short")
        bad(hosts=[])
        bad(substitute=["cookies"])
        bad(value=None)
        bad(set_header={"name": "X", "format": "no braces"})
        bad(placeholder=PH_HDR + "_x")  # contains another placeholder


class EvaluateTests(unittest.TestCase):
    def setUp(self):
        self.cfg, self.store = make()

    def test_header_placeholder_injected(self):
        o = evaluate(self.cfg, self.store, req(headers=[("Authorization", f"Bearer {PH_API}")]))
        self.assertEqual(o.action, "forward", o.reason)
        self.assertEqual(hdr(o.request, "authorization"), [f"Bearer {ENV['FAKEAPI']}"])
        self.assertEqual(o.used, ["fakeapi"])

    def test_query_placeholder_injected_and_encoded(self):
        o = evaluate(self.cfg, self.store, req(query=f"key={PH_API}&x=1"))
        self.assertEqual(o.action, "forward", o.reason)
        self.assertEqual(o.request.query, f"key={quote_plus(ENV['FAKEAPI'])}&x=1")

    def test_basic_auth_inside_base64(self):
        b = base64.b64encode(f"user:{PH_API}".encode()).decode()
        o = evaluate(self.cfg, self.store, req(headers=[("Authorization", f"Basic {b}")]))
        self.assertEqual(o.action, "forward", o.reason)
        decoded = base64.b64decode(hdr(o.request, "authorization")[0].split()[1]).decode()
        self.assertEqual(decoded, f"user:{ENV['FAKEAPI']}")

    def test_placeholder_to_unbound_host_blocked(self):
        o = evaluate(self.cfg, self.store,
                     req(host="other.example.test", headers=[("Authorization", PH_API)]))
        self.assertEqual((o.action, o.status), ("block", 403))
        self.assertIn("not valid", o.reason)

    def test_denied_host_blocked(self):
        o = evaluate(self.cfg, self.store, req(host="evil.example.test"))
        self.assertEqual((o.action, o.status), ("block", 403))
        self.assertIn("egress", o.reason)

    def test_wrong_path_method_scheme(self):
        h = [("Authorization", PH_API)]
        for r in (req(path="/v2/chat", headers=h), req(method="DELETE", headers=h),
                  req(scheme="http", headers=h)):
            o = evaluate(self.cfg, self.store, r)
            self.assertEqual((o.action, o.status), ("block", 403), r)

    def test_location_not_allowed(self):
        o = evaluate(self.cfg, self.store, req(method="POST", body=PH_API.encode()))
        self.assertEqual((o.action, o.status), ("block", 403))
        self.assertIn("body", o.reason)

    def test_body_substitution_json_escaped(self):
        body = json.dumps({"token": PH_BODY}).encode()
        o = evaluate(self.cfg, self.store, req(host="body.example.test", method="POST", body=body,
                                               ctype="application/json"))
        self.assertEqual(o.action, "forward", o.reason)
        self.assertEqual(json.loads(o.request.body)["token"], ENV["BODY"])

    def test_set_header_overwrites_without_placeholder(self):
        o = evaluate(self.cfg, self.store,
                     req(path="/env/x", headers=[("x-api-key", "agent-supplied")]))
        self.assertEqual(o.action, "forward", o.reason)
        self.assertEqual(hdr(o.request, "x-api-key"), [ENV["HDR"]])
        self.assertEqual(o.used, ["hdr"])

    def test_real_value_never_leaves_to_other_host(self):
        evaluate(self.cfg, self.store, req(headers=[("Authorization", PH_API)]))  # resolves it
        o = evaluate(self.cfg, self.store,
                     req(host="other.example.test", query=f"q={quote_plus(ENV['FAKEAPI'])}"))
        self.assertEqual((o.action, o.status), ("block", 403))
        self.assertNotIn(ENV["FAKEAPI"], o.reason)

    def test_fail_closed_502(self):
        cfg, store = make(env={})
        o = evaluate(cfg, store, req(headers=[("Authorization", PH_API)]))
        self.assertEqual((o.action, o.status), ("block", 502))
        self.assertIn("unavailable", o.reason)

    def test_control_chars_rejected(self):
        cfg, store = make(env={**ENV, "FAKEAPI": "bad\r\nInjected: 1"})
        o = evaluate(cfg, store, req(headers=[("Authorization", PH_API)]))
        self.assertEqual((o.action, o.status), ("block", 502))

    def test_no_placeholder_passes_untouched(self):
        r = req(host="other.example.test", headers=[("Accept", "*/*")])
        o = evaluate(self.cfg, self.store, r)
        self.assertEqual(o.action, "forward")
        self.assertEqual(o.request.headers, r.headers)
        self.assertEqual(o.used, [])


class RedactionTests(unittest.TestCase):
    def setUp(self):
        self.cfg, self.store = make()
        for s in self.cfg.secrets:
            self.store.get(s.name, s.refs)
        self.pairs = redaction_pairs(self.cfg, self.store)
        self.secret = ENV["FAKEAPI"].encode()

    def test_encodings_redacted(self):
        v = ENV["FAKEAPI"]
        data = f"a {v} b {quote_plus(v)} c {json.dumps(v)} d".encode()
        out = redact_bytes(data, self.pairs)
        self.assertNotIn(self.secret, out)
        self.assertNotIn(quote_plus(v).encode(), out)
        self.assertEqual(out.count(PH_API.encode()), 3)

    def test_stream_split_at_every_offset(self):
        payload = b"data: hello " + self.secret + b" world\n\n" + ENV["HDR"].encode() + b"!"
        for cut in range(1, len(payload)):
            for step in (1, 3, 7):
                red = StreamRedactor(self.pairs)
                chunks = [payload[:cut]] + [payload[i:i + step] for i in range(cut, len(payload), step)]
                out = b"".join(red(c) for c in chunks) + red(b"")
                self.assertNotIn(self.secret, out, (cut, step))
                self.assertNotIn(ENV["HDR"].encode(), out)
                self.assertEqual(out, redact_bytes(payload, self.pairs))

    def test_redact_text(self):
        self.assertEqual(rules.redact_text(f"Bearer {ENV['FAKEAPI']}", self.pairs), f"Bearer {PH_API}")


if __name__ == "__main__":
    unittest.main()
