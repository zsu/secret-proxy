import json
import unittest
from types import SimpleNamespace

from mitmproxy import http
from mitmproxy.proxy.server_hooks import ServerConnectionHookData
from mitmproxy.test import tflow, tutils

from secretproxy.addon import SecretProxy
from secretproxy.rules import StreamRedactor

from .common import ENV, PH_API, RAW, make


def mkflow(host="api.example.test", path="/v1/chat", method="GET", headers=(), content=b"",
           scheme="https", sni="same", dst=("10.9.9.9", 443)):
    hdrs = http.Headers([(b"host", host.encode())]
                        + [(k.encode(), v.encode()) for k, v in headers])
    r = tutils.treq(host=dst[0], port=dst[1], scheme=scheme.encode(), method=method.encode(),
                    path=path.encode(), headers=hdrs, content=content, authority=b"")
    f = tflow.tflow(req=r)
    f.response = None
    f.client_conn.sni = (host if scheme == "https" else None) if sni == "same" else sni
    return f


class AddonTests(unittest.TestCase):
    def setUp(self):
        cfg, _ = make()
        self.addon = SecretProxy()
        self.addon.cfg = cfg
        from secretproxy.providers import SecretStore
        self.addon.store = SecretStore(cfg.providers)
        self.events = []
        self.addon.audit = lambda **e: self.events.append(e)

    def roundtrip(self, f, status=200, body=b"", resp_headers=()):
        self.addon.request(f)
        if f.response is None:
            f.response = tutils.tresp(status_code=status, content=body,
                                      headers=http.Headers([(k.encode(), v.encode())
                                                            for k, v in resp_headers]))
            self.addon.responseheaders(f)
        self.addon.response(f)
        return f

    def test_inject_pins_host_and_strips_encoding(self):
        f = mkflow(headers=[("Authorization", f"Bearer {PH_API}"), ("Accept-Encoding", "gzip")])
        self.addon.request(f)
        self.assertIsNone(f.response)
        self.assertEqual(f.request.headers["authorization"], f"Bearer {ENV['FAKEAPI']}")
        self.assertEqual(f.request.host, "api.example.test")  # not the sandbox-chosen 10.9.9.9
        self.assertNotIn("accept-encoding", f.request.headers)

    def test_host_header_must_match_sni(self):
        f = mkflow(headers=[("Authorization", PH_API)], sni="other.example.test")
        self.addon.request(f)
        self.assertEqual(f.response.status_code, 403)
        self.assertIn("does not match TLS SNI", f.response.get_text())

    def test_block_response_and_audit_have_no_values(self):
        f = self.roundtrip(mkflow(host="other.example.test", path="/x",
                                  headers=[("Authorization", PH_API)]))
        self.assertEqual(f.response.status_code, 403)
        self.assertEqual(f.response.headers["x-secretproxy"], "blocked")
        dumped = json.dumps(self.events)
        self.assertIn('"decision": "block"', dumped)
        self.assertNotIn(ENV["FAKEAPI"], dumped)

    def test_query_rewrite(self):
        f = mkflow(path=f"/v1/models?key={PH_API}")
        self.addon.request(f)
        self.assertIn("key=real-fakeapi-SECRET%2F%2B%3D", f.request.path)

    def test_echoed_secret_redacted_in_headers_and_body(self):
        f = mkflow(headers=[("Authorization", f"Bearer {PH_API}")])
        body = json.dumps({"auth": f"Bearer {ENV['FAKEAPI']}"}).encode()
        f = self.roundtrip(f, body=body, resp_headers=[("X-Echo", ENV["FAKEAPI"]),
                                                       ("content-type", "application/json"),
                                                       ("content-length", str(len(body)))])
        self.assertEqual(f.response.headers["x-echo"], PH_API)
        self.assertNotIn(ENV["FAKEAPI"], f.response.get_text())
        self.assertIn(PH_API, f.response.get_text())
        self.assertEqual(self.events[-1]["secrets"], ["fakeapi"])
        self.assertNotIn(ENV["FAKEAPI"], json.dumps(self.events))

    def test_gzip_body_redacted(self):
        f = mkflow(headers=[("Authorization", PH_API)])
        self.addon.request(f)
        f.response = tutils.tresp(headers=http.Headers([(b"content-type", b"text/plain")]))
        f.response.set_content(None)
        f.response.headers["content-encoding"] = "gzip"
        f.response.set_content(f"echo {ENV['FAKEAPI']}".encode())  # stored gzip-encoded
        self.addon.responseheaders(f)
        self.assertFalse(f.response.stream)
        self.addon.response(f)
        self.assertEqual(f.response.get_text(), f"echo {PH_API}")

    def test_sse_is_streamed_through_redactor(self):
        f = mkflow(headers=[("Authorization", PH_API)])
        self.addon.request(f)
        f.response = tutils.tresp(headers=http.Headers([(b"content-type", b"text/event-stream")]),
                                  content=None)
        self.addon.responseheaders(f)
        self.assertIsInstance(f.response.stream, StreamRedactor)
        s = ENV["FAKEAPI"].encode()
        out = f.response.stream(b"data: " + s[:5]) + f.response.stream(s[5:] + b"\n\n")
        out += f.response.stream(b"")
        self.assertEqual(out, b"data: " + PH_API.encode() + b"\n\n")

    def test_refresh_on_invalidates_cache(self):
        raw = json.loads(json.dumps(RAW))
        raw["secrets"][0]["refresh_on"] = [401]
        cfg, store = make(raw)
        self.addon.cfg, self.addon.store = cfg, store
        self.roundtrip(mkflow(headers=[("Authorization", PH_API)]), status=401)
        self.assertNotIn("fakeapi", store._cache)

    def test_tls_clienthello_tunnel_only(self):
        for sni, ignored in (("pypi.org", True), ("api.example.test", False),
                             ("evil.example.test", False), (None, False)):
            data = SimpleNamespace(client_hello=SimpleNamespace(sni=sni), ignore_connection=False)
            self.addon.tls_clienthello(data)
            self.assertEqual(data.ignore_connection, ignored, sni)

    def test_server_connect_pins_sni_and_denies(self):
        client = tflow.tclient_conn()
        server = tflow.tserver_conn()
        client.sni, server.address, server.sni = "pypi.org", ("6.6.6.6", 443), None
        self.addon.server_connect(ServerConnectionHookData(server=server, client=client))
        self.assertIsNone(server.error)
        self.assertEqual(server.address, ("pypi.org", 443))  # sandbox can't pick the IP

        client.sni, server.address = None, ("6.6.6.6", 22)
        self.addon.server_connect(ServerConnectionHookData(server=server, client=client))
        self.assertIn("blocked", server.error)

    def test_websocket_server_messages_redacted(self):
        f = tflow.twebsocketflow()
        self.addon.store.get("fakeapi", self.addon.cfg.secrets[0].refs)
        f.websocket.messages[-1].from_client = False
        f.websocket.messages[-1].content = f"tok={ENV['FAKEAPI']}".encode()
        self.addon.websocket_message(f)
        self.assertEqual(f.websocket.messages[-1].content, f"tok={PH_API}".encode())


if __name__ == "__main__":
    unittest.main()
