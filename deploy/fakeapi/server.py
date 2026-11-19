"""Hermetic HTTPS echo upstream for the end-to-end test.

Serves api/evil/tunnel/intercepted.example.test with a cert from a throwaway
"public" test CA. Every request it receives is appended to /log/requests.jsonl,
so the test can prove what did (and did not) reach the upstream.
"""
import json
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = "/log/requests.jsonl"
_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        entry = {"host": self.headers.get("Host"), "method": self.command, "path": self.path,
                 "headers": dict(self.headers.items()), "body": body.decode("utf-8", "replace")}
        with _lock, open(LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        auth = self.headers.get("Authorization", "")
        if self.path.startswith("/v1/stream"):
            # SSE that echoes the credential split across two chunks.
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            msg = f"data: you sent {auth}\n\n".encode()
            mid = len(msg) - len(auth) // 2 - 2
            for part in (msg[:mid], msg[mid:]):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
                self.wfile.flush()
                time.sleep(0.2)
            self.wfile.write(b"0\r\n\r\n")
            return
        payload = json.dumps(entry).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Echo-Authorization", auth)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_DELETE = _handle

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/fakeapi.pem", "/certs/fakeapi.key")
    srv = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print("fakeapi listening on :443", flush=True)
    srv.serve_forever()
