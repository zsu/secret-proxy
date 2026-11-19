import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from secretproxy.providers import (
    CmdProvider,
    EnvProvider,
    FileProvider,
    SecretError,
    SecretProvider,
    SecretStore,
    VaultProvider,
    build_registry,
    parse_dotenv,
)


class StaticProvider(SecretProvider):
    """Plugin used by test_plugin_loaded_by_class_path."""

    scheme = "static"

    def get(self, ref: str) -> str:
        return f"{self.options['prefix']}{ref}"


class BrokenProvider(SecretProvider):
    def get(self, ref: str) -> str:
        raise RuntimeError("boom with secret-ish text")


def py(code: str) -> str:
    return f'"{sys.executable}" -c "{code}"'


class EnvTests(unittest.TestCase):
    def test_get_and_missing(self):
        p = EnvProvider(environ={"A": "1"})
        self.assertEqual(p.get("A"), "1")
        with self.assertRaises(SecretError):
            p.get("B")


class DotenvTests(unittest.TestCase):
    def test_parse(self):
        text = (
            "# comment\n\n"
            "export A=plain\n"
            'B="with space\\nand newline"\n'
            "C='literal $HOME \\n'\n"
            "D=value # trailing comment\n"
            "E=\n"
            "F = spaced \n"
            "not a line\n"
        )
        self.assertEqual(
            parse_dotenv(text),
            {"A": "plain", "B": "with space\nand newline", "C": "literal $HOME \\n",
             "D": "value", "E": "", "F": "spaced"},
        )


class FileTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.whole = os.path.join(self.dir, "token")
        with open(self.whole, "w", encoding="utf-8") as fh:
            fh.write("s3cr3t-token\n")
        self.envf = os.path.join(self.dir, "app.env")
        with open(self.envf, "w", encoding="utf-8") as fh:
            fh.write('OPENAI_API_KEY="sk-abc"\nEMPTY=\n')

    def test_whole_file(self):
        self.assertEqual(FileProvider().get(self.whole), "s3cr3t-token")

    def test_env_key(self):
        self.assertEqual(FileProvider().get(self.envf + "#OPENAI_API_KEY"), "sk-abc")

    def test_missing_key_and_file(self):
        with self.assertRaises(SecretError):
            FileProvider().get(self.envf + "#NOPE")
        with self.assertRaises(SecretError):
            FileProvider().get(self.envf + "#EMPTY")
        with self.assertRaises(SecretError):
            FileProvider().get(os.path.join(self.dir, "missing"))


class CmdTests(unittest.TestCase):
    def test_stdout(self):
        self.assertEqual(CmdProvider().get(py("print('from-cmd')")), "from-cmd")

    def test_nonzero_exit_hides_stderr(self):
        with self.assertRaises(SecretError) as cm:
            CmdProvider().get(py("import sys; sys.stderr.write('LEAK'); sys.exit(3)"))
        self.assertIn("status 3", str(cm.exception))
        self.assertNotIn("LEAK", str(cm.exception))

    def test_timeout(self):
        with self.assertRaises(SecretError) as cm:
            CmdProvider(timeout=0.5).get(py("import time; time.sleep(5)"))
        self.assertIn("timed out", str(cm.exception))

    def test_empty_output(self):
        with self.assertRaises(SecretError):
            CmdProvider().get(py("pass"))


class _Vault(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("X-Vault-Token") != "tok":
            self.send_response(403)
            self.end_headers()
            return
        if self.path == "/v1/secret/data/openai":
            body = {"data": {"data": {"api_key": "sk-vault"}, "metadata": {}}}
        elif self.path == "/v1/kv1/openai":
            body = {"data": {"api_key": "sk-v1"}}
        else:
            self.send_response(404)
            self.end_headers()
            return
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


class VaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _Vault)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.addr = f"http://127.0.0.1:{cls.srv.server_port}"
        tf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".tok")
        tf.write("tok\n")
        tf.close()
        cls.token_file = tf.name

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_kv2_and_kv1(self):
        p = VaultProvider(addr=self.addr, token_file=self.token_file)
        self.assertEqual(p.get("secret/data/openai#api_key"), "sk-vault")
        self.assertEqual(p.get("kv1/openai#api_key"), "sk-v1")

    def test_errors(self):
        p = VaultProvider(addr=self.addr, token_file=self.token_file)
        with self.assertRaises(SecretError):
            p.get("secret/data/openai#missing")
        with self.assertRaises(SecretError):
            p.get("secret/data/nope#api_key")
        with self.assertRaises(SecretError):
            p.get("secret/data/openai")  # no #field
        os.environ["SP_TEST_BAD_TOKEN"] = "wrong"
        with self.assertRaises(SecretError) as cm:
            VaultProvider(addr=self.addr, token_env="SP_TEST_BAD_TOKEN").get("secret/data/openai#api_key")
        self.assertIn("403", str(cm.exception))


class RegistryAndStoreTests(unittest.TestCase):
    def test_plugin_loaded_by_class_path(self):
        reg = build_registry([{"scheme": "static", "class": "tests.test_providers:StaticProvider",
                               "options": {"prefix": "v-"}}])
        self.assertEqual(reg["static"].get("x"), "v-x")
        self.assertIn("env", reg)  # built-ins stay registered

    def test_builtin_options_override(self):
        reg = build_registry([{"scheme": "cmd", "options": {"timeout": 2}}])
        self.assertEqual(reg["cmd"].options["timeout"], 2)

    def test_bad_plugin(self):
        with self.assertRaises(ValueError):
            build_registry([{"scheme": "nope"}])
        with self.assertRaises(TypeError):
            build_registry([{"scheme": "x", "class": "json:JSONDecoder"}])

    def test_fallback_ttl_rotation(self):
        env = {"B": "v1"}
        now = [0.0]
        store = SecretStore({"env": EnvProvider(environ=env)}, clock=lambda: now[0])
        self.assertEqual(store.get("s", ["env:A", "env:B"], ttl=10), "v1")
        env["B"] = "v2"
        now[0] = 5
        self.assertEqual(store.get("s", ["env:A", "env:B"], ttl=10), "v1")  # cached
        now[0] = 11
        self.assertEqual(store.get("s", ["env:A", "env:B"], ttl=10), "v2")  # refreshed
        self.assertEqual(store.known_values()["s"], {"v1", "v2"})  # both redacted
        env["B"] = "v3"
        store.invalidate("s")
        self.assertEqual(store.get("s", ["env:B"], ttl=None), "v3")

    def test_fail_closed_messages(self):
        store = SecretStore({"env": EnvProvider(environ={}), "broken": BrokenProvider()})
        with self.assertRaises(SecretError) as cm:
            store.get("s", ["env:A", "broken:x", "vault2:y"])
        msg = str(cm.exception)
        self.assertIn("'A' is not set", msg)
        self.assertIn("provider error: RuntimeError", msg)
        self.assertNotIn("boom", msg)
        self.assertIn("unknown secret provider scheme 'vault2'", msg)


if __name__ == "__main__":
    unittest.main()
