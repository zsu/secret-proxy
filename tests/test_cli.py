import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from secretproxy.__main__ import main, mitmdump_args

CONFIG = """
tunnel: [pypi.org]
secrets:
  - name: demo
    value: [env:SP_CLI_TEST_MISSING, env:SP_CLI_TEST_TOKEN]
    placeholder: sp_demo_0123456789abcdef0123456789
    sandbox_env: DEMO_TOKEN
    hosts: [api.example.test]
"""


def run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = main(list(argv))
    return code, out.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cfg = os.path.join(self.dir, "config.yaml")
        Path(self.cfg).write_text(CONFIG, encoding="utf-8")
        os.environ.pop("SP_CLI_TEST_TOKEN", None)

    def test_mitmdump_args(self):
        a = mitmdump_args("/etc/c.yaml", "/var/lib/ca", "0.0.0.0", 9000, "/ca.pem", ["--set", "x=1"])
        self.assertEqual(a[:6], ["--mode", "transparent", "--listen-host", "0.0.0.0",
                                 "--listen-port", "9000"])
        self.assertTrue(a[a.index("-s") + 1].endswith("mitm_entry.py"))
        self.assertTrue(Path(a[a.index("-s") + 1]).is_file())
        for opt in ("confdir=/var/lib/ca", "secretproxy_config=/etc/c.yaml",
                    "connection_strategy=lazy", "flow_detail=0",
                    "ssl_verify_upstream_trusted_ca=/ca.pem"):
            self.assertIn(opt, a)
        self.assertEqual(a[-2:], ["--set", "x=1"])

    def test_check_with_env_file_never_prints_value(self):
        code, out = run("check", "-c", self.cfg)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  demo", out)
        envf = os.path.join(self.dir, "secrets.env")
        Path(envf).write_text('SP_CLI_TEST_TOKEN="very-secret-value"\n', encoding="utf-8")
        code, out = run("check", "-c", self.cfg, "--env-file", envf)
        self.assertEqual(code, 0, out)
        self.assertIn("ok    demo", out)
        self.assertNotIn("very-secret-value", out)

    def test_sandbox_env_and_placeholder(self):
        code, out = run("sandbox-env", "-c", self.cfg)
        self.assertEqual(out.strip(), "DEMO_TOKEN=sp_demo_0123456789abcdef0123456789")
        code, out = run("new-placeholder", "My API")
        self.assertRegex(out.strip(), r"^sp_my_api_[0-9a-f]{32}$")

    def test_dns_config_allowlist(self):
        text = CONFIG.replace("tunnel: [pypi.org]",
                              'tunnel: [pypi.org, "*.pythonhosted.org", files.pypi.org]\n'
                              "intercept: [internal.corp.example]")
        Path(self.cfg).write_text(text, encoding="utf-8")
        code, out = run("dns-config", "-c", self.cfg, "--upstream", "1.1.1.1", "--interface", "eth1")
        self.assertEqual(code, 0, out)
        lines = out.splitlines()
        self.assertIn("interface=eth1", lines)
        self.assertIn("no-resolv", lines)
        servers = sorted(l for l in lines if l.startswith("server="))
        self.assertEqual(servers, ["server=/api.example.test/1.1.1.1",
                                   "server=/internal.corp.example/1.1.1.1",
                                   "server=/pypi.org/1.1.1.1",          # covers files.pypi.org
                                   "server=/pythonhosted.org/1.1.1.1"])
        code, out = run("dns-config", "-c", self.cfg, "--upstream", "9.9.9.9", "--allow-all")
        self.assertIn("server=9.9.9.9", out.splitlines())

    def test_bad_config(self):
        Path(self.cfg).write_text("secrets: [{name: x}]\n", encoding="utf-8")
        code, out = run("check", "-c", self.cfg)
        self.assertEqual(code, 2)
        self.assertIn("config error", out)

    def test_yaml_syntax_error_is_reported_cleanly(self):
        Path(self.cfg).write_text("secrets:\n  - value: [env:A, file:${X}/b]\n", encoding="utf-8")
        code, out = run("check", "-c", self.cfg)
        self.assertEqual(code, 2)
        self.assertIn("line 2", out)
        self.assertNotIn("Traceback", out)

    def test_shipped_example_configs_parse(self):
        root = Path(__file__).resolve().parents[1]
        for rel in ("deploy/config.yaml", "deploy/vm/config.example.yaml", "deploy/k8s/config.yaml"):
            text = (root / rel).read_text(encoding="utf-8")
            text = text.replace("REPLACE-with-new-placeholder", "0123456789abcdef0123")
            Path(self.cfg).write_text(text, encoding="utf-8")
            code, out = run("sandbox-env", "-c", self.cfg)
            self.assertEqual(code, 0, f"{rel}: {out}")


if __name__ == "__main__":
    unittest.main()
