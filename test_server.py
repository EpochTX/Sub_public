import hashlib
import hmac
import http.client
import json
import ssl
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock
from urllib.parse import quote

from server import FILES, Sync, download_content, load_config, make_server, validate_config

YAML = b"dns: {nameserver: [1.1.1.1]}\nproxies: [{name: test}]\nproxy-groups: [{name: test}]\nrules: [MATCH,test]\n"
PROFILE = b"[General]\n[Proxy Group]\n[Rule]\nFINAL,DIRECT\n"

NETPROXY_NODES = b"proxies:\\n  - name: HK-VPS\\n    type: ss\\n    server: 127.0.0.1\\n    port: 8388\\n"


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config = {"repo": "EpochTX/sub", "branch": "main", "port": 0,
                       "domain": "sub.example.invalid",
                       "state_dir": self.temp.name, "download_token": "a" * 64,
                       "webhook_secret": "b" * 64}
        self.sync = Sync(self.config)
        self.sync.request = Mock()
        release = Path(self.temp.name) / "releases" / ("c" * 40)
        release.mkdir(parents=True)
        (release / "surge.conf").write_bytes(PROFILE)
        (Path(self.temp.name) / "current.sha").write_text("c" * 40)
        self.server = make_server(self.config, self.sync)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def hook(self, payload, event="push", signed=True):
        body = json.dumps(payload).encode()
        headers = {"X-GitHub-Event": event, "Content-Type": "application/json"}
        if signed:
            headers["X-Hub-Signature-256"] = "sha256=" + hmac.new(
                self.config["webhook_secret"].encode(), body, hashlib.sha256).hexdigest()
        return self.request("POST", "/hook", body, headers)[0]

    def test_private_download_and_conditional_request(self):
        path = "/s/" + self.config["download_token"] + "/surge.conf"
        status, headers, data = self.request("GET", path)
        self.assertEqual(status, 200)
        self.assertEqual(data, download_content("surge.conf", PROFILE, self.config))
        self.assertTrue(data.startswith(("#!MANAGED-CONFIG https://sub.example.invalid" + path).encode()))
        self.assertTrue(data.endswith(PROFILE))
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(self.request("HEAD", path)[2], b"")
        self.assertEqual(self.request("GET", path, headers={"If-None-Match": headers["ETag"]})[0], 304)

    def test_no_token_wrong_token_traversal_and_git_are_denied(self):
        token = self.config["download_token"]
        for path in ("/", "/surge.conf", "/s/wrong/surge.conf", "/.git/config",
                     "/s/" + token + "/../config.json", "/s/" + token + "/config.json",
                     "/s/" + token + "/%2e%2e%2frepo.git/config",
                     "/s/" + token + "/" + quote("宝宝巴士_surge.conf")):
            with self.subTest(path=path):
                status, headers, data = self.request("GET", path)
                self.assertEqual((status, data), (404, b""))
                self.assertNotIn("ETag", headers)

    def test_unsigned_and_tampered_webhooks_are_denied(self):
        payload = {"repository": {"full_name": "EpochTX/sub"}, "ref": "refs/heads/main"}
        self.assertEqual(self.hook(payload, signed=False), 403)
        self.assertEqual(self.request("POST", "/hook", b"{}", {"X-Hub-Signature-256": "sha256=wrong"})[0], 403)
        self.sync.request.assert_not_called()

    def test_only_private_repo_main_push_triggers_sync(self):
        payload = {"repository": {"full_name": "EpochTX/sub"}, "ref": "refs/heads/dev"}
        self.assertEqual(self.hook(payload), 204)
        payload["ref"] = "refs/heads/main"
        payload["repository"]["full_name"] = "EpochTX/Sub_public"
        self.assertEqual(self.hook(payload), 403)
        self.sync.request.assert_not_called()
        payload["repository"]["full_name"] = "EpochTX/sub"
        self.assertEqual(self.hook(payload), 202)
        self.sync.request.assert_called_once()

    def test_ping_does_not_fetch_and_bad_json_is_rejected(self):
        self.assertEqual(self.hook({"repository": {"full_name": "EpochTX/sub"}}, "ping"), 200)
        self.assertEqual(self.hook([]), 403)
        self.assertEqual(self.request("POST", "/hook", b"x", {"Content-Length": "99999999"})[0], 413)
        self.sync.request.assert_not_called()


class SyncTests(unittest.TestCase):
    def test_atomic_publication_and_failed_update_retains_previous_version(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            def git(*args):
                return subprocess.run(["git", "-C", str(source), *args], check=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
            git("init", "--initial-branch=main")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.invalid")
            for alias, path in FILES.items():
                (source / path).write_bytes(NETPROXY_NODES if alias == "openclash.yaml" else (YAML if alias.endswith(".yaml") else PROFILE))
            (source / "private.env").write_text("SHOULD_NOT_BE_SERVED")
            git("add", ".")
            git("commit", "-m", "valid")
            sync = Sync({"repo": "EpochTX/sub", "branch": "main",
                         "state_dir": str(root / "state"), "source_url": str(source)})
            self.assertTrue(sync.once())
            previous = sync.current_release()
            self.assertEqual({p.name for p in previous.iterdir()}, set(FILES))
            self.assertFalse(sync.once())
            (source / FILES["clash.yaml"]).write_text("dns: [invalid YAML")
            git("add", ".")
            git("commit", "-m", "invalid")
            with self.assertRaises(Exception):
                sync.once()
            self.assertEqual(sync.current_release(), previous)
            self.assertEqual((previous / "surge.conf").read_bytes(), PROFILE)
            self.assertFalse(list((sync.state / "releases").glob(".stage-*")))
            (source / FILES["clash.yaml"]).write_bytes(YAML + b"# fixed\n")
            git("add", ".")
            git("commit", "-m", "fixed")
            self.assertTrue(sync.once())
            self.assertNotEqual(sync.current_release(), previous)

    def test_empty_truncated_and_incomplete_files_fail_validation(self):
        for alias, data in (("clash.yaml", b""), ("clash.yaml", b"dns: {}\n"),
                            ("surge.conf", b"[General]\n"), ("surge.conf", b"\xff")):
            with self.subTest(alias=alias, data=data), self.assertRaises(Exception):
                validate_config(alias, data)

    def test_netproxy_nodes_at_original_openclash_alias(self):
        validate_config("openclash.yaml", NETPROXY_NODES)
        validate_config("openclash.yaml", YAML)  # Allow historical full-profile rollback.
        for alias in ("clash.yaml", "maomao.yaml"):
            with self.subTest(alias=alias), self.assertRaises(ValueError):
                validate_config(alias, NETPROXY_NODES)
        invalid_nodes = (
            b"proxies: []\\n",
            b"proxies: [{name: missing_type}]\\n",
            b"proxies: [{type: ss}]\\n",
            b"proxies: [{name: n, type: ss}]\\nproxy-groups: []\\n",
        )
        for value in invalid_nodes:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_config("openclash.yaml", value)

    def test_public_binding_requires_tls_and_url_keeps_port(self):
        with tempfile.TemporaryDirectory() as temp:
            config = {"repo": "EpochTX/sub", "branch": "main", "domain": "sub.example.invalid",
                      "bind": "0.0.0.0", "state_dir": temp,
                      "download_token": "a" * 64, "webhook_secret": "b" * 64}
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(config))
            with self.assertRaises(ValueError):
                load_config(path)
            config.update(tls_cert="cert.pem", tls_key="key.pem",
                          public_base_url="https://sub.example.invalid:8443")
            path.write_text(json.dumps(config))
            self.assertEqual(load_config(path)["bind"], "0.0.0.0")
            self.assertIn(b"https://sub.example.invalid:8443/s/", download_content("surge.conf", PROFILE, config))

    @unittest.skipUnless(__import__("shutil").which("openssl"), "openssl is needed for TLS integration")
    def test_https_certificate_verification_and_private_download(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1",
                            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            config = {"repo": "EpochTX/sub", "branch": "main", "domain": "localhost",
                      "state_dir": temp, "port": 0, "download_token": "a" * 64,
                      "webhook_secret": "b" * 64, "tls_cert": str(cert), "tls_key": str(key)}
            sync = Sync(config)
            release = root / "releases" / ("d" * 40)
            release.mkdir(parents=True)
            (release / "clash.yaml").write_bytes(YAML)
            (root / "current.sha").write_text("d" * 40)
            server = make_server(config, sync)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                context = ssl.create_default_context(cafile=str(cert))
                connection = http.client.HTTPSConnection("localhost", server.server_port, context=context)
                connection.request("GET", "/s/" + config["download_token"] + "/clash.yaml")
                response = connection.getresponse()
                self.assertEqual((response.status, response.read()), (200, YAML))
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


if __name__ == "__main__":
    unittest.main()
