#!/usr/bin/env python3
"""Private configuration downloads and authenticated, event-driven Git sync."""
import argparse
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import yaml

FILES = {
    "clash.yaml": "宝宝巴士.yaml",
    "surge.conf": "宝宝巴士_surge.conf",
    "loon.conf": "宝宝巴士_loon.conf",
    "openclash.yaml": "宝宝巴士_软路由.yaml",
    "maomao.yaml": "宝宝巴士_猫猫.yaml",
}
MAX_FILE = 2 * 1024 * 1024
LOG = logging.getLogger("sub-sync")


def validate_config(name, data):
    if not 0 < len(data) <= MAX_FILE or b"\x00" in data:
        raise ValueError("invalid file size or encoding")
    text = data.decode("utf-8-sig")
    if name.endswith(".yaml"):
        parsed = yaml.safe_load(text)
        if not isinstance(parsed, dict):
            raise ValueError("expected YAML mapping")
        # The legacy openclash.yaml URL now serves a NetProxy node-only subscription.
        # Continue accepting the historical full Mihomo document for safe rollbacks.
        # Other YAML aliases still require complete client profiles.
        if name == "openclash.yaml" and set(parsed) == {"proxies"}:
            nodes = parsed["proxies"]
            if (not isinstance(nodes, list) or not nodes
                    or any(not isinstance(node, dict)
                           or not isinstance(node.get("name"), str) or not node["name"]
                           or not isinstance(node.get("type"), str) or not node["type"]
                           for node in nodes)):
                raise ValueError("invalid NetProxy node-only subscription")
        else:
            for key, kind in (("dns", dict), ("proxy-groups", list), ("rules", list)):
                if not isinstance(parsed.get(key), kind) or not parsed[key]:
                    raise ValueError("missing required YAML section")
            if not (parsed.get("proxies") or parsed.get("proxy-providers")):
                raise ValueError("missing proxy definitions")
    else:
        for section in ("[General]", "[Proxy Group]", "[Rule]"):
            if not re.search(r"(?m)^" + re.escape(section) + r"\s*$", text):
                raise ValueError("missing required profile section")


def download_content(alias, data, config):
    if alias != "surge.conf":
        return data
    # Keep the private source unchanged; the served copy tracks this same URL.
    text = data.decode("utf-8-sig")
    text = "\n".join(line for line in text.split("\n")
                     if not line.startswith("#!MANAGED-CONFIG "))
    base = config.get("public_base_url", "https://" + config["domain"])
    url = base + "/s/" + config["download_token"] + "/surge.conf"
    return ("#!MANAGED-CONFIG " + url + " interval=3600 strict=false\n" + text).encode()


class Sync:
    def __init__(self, config):
        self.config = config
        self.state = Path(config["state_dir"])
        self.repo = self.state / "repo.git"
        self.pending = threading.Event()
        self.lock = threading.Lock()
        self.stop = threading.Event()

    def git(self, *args):
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_CONFIG_GLOBAL"] = os.devnull
        if self.config.get("ssh_key"):
            import shlex
            env["GIT_SSH_COMMAND"] = " ".join([
                shlex.quote(self.config.get("ssh_executable", "ssh").replace("\\", "/")),
                "-F none -o BatchMode=yes -o IdentitiesOnly=yes",
                "-o StrictHostKeyChecking=yes -o ConnectTimeout=15",
                "-i", shlex.quote(self.config["ssh_key"].replace("\\", "/")),
                "-o", shlex.quote("UserKnownHostsFile=" + self.config["known_hosts"].replace("\\", "/")),
            ])
        result = subprocess.run(
            [self.config.get("git_executable", "git"), "--git-dir", str(self.repo), *args], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120,
            check=True,
        )
        return result.stdout

    def source_url(self):
        return self.config.get("source_url", "git@github.com:" + self.config["repo"] + ".git")

    def current_release(self):
        pointer = self.state / "current.sha"
        if pointer.exists():
            revision = pointer.read_text().strip()
            if not re.fullmatch(r"[0-9a-f]{40,64}", revision):
                raise OSError("invalid release pointer")
            return self.state / "releases" / revision
        # Read already-installed Linux releases during a version transition.
        return (self.state / "current").resolve(strict=True)

    def once(self):
        with self.lock:
            self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not self.repo.exists():
                subprocess.run([self.config.get("git_executable", "git"), "init", "--bare", str(self.repo)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               check=True, timeout=30)
            branch = self.config["branch"]
            self.git("fetch", "--depth=1", "--no-tags", self.source_url(),
                     "+refs/heads/" + branch + ":refs/heads/current")
            revision = self.git("rev-parse", "refs/heads/current").decode().strip()
            try:
                if self.current_release().name == revision:
                    return False
            except OSError:
                pass
            releases = self.state / "releases"
            releases.mkdir(mode=0o700, exist_ok=True)
            stage = Path(tempfile.mkdtemp(prefix=".stage-", dir=releases))
            try:
                for alias, path in FILES.items():
                    data = self.git("show", revision + ":" + path)
                    validate_config(alias, data)
                    target = stage / alias
                    target.write_bytes(data)
                    target.chmod(0o600)
                release = releases / revision
                if not release.exists():
                    os.replace(stage, release)
                else:
                    shutil.rmtree(stage)
                pointer = self.state / ".next"
                pointer.unlink(missing_ok=True)
                pointer.write_text(revision + "\n", encoding="ascii")
                os.replace(pointer, self.state / "current.sha")
                LOG.info("Published configuration revision %s", revision[:12])
                old = sorted((p for p in releases.iterdir()
                              if p.is_dir() and re.fullmatch(r"[0-9a-f]{40,64}", p.name)
                              and p != release), key=lambda p: p.stat().st_mtime, reverse=True)
                for path in old[2:]:
                    shutil.rmtree(path)
                return True
            finally:
                if stage.exists():
                    shutil.rmtree(stage)

    def request(self):
        self.pending.set()

    def worker(self):
        while not self.stop.is_set():
            self.pending.wait()
            if self.stop.is_set():
                return
            self.pending.clear()
            for delay in (0, 15, 60, 180):
                if delay and self.stop.wait(delay):
                    return
                try:
                    self.once()
                    break
                except Exception as exc:
                    # Do not log exception text: YAML errors can contain credentials.
                    LOG.error("Sync failed (%s); previous configuration retained", type(exc).__name__)


def make_server(config, sync):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SubSync"
        sys_version = ""

        def setup(self):
            super().setup()
            self.connection.settimeout(15)

        def log_message(self, *_):
            pass  # URLs carry the download token; never record them.

        def reply(self, status, body=b"", content_type="text/plain; charset=utf-8", etag=None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            if etag:
                self.send_header("ETag", etag)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            parts = urlsplit(self.path).path.split("/")
            if (len(parts) != 4 or parts[1] != "s" or parts[3] not in FILES
                    or not hmac.compare_digest(parts[2].encode(), config["download_token"].encode())):
                self.reply(404)
                return
            try:
                release = sync.current_release()
                data = (release / parts[3]).read_bytes()
            except OSError:
                self.reply(503, b"Configuration not ready\n")
                return
            data = download_content(parts[3], data, config)
            etag = '"' + hashlib.sha256(data).hexdigest() + '"'
            if self.headers.get("If-None-Match") == etag:
                self.reply(304, etag=etag)
            else:
                self.reply(200, data, etag=etag)

        def do_POST(self):
            if urlsplit(self.path).path != "/hook":
                self.reply(404)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 4 * 1024 * 1024 or self.headers.get("Transfer-Encoding"):
                    self.reply(413)
                    return
                body = self.rfile.read(size)
                if len(body) != size:
                    self.reply(400)
                    return
                expected = "sha256=" + hmac.new(config["webhook_secret"].encode(), body,
                                                hashlib.sha256).hexdigest()
                supplied = self.headers.get("X-Hub-Signature-256", "")
                if not hmac.compare_digest(expected.encode(), supplied.encode()):
                    self.reply(403)
                    return
                payload = json.loads(body)
                if (not isinstance(payload, dict)
                        or not isinstance(payload.get("repository"), dict)
                        or payload["repository"].get("full_name") != config["repo"]):
                    self.reply(403)
                    return
                event = self.headers.get("X-GitHub-Event", "")
                if event == "ping":
                    self.reply(200, b"pong\n")
                elif (event == "push" and payload.get("ref") == "refs/heads/" + config["branch"]
                      and not payload.get("deleted")):
                    sync.request()
                    self.reply(202, b"queued\n")
                else:
                    self.reply(204)
            except (ValueError, UnicodeError):
                self.reply(400)
            except OSError:
                self.close_connection = True

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 16

        def get_request(self):
            connection, address = super().get_request()
            if not config.get("tls_cert"):
                return connection, address
            try:
                self.refresh_tls()
                connection.settimeout(15)
                return self.tls_context.wrap_socket(connection, server_side=True,
                                                    do_handshake_on_connect=False), address
            except Exception:
                connection.close()
                raise

        def refresh_tls(self):
            paths = (config["tls_cert"], config["tls_key"])
            stamp = tuple(Path(path).stat().st_mtime_ns for path in paths)
            if getattr(self, "tls_stamp", None) == stamp:
                return
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(*paths)
            self.tls_context = context
            self.tls_stamp = stamp

    server = Server((config.get("bind", "127.0.0.1"), config.get("port", 8767)), Handler)
    try:
        if config.get("tls_cert"):
            server.refresh_tls()
    except Exception:
        server.server_close()
        raise
    return server


def load_config(path):
    config = json.loads(Path(path).read_text())
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", config["repo"]):
        raise ValueError("invalid repository")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", config["branch"]):
        raise ValueError("invalid branch")
    for key in ("download_token", "webhook_secret"):
        if not re.fullmatch(r"[0-9a-f]{64}", config[key]):
            raise ValueError("invalid secret")
    if bool(config.get("tls_cert")) != bool(config.get("tls_key")):
        raise ValueError("both TLS certificate and key are required")
    if config.get("bind", "127.0.0.1") != "127.0.0.1" and not config.get("tls_cert"):
        raise ValueError("public binding requires HTTPS")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", config["domain"]):
        raise ValueError("invalid domain")
    if config.get("public_base_url"):
        base = urlsplit(config["public_base_url"])
        if (base.scheme != "https" or base.hostname != config["domain"].lower()
                or base.username or base.password or base.path or base.query or base.fragment):
            raise ValueError("invalid public HTTPS URL")
    return config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/sub-sync/config.json")
    parser.add_argument("--sync-once", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = load_config(args.config)
    sync = Sync(config)
    if args.sync_once:
        try:
            sync.once()
        except Exception as exc:
            LOG.error("Sync failed (%s)", type(exc).__name__)
            raise SystemExit(1)
        return
    thread = threading.Thread(target=sync.worker, daemon=True)
    thread.start()
    sync.request()  # Startup recovery; no periodic repository polling.
    server = make_server(config, sync)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        sync.stop.set()
        sync.pending.set()
        server.server_close()


if __name__ == "__main__":
    main()
