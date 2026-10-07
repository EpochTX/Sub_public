#!/usr/bin/env python3
"""Generate secrets on the VPS; prepare does not change the existing web server."""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import subprocess

ETC = Path("/etc/sub-sync")
APP = Path("/opt/sub-sync")
STATE = Path("/var/lib/sub-sync")
UNIT = Path("/etc/systemd/system/sub-sync.service")
ACCOUNT = "sub-sync"
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
ALIASES = ("surge.conf", "clash.yaml", "loon.conf", "openclash.yaml", "maomao.yaml")


def write(path, text, mode, gid=None):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.chmod(mode)
    if gid is not None:
        os.chown(temporary, 0, gid)
    os.replace(temporary, path)


def info():
    config = json.loads((ETC / "config.json").read_text())
    print("GitHub 私库 Deploy Key（只读，不勾选 Allow write access）：")
    print((ETC / "deploy_key.pub").read_text().strip())
    print("\nGitHub 私库 Webhook：")
    print("Payload URL:", "https://" + config["domain"] + "/hook")
    print("Content type: application/json")
    print("Secret:", config["webhook_secret"])
    print("Events: Just the push event; Enable SSL verification")
    print("\n私人下载链接（请勿公开或发给别人）：")
    for alias in ALIASES:
        print("https://" + config["domain"] + "/s/" + config["download_token"] + "/" + alias)
    print("\n先将现有 HTTPS 网站反向代理到 127.0.0.1:8767，再运行 sudo bash install.sh start。")
    print("Nginx location 示例:", ETC / "nginx.locations.conf")
    print("Caddy 站点示例:", ETC / "caddy.site.conf")


def prepare(domain):
    if not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", domain):
        raise SystemExit("请提供纯域名，例如 sub.example.com，不带 https://、端口或路径。")
    try:
        account = pwd.getpwnam(ACCOUNT)
    except KeyError:
        subprocess.run(["useradd", "--system", "--home-dir", str(STATE),
                        "--shell", "/usr/sbin/nologin", ACCOUNT], check=True)
        account = pwd.getpwnam(ACCOUNT)
    APP.mkdir(mode=0o755, exist_ok=True)
    APP.chmod(0o755)
    ETC.mkdir(mode=0o750, exist_ok=True)
    os.chown(ETC, 0, account.pw_gid)
    ETC.chmod(0o750)
    STATE.mkdir(mode=0o700, exist_ok=True)
    os.chown(STATE, account.pw_uid, account.pw_gid)
    for filename in ("server.py", "setup.py"):
        shutil.copyfile(Path(__file__).with_name(filename), APP / filename)
        (APP / filename).chmod(0o644)
    key = ETC / "deploy_key"
    if not key.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                        "sub-sync-readonly", "-f", str(key)], check=True)
    key.chmod(0o640)
    os.chown(key, 0, account.pw_gid)
    write(ETC / "known_hosts", "github.com " + HOST_KEY + "\n", 0o644)
    target = ETC / "config.json"
    if target.exists():
        config = json.loads(target.read_text())
        if config["domain"] != domain:
            raise SystemExit("域名与现有设置不同；为避免改变固定链接，本次停止。")
    else:
        config = {
            "repo": "EpochTX/sub", "branch": "main", "domain": domain,
            "state_dir": str(STATE), "ssh_key": str(key),
            "known_hosts": str(ETC / "known_hosts"),
            "bind": "127.0.0.1", "port": 8767,
            "download_token": secrets.token_hex(32),
            "webhook_secret": secrets.token_hex(32),
        }
    write(target, json.dumps(config, indent=2) + "\n", 0o640, account.pw_gid)
    write(UNIT, """[Unit]
Description=Private subscription sync and downloads
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sub-sync
Group=sub-sync
WorkingDirectory=/var/lib/sub-sync
ExecStart=/usr/bin/python3 /opt/sub-sync/server.py --config /etc/sub-sync/config.json
Restart=on-failure
RestartSec=10
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sub-sync
RestrictSUIDSGID=true
ProtectKernelTunables=true
ProtectControlGroups=true
Environment=PYTHONDONTWRITEBYTECODE=1

[Install]
WantedBy=multi-user.target
""", 0o644)
    write(ETC / "nginx.locations.conf", """location ^~ /s/ {
    access_log off;
    proxy_pass http://127.0.0.1:8767;
    proxy_http_version 1.1;
}
location = /hook {
    access_log off;
    client_max_body_size 4m;
    proxy_pass http://127.0.0.1:8767;
    proxy_http_version 1.1;
}
""", 0o644)
    write(ETC / "caddy.site.conf", domain + """ {
    @subsync path /s/* /hook
    handle @subsync {
        reverse_proxy 127.0.0.1:8767
    }
    handle {
        respond 404
    }
}
""", 0o644)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    info()


def start():
    if not (ETC / "config.json").exists():
        raise SystemExit("先运行 prepare 你的域名。")
    result = subprocess.run(["runuser", "-u", ACCOUNT, "--", "/usr/bin/python3",
                             str(APP / "server.py"), "--sync-once"])
    if result.returncode:
        raise SystemExit("首次拉取或配置检查未通过。请检查只读 Deploy Key、GitHub 网络和源配置。")
    subprocess.run(["systemctl", "enable", "sub-sync.service"], check=True)
    subprocess.run(["systemctl", "restart", "sub-sync.service"], check=True)
    print("同步服务已启动；确认 HTTPS 反向代理可用后，在 GitHub 私库添加 Webhook。")


def main():
    parser = argparse.ArgumentParser(description="私人订阅部署：prepare 域名 → 配置只读密钥和 HTTPS → start")
    parser.add_argument("action", choices=("prepare", "start", "info"))
    parser.add_argument("domain", nargs="?")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("请使用 sudo。")
    os.umask(0o077)
    if args.action == "prepare":
        if not args.domain:
            parser.error("prepare 需要域名")
        prepare(args.domain)
    elif args.action == "start":
        start()
    else:
        info()


if __name__ == "__main__":
    main()
