#!/usr/bin/env python3
"""Windows Server setup. Only the VPS generates and stores private secrets."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys

ROOT = Path(os.environ.get("ProgramData", "C:/ProgramData")) / "SubSync"
CONFIG = ROOT / "config.json"
TASK = "SubSync"
HOST_KEY = "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"


def powershell(script):
    import base64
    encoded = base64.b64encode(script.encode("utf-16le")).decode()
    return subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                          check=True)


def ps_string(value):
    return "'" + str(value).replace("'", "''") + "'"


def read_config():
    if not CONFIG.exists():
        raise SystemExit("Run prepare first.")
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def info():
    from server import FILES
    config = read_config()
    print("Read-only Deploy Key for EpochTX/sub (leave write access unchecked):")
    print((ROOT / "deploy_key.pub").read_text().strip())
    print("\nPrivate repository webhook:")
    print("Payload URL:", config["public_base_url"] + "/hook")
    print("Content type: application/json; Just the push event; SSL verification enabled")
    print("Secret:", config["webhook_secret"])
    print("\nPrivate download URLs:")
    for alias in FILES:
        print(config["public_base_url"] + "/s/" + config["download_token"] + "/" + alias)
    if not config.get("tls_cert"):
        print("\nHTTPS is not configured. Run prepare again with --cert and --key before start.")


def prepare(args):
    import yaml  # Verify the required parser exists before changing the VPS.
    if not args.domain or not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", args.domain):
        raise SystemExit("Supply --domain with a DNS hostname.")
    if args.port in (443, 24443, 3389) or not 1024 <= args.port <= 65535:
        raise SystemExit("Choose a separate unoccupied HTTPS port; default is 8443.")
    if bool(args.cert) != bool(args.key):
        raise SystemExit("Supply both --cert and --key.")
    if args.cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
    git = shutil.which("git.exe")
    system_git = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/cmd/git.exe"
    if system_git.exists():
        git = str(system_git)
    if not git:
        raise SystemExit("Install Git for Windows first.")
    git_root = Path(git).resolve().parent.parent
    ssh = git_root / "usr/bin/ssh.exe"
    keygen = git_root / "usr/bin/ssh-keygen.exe"
    if not ssh.exists() or not keygen.exists():
        raise SystemExit("Use the standard Git for Windows installation with bundled OpenSSH.")
    ROOT.mkdir(parents=True, exist_ok=True)
    # SID-based ACLs work on both Chinese and English Windows.
    subprocess.run(["icacls.exe", str(ROOT), "/inheritance:r", "/grant:r",
                    "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"],
                   check=True, stdout=subprocess.DEVNULL)
    base = "https://" + args.domain + ":" + str(args.port)
    if CONFIG.exists():
        config = read_config()
        if config["public_base_url"] != base:
            raise SystemExit("Existing fixed URL differs; refusing to change it automatically.")
    else:
        config = {
            "repo": "EpochTX/sub", "branch": "main", "domain": args.domain,
            "public_base_url": base, "state_dir": str(ROOT / "state"),
            "bind": "127.0.0.1", "port": args.port,
            "download_token": secrets.token_hex(32), "webhook_secret": secrets.token_hex(32),
        }
    config.update(git_executable=str(git), ssh_executable=str(ssh),
                  ssh_key=str(ROOT / "deploy_key"), known_hosts=str(ROOT / "known_hosts"))
    if args.cert:
        # Reference the existing renewal paths so renewed certificates are reloaded automatically.
        config.update(tls_cert=str(Path(args.cert).resolve()), tls_key=str(Path(args.key).resolve()),
                      bind="0.0.0.0")
    (ROOT / "state").mkdir(exist_ok=True)
    for name in ("server.py", "setup_windows.py"):
        source = Path(__file__).with_name(name)
        if source.resolve() != (ROOT / name).resolve():
            shutil.copyfile(source, ROOT / name)
    (ROOT / "known_hosts").write_text(HOST_KEY, encoding="ascii")
    if not (ROOT / "deploy_key").exists():
        subprocess.run([str(keygen), "-q", "-t", "ed25519", "-N", "", "-C",
                        "sub-sync-readonly", "-f", str(ROOT / "deploy_key")], check=True)
    CONFIG.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    info()


def start():
    config = read_config()
    if not config.get("tls_cert"):
        raise SystemExit("Configure --cert and --key first; the public service requires HTTPS.")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(config["tls_cert"], config["tls_key"])
    # Finish the first authenticated pull and validation before opening the download port.
    subprocess.run([sys.executable, str(ROOT / "server.py"), "--config", str(CONFIG), "--sync-once"], check=True)
    powershell("""$ErrorActionPreference = 'Stop'
$taskName = 'SubSync'
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) { Stop-ScheduledTask -TaskName $taskName; Start-Sleep -Seconds 2 }
$listeners = Get-NetTCPConnection -LocalPort PORT -State Listen -ErrorAction SilentlyContinue
if ($listeners) { throw 'HTTPS port already in use; existing services were not changed.' }
$action = New-ScheduledTaskAction -Execute PYTHON -Argument ARGUMENTS -WorkingDirectory DIRECTORY
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 100 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
$rule = Get-NetFirewallRule -Name 'SubSync-HTTPS' -ErrorAction SilentlyContinue
if (-not $rule) {
    New-NetFirewallRule -Name 'SubSync-HTTPS' -DisplayName 'SubSync private HTTPS' -Direction Inbound -Action Allow -Protocol TCP -LocalPort PORT -Program PYTHON | Out-Null
}
Start-ScheduledTask -TaskName $taskName
""".replace("PYTHON", ps_string(sys.executable)).replace("ARGUMENTS", ps_string(
            subprocess.list2cmdline([str(ROOT / "server.py"), "--config", str(CONFIG)])))
            .replace("DIRECTORY", ps_string(ROOT)).replace("PORT", str(config["port"])))
    print("Startup task registered and started. Check Azure NSG inbound TCP", config["port"], "as well.")
    print("Confirm the HTTPS URL before adding the webhook to EpochTX/sub.")


def main():
    parser = argparse.ArgumentParser(description="Windows Server: prepare, configure GitHub read-only key, then start")
    parser.add_argument("action", choices=("prepare", "start", "info"))
    parser.add_argument("--domain")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", help="Existing trusted full-chain PEM path for the chosen domain")
    parser.add_argument("--key", help="Existing matching private-key PEM path")
    args = parser.parse_args()
    if os.name != "nt":
        raise SystemExit("This installer requires Windows.")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("Run in an Administrator PowerShell window.")
    if args.action == "prepare":
        prepare(args)
    elif args.action == "start":
        start()
    else:
        info()


if __name__ == "__main__":
    main()
