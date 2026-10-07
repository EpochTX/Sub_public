#!/usr/bin/env bash
set -euo pipefail
umask 077
if [[ ${EUID} -ne 0 ]]; then
  printf '%s\n' '请使用 sudo bash install.sh prepare 你的域名，或 sudo bash install.sh start。' >&2
  exit 1
fi
if [[ ! -d /run/systemd/system ]]; then
  printf '%s\n' '本脚本适用于使用 systemd 的 Linux。' >&2
  exit 1
fi
SUB_SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if ! command -v git >/dev/null || ! command -v ssh-keygen >/dev/null ||
   ! python3 -c 'import yaml' 2>/dev/null; then
  if ! command -v apt-get >/dev/null; then
    printf '%s\n' '请先安装 git、openssh-client、python3、python3-yaml。' >&2
    exit 1
  fi
  apt-get update
  apt-get install -y --no-install-recommends git openssh-client python3 python3-yaml
fi
exec python3 "${SUB_SCRIPT_DIR}/setup.py" "$@"
