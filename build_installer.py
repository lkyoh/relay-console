"""Build a portable, data-free, self-extracting installer from an explicit allow-list."""
import base64
import hashlib
import io
import json
from pathlib import Path
import tarfile
HERE=Path(__file__).resolve().parent
FILES=['server.py','first_setup.py','backup.py','deploy_standby.py','renew_standby.py','traffic.py','index.html','app.js','app.css','qrcode.js','standalone_installer.py']

def build():
    entries={name:(HERE/name).read_bytes() for name in FILES}
    entries['manifest.json']=json.dumps({name:hashlib.sha256(raw).hexdigest() for name,raw in entries.items()},sort_keys=True).encode()
    payload=io.BytesIO()
    with tarfile.open(fileobj=payload,mode='w:gz') as archive:
        for name,content in entries.items():
            info=tarfile.TarInfo(name);info.size=len(content);info.mode=0o644;info.mtime=0
            archive.addfile(info,io.BytesIO(content))
    encoded=base64.b64encode(payload.getvalue()).decode()
    shell='''#!/usr/bin/env bash
set -euo pipefail
relay_check=0
for relay_arg in "$@"; do
  if [ "$relay_arg" = "--check" ]; then relay_check=1; fi
done
if [ "$relay_check" -eq 0 ]; then
  if [ "$(id -u)" -ne 0 ]; then echo '请使用 sudo bash relay-panel-install.sh'; exit 1; fi
  if [ -e /etc/sbgateway-relay-manager ] || [ -e /opt/sbgateway-relay-manager ]; then
    echo '已有面板或配置，停止安装；不会覆盖现有数据。'; exit 1
  fi
  if ! command -v apt-get >/dev/null; then echo '此安装包支持 Debian / Ubuntu。'; exit 1; fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y python3 python3-paramiko python3-cryptography ca-certificates openssl certbot nftables
fi
if ! command -v python3 >/dev/null; then echo '检查未通过：需要 Python 3（正式安装时会自动安装依赖）。'; exit 1; fi
python3 - "$0" "$@" <<'RELAY_INSTALLER_PY'
import base64,hashlib,io,json,pathlib,runpy,sys,tarfile,tempfile
encoded="__PAYLOAD__"
with tempfile.TemporaryDirectory(prefix='relay-panel-install-') as temporary:
    directory=pathlib.Path(temporary)
    with tarfile.open(fileobj=io.BytesIO(base64.b64decode(encoded)),mode='r:gz') as archive:
        for item in archive.getmembers():
            if not item.isfile() or pathlib.PurePosixPath(item.name).name!=item.name:
                raise SystemExit('安装包包含非法路径')
            (directory/item.name).write_bytes(archive.extractfile(item).read())
    manifest=json.loads((directory/'manifest.json').read_text())
    for name,digest in manifest.items():
        if pathlib.PurePosixPath(name).name!=name or hashlib.sha256((directory/name).read_bytes()).hexdigest()!=digest:
            raise SystemExit('安装包文件校验失败')
    original=sys.argv[1]
    sys.argv=[str(directory/'standalone_installer.py'),*sys.argv[2:],'--script',original]
    runpy.run_path(str(directory/'standalone_installer.py'),run_name='__main__')
RELAY_INSTALLER_PY
'''.replace('__PAYLOAD__',encoded)
    return shell

if __name__=='__main__':
    script=build()
    (HERE/'relay-panel-install.sh').write_text(script,encoding='utf-8',newline='\n')
    print('Built portable installer:',len(script.encode()),'bytes; includes code only, no state or credentials')
