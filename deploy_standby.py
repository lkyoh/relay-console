"""Runs only on a deliberately selected standby host. Never touches sing-box.service."""
import json
import copy
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import secrets

ROOT=Path('/etc/sbgateway-relay-manager')
APP=Path('/opt/sbgateway-relay-manager')
CORE=Path('/opt/sbgateway-relay-managed/sing-box')
UNITS=Path('/etc/systemd/system')
SERVICES=['sbgateway-relay-managed','sbgateway-relay-manager']
ASSETS=['server.py','firewall.py','first_setup.py','backup.py','deploy_standby.py','renew_standby.py','traffic.py','app.js','app.css','index.html','qrcode.js','relay-panel-install.sh']
PRIVATE=['state.json','config.json','live.crt','live.key','panel.crt','panel.key','servers.enc','servers.key']
CORE_UNIT='''[Unit]
Description=Managed standby relay
After=network-online.target
[Service]
ExecStart=/opt/sbgateway-relay-managed/sing-box run -c /etc/sbgateway-relay-manager/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
'''
PANEL_UNIT='''[Unit]
Description=Standby relay management page
After=network-online.target
[Service]
Environment=RELAY_MANAGER_BIN=/opt/sbgateway-relay-managed/sing-box
ExecStart=/usr/bin/python3 /opt/sbgateway-relay-manager/server.py
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/sbgateway-relay-manager -/etc/ufw -/var/lib/ufw -/run/ufw -/run/xtables.lock
[Install]
WantedBy=multi-user.target
'''

def run(args,check=True):
    return subprocess.run(args,check=check,capture_output=True,timeout=30)

def main(stage):
    if os.geteuid()!=0:raise ValueError('NOT_ROOT')
    if stage.parent!=Path('/tmp') or not stage.name.startswith('sbg-relay-') or stage.is_symlink():raise ValueError('NOT_MANAGED')
    managed=(ROOT/'standby-managed').exists()
    if not managed and (ROOT.exists() or APP.exists() or CORE.exists() or any((UNITS/(s+'.service')).exists() for s in SERVICES) or any((UNITS/name).exists() for name in ['sbgateway-relay-cert-renew.service','sbgateway-relay-cert-renew.timer'])):
        raise ValueError('NOT_MANAGED')
    config=json.loads((stage/'config.json').read_text())
    verify=copy.deepcopy(config)
    for inbound in verify['inbounds']:
        tls=inbound.get('tls',{})
        if 'certificate_path' in tls:tls['certificate_path']=str(stage/'live.crt')
        if 'key_path' in tls:tls['key_path']=str(stage/'live.key')
    (stage/'check.json').write_text(json.dumps(verify));os.chmod(stage/'check.json',0o600)
    if run([str(stage/'sing-box'),'check','-c',str(stage/'check.json')],check=False).returncode:raise ValueError('INVALID_CONFIG')
    import sys
    sys.path.insert(0,str(stage))
    from firewall import provision
    provision(json.loads((stage/'state.json').read_text()))
    managed_units=[*SERVICES,'sbgateway-relay-cert-renew.timer']
    was_active={s:run(['systemctl','is-active','--quiet',s],check=False).returncode==0 for s in managed_units}
    was_enabled={s:run(['systemctl','is-enabled','--quiet',s],check=False).returncode==0 for s in managed_units}
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(ROOT,0o700)
    backup=ROOT/'backups'/('standby-deploy-'+time.strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3))
    backup.mkdir(mode=0o700,parents=True)
    destinations={APP/name:stage/name for name in ASSETS}
    destinations.update({ROOT/name:stage/name for name in PRIVATE if (stage/name).exists()})
    destinations[CORE]=stage/'sing-box'
    previous={}
    units={UNITS/'sbgateway-relay-managed.service':CORE_UNIT,UNITS/'sbgateway-relay-manager.service':PANEL_UNIT}
    units[UNITS/'sbgateway-relay-cert-renew.service']='[Unit]\nDescription=Renew active standby certificate\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /opt/sbgateway-relay-manager/renew_standby.py\n'
    units[UNITS/'sbgateway-relay-cert-renew.timer']='[Unit]\nDescription=Check standby certificate daily\n[Timer]\nOnCalendar=daily\nRandomizedDelaySec=1h\nPersistent=true\n[Install]\nWantedBy=timers.target\n'
    for i,path in enumerate([*destinations,*units,ROOT/'standby-managed']):
        saved=backup/str(i)
        if path.exists():shutil.copy2(path,saved);previous[path]=saved
        else:previous[path]=None
    try:
        if managed:
            for service in reversed(managed_units):run(['systemctl','stop',service])
        held=[]
        try:
            checks=[(socket.SOCK_STREAM,18443)]
            checks += [(socket.SOCK_DGRAM if n['type'] in ['hysteria2','tuic'] else socket.SOCK_STREAM,n['listen_port']) for n in config['inbounds']]
            for kind,port in checks:
                sock=socket.socket(socket.AF_INET6,kind);held.append(sock)
                sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                sock.bind(('::',port))
                if kind==socket.SOCK_STREAM:sock.listen(1)
        except OSError:raise ValueError('PORT_CONFLICT')
        finally:
            for sock in held:sock.close()
        for path,source in destinations.items():
            path.parent.mkdir(parents=True,exist_ok=True)
            tmp=path.with_name(path.name+'.standby-new')
            shutil.copyfile(source,tmp)
            os.chmod(tmp,0o755 if path==CORE else 0o600 if path.parent==ROOT else 0o644)
            os.replace(tmp,path)
        for path,content in units.items():path.write_text(content);os.chmod(path,0o644)
        (ROOT/'standby-managed').write_text('managed standby; original sing-box.service is separate\n')
        os.chmod(ROOT/'standby-managed',0o600)
        run(['systemctl','daemon-reload'])
        for service in managed_units:run(['systemctl','enable',service]);run(['systemctl','start',service])
        time.sleep(1)
        for service in managed_units:run(['systemctl','is-active','--quiet',service])
        print('READY')
    except Exception as error:
        for service in reversed(managed_units):run(['systemctl','stop',service],check=False)
        for path,saved in previous.items():
            if saved:shutil.copy2(saved,path)
            else:path.unlink(missing_ok=True)
        run(['systemctl','daemon-reload'],check=False)
        for service in managed_units:
            run(['systemctl','enable' if was_enabled[service] else 'disable',service],check=False)
            if was_active[service]:run(['systemctl','start',service],check=False)
        if not managed:
            (ROOT/'standby-managed').write_text('incomplete standby deployment; safe to retry\n')
            os.chmod(ROOT/'standby-managed',0o600)
        if isinstance(error,ValueError):raise
        raise ValueError('DEPLOY_ROLLED_BACK')

    # Keep a bounded history of this deployer's own rollback directories only.
    history_root=ROOT/'backups'
    history=sorted(path for path in history_root.glob('standby-deploy-*')
                   if path.is_dir() and not path.is_symlink() and path.resolve().parent==history_root.resolve())
    for old in history[:-5]:
        try:shutil.rmtree(old)
        except OSError:pass

if __name__=='__main__':
    try:
        import fcntl
        with open('/run/sbgateway-relay-standby.lock','w') as deploy_lock:
            try:fcntl.flock(deploy_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError('备用服务器已有部署任务，请稍后重试')
            main(Path(sys.argv[1]))
    except Exception as error:
        print(str(error) if isinstance(error,ValueError) else 'DEPLOY_ROLLED_BACK',file=sys.stderr)
        sys.exit(1)
