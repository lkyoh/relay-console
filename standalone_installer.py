"""Fresh-server installer. Refuses existing installations and unrelated service names."""
import argparse
import base64
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT=Path('/etc/sbgateway-relay-manager')
APP=Path('/opt/sbgateway-relay-manager')
CORE=Path('/opt/sbgateway-relay-managed/sing-box')
UNITS=Path('/etc/systemd/system')
VERSION='1.14.4'
HASHES={'amd64':'699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968',
        'arm64':'436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26'}
ASSETS=['server.py','firewall.py','first_setup.py','backup.py','deploy_standby.py','renew_standby.py','traffic.py','index.html','app.js','app.css','qrcode.js']
SERVICE_NAMES=['sbgateway-relay-managed.service','sbgateway-relay-manager.service','sbgateway-relay-cert-renew.service','sbgateway-relay-cert-renew.timer']

def run(args):return subprocess.run(args,check=True,capture_output=True,timeout=60)

def preflight():
    if ROOT.exists() or APP.exists() or CORE.exists() or any((UNITS/n).exists() for n in SERVICE_NAMES):
        raise ValueError('检测到已有面板或同名服务，安装已停止，不会覆盖。已有服务器请使用备份迁移或升级流程。')
    if sys.version_info < (3,10):raise ValueError('需要 Python 3.10+，建议 Ubuntu 22.04+ 或 Debian 12+')
    if platform.system()!='Linux' or platform.machine() not in ['x86_64','aarch64']:raise ValueError('支持 Debian/Ubuntu 的 amd64、arm64 服务器')
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        try:sock.bind(('0.0.0.0',18443))
        except OSError:raise ValueError('面板端口 18443 被占用，未修改现有服务')

def binary(arch):
    name=f'sing-box-{VERSION}-linux-{arch}.tar.gz'
    url=f'https://github.com/SagerNet/sing-box/releases/download/v{VERSION}/{name}'
    request=urllib.request.Request(url,headers={'User-Agent':'Relay-Panel-Installer'})
    with urllib.request.urlopen(request,timeout=90) as response:data=response.read(100*1024*1024)
    if hashlib.sha256(data).hexdigest()!=HASHES[arch]:raise ValueError('sing-box 下载校验失败，未安装')
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
        members=[m for m in archive.getmembers() if m.isfile() and m.name==f'sing-box-{VERSION}-linux-{arch}/sing-box']
        if len(members)!=1:raise ValueError('sing-box 安装包内容不正确')
        return archive.extractfile(members[0]).read()

def public_ip(value):
    if not value:
        with urllib.request.urlopen('https://api.ipify.org',timeout=10) as response:value=response.read(64).decode().strip()
    try:
        ip=ipaddress.ip_address(value)
        if ip.version!=4 or not ip.is_global:raise ValueError()
    except ValueError:raise ValueError('请通过 --server-ip 指定有效的公网 IPv4')
    return str(ip)

def seed(ip,password):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    private=x25519.X25519PrivateKey.generate()
    encode=lambda raw:base64.urlsafe_b64encode(raw).decode().rstrip('=')
    secret=encode(private.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()))
    public=encode(private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
    sid=secrets.token_hex(4);sni='www.apple.com';salt=secrets.token_hex(16)
    return {'initialized':False,'firewall_managed':True,'allow_empty_nodes':True,'server_ip':ip,'public_host':ip,'entry_domain':'',
        'panel_port':18443,'server_role':'primary','nodes':[],'enabled_protocols':['reality'],
        'subscription_token':secrets.token_urlsafe(32),'password_salt':salt,
        'password_hash':hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),250000).hex(),
        'inbound_template':{'type':'vless','tls':{'enabled':True,'server_name':sni,'reality':{'enabled':True,
            'handshake':{'server':sni,'server_port':443},'private_key':secret,'short_id':[sid]}}},
        'client_tls':{'enabled':True,'server_name':sni,'utls':{'enabled':True,'fingerprint':'chrome'},
                      'reality':{'enabled':True,'public_key':public,'short_id':sid}}}

def enable_bbr(path=Path('/etc/sysctl.d/99-relay-console-bbr.conf')):
    """Best effort on new installs; restore runtime settings if persistence fails."""
    old={};changed=False;created=False
    def command(args):
        result=subprocess.run(args,capture_output=True,text=True,timeout=15)
        if result.returncode:raise ValueError('内核不支持或当前环境不允许修改')
        return result.stdout.strip()
    try:
        if path.exists():return 'BBR：保留已有专用配置，跳过自动修改'
        old={key:command(['sysctl','-n',key]) for key in ['net.ipv4.tcp_congestion_control','net.core.default_qdisc']}
        available=command(['sysctl','-n','net.ipv4.tcp_available_congestion_control']).split()
        if 'bbr' not in available:
            command(['modprobe','tcp_bbr'])
            available=command(['sysctl','-n','net.ipv4.tcp_available_congestion_control']).split()
        if 'bbr' not in available:return 'BBR：内核未提供，已跳过；安装继续'
        changed=True
        command(['sysctl','-w','net.core.default_qdisc=fq'])
        command(['sysctl','-w','net.ipv4.tcp_congestion_control=bbr'])
        if command(['sysctl','-n','net.ipv4.tcp_congestion_control'])!='bbr':raise ValueError('BBR 验证失败')
        content='# Managed by Relay Console installer\n# Previous: '+json.dumps(old,sort_keys=True)+'\nnet.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n'
        # Exclusive create prevents overwriting a configuration created concurrently.
        with path.open('x') as out:
            created=True
            out.write(content)
        return 'BBR：已开启并写入重启持久配置（不重启网卡、不替换当前队列）'
    except Exception:
        if created:
            try:path.unlink()
            except OSError:pass
        if changed:
            for key,value in old.items():
                try:command(['sysctl','-w',key+'='+value])
                except Exception:pass
        return 'BBR：启用未完成，已尝试恢复原参数；安装继续，请检查内核权限'

def tune_network(path=Path('/etc/sysctl.d/99-relay-console-network.conf')):
    """Raise small accept/SYN queue limits; retain higher existing settings."""
    old={};changed=[];created=False
    def command(args):
        result=subprocess.run(args,capture_output=True,text=True,timeout=15)
        if result.returncode:raise ValueError('无法读取或修改内核参数')
        return result.stdout.strip()
    try:
        if path.exists():return '网络参数：保留已有专用配置，跳过自动修改'
        targets={}
        for key,floor in [('net.core.somaxconn',4096),('net.ipv4.tcp_max_syn_backlog',4096)]:
            old[key]=int(command(['sysctl','-n',key]))
            targets[key]=max(old[key],floor)
        for key,value in targets.items():
            if old[key]!=value:
                changed.append(key)
                command(['sysctl','-w',key+'='+str(value)])
            if int(command(['sysctl','-n',key]))!=value:raise ValueError('参数验证失败')
        content='# Managed by Relay Console installer\n# Previous: '+json.dumps(old,sort_keys=True)+'\n'+''.join(key+'='+str(value)+'\n' for key,value in targets.items())
        with path.open('x') as out:
            created=True
            out.write(content)
        return '网络参数：已验证并持久保存 '+json.dumps(targets,sort_keys=True)
    except Exception:
        if created:
            try:path.unlink()
            except OSError:pass
        failures=[]
        for key in reversed(changed):
            try:command(['sysctl','-w',key+'='+str(old[key])])
            except Exception:failures.append(key)
        return '网络参数：应用未完成；'+('原值恢复失败：'+','.join(failures) if failures else '已恢复本次修改')+'；安装继续'

def install(ip,domain,source,script=None,bbr=True,tuning=True):
    preflight()
    password=secrets.token_urlsafe(20)
    core=binary('amd64' if platform.machine()=='x86_64' else 'arm64')
    # Everything below is confined to namespaces checked absent by preflight.
    created_units=[]
    try:
        ROOT.mkdir(mode=0o700,parents=True);APP.mkdir(mode=0o755,parents=True);CORE.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        for name in ASSETS:shutil.copyfile(source/name,APP/name);os.chmod(APP/name,0o644)
        CORE.write_bytes(core);os.chmod(CORE,0o755)
        sys.path.insert(0,str(APP))
        import server
        server.ROOT=ROOT;server.BIN=str(CORE)
        state=seed(ip,password)
        from firewall import ensure
        firewall_status=ensure([(80,'tcp'),(18443,'tcp')] if domain else [])
        print('主机防火墙检查：'+firewall_status['manager']+'；云安全组需另外放行，脚本无法代为验证。')
        server.atomic(ROOT/'state.json',json.dumps(state,ensure_ascii=False,indent=2))
        server.atomic(ROOT/'config.json',json.dumps(server.build(state),ensure_ascii=False,indent=2))
        run([str(CORE),'check','-c',str(ROOT/'config.json')])
        run(['openssl','req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','365',
             '-keyout',str(ROOT/'panel.key'),'-out',str(ROOT/'panel.crt'),'-subj','/CN='+ip,'-addext','subjectAltName=IP:'+ip])
        os.chmod(ROOT/'panel.key',0o600);os.chmod(ROOT/'panel.crt',0o600)
        http=True
        if domain:
            from first_setup import SetupManager
            manager=SetupManager(server)
            # Validate using the generated temporary password; do not complete setup yet.
            candidate,_=manager.validate({'domain':domain,'password':password,'protocols':['reality']})
            manager.issue_certificate(candidate['tls_domain'])
            state.update(entry_domain=domain,public_host=domain,tls_domain=domain,
                certificate_path=str(ROOT/'live.crt'),key_path=str(ROOT/'live.key'))
            server.atomic(ROOT/'state.json',json.dumps(state,ensure_ascii=False,indent=2));http=False
        server.atomic(ROOT/'runtime.env','RELAY_MANAGER_HTTP='+('1' if http else '0')+'\n')
        from deploy_standby import CORE_UNIT,PANEL_UNIT
        panel=PANEL_UNIT.replace('ExecStart=','EnvironmentFile=-/etc/sbgateway-relay-manager/runtime.env\nExecStart=',1)
        units={SERVICE_NAMES[0]:CORE_UNIT,SERVICE_NAMES[1]:panel,
            SERVICE_NAMES[2]:'[Unit]\nDescription=Renew active relay certificate\n[Service]\nType=oneshot\nTimeoutStartSec=240\nExecStart=/usr/bin/python3 /opt/sbgateway-relay-manager/renew_standby.py\n',
            SERVICE_NAMES[3]:'[Unit]\nDescription=Check relay certificate daily\n[Timer]\nOnCalendar=daily\nRandomizedDelaySec=1h\nPersistent=true\n[Install]\nWantedBy=timers.target\n'}
        for name,content in units.items():(UNITS/name).write_text(content);os.chmod(UNITS/name,0o644);created_units.append(name)
        if script and script.is_file():shutil.copyfile(script,APP/'relay-panel-install.sh');os.chmod(APP/'relay-panel-install.sh',0o644)
        run(['systemctl','daemon-reload'])
        for service in [SERVICE_NAMES[0],SERVICE_NAMES[1],SERVICE_NAMES[3]]:run(['systemctl','enable','--now',service])
        access='管理密码：'+password+'\n'
        if http:
            access+='首次初始化通过 SSH 隧道访问（在你自己的电脑执行）：\nssh -L 18080:127.0.0.1:18443 root@'+ip+'\n浏览器打开：http://127.0.0.1:18080/\n'
        else:access+='管理地址：https://'+domain+':18443/\n'
        access+='首次登录后完成网页向导。可选择无域名 IP 模式（管理面板通过 SSH 隧道访问）；域名模式申请证书需要仅 DNS 解析及公网 TCP 80 可达。\n'
        server.atomic(ROOT/'initial-access.txt',access)
        print(tune_network() if tuning else '网络参数：已按 --no-tuning 跳过')
        print(enable_bbr() if bbr else 'BBR：已按 --no-bbr 跳过')
        print(access)
    except Exception:
        for name in created_units:
            subprocess.run(['systemctl','disable','--now',name],capture_output=True,timeout=30)
            (UNITS/name).unlink(missing_ok=True)
        subprocess.run(['systemctl','daemon-reload'],capture_output=True,timeout=30)
        # These exact directories/files were verified absent before this install.
        for path in [ROOT,APP]:
            if path.exists() and not path.is_symlink():shutil.rmtree(path)
        CORE.unlink(missing_ok=True)
        raise

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Relay 独立面板安装程序')
    parser.add_argument('--no-tuning',action='store_true',help='跳过全部网络参数及 BBR 配置');parser.add_argument('--no-bbr',action='store_true',help='保留现有拥塞控制参数，不自动启用 BBR');parser.add_argument('--domain',default='');parser.add_argument('--server-ip',default='');parser.add_argument('--check',action='store_true');parser.add_argument('--script',type=Path)
    args=parser.parse_args()
    if args.check:
        try:preflight();print('检查通过：命名空间和面板端口可用。未修改系统。')
        except Exception as error:sys.exit(str(error))
        sys.exit(0)
    if os.geteuid()!=0:sys.exit('请使用 root 或 sudo 运行')
    try:install(public_ip(args.server_ip),args.domain.strip().lower().rstrip('.'),Path(__file__).parent,args.script,bbr=not (args.no_bbr or args.no_tuning),tuning=not args.no_tuning)
    except Exception as error:sys.exit(str(error) if isinstance(error,ValueError) else '安装失败，已尝试清理本次安装；请检查网络和依赖后重试')
