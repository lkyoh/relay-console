"""Encrypted standby inventory, bounded background operations and Cloudflare DNS."""
import base64
import copy
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import socket
import threading
import time
import urllib.request
import urllib.error


class BackupManager:
    def __init__(self, manager):
        self.m = manager
        self.lock = threading.RLock()
        self.job = {'running': False}
        self.stop = threading.Event()

    def read(self):
        path = self.m.ROOT / 'servers.enc'
        if not path.exists():
            return {'servers': [], 'dns': {}}
        from cryptography.fernet import Fernet
        return json.loads(Fernet((self.m.ROOT/'servers.key').read_bytes()).decrypt(path.read_bytes()))

    def write(self, value):
        from cryptography.fernet import Fernet
        key = self.m.ROOT/'servers.key'
        if not key.exists():
            fd = os.open(key, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd,'wb') as f: f.write(Fernet.generate_key())
        self.m.atomic(self.m.ROOT/'servers.enc', Fernet(key.read_bytes()).encrypt(json.dumps(value).encode()).decode())

    def snapshot_state(self):
        with self.m.LOCK: return copy.deepcopy(self.m.load())

    def fingerprint(self, state):
        content = json.dumps(self.m.build(state), sort_keys=True).encode()
        for key in ['certificate_path','key_path']:
            if state.get(key): content += Path(state[key]).read_bytes()
        # Include panel assets so backups follow later panel upgrades too.
        for name in ['server.py','firewall.py','first_setup.py','backup.py','deploy_standby.py','renew_standby.py','traffic.py','app.js','app.css','index.html','qrcode.js','relay-panel-install.sh']:
            content += (Path(__file__).parent/name).read_bytes()
        return hashlib.sha256(content).hexdigest()

    def public(self):
        state = self.snapshot_state()
        wanted = self.fingerprint(state)
        with self.lock:
            settings = self.read()
            servers = []
            for item in settings['servers']:
                row = {k:v for k,v in item.items() if k not in ['credential','passphrase']}
                row['has_credential'] = bool(item.get('credential'))
                row['is_self'] = item['host'] == state['server_ip']
                row['in_sync'] = item.get('last_sync_fingerprint') == wanted
                servers.append(row)
            dns = settings.get('dns',{})
            return {'servers': servers, 'job': copy.deepcopy(self.job),
                    'current_ip':state['server_ip'],'domain':state['public_host'],
                    'origin_ip':state.get('primary_server_ip',state['server_ip']),
                    'dns':{k:v for k,v in dns.items() if k!='token'}|{'has_token':bool(dns.get('token'))}}

    def save_server(self, data):
        state = self.snapshot_state()
        host = str(data.get('host','')).strip()
        try:
            ip = ipaddress.ip_address(host)
            if ip.version != 4 or not ip.is_global: raise ValueError()
        except ValueError: raise ValueError('请填写备用服务器的公网 IPv4 地址')
        if host == state['server_ip']: raise ValueError('不能将当前服务器添加为备用')
        port = data.get('port',22)
        if isinstance(port,bool) or not re.fullmatch(r'\d{1,5}',str(port)) or not 1<=int(port)<=65535:
            raise ValueError('SSH 端口无效')
        auth = data.get('auth','password')
        if auth not in ['password','key']: raise ValueError('SSH 认证方式无效')
        username = str(data.get('username','root')).strip()
        if username != 'root': raise ValueError('一键部署需要 root 登录')
        name = str(data.get('name','')).strip() or '备用 · '+host
        credential = str(data.get('credential',''))
        if len(name)>100 or len(credential)>32768: raise ValueError('名称或凭据过长')
        with self.lock:
            if self.job.get('running'): raise ValueError('操作进行中，请稍后编辑服务器')
            settings=self.read()
            old=next((v for v in settings['servers'] if v['id']==data.get('id')),None)
            if data.get('id') and old is None: raise ValueError('服务器不存在')
            if any(v['host']==host and v!=old for v in settings['servers']): raise ValueError('该服务器已添加')
            same=bool(old and old['host']==host and old['port']==int(port) and old['auth']==auth)
            credential=credential or (old.get('credential','') if same else '')
            if not credential: raise ValueError('请填写 SSH 密码或私钥')
            if len(settings['servers'])>=10 and not old: raise ValueError('最多添加 10 台备用服务器')
            row=copy.deepcopy(old) if old else {'id':secrets.token_hex(8)}
            if not same:
                for k in ['fingerprint','last_sync','last_sync_fingerprint','health','checked_at']:
                    row.pop(k,None)
            row.update(name=name,host=host,port=int(port),username=username,auth=auth,credential=credential,
                       passphrase=str(data.get('passphrase','')) or (old.get('passphrase','') if same else ''),
                       auto_sync=data.get('auto_sync') is True)
            if old: settings['servers'][settings['servers'].index(old)]=row
            else: settings['servers'].append(row)
            self.write(settings)
        return {'ok':True,'id':row['id']}

    def save_dns(self,data):
        zone=str(data.get('zone_id','')).strip()
        if not re.fullmatch('[a-fA-F0-9]{32}',zone): raise ValueError('Cloudflare Zone ID 应为 32 位十六进制字符')
        token=str(data.get('token','')).strip()
        if len(token)>2048 or any(ord(c)<33 for c in token): raise ValueError('API Token 格式无效')
        with self.lock:
            if self.job.get('running'): raise ValueError('操作进行中，请稍后修改 DNS 配置')
            settings=self.read();old=settings.get('dns',{})
            token=token or (old.get('token','') if old.get('zone_id')==zone else '')
            if not token: raise ValueError('请填写 Cloudflare API Token')
            settings['dns']={'zone_id':zone,'token':token,**{k:v for k,v in old.items() if k in ['active_ip','switched_at']}}
            self.write(settings)
        return {'ok':True}

    def remove(self,server_id):
        with self.lock:
            if self.job.get('running'): raise ValueError('操作进行中，请稍后移除')
            settings=self.read()
            if not any(v['id']==server_id for v in settings['servers']): raise ValueError('服务器不存在')
            settings['servers']=[v for v in settings['servers'] if v['id']!=server_id]
            self.write(settings)
        return {'ok':True}

    def update(self,server_id,**changes):
        with self.lock:
            settings=self.read()
            row=next((v for v in settings['servers'] if v['id']==server_id),None)
            if row is None: raise ValueError('服务器已移除')
            row.update(changes);self.write(settings)

    def connect(self,item):
        import paramiko
        expected=item.get('fingerprint')
        class Pin(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self,client,hostname,key):
                actual='SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
                if expected and actual!=expected: raise ValueError('SSH 主机指纹已变化，请核实服务器后重新添加')
        client=paramiko.SSHClient();client.set_missing_host_key_policy(Pin())
        options=dict(hostname=item['host'],port=item['port'],username=item['username'],timeout=10,
                     banner_timeout=10,auth_timeout=10,look_for_keys=False,allow_agent=False)
        if item['auth']=='password': options['password']=item['credential']
        else:
            key=None
            for kind in [paramiko.Ed25519Key,paramiko.ECDSAKey,paramiko.RSAKey]:
                try: key=kind.from_private_key(io.StringIO(item['credential']),password=item.get('passphrase') or None);break
                except (paramiko.SSHException,ValueError): pass
            if key is None: raise ValueError('SSH 私钥格式或私钥口令不正确')
            options['pkey']=key
        try:
            client.connect(**options)
            key=client.get_transport().get_remote_server_key()
            actual='SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
            return client,actual
        except Exception:
            client.close();raise

    @staticmethod
    def run(client,command,timeout=30):
        _,out,err=client.exec_command(command,timeout=timeout)
        text=out.read().decode();error=err.read().decode()
        if out.channel.recv_exit_status():
            # Only our fixed diagnostic codes are exposed; never raw command output.
            known=['PORT_CONFLICT','ARCH_MISMATCH','NOT_MANAGED','MISSING_DEPENDENCY','NOT_ROOT','INVALID_CONFIG','DEPLOY_ROLLED_BACK']
            code=next((v for v in known if v in error or v in text),None)
            raise ValueError({'PORT_CONFLICT':'备用服务器的入口端口或面板端口被其他服务占用',
                'ARCH_MISMATCH':'备用服务器架构与主服务器不同，无法复制当前核心',
                'NOT_MANAGED':'目标已有未知配置或同名服务，未覆盖',
                'MISSING_DEPENDENCY':'目标需要 Python 3、systemd、nftables 和 python3-paramiko（可使用 Debian/Ubuntu）',
                'NOT_ROOT':'需要 root 权限','INVALID_CONFIG':'备用配置未通过核心校验',
                'DEPLOY_ROLLED_BACK':'备用部署失败，已尝试恢复原配置和服务'}.get(code,'备用服务器命令执行失败'))
        return text

    def check(self,item,state,require_synced=False):
        client,fingerprint=self.connect(item)
        try:
            info=json.loads(self.run(client,"python3 - <<'PY'\nimport json,platform,os,subprocess,pathlib\np=pathlib.Path('/etc/sbgateway-relay-manager')\nconfig=p/'config.json'\nprint(json.dumps({'arch':platform.machine(),'root':os.geteuid()==0,'managed':(p/'standby-managed').exists(),'active':subprocess.run(['systemctl','is-active','--quiet','sbgateway-relay-managed']).returncode==0,'config':json.loads(config.read_text()) if (p/'standby-managed').exists() and config.exists() else None}))\nPY"))
            if not info['root']: raise ValueError('需要 root 权限')
            if info['arch']!=platform.machine(): raise ValueError('备用服务器架构与主服务器不同')
            if require_synced:
                if not info['managed'] or not info['active'] or not info['config']:
                    raise ValueError('备用服务尚未部署或没有运行')
                expected=self.m.build(state)
                # Certificate paths differ across hosts; compare all routing and protocol identities.
                for config in [expected,info['config']]:
                    for inbound in config['inbounds']:
                        for field in ['certificate_path','key_path']: inbound.get('tls',{}).pop(field,None)
                if expected!=info['config']: raise ValueError('备用节点配置已过期，请先同步')
                if item.get('last_sync_fingerprint')!=self.fingerprint(state): raise ValueError('备用证书或面板版本已过期，请先同步')
                if 'reality' in self.m.available_protocols(state) and any(n.get('enabled',True) for n in state['nodes']):
                    with socket.create_connection((item['host'],next(n['port'] for n in state['nodes'] if n.get('enabled',True))),timeout=5): pass
            health='运行正常' if info['managed'] and info['active'] else 'SSH 正常 · 待部署'
            self.update(item['id'],fingerprint=fingerprint,health=health,checked_at=time.time(),last_error='')
            return {'fingerprint':fingerprint,'health':health,'arch':info['arch']}
        finally: client.close()

    def sync(self,item,state):
        client,fingerprint=self.connect(item)
        stage='/tmp/sbg-relay-'+secrets.token_hex(12)
        try:
            self.run(client,"test $(id -u) -eq 0 || { echo NOT_ROOT; exit 1; }; test $(uname -m) = "+shlex.quote(platform.machine())+" || { echo ARCH_MISMATCH; exit 1; }; command -v python3 >/dev/null && command -v systemctl >/dev/null || { echo MISSING_DEPENDENCY; exit 1; }")
            # Only official distribution packages; keep existing proxy services untouched.
            self.run(client,"if ! python3 -c 'import paramiko,cryptography' 2>/dev/null || ! command -v nft >/dev/null || ! command -v certbot >/dev/null; then command -v apt-get >/dev/null || { echo MISSING_DEPENDENCY; exit 1; }; DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y python3-paramiko nftables certbot || { echo MISSING_DEPENDENCY; exit 1; }; fi",timeout=180)
            sftp=client.open_sftp();sftp.mkdir(stage,mode=0o700)
            def put(name,content,mode=0o600):
                if isinstance(content,str):content=content.encode()
                with sftp.open(stage+'/'+name,'wb') as f:f.write(content)
                sftp.chmod(stage+'/'+name,mode)
            for name in ['server.py','firewall.py','first_setup.py','backup.py','deploy_standby.py','renew_standby.py','traffic.py','app.js','app.css','index.html','qrcode.js','relay-panel-install.sh']:
                put(name,(Path(__file__).parent/name).read_bytes(),0o644)
            put('sing-box',Path(self.m.BIN).read_bytes(),0o755)
            target=copy.deepcopy(state)
            target.update(server_ip=item['host'],primary_server_ip=state.get('primary_server_ip',state['server_ip']),
                          server_role='standby',certificate_path='/etc/sbgateway-relay-manager/live.crt',
                          key_path='/etc/sbgateway-relay-manager/live.key')
            put('state.json',json.dumps(target,ensure_ascii=False,indent=2))
            put('config.json',json.dumps(self.m.build(target),ensure_ascii=False,indent=2))
            for name,path in [('live.crt',state['certificate_path']),('live.key',state['key_path']),
                              ('panel.crt',self.m.ROOT/'panel.crt'),('panel.key',self.m.ROOT/'panel.key')]:
                put(name,Path(path).read_bytes())
            with self.lock:
                if (self.m.ROOT/'servers.enc').exists():
                    put('servers.enc',(self.m.ROOT/'servers.enc').read_bytes())
                    put('servers.key',(self.m.ROOT/'servers.key').read_bytes())
            self.run(client,'python3 '+stage+'/deploy_standby.py '+stage,timeout=120)
            self.update(item['id'],fingerprint=fingerprint,last_sync=time.time(),last_sync_fingerprint=self.fingerprint(state),
                        health='运行正常',checked_at=time.time(),last_error='')
            return {'health':'运行正常','nodes':len(state['nodes'])}
        finally:
            # Delete only our cryptographically unique staging directory.
            try:self.run(client,'rm -rf -- '+stage,timeout=10)
            except Exception:pass
            client.close()

    @staticmethod
    def cf(dns,path,body=None):
        request=urllib.request.Request('https://api.cloudflare.com/client/v4/'+path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization':'Bearer '+dns['token'],'Content-Type':'application/json'},
            method='PATCH' if body is not None else 'GET')
        try:
            with urllib.request.urlopen(request,timeout=15) as response: result=json.load(response)
        except urllib.error.HTTPError as error:
            error.close()
            raise ValueError('Cloudflare 拒绝请求，请检查 Zone ID 和 Token 的 DNS 编辑权限')
        except (OSError,ValueError):raise ValueError('Cloudflare 请求失败，请稍后重试')
        if not result.get('success'):raise ValueError('Cloudflare 操作失败，请检查权限')
        return result['result']

    def dns_record(self,dns,state):
        if not dns.get('token') or not dns.get('zone_id'):raise ValueError('请先保存 Cloudflare 配置')
        from urllib.parse import urlencode
        records=self.cf(dns,'zones/'+dns['zone_id']+'/dns_records?'+urlencode({'name':state['public_host'],'per_page':100}))
        ipv4=[r for r in records if r['type']=='A']
        if len(ipv4)!=1 or any(r['type'] in ['AAAA','CNAME'] for r in records):
            raise ValueError('入口域名需要恰好一条 A 记录，且不能同时存在 AAAA 或 CNAME')
        if ipv4[0].get('proxied'):raise ValueError('入口记录需要设为仅 DNS（灰云）')
        return ipv4[0]

    def mark_target(self,item,target):
        client,_=self.connect(item)
        try:
            sftp=client.open_sftp()
            with sftp.open('/etc/sbgateway-relay-manager/entry-role.json.new','w') as role:
                role.write(json.dumps({'active_ip':target}))
            sftp.chmod('/etc/sbgateway-relay-manager/entry-role.json.new',0o600)
            sftp.posix_rename('/etc/sbgateway-relay-manager/entry-role.json.new','/etc/sbgateway-relay-manager/entry-role.json')
        finally:client.close()

    def start(self,kind,server_id=None):
        if kind not in ['check','sync','dns-check','switch']:raise ValueError('未知操作')
        state=self.snapshot_state()
        with self.lock:
            if self.job.get('running'):raise ValueError('已有服务器操作正在进行')
            settings=self.read()
            item=next((v for v in settings['servers'] if v['id']==server_id),None)
            if kind in ['check','sync'] or kind=='switch' and server_id!='current':
                if item is None:raise ValueError('请选择已添加的备用服务器')
                if item['host']==state['server_ip']:raise ValueError('不能对当前服务器执行备用操作')
            self.job={'running':True,'kind':kind,'server_id':server_id,'started_at':time.time(),'message':'正在'+{'check':'检测连接','sync':'部署并同步','dns-check':'检查 Cloudflare','switch':'检查并切换 DNS'}[kind]}
        def worker():
            try:
                if kind=='check':result=self.check(item,state)
                elif kind=='sync':result=self.sync(item,state)
                else:
                    record=self.dns_record(settings['dns'],state)
                    if kind=='dns-check':result={'ip':record['content'],'domain':state['public_host']}
                    else:
                        target=state['server_ip'] if server_id=='current' else item['host']
                        if item:self.check(item,state,require_synced=True)
                        elif not subprocess_active(self.m.SERVICE):raise ValueError('当前代理服务未运行，未切换')
                        if item:self.mark_target(item,target)
                        # Serialize the final check and DNS update against concurrent node edits.
                        with self.m.LOCK:
                            if self.fingerprint(state)!=self.fingerprint(self.snapshot_state()):raise ValueError('配置在检查期间发生变化，请重试')
                            result=self.cf(settings['dns'],'zones/'+settings['dns']['zone_id']+'/dns_records/'+record['id'],
                                {'content':target,'ttl':60,'proxied':False})
                            if result.get('content')!=target:raise ValueError('Cloudflare 返回的地址不一致，请检查解析')
                            self.m.atomic(self.m.ROOT/'entry-role.json',json.dumps({'active_ip':target}))
                            with self.lock:
                                current=self.read();current['dns'].update(active_ip=target,switched_at=time.time());self.write(current)
                        result={'ip':target,'domain':state['public_host']}
                with self.lock:self.job.update(running=False,ok=True,result=result,message='操作完成',finished_at=time.time())
            except Exception as error:
                import paramiko
                message=str(error) if isinstance(error,ValueError) else ('SSH 认证失败' if isinstance(error,paramiko.AuthenticationException) else '连接或操作失败，请检查 SSH、网络及目标依赖')
                if item:
                    self.update(item['id'],last_error=message,checked_at=time.time(),health='操作失败')
                with self.lock:self.job.update(running=False,ok=False,message=message,finished_at=time.time())
        threading.Thread(target=worker,daemon=True).start()
        return {'ok':True}

    def start_auto_sync(self):
        def loop():
            while not self.stop.wait(60):
                try:
                    state=self.snapshot_state()
                    with self.lock:
                        if self.job.get('running'):continue
                        settings=self.read()
                    # Once DNS moves elsewhere this instance stops pushing its old state.
                    role_path=self.m.ROOT/'entry-role.json'
                    role=json.loads(role_path.read_text()) if role_path.exists() else {}
                    if role.get('active_ip',state['server_ip'])!=state['server_ip']:continue
                    addresses={v[4][0] for v in socket.getaddrinfo(state['public_host'],None,socket.AF_INET)}
                    if addresses!={state['server_ip']}:continue
                    wanted=self.fingerprint(state)
                    for item in settings['servers']:
                        if item['host']!=state['server_ip'] and item.get('auto_sync') and item.get('last_sync') and item.get('last_sync_fingerprint')!=wanted:
                            self.start('sync',item['id']);break
                except Exception:pass
        threading.Thread(target=loop,daemon=True).start()


def subprocess_active(service):
    import subprocess
    return subprocess.run(['systemctl','is-active','--quiet',service],timeout=5).returncode==0
