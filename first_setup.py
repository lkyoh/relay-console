"""One-time web initialization for a fresh standalone installation."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import secrets
import socket
import subprocess
import threading
import time

class SetupManager:
    def __init__(self,manager):
        self.m=manager;self.lock=threading.Lock();self.job={'running':False}
    def state(self):
        with self.m.LOCK:return copy.deepcopy(self.m.load())
    def public(self):
        state=self.state()
        with self.lock:job=copy.deepcopy(self.job)
        return {'required':state.get('initialized') is False,'server_ip':state['server_ip'],
                'domain':state.get('entry_domain',''),'mode':'domain' if state.get('entry_domain') else 'ip','protocols':self.m.available_protocols(state),
                'sni':state['client_tls'].get('server_name','www.apple.com'),'nodes':len(state['nodes']),
                'panel_port':state.get('panel_port',18443),'job':job}
    def validate(self,data):
        state=self.state()
        if state.get('initialized') is not False:raise ValueError('当前服务器已完成初始化，不能重复初始化')
        domain=str(data.get('domain','')).strip().lower().rstrip('.')
        mode=data.get('mode','domain' if domain else 'ip')
        if mode not in ['ip','domain']:raise ValueError('入口模式无效')
        if mode=='domain':
            if not self.m.host_valid(domain):raise ValueError('请输入有效的入口域名')
            try:ipaddress.ip_address(domain)
            except ValueError:pass
            else:raise ValueError('域名模式需要域名，请选择 IP 模式')
            try:addresses={v[4][0] for v in socket.getaddrinfo(domain,None)}
            except socket.gaierror:addresses=set()
            if addresses!={state['server_ip']}:raise ValueError('域名需要仅解析到 '+state['server_ip']+'，请检查 A、AAAA 和代理状态')
        else:domain=''
        protocols=data.get('protocols')
        if not isinstance(protocols,list) or not protocols or any(p not in ['reality','hysteria2','tuic','trojan','shadowsocks'] for p in protocols):
            raise ValueError('请选择至少一种支持的协议')
        protocols=list(dict.fromkeys(protocols))
        if mode=='ip' and any(p not in ['reality','shadowsocks'] for p in protocols):raise ValueError('IP 模式仅支持 VLESS Reality 和 Shadowsocks 2022；其他协议请选择域名模式')
        password=str(data.get('password',''))
        if not 14<=len(password)<=200:raise ValueError('管理员密码需为 14～200 位')
        sni=str(data.get('sni','www.apple.com')).strip().lower()
        if 'reality' in protocols and not self.m.host_valid(sni):raise ValueError('Reality 握手域名无效')
        text=str(data.get('text','')).strip()
        rows=self.m.parse_rows(text) if text else []
        candidate=copy.deepcopy(state)
        candidate.update(entry_domain=domain,public_host=domain or state['server_ip'],tls_domain=domain,
            certificate_path=str(self.m.ROOT/'live.crt'),key_path=str(self.m.ROOT/'live.key'),
            enabled_protocols=protocols,extra_protocols_enabled=any(p!='reality' for p in protocols),
            extra_protocols_ready=True,allow_empty_nodes=True,initialized=True)
        candidate['client_tls']['server_name']=sni
        candidate['inbound_template']['tls']['server_name']=sni
        candidate['inbound_template']['tls']['reality']['handshake']={'server':sni,'server_port':443}
        if text:candidate,_,_=self.m.add_nodes(candidate,text)
        candidate['password_salt']=secrets.token_hex(16)
        candidate['password_hash']=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(candidate['password_salt']),250000).hex()
        return candidate,{'ready':True,'domain':domain,'protocols':protocols,'nodes':len(rows),'server_ip':state['server_ip']}
    def issue_certificate(self,domain):
        result=subprocess.run(['certbot','certonly','--standalone','--non-interactive','--agree-tos',
            '--register-unsafely-without-email','--keep-until-expiring','--preferred-challenges','http',
            '--config-dir',str(self.m.ROOT/'acme'),'--work-dir',str(self.m.ROOT/'acme-work'),
            '--logs-dir',str(self.m.ROOT/'acme-log'),'--cert-name','sbgateway-relay-standby','-d',domain],
            capture_output=True,timeout=180)
        if result.returncode:raise ValueError('证书申请失败，请确认域名仅 DNS 解析，且公网 TCP 80 可达、未被其他服务占用')
        lineage=self.m.ROOT/'acme/live/sbgateway-relay-standby'
        for source,name in [('fullchain.pem','live.crt'),('privkey.pem','live.key')]:
            self.m.atomic(self.m.ROOT/name,(lineage/source).read_text())
    def restart_panel(self):
        subprocess.run(['systemctl','restart','sbgateway-relay-manager'],check=True,timeout=30)
    def start(self,data):
        candidate,summary=self.validate(data)
        with self.lock:
            if self.job['running']:raise ValueError('初始化正在进行')
            self.job={'running':True,'message':'正在申请 HTTPS 证书…' if candidate['entry_domain'] else '正在初始化 IP 入口…'}
        def worker():
            applied=False;previous=self.state()
            env_path=self.m.ROOT/'runtime.env';old_env=env_path.read_text() if env_path.exists() else None
            try:
                if candidate.get('firewall_managed'):
                    from firewall import provision
                    provision(candidate)
                if candidate['entry_domain']:self.issue_certificate(candidate['tls_domain'])
                with self.lock:self.job['message']='正在校验配置并启动服务…'
                with self.m.LOCK:
                    if self.m.load().get('initialized') is not False:raise ValueError('初始化状态已变化，请刷新')
                    self.m.apply(candidate);applied=True
                    self.m.atomic(env_path,'RELAY_MANAGER_HTTP='+('0' if candidate['entry_domain'] else '1')+'\n')
                (self.m.ROOT/'initial-access.txt').unlink(missing_ok=True)
                url=('https://'+candidate['tls_domain']+':'+str(candidate.get('panel_port',18443))+'/') if candidate['entry_domain'] else ''
                with self.lock:self.job={'running':False,'ok':True,'message':('初始化完成，请打开 HTTPS 面板并使用新密码登录' if url else 'IP 模式初始化完成，请继续通过当前 SSH 隧道地址使用新密码登录；无须域名'),'url':url}
                timer=threading.Timer(4,self.restart_panel);timer.daemon=True;timer.start()
            except Exception as error:
                if applied:
                    try:
                        with self.m.LOCK:self.m.apply(previous)
                        if old_env is not None:self.m.atomic(env_path,old_env)
                    except Exception:pass
                message=str(error) if isinstance(error,ValueError) else '初始化未完成，已尝试恢复初始配置，请检查网络和服务后重试'
                with self.lock:self.job={'running':False,'ok':False,'message':message}
        threading.Thread(target=worker,daemon=True).start()
        return {'ok':True}
