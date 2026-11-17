#!/usr/bin/env python3
"""Small authenticated manager for an isolated sing-box relay service."""
import base64
import copy
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
import uuid
import signal
import atexit
import concurrent.futures
import struct
import sys
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(os.environ.get('RELAY_MANAGER_ROOT', '/etc/sbgateway-relay-manager'))
BIN = os.environ.get('RELAY_MANAGER_BIN', '/etc/s-box/sing-box')
SERVICE = 'sbgateway-relay-managed'
LOCK = threading.RLock()
SESSIONS = {}
FAILURES = {}
TRAFFIC = None
BACKUPS = None
SETUP = None
HTTP_MODE = os.environ.get('RELAY_MANAGER_HTTP') == '1'



# Only server-side SOCKS egress is measured; no production core restart is needed.
LATENCY = {'running': False, 'results': {}, 'pending': [], 'completed': 0, 'total': 0}
LATENCY_LOCK = threading.Lock()

def probe_landing(outbound):
    started = time.monotonic()
    deadline = started + 12
    def receive(sock, count):
        value = b''
        while len(value) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            sock.settimeout(remaining)
            part = sock.recv(count - len(value))
            if not part:
                raise OSError('代理提前关闭连接')
            value += part
        return value
    try:
        with socket.create_connection((outbound['server'], outbound['server_port']), timeout=6) as sock:
            sock.settimeout(6)
            username = outbound.get('username', '').encode()
            password = outbound.get('password', '').encode()
            if len(username) > 255 or len(password) > 255:
                raise ValueError('认证信息过长')
            sock.sendall(b'\x05\x02\x00\x02' if username else b'\x05\x01\x00')
            version, method = receive(sock, 2)
            if version != 5 or method not in (0, 2):
                raise ValueError('SOCKS5 认证方式不支持')
            if method == 2:
                sock.sendall(b'\x01' + bytes([len(username)]) + username + bytes([len(password)]) + password)
                if receive(sock, 2) != b'\x01\x00':
                    raise ValueError('SOCKS5 认证失败')
            host = b'www.gstatic.com'
            sock.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host + struct.pack('!H', 443))
            reply = receive(sock, 4)
            if reply[0] != 5 or reply[1] != 0:
                raise ValueError('SOCKS5 无法连接测试网站')
            size = {1: 4, 4: 16}.get(reply[3])
            if reply[3] == 3:
                size = receive(sock, 1)[0]
            if size is None:
                raise ValueError('SOCKS5 响应无效')
            receive(sock, size + 2)
            sock.settimeout(max(.01, deadline-time.monotonic()))
            with ssl.create_default_context().wrap_socket(sock, server_hostname='www.gstatic.com') as tls:
                tls.sendall(b'HEAD /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n')
                response = b''
                while b'\r\n' not in response and len(response) < 1024:
                    response += receive(tls, 1)
                if not response.startswith((b'HTTP/1.1 204', b'HTTP/1.0 204')):
                    raise ValueError('测试网站响应异常')
        return {'ms': round((time.monotonic()-started)*1000), 'checked_at': time.time()}
    except Exception as error:
        message = str(error) if isinstance(error, ValueError) else ('测试超时' if isinstance(error, (TimeoutError, socket.timeout)) else '连接或 TLS 检查失败')
        return {'ms': None, 'error': message, 'checked_at': time.time()}

def start_latency(nodes):
    with LATENCY_LOCK:
        if LATENCY['running']:
            raise ValueError('已有延迟测试正在进行，请稍后重试')
        LATENCY.update(running=True, pending=[n['id'] for n in nodes], completed=0, total=len(nodes))
    originals = {n['id']: n for n in nodes}
    def complete(node_id, result):
        with LOCK:
            try:
                current = next((n for n in load()['nodes'] if n['id'] == node_id), None)
            except (OSError, ValueError):
                current = None
            with LATENCY_LOCK:
                if current and current['outbound'] == originals[node_id]['outbound']:
                    LATENCY['results'][node_id] = result
                if node_id in LATENCY['pending']:
                    LATENCY['pending'].remove(node_id)
                    LATENCY['completed'] += 1
    def worker():
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                jobs = {pool.submit(probe_landing, n['outbound']): n['id'] for n in nodes}
                for job in concurrent.futures.as_completed(jobs):
                    try:
                        result = job.result()
                    except Exception:
                        result = {'ms': None, 'error': '延迟测试异常，请重试', 'checked_at': time.time()}
                    complete(jobs[job], result)
        finally:
            with LATENCY_LOCK:
                unfinished = list(LATENCY['pending'])
            for node_id in unfinished:
                complete(node_id, {'ms': None, 'error': '测试未完成，请重试', 'checked_at': time.time()})
            with LATENCY_LOCK:
                LATENCY['running'] = False
    threading.Thread(target=worker, daemon=True).start()


def load():
    return json.loads((ROOT / 'state.json').read_text())


def atomic(path, data):
    tmp = Path(str(path) + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def build(state):
    ins, outs, rules = [], [], []
    protocols = available_protocols(state)
    for n in state['nodes']:
        if not n.get('enabled', True):
            continue
        inbound_tags = []
        if 'reality' in protocols:
            inbound = copy.deepcopy(state['inbound_template'])
            inbound.update(tag='in-' + n['id'], listen='::', listen_port=n['port'],
                           users=[{'uuid': n['uuid'], 'flow': 'xtls-rprx-vision'}])
            ins.append(inbound)
            inbound_tags.append(inbound['tag'])
        if state.get('extra_protocols_enabled'):
            tls = {'enabled': True, 'server_name': state['tls_domain'], 'alpn': ['h3'],
                   'certificate_path': state['certificate_path'], 'key_path': state['key_path']}
            for protocol in [p for p in ['hysteria2', 'tuic'] if p in protocols]:
                extra = {'type': protocol, 'tag': protocol + '-' + n['id'], 'listen': '::',
                         'listen_port': n['hy2_port' if protocol == 'hysteria2' else 'tuic_port'],
                         'tls': copy.deepcopy(tls)}
                if protocol == 'hysteria2':
                    extra.update(users=[{'name': n['id'], 'password': n['hy2_password']}],
                                 obfs={'type': 'salamander', 'password': n['hy2_obfs_password']},
                                 ignore_client_bandwidth=True)
                else:
                    extra.update(users=[{'name': n['id'], 'uuid': n['uuid'], 'password': n['tuic_password']}],
                                 congestion_control='cubic', zero_rtt_handshake=False)
                ins.append(extra)
                inbound_tags.append(extra['tag'])
        outbound = copy.deepcopy(n['outbound'])
        outbound.pop('detour', None)
        outbound['tag'] = 'out-' + n['id']
        outs.append(outbound)
        rules.append({'inbound': inbound_tags, 'action': 'route', 'outbound': outbound['tag']})
    if not outs:
        if not state.get('allow_empty_nodes'):
            raise ValueError('至少保留一条启用的线路')
        outs = [{'type':'direct','tag':'idle'}]
    return {'log': {'level': 'warn'}, 'inbounds': ins, 'outbounds': outs,
            'dns': {'servers': [{'type': 'udp', 'tag': 'resolver', 'server': '223.5.5.5'}]},
            'route': {'rules': rules, 'final': outs[0]['tag'], 'default_domain_resolver': 'resolver'}}


def available_protocols(state):
    possible = ['reality', 'hysteria2', 'tuic'] if state.get('extra_protocols_ready') else ['reality']
    selected = state.get('enabled_protocols', possible)
    return [p for p in possible if p in selected]


def node_links(state, node):
    return {p: link(state, node, p) for p in available_protocols(state)}


def init_extra(node):
    node.setdefault('hy2_port', node['port'] + 1000)
    node.setdefault('tuic_port', node['port'] + 2000)
    node.setdefault('hy2_password', secrets.token_urlsafe(24))
    node.setdefault('hy2_obfs_password', secrets.token_urlsafe(24))
    node.setdefault('tuic_password', secrets.token_urlsafe(24))


def link(state, node, protocol=None):
    protocol = protocol or available_protocols(state)[0]
    label = urllib.parse.quote(node.get('link_labels', {}).get(protocol, node.get('link_label', node['outbound']['server'])))
    entry_host = state['public_host']
    if ':' in entry_host and not entry_host.startswith('['):
        entry_host = '[' + entry_host + ']'
    if protocol in ['hysteria2', 'tuic']:
        if not state.get('extra_protocols_enabled'):
            raise ValueError('该协议尚未启用')
        q = {'sni': state['tls_domain'], 'alpn': 'h3'}
        if protocol == 'hysteria2':
            q.update(obfs='salamander', **{'obfs-password': node['hy2_obfs_password']})
            auth, port = urllib.parse.quote(node['hy2_password'], safe=''), node['hy2_port']
        else:
            q.update(congestion_control='cubic', udp_relay_mode='native')
            auth, port = node['uuid'] + ':' + urllib.parse.quote(node['tuic_password'], safe=''), node['tuic_port']
        return protocol + '://' + auth + '@' + entry_host + ':' + str(port) + '?' + urllib.parse.urlencode(q) + '#' + label
    if protocol != 'reality':
        raise ValueError('协议无效')
    t = state['client_tls']
    q = {'encryption': 'none', 'security': 'reality', 'type': 'tcp',
         'flow': 'xtls-rprx-vision', 'sni': t.get('server_name', ''),
         'fp': t.get('utls', {}).get('fingerprint', 'chrome'),
         'pbk': t['reality']['public_key'], 'sid': t['reality'].get('short_id', '')}
    return ('vless://' + node['uuid'] + '@' + entry_host + ':' + str(node['port'])
            + '?' + urllib.parse.urlencode(q) + '#' + label)


def apply(candidate):
    """Validate first; restore old files and service on any failure."""
    config = json.dumps(build(candidate), ensure_ascii=False, indent=2)
    pending = ROOT / 'candidate.json'
    atomic(pending, config)
    check = subprocess.run([BIN, 'check', '-c', str(pending)], capture_output=True, timeout=20)
    if check.returncode:
        pending.unlink(missing_ok=True)
        raise ValueError('配置校验未通过，未应用变更')
    paths = [ROOT / 'state.json', ROOT / 'config.json']
    previous = {p: p.read_text() for p in paths}
    try:
        needs_restart = json.loads(previous[paths[1]]) != json.loads(config)
    except ValueError:
        needs_restart = True
    backup = ROOT / 'backups' / (time.strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(3))
    backup.mkdir(mode=0o700, parents=True)
    for p, content in previous.items():
        atomic(backup / p.name, content)
    try:
        if TRAFFIC and needs_restart:
            TRAFFIC.ensure(candidate['nodes'])
        atomic(paths[1], config)
        atomic(paths[0], json.dumps(candidate, ensure_ascii=False, indent=2))
        if needs_restart:
            subprocess.run(['systemctl', 'restart', SERVICE], check=True, capture_output=True, timeout=20)
            time.sleep(.5)
            subprocess.run(['systemctl', 'is-active', '--quiet', SERVICE], check=True, timeout=5)
    except Exception:
        for p, content in previous.items():
            atomic(p, content)
        if needs_restart:
            subprocess.run(['systemctl', 'restart', SERVICE], capture_output=True, timeout=20)
        raise ValueError('应用失败，已恢复上一版配置')
    finally:
        pending.unlink(missing_ok=True)
    # Bound backup growth while retaining recent rollback points.
    # Only prune our own flat snapshots. Deployment backups may contain subdirectories.
    snapshots = sorted(p for p in (ROOT / 'backups').iterdir()
                       if re.fullmatch(r'\d{8}-\d{6}-[0-9a-f]{6}', p.name) and p.is_dir() and not p.is_symlink())
    for old in snapshots[:-30]:
        try:
            contents = list(old.iterdir())
            if any(p.is_dir() or p.is_symlink() for p in contents):
                continue
            for p in contents:
                p.unlink()
            old.rmdir()
        except OSError:
            # Retention is best effort and must not turn a successful apply into an error.
            pass


def host_valid(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_global
    except ValueError:
        if len(host) > 253 or '.' not in host or re.fullmatch(r'[0-9.]+', host):
            return False
        return all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                   for label in host.split('.'))


def parse_rows(text):
    result = []
    for i, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            if line.startswith(('socks5://', 'socks5h://')):
                u = urllib.parse.urlsplit(line)
                host, port = u.hostname, u.port
                user, pw = urllib.parse.unquote(u.username or ''), urllib.parse.unquote(u.password or '')
                name = urllib.parse.unquote(u.fragment).strip()
            else:
                parts = line.split('|') if '|' in line else line.split()
                if len(parts) == 1:
                    parts = line.split(':', 3)
                if len(parts) not in (2, 4, 5):
                    raise ValueError()
                host, port = parts[:2]
                user, pw = (parts[2:4] if len(parts) >= 4 else ('', ''))
                name = parts[4].strip() if len(parts) == 5 else ''
            port = int(port)
            if not host or not host_valid(host) or not 1 <= port <= 65535:
                raise ValueError()
            if any(len(v) > 1024 or any(ord(ch) < 32 for ch in v) for v in [user, pw, name]):
                raise ValueError()
            if len(user.encode()) > 255 or len(pw.encode()) > 255:
                raise ValueError()
            result.append({'name': name[:100], 'outbound': {'type': 'socks', 'version': '5',
                           'server': host, 'server_port': port, 'username': user, 'password': pw}})
        except Exception:
            raise ValueError('第 %d 行格式错误；请检查地址、端口和分隔符' % i)
    if not 1 <= len(result) <= 200:
        raise ValueError('每批请添加 1～200 条')
    return result


PROTOCOL_LABELS = {'reality':'VLESS-Reality','hysteria2':'Hysteria2','tuic':'TUIC-v5'}


def automatic_name(nodes, host, exclude_id=None):
    used = {n['name'] for n in nodes if n.get('id') != exclude_id}
    base = host+'-VLESS-Reality'
    name = base
    index = 2
    while name in used:
        name = f'{base}-{index:03d}'
        index += 1
    return name


def display_names(node):
    if not node.get('auto_name'):
        return {p:node['name'] for p in [*PROTOCOL_LABELS,'all']}
    host=node['outbound']['server']
    suffix=node['name'].removeprefix(host+'-VLESS-Reality')
    return {**{p:host+'-'+label+suffix for p,label in PROTOCOL_LABELS.items()},'all':host+'-多协议'+suffix}


def identity(n):
    o = n['outbound']
    return tuple(o.get(k, '') for k in ['server', 'server_port', 'username', 'password'])


def add_nodes(state, text):
    candidate = copy.deepcopy(state)
    seen = {identity(n) for n in candidate['nodes']}
    used = {n['port'] for n in candidate['nodes']}
    skipped = 0
    added = []
    for row in parse_rows(text):
        if identity(row) in seen:
            skipped += 1
            continue
        if len(candidate['nodes']) >= 500:
            raise ValueError('当前页面最多管理 500 条线路')
        port = 32001
        while port <= 32999:
            if port in used:
                port += 1
                continue
            bound = []
            try:
                checks = [(socket.SOCK_STREAM, port)]
                if state.get('extra_protocols_enabled'):
                    checks += [(socket.SOCK_DGRAM, port + 1000), (socket.SOCK_DGRAM, port + 2000)]
                for kind, listen_port in checks:
                    sock = socket.socket(socket.AF_INET6, kind)
                    bound.append(sock)
                    sock.bind(('::', listen_port))
                break
            except OSError:
                port += 1
            finally:
                for sock in bound:
                    sock.close()
        if port > 32999:
            raise ValueError('没有可用入口端口')
        row['auto_name'] = not bool(row['name'])
        row['name'] = row['name'] or automatic_name(candidate['nodes'], row['outbound']['server'])
        row.update(id=secrets.token_hex(8), uuid=str(uuid.uuid4()), port=port, enabled=True,
                   link_label=row['name'])
        if row['auto_name']:
            row['link_labels'] = {p:name for p,name in display_names(row).items() if p!='all'}
        if state.get('extra_protocols_enabled'):
            init_extra(row)
        candidate['nodes'].append(row)
        used.add(port)
        seen.add(identity(row))
        added.append(row)
    return candidate, added, skipped


class SecureHTTPServer(ThreadingHTTPServer):
    # Handshakes belong in connection workers, never in the accept loop.
    def __init__(self, address, handler, tls_context):
        self.tls_context = tls_context
        super().__init__(address, handler)

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(15)
            request = self.tls_context.wrap_socket(request, server_side=True)
        except (OSError, ssl.SSLError):
            request.close()
            return
        super().process_request_thread(request, client_address)


class Handler(BaseHTTPRequestHandler):
    server_version = 'RelayManager'

    def log_message(self, *args):
        pass  # Never log subscription tokens or proxy credentials.

    def send(self, code, body, content_type='application/json; charset=utf-8', headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def session(self):
        try:
            cookie = SimpleCookie(self.headers.get('Cookie', ''))
            token = cookie['relay_session'].value
            with LOCK:
                value = SESSIONS.get(token)
                if value and value['expires'] > time.time():
                    return value
        except Exception:
            pass
        return None

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path)
        if path.path == '/':
            return self.send(200, (Path(__file__).parent / 'index.html').read_bytes(), 'text/html; charset=utf-8')
        if path.path in ['/app.css', '/app.js', '/qrcode.js']:
            return self.send(200, (Path(__file__).parent / path.path[1:]).read_bytes(),
                             'text/css; charset=utf-8' if path.path.endswith('.css') else 'application/javascript; charset=utf-8')
        if path.path.startswith('/subscription/'):
            with LOCK:
                state = load()
                token = path.path.removeprefix('/subscription/')
                if not hmac.compare_digest(token, state['subscription_token']):
                    return self.send(404, {'error': '地址不存在'})
                protocol = urllib.parse.parse_qs(path.query).get('protocol', [available_protocols(state)[0]])[0]
                protocols = available_protocols(state) if protocol == 'all' else [protocol]
                if any(p not in available_protocols(state) for p in protocols):
                    return self.send(400, {'error': '该协议尚不可用'})
                lines = '\n'.join(link(state, n, p) for n in state['nodes'] if n.get('enabled', True) for p in protocols) + '\n'
            return self.send(200, base64.b64encode(lines.encode()), 'text/plain; charset=utf-8')
        session = self.session()
        if not session:
            return self.send(401, {'error': '请先登录'})
        if path.path == '/api/installer':
            package=Path(__file__).parent/'relay-panel-install.sh'
            if not package.exists():return self.send(404, {'error':'安装包暂不可用'})
            return self.send(200,package.read_bytes(),'application/octet-stream',{'Content-Disposition':'attachment; filename=relay-panel-install.sh'})
        if path.path == '/api/setup':
            if not SETUP:return self.send(503, {'error':'初始化服务未就绪'})
            return self.send(200,SETUP.public())
        if path.path == '/api/nodes':
            with LOCK:
                state = load()
                nodes = [{'id': n['id'], 'name': n['name'], 'display_names': display_names(n), 'server': n['outbound']['server'],
                          'socks_port': n['outbound']['server_port'], 'port': n['port'],
                          'enabled': n.get('enabled', True), 'link': link(state, n), 'links': node_links(state, n),
                          'ports': {p: n['port'] if p=='reality' else n['hy2_port'] if p=='hysteria2' else n['tuic_port'] for p in available_protocols(state)}}
                         for n in state['nodes']]
                active = subprocess.run(['systemctl', 'is-active', '--quiet', SERVICE], timeout=5).returncode == 0
                return self.send(200, {'nodes': nodes, 'csrf': session['csrf'], 'active': active,
                            'public_host': state['public_host'], 'entry_domain': state.get('entry_domain', ''),
                            'server_ip': state.get('server_ip', '107.173.82.21'),
                            'protocols': available_protocols(state), 'setup_required':state.get('initialized') is False,
                            'subscription_base': 'https://' + state['tls_domain'] + ':18443' if state.get('tls_domain') else '',
                            'subscription_path': '/subscription/' + state['subscription_token']})
        if path.path == '/api/servers':
            if not BACKUPS:
                return self.send(503, {'error':'服务器管理尚未初始化'})
            return self.send(200, BACKUPS.public())
        if path.path == '/api/latency':
            with LATENCY_LOCK:
                return self.send(200, copy.deepcopy(LATENCY))
        if path.path == '/api/traffic':
            result = TRAFFIC.snapshot() if TRAFFIC else {'available': False, 'error': '统计未初始化', 'rates': {}, 'totals': {}}
            try:
                result['service_active'] = subprocess.run(['systemctl', 'is-active', '--quiet', SERVICE], timeout=3).returncode == 0
            except Exception:
                result['service_active'] = False
            try:
                with open('/proc/meminfo') as f:
                    mem = {k: int(v.split()[0]) for k, v in (line.split(':', 1) for line in f)}
                result['system'] = {'load': os.getloadavg()[0], 'memory_total': mem['MemTotal'] * 1024,
                                    'memory_used': (mem['MemTotal'] - mem['MemAvailable']) * 1024,
                                    'uptime': int(float(Path('/proc/uptime').read_text().split()[0]))}
            except Exception:
                result['system'] = {}
            return self.send(200, result)
        if path.path == '/api/node':
            with LOCK:
                state = load()
                node_id = urllib.parse.parse_qs(path.query).get('id', [''])[0]
                node = next((n for n in state['nodes'] if n['id'] == node_id), None)
                if node is None:
                    return self.send(404, {'error': '线路不存在'})
                o = node['outbound']
                return self.send(200, {'id': node['id'], 'name': node['name'], 'auto_name':node.get('auto_name',False), 'server': o['server'],
                    'socks_port': o['server_port'], 'username': o.get('username', ''),
                    'has_password': bool(o.get('password')), 'entry_port': node['port'], 'link': link(state, node)})
        return self.send(404, {'error': '地址不存在'})

    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            if not 0 < length <= 262144 or not self.headers.get('Content-Type', '').startswith('application/json'):
                return self.send(400, {'error': '请求格式错误'})
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError('请求格式错误')
            if self.path == '/api/login':
                peer = self.client_address[0]
                with LOCK:
                    now = time.time()
                    FAILURES[peer] = [v for v in FAILURES.get(peer, []) if now - v < 600]
                    if len(FAILURES[peer]) >= 10:
                        return self.send(429, {'error': '尝试过多，请 10 分钟后重试'})
                    state = load()
                    value = hashlib.pbkdf2_hmac('sha256', str(data.get('password', '')).encode(), bytes.fromhex(state['password_salt']), 250000).hex()
                    if not hmac.compare_digest(value, state['password_hash']):
                        FAILURES[peer].append(now)
                        return self.send(401, {'error': '密码错误'})
                    FAILURES.pop(peer, None)
                    for key in list(SESSIONS):
                        if SESSIONS[key]['expires'] < now:
                            del SESSIONS[key]
                    token = secrets.token_urlsafe(32)
                    SESSIONS[token] = {'csrf': secrets.token_urlsafe(24), 'expires': now + 43200}
                return self.send(200, {'ok': True}, headers={'Set-Cookie': 'relay_session=' + token + '; Path=/; HttpOnly;'+('' if HTTP_MODE else ' Secure;')+' SameSite=Strict; Max-Age=43200'})
            session = self.session()
            if not session:
                return self.send(401, {'error': '请先登录'})
            if not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), session['csrf']):
                return self.send(403, {'error': '请刷新页面后重试'})
            if self.path == '/api/logout':
                cookie = SimpleCookie(self.headers.get('Cookie', ''))
                with LOCK:
                    SESSIONS.pop(cookie['relay_session'].value, None)
                return self.send(200, {'ok': True}, headers={'Set-Cookie': 'relay_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'})
            if self.path.startswith('/api/setup/'):
                if not SETUP:return self.send(503, {'error':'初始化服务未就绪'})
                if self.path=='/api/setup/validate':return self.send(200,SETUP.validate(data)[1])
                if self.path=='/api/setup/apply':return self.send(200,SETUP.start(data))
                raise ValueError('初始化操作不存在')
            with LOCK:
                if load().get('initialized') is False:raise ValueError('请先完成首次初始化')
            if self.path.startswith('/api/servers/'):
                if not BACKUPS:
                    return self.send(503, {'error':'服务器管理尚未初始化'})
                action=self.path.removeprefix('/api/servers/')
                if action=='save': result=BACKUPS.save_server(data)
                elif action=='remove': result=BACKUPS.remove(data.get('id'))
                elif action=='dns-save': result=BACKUPS.save_dns(data)
                else: result=BACKUPS.start(action,data.get('id'))
                return self.send(200,result)
            with LOCK:
                state = load()
                if self.path == '/api/latency/test':
                    ids = data.get('ids')
                    if not isinstance(ids, list) or not ids or any(not isinstance(v, str) for v in ids):
                        raise ValueError('请选择测试线路')
                    nodes = [copy.deepcopy(n) for n in state['nodes'] if n['id'] in ids]
                    if len(nodes) != len(set(ids)):
                        raise ValueError('线路不存在')
                    start_latency(nodes)
                    return self.send(200, {'ok': True, 'count': len(nodes)})
                if self.path in ['/api/preview', '/api/add']:
                    candidate, added, skipped = add_nodes(state, str(data.get('text', '')))
                    if self.path == '/api/add' and added:
                        apply(candidate)
                    return self.send(200, {'added': len(added), 'skipped': skipped, 'nodes': [
                        {'name': n['name'], 'server': n['outbound']['server'], 'port': n['port']} for n in added]})
                if self.path == '/api/toggle':
                    candidate = copy.deepcopy(state)
                    node = next((n for n in candidate['nodes'] if n['id'] == data.get('id')), None)
                    if node is None:
                        raise ValueError('线路不存在')
                    node['enabled'] = not node.get('enabled', True)
                    apply(candidate)
                    return self.send(200, {'ok': True})
                if self.path == '/api/edit':
                    candidate = copy.deepcopy(state)
                    node = next((n for n in candidate['nodes'] if n['id'] == data.get('id')), None)
                    if node is None:
                        raise ValueError('线路不存在')
                    node.setdefault('link_label', node['outbound']['server'])
                    before = link(candidate, node)
                    name = str(data.get('name', node['name'])).strip()
                    host = str(data.get('server', '')).strip()
                    port = int(data.get('socks_port', 0))
                    username = str(data.get('username', ''))
                    password = str(data.get('password', ''))
                    if len(name) > 100 or not host_valid(host) or not 1 <= port <= 65535:
                        raise ValueError('请检查线路名称、落地地址和端口')
                    if len(username.encode()) > 255 or len(password.encode()) > 255 or any(ord(c) < 32 for c in name + username + password):
                        raise ValueError('名称或凭据格式无效')
                    automatic = not name or node.get('auto_name',False) and name==node['name']
                    node['auto_name'] = automatic
                    node['name'] = automatic_name(candidate['nodes'],host,node['id']) if automatic else name
                    node['outbound'].update(server=host, server_port=port, username=username)
                    if password or data.get('clear_password') is True:
                        node['outbound']['password'] = password
                    if link(candidate, node) != before:
                        raise ValueError('入口身份校验失败，未保存')
                    apply(candidate)
                    if node['outbound'] != next(n for n in state['nodes'] if n['id'] == node['id'])['outbound']:
                        with LATENCY_LOCK:
                            LATENCY['results'].pop(node['id'], None)
                    return self.send(200, {'ok': True, 'link_unchanged': True})
                if self.path in ['/api/domain/check', '/api/domain/activate']:
                    domain = str(data.get('domain', '')).strip().lower().rstrip('.')
                    if not host_valid(domain):
                        raise ValueError('请输入有效域名')
                    try:
                        ipaddress.ip_address(domain)
                        raise ValueError('这里需要域名，不能填写 IP')
                    except ValueError as ex:
                        if str(ex) == '这里需要域名，不能填写 IP':
                            raise
                    try:
                        addresses = sorted({info[4][0] for info in socket.getaddrinfo(domain, None)})
                    except socket.gaierror:
                        addresses = []
                    expected = state.get('server_ip', '107.173.82.21')
                    ready = bool(addresses) and all(address == expected for address in addresses)
                    if self.path == '/api/domain/check':
                        return self.send(200, {'ready': ready, 'addresses': addresses, 'expected': expected})
                    if not ready:
                        raise ValueError('域名尚未仅解析到当前服务器；请检查 A、AAAA 和代理状态')
                    state['entry_domain'] = domain
                    state['public_host'] = domain
                    atomic(ROOT / 'state.json', json.dumps(state, ensure_ascii=False, indent=2))
                    return self.send(200, {'ok': True, 'public_host': domain})
                if self.path == '/api/password':
                    password = str(data.get('password', ''))
                    if not 14 <= len(password) <= 200:
                        raise ValueError('密码长度需为 14～200 位')
                    state['password_salt'] = secrets.token_hex(16)
                    state['password_hash'] = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(state['password_salt']), 250000).hex()
                    atomic(ROOT / 'state.json', json.dumps(state, ensure_ascii=False, indent=2))
                    SESSIONS.clear()
                    return self.send(200, {'ok': True})
            return self.send(404, {'error': '地址不存在'})
        except ValueError as ex:
            return self.send(400, {'error': str(ex)})
        except Exception:
            return self.send(500, {'error': '操作未完成，请检查服务状态后重试'})


if __name__ == '__main__':
    state = load()
    from first_setup import SetupManager
    SETUP = SetupManager(sys.modules[__name__])
    from backup import BackupManager
    BACKUPS = BackupManager(sys.modules[__name__])
    BACKUPS.start_auto_sync()
    from traffic import Traffic
    TRAFFIC = Traffic(ROOT)
    try:
        TRAFFIC.ensure(state['nodes'])
    except Exception:
        TRAFFIC.error = '入口计数器初始化失败'
    TRAFFIC.start()
    atexit.register(TRAFFIC.flush)
    def shutdown(signum, frame):
        TRAFFIC.stop.set()
        TRAFFIC.sample()
        TRAFFIC.flush()
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    if HTTP_MODE:
        server = ThreadingHTTPServer(('127.0.0.1', int(state.get('panel_port',18443))), Handler)
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(ROOT / 'panel.crt'), str(ROOT / 'panel.key'))
        if state.get('tls_domain') and state.get('certificate_path') and state.get('key_path'):
            public_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            public_context.minimum_version = ssl.TLSVersion.TLSv1_2
            public_context.load_cert_chain(state['certificate_path'], state['key_path'])
            def choose_certificate(sock, hostname, original_context):
                if hostname == state['tls_domain']:
                    sock.context = public_context
            context.set_servername_callback(choose_certificate)
        server = SecureHTTPServer(('0.0.0.0', int(state.get('panel_port',18443))), Handler, context)
    server.serve_forever()
