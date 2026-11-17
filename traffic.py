"""Per-entry network byte counters; independent of sing-box process lifetime."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time


class Traffic:
    def __init__(self, root, boot_id=None):
        self.root = Path(root)
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.available = False
        self.error = '正在初始化'
        self.last = {}
        self.rates = {}
        self.last_time = None
        self.sampled_at = None
        self.last_flush = time.monotonic()
        try:
            self.saved = json.loads((self.root / 'traffic.json').read_text())
        except (OSError, ValueError):
            self.saved = {'started_at': int(time.time()), 'totals': {}, 'raw': {}, 'boot_id': ''}
        self.boot_id = boot_id or Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        # Resume from durable raw offsets only within the same kernel lifetime.
        if self.saved.get('boot_id') == self.boot_id:
            self.last = self.saved.get('raw', {})

    def nft(self, *args, input=None):
        r = subprocess.run(['/usr/sbin/nft', *args], input=input, text=True, capture_output=True, timeout=8)
        if r.returncode:
            raise RuntimeError('入口计数器暂不可用')
        return r.stdout

    def ensure(self, nodes):
        with self.lock:
            try:
                self.nft('list', 'table', 'inet', 'sbg_relay_stats')
            except RuntimeError:
                self.nft('-f', '-', input='add table inet sbg_relay_stats\n'
                         'add chain inet sbg_relay_stats input { type filter hook input priority -10; policy accept; }\n'
                         'add chain inet sbg_relay_stats output { type filter hook output priority -10; policy accept; }\n')
            objects = json.loads(self.nft('-j', 'list', 'table', 'inet', 'sbg_relay_stats'))['nftables']
            names = {o['counter']['name'] for o in objects if 'counter' in o}
            comments = {o['rule'].get('comment') for o in objects if 'rule' in o}
            rules = []
            for n in nodes:
                if not re.fullmatch('[a-f0-9]{1,64}', n['id']):
                    raise ValueError('invalid node identity')
                port = int(n['port'])
                if not 1 <= port <= 65535:
                    raise ValueError('invalid node port')
                for prefix, chain, direction in [('u', 'input', 'dport'), ('d', 'output', 'sport')]:
                    name = prefix + '_' + n['id']
                    if name not in names:
                        rules.extend(['add counter inet sbg_relay_stats ' + name,
                                      'add rule inet sbg_relay_stats ' + chain + ' tcp ' + direction + ' ' + str(port) + ' counter name ' + name])
                    if n.get('hy2_port') and n.get('tuic_port'):
                        comment = 'extra-' + name
                        if comment not in comments:
                            ports = [int(n['hy2_port']), int(n['tuic_port'])]
                            if not all(1 <= p <= 65535 for p in ports):
                                raise ValueError('invalid extra port')
                            rules.append('add rule inet sbg_relay_stats ' + chain + ' udp ' + direction
                                         + ' { ' + ', '.join(str(p) for p in ports) + ' } counter name ' + name
                                         + ' comment "' + comment + '"')
            if rules:
                self.nft('-f', '-', input='\n'.join(rules) + '\n')

    def sample(self):
        with self.lock:
            try:
                objects = json.loads(self.nft('-j', 'list', 'table', 'inet', 'sbg_relay_stats'))['nftables']
                raw = {o['counter']['name']: o['counter']['bytes'] for o in objects if 'counter' in o}
                now = time.monotonic()
                dt = now - self.last_time if self.last_time is not None else None
                self.rates = {}
                for name, value in raw.items():
                    direction, node_id = name.split('_', 1)
                    key = 'upload' if direction == 'u' else 'download'
                    previous = self.last.get(name, 0)
                    delta = value - previous if value >= previous else value
                    totals = self.saved['totals'].setdefault(node_id, {'upload': 0, 'download': 0})
                    totals[key] += delta
                    self.rates.setdefault(node_id, {'upload': 0, 'download': 0})[key] = round(delta / dt) if dt else 0
                self.last = raw
                self.last_time = now
                self.sampled_at = int(time.time())
                self.available, self.error = True, ''
                if now - self.last_flush >= 10:
                    self.flush()
            except Exception:
                self.available, self.error = False, '入口计数器暂不可用'
                self.rates = {}

    def flush(self):
        with self.lock:
            self.saved.update(raw=self.last, boot_id=self.boot_id)
            path = self.root / 'traffic.json'
            tmp = path.with_suffix('.tmp')
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump(self.saved, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            self.last_flush = time.monotonic()

    def snapshot(self):
        with self.lock:
            return {'available': self.available, 'error': self.error, 'started_at': self.saved['started_at'],
                    'sampled_at': self.sampled_at, 'rates': copy.deepcopy(self.rates),
                    'totals': copy.deepcopy(self.saved['totals'])}

    def start(self):
        def loop():
            while not self.stop.wait(2):
                self.sample()
        self.sample()
        threading.Thread(target=loop, daemon=True).start()
