import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import Mock,patch
import first_setup
import standalone_installer as installer
import build_installer
from test_manager import m

class SetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.value=installer.seed('8.8.8.8','bootstrap-password-long');self.value['firewall_managed']=False
        self.fake=types.SimpleNamespace(ROOT=self.root,LOCK=threading.RLock(),load=lambda:copy.deepcopy(self.value),
            build=m.build,available_protocols=m.available_protocols,host_valid=m.host_valid,parse_rows=m.parse_rows,
            add_nodes=m.add_nodes,atomic=self.atomic,HTTP_MODE=True)
        self.fake.apply=Mock(side_effect=self.apply)
        self.manager=first_setup.SetupManager(self.fake)
        self.payload={'domain':'relay.example.com','password':'permanent-password-long','protocols':['reality','hysteria2'],'sni':'www.apple.com','text':''}
        self.dns=patch.object(first_setup.socket,'getaddrinfo',return_value=[(None,None,None,None,('8.8.8.8',0))]);self.dns.start()
    def tearDown(self):self.dns.stop();self.tmp.cleanup()
    def atomic(self,path,value):path.write_text(value)
    def apply(self,state):self.value=copy.deepcopy(state)
    def wait(self):
        deadline=time.monotonic()+3
        while self.manager.job['running'] and time.monotonic()<deadline:time.sleep(.01)
        self.assertFalse(self.manager.job['running'])
    def test_existing_install_cannot_be_reinitialized(self):
        self.value.pop('initialized')
        with self.assertRaisesRegex(ValueError,'已完成'):self.manager.validate(self.payload)
        self.fake.apply.assert_not_called()
    def test_dns_ipv6_conflicts_and_missing_protocol_rejected(self):
        with patch.object(first_setup.socket,'getaddrinfo',return_value=[(None,None,None,None,('1.1.1.1',0))]):
            with self.assertRaises(ValueError):self.manager.validate(self.payload)
        for change in [{'protocols':[]},{'protocols':['unknown']},{'password':'short'},{'domain':'8.8.8.8'}]:
            with self.assertRaises(ValueError):self.manager.validate(self.payload|change)
    def test_validation_is_read_only_and_public_state_does_not_return_secrets(self):
        candidate,result=self.manager.validate(self.payload)
        self.assertTrue(result['ready']);self.assertFalse(self.value['initialized'])
        self.assertEqual(candidate['enabled_protocols'],['reality','hysteria2'])
        self.assertNotIn('password_hash',str(self.manager.public()));self.assertNotIn('private_key',str(self.manager.public()))
    def test_success_switches_to_https_and_generates_valid_empty_config(self):
        (self.root/'runtime.env').write_text('RELAY_MANAGER_HTTP=1\n')
        with patch.object(self.manager,'issue_certificate'),patch.object(first_setup.threading,'Timer') as timer:
            self.manager.start(self.payload);self.wait()
            self.assertTrue(self.manager.job['ok']);self.assertTrue(self.value['initialized'])
            self.assertEqual((self.root/'runtime.env').read_text(),'RELAY_MANAGER_HTTP=0\n')
            timer.assert_called_once()
            self.assertEqual(m.build(self.value)['outbounds'],[{'type':'direct','tag':'idle'}])
    def test_certificate_failure_keeps_bootstrap_access_and_state(self):
        with patch.object(self.manager,'issue_certificate',side_effect=ValueError('证书失败')):
            self.manager.start(self.payload);self.wait()
        self.assertFalse(self.manager.job['ok']);self.assertFalse(self.value['initialized']);self.fake.apply.assert_not_called()
    def test_failure_after_applying_rolls_back_state_and_environment(self):
        (self.root/'runtime.env').write_text('RELAY_MANAGER_HTTP=1\n')
        def write(path,value):
            if value=='RELAY_MANAGER_HTTP=0\n':raise OSError('disk error')
            self.atomic(path,value)
        with patch.object(self.manager,'issue_certificate'),patch.object(self.fake,'atomic',side_effect=write):
            self.manager.start(self.payload);self.wait()
        self.assertFalse(self.value['initialized']);self.assertFalse(self.manager.job['ok'])
        self.assertEqual(self.fake.apply.call_count,2)
        self.assertEqual((self.root/'runtime.env').read_text(),'RELAY_MANAGER_HTTP=1\n')
    def test_ip_mode_without_domain_dns_or_certificate(self):
        payload=self.payload|{'mode':'ip','domain':'','protocols':['reality','shadowsocks']}
        with patch.object(first_setup.socket,'getaddrinfo',side_effect=AssertionError('DNS must not run')),patch.object(self.manager,'issue_certificate') as cert,patch.object(first_setup.threading,'Timer'):
            self.manager.start(payload);self.wait()
        self.assertTrue(self.manager.job['ok']);cert.assert_not_called()
        self.assertEqual(self.value['public_host'],'8.8.8.8');self.assertEqual(self.value['entry_domain'],'')
        self.assertEqual(self.manager.job['url'],'')
        self.assertEqual((self.root/'runtime.env').read_text(),'RELAY_MANAGER_HTTP=1\n')
        self.assertEqual(m.build(self.value)['inbounds'],[])
    def test_ip_mode_rejects_certificate_protocols_and_invalid_mode(self):
        for protocol in ['trojan','hysteria2','tuic']:
            with self.assertRaisesRegex(ValueError,'IP 模式'):
                self.manager.validate(self.payload|{'mode':'ip','domain':'','protocols':[protocol]})
        with self.assertRaisesRegex(ValueError,'入口模式'):
            self.manager.validate(self.payload|{'mode':'bad'})
    def test_ip_mode_ss_only_with_landing_generates_real_inbound(self):
        with patch.object(m.socket,'socket'):
            candidate,_=self.manager.validate(self.payload|{'mode':'ip','domain':'','protocols':['shadowsocks'],'text':'1.1.1.1|1080|u|p'})
        self.assertEqual([i['type'] for i in m.build(candidate)['inbounds']],['shadowsocks'])
        self.assertIn('@8.8.8.8:',m.node_links(candidate,candidate['nodes'][0])['shadowsocks'])

    def test_only_selected_protocol_gets_inbound_and_link(self):
        state=installer.seed('8.8.8.8','long-bootstrap-password')
        state.update(enabled_protocols=['hysteria2'],extra_protocols_enabled=True,extra_protocols_ready=True,
                     tls_domain='relay.example.com',certificate_path='/crt',key_path='/key')
        with patch.object(m.socket,'socket'):
            state,_,_=m.add_nodes(state,'1.1.1.1|1080|u|p')
        config=m.build(state)
        self.assertEqual([n['type'] for n in config['inbounds']],['hysteria2'])
        self.assertEqual(list(m.node_links(state,state['nodes'][0])),['hysteria2'])

class InstallerTests(unittest.TestCase):
    def test_seed_contains_new_identities_and_no_shared_credentials(self):
        a=installer.seed('8.8.8.8','some-password-long');b=installer.seed('8.8.8.8','some-password-long')
        self.assertNotEqual(a['subscription_token'],b['subscription_token'])
        self.assertNotEqual(a['inbound_template']['tls']['reality']['private_key'],b['inbound_template']['tls']['reality']['private_key'])
        self.assertEqual(a['nodes'],[]);self.assertFalse(a['initialized'])
    def test_bbr_supported_is_verified_and_persisted(self):
        values={'net.ipv4.tcp_congestion_control':'cubic','net.core.default_qdisc':'fq_codel','net.ipv4.tcp_available_congestion_control':'reno cubic bbr'}
        def run(args,**kwargs):
            if args[1]=='-n':return types.SimpleNamespace(returncode=0,stdout=values[args[2]])
            key,value=args[2].split('=',1);values[key]=value;return types.SimpleNamespace(returncode=0,stdout='')
        with tempfile.TemporaryDirectory() as tmp,patch.object(installer.subprocess,'run',side_effect=run):
            path=Path(tmp)/'bbr.conf';result=installer.enable_bbr(path)
            self.assertIn('已开启',result);self.assertEqual(values['net.ipv4.tcp_congestion_control'],'bbr')
            self.assertIn('net.core.default_qdisc=fq',path.read_text());self.assertIn('cubic',path.read_text())
    def test_bbr_persist_failure_restores_parameters(self):
        values={'net.ipv4.tcp_congestion_control':'cubic','net.core.default_qdisc':'fq_codel','net.ipv4.tcp_available_congestion_control':'reno cubic bbr'}
        def run(args,**kwargs):
            if args[1]=='-n':return types.SimpleNamespace(returncode=0,stdout=values[args[2]])
            key,value=args[2].split('=',1);values[key]=value;return types.SimpleNamespace(returncode=0,stdout='')
        with tempfile.TemporaryDirectory() as tmp,patch.object(installer.subprocess,'run',side_effect=run):
            self.assertIn('已尝试恢复',installer.enable_bbr(Path(tmp)/'missing'/'bbr.conf'))
            self.assertEqual(values['net.ipv4.tcp_congestion_control'],'cubic');self.assertEqual(values['net.core.default_qdisc'],'fq_codel')
    def test_bbr_existing_file_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(installer.subprocess,'run') as run:
            path=Path(tmp)/'bbr.conf';path.write_text('original')
            installer.enable_bbr(path);self.assertEqual(path.read_text(),'original');run.assert_not_called()

    def test_network_tuning_raises_low_values_and_keeps_higher_values(self):
        values={'net.core.somaxconn':8192,'net.ipv4.tcp_max_syn_backlog':128}
        def run(args,**kwargs):
            if args[1]=='-n':return types.SimpleNamespace(returncode=0,stdout=str(values[args[2]]))
            key,value=args[2].split('=',1);values[key]=int(value);return types.SimpleNamespace(returncode=0,stdout='')
        with tempfile.TemporaryDirectory() as tmp,patch.object(installer.subprocess,'run',side_effect=run):
            path=Path(tmp)/'network.conf';result=installer.tune_network(path)
            self.assertIn('已验证',result);self.assertEqual(values,{'net.core.somaxconn':8192,'net.ipv4.tcp_max_syn_backlog':4096})
            self.assertIn('128',path.read_text());self.assertIn('net.core.somaxconn=8192',path.read_text())
    def test_network_tuning_write_failure_rolls_back(self):
        values={'net.core.somaxconn':128,'net.ipv4.tcp_max_syn_backlog':128}
        def run(args,**kwargs):
            if args[1]=='-n':return types.SimpleNamespace(returncode=0,stdout=str(values[args[2]]))
            key,value=args[2].split('=',1);values[key]=int(value);return types.SimpleNamespace(returncode=0,stdout='')
        with tempfile.TemporaryDirectory() as tmp,patch.object(installer.subprocess,'run',side_effect=run):
            self.assertIn('已恢复',installer.tune_network(Path(tmp)/'missing'/'network.conf'))
            self.assertEqual(list(values.values()),[128,128])
    def test_network_tuning_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(installer.subprocess,'run') as run:
            path=Path(tmp)/'network.conf';path.write_text('existing');installer.tune_network(path)
            self.assertEqual(path.read_text(),'existing');run.assert_not_called()

    def test_existing_directory_is_rejected_before_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(installer,'ROOT',Path(tmp)):
                with self.assertRaisesRegex(ValueError,'不会覆盖'):installer.preflight()
    def test_binary_hash_mismatch_is_rejected(self):
        response=Mock();response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False);response.read.return_value=b'corrupted'
        with patch.object(installer.urllib.request,'urlopen',return_value=response):
            with self.assertRaisesRegex(ValueError,'校验失败'):installer.binary('amd64')
    def test_portable_payload_allowlist_and_file_hashes(self):
        import base64,io,tarfile,re
        script=build_installer.build()
        encoded=re.search('encoded="([A-Za-z0-9+/=]+)"',script).group(1)
        with tarfile.open(fileobj=io.BytesIO(base64.b64decode(encoded))) as archive:
            names=archive.getnames();self.assertEqual(set(names),set(build_installer.FILES)|{'manifest.json'})
            self.assertTrue(all(Path(name).name==name for name in names))
            self.assertFalse(any(name in names for name in ['state.json','servers.enc','servers.key','panel.key','traffic.json']))
            manifest=json.load(archive.extractfile('manifest.json'))
            for name,digest in manifest.items():self.assertEqual(hashlib.sha256(archive.extractfile(name).read()).hexdigest(),digest)

if __name__=='__main__':unittest.main()
