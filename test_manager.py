import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import threading
import urllib.request
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('manager', Path(__file__).with_name('server.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ProbeTests(unittest.TestCase):
    class Wire:
        def __init__(self, response): self.response=response; self.sent=[]
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def settimeout(self, value): pass
        def recv(self, size):
            part,self.response=self.response[:size],self.response[size:]
            return part
        def sendall(self, value): self.sent.append(value)

    def test_authenticated_socks_and_verified_https_request(self):
        wire=self.Wire(b'\x05\x02\x01\x00\x05\x00\x00\x01'+b'\x00'*6+b'HTTP/1.1 204 No Content\r\n')
        context=unittest.mock.Mock()
        context.wrap_socket.return_value=wire
        with patch.object(m.socket,'create_connection',return_value=wire), patch.object(m.ssl,'create_default_context',return_value=context):
            result=m.probe_landing({'server':'8.8.8.8','server_port':443,'username':'u','password':'p'})
        self.assertIsInstance(result['ms'],int)
        self.assertEqual(wire.sent[1],b'\x01\x01u\x01p')
        self.assertIn(b'www.gstatic.com',wire.sent[2])
        context.wrap_socket.assert_called_once_with(wire,server_hostname='www.gstatic.com')
        self.assertTrue(wire.sent[-1].startswith(b'HEAD /generate_204'))

    def test_authentication_failure_does_not_report_latency(self):
        wire=self.Wire(b'\x05\x02\x01\x01')
        with patch.object(m.socket,'create_connection',return_value=wire):
            result=m.probe_landing({'server':'8.8.8.8','server_port':443,'username':'u','password':'private'})
        self.assertIsNone(result['ms'])
        self.assertEqual(result['error'],'SOCKS5 认证失败')
        self.assertNotIn('private',str(result))

    def test_concurrent_batches_rejected(self):
        with patch.dict(m.LATENCY,{'running':True}):
            with self.assertRaises(ValueError): m.start_latency([])


class TLSConcurrencyTests(unittest.TestCase):
    def test_incomplete_tls_handshake_does_not_block_other_clients(self):
        import datetime
        import ipaddress
        import ssl
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
        now=datetime.datetime.now(datetime.timezone.utc)
        cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
              .not_valid_after(now+datetime.timedelta(days=1))
              .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
              .sign(key,hashes.SHA256()))
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            (root/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'cert.pem',root/'key.pem')
            http=m.SecureHTTPServer(('127.0.0.1',0),m.Handler,context)
            threading.Thread(target=http.serve_forever,daemon=True).start()
            stalled=m.socket.create_connection(('127.0.0.1',http.server_port),timeout=2)
            try:
                # Ensure the first client reaches its handshake worker before connecting client two.
                m.time.sleep(.05)
                trusted=ssl.create_default_context(cafile=str(root/'cert.pem'))
                with urllib.request.urlopen('https://127.0.0.1:%d/'%http.server_port,context=trusted,timeout=2) as response:
                    self.assertEqual(response.status,200)
                    response.read()
            finally:
                stalled.close();http.shutdown();http.server_close()


class ManagerTests(unittest.TestCase):
    def seed(self):
        return {'inbound_template': {'type': 'vless', 'tls': {'enabled': True}},
                'nodes': [{'id': 'a', 'uuid': 'u', 'port': 32001, 'name': 'A', 'enabled': True,
                           'outbound': {'type': 'socks', 'server': '8.8.8.8', 'server_port': 443,
                                        'username': 'u', 'password': 'p', 'detour': 'old'}}]}

    def test_credentials_and_invalid_rows(self):
        rows = m.parse_rows('socks5://u:p%40%3A%23@8.8.8.8:443#A\n1.1.1.1|1080|x|a:b|B')
        self.assertEqual(rows[0]['outbound']['password'], 'p@:#')
        self.assertEqual(rows[1]['outbound']['password'], 'a:b')
        for text in ['127.0.0.1|80', '8.8.8.8|0', '8.8.8.8|443|u', 'file:///etc/passwd']:
            with self.assertRaises(ValueError):
                m.parse_rows(text)

    def test_dedupe_and_existing_identity_stability(self):
        seed = self.seed()
        with patch.object(m.socket, 'socket'):
            state, added, skipped = m.add_nodes(seed, '8.8.8.8|443|u|p|duplicate\n1.1.1.1|443|u|p|new')
        self.assertEqual(skipped, 1)
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0]['port'], 32002)
        self.assertEqual(state['nodes'][0], seed['nodes'][0])
        self.assertEqual(len(seed['nodes']), 1)

    def test_automatic_names_per_ip_and_explicit_names_preserved(self):
        seed=self.seed()
        with patch.object(m.socket,'socket'):
            state,added,_=m.add_nodes(seed,'1.1.1.1|1080|a|b\n1.1.1.1|1080|c|d|\n1.1.1.1|1080|e|f|My node')
        self.assertEqual([n['name'] for n in added],['1.1.1.1-VLESS-Reality','1.1.1.1-VLESS-Reality-002','My node'])
        self.assertEqual([n['link_label'] for n in added],[n['name'] for n in added])
        self.assertEqual(m.automatic_name(state['nodes'],'1.1.1.1'),'1.1.1.1-VLESS-Reality-003')
        self.assertEqual(m.automatic_name(state['nodes'],'1.1.1.1',added[0]['id']),'1.1.1.1-VLESS-Reality')
        self.assertEqual(seed['nodes'][0]['name'],'A')

    def test_automatic_protocol_labels_and_frozen_links_after_landing_change(self):
        seed=self.seed();seed.update(public_host='us.example.com',client_tls={'reality':{'public_key':'public'}},extra_protocols_enabled=True,extra_protocols_ready=True,tls_domain='us.example.com')
        with patch.object(m.socket,'socket'):
            state,added,_=m.add_nodes(seed,'1.1.1.1|1080|a|b')
        node=added[0]
        names=m.display_names(node)
        self.assertEqual(names['hysteria2'],'1.1.1.1-Hysteria2')
        self.assertEqual(names['tuic'],'1.1.1.1-TUIC-v5')
        links=m.node_links(state,node)
        self.assertTrue(links['hysteria2'].endswith('#1.1.1.1-Hysteria2'))
        node['outbound']['server']='9.9.9.9';node['name']='9.9.9.9-VLESS-Reality'
        self.assertEqual(m.display_names(node)['hysteria2'],'9.9.9.9-Hysteria2')
        self.assertEqual(links,m.node_links(state,node))

    def test_name_only_update_does_not_restart_core(self):
        state=self.seed()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'state.json').write_text(json.dumps(state))
            (root/'config.json').write_text(json.dumps(m.build(state)))
            renamed=copy.deepcopy(state);renamed['nodes'][0]['name']='New name'
            ok=type('Result',(),{'returncode':0})()
            with patch.object(m,'ROOT',root),patch.object(m.subprocess,'run',return_value=ok) as commands:
                m.apply(renamed)
            self.assertEqual(len(commands.call_args_list),1)
            self.assertEqual(commands.call_args.args[0][1],'check')
            self.assertEqual(json.loads((root/'state.json').read_text())['nodes'][0]['name'],'New name')

    def test_allocator_skips_disabled_reserved_ports_after_bind_failure(self):
        seed=self.seed()
        other=copy.deepcopy(seed['nodes'][0]);other.update(id='b',port=32003,enabled=False)
        seed['nodes'].append(other)
        def bind(address):
            if address[1]==32002: raise OSError('occupied')
        with patch.object(m.socket,'socket') as factory:
            factory.return_value.bind.side_effect=bind
            state,added,_=m.add_nodes(seed,'1.1.1.1|1080')
        self.assertEqual(added[0]['port'],32004)
        self.assertEqual(len({n['port'] for n in state['nodes']}),len(state['nodes']))

    def test_allocator_checks_udp_ports_as_well_as_tcp(self):
        seed=self.seed();seed['extra_protocols_enabled']=True
        calls=[]
        def bind(address):
            calls.append(address[1])
            if address[1]==33002: raise OSError('udp occupied')
        with patch.object(m.socket,'socket') as factory:
            factory.return_value.bind.side_effect=bind
            _,added,_=m.add_nodes(seed,'1.1.1.1|1080')
        self.assertEqual(added[0]['port'],32003)
        self.assertIn(34003,calls)

    def test_socks_limits_are_bytes_and_domains_have_valid_labels(self):
        for value in ['8.8.8.8|1080|'+('中'*86)+'|p','8.8.8.8|1080|u|'+('x'*256),
                      '999.1.1.1|1080','bad..example.com|1080','-bad.example.com|1080']:
            with self.assertRaises(ValueError):m.parse_rows(value)
        self.assertEqual(len(m.parse_rows('proxy.example.com|1080')),1)

    def test_probe_worker_exception_is_terminal_and_does_not_stick_pending(self):
        seed=self.seed()
        with patch.object(m,'load',return_value=seed),patch.object(m,'probe_landing',side_effect=RuntimeError('private')),patch.dict(m.LATENCY,{'running':False,'results':{},'pending':[]}):
            m.start_latency(seed['nodes'])
            deadline=m.time.monotonic()+3
            while m.LATENCY['running'] and m.time.monotonic()<deadline:m.time.sleep(.01)
            self.assertFalse(m.LATENCY['running'])
            self.assertEqual(m.LATENCY['pending'],[])
            self.assertEqual(m.LATENCY['completed'],1)
            self.assertIsNone(m.LATENCY['results']['a']['ms'])
            self.assertNotIn('private',str(m.LATENCY))

    def test_every_inbound_routes_to_its_own_landing(self):
        state = self.seed()
        second = copy.deepcopy(state['nodes'][0])
        second.update(id='b', port=32002, uuid='v')
        state['nodes'].append(second)
        config = m.build(state)
        self.assertEqual(len(config['route']['rules']), 2)
        self.assertEqual(config['route']['rules'][1]['outbound'], 'out-b')
        self.assertTrue(all('detour' not in o for o in config['outbounds']))
        self.assertEqual(state['nodes'][0]['outbound']['detour'], 'old')

    def test_landing_changes_do_not_change_fixed_link(self):
        state = self.seed()
        state.update(public_host='us.masaki.cc.cd', client_tls={'reality': {'public_key': 'public'}})
        node = state['nodes'][0]
        node['link_label'] = node['outbound']['server']
        before = m.link(state, node)
        node['name'] = 'New display name'
        node['outbound'].update(server='1.1.1.1', server_port=1080, username='different', password='different')
        self.assertEqual(m.link(state, node), before)

    def test_protocols_share_landing_without_changing_reality_link(self):
        state = self.seed()
        state.update(public_host='us.masaki.cc.cd', client_tls={'reality': {'public_key': 'public'}},
                     tls_domain='us.masaki.cc.cd', certificate_path='/cert', key_path='/key')
        n = state['nodes'][0]
        n['link_label'] = n['outbound']['server']
        reality = m.link(state, n)
        m.init_extra(n)
        state['extra_protocols_enabled'] = True
        state['extra_protocols_ready'] = True
        config = m.build(state)
        self.assertEqual([i['type'] for i in config['inbounds']], ['vless', 'hysteria2', 'tuic'])
        self.assertEqual(len(config['outbounds']), 1)
        self.assertEqual(len(config['route']['rules'][0]['inbound']), 3)
        self.assertEqual(m.link(state, n), reality)
        before = m.node_links(state, n)
        n['outbound'].update(server='1.1.1.1', password='changed')
        self.assertEqual(m.node_links(state, n), before)
        self.assertNotIn('insecure', m.link(state, n, 'tuic'))
        self.assertIn('obfs=salamander', m.link(state, n, 'hysteria2'))
        state['extra_protocols_ready'] = False
        self.assertEqual(m.available_protocols(state), ['reality'])

    def test_udp_counters_share_existing_line_totals(self):
        traffic_spec = importlib.util.spec_from_file_location('traffic', Path(__file__).with_name('traffic.py'))
        traffic_module = importlib.util.module_from_spec(traffic_spec)
        traffic_spec.loader.exec_module(traffic_module)
        with tempfile.TemporaryDirectory() as tmp:
            t = traffic_module.Traffic(tmp, boot_id='boot')
            response = json.dumps({'nftables': [{'counter': {'name': 'u_a'}}, {'counter': {'name': 'd_a'}}]})
            with patch.object(t, 'nft', return_value=response) as mock:
                t.ensure([{'id': 'a', 'port': 32001, 'hy2_port': 33001, 'tuic_port': 34001}])
            rules = mock.call_args.kwargs['input']
            self.assertIn('udp dport { 33001, 34001 } counter name u_a', rules)
            self.assertIn('udp sport { 33001, 34001 } counter name d_a', rules)
            self.assertNotIn('add counter', rules)

    def test_edit_api_preserves_identity_and_blank_password(self):
        state = self.seed()
        state.update(public_host='107.173.82.21', client_tls={'reality': {'public_key': 'public'}})
        state['nodes'][0]['link_label'] = '8.8.8.8'
        before = m.link(state, state['nodes'][0])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'state.json').write_text(json.dumps(state))
            def save(candidate):
                (root / 'state.json').write_text(json.dumps(candidate))
            with patch.object(m, 'ROOT', root), patch.object(m, 'apply', side_effect=save), patch.dict(m.SESSIONS, {'test-session': {'csrf': 'test-csrf', 'expires': 9999999999}}):
                http = m.ThreadingHTTPServer(('127.0.0.1', 0), m.Handler)
                thread = threading.Thread(target=http.serve_forever, daemon=True)
                thread.start()
                try:
                    payload = {'id': 'a', 'name': '', 'server': '1.1.1.1', 'socks_port': 1080,
                               'username': 'new-user', 'password': ''}
                    request = urllib.request.Request('http://127.0.0.1:%d/api/edit' % http.server_port,
                        data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json',
                        'Cookie': 'relay_session=test-session', 'X-CSRF-Token': 'test-csrf'})
                    with patch.dict(m.LATENCY, {'results': {'a': {'ms':123}}}):
                        bad = dict(payload, server='127.0.0.1')
                        bad_request = urllib.request.Request('http://127.0.0.1:%d/api/edit' % http.server_port,
                            data=json.dumps(bad).encode(), headers={'Content-Type':'application/json',
                            'Cookie':'relay_session=test-session','X-CSRF-Token':'test-csrf'})
                        with self.assertRaises(urllib.error.HTTPError) as invalid:
                            urllib.request.urlopen(bad_request)
                        self.assertEqual(invalid.exception.code,400)
                        invalid.exception.close()
                        self.assertEqual(m.LATENCY['results']['a']['ms'],123)
                        response = json.load(urllib.request.urlopen(request))
                        self.assertNotIn('a',m.LATENCY['results'])
                    after = json.loads((root / 'state.json').read_text())
                    self.assertTrue(response['link_unchanged'])
                    self.assertEqual(before, m.link(after, after['nodes'][0]))
                    self.assertEqual(after['nodes'][0]['outbound']['password'], 'p')
                    self.assertEqual(after['nodes'][0]['outbound']['server'], '1.1.1.1')
                    self.assertEqual(after['nodes'][0]['name'], '1.1.1.1-VLESS-Reality')
                finally:
                    http.shutdown()
                    http.server_close()

    def test_traffic_survives_process_restart_and_kernel_counter_reset(self):
        traffic_spec = importlib.util.spec_from_file_location('traffic', Path(__file__).with_name('traffic.py'))
        traffic_module = importlib.util.module_from_spec(traffic_spec)
        traffic_spec.loader.exec_module(traffic_module)
        def counters(up, down):
            return json.dumps({'nftables': [{'counter': {'name': 'u_a', 'bytes': up}},
                                           {'counter': {'name': 'd_a', 'bytes': down}}]})
        with tempfile.TemporaryDirectory() as tmp:
            t = traffic_module.Traffic(tmp, boot_id='boot-a')
            with patch.object(t, 'nft', return_value=counters(100, 1000)):
                t.sample()
            t.flush()
            t2 = traffic_module.Traffic(tmp, boot_id='boot-a')
            with patch.object(t2, 'nft', return_value=counters(150, 1100)):
                t2.sample()
            self.assertEqual(t2.snapshot()['totals']['a'], {'upload': 150, 'download': 1100})
            with patch.object(t2, 'nft', return_value=counters(10, 20)):
                t2.sample()
            self.assertEqual(t2.snapshot()['totals']['a'], {'upload': 160, 'download': 1120})
            t2.flush()
            t3 = traffic_module.Traffic(tmp, boot_id='boot-b')
            with patch.object(t3, 'nft', return_value=counters(5, 10)):
                t3.sample()
            self.assertEqual(t3.snapshot()['totals']['a'], {'upload': 165, 'download': 1130})

    def test_invalid_candidate_never_overwrites_active_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ['state.json', 'config.json']:
                (root / name).write_text('original')
            result = type('Result', (), {'returncode': 1})()
            with patch.object(m, 'ROOT', root), patch.object(m.subprocess, 'run', return_value=result):
                with self.assertRaises(ValueError):
                    m.apply(self.seed())
            self.assertEqual((root / 'state.json').read_text(), 'original')
            self.assertEqual((root / 'config.json').read_text(), 'original')

    def test_retention_preserves_nested_deployment_backups(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);state=self.seed()
            (root/'state.json').write_text(json.dumps(state))
            (root/'config.json').write_text(json.dumps(m.build(state)))
            backup=root/'backups';backup.mkdir()
            protected=backup/'000-deployment';(protected/'candidate').mkdir(parents=True)
            (protected/'candidate'/'valuable.txt').write_text('keep')
            for i in range(35):
                snap=backup/f'20260101-000000-{i:06x}';snap.mkdir();(snap/'state.json').write_text('{}')
            result=type('Result',(),{'returncode':0})()
            with patch.object(m,'ROOT',root),patch.object(m.subprocess,'run',return_value=result):
                m.apply(state)
            self.assertEqual((protected/'candidate'/'valuable.txt').read_text(),'keep')
            self.assertEqual(len(list(backup.iterdir())),31)

    def test_default_link_uses_enabled_protocol_and_ipv6_authority(self):
        state=self.seed();node=state['nodes'][0];m.init_extra(node)
        state.update(extra_protocols_ready=True,extra_protocols_enabled=True,enabled_protocols=['hysteria2'],
                     public_host='2606:4700:4700::1111',tls_domain='relay.example.com')
        value=m.link(state,node)
        self.assertTrue(value.startswith('hysteria2://'))
        self.assertIn('@[2606:4700:4700::1111]:33001?',value)

    def test_restart_failure_restores_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ['state.json', 'config.json']:
                (root / name).write_text('original')
            result = type('Result', (), {'returncode': 0})()
            with patch.object(m, 'ROOT', root), patch.object(m.subprocess, 'run', side_effect=[result, RuntimeError(), result]):
                with self.assertRaises(ValueError):
                    m.apply(self.seed())
            self.assertEqual((root / 'state.json').read_text(), 'original')
            self.assertEqual((root / 'config.json').read_text(), 'original')


if __name__ == '__main__':
    unittest.main()
