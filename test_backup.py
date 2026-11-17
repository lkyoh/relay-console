import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch,Mock
import backup

class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.state={'server_ip':'8.8.8.8','public_host':'us.example.com','nodes':[{'id':'a','port':32001,'name':'A'}]}
        self.m=types.SimpleNamespace(ROOT=self.root,LOCK=threading.RLock(),SERVICE='test',
            load=lambda:copy.deepcopy(self.state),atomic=self.atomic,build=lambda state:{'inbounds':[{'type':'vless','listen_port':n['port'],'tag':n['id']}] for n in state['nodes']})
        self.manager=backup.BackupManager(self.m)
    def tearDown(self):self.tmp.cleanup()
    @staticmethod
    def atomic(path,value):path.write_text(value)
    def add(self,**changes):
        value={'host':'1.1.1.1','credential':'private-password','auth':'password','auto_sync':True};value.update(changes)
        return self.manager.save_server(value)['id']
    def wait(self):
        deadline=time.monotonic()+3
        while self.manager.job['running'] and time.monotonic()<deadline:time.sleep(.01)
        self.assertFalse(self.manager.job['running'])
    def test_encrypted_credentials_and_no_secret_in_public_response(self):
        identity=self.add();self.manager.save_dns({'zone_id':'a'*32,'token':'private-token'})
        raw=(self.root/'servers.enc').read_text()
        self.assertNotIn('private-password',raw);self.assertNotIn('private-token',raw)
        public=self.manager.public();self.assertNotIn('private-password',str(public));self.assertNotIn('private-token',str(public))
        self.assertTrue(public['servers'][0]['has_credential']);self.assertTrue(public['dns']['has_token'])
        self.manager.save_server({'id':identity,'host':'1.1.1.1','credential':'','auth':'password'})
        self.assertEqual(self.manager.read()['servers'][0]['credential'],'private-password')
    def test_self_private_address_and_bad_ports_rejected(self):
        for change in [{'host':'8.8.8.8'},{'host':'127.0.0.1'},{'host':'10.0.0.1'},{'host':'example.com'},{'port':0},{'port':True}]:
            with self.assertRaises(ValueError):self.add(**change)
    def test_changing_host_needs_new_credentials_and_drops_pin(self):
        identity=self.add();self.manager.update(identity,fingerprint='old')
        with self.assertRaises(ValueError):self.manager.save_server({'id':identity,'host':'9.9.9.9','credential':''})
        self.manager.save_server({'id':identity,'host':'9.9.9.9','credential':'new'})
        self.assertNotIn('fingerprint',self.manager.read()['servers'][0])
    def test_job_prevents_inventory_and_dns_edits(self):
        identity=self.add();self.manager.job={'running':True}
        for call in [lambda:self.manager.save_server({'id':identity,'host':'1.1.1.1','credential':''}),lambda:self.manager.remove(identity),lambda:self.manager.save_dns({'zone_id':'a'*32,'token':'t'}),lambda:self.manager.start('check',identity)]:
            with self.assertRaises(ValueError):call()
    def test_dns_requires_single_dns_only_ipv4(self):
        dns={'token':'t','zone_id':'a'*32}
        for records in [[],[{'type':'A','proxied':True}],[{'type':'A'},{'type':'AAAA'}],[{'type':'A'},{'type':'A'}]]:
            with patch.object(self.manager,'cf',return_value=records):
                with self.assertRaises(ValueError):self.manager.dns_record(dns,self.state)
        with patch.object(self.manager,'cf',return_value=[{'type':'A','id':'r','content':'8.8.8.8','proxied':False}]):
            self.assertEqual(self.manager.dns_record(dns,self.state)['id'],'r')
    def test_switch_preflight_failure_never_writes_dns(self):
        identity=self.add();self.manager.save_dns({'zone_id':'a'*32,'token':'t'})
        with patch.object(self.manager,'dns_record',return_value={'id':'r'}),patch.object(self.manager,'check',side_effect=ValueError('过期')),patch.object(self.manager,'cf') as cloudflare:
            self.manager.start('switch',identity);self.wait()
            cloudflare.assert_not_called();self.assertFalse(self.manager.job['ok'])
    def test_switch_uses_patch_content_only_and_records_target(self):
        identity=self.add();self.manager.save_dns({'zone_id':'a'*32,'token':'t'})
        with patch.object(self.manager,'dns_record',return_value={'id':'r'}),patch.object(self.manager,'check',return_value={}),patch.object(self.manager,'mark_target'),patch.object(self.manager,'cf',return_value={'content':'1.1.1.1'}) as cloudflare:
            self.manager.start('switch',identity);self.wait()
            self.assertTrue(self.manager.job['ok'])
            self.assertEqual(cloudflare.call_args.args[2],{'content':'1.1.1.1','ttl':60,'proxied':False})
            self.assertEqual(self.manager.read()['dns']['active_ip'],'1.1.1.1')
    def test_config_change_during_switch_prevents_dns_write(self):
        identity=self.add();self.manager.save_dns({'zone_id':'a'*32,'token':'t'})
        with patch.object(self.manager,'dns_record',return_value={'id':'r'}),patch.object(self.manager,'check',return_value={}),patch.object(self.manager,'mark_target'),patch.object(self.manager,'fingerprint',side_effect=['old','new']),patch.object(self.manager,'cf') as cloudflare:
            self.manager.start('switch',identity);self.wait()
            cloudflare.assert_not_called();self.assertFalse(self.manager.job['ok'])

    def test_cloudflare_transport_uses_fixed_api_and_patch(self):
        response=Mock();response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
        response.read.return_value=b'{"success":true,"result":{"content":"1.1.1.1"}}'
        with patch.object(backup.urllib.request,'urlopen',return_value=response) as call:
            backup.BackupManager.cf({'token':'private','zone_id':'a'*32},'zones/'+'a'*32+'/dns_records/record',{'content':'1.1.1.1','ttl':60,'proxied':False})
        request=call.call_args.args[0]
        self.assertEqual(request.method,'PATCH')
        self.assertTrue(request.full_url.startswith('https://api.cloudflare.com/client/v4/'))
        self.assertEqual(json.loads(request.data)['ttl'],60)

    def test_pinned_ssh_host_change_is_rejected(self):
        import paramiko
        identity=self.add();item=self.manager.read()['servers'][0];item['fingerprint']='SHA256:wrong'
        fake=Mock();policy=[]
        fake.set_missing_host_key_policy.side_effect=lambda value:policy.append(value)
        key=Mock();key.asbytes.return_value=b'new-key'
        fake.connect.side_effect=lambda **kwargs:policy[0].missing_host_key(fake,'1.1.1.1',key)
        with patch.object(paramiko,'SSHClient',return_value=fake):
            with self.assertRaisesRegex(ValueError,'指纹'):self.manager.connect(item)
        fake.close.assert_called_once()

class DeploymentTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('standby_deploy',Path(__file__).with_name('deploy_standby.py'))
        self.d=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.d)
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.stage=self.root/'sbg-relay-test';self.stage.mkdir()
        self.d.ROOT=self.root/'etc';self.d.APP=self.root/'app';self.d.CORE=self.root/'bin'/'sing-box';self.d.UNITS=self.root/'units';self.d.UNITS.mkdir()
        for name in self.d.ASSETS+self.d.PRIVATE+['sing-box']:(self.stage/name).write_text('{}')
        (self.stage/'config.json').write_text(json.dumps({'inbounds':[]}))
        self.calls=[]
    def tearDown(self):self.tmp.cleanup()
    def fake_run(self,args,check=True):
        self.calls.append(args)
        rc=1 if args[0]=='systemctl' and args[1] in ['is-active','is-enabled'] and not getattr(self,'started',False) else 0
        if args[0]=='systemctl' and args[1]=='start':self.started=True
        return types.SimpleNamespace(returncode=rc)
    def execute(self,run=None,socket_factory=None):
        actual_path=Path
        with patch.object(self.d,'Path',side_effect=lambda value:self.root if value=='/tmp' else actual_path(value)),patch.object(self.d.os,'geteuid',return_value=0,create=True),patch.object(self.d,'run',side_effect=run or self.fake_run),patch.object(self.d.socket,'socket',socket_factory or Mock()),patch.object(self.d.time,'sleep'):
            self.d.main(self.stage)
    def test_success_installs_isolated_services_and_private_files(self):
        self.execute()
        self.assertTrue((self.d.ROOT/'standby-managed').exists())
        self.assertTrue(self.d.CORE.exists())
        self.assertTrue(all('sing-box.service' not in args for args in self.calls))
        self.assertIn('RELAY_MANAGER_BIN', (self.d.UNITS/'sbgateway-relay-manager.service').read_text())
    def test_retention_only_prunes_its_own_history(self):
        self.d.ROOT.mkdir();(self.d.ROOT/'standby-managed').write_text('managed')
        history=self.d.ROOT/'backups';history.mkdir()
        for i in range(6):(history/f'standby-deploy-{i:03d}').mkdir()
        (history/'manual-backup').mkdir()
        self.execute()
        self.assertEqual(len(list(history.glob('standby-deploy-*'))),5)
        self.assertTrue((history/'manual-backup').exists())

    def test_unknown_existing_installation_is_not_touched(self):
        self.d.ROOT.mkdir();(self.d.ROOT/'keep').write_text('original')
        with self.assertRaisesRegex(ValueError,'NOT_MANAGED'):self.execute()
        self.assertEqual((self.d.ROOT/'keep').read_text(),'original')
    def test_port_conflict_leaves_retryable_owned_marker(self):
        sockets=Mock();sockets.return_value.bind.side_effect=OSError('occupied')
        with self.assertRaisesRegex(ValueError,'PORT_CONFLICT'):self.execute(socket_factory=sockets)
        self.assertTrue((self.d.ROOT/'standby-managed').exists())
        self.assertFalse((self.d.ROOT/'config.json').exists())
    def test_failed_update_restores_old_state_config_and_services(self):
        self.d.ROOT.mkdir();(self.d.ROOT/'standby-managed').write_text('previous')
        (self.d.ROOT/'config.json').write_text('old config');(self.d.ROOT/'state.json').write_text('old state')
        failed=[False]
        def fail_start(args,check=True):
            if args[:2]==['systemctl','start'] and not failed[0]:failed[0]=True;raise RuntimeError('failed')
            return self.fake_run(args,check)
        with self.assertRaisesRegex(ValueError,'DEPLOY_ROLLED_BACK'):self.execute(run=fail_start)
        self.assertEqual((self.d.ROOT/'config.json').read_text(),'old config')
        self.assertEqual((self.d.ROOT/'state.json').read_text(),'old state')
        self.assertEqual((self.d.ROOT/'standby-managed').read_text(),'previous')

class RenewalTests(unittest.TestCase):
    def test_inactive_standby_does_not_attempt_certificate_issuance(self):
        import renew_standby as renewal
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'state.json').write_text(json.dumps({'public_host':'us.example.com','server_ip':'1.1.1.1'}))
            with patch.object(renewal,'ROOT',root),patch.object(renewal.socket,'getaddrinfo',return_value=[(None,None,None,None,('8.8.8.8',0))]),patch.object(renewal.subprocess,'run') as command:
                renewal.main()
            command.assert_not_called()
    def test_renewal_uses_private_acme_directory_and_restarts_only_managed_services(self):
        import renew_standby as renewal
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'state.json').write_text(json.dumps({'public_host':'us.example.com','tls_domain':'us.example.com','server_ip':'1.1.1.1'}))
            (root/'live.crt').write_text('old');(root/'live.key').write_text('old')
            lineage=root/'acme/live/sbgateway-relay-standby';lineage.mkdir(parents=True)
            (lineage/'fullchain.pem').write_text('new cert');(lineage/'privkey.pem').write_text('new key')
            certificate=Mock();certificate.not_valid_after_utc.timestamp.return_value=time.time()+20*86400
            with patch.object(renewal,'ROOT',root),patch.object(renewal.socket,'getaddrinfo',return_value=[(None,None,None,None,('1.1.1.1',0))]),patch.object(renewal.x509,'load_pem_x509_certificate',return_value=certificate),patch.object(renewal.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)) as command:
                renewal.main()
            self.assertEqual((root/'live.crt').read_text(),'new cert')
            self.assertIn(str(root/'acme'),command.call_args_list[0].args[0])
            self.assertEqual(command.call_args.args[0],['systemctl','try-restart','sbgateway-relay-managed','sbgateway-relay-manager'])

if __name__=='__main__':unittest.main()
