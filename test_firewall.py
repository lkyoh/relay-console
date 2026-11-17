import unittest
from unittest.mock import patch
from types import SimpleNamespace
import firewall as f
class FirewallTests(unittest.TestCase):
 def test_exact_transport_ports_and_no_ip_management_exposure(self):
  state={'enabled_protocols':['reality','shadowsocks'],'nodes':[{'port':32001,'ss_port':36001}]}
  self.assertEqual(f.ports_for(state),[(32001,'tcp'),(36001,'tcp'),(36001,'udp')])
  state['entry_domain']='relay.example.com';self.assertIn((80,'tcp'),f.ports_for(state));self.assertIn((18443,'tcp'),f.ports_for(state))
 def test_ufw_adds_only_requested_ports_without_enable_or_flush(self):
  calls=[]
  def run(args):
   calls.append(args);return SimpleNamespace(returncode=0,stdout='Status: active' if args==['ufw','status'] else '')
  with patch.object(f.shutil,'which',side_effect=lambda b:b if b=='ufw' else None),patch.object(f,'run',side_effect=run):
   self.assertEqual(f.ensure([(33001,'udp')])['manager'],'ufw')
  self.assertEqual(calls,[['ufw','status'],['ufw','allow','33001/udp','comment','Relay Console']])
 def test_custom_nft_drop_is_not_silently_claimed_open(self):
  with patch.object(f.shutil,'which',side_effect=lambda b:b if b=='nft' else None),patch.object(f,'run',return_value=SimpleNamespace(returncode=0,stdout='{"policy":"drop"}')):
   with self.assertRaisesRegex(ValueError,'自定义 nftables'):f.ensure([(32001,'tcp')])
 def test_legacy_configuration_does_not_change_firewall(self):
  with patch.object(f,'ensure') as ensure:f.provision({});ensure.assert_not_called()
 def test_firewalld_runtime_and_persistent_without_reload(self):
  calls=[]
  def run(args):
   calls.append(args);return SimpleNamespace(returncode=0,stdout='running' if args==['firewall-cmd','--state'] else 'public\n  interfaces: eth0\n' if '--get-active-zones' in args else '')
  with patch.object(f.shutil,'which',side_effect=lambda b:b if b=='firewall-cmd' else None),patch.object(f,'run',side_effect=run):f.ensure([(32001,'tcp')])
  self.assertIn(['firewall-cmd','--zone=public','--add-port=32001/tcp'],calls)
  self.assertIn(['firewall-cmd','--zone=public','--permanent','--add-port=32001/tcp'],calls)
