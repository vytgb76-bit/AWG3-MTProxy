#!/usr/bin/env python3
"""Rollback tests use isolated temporary state and mock ALL destructive commands."""
import argparse
import contextlib
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
from unittest.mock import patch
import unittest

SPEC=importlib.util.spec_from_file_location('euag3ctl',str(Path(__file__).resolve().parents[1]/'euag3ctl.py'))
m=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)

class TestRollback(unittest.TestCase):
    @contextlib.contextmanager
    def fakepaths(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            state=root/'state'; ctl=root/'euag3ctl'; un=root/'uninstall'
            with patch.object(m,'STATE',state),patch.object(m,'CONFIG',state/'config.json'),\
                 patch.object(m,'BACKUP',state/'backup'),patch.object(m,'CTL',ctl),\
                 patch.object(m,'UNINSTALL',un),patch.object(m,'UNIT_FILES',[]):
                yield state,ctl,un

    def test_cleanup_removes_only_owned_state(self):
        with self.fakepaths() as (state,ctl,un):
            state.mkdir()
            (state/'config.json').write_text('''{"container":"amnezia-awg2","awg_if":"awg0","awg_addr":"10.66.44.1","awg_net":"10.66.44.0/24","mt_port":5443,"tunnel_port":5443,"ssh_port":22,"awg_udp_port":443,"moscow_ips":[],"bridge_if":"","bridge_ip":"","update_at":"04:25"}''')
            ctl.write_text('# EUAG3-MANAGED\n');un.write_text('# EUAG3-MANAGED\n')
            calls=[]
            with patch.object(m,'run',side_effect=lambda a,**kw: NS(returncode=0,stdout='',stderr='')),\
                 patch.object(m,'clean_container_rules',side_effect=lambda c:calls.append('docker')),\
                 patch.object(m,'clean_host_rules',side_effect=lambda c:calls.append('firewall')),\
                 patch.object(m,'restore_network',side_effect=lambda:calls.append('network')):
                m.cleanup()
            self.assertEqual(calls,['docker','firewall','network'])
            self.assertFalse(state.exists())
            self.assertFalse(ctl.exists())
            self.assertFalse(un.exists())

    def test_cleanup_refuses_to_claim_complete_on_error(self):
        with self.fakepaths() as (state,ctl,un):
            state.mkdir(); (state/'backup').mkdir()
            (state/'config.json').write_text('''{"container":"amnezia-awg2","awg_if":"awg0","awg_addr":"10.66.44.1","awg_net":"10.66.44.0/24","mt_port":5443,"tunnel_port":5443,"ssh_port":22,"awg_udp_port":443,"moscow_ips":[],"bridge_if":"","bridge_ip":"","update_at":"04:25"}''')
            with patch.object(m,'run',side_effect=lambda a,**kw: NS(returncode=0,stdout='',stderr='')),\
                 patch.object(m,'clean_container_rules',side_effect=RuntimeError('Docker offline')),\
                 patch.object(m,'clean_host_rules'),patch.object(m,'restore_network'):
                with self.assertRaisesRegex(RuntimeError,'Docker offline'):m.cleanup()
            self.assertTrue(state.exists())
            self.assertTrue((state/'backup').exists())

    def test_install_auto_rolls_back_if_apply_fails(self):
        with self.fakepaths() as (state,ctl,un):
            args=argparse.Namespace(**{x:None for x in ['container','awg_interface','awg_address','awg_cidr','mt_port','tunnel_port','ssh_port','awg_udp_port','bridge_ip','bridge_if','moscow_ips','update_at']},fix_ifupdown=False,dry_run=False)
            def fake_fetch(folder):
                (folder/'ru4.zone').write_text('192.0.2.0/24\n')
                (folder/'ru6.zone').write_text('2001:db8::/32\n')
                return folder/'ru4.zone',folder/'ru6.zone'
            calls=[]
            def docker_cip(c,*a,**kw):return NS(returncode=0,stdout='',stderr='')
            def fake_run(a,**kw):return NS(returncode=0,stdout='',stderr='')
            with patch.object(m,'need_tools'),patch.object(m,'detect_defaults',return_value=('10.66.44.1','10.66.44.0/24')),\
                 patch.object(m,'check_install',return_value={'docker_dev':'eth0','gateway':'172.30.50.1','docker_ip':'172.30.50.2','host_if':'amn0'}),\
                 patch.object(m,'cip',side_effect=docker_cip),patch.object(m,'ipt',side_effect=lambda *a,**k:NS(returncode=1,stdout='',stderr='')),\
                 patch.object(m,'ipset_exists',return_value=False),patch.object(m,'is_ifupdown_conflict',return_value=False),\
                 patch.object(m,'output',return_value=''),patch.object(m,'download_lists',side_effect=fake_fetch),\
                 patch.object(m,'run',side_effect=fake_run),patch.object(m,'update_sets'),\
                 patch.object(m,'ensure_port_guard'),patch.object(m,'ensure_geo'),\
                 patch.object(m,'apply',side_effect=RuntimeError('simulated NAT failure')),\
                 patch.object(m,'clean_container_rules',side_effect=lambda c:calls.append('docker undo')),\
                 patch.object(m,'clean_host_rules',side_effect=lambda c:calls.append('host undo')),\
                 patch.object(m,'restore_network'):
                with self.assertRaisesRegex(RuntimeError,'simulated NAT failure'):
                    m.install(args)
            self.assertFalse(state.exists(),'Failed install left transaction state')
            self.assertFalse(ctl.exists(),'Failed install left system binary')
            self.assertFalse(un.exists(),'Failed install left uninstall binary')
            self.assertEqual(calls,['host undo'], 'No Docker operations occurred before simulated failure')

if __name__=='__main__':unittest.main(verbosity=2)
