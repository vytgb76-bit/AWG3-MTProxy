#!/usr/bin/env python3
"""Independent regression cases for v6 bugs found during source audit.
All real I/O is contained in tempfile paths or fully mocked.
"""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
from unittest.mock import patch
import unittest

SPEC=importlib.util.spec_from_file_location('euag3v6',str(Path(__file__).resolve().parents[1]/'euag3ctl.py'))
m=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

CONF={"container":"amnezia-awg2","awg_if":"awg0","awg_addr":"10.66.44.1",
      "awg_net":"10.66.44.0/24","mt_port":5443,"tunnel_port":5443,
      "ssh_port":22,"awg_udp_port":443,"moscow_ips":[],"bridge_if":"",
      "bridge_ip":"","update_at":"04:25"}

class TestV6Regressions(unittest.TestCase):
    def test_existing_empty_ipsets_restore_from_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp)
            (state/'ru4.zone').write_text('192.0.2.0/24\n')
            (state/'ru6.zone').write_text('2001:db8::/32\n')
            with patch.object(m,'STATE',state),patch.object(m,'ipset_count',side_effect=[0,0,8664,2182]),\
                 patch.object(m,'update_sets') as upd,patch.object(m,'ensure_chain'),\
                 patch.object(m,'inject'),patch.object(m,'ensure_anchor'),patch.object(m,'append_rule'):
                m.ensure_geo(CONF)
            upd.assert_called_once_with(state/'ru4.zone',state/'ru6.zone')

    def test_existing_populated_sets_not_reloaded(self):
        with patch.object(m,'ipset_count',side_effect=[8664,2182]),\
             patch.object(m,'update_sets') as upd,patch.object(m,'ensure_chain'),\
             patch.object(m,'inject'),patch.object(m,'ensure_anchor'),patch.object(m,'append_rule'):
            m.ensure_geo(CONF)
        upd.assert_not_called()

    def test_ipset_terse_header_parser(self):
        result='Name: eg3_ru4\nType: hash:net\nHeader: family inet hashsize 1024\nNumber of entries: 8664\n'
        with patch.object(m,'run',return_value=NS(returncode=0,stdout=result)):
            self.assertEqual(m.ipset_count('eg3_ru4'),8664)

    def test_rollback_unmodified_interfaces_with_stale_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); state=root/'state'; backup=state/'backup'; backup.mkdir(parents=True)
            original=backup/'interfaces.original'; original.write_text('auto lo\n')
            (backup/'interfaces.modified.sha256').write_text('0'*64)
            target=root/'interfaces'; target.write_text('auto lo\n')
            with patch.object(m,'BACKUP',backup), patch.object(m,'NETWORK_IFACES',target):
                m.restore_network()
            self.assertEqual(target.read_text(),'auto lo\n')

    def test_rollback_modified_interfaces_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); backup=root/'backup'; backup.mkdir()
            (backup/'interfaces.original').write_text('auto lo\n')
            (backup/'interfaces.modified.sha256').write_text('0'*64)
            target=root/'interfaces'; target.write_text('auto lo\n# custom later edit\n')
            with patch.object(m,'BACKUP',backup), patch.object(m,'NETWORK_IFACES',target):
                with self.assertRaisesRegex(RuntimeError,'Network file changed'):
                    m.restore_network()

    def test_failed_disable_does_not_claim_full_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); state=root/'state'; state.mkdir()
            (state/'config.json').write_text(__import__('json').dumps(CONF))
            unit_dir=root/'units';unit_dir.mkdir()
            (unit_dir/'euag3-bridge.timer').write_text('# EUAG3-MANAGED\n')
            def fake_run(a,**kw):
                rc=1 if a[:3]==['systemctl','disable','euag3-bridge.timer'] else 0
                return NS(returncode=rc,stdout='',stderr='simulated failure')
            with patch.object(m,'STATE',state),patch.object(m,'CONFIG',state/'config.json'),\
                 patch.object(m,'BACKUP',state/'backup'),patch.object(m,'UNIT_DIR',unit_dir),\
                 patch.object(m,'CTL',root/'ctl'),patch.object(m,'UNINSTALL',root/'un'),\
                 patch.object(m,'UNIT_FILES',['euag3-bridge.timer']),\
                 patch.object(m,'TIMERS',['euag3-bridge.timer']),patch.object(m,'run',side_effect=fake_run),\
                 patch.object(m,'clean_container_rules'),patch.object(m,'clean_host_rules'),\
                 patch.object(m,'restore_network'):
                with self.assertRaisesRegex(RuntimeError,'systemctl disable'):
                    m.cleanup()
            self.assertTrue(state.exists())
            self.assertTrue((unit_dir/'euag3-bridge.timer').exists())

    def test_foreign_modified_service_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); state=root/'state'; state.mkdir()
            (state/'config.json').write_text(__import__('json').dumps(CONF))
            unit_dir=root/'units';unit_dir.mkdir()
            (unit_dir/'euag3-main.service').write_text('# locally edited\n')
            with patch.object(m,'STATE',state),patch.object(m,'CONFIG',state/'config.json'),\
                 patch.object(m,'UNIT_DIR',unit_dir),patch.object(m,'CTL',root/'ctl'),\
                 patch.object(m,'UNINSTALL',root/'un'),\
                 patch.object(m,'UNIT_FILES',['euag3-main.service']):
                with self.assertRaisesRegex(RuntimeError,'modified or replaced'):
                    m.cleanup()
            self.assertTrue((unit_dir/'euag3-main.service').exists())
            self.assertTrue(state.exists())

    def test_container_transaction_marker_written_before_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); state=root/'state'; state.mkdir()
            (state/'config.json').write_text('{}')
            with patch.object(m,'STATE',state),patch.object(m,'CONFIG',state/'config.json'),\
                 patch.object(m,'cip',side_effect=RuntimeError('simulated first rule failure')):
                with self.assertRaisesRegex(RuntimeError,'simulated first rule failure'):
                    m.ensure_bridge_container(CONF,{'gateway':'172.30.50.1','docker_dev':'eth0'})
            self.assertTrue((state/'container-touched').exists())

if __name__=='__main__':unittest.main(verbosity=2)
