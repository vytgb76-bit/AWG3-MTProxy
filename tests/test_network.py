#!/usr/bin/env python3
"""Docker bridge choice with multiple Docker networks, without touching the network."""
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch
import unittest
SPEC=importlib.util.spec_from_file_location('euag3ctl',str(Path(__file__).resolve().parents[1]/'euag3ctl.py'))
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)

class TestNetwork(unittest.TestCase):
    def fakeoutput(self,a):
        if a[:2]==['docker','inspect']:return json.dumps({'Running':True,'Pid':12345})
        if a[:3]==['docker','exec','amnezia-awg2']:
            if 'addr' in a:
                return json.dumps([
                    {'ifname':'eth0','addr_info':[{'family':'inet','local':'172.29.172.2','prefixlen':24}]},
                    {'ifname':'eth1','addr_info':[{'family':'inet','local':'172.17.0.2','prefixlen':16}]},
                    {'ifname':'awg0','addr_info':[{'family':'inet','local':'10.8.32.0','prefixlen':24}]},])
            if 'route' in a:return json.dumps([{'gateway':'172.29.172.1','dev':'eth0'}])
            if 'cat' in a:return '1'
        if a[:3]==['ip','-j','-4']:
            return json.dumps([
                {'ifname':'docker0','addr_info':[{'family':'inet','local':'172.17.0.1','prefixlen':16}]},
                {'ifname':'amn0','addr_info':[{'family':'inet','local':'172.29.172.1','prefixlen':24}]},])
        raise AssertionError(a)
    def test_selects_default_bridge(self):
        c={'container':'amnezia-awg2','awg_if':'awg0','awg_addr':'10.8.32.0','awg_net':'10.8.32.0/24','bridge_ip':'','bridge_if':''}
        with patch.object(m,'output',side_effect=self.fakeoutput):
            net=m.container_network(c)
        self.assertEqual(net['docker_dev'],'eth0')
        self.assertEqual(net['host_if'],'amn0')
        self.assertEqual(net['docker_ip'],'172.29.172.2')
    def test_explicit_bridge_overrides_default(self):
        c={'container':'amnezia-awg2','awg_if':'awg0','awg_addr':'10.8.32.0','awg_net':'10.8.32.0/24','bridge_ip':'172.17.0.1','bridge_if':'docker0'}
        with patch.object(m,'output',side_effect=self.fakeoutput):
            net=m.container_network(c)
        self.assertEqual(net['docker_dev'],'eth1')
        self.assertEqual(net['docker_ip'],'172.17.0.2')
    def test_mismatched_bridge_fails_closed(self):
        c={'container':'amnezia-awg2','awg_if':'awg0','awg_addr':'10.8.32.0','awg_net':'10.8.32.0/24','bridge_ip':'192.168.12.1','bridge_if':''}
        with patch.object(m,'output',side_effect=self.fakeoutput):
            with self.assertRaisesRegex(RuntimeError,'No Docker container interface'):
                m.container_network(c)

if __name__=='__main__':unittest.main(verbosity=2)
