#!/usr/bin/env python3
"""Offline regression tests: never run actual iptables, Docker, systemctl or network commands."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
import unittest
import shlex

SPEC=importlib.util.spec_from_file_location('euag3ctl',str(Path(__file__).resolve().parents[1]/'euag3ctl.py'))
m=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)

class FW:
    def __init__(self):
        self.rules={};self.ops=[]
    def canonical(self,r):
        r=list(r)
        if '-p' in r and r[r.index('-p')+1]=='tcp' and '-m' not in r:
            pass
        return m.normalized_rule(r)
    def data(self,table,chain):
        return self.rules.setdefault((table,chain),[])
    def call(self,*args,check=True,capture=False):
        a=list(args); self.ops.append(a)
        table='filter'
        if a[:2]==['-t','nat']:
            table='nat'; a=a[2:]
        cmd=a[0];ch=a[1]
        entries=self.data(table,ch)
        rc=0
        if cmd=='-S':
            out=[]
            for r in entries:
                present=list(r)
                if '-p' in present:
                    i=present.index('-p')
                    if present[i+1]=='tcp' and present[i+2:i+4]!=['-m','tcp']:
                        present[i+2:i+2]=['-m','tcp']
                out.append('-A '+ch+' '+shlex.join(present))
            return NS(returncode=0,stdout='\n'.join(out)+'\n',stderr='')
        if cmd=='-C':
            candidate=self.canonical(a[2:]); rc=0 if any(self.canonical(e)==candidate for e in entries) else 1
        elif cmd=='-I':
            pos=int(a[2]); entries.insert(pos-1,a[3:])
        elif cmd=='-D':
            if len(a)==3 and a[2].isdigit():
                entries.pop(int(a[2])-1)
            else:
                candidate=self.canonical(a[2:]); matches=[i for i,e in enumerate(entries) if self.canonical(e)==candidate]
                if not matches: rc=1
                else: entries.pop(matches[0])
        else:
            raise AssertionError('unexpected '+str(a))
        return NS(returncode=rc,stdout='',stderr='')

class TestRules(unittest.TestCase):
    def test_normalized_tcp(self):
        self.assertEqual(m.normalized_rule(['-p','tcp','--dport','5443']),
                         m.normalized_rule(['-p','tcp','-m','tcp','--dport','5443']))

    def test_container_rules_survive_reconciliation(self):
        fw=FW()
        c={'container':'amnezia-awg2','tunnel_port':5443,'mt_port':5443,'awg_if':'awg0',
           'awg_addr':'10.66.44.1','awg_net':'10.66.44.0/24'}
        net={'docker_dev':'eth0','gateway':'172.30.50.1'}
        with patch.object(m,'cip',side_effect=lambda c,*a,**k: fw.call(*a,**k)):
            m.ensure_bridge_container(c,net)
            initial={k:[list(x) for x in v] for k,v in fw.rules.items()}
            self.assertEqual(sum(map(len,fw.rules.values())),4)
            m.ensure_bridge_container(c,net)
            self.assertEqual(fw.rules,initial,'Reconcile removed valid iptables -m tcp formatted rules!')
            # Docker may change which interface connects the host bridge.
            m.ensure_bridge_container(c,{**net,'docker_dev':'eth1'})
            self.assertEqual(sum(map(len,fw.rules.values())),4)
            self.assertIn('eth1',str(fw.rules))
            self.assertNotIn("'eth0'",str(fw.rules))

    def test_guard_anchor_is_first_and_no_exposure_during_move(self):
        fw=FW(); fw.data('filter','INPUT').append(['-j','ufw-before-input'])
        fw.data('filter','INPUT').append(['-m','comment','--comment','euag3guard:anchor:INPUT:EG3_IN','-j','EG3_IN'])
        orig=fw.call
        def host_ipt(family,*a,**k): return orig(*a,**k)
        def host_output(argv): return orig('-S',argv[-1],capture=True).stdout.strip()
        with patch.object(m,'ipt',side_effect=host_ipt), patch.object(m,'output',side_effect=host_output):
            m.ensure_anchor(4,'INPUT','EG3_IN',match=('-p','tcp','--dport','5443'))
            rules=fw.data('filter','INPUT')
            self.assertEqual(rules[0][-1],'EG3_IN')
            self.assertEqual(len(rules),2)
            history=len(fw.ops)
            m.ensure_anchor(4,'INPUT','EG3_IN',match=('-p','tcp','--dport','5443'))
            self.assertEqual(len(fw.data('filter','INPUT')),2)
            self.assertNotIn('-I',str(fw.ops[history:]),'Unnecessary reinsert on every timer')

    def test_host_bridge_rule_not_removed_on_iptables_tcp_format(self):
        fw=FW()
        fw.data('filter','EG3_IN').append(['-m','comment','--comment','euag3guard:drop','-j','DROP'])
        c={'mt_port':5443}
        net={'host_if':'amn0','docker_ip':'172.30.50.2','gateway':'172.30.50.1'}
        with patch.object(m,'ipt',side_effect=lambda fam,*a,**k:fw.call(*a,**k)):
            m.ensure_bridge_host(c,net)
            old={k:[list(x) for x in v] for k,v in fw.rules.items()}
            m.ensure_bridge_host(c,net)
            self.assertEqual(fw.rules,old)
            self.assertEqual(len(fw.data('filter','EG3_IN')),2)

    def test_config_validation(self):
        base={'container':'amnezia-awg2','awg_if':'awg0','awg_addr':'10.66.44.1','awg_net':'10.66.44.2/24',
              'mt_port':'5443','tunnel_port':'5443','ssh_port':'22','awg_udp_port':'443',
              'moscow_ips':[],'bridge_if':'','bridge_ip':'','update_at':'04:25'}
        c=m.validate_config(base)
        self.assertEqual(c['awg_net'],'10.66.44.0/24')
        self.assertIn('04:25:00 UTC',m.units_content(c)['euag3-update.timer'])
        for key,value in [('mt_port','0'),('ssh_port','65536'),('update_at','25:25'),('awg_addr','not.an.ip')]:
            with self.subTest(key=key), self.assertRaises(Exception):
                m.validate_config({**base,key:value})

    def test_udp_moscow_exception_survives_iptables_format(self):
        self.assertEqual(m.normalized_rule(['-p','udp','--sport','443']),
                         m.normalized_rule(['-p','udp','-m','udp','--sport','443']))
        c={'moscow_ips':['198.51.100.96'],'awg_udp_port':443}
        net={'docker_ip':'172.30.50.2'}
        existing=['-s','172.30.50.2/32','-d','198.51.100.96/32',
                  '-p','udp','-m','udp','--sport','443',
                  '-m','comment','--comment',m.TAG+':awg-peer','-j','RETURN']
        seen=[]
        with patch.object(m,'ipset_count',return_value=5000),patch.object(m,'ensure_chain'),\
             patch.object(m,'ensure_anchor'),patch.object(m,'append_rule'),\
             patch.object(m,'inject'),patch.object(m,'owned_rules',return_value=[existing]),\
             patch.object(m,'ipt',side_effect=lambda *args,**kw:seen.append(args)):
            m.ensure_geo(c,net)
        self.assertFalse(seen,'An existing legitimate Moscow UDP exception was removed')

    def test_installer_does_not_start_own_service_under_lock(self):
        src=(Path(__file__).resolve().parents[1]/'euag3ctl.py').read_text()
        self.assertNotIn("run(['systemctl','start','euag3-main.service']",src)
        self.assertNotIn("run(['systemctl','start','euag3-port.service']",src)
        self.assertIn('automatic rollback started',src)

if __name__=='__main__': unittest.main(verbosity=2)
