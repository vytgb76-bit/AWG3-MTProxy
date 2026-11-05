#!/usr/bin/env python3
"""EU AWG3 -> host MTProto, RU egress policy. Owns only EUAG3-tagged firewall state."""
# EUAG3-MANAGED v6.0
import argparse
import hashlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import signal

STATE = Path('/var/lib/euag3guard')
CONFIG = STATE / 'config.json'
BACKUP = STATE / 'backup'
UNIT_DIR = Path('/etc/systemd/system')
NETWORK_IFACES = Path('/etc/network/interfaces')
CTL = Path('/usr/local/sbin/euag3ctl')
UNINSTALL = Path('/usr/local/sbin/euag3-uninstall')
RU4, RU6 = 'eg3_ru4', 'eg3_ru6'
RU4_TMP, RU6_TMP = 'eg3_ru4_tmp', 'eg3_ru6_tmp'
IN, OUT, FWD = 'EG3_IN', 'EG3_OUT', 'EG3_FWD'
TAG = 'euag3guard'
UNIT_FILES = [
    'euag3-port.service', 'euag3-main.service',
    'euag3-bridge.service', 'euag3-bridge.timer',
    'euag3-update.service', 'euag3-update.timer',
]
TIMERS = ['euag3-bridge.timer', 'euag3-update.timer']
URL4 = 'https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone'
URL6 = 'https://www.ipdeny.com/ipv6/ipaddresses/blocks/ru.zone'


def log(msg):
    print('[EUAG3] ' + str(msg), flush=True)


def die(msg):
    raise RuntimeError(str(msg))


def run(argv, *, check=True, capture=False, input_data=None, timeout=45):
    p = subprocess.run(list(map(str, argv)), text=True, input=input_data,
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.PIPE if capture else None,
                       timeout=timeout)
    if check and p.returncode:
        die(f'Command failed ({p.returncode}): {shlex.join(list(map(str,argv)))}\n{p.stderr or ""}')
    return p


def output(argv, **kw):
    return run(argv, capture=True, **kw).stdout.strip()


def exists_command(c):
    return shutil.which(c) is not None


def need_tools():
    missing = [c for c in ('iptables','ip6tables','ipset','docker','ip','ss',
                            'curl','nsenter','systemctl','awk') if not exists_command(c)]
    if missing:
        die('Missing packages/tools: ' + ', '.join(missing) +
            '. On Ubuntu install tools separately: apt-get update && apt-get install -y iptables ipset curl iproute2 util-linux')


def ipt(family, *args, check=True, capture=False):
    return run(['iptables' if family == 4 else 'ip6tables','-w','10',*args],
               check=check, capture=capture)


def cip(c, *args, check=True, capture=False):
    return run(['docker','exec',c['container'],'iptables','-w','10',*args],
               check=check, capture=capture)


def optional_rule(checker, arg):
    return checker(*arg, check=False, capture=True).returncode == 0


def ensure_chain(family, chain):
    if not optional_rule(lambda *a,**k: ipt(family,*a,**k), ('-S',chain)):
        ipt(family,'-N',chain)


def owned_rules(tool, chain, *, family=4, c=None):
    if tool == 'host':
        p = ipt(family,'-S',chain,check=False,capture=True)
    else:
        p = cip(c,'-S',chain,check=False,capture=True)
    if p.returncode: return []
    ans = []
    for line in p.stdout.splitlines():
        parts = shlex.split(line)
        if len(parts)>=3 and parts[:2]==['-A',chain] and TAG in line:
            ans.append(parts[2:])
    return ans


def purge_tagged_in_chain(family, chain, *, c=None):
    tool = 'container' if c else 'host'
    for args in owned_rules(tool,chain,family=family,c=c):
        if c: cip(c,'-D',chain,*args,check=False)
        else: ipt(family,'-D',chain,*args,check=False)


def inject(family, chain, args, *, position=1, c=None):
    check_cmd = lambda *s,**k: cip(c,*s,**k) if c else ipt(family,*s,**k)
    if not optional_rule(check_cmd,('-C',chain,*args)):
        check_cmd('-I',chain,str(position),*args)


def append_rule(family, chain, args):
    if not optional_rule(lambda *a,**k: ipt(family,*a,**k), ('-C',chain,*args)):
        ipt(family,'-A',chain,*args)


def normalized_rule(parts):
    """Compare iptables -S rules ignoring implicit protocol matcher (-m tcp/udp)."""
    ans=[]
    i=0
    while i<len(parts):
        if (i+1<len(parts) and parts[i]=='-m' and parts[i+1] in ('tcp','udp')
                and '-p' in parts and parts[parts.index('-p')+1]==parts[i+1]):
            i+=2
            continue
        ans.append(parts[i]);i+=1
    return ans


def ensure_first_rule(family, hook, spec, marker):
    """Keep tagged guard at rule 1, without ever removing the last existing guard first."""
    cmd='iptables' if family==4 else 'ip6tables'
    existing=output([cmd,'-S',hook]).splitlines()
    rules=[shlex.split(x)[2:] for x in existing if x.startswith(f'-A {hook} ')]
    desired=normalized_rule(spec)
    first_ok=bool(rules) and normalized_rule(rules[0])==desired
    tagged=[idx for idx,r in enumerate(rules,1) if marker in r]
    # If the desired guard has drifted behind UFW, insert the replacement FIRST.
    if not first_ok:
        ipt(family,'-I',hook,'1',*spec)
    # Remove duplicates and stale tagged versions, always retaining the first guard.
    fresh=output([cmd,'-S',hook]).splitlines()
    lines=[shlex.split(x)[2:] for x in fresh if x.startswith(f'-A {hook} ')]
    for idx in range(len(lines),1,-1):
        if marker in lines[idx-1]:
            ipt(family,'-D',hook,str(idx))
    if not lines or normalized_rule(lines[0])!=desired:
        die(f'Failed to place IPv{family} {hook} guard as first rule')


def ensure_anchor(family, hook, chain, *, match=()):
    spec=[*match,'-m','comment','--comment',TAG + ':anchor:'+hook+':'+chain, '-j',chain]
    ensure_first_rule(family,hook,spec,TAG+':anchor:'+hook+':'+chain)


def ip_data(obj):
    return json.loads(output(obj))


def container_network(c):
    container = c['container']
    doc = json.loads(output(['docker','inspect','--format','{{json .State}}',container]))
    if not doc.get('Running') or not doc.get('Pid'):
        die(f'Container {container} not running')
    ns_pid = int(doc['Pid'])
    ips = ip_data(['docker','exec',container,'ip','-j','-4','addr'])
    awg_addresses = []
    for i in ips:
        if i.get('ifname') == c['awg_if']:
            for addr in i.get('addr_info',[]):
                if addr.get('family') == 'inet':
                    awg_addresses.append(ipaddress.ip_interface(addr['local']+'/'+str(addr['prefixlen'])))
    if not awg_addresses:
        die(f'No IPv4 address on {c["awg_if"]} inside {container}')
    address = ipaddress.ip_address(c['awg_addr'])
    net = ipaddress.ip_network(c['awg_net'],strict=False)
    if address.version != 4 or net.version !=4 or address not in net:
        die('AWG address/CIDR invalid')
    if not any(str(i.ip)==str(address) and i.network==net for i in awg_addresses):
        die(f'AWG {c["awg_if"]} actual addresses {awg_addresses}, expected {address}/{net.prefixlen}')
    host_ips = ip_data(['ip','-j','-4','addr'])
    # Explicit bridge IP or interface overrides the container's default route.
    # Containers may have two Docker networks and a different default gateway.
    candidates=[]
    for hostif in host_ips:
        hostdev=hostif.get('ifname','')
        if c.get('bridge_if') and hostdev!=c['bridge_if']: continue
        for haddr in hostif.get('addr_info',[]):
            if haddr.get('family')!='inet': continue
            h_ip=haddr['local']
            if c.get('bridge_ip') and h_ip!=c['bridge_ip']: continue
            for dockerif in ips:
                dockerdev=dockerif.get('ifname','')
                if dockerdev in ('lo',c['awg_if']): continue
                for a in dockerif.get('addr_info',[]):
                    if a.get('family')!='inet': continue
                    net4=ipaddress.IPv4Interface(a['local']+'/'+str(a['prefixlen'])).network
                    if ipaddress.IPv4Address(h_ip) in net4:
                        candidates.append(dict(docker_dev=dockerdev,docker_ip=a['local'],
                                               gateway=h_ip,host_if=hostdev))
    if not candidates:
        die('No Docker container interface shares a subnet with the selected host bridge')
    routes = ip_data(['docker','exec',container,'ip','-j','-4','route','show','default'])
    default_gateway=next((r.get('gateway') for r in routes if r.get('gateway')),None)
    if not c.get('bridge_ip') and not c.get('bridge_if'):
        # Preserve working installation behavior when no bridge is specified.
        matches=[x for x in candidates if x['gateway']==default_gateway]
        if len(matches)==1: candidates=matches
        elif len(candidates)>1:
            die('Multiple Docker bridges detected, and none uniquely matches the default route; specify --bridge-ip')
    elif len(candidates)>1:
        die('Selected bridge maps to multiple Docker interfaces; specify both --bridge-if and --bridge-ip')
    net=candidates[0]
    if len(candidates)!=1:
        die('Ambiguous Docker bridge selection; specify bridge IP/interface')
    fw = output(['docker','exec',container,'cat','/proc/sys/net/ipv4/ip_forward'])
    if fw!='1': die('Container net.ipv4.ip_forward must be 1; refusing to mutate AWG settings')
    return dict(pid=ns_pid, **net)


def listening(port):
    # Avoid depending on localized ss process strings.
    s = output(['ss','-H','-lnt'])
    for line in s.splitlines():
        cols=line.split()
        if len(cols)<4: continue
        endpoint=cols[3]
        if endpoint.endswith(':'+str(port)):
            return True
    return False


def tcp_test(addr,port,ns_pid=None):
    code = 'import socket; x=socket.create_connection((' + repr(str(addr)) + ','+str(int(port))+'),3);x.close()'
    argv = ['python3','-c',code]
    if ns_pid is not None: argv=['nsenter','-t',str(ns_pid),'-n',*argv]
    return run(argv,check=False,capture=True,timeout=10).returncode==0


def check_install(c, *, require_connection=True):
    need_tools()
    for extra in ('iptables-save','ip6tables-save'):
        if not exists_command(extra): die(f'Missing {extra}')
    if not listening(c['ssh_port']): die(f'SSH TCP {c["ssh_port"]} not listening; refusing install')
    if not listening(c['mt_port']): die(f'MTProxy TCP {c["mt_port"]} not listening')
    net = container_network(c)
    if not tcp_test('127.0.0.1',c['mt_port']): die('Host MTProxy loopback TCP failed')
    # Do not require bridge TCP before our narrow host ACCEPT is installed; UFW may block it until then.
    log('Preflight OK: '+str({k:v for k,v in net.items() if k!='pid'}))
    return net


def validate_config(c):
    c = dict(c)
    if not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{0,75}',c['container']): die('Invalid container name')
    if not re.fullmatch('[a-zA-Z][a-zA-Z0-9_.-]{0,25}',c['awg_if']): die('Invalid AWG interface')
    for x in ('mt_port','tunnel_port','ssh_port','awg_udp_port'):
        try: c[x]=int(c[x])
        except (ValueError,TypeError): die(f'Invalid {x}')
        if not 1 <= c[x] <= 65535: die(f'Port out of range: {x}')
    if c['ssh_port'] == c['mt_port']: die('SSH and telemt port must differ')
    ipaddress.IPv4Address(c['awg_addr'])
    c['awg_net']=str(ipaddress.IPv4Network(c['awg_net'],strict=False))
    if ipaddress.IPv4Address(c['awg_addr']) not in ipaddress.IPv4Network(c['awg_net'],strict=False):
        die('AWG address does not belong to AWG network')
    for peer in c['moscow_ips']:
        ipaddress.IPv4Address(peer)
    c['moscow_ips'] = sorted(set(c['moscow_ips']))
    c['update_at'] = str(c.get('update_at','04:25'))
    if not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]',c['update_at']):
        die('update_at must be HH:MM in UTC')
    for x in ('bridge_if','bridge_ip'):
        if not c.get(x): c[x]=''
    if c['bridge_if'] and not re.fullmatch('[a-zA-Z0-9_.:-]{1,32}', c['bridge_if']):
        die('Invalid host bridge interface')
    if c['bridge_ip']: ipaddress.IPv4Address(c['bridge_ip'])
    return c


def get_config():
    if not CONFIG.is_file(): die('EUAG3 is not installed: config missing')
    return validate_config(json.loads(CONFIG.read_text()))


def download_lists(dst):
    dst.mkdir(parents=True,exist_ok=True)
    p4, p6=dst/'ru4.zone', dst/'ru6.zone'
    for url,path in ((URL4,p4),(URL6,p6)):
        run(['curl','--proto','=https','--tlsv1.2','--fail','--silent','--show-error',
             '--location','--connect-timeout','10','--max-time','55',
             '--retry','2','--output',str(path),url],timeout=150)
    def verify(p,family,minimum):
        data=[]
        for line in p.read_text(encoding='ascii').splitlines():
            line=line.strip()
            if not line: continue
            network=ipaddress.ip_network(line, strict=True)
            if network.version!=family or network.prefixlen < (8 if family==4 else 16):
                die(f'Suspicious RU IPv{family} entry: {line}')
            data.append(str(network))
        if not minimum <= len(data) <= 100000:
            die(f'Unexpected IPv{family} count {len(data)}; no changes applied')
        p.write_text('\n'.join(data)+'\n',encoding='ascii')
        return len(data)
    n4=verify(p4,4,1000); n6=verify(p6,6,50)
    log(f'RU ranges downloaded and validated: IPv4 {n4}; IPv6 {n6}')
    return p4,p6


def set_create(name,family):
    run(['ipset','create',name,'hash:net','family',family,'maxelem','120000','-exist'])


def ipset_exists(name):
    return run(['ipset','list',name,'-terse'],check=False,capture=True).returncode==0


def ipset_count(name):
    """Inspect live member count. An existing but EMPTY set blocks nothing."""
    p=run(['ipset','list',name,'-terse'],check=False,capture=True)
    if p.returncode: return -1
    m=re.search(r'^Number of entries:\s*(\d+)\s*$',p.stdout,re.M)
    if not m: die(f'Cannot read ipset member count for {name}')
    return int(m.group(1))


def write_ipset(name,family,path):
    set_create(name,family)
    script='flush '+name+'\n'+''.join(f'add {name} {line.strip()}\n' for line in path.read_text().splitlines() if line.strip())
    run(['ipset','restore','-exist'],input_data=script,timeout=160)


def update_sets(p4,p6):
    # Build both first, swap both; reverse on second-swap error.
    for name in (RU4_TMP,RU6_TMP):
        if ipset_exists(name): run(['ipset','destroy',name],check=False)
    try:
        write_ipset(RU4_TMP,'inet',p4)
        write_ipset(RU6_TMP,'inet6',p6)
        # Ensure live sets exist to allow an atomic initial load.
        set_create(RU4,'inet'); set_create(RU6,'inet6')
        run(['ipset','swap',RU4,RU4_TMP])
        try: run(['ipset','swap',RU6,RU6_TMP])
        except Exception:
            run(['ipset','swap',RU4,RU4_TMP])
            raise
    finally:
        for name in (RU4_TMP,RU6_TMP):
            run(['ipset','destroy',name],check=False)


def ensure_port_guard(c):
    ensure_chain(4,IN)
    inject(4,IN,['-m','comment','--comment',TAG+':drop','-j','DROP'],position=1)
    inject(4,IN,['-i','lo','-m','comment','--comment',TAG+':lo','-j','ACCEPT'],position=1)
    ensure_anchor(4,'INPUT',IN,match=('-p','tcp','--dport',str(c['mt_port'])))
    # IPv6 localhost remains available, all non-loopback access to telemt blocked.
    spec=['!','-i','lo','-p','tcp','--dport',str(c['mt_port']),'-m','comment',
          '--comment',TAG+':v6port','-j','DROP']
    ensure_first_rule(6,'INPUT',spec,TAG+':v6port')


def ensure_bridge_host(c,net):
    spec=['-i',net['host_if'],'-s',net['docker_ip']+'/32',
          '-d',net['gateway']+'/32','-p','tcp','--dport',str(c['mt_port']),
          '-m','comment','--comment',TAG+':bridge-allow','-j','ACCEPT']
    inject(4,IN,spec,position=1)
    # Remove ONLY our previous dynamic bridge allows (container could change IP).
    for args in owned_rules('host',IN):
        if TAG+':bridge-allow' in args and normalized_rule(args)!=normalized_rule(spec):
            ipt(4,'-D',IN,*args)
    # Input DROP stays last because permits inserted before it.


def ensure_geo(c,net=None):
    # netfilter-persistent (or another boot service) can recreate empty ipsets.
    # Never claim RU protection solely because names exist: validate member counts.
    n4,n6=ipset_count(RU4),ipset_count(RU6)
    if n4<1000 or n6<50:
        log(f'RU live sets missing/incomplete (IPv4={n4}; IPv6={n6}); restoring saved CIDRs')
        p4,p6 = STATE/'ru4.zone',STATE/'ru6.zone'
        if not p4.is_file() or not p6.is_file(): die('RU lists unavailable on disk')
        update_sets(p4,p6)
        n4,n6=ipset_count(RU4),ipset_count(RU6)
        if n4<1000 or n6<50: die('RU live sets still incomplete after restore')
    for family,setname in ((4,RU4),(6,RU6)):
        for chain,hook in ((OUT,'OUTPUT'),(FWD,'FORWARD')):
            ensure_chain(family,chain)
            inject(family,chain,['-m','conntrack','--ctstate','ESTABLISHED,RELATED',
                                 '-m','comment','--comment',TAG+':est','-j','RETURN'])
            ensure_anchor(family,hook,chain)
            rej=['-m','conntrack','--ctstate','NEW','-m','set','--match-set',setname,'dst',
                 '-m','comment','--comment',TAG+':ru','-j','REJECT']
            append_rule(family,chain,rej)
            # Optional new UDP replies to a SPECIFIC known Moscow public IPv4.
            if family==4 and chain==FWD and net:
                for ip in c['moscow_ips']:
                    allow=['-s',net['docker_ip']+'/32','-d',ip+'/32',
                           '-p','udp','--sport',str(c['awg_udp_port']),'-m','comment',
                           '--comment',TAG+':awg-peer','-j','RETURN']
                    inject(family,chain,allow,position=2)
                for args in owned_rules('host',chain,family=4):
                    if TAG+':awg-peer' in args:
                        valid = any(normalized_rule(args)==normalized_rule(['-s',net['docker_ip']+'/32','-d',ip+'/32',
                           '-p','udp','--sport',str(c['awg_udp_port']),'-m','comment',
                           '--comment',TAG+':awg-peer','-j','RETURN']) for ip in c['moscow_ips'])
                        if not valid: ipt(4,'-D',chain,*args)
            # Ensure the RU REJECT is AFTER all exceptions (established first).
            # Any unknown egress remains governed by existing firewall rules.


def ensure_bridge_container(c,net):
    # Persist a transaction marker BEFORE the first potential container change.
    # On an early installer failure, rollback can safely skip an untouched Docker.
    if STATE.exists() and CONFIG.is_file():
        touched=STATE/'container-touched'
        if not touched.exists():
            touched.write_text('container firewall may have been changed\n')
            with touched.open('rb') as fd: os.fsync(fd.fileno())
    pp=str(c['tunnel_port']); mp=str(c['mt_port']); gw=net['gateway']
    specs=[
       ('nat','PREROUTING',['-i',c['awg_if'],'-s',c['awg_net'],'-d',c['awg_addr']+'/32',
           '-p','tcp','--dport',pp,'-m','comment','--comment',TAG+':dnat',
           '-j','DNAT','--to-destination',gw+':'+mp]),
       ('nat','POSTROUTING',['-o',net['docker_dev'],'-s',c['awg_net'],'-d',gw+'/32',
           '-p','tcp','--dport',mp,'-m','comment','--comment',TAG+':snat','-j','MASQUERADE']),
       ('filter','FORWARD',['-i',c['awg_if'],'-o',net['docker_dev'],'-s',c['awg_net'],
           '-d',gw+'/32','-p','tcp','--dport',mp,'-m','comment','--comment',TAG+':fwd',
           '-j','ACCEPT']),
       ('filter','FORWARD',['-i',net['docker_dev'],'-o',c['awg_if'],
           '-m','conntrack','--ctstate','ESTABLISHED,RELATED',
           '-m','comment','--comment',TAG+':return','-j','ACCEPT']),
    ]
    for table,chain,args in specs:
        q=['-t',table] if table!='filter' else []
        if not optional_rule(lambda *a,**k: cip(c,*a,**k),(*q,'-C',chain,*args)):
            cip(c,*q,'-I',chain,'1',*args)
    # Retire ONLY outdated own rules. Normalize iptables's implicit '-m tcp'
    # so we never delete an active DNAT just because its printable format changed.
    for table,chain in (('nat','PREROUTING'),('nat','POSTROUTING'),('filter','FORWARD')):
        q=['-t',table] if table!='filter' else []
        p=cip(c,*q,'-S',chain,check=False,capture=True)
        if p.returncode: die(f'Cannot list container {table}/{chain}')
        wanted=[normalized_rule(args) for t,ch,args in specs if t==table and ch==chain]
        counts={tuple(w):0 for w in wanted}
        for line in p.stdout.splitlines():
            args=shlex.split(line)
            if len(args)<3 or args[:2]!=['-A',chain] or TAG not in line: continue
            rule=tuple(normalized_rule(args[2:]))
            if rule in counts and counts[rule]==0:
                counts[rule]+=1
            else:
                cip(c,*q,'-D',chain,*args[2:])
    # Recheck all desired rules after the cleanup.
    for table,chain,args in specs:
        q=['-t',table] if table!='filter' else []
        if not optional_rule(lambda *a,**k: cip(c,*a,**k),(*q,'-C',chain,*args)):
            die(f'Container rule vanished: {table}/{chain} {args}')


def apply(c, *, wait_sec=0, host_only=False):
    ensure_port_guard(c)
    ensure_geo(c)
    if host_only:
        log('Port and RU egress rules restored (container not yet required)')
        return
    stop=time.monotonic()+wait_sec
    while True:
        try:
            net=container_network(c)
            if not listening(c['mt_port']): die(f'Telemt not listening on {c["mt_port"]}')
            ensure_bridge_host(c,net)
            ensure_bridge_container(c,net)
            ensure_geo(c,net)
            if not tcp_test(net['gateway'],c['mt_port'],ns_pid=net['pid']):
                die(f'TCP bridge test to {net["gateway"]}:{c["mt_port"]} failed')
            log(f'OK: {c["awg_addr"]}:{c["tunnel_port"]} -> {net["gateway"]}:{c["mt_port"]}; '
                f'{c["container"]}/{net["docker_dev"]}={net["docker_ip"]}; external MT port guarded')
            return
        except Exception as e:
            if time.monotonic()+3>stop:
                raise
            log(f'AWG not ready, retrying: {e}')
            time.sleep(3)


def is_ifupdown_conflict(iface):
    f=NETWORK_IFACES
    if not f.exists(): return False
    contents=f.read_text()
    if not re.search(r'^\s*iface\s+'+re.escape(iface)+r'\s+inet\s+(static|dhcp)\b',contents,re.M):
        return False
    if run(['systemctl','is-active','systemd-networkd'],check=False,capture=True).stdout.strip()!='active':
        return False
    # Netplan generated config / active networkd owner.
    status=output(['networkctl','status',iface])
    return 'netplan' in status.lower() or 'Network File:' in status and bool(list(Path('/etc/netplan').glob('*.yaml')))


def disable_ifupdown(iface):
    path=NETWORK_IFACES
    source=path.read_text()
    lines=source.splitlines(keepends=True)
    if not is_ifupdown_conflict(iface): return False
    pat_iface=re.compile(r'^\s*iface\s+'+re.escape(iface)+r'\s+inet\s+\w+')
    pat_auto=re.compile(r'^\s*(auto|allow-hotplug)\s+(.+)$')
    # Refuse complex multi-interface auto declarations; preserve other settings.
    start=None; end=None
    for i,line in enumerate(lines):
        if pat_iface.match(line):
            if start is not None: die('Multiple ifupdown stanzas for interface; cannot safely edit')
            start=i
    if start is None: return False
    end=len(lines)
    for j in range(start+1,len(lines)):
        if re.match(r'^\s*(iface|auto|allow-hotplug|mapping|source|source-directory)\b',lines[j]):
            end=j;break
    indices=set(range(start,end))
    for i,line in enumerate(lines):
        ma=pat_auto.match(line)
        if ma and iface in ma.group(2).split():
            if ma.group(2).split()!=[iface]:
                die('Complex auto/allow-hotplug declaration; manual network adjustment required')
            indices.add(i)
    if not indices: return False
    BACKUP.mkdir(parents=True,exist_ok=True)
    shutil.copy2(path,BACKUP/'interfaces.original')
    new=''.join('# EUAG3 disabled: '+line if i in indices and line.strip() else line
                for i,line in enumerate(lines))
    (BACKUP/'interfaces.modified.sha256').write_text(hashlib.sha256(new.encode()).hexdigest())
    tmp=path.with_suffix('.euag3.tmp')
    tmp.write_text(new)
    shutil.copymode(path,tmp)
    os.replace(tmp,path)
    log(f'Disabled duplicate ifupdown config of {iface} (Netplan stays active; no network restart)')
    return True


def units_content(c):
    binary=str(CTL)
    return {
' euag3-port.service'.strip():f'''# EUAG3-MANAGED
[Unit]
Description=EU AWG3 early fail-closed MTProxy port guard
DefaultDependencies=no
After=local-fs.target systemd-modules-load.service
Before=network-pre.target network.target docker.service
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart={binary} early
RemainAfterExit=yes
TimeoutStartSec=40
[Install]
WantedBy=sysinit.target
''',
'euag3-main.service':f'''# EUAG3-MANAGED
[Unit]
Description=EU AWG3 to MTProxy and RU egress firewall
After=network-online.target docker.service euag3-port.service netfilter-persistent.service ufw.service
Wants=network-online.target
Requires=docker.service euag3-port.service
[Service]
Type=oneshot
ExecStart={binary} apply --wait 180
RemainAfterExit=yes
TimeoutStartSec=230
[Install]
WantedBy=multi-user.target
''',
'euag3-bridge.service':f'''# EUAG3-MANAGED
[Unit]
Description=Reapply EU AWG3 Docker MTProxy rules
After=docker.service euag3-port.service euag3-main.service netfilter-persistent.service ufw.service
Wants=docker.service
[Service]
Type=oneshot
ExecStart={binary} apply
TimeoutStartSec=35
''',
'euag3-bridge.timer':'''# EUAG3-MANAGED
[Unit]
Description=EU AWG3 bridge health check every 45 seconds
[Timer]
OnBootSec=12s
OnUnitInactiveSec=45s
AccuracySec=5s
Unit=euag3-bridge.service
[Install]
WantedBy=timers.target
''',
'euag3-update.service':f'''# EUAG3-MANAGED
[Unit]
Description=Refresh RU IPv4 and IPv6 sets for EU AWG3
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart={binary} update
TimeoutStartSec=200
''',
'euag3-update.timer':f'''# EUAG3-MANAGED
[Unit]
Description=Daily RU IP list update
[Timer]
OnCalendar=*-*-* {c['update_at']}:00 UTC
Persistent=true
Unit=euag3-update.service
[Install]
WantedBy=timers.target
'''
}


def write_units(c):
    for name,content in units_content(c).items():
        p=UNIT_DIR/name
        if p.exists(): die(f'Service file already exists: {p}')
        p.write_text(content)
        p.chmod(0o644)
    run(['systemctl','daemon-reload'])


def clean_container_rules(c):
    if run(['docker','info','--format','{{.ServerVersion}}'],check=False,capture=True).returncode:
        die('Docker daemon unavailable; cannot verify container rule removal. Retry uninstall when Docker is available')
    chk=run(['docker','inspect','--format','{{json .State}}',c['container']],check=False,capture=True)
    if chk.returncode:
        log('Container no longer exists; its network namespace rules have been discarded')
        return
    if not json.loads(chk.stdout).get('Running'):
        log('Container is stopped; no active container network namespace to clean')
        return
    for table,chain in (('nat','PREROUTING'),('nat','POSTROUTING'),('filter','FORWARD')):
        q=['-t',table] if table!='filter' else []
        p=cip(c,*q,'-S',chain,check=False,capture=True)
        if p.returncode: die(f'Cannot inspect {chain} in running AWG container for uninstall')
        for line in p.stdout.splitlines():
            parts=shlex.split(line)
            if len(parts)>=3 and parts[:2]==['-A',chain] and TAG in line:
                cip(c,*q,'-D',chain,*parts[2:])


def clean_host_rules(c):
    # Remove only anchors marked EUAG3 in builtin chains, preserving UFW/Docker.
    for family in (4,6):
        for hook in ('INPUT','OUTPUT','FORWARD'):
            purge_tagged_in_chain(family,hook)
        for chain in (IN,OUT,FWD):
            purge_tagged_in_chain(family,chain)
            if optional_rule(lambda *a,**k: ipt(family,*a,**k),('-S',chain)):
                # Only remove empty owned chains; never flush somebody else's rules.
                leftover=ipt(family,'-S',chain,capture=True).stdout.splitlines()
                if any(x.startswith('-A ') for x in leftover):
                    die(f'Unexpected rules in {chain}: refusing to delete or flush foreign rules')
                ipt(family,'-X',chain)
    for family in (4,6):
        for hook in ('INPUT','OUTPUT','FORWARD'):
            if owned_rules('host',hook,family=family):
                die(f'IPv{family} {hook} still has EUAG3-tagged rules; cannot claim clean rollback')
    # Destroy only our sets once all references are gone.
    for name in (RU4,RU6,RU4_TMP,RU6_TMP):
        if ipset_exists(name): run(['ipset','destroy',name])


def restore_network():
    original=BACKUP/'interfaces.original'
    hashfile=BACKUP/'interfaces.modified.sha256'
    if not original.exists(): return
    actual=NETWORK_IFACES
    if not actual.exists(): die('Cannot restore /etc/network/interfaces: file missing')
    digest=hashlib.sha256(actual.read_bytes()).hexdigest()
    original_hash=hashlib.sha256(original.read_bytes()).hexdigest()
    if digest==original_hash:
        log('Network file is already original; nothing to restore')
        return
    if not hashfile.exists() or digest!=hashfile.read_text().strip():
        die('Network file changed after install! Original saved in '+str(original)+'. Restore manually.')
    shutil.copy2(original,actual)
    log('Restored original /etc/network/interfaces (no live network restart)')


def cleanup(*, initial_failure=False):
    if not STATE.exists():
        log('Not installed: nothing to uninstall')
        return
    if not CONFIG.is_file():
        log('Installation stopped before writing config: removing empty transaction directory')
        shutil.rmtree(STATE)
        return
    c=get_config()
    # Refuse to erase user-modified or foreign files and to claim a full
    # rollback when an owned service/script was replaced after installation.
    for path in [*(UNIT_DIR/u for u in UNIT_FILES),CTL,UNINSTALL]:
        if path.exists() and 'EUAG3-MANAGED' not in path.read_text(errors='replace'):
            die(f'Managed file modified or replaced: {path}. State/backups retained; inspect manually.')
    errors=[]
    def attempt(description,cb):
        try: cb()
        except Exception as e:
            errors.append(f'{description}: {e}')
            log(f'WARNING: {description}: {e}')
    # Never claim full cleanup when systemd failed to disable/stop a managed unit.
    # --no-block avoids waiting for a service whose ExecStart holds our lock.
    for unit in (TIMERS+['euag3-main.service','euag3-port.service']):
        if not (UNIT_DIR/unit).exists():
            continue  # failed before creating this unit; nothing to disable
        def disable_unit(u=unit):
            a=run(['systemctl','disable',u],check=False,capture=True)
            if a.returncode: die(f'systemctl disable {u}: {a.stderr or a.stdout}')
            b=run(['systemctl','stop','--no-block',u],check=False,capture=True)
            if b.returncode: die(f'systemctl stop {u}: {b.stderr or b.stdout}')
        attempt('Disable and stop '+unit,disable_unit)
    if initial_failure and not (STATE/'container-touched').exists():
        log('Container never modified in failed install; Docker cleanup not required')
    else:
        attempt('Remove AWG container forwarding', lambda: clean_container_rules(c))
    attempt('Remove owned host firewall rules and ipsets', lambda: clean_host_rules(c))
    attempt('Restore ifupdown file',restore_network)
    if errors:
        log('INCOMPLETE ROLLBACK. State and backups preserved: '+str(STATE))
        die('; '.join(errors))
    for unit in UNIT_FILES:
        u=UNIT_DIR/unit
        if u.exists():
            u.unlink()
    p=run(['systemctl','daemon-reload'],check=False,capture=True)
    if p.returncode:
        die('Owned rules removed, but systemctl daemon-reload failed; state preserved. Retry uninstall.')
    for path in (CTL,UNINSTALL):
        if path.exists():
            path.unlink()
    shutil.rmtree(STATE)
    log('FULL ROLLBACK: original network file restored; owned iptables/ipset/systemd/files removed.')
    log('AWG3 Docker, MTProxyL, SSH and other firewall rules were not removed or restarted.')
    log('CAUTION: public MTProxy port may now be reachable because its access guard was removed.')


def prompt(label,default):
    if not sys.stdin.isatty(): return str(default)
    val=input(f'{label} [{default}]: ').strip()
    return val if val else str(default)


def detect_defaults(container,awg_if):
    try:
        ips=ip_data(['docker','exec',container,'ip','-j','-4','addr'])
        a=next(x for i in ips if i.get('ifname')==awg_if for x in i.get('addr_info',[])
               if x.get('family')=='inet')
        return a['local'],a['local']+'/'+str(a['prefixlen'])
    except Exception: return '10.66.44.1','10.66.44.0/24'


def install(args):
    if os.geteuid()!=0: die('Must run as root')
    if STATE.exists(): die(f'Existing installation detected: {STATE}; use uninstall.sh first')
    need_tools()
    pre={}
    # Each value may be set by CLI; otherwise interactive prompt or sensible default.
    name=args.container or prompt('Docker AWG container','amnezia-awg2')
    awgif=args.awg_interface or prompt('AWG interface inside container','awg0')
    ipdef,netdef=detect_defaults(name,awgif)
    pre['container']=name; pre['awg_if']=awgif
    pre['awg_addr']=args.awg_address or prompt('AWG internal IPv4 address',ipdef)
    pre['awg_net']=args.awg_cidr or prompt('AWG client CIDR',netdef)
    pre['mt_port']=args.mt_port or prompt('MTProxyL host TCP port','5443')
    pre['tunnel_port']=args.tunnel_port or prompt('Port for AWG clients to reach MTProxyL',pre['mt_port'])
    pre['ssh_port']=args.ssh_port or prompt('Current SSH TCP port (check only, never change)','22')
    pre['awg_udp_port']=args.awg_udp_port or prompt('AWG server UDP port','443')
    peers=args.moscow_ips
    if peers is None: peers=prompt('Future Moscow public IPv4(s), comma-separated (optional)','')
    pre['moscow_ips']=[x.strip() for x in peers.split(',') if x.strip()]
    pre['bridge_ip']=args.bridge_ip or ''
    pre['bridge_if']=args.bridge_if or ''
    pre['update_at']=args.update_at or prompt('Daily RU list update UTC HH:MM','04:25')
    c=validate_config(pre)
    log('Selected config: '+json.dumps(c,ensure_ascii=False))
    net=check_install(c)
    # Never silently overwrite existing firewall chains, ipsets or service files.
    for family in (4,6):
        for ch in (IN,OUT,FWD):
            if optional_rule(lambda *a,**k: ipt(family,*a,**k),('-S',ch)):
                die(f'Firewall chain {ch} already exists (IPv{family}); refusing ownership collision')
    for s in (RU4,RU6,RU4_TMP,RU6_TMP):
        if ipset_exists(s): die(f'IP set {s} already exists; refusing ownership collision')
    for unit in UNIT_FILES:
        if (UNIT_DIR/unit).exists(): die(f'Unit {unit} already exists')
    if CTL.exists() or UNINSTALL.exists(): die('Managed binary path already exists')
    # Refuse to claim ownership of rules from a partial previous run or an old installer.
    for family in (4,6):
        tool='iptables' if family==4 else 'ip6tables'
        for ch in ('INPUT','OUTPUT','FORWARD'):
            rule_lines=output([tool,'-S',ch])
            if TAG in rule_lines: die(f'Orphan {TAG} firewall rule found in IPv{family}/{ch}; manual recovery required')
        if family==4 and 'EU_AWG_MTP_IN' in output([tool,'-S','INPUT']):
            die('Legacy eu-awg3-guard detected; uninstall legacy configuration first')
    for table,chain in (('nat','PREROUTING'),('nat','POSTROUTING'),('filter','FORWARD')):
        q=['-t',table] if table!='filter' else []
        existing=cip(c,*q,'-S',chain,check=False,capture=True)
        if existing.returncode: die(f'Cannot inspect Docker {table}/{chain}')
        if TAG in existing.stdout: die('Orphan tagged AWG container rule found; manual recovery required')
    if Path('/etc/systemd/system/eu-awg3-guard.service').exists():
        die('Legacy eu-awg3-guard service found: remove it before deploying this standalone installer')
    ifup_conflict = is_ifupdown_conflict('eth0')
    wantfix = args.fix_ifupdown
    if ifup_conflict:
        log('Detected duplicate network ownership: ifupdown eth0 + active systemd-networkd/Netplan')
        if wantfix is None:
            wantfix=(prompt('Disable only old ifupdown eth0 stanza without network restart? y/N','N').lower()=='y')
        if not wantfix:
            log('WARNING: eth0 ifupdown conflict left unchanged (safe default).')
    else: wantfix=False
    if args.dry_run:
        with tempfile.TemporaryDirectory(prefix='euag3-dry-run-') as td:
            download_lists(Path(td))
        log('DRY RUN PASSED: preflight, ownership and list retrieval are valid. No changes were made.')
        return
    with tempfile.TemporaryDirectory(prefix='euag3-fetch-') as td:
        p4,p6=download_lists(Path(td))
        STATE.mkdir(mode=0o700)
        def interrupted(signum, frame):
            raise KeyboardInterrupt(f'Interrupted by signal {signum}')
        original_signals={x:signal.getsignal(x) for x in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP)}
        for x in original_signals: signal.signal(x,interrupted)
        try:
            cfg_temp=STATE/'config.json.new'
            cfg_temp.write_text(json.dumps(c,indent=2,ensure_ascii=False)+'\n')
            cfg_temp.chmod(0o600)
            os.replace(cfg_temp,CONFIG)
            BACKUP.mkdir(mode=0o700)
            run(['iptables-save'],capture=True)  # ensure availability before proceeding
            for fam,cmd in ((4,'iptables-save'),(6,'ip6tables-save')):
                (BACKUP/f'firewall-before-ipv{fam}.txt').write_text(output([cmd])+'\n')
            (BACKUP/'docker-before.txt').write_text(output(['docker','exec',c['container'],'iptables-save'])+'\n')
            (BACKUP/'network-routes-before.txt').write_text(output(['ip','route'])+'\n')
            shutil.copy2(Path(__file__),CTL); CTL.chmod(0o700)
            src=Path(__file__).with_name('uninstall.sh')
            if src.exists(): shutil.copy2(src,UNINSTALL)
            else:
                UNINSTALL.write_text('#!/usr/bin/env bash\n# EUAG3-MANAGED\nexec python3 /usr/local/sbin/euag3ctl uninstall "$@"\n')
            UNINSTALL.chmod(0o700)
            shutil.copy2(p4,STATE/'ru4.zone');shutil.copy2(p6,STATE/'ru6.zone')
            if wantfix: disable_ifupdown('eth0')
            update_sets(STATE/'ru4.zone',STATE/'ru6.zone')
            ensure_port_guard(c)
            ensure_geo(c,net)
            apply(c)
            write_units(c)
            run(['systemctl','enable','euag3-port.service','euag3-main.service',*TIMERS])
            # Never synchronously start our own ExecStart=euag3ctl service while
            # holding the exclusive euag3guard.lock: this causes a systemd deadlock.
            # Rules were already applied and tested in this installation process.
            # These enabled oneshot units will start normally on the next boot.
            # Smoke check after all modifications, no need to wait for our units.
            apply(c)
            for unit in TIMERS: run(['systemctl','start',unit])
            status(c)
            log('INSTALLATION COMPLETE. No reboot was performed.')
        except BaseException as error:
            # During rollback, do not interrupt midway on a second Ctrl-C.
            for x in original_signals: signal.signal(x,signal.SIG_IGN)
            log('INSTALL FAILED — automatic rollback started: '+str(error))
            try: cleanup(initial_failure=True)
            except BaseException as e: log('AUTOMATIC ROLLBACK INCOMPLETE: '+str(e))
            raise
        finally:
            for x,handler in original_signals.items(): signal.signal(x,handler)


def update(c):
    with tempfile.TemporaryDirectory(prefix='euag3-update-') as t:
        p4,p6=download_lists(Path(t))
        update_sets(p4,p6)
        shutil.copy2(p4,STATE/'ru4.zone.tmp')
        shutil.copy2(p6,STATE/'ru6.zone.tmp')
        os.replace(STATE/'ru4.zone.tmp',STATE/'ru4.zone')
        os.replace(STATE/'ru6.zone.tmp',STATE/'ru6.zone')
    log('IPdeny sets updated; existing rules and established connections preserved.')


def status(c):
    log('Configuration: '+json.dumps(c,ensure_ascii=False))
    for x in (RU4,RU6):
        p=run(['ipset','list',x],check=False,capture=True)
        if p.returncode: log(x+': not present')
        else:
            line=next((s for s in p.stdout.splitlines() if s.startswith('Number of entries:')),'?')
            log(x+': '+line)
    for f in (4,6):
        for chain in ('INPUT','OUTPUT','FORWARD'):
            p=ipt(f,'-S',chain,check=False,capture=True)
            for line in p.stdout.splitlines():
                if TAG in line: log('IPv'+str(f)+' '+line)
    try:
        n=container_network(c)
        log('Docker bridge: '+json.dumps({k:v for k,v in n.items() if k!='pid'}))
        p=cip(c,'-t','nat','-S','PREROUTING',check=False,capture=True)
        for line in p.stdout.splitlines():
            if TAG in line: log('Docker: '+line)
    except Exception as e: log('Docker not ready: '+str(e))
    for unit in ('euag3-port.service','euag3-main.service',*TIMERS):
        x=run(['systemctl','is-active',unit],check=False,capture=True).stdout.strip()
        log(unit+': '+x)


def main():
    if os.geteuid()!=0: die('Root required')
    ap=argparse.ArgumentParser(description='EUAWG3 guarded MTProxy and RU outgoing block')
    subs=ap.add_subparsers(dest='action',required=True)
    si=subs.add_parser('install',help='Interactive installation with auto rollback')
    for opt in ('container','awg-interface','awg-address','awg-cidr','mt-port','tunnel-port','ssh-port','awg-udp-port','bridge-ip','bridge-if','moscow-ips','update-at'):
        si.add_argument('--'+opt,default=None)
    si.add_argument('--dry-run',action='store_true',help='Check requirements and lists, do not change server')
    si.add_argument('--fix-ifupdown',action='store_true',default=None)
    si.add_argument('--no-fix-ifupdown',action='store_false',dest='fix_ifupdown')
    su=subs.add_parser('uninstall',help='Remove all changes owned by this installer')
    for name in ('status','apply','early','update','check'):
        sub=subs.add_parser(name)
        if name=='apply':sub.add_argument('--wait',type=int,default=0)
    args=ap.parse_args()
    # Serialize timer, install, update and uninstall (avoid overlapping ipset swaps).
    with open('/run/euag3guard.lock','w') as lock:
        deadline=time.monotonic()+180
        while True:
            try:
                fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic()>deadline: die('EUAG3 lock timeout; another operation is running')
                time.sleep(0.5)
        if args.action=='install': install(args)
        elif args.action=='uninstall': cleanup()
        else:
            c=get_config()
            if args.action=='status': status(c)
            elif args.action=='check':check_install(c)
            elif args.action=='apply':apply(c,wait_sec=args.wait)
            elif args.action=='early':apply(c,host_only=True)
            elif args.action=='update':update(c)

if __name__=='__main__':
    try: main()
    except Exception as e:
        log('ERROR: '+str(e))
        sys.exit(1)
