"""Additive host firewall provisioning; never flush rules or enable a firewall."""
import os
import shutil
import subprocess

def run(args):
    return subprocess.run(args,capture_output=True,text=True,timeout=30,env={**os.environ,'LC_ALL':'C'})

def ports_for(state):
    ports=set()
    if state.get('entry_domain'):ports.update([(80,'tcp'),(int(state.get('panel_port',18443)),'tcp')])
    selected=state.get('enabled_protocols',['reality'])
    fields={'reality':('port',['tcp']),'hysteria2':('hy2_port',['udp']),'tuic':('tuic_port',['udp']),'trojan':('trojan_port',['tcp']),'shadowsocks':('ss_port',['tcp','udp'])}
    for node in state.get('nodes',[]):
        if not node.get('enabled',True):continue
        for protocol in selected:
            field,transports=fields[protocol]
            for transport in transports:ports.add((int(node[field]),transport))
    if any(not 1<=p<=65535 for p,_ in ports):raise ValueError('防火墙端口无效')
    return sorted(ports)

def ensure(ports):
    ports=sorted(set(ports))
    if any(not isinstance(p,int) or not 1<=p<=65535 or t not in ['tcp','udp'] for p,t in ports):raise ValueError('防火墙端口无效')
    ufw=run(['ufw','status']) if shutil.which('ufw') else None
    if ufw and ufw.returncode:raise ValueError('无法读取 UFW 状态，请检查权限或配置后重试')
    firewalld=run(['firewall-cmd','--state']) if shutil.which('firewall-cmd') else None
    active_ufw=bool(ufw and ufw.returncode==0 and 'Status: active' in ufw.stdout)
    active_firewalld=bool(firewalld and firewalld.returncode==0 and firewalld.stdout.strip()=='running')
    if active_ufw and active_firewalld:raise ValueError('同时启用了 UFW 与 firewalld，请先统一防火墙管理方式')
    if active_ufw:
        for port,transport in ports:
            result=run(['ufw','allow',str(port)+'/'+transport,'comment','Relay Console'])
            if result.returncode:raise ValueError('UFW 放行失败：'+str(port)+'/'+transport+'，请检查防火墙后重试')
        return {'manager':'ufw','ports':ports}
    if active_firewalld:
        zones=run(['firewall-cmd','--get-active-zones'])
        if zones.returncode:raise ValueError('无法读取 firewalld 活动区域')
        names=[line.strip() for line in zones.stdout.splitlines() if line and not line[0].isspace()]
        if len(names)!=1:raise ValueError('firewalld 活动区域不唯一，请手动确认入口网卡区域并放行节点端口')
        for port,transport in ports:
            for extra in [[],['--permanent']]:
                result=run(['firewall-cmd','--zone='+names[0],*extra,'--add-port='+str(port)+'/'+transport])
                if result.returncode:raise ValueError('firewalld 放行失败：'+str(port)+'/'+transport)
        return {'manager':'firewalld','ports':ports}
    # An ACCEPT in a separate nftables base chain cannot override another chain's DROP.
    # Refuse blind edits to custom rule sets instead of claiming a port is open.
    if shutil.which('nft'):
        result=run(['nft','-j','list','ruleset'])
        if result.returncode:raise ValueError('无法检查 nftables，请确认防火墙状态后重试')
        text=result.stdout.lower()
        if any(token in text for token in ['"drop"','"reject"']):raise ValueError('检测到自定义 nftables 拦截规则，请手动放行所需端口后再安装；支持自动管理 UFW 或 firewalld')
    for binary in ['iptables','ip6tables']:
        if not shutil.which(binary):continue
        result=run([binary,'-S','INPUT'])
        if result.returncode:raise ValueError('无法检查 '+binary+' INPUT 规则')
        if any(token in result.stdout for token in ['-P INPUT DROP','-P INPUT REJECT','-j DROP','-j REJECT','-j ']):raise ValueError('检测到自定义 '+binary+' INPUT 规则，请先确认节点端口放行；支持自动管理 UFW 或 firewalld')
    return {'manager':'no-managed-firewall','ports':ports}

def provision(state):
    if state.get('firewall_managed'):return ensure(ports_for(state))
    return {'manager':'legacy-unchanged','ports':[]}
