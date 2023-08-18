#!/usr/bin/env python

# python
import logging
import unittest
from unittest.mock import Mock
from randmac import RandMac
import macaddress
import json    
import time
import os
from IxNetwork import IxNet
from ats.log.utils import banner

# Genie package
from genie.tests.conf import TestCase
from genie.conf import Genie
from genie.conf.base import Testbed, Device, Link, Interface

# xBU-shared genie pacakge
from genie.libs.conf.interface import TunnelTeInterface
from genie.libs.conf.base import MAC, IPv4Interface, IPv6Interface, IPv4Address, IPv6Address
from genie.libs.conf.interface import Layer, L2_type, IPv4Addr, IPv6Addr,NveInterface
from genie.libs.conf.vrf import Vrf
from genie.libs.conf.interface.nxos import Interface
from genie.conf.base.attributes import UnsupportedAttributeWarning
from netaddr.ip import IPNetwork, IPAddress

# Vpc
from genie.libs.conf.vpc import Vpc
from genie.libs.conf.interface.nxos import LoopbackInterface
from genie.libs.conf.interface.nxos import SubInterface

from genie.libs.conf.ospf import Ospf

logger = logging.getLogger(__name__)

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# import genie.libs
from genie.libs.conf.bgp import Bgp
import time
from ipaddress import *   
 
import re

def fhsCliCheck(uut):
    op = uut.execute("show run dhcp")
    for cli in ['ip verify source dhcp-snooping-vlan','evpn','ip verify source dhcp-snooping-vlan','ip arp inspection vlan ']:
        if not cli in op:
            return 0
    return 1    
def format_mac(mac: str) -> str:
    mac = re.sub('[.:-]', '', mac).lower()  # remove delimiters and convert to lower case
    mac = ''.join(mac.split())  # remove whitespaces
    assert len(mac) == 12  # length should be now exactly 12 (eg. 008041aefd7e)
    assert mac.isalnum()  # should only contain letters and numbers
    # convert mac in canonical form (eg. 00:80:41:ae:fd:7e)
    mac = ":".join(["%s" % (mac[i:i+2]) for i in range(0, 12, 2)])
    return mac


def ipsgDaiCheck(sw,sw_svi_mac):
    sw.configure("clear ip arp force-delete")
    sw.configure("ping 4.5.0.1") 
    if not '0000.2222.3333' in sw.configure("show ip arp"):
        log.info("GW ARP Not resolved")
        return 0
    if not '64 bytes from 4.5.0.15: icmp_seq=2' in sw.configure("ping 4.5.0.15"):
        log.info("Non E2E traffic ")
        return 0         
    cfg1 = \
    """
    interface vlan 1005
    no ip address dhcp
    ip address 4.5.0.99/16
    no sh
    """    
    cfg2 = \
    """
    interface vlan 1005
    no ip address  
    no sh
    ip address dhcp
    """   

    sw.configure(cfg1)
    sw.configure("clear ip arp force-delete")

    countdown(10)

    sw.configure("ping 4.5.0.1") 
    if '0000.2222.3333' in sw.configure("show ip arp"):
        accessSWSviConf(sw,sw_svi_mac)
        return 0    
    if '64 bytes from 4.5.0.15: icmp_seq=2' in sw.configure("ping 4.5.0.15"):
        accessSWSviConf(sw,sw_svi_mac)
        return 0   
    accessSWSviConf(sw,sw_svi_mac)
    return 1
    

def ipsgCliCheck(uut,ip_address,interface):
    op1= uut.execute(f"sh ip verify source interface {interface}")
    if not ip_address in op1:
        return 0
    return 1


def clearIpDhcpBinding(leaf1,sw1):
    cfg1 = \
    """
    interface vlan 1005
    no ip address dhcp
    ip address 4.5.0.99/16
    no sh
    sleep 2
    no ip address 4.5.0.99/16
    ip address dhcp  
    """    

    sw1.configure(cfg1)

    countdown(30)

    leaf1.configure('clear ip dhcp snooping binding interface port-channel11')
    sw1.configure("ping 4.5.0.1") 
    if '0000.2222.3333' in sw1.configure("show ip arp"):
        sw1.configure(cfg1)
        return 0    
    if '64 bytes from 4.5.0.15: icmp_seq=2' in sw1.configure("ping 4.5.0.15"):
        sw1.configure(cfg1)
        return 0  
    sw1.configure(cfg1)    
    return 1   
 

def checkdhcpBinding(uut,snoopDict,leaf_uut_list):

    for leaf in leaf_uut_list:
        op1 = leaf.execute("show ip dhcp snooping binding | inc static")
        for line in op1.splitlines():
            if 'static' in line or 'dhcp-snoop' in line :
                mac1 = line.split()[0]
                ip1 = line.split()[1]
                leasetime = line.split()[2]
                type = line.split()[3]
                vlan = line.split()[4]
                inteface = line.split()[5]
                if ip1 in snoopDict.keys(): 
                    if mac1 == format_mac(snoopDict[ip1]):
                        print("Found Snooping entry")
                    else:
                        return False

    return True  
                         
 
def checkCore(uut):
    op = uut.execute('sh core | excl PID | exc --')
    if 'core' in op:
        print(f"Core found in {uut.name}")
        return False 
    return 1
    

def checksnoopBinding(uut,snoop_mac_list):

    snoop_mac_list2 = []
    for mac in snoop_mac_list:
        snoop_mac_list2.append(format_mac(mac))

    if 'crash' in uut.execute('show core'):
        print(f"Core found in {uut.name}")
        return False 

    op1 = uut.execute("show ip dhcp snooping binding ")
    for mac in snoop_mac_list2:
        if not mac in op1:
            log.info("++"*10)                
            log.info(f"MAC {mac} not found in {uut.name}")
            log.info(f'snooping table is {op1}')
            log.info("++"*10)     
            return False                   
    return True  
                        

def CreateDhcpClient(chassisIP):
    pass


def saveConf(uut):
    uut.configure('end')
    uut.execute('copy run start')


def fhsCliEnable(uut,conf_dict):
    
    vlan_list = conf_dict['vxlan_fhs'][uut.name]['vlan_list']
    port_list = conf_dict['vxlan_fhs'][uut.name]['port_list']
    test_vlan = vlan_list[0]

    uut.configure('feature dhcp')
    uut.configure('ip dhcp snooping')
    for vlan in vlan_list:
        uut.configure(f'ip dhcp snooping vlan {vlan} evpn')

    for vlan in vlan_list:
        uut.configure(f'ip arp inspection vlan  {vlan}')

    cfg1 = \
        """
        """
    for port in port_list:
        cfg1 +=f'interface {port} \n'
        cfg1 +=f'ip verify source dhcp-snooping-vlan \n'

    uut.configure(cfg1,timeout=300)


def dhcpStaticBinding(uut,conf_dict):

    vlan = conf_dict['dhcp_static'][uut.name]['profile1']['vlan']
    intf = conf_dict['dhcp_static'][uut.name]['profile1']['interface']  
    ipaddress = conf_dict['dhcp_static'][uut.name]['profile1']['ip_address_start']
    scale = conf_dict['dhcp_static'][uut.name]['profile1']['scale']
    cfg = \
        """
        """
    staticDict = {}    
    mac = macGenerator()
    for i in range(scale):
        mac1 = mac
        cfg += f"ip source binding {ipaddress} {mac} vlan {vlan} interface {intf} \n"
        staticDict[str(ipaddress)] = mac  
        ipaddress = ip_address(ipaddress)+1
        mac = macGenerator()
        if mac == mac1:
            mac = macGenerator()  
                    

    print(cfg)
    uut.configure(cfg,timeout=300)
    print(conf_dict)
    return(staticDict)


def hostMoveSetup(uut,conf_dict):
    vlan_list = conf_dict['host_move'][uut.name]['vlan_list']
    port_list = conf_dict['host_move'][uut.name]['port_list']

    test_vlan = vlan_list[0]
    port_list_all = []
    for line in uut.execute(f'show span vl {test_vlan} | inc FWD').splitlines():
        if not 'peer-link' in line:
            port = line.split()[0]
            port_list_all.append(port)
    cfgnone = \
        """
        """
    for port in port_list_all:
        cfgnone += f'interface {port} \n'
        cfgnone += f'switchport trunk allowed vlan none \n'

    uut.configure(cfgnone) 

    cfg1 = \
        """
        """
    for port in port_list:
        for vlan in vlan_list:
            cfg1 += f'interface {port} \n'
            cfg1 += f'switchport trunk allowed vlan {vlan} \n'

    uut.configure(cfg1) 


def macGenerator():
    mac1 = str(RandMac("00:00:00:00:00:00", True)).replace("'","")
    segments = mac1.split(':')
    groups = [segments[0:2], segments[2:4], segments[4:]]
    a = [''.join(group) for group in groups]
    mac = '.'.join(a)
    return mac 


def countdown(t):
    t1 = t
    logger.info(f'Start countdown for {t} seconds')
    while t:
        mins, secs = divmod(t, 60)
        timeformat = '{:02d}:{:02d}'.format(mins, secs)
        print("Countdown - ",timeformat, end='\r')
        time.sleep(1)
        t -= 1
    logger.info(f'Completed countdown for {t1} seconds')

 
def confBgp(dev,conf_dict): 
    
    as_number = conf_dict['bgp']['ibgp']['as_number']
    router_id = conf_dict['bgp']['ibgp'][dev.name]['router_id']
    neigh_list = conf_dict['bgp']['ibgp'][dev.name]['neigh_list']


    bgp = Bgp(bgp_id=as_number)
    af_name = 'l2vpn evpn'
    vrf = Vrf('default')
    bgp.device_attr[dev].vrf_attr[vrf].address_family_attr[af_name].af_advertise_pip = True
    neighbor_id = '10.0.0.1'
    for neighbor_id in neigh_list:
        bgp.device_attr[dev].vrf_attr[vrf].neighbor_attr[neighbor_id].nbr_remote_as = as_number
        bgp.device_attr[dev].vrf_attr[vrf].neighbor_attr[neighbor_id].nbr_update_source = 'loopback0'
        bgp.device_attr[dev].vrf_attr[vrf].neighbor_attr[neighbor_id].address_family_attr[af_name].nbr_af_send_community = 'both'

    if 'spine' in dev.name:
        bgp1.device_attr[dev1].vrf_attr[vrf].neighbor_attr[neighbor_id].address_family_attr[af_name].nbr_af_route_reflector_client = True

    dev.add_feature(bgp)
    cfgs = bgp.build_config(apply=False)
    
    # Defining attributes
    af_name = 'ipv4 mvpn'
    vrf = Vrf('default')


def accessSWSviConf(uut,mac):
    cfg =\
    """
    feature interface-vlan
    no interface vlan 1005
    interface vlan 1005
    no shut
    sleep 2
    mac-address {mac}
    ip address dhcp

    """
    uut.configure(cfg.format(mac=mac))


def find_svi_ip(uut,svi):
    cmd = uut.execute("show int vlan {vlan} | json-pretty".format(vlan=svi))
    if not "svi_ip_addr" in str(cmd):
        log.info('svi_ip_addr found,Test failed')
        return 0
                
    else: 
        test1=json.loads(cmd)   
        ip = test1["TABLE_interface"]["ROW_interface"]["svi_ip_addr"]
        return ip 


def sviPing(uut1,uut2):
    ip1 = find_svi_ip(uut1,'1005')
    if not ip1:
        return 0
    ip2 = find_svi_ip(uut2,'1005')
    if not ip2:
        return 0
    

def find_loop_ip(uut,loop):
    cmd = uut.execute("show int loopb {loop} | json-pretty".format(loop=loop))
    if not "eth_ip_addr" in str(cmd):
        log.info('svi_ip_addr found,Test failed')
        return 0
                
    else: 
        test1=json.loads(cmd)   
        ip = test1["TABLE_interface"]["ROW_interface"]["eth_ip_addr"]
        return ip        


def dhcpCleanup(uut):
    op = uut.execute("sh run | inc 'ip source bindin'")
    for line in op.splitlines():
        if 'binding' in line:
            uut.configure(f"no {line}")
    uut.configure("clear ip dhcp snooping binding")


def snoop(uut):
    cfg = \
    """
    conf t
    
    hardware access-list tcam region ing-racl 256
    hardware access-list tcam region egr-racl 256
    hardware access-list tcam region ing-sup 768

    feature dhcp
    ip dhcp snooping vlan 1001 evpn

    copy run start
    y
    reload
    y

    """


def spineBgpConf(spine):
    
    cfg =\
        """
        router bgp 65535
        router-id 100.1.1.2

        template peer leaf_nodes
        bfd
        update-source loopback1
        address-family l2vpn evpn
        send-community both
        route-reflector-client
        neighbor 1.1.100.12 remote-as 65535
        inherit peer leaf_nodes
        neighbor 1.1.100.22 remote-as 65535
        inherit peer leaf_nodes
        neighbor 1.1.100.32 remote-as 65535
        inherit peer leaf_nodes

        """
    spine.configure(cfg)


def vxlanRouteAdd(uut,conf_dict):
    cmd = uut.execute("sh bgp all summary | json-pretty ")
    test1=json.loads(cmd)   
    as_number = test1["TABLE_vrf"]["ROW_vrf"]["vrf-local-as"]
    interface = conf_dict['vxlan_route'][uut.name]['interface']
    ip_address = conf_dict['vxlan_route'][uut.name]['ip_address']
    vrf = conf_dict['vxlan_route'][uut.name]['vrf']

    cfg = \
        """
        """
    cfg += f'interface {interface}\n'
    cfg += f'vrf member {vrf}\n'
    cfg += f'ip address {ip_address}\n'
    cfg += f'no shut\n'
    cfg += f'router bgp {as_number}\n'
    cfg += f'vrf {vrf}\n'
    cfg += f'address-family ipv4 unicast\n'
    cfg += f'network {ip_address}\n'
 
    uut.configure(cfg,timeout=300) 


def configVxlanLeaf(uut,conf_dict):
    l2_vlan_start = conf_dict['vxlan']['l2_vlan_start']
    l2_vlan_scale = conf_dict['vxlan']['l2_vlan_scale']
    l2_vni_start = conf_dict['vxlan']['l2_vni_start']
    l3_vlan_start = conf_dict['vxlan']['l3_vlan_start']    
    l3_vlan_scale = conf_dict['vxlan']['l3_vlan_scale']
    l3_vni_start = conf_dict['vxlan']['l3_vni_start']
    ipaddress = conf_dict['vxlan']['ip_address']
    ipv6address = conf_dict['vxlan']['ipv6_address']
    l2vlan_per_vrf = int(l2_vlan_scale/l3_vlan_scale)
    mcast_group_start = conf_dict['vxlan']['mcast_group_start']
    uut.configure('no vlan 100-1200')
    uut.configure('no interface nve 1')

    cfg = \
        """
        feature interface-vlan
        feature lacp
        feature bfd
        feature nv overlay
        nv overlay evpn        
        feature vn-segment-vlan-based
        """

    l2_vlan = l2_vlan_start
    l2_vni = l2_vni_start
    if 'N9K' in uut.execute("show module"):
        cfg += f'feature fabric forwarding\n'

    for i in range(l2_vlan_scale):        
        cfg += f'vlan {l2_vlan}\n'
        cfg += f'vn-seg {l2_vni}\n'   
        l2_vni = l2_vni+1 
        l2_vlan = l2_vlan+1

    uut.configure(cfg,timeout=300)

    cfg = \
        """
        """

    l3_vlan = l3_vlan_start
    l3_vni = l3_vni_start

    for i in range(l3_vlan_scale):
        cfg += f'vlan {l3_vlan}\n'
        cfg += f'vn-seg {l3_vni}\n' 
        l3_vlan = l3_vlan+1  
        l3_vni = l3_vni+1 
 
    uut.configure(cfg,timeout=300)
 
    cfg = \
        """
        """

    l3_vni = l3_vni_start
    l3_vlan = l3_vlan_start

    vrf_list = []
    for i in range(l3_vlan_scale):
        vrf = 'vxlan-'+str(l3_vni)
        vrf_list.append(vrf)
        cfg += f'vrf context {vrf}\n'
        cfg += f'vni {l3_vni}\n'
        cfg += f'rd auto\n'
        cfg += f'address-family ipv4 unicast\n'
        cfg += f'route-target both auto\n'
        cfg += f'route-target both auto evpn\n'
        cfg += f'address-family ipv6 unicast\n'
        cfg += f'route-target both auto\n'
        cfg += f'route-target both auto evpn\n'
        cfg += f'interface Vlan {l3_vlan}\n'
        cfg += f'no shutdown\n'
        cfg += f'vrf member {vrf}\n'
        cfg += f'ip forward\n'
        l3_vni = l3_vni+1  
        l3_vlan = l3_vlan+1 

    uut.configure(cfg,timeout=300)

    cfg = \
        """
        """
        
    l2_vlan = l2_vlan_start
    l2_vni = l2_vni_start
    l3_vlan = l3_vlan_start
    l3_vni = l3_vni_start

    vrf_vlan_dict = {}

    for i in range(l3_vlan_scale):
        vrf = 'vxlan-'+str(l3_vni)
        vlan_list = []
        for j in range(l2vlan_per_vrf): 
            cfg += f'no interface Vlan {l2_vlan}\n'
            cfg += f'interface Vlan {l2_vlan}\n'
            cfg += f'no shutdown\n'
            cfg += f'vrf member {vrf}\n'
            cfg += f'ip address {ipaddress}/16\n'
            cfg += f'ipv6 address  {ipv6address}/96\n'
            cfg += f'fabric forwarding mode anycast-gateway\n'
            ipaddress = ip_address(ipaddress)+65536
            ipv6address = ip_address(ipv6address)+1024
            l2_vlan = l2_vlan+1
        l3_vni = l3_vni+1

    uut.configure(cfg,timeout=300)

    l2_vlan_start = conf_dict['vxlan']['l2_vlan_start']
    l2_vni_start = conf_dict['vxlan']['l2_vni_start']
    l3_vlan_start = conf_dict['vxlan']['l3_vlan_start']    
    l3_vni_start = conf_dict['vxlan']['l3_vni_start']

    cfg = \
        """
        """
    cfg += f'no interface nve1\n'
    cfg += f'interface nve1\n'
    cfg += f'no shutd\n'
    cfg += f'source-interface loopback0\n'
    cfg += f'host-reachability protocol bgp\n'

    for i in range(l3_vlan_scale):
        cfg += f'member vni {l3_vni_start} associate-vrf\n'
        l3_vni_start = l3_vni_start+1

    l2_vlan_start = conf_dict['vxlan']['l2_vlan_start']
    l2_vni_start = conf_dict['vxlan']['l2_vni_start']
    l3_vlan_start = conf_dict['vxlan']['l3_vlan_start']    
    l3_vni_start = conf_dict['vxlan']['l3_vni_start']

    cfg += f'member vni {l2_vni_start}\n'
    cfg += f' ingress-replication protocol bgp\n'

    for i in range(l3_vlan_scale):
        cfg += f'member vni {l2_vni_start+1}-{l2_vni_start+l2vlan_per_vrf-1}\n'
        cfg += f'mcast-group {mcast_group_start}\n'
        mcast_group_start = ip_address(mcast_group_start)+1
        l2_vni_start = l2_vni_start+l2vlan_per_vrf-1

    uut.configure(cfg,timeout=300)

    l2_vlan_start = conf_dict['vxlan']['l2_vlan_start']
    l2_vni_start = conf_dict['vxlan']['l2_vni_start']
    l3_vlan_start = conf_dict['vxlan']['l3_vlan_start']    
    l3_vni_start = conf_dict['vxlan']['l3_vni_start']

    cmd = uut.execute("sh bgp all summary | json-pretty ")
    test1=json.loads(cmd)   
    as_number = test1["TABLE_vrf"]["ROW_vrf"]["vrf-local-as"]
 
    cfg = \
        """
        """
    cfg += f'router bgp {as_number}\n'

    for i in range(l3_vlan_scale):
        vrf = 'vxlan-'+str(l3_vni_start)
        cfg += f'vrf {vrf}\n'
        cfg += f'address-family ipv4 unicast\n'
        cfg += f'advertise l2vpn evpn\n'
        l3_vni_start = l3_vni_start+1

    uut.configure(cfg,timeout=300)

    l2_vlan_start = conf_dict['vxlan']['l2_vlan_start']
    l2_vni_start = conf_dict['vxlan']['l2_vni_start']
    l3_vlan_start = conf_dict['vxlan']['l3_vlan_start']    
    l3_vni_start = conf_dict['vxlan']['l3_vni_start']
 
    cfg = \
        """
        evpn
        """
    l2_vni = l2_vni_start
    for i in range(l2_vlan_scale):        
        cfg += f'vni {l2_vni} l2\n'   
        cfg += f'rd auto\n' 
        cfg += f'route-target import auto\n' 
        cfg += f'route-target export auto\n' 
        l2_vni = l2_vni+1 

    uut.configure(cfg,timeout=300)


def leafConfig(leaf):

    op = leaf.execute("sh run int lo0")

    cfg = \
    """
    router bgp 65535
    neighbor 100.1.1.2 remote-as 65535
        bfd
        update-source loopback1
        address-family l2vpn evpn
        send-community both
        router bgp 65535
        address-family ipv4 unicast

    """
    for line in op.splitlines():
        if 'address' in line:
            network = line.split()[2]
            pass

    leaf.configure(cfg)


def dciebgpConfigure(uut,conf_dict):
    
    router_id = conf_dict['bgp']['ebgp'][uut.name]['router_id']
    as_number = conf_dict['bgp']['ebgp'][uut.name]['as_number']
    neigh_list = conf_dict['bgp']['ebgp'][uut.name]['neigh_list'].keys()
 
    cfg = \
        """
        ip prefix-list redistribute-direct-underlay seq 5 permit 0.0.0.0/0 le 32
        route-map redistribute-direct-underlay permit 10
        match ip address prefix-list redistribute-direct-underlay 
        """
    cfg+= f"router bgp {as_number}\n"
    cfg+= f"router-id {router_id}\n"
    cfg+= "address-family ipv4 unicast\n"
    cfg+= "redistribute direct route-map redistribute-direct-underlay\n"

    for neighbor in neigh_list:
        remote_as = conf_dict['bgp']['ebgp'][uut.name]['neigh_list'][neighbor]['remote_as']
        update_source = conf_dict['bgp']['ebgp'][uut.name]['neigh_list'][neighbor]['update_source']
        cfg+= f"neighbor {neighbor} remote-as {remote_as}\n"
        cfg+= "bfd\n"
        cfg+= f"update-source {update_source}\n"
        cfg+= "address-family ipv4 unicast\n"

    uut.configure(cfg)


def dcievpnbgpConfigure(uut,conf_dict):

    as_number = conf_dict['bgp']['ebgpl2vpn'][uut.name]['as_number']
    neigh_list = conf_dict['bgp']['ebgpl2vpn'][uut.name]['neigh_list'].keys()
 
    cfg = \
        """
        feature bgp
        """
    cfg+= f"router bgp {as_number}\n"

    for neighbor in neigh_list:
        remote_as = conf_dict['bgp']['ebgpl2vpn'][uut.name]['neigh_list'][neighbor]['remote_as']
        update_source = conf_dict['bgp']['ebgpl2vpn'][uut.name]['neigh_list'][neighbor]['update_source']
        cfg+= f"neighbor {neighbor} remote-as {remote_as}\n"
        cfg+= f"update-source {update_source}\n"
        cfg+= "ebgp-multihop 255\n"
        cfg+= "address-family l2vpn evpn\n"
        cfg+= "ebgp-multihop 255\n"
        if 'bgw' in uut.name:
            cfg+= "peer-type fabric-external\n"
        cfg+= "address-family l2vpn evpn\n"
        cfg+= "send-community\n"
        cfg+= "send-community extended\n"
        cfg+= "rewrite-evpn-rt-asn\n"        
    uut.configure(cfg)


def bgpmvpnConfigure(uut,conf_dict):
    
    if uut.name in conf_dict['bgp']['mvpn'].keys():
        if not str(31) in uut.name:
            as_number = conf_dict['bgp']['mvpn'][uut.name]['as_number']
            neigh_list = conf_dict['bgp']['mvpn'][uut.name]['neigh_list'].keys()    
            cfg = \
                """
                router bgp {as_number}
                address-family ipv4 mvpn
                maximum-paths 32
                retain route-target all
                """
            for neighbor in neigh_list:
                remote_as = conf_dict['bgp']['mvpn'][uut.name]['neigh_list'][neighbor]['remote_as']
                cfg+= f"neighbor {neighbor} remote-as {remote_as}\n"
                cfg+= "address-family ipv4 mvpn\n"
                cfg+= "send-community\n"
                cfg+= "send-community extended\n"
                
            uut.configure(cfg.format(as_number=as_number))


def bgwmultisiteconfig(uut,conf_dict):
    as_number = conf_dict['multisite'][uut.name]['as_number']
    dci_intf_list = []
    fabric_intf_list = []

    op1 = uut.execute("show ip ospf nei")
    for line in op1.splitlines():
        if 'FULL' in line:
            intf = line.split()[-1]
            fabric_intf_list.append(intf)

    op2 = uut.execute("show ip interface brief")
    for line in op2.splitlines():
        if '44.1' in line:
            intf = line.split()[0]
            dci_intf_list.append(intf)

    cfg = \
        """
        """

    cfg+= f"evpn multisite border-gateway {as_number}\n"
    cfg+= f"delay-restore time 30 \n"

    uut.configure(cfg)
 
    cfg = \
        """
        interface nve1
        multisite border-gateway interface loopback88
        member vni 201002-201010
            multisite ingress-replication
        member vni 201011-201019
            multisite ingress-replication
        member vni 900101 associate-vrf
        member vni 900102 associate-vrf
        """
    for intf in dci_intf_list:
        cfg+= f"interface {intf} \n"
        cfg+= f"evpn multisite dci-tracking\n"          
    for intf in fabric_intf_list:
        cfg+= f"interface {intf} \n"
        cfg+= f"evpn multisite fabric-tracking\n"       

    uut.configure(cfg) 


def dccdciebgpConfigure(uut,conf_dict):
    router_id = conf_dict['bgp']['ebgp'][uut.name]['router_id']
    as_number = conf_dict['bgp']['ebgp'][uut.name]['as_number']
    neigh_list = conf_dict['bgp']['ebgp'][uut.name]['neigh_list'].keys()
 
    cfg = \
        """
        ip prefix-list redistribute-direct-underlay seq 5 permit 0.0.0.0/0 le 32
        route-map redistribute-direct-underlay permit 10
        match ip address prefix-list redistribute-direct-underlay 
        """
    cfg+= f"router bgp {as_number}\n"
    cfg+= f"router-id {router_id}\n"
    cfg+= "address-family ipv4 unicast\n"
    cfg+= "redistribute direct route-map redistribute-direct-underlay\n"

    for neighbor in neigh_list:
        remote_as = conf_dict['bgp']['ibgp'][uut.name]['neigh_list'][neighbor]['remote_as']
        update_source = conf_dict['bgp']['ibgp'][uut.name]['neigh_list'][neighbor]['update_source']
        cfg+= f"neighbor {neighbor} remote-as {remote_as}\n"
        cfg+= "bfd\n"
        cfg+= f"update-source {update_source}\n"
        cfg+= "address-family ipv4 unicast\n"

    uut.configure(cfg)


def ibgpConfigure(uut,conf_dict):
 
    router_id = conf_dict['bgp']['ibgp'][uut.name]['router_id']
    as_number = conf_dict['bgp']['ibgp'][uut.name]['as_number']
    neigh_list = conf_dict['bgp']['ibgp'][uut.name]['neigh_list']
 
    cfg = \
        """
        feature bgp
        """
    cfg+= f"no router bgp {as_number}\n"
    cfg+= f"router bgp {as_number}\n"
    cfg+= f"router-id {router_id}\n"
    for neighbor in neigh_list:
        cfg+= f"neighbor {neighbor} remote-as {as_number}\n"
        cfg+= "bfd\n"
        cfg+= "update-source loopback1\n"
        cfg+= "address-family l2vpn evpn\n"
        cfg+= "send-community both\n"
        if 'SPINE' in uut.name:
            cfg+= "route-reflector-client \n"

    uut.configure(cfg)
    

def clearMac(uut):
    uut.execute('clear mac address-table dynamic ')


def pimConfig(uut,conf_dict):

    ssm_range = conf_dict['pim']['ssm_range']
    pim_rp_address = conf_dict['pim']['pim_rp_address']

    cfg =\
    f"""    
    ip pim rp-address {pim_rp_address} group-list 224.0.0.0/4
    ip pim ssm range {ssm_range}
    """
    op1= uut.execute("show ip interf brie")
    intf_list = []
        
    for line in op1.splitlines():
        if "Lo" in line:
            intf = line.split()[0]
            cfg += f" interface {intf} \n"
            cfg +=  "ip pim sparse-mode \n"
            uut.configure(cfg,timeout=300)
        elif "Po" in line:
            intf = line.split()[0]
            cfg += f" interface {intf} \n"
            cfg +=  "ip pim sparse-mode \n"
            uut.configure(cfg,timeout=300)
        elif 'Eth' in line:       
            intf = line.split()[0]
            cfg += f" interface {intf} \n"
            cfg +=  "ip pim sparse-mode \n"
    uut.configure(cfg,timeout=300)   


def pimConfigMs(uut,ssm_range,pim_rp_address):

    cfg =\
    f"""    
    ip pim rp-address {pim_rp_address} group-list 224.0.0.0/4
    ip pim ssm range {ssm_range}
    """
    op1= uut.execute("show ip interf brie")
    intf_list = []
        
    for line in op1.splitlines():
        if "Lo" in line:
            intf = line.split()[0]
            cfg += f" interface {intf} \n"
            cfg +=  "ip pim sparse-mode \n"
            uut.configure(cfg,timeout=300)
        elif "Po" in line:
            intf = line.split()[0]
            cfg += f" interface {intf} \n"
            cfg +=  "ip pim sparse-mode \n"
            uut.configure(cfg,timeout=300)
        elif 'Eth' in line:       
            intf = line.split()[0]
            cfg += f" interface {intf} \n"
            cfg +=  "ip pim sparse-mode \n"
    uut.configure(cfg,timeout=300)   


def preSetupVxlan(uut):
    clearIPConf(uut)

    cfg = \
    """
    no feature ospf
    no feature bgp
    no feature nv overlay
    no feature lacp
    no feature pim
    no vlan 2-3000
    no feature dhcp
    clear cores
    """
    cfg2 = \
    """
    vlan 1001-1101
    no shut
    feature ospf
    feature bgp
    feature nv overlay
    feature lacp
    feature pim
    nv overlay evpn
    feature interface-vlan
    feature vn-segment-vlan-based
    fabric forwarding anycast-gateway-mac 0000.2222.3333
    feature bfd
    bfd interval 300 min_rx 300 multiplier 3
    bfd multihop interval 999 min_rx 999 multiplier 10
    ntp server 10.64.58.51 use-vrf management 
    ntp server 72.163.32.44 use-vrf management 
    system jumbomtu 9216
    """
    uut.configure(cfg,timeout=300)
    time.sleep(10)
    uut.configure(cfg2,timeout=300)
    clearVrfConf(uut)
    cleararpConf(uut)


def cleararpConf(uut):
    cfg3 = \
    """
    """
    for line in uut.execute('sh run | inc arp').splitlines():
        if 'inspection' in line:
            cfg3 +=f'no {line}'

    uut.configure(cfg3,timeout=300)   


def cleardhcpConf(uut):
    uut.configure('no feature dhcp',timeout=300)   
 
 
def clearVrfConf(uut):
    cfg3 = \
    """
    """
    for line in uut.execute('show vrf').splitlines():
        if 'vxlan' in line:
            vrf = line.split()[0]
            cfg3 +=f'no vrf context {vrf} \n'

    uut.configure(cfg3,timeout=300)        


def clearIPConf(uut):
    op1= uut.execute("show interf brie")
    intf_list = []
    cfg = \
        """
        """        
    for line in op1.splitlines():
        if "Lo" in line:
            intf = line.split()[0]
            intf_list.append(intf)
        elif "Po" in line:
            intf = line.split()[0]
            intf_list.append(intf)

    for intf in intf_list:
            cfg +=  f"no interface {intf} \n"

    uut.configure(cfg,timeout=300)        


def configureLoopInterface1(uut,conf_dict):
   for intf in conf_dict['interfaces'][uut.name]['loopback']:
        ip_add = conf_dict['interfaces'][uut.name]['loopback'][intf]['ip_add']
        description = conf_dict['interfaces'][uut.name]['loopback'][intf]['Description']
        prefix_length = conf_dict['interfaces'][uut.name]['loopback'][intf]['prefix_length']        

        Loopif = SubInterface(name=intf,device=uut)    
        Loopif.description = description
        Loopif.ipv4 = ip_add
        Loopif.ipv4.netprefix_length = prefix_length
        Loopif.shutdown = False
    
        cfgs = Loopif.build_config(apply=False)

        if 'ip_add_secondary' in conf_dict['interfaces'][uut.name]['loopback'][intf]:
            ip_add_secondary = conf_dict['interfaces'][uut.name]['loopback'][intf]['ip_add_secondary']
            cfgs += f"\n ip address {ip_add_secondary} secondary\n "
            
        uut.configure(cfgs)


def configureLoopInterface(uut,conf_dict):
   for intf in conf_dict['interfaces'][uut.name]['loopback']:
        intf1 = Interface(name=intf, device=uut)
        ip_add = conf_dict['interfaces'][uut.name]['loopback'][intf]['ip_add']
        description = conf_dict['interfaces'][uut.name]['loopback'][intf]['Description']
        prefix_length = conf_dict['interfaces'][uut.name]['loopback'][intf]['prefix_length']      
        ipv4a = IPv4Addr(device=uut)
        ipv4a.ipv4 = IPv4Address(ip_add)
        ipv4a.prefix_length = prefix_length
        intf1.add_ipv4addr(ipv4a)
        intf1.shutdown = False

        cfgs = intf1.build_config(apply=True)

        if 'ip_add_secondary' in conf_dict['interfaces'][uut.name]['loopback'][intf]:
            ip_add_secondary = conf_dict['interfaces'][uut.name]['loopback'][intf]['ip_add_secondary']        
            ipv4b = IPv4Addr(device=uut)
            ipv4b.ipv4 = IPv4Address(ip_add_secondary)
            ipv4b.prefix_length = prefix_length
            ipv4b.ipv4_secondary = True
            intf1.add_ipv4addr(ipv4b)
        
        cfgs = intf1.build_config(apply=True)


def configureL3Interface(uut,conf_dict):

    for intf in conf_dict['interfaces'][uut.name]['layer3']:
        cfg = \
        """
        interface {intf}
        no switchport
        """
        uut.configure(cfg.format(intf=intf))

        ip_add = conf_dict['interfaces'][uut.name]['layer3'][intf]['ip_add']
        description = conf_dict['interfaces'][uut.name]['layer3'][intf]['Description']
        uut.configure(cfg.format(intf=intf))
        if 'loopback' in ip_add:
            intf1 = Interface(name=intf,device=uut)  
            intf1.description = description        
            intf1.unnumbered_intf_ref  = ip_add
            intf1.medium = 'p2p'
            intf1.shutdown = False    
            intf1.enabled = True
            intf1.switchport_enable = False
            intf1.mtu = 9126
            cfgs = intf1.build_config(apply=True)

        else:        
            intf1 = Interface(name=intf,device=uut)         
            prefix_length = conf_dict['interfaces'][uut.name]['layer3'][intf]['prefix_length']   
            intf1.ipv4 = ip_add
            intf1.ipv4.netprefix_length = prefix_length
            cfg += f'ip address {ip_add}/{prefix_length}\n'
            cfg += 'mtu 9216\n'
            uut.configure(cfg.format(intf=intf))

        if 'port_channel' in intf: 
            intf1.channel_group_mode = 'active'
            intf_name = conf_dict['interfaces'][uut.name]['layer3'][intf]['name']            
            for member in conf_dict['interfaces'][uut.name]['layer3'][intf]['members']:
                intf2 = Interface(name=member,device=uut)
                intf1.add_member(intf2)
            cfgs = intf1.build_config(apply=True)


def configureL2Interface(uut,conf_dict): 

    if 'layer2' in conf_dict['interfaces'][uut.name]:
        for intf in conf_dict['interfaces'][uut.name]['layer2']:    
            if 'Po' in intf:    
                print(intf)
                intf_name = conf_dict['interfaces'][uut.name]['layer2'][intf]['name'] 
                description = conf_dict['interfaces'][uut.name]['layer2'][intf]['Description']
                switchport_mode = conf_dict['interfaces'][uut.name]['layer2'][intf]['switchport_mode']
                switchport_vlan = conf_dict['interfaces'][uut.name]['layer2'][intf]['switchport_vlan']
                intf1 = Interface(name=intf_name,device=uut)    
                intf1.description = description
                intf1.switchport_mode = switchport_mode
                if 'access' in switchport_mode:
                    intf1.access_vlan = switchport_vlan
                elif 'trunk' in switchport_mode:
                    intf1.trunk_vlans = switchport_vlan
                intf1.shutdown = False
                intf1.channel_group_mode = 'active'
                intf1.enabled = True
                intf1.switchport_enable = True

                for member in conf_dict['interfaces'][uut.name]['layer2'][intf]['members']:
                    print(member)  
                    intf2 = Interface(name=member,device=uut)
                    intf1.add_member(intf2)

                # Build config
                cfgs = intf1.build_config(apply=False)
                
                cfgs2 = cfgs.replace("mode active","force mode active") 

                if 'vpc' in conf_dict['interfaces'][uut.name]['layer2'][intf]:
                    uut.configure('feature vpc')
                    vpc1 = conf_dict['interfaces'][uut.name]['layer2'][intf]['vpc']
                    cfgs2 += f"\ninterface  {intf_name}\n "
                    cfgs2 += f"\n vpc {vpc1}\n "
                    
                uut.configure(cfgs2,timeout=300)

            elif 'Eth' in intf:  
                print(intf)
                intf_name = conf_dict['interfaces'][uut.name]['layer2'][intf]['name'] 
                description = conf_dict['interfaces'][uut.name]['layer2'][intf]['Description']
                switchport_mode = conf_dict['interfaces'][uut.name]['layer2'][intf]['switchport_mode']
                switchport_vlan = conf_dict['interfaces'][uut.name]['layer2'][intf]['switchport_vlan']
                intf1 = Interface(name=intf_name,device=uut)    
                intf1.switchport_enable = True
                intf1.shutdown = False
                intf1.enabled = True
                intf1.description = description
                intf1.switchport_mode = switchport_mode                
                if 'access' in switchport_mode:
                    intf1.access_vlan = switchport_vlan
                    intf1.switchport_mode = 'access'
                elif 'trunk' in switchport_mode:
                    intf1.trunk_vlans = switchport_vlan

                cfgs = str(intf1.build_config(apply=False))
                if 'access' in switchport_mode:
                    cfgs += f"\ninterface  {intf_name}\n "
                    cfgs += f"\n switchport access vlan {switchport_vlan}\n "

                elif 'trunk' in switchport_mode:
                    cfgs += f"\ninterface  {intf_name}\n "
                    cfgs += f"\n switchport trunk allowed vlan add {switchport_vlan}\n "                    

                uut.configure(cfgs,timeout=300)  


def intfUnshut(uut,intf):
    intf1 = Interface(name=intf,device=uut)
    intf1.shutdown = False
    cfg = intf1.build_config(apply=True)


def getEthIntfList(uut):
    intf_list = []
    for line in uut.execute("show interface brief").splitlines():
        if not "VLAN" in line:
            if "Eth" in line:
                intf_list.append(line.split()[0])
    return(intf_list)  


def unshutAllintf(uut):
    intf_list1 = getEthIntfList(uut)
    for intf in intf_list1:
        intfUnshut(uut,intf)


def addVpcConfig(uut,conf_dict):
    if 'vpc' in conf_dict['interfaces'][uut.name]:    
        domain_id = conf_dict['interfaces'][uut.name]['vpc']['domain_id']
        keepalive_dst_ip = conf_dict['interfaces'][uut.name]['vpc']['keepalive_dst_ip']
        keepalive_src_ip =conf_dict['interfaces'][uut.name]['vpc']['keepalive_src_ip']
    
        vpc = Vpc()
        dev = uut
        dev.add_feature(vpc)
        maxDiff = None

        vpc.enabled = True
        vpc.device_attr[dev].enabled = True
        vpc.device_attr[dev].domain_attr[domain_id]
        vpc.device_attr[dev].domain_attr[domain_id].keepalive_dst_ip = keepalive_dst_ip
        vpc.device_attr[dev].domain_attr[domain_id].keepalive_src_ip = keepalive_src_ip
        vpc.device_attr[dev].domain_attr[domain_id].keepalive_vrf = 'management'

        cfgs = vpc.build_config(apply=True)


def addOspfConfig(uut,conf_dict):
    dev1 = uut
    intf1_list = conf_dict['igp']['ospf'][uut.name]['intf1_list']   
    router_id = find_loop_ip(uut,'0')

    # Create OSPF object
    ospf1 = Ospf()
    ospf1.device_attr[dev1].enabled = True
    vrf0 = Vrf('default')

    # Add OSPF configuration to vrf default
    ospf1.device_attr[dev1].vrf_attr[vrf0].instance = 'UNDERLAY'
    ospf1.device_attr[dev1].vrf_attr[vrf0].enable = True
    ospf1.device_attr[dev1].vrf_attr[vrf0].router_id = router_id
    ospf1.device_attr[dev1].vrf_attr[vrf0].log_adjacency_changes = True
    ospf1.device_attr[dev1].vrf_attr[vrf0].log_adjacency_changes_detail = True

    # Add area configuration to VRF default
    ospf1.device_attr[dev1].vrf_attr[vrf0].area_attr['0'].area_te_enable = True
    for intf1 in intf1_list:
        if 'loop' in intf1:
            ospf1.device_attr[dev1].vrf_attr[vrf0].area_attr['0'].interface_attr[intf1].if_admin_control = True
        else:
            # Add interface configuration to VRF default
            ospf1.device_attr[dev1].vrf_attr[vrf0].area_attr['0'].interface_attr[intf1].if_admin_control = True
            ospf1.device_attr[dev1].vrf_attr[vrf0].area_attr['0'].interface_attr[intf1].if_type = 'point-to-point'
            ospf1.device_attr[dev1].vrf_attr[vrf0].area_attr['0'].interface_attr[intf1].if_mtu_ignore = True

    # Add OSPF to the device
    dev1.add_feature(ospf1)
    
    # Build config
    cfgs = ospf1.build_config(apply=True)


def addBgpConfig(uut,conf_dict):
    dev1 = uut
    router_id = conf_dict['bgp'][uut.name]['router_id']   
    neigh_list = conf_dict['bgp'][uut.name]['neigh_list']   

    bgp = Bgp(bgp_id=100)
    af_name = 'l2vpn evpn'
    af_name1 = 'ipv4 unicast'
    vrf = Vrf('default')
    bgp.device_attr[dev1].vrf_attr[vrf].address_family_attr[af_name].af_advertise_pip = True
    bgp.device_attr[dev1]
    dev1.add_feature(bgp)
    cfgs = bgp.build_config(apply=False)
    neighbor_id = '10.0.0.1'
    bgp2.device_attr[dev1].vrf_attr[vrf].neighbor_attr[neighbor_id]
  

def ProcessRestart(uut,proc):
    # Function to configure vpc 

    logger.info(banner("Entering proc to restart the processes"))
    try:
        uut.configure('feature bash-shell',timeout=40)
    except:
        log.error('bash enable failed for %r',uut)
        log.error(sys.exc_info())

    try:
        log.info('-----Proc State before Restart-----')
        config_str = '''sh system internal sysmgr service name {proc} '''
        out=uut.execute(config_str.format(proc=proc),timeout=40)
        log.info('----------------------------------------')
        config_str = '''sh system internal sysmgr service name {proc} | grep PID'''
        out=uut.execute(config_str.format(proc=proc),timeout=40)
        pid  = out.split()[5].strip(',')

        uut.transmit('run bash \r',timeout=60)
        uut.receive('bash-4.4$')
        uut.transmit('sudo su \r',timeout=60)
        uut.receive('bash-4.4#')
        uut.transmit('kill %s\r' %pid,timeout=60)
        uut.receive('bash-4.4#')
        uut.transmit('exit \r',timeout=180)
        uut.receive('bash-4.4$',timeout=180)
        uut.transmit('exit \r')        
        uut.receive('#')
        log.info('-----Proc State AFTER Restart-----')
        config_str = '''sh system internal sysmgr service name {proc} '''
        out=uut.execute(config_str.format(proc=proc),timeout=40)
        log.info('----------------------------------------')
    except:
        log.error('proc restart test failed for %r',proc)
        log.error(sys.exc_info())


def configureTrm1(uut):
    cfg = \
    """
    feature ngmvpn 
    ip pim pre-build-spt
    ip igmp snooping vxlan

    route-map ssm-1 permit 10
    match ip multicast group 232.0.0.0/8
    route-map ssm-1 permit 11
    match ip multicast group 233.0.0.0/8 
    route-map no-pim-neighbor deny 10
    match ip address prefix-list anyip 
    interface loopback111
    description Overlay VRF RP Loopback interface
    vrf member vxlan-900101
    ip address 1.2.3.111/32
    no sh
    interface loopback112
    description Overlay VRF RP Loopback interface
    vrf member vxlan-900102
    ip address 1.2.3.112/32 
    ip pim sparse-mode
    no sh
    vrf context vxlan-900101
    vni 900101
    ip pim rp-address 1.2.3.111 group-list 224.0.0.0/4
    ip pim ssm route-map ssm-1
    rd auto
    address-family ipv4 unicast
        route-target both auto
        route-target both auto mvpn
        route-target both auto evpn
    address-family ipv6 unicast
        route-target both auto
        route-target both auto evpn
    
    vrf context vxlan-900102
    vni 900101
    ip pim rp-address 1.2.3.111 group-list 224.0.0.0/4
    ip pim ssm route-map ssm-1
    rd auto
    address-family ipv4 unicast
        route-target both auto
        route-target both auto mvpn
        route-target both auto evpn
    address-family ipv6 unicast
        route-target both auto
        route-target both auto evpn

    interface Vlan101-102
    ip pim sparse-mode

    interface Vlan1001-1020
    no shutdown
    ip pim sparse-mode
    ip pim neighbor-policy no-pim-neighbor
    fabric forwarding mode anycast-gateway

    interface nve1
    no shutdown
    host-reachability protocol bgp
    source-interface loopback0
    member vni 201001
        ingress-replication protocol bgp
        suppress-arp
    member vni 201002-201010
        mcast-group 239.1.1.1
        suppress-arp
    member vni 201011-201019
        mcast-group 239.1.1.2
        suppress-arp
    """
    if not 'paris' in uut.name:
        uut.configure(cfg)

    cfg2 = \
    """
    interface nve1
    member vni 900101 associate-vrf
    multisite ingress-replication optimized
    member vni 900102 associate-vrf
    multisite ingress-replication optimized
    """    
    if 'bgw' in uut.name:
        uut.configure(cfg2)    


def relayConf(vtep,device):
    cfg = \
    """
    feature dhcp

    service dhcp
    ip dhcp relay
    ip dhcp relay information option
    ip dhcp relay information option vpn
    ipv6 dhcp relay

    interface Vlan1020
    no shutdown
    vrf member vxlan-900102
    ip address 4.20.0.1/16
    fabric forwarding mode anycast-gateway
    ip dhcp relay address 4.5.0.9 use-vrf vxlan-900101 
    ip dhcp relay source-interface loopback99

    vrf context vxlan-900101
     address-family ipv4 unicast
      route-target import 65535:900102
      route-target export 65535:900101
    
    vrf context vxlan-900102
     address-family ipv4 unicast
      route-target import 65535:900101
      route-target export 65535:900102
    """

    cfg1 = \
    """
    interface Ethernet1/53
    description TGN
    switchport
    switchport access vlan 1020
    spanning-tree port type edge
    no shutdown
    """

    cfg2 = \
    """
    interface Ethernet1/51
    description TGN
    switchport
    switchport access vlan 1020
    spanning-tree port type edge
    no shutdown
    """

    cfg3 = \
    """
    interface Ethernet1/49
    description TGN
    switchport
    switchport access vlan 1020
    spanning-tree port type edge
    no shutdown
    """

    vtep.configure(cfg)

    if device == "vtep1":
        vtep.configure(cfg1)
    elif device == "vtep2":
        vtep.configure(cfg1)
    elif device == "vtep3":
        vtep.configure(cfg2)
    elif device == "vtep32":
        vtep.configure(cfg1)
    elif device == "fanout":
        vtep.configure(cfg3)


def vpcVtep(vtep):
    cfg = \
    """
    router bgp 65535
    address-family l2vpn evpn
    advertise-pip

    interface nve1
    no shutdown
    host-reachability protocol bgp
    advertise virtual-rmac
    """

    vtep.configure(cfg)


def confPort(vtep,device):
    cfg = \
    """
    int port-channel 11
    switchport trunk allowed vlan add 1020
    """

    cfg1 = \
    """
    no feature dhcp
    """

    vtep.configure(cfg)

    if device == "fanout":
        vtep.configure(cfg1)


def dhcpServerRelay(vtep):
    cfg = \
    """
    feature dhcp
    service dhcp
    ip dhcp relay
    ip dhcp relay information option
    ip dhcp relay information option vpn
    ipv6 dhcp relay


    interface Vlan1020
     ip dhcp relay address 4.5.0.9 use-vrf vxlan-900101
     ip dhcp relay source-interface loopback99
    """    

    vtep.configure(cfg)


def cleanupConf(vtep,device):
    cfg1 = \
    """
    interface Ethernet1/53
    description TGN
    switchport
    switchport access vlan 1005
    spanning-tree port type edge
    no shutdown
    """

    cfg2 = \
    """
    interface Ethernet1/51
    description TGN
    switchport
    switchport access vlan 1005
    spanning-tree port type edge
    no shutdown
    """

    cfg3 = \
    """
    interface Ethernet1/49
    description TGN
    switchport
    switchport access vlan 1005
    spanning-tree port type edge
    no shutdown
    """

    if device == "vtep1":
        vtep.configure(cfg1)
    elif device == "vtep2":
        vtep.configure(cfg1)
    elif device == "vtep3":
        vtep.configure(cfg2)
    elif device == "vtep32":
        vtep.configure(cfg1)
    elif device == "fanout":
        vtep.configure(cfg3)


def dhcpServerRelaySymm(vtep):
    cfg = \
    """
    feature dhcp
    service dhcp
    ip dhcp relay
    ip dhcp relay information option
    ip dhcp relay information option vpn
    ipv6 dhcp relay


    interface Vlan1002
     ip dhcp relay address 4.5.0.9 use-vrf vxlan-900101
     ip dhcp relay source-interface loopback99
    """    

    vtep.configure(cfg)


def dhcpServerRelayAsymm(vtep):
    cfg = \
    """
    feature dhcp
    service dhcp
    ip dhcp relay
    ip dhcp relay information option
    ip dhcp relay information option vpn
    ipv6 dhcp relay


    interface Vlan1002
     ip dhcp relay address 4.5.0.9 use-vrf vxlan-900101
     ip dhcp relay source-interface loopback99
     shutdown
    """    

    vtep.configure(cfg)


def dhcpServerRelayAsymmDiff(vtep):
    cfg = \
    """
    feature dhcp
    service dhcp
    ip dhcp relay
    ip dhcp relay information option
    ip dhcp relay information option vpn
    ipv6 dhcp relay


    interface Vlan1020
     ip dhcp relay address 4.5.0.9 use-vrf vxlan-900101
     ip dhcp relay source-interface loopback99
     shutdown
    """    

    vtep.configure(cfg)


def relayConfSymm(vtep,device):
    cfg = \
    """
    feature dhcp

    service dhcp
    ip dhcp relay
    ip dhcp relay information option
    ip dhcp relay information option vpn
    ipv6 dhcp relay

    interface Vlan1002
    no shutdown
    vrf member vxlan-900102
    ip address 4.2.0.1/16
    fabric forwarding mode anycast-gateway
    ip dhcp relay address 4.5.0.9 use-vrf vxlan-900101 
    ip dhcp relay source-interface loopback99
    """

    cfg1 = \
    """
    interface Ethernet1/53
    description TGN
    switchport
    switchport access vlan 1002
    spanning-tree port type edge
    no shutdown
    """

    cfg2 = \
    """
    interface Ethernet1/51
    description TGN
    switchport
    switchport access vlan 1002
    spanning-tree port type edge
    no shutdown
    """

    cfg3 = \
    """
    interface Ethernet1/49
    description TGN
    switchport
    switchport access vlan 1002
    spanning-tree port type edge
    no shutdown
    """

    vtep.configure(cfg)

    if device == "vtep1":
        vtep.configure(cfg1)
    elif device == "vtep2":
        vtep.configure(cfg1)
    elif device == "vtep3":
        vtep.configure(cfg2)
    elif device == "vtep32":
        vtep.configure(cfg1)
    elif device == "fanout":
        vtep.configure(cfg3)


def v6Server(vtep):
    cfg = \
    """
    interface vlan 1005
     ipv6 address 2001:100:1:10::1/64
     no ipv6 redirects
    """

    vtep.configure(cfg)