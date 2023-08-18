#!/usr/bin/env python
import re
import pdb
import logging
import time
#import pexpect
from time import sleep
import threading
import hashlib
import sys
from ipaddress import *
import json
from ats.log.utils import banner
from random import *
from ats.topology import Device
import requests
from ats import aetest, log
from ats.log.utils import banner
from netaddr import *
from re import *
#from randmac import RandMac
from unicon.utils import Utils
import socket
from pyats.async_ import pcall
from unicon.eal.dialogs import Statement, Dialog
from unicon.utils import Utils
import collections
#from ixia_vxlan_lib import *


#### sep 19
from genie.libs.conf.interface.nxos import Interface
from genie.libs.conf.ospf.nxos.ospf import Ospf
#from genie.libs.conf.rip.rip import Rip
#pkgs/conf-pkg/src/genie/libs/conf/ospf/nxos/ospf.py

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


#import general_lib
#ixia source 
from ixiatcl import IxiaTcl
from ixiahlt import IxiaHlt
from ixiangpf import IxiaNgpf
from ixiaerror import IxiaError

 
ixiatcl = IxiaTcl()
ixiahlt = IxiaHlt(ixiatcl)
#if the user wishes to set HLTSET at instantiation : ixiahlt = IxiaHlt(ixiatcl, ixia_version='HLTSET166')
ixiangpf = IxiaNgpf(ixiahlt)
 
 
 
def DeviceConnect(uut):
    log.info(banner('Starting DeviceConnect'))
    result_list = []
    for uut in [uut] :   
        log.info('connect to %s' % uut.alias)
        try:
            uut.connect(connection_timeout=700)
            uut.execute('show version')  
            log.info("DeviceConnect passed for %r ",uut)
        except:
            log.info(banner('connect failed once ; clearing console'))
            if 'port' in uut.connections['a']:
                ts = str(uut.connections['a']['ip'])
                port=str(uut.connections['a']['port'])[-2:]
                u = Utils()
                u.clear_line(ts, port, 'lab', 'lab')
            try:
                uut.connect(connection_timeout=700)
                uut.execute('show version')   
                log.info("DeviceConnect passed for %r ",uut)
            except:
               log.info("DeviceConnect FAIL for %r ",uut)
               result_list.append('fail')
               #return 1
    if 'fail' in result_list:
        return 1
        

def DeviceVxlanPreCleanupAll(uut):
    log.info(banner('Starting DeviceVxlanPreCleanupAll'))

    cmd=""
    log.info(banner("Deleteing PO ------"))
    op = uut.execute('show port-channel summary | incl Eth',timeout = 180)
    op1 = op.splitlines()

    for line in op1:
        if 'Po' in line:
            Po = line.split()[0]
            cmd +=  'no interface Po{Po}\n'.format(Po=Po)
   
    log.info(banner("Deleteing VLAN ------"))
    op = uut.execute('show vlan brief | incl active')
    op1 = op.splitlines()

    for line in op1:
        if not 'default' in line:
            if 'Po' in line:
                vlan = line.split()[0]
                cmd +=  'no vlan {vlan}\n'.format(vlan=vlan)
 
    log.info(banner("Deleteing Monitor session"))
    op = uut.execute('sh run monitor | incl sess')
    if op:
        op1 = op.splitlines()
        for line in op1:
            if 'session' in line:
                cmd +=  'no {line}\n'.format(line=line)

    log.info(banner("Deleteing PO"))
    op = uut.execute('show interface brief | include Po')
    op1 = op.splitlines()
    po_list=[]
    for line in op1:
        list1 = line.split(" ")
        if 'Po' in list1[0]:
            po_list.append(list1[0])
        po_list = po_list[2:]
        if len(po_list) > 0:
            for po in po_list:
                if not 'port' in po:
                    cmd +=  'no interface {po}\n'.format(po=po)

    log.info(banner("Deleteing access lists"))
    op = uut.configure("sh run | incl 'ip access-list'")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'copp' in line:
                if not "sh run |" in line:
                    if "access-list" in line:
                        cmd +=  "no {line}\n".format(line=line)

    log.info(banner("Delete static routes"))
    op = uut.configure("sh run | incl 'ip route '")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'run' in line:
                if not '10.127' in line:
                    if 'ip route ' in line:
                        cmd +=  "no {line}\n".format(line=line)

    log.info(banner("Deleting Loopbacks/Eth Ip address vrf"))
    op = uut.configure("show ip interface brief vrf all ")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'Lo' in line:
                intf = line.split()[0]
                cmd +=  'no interface {intf}\n'.format(intf=intf)
            elif 'Eth' in line:
                intf = line.split()[0]
                log.info('******** L3 intf is %r',intf)
                cmd +=  'default interface {intf}\n'.format(intf=intf)
            elif 'Po' in line:
                log.info('******** L3 Po intf is %r',intf)
                intf = line.split()[0]
                cmd +=  'no interface {intf}\n'.format(intf=intf)



    log.info(banner("Deleting vrf"))
    op = uut.configure("show vrf")
    op1 = op.splitlines()
    for line in op1:
        if line:
            #for key1 in ['VRF-Name','show','default','management']:
            if not 'VRF-Name' in line:
                if not 'show' in line:
                    if not 'management' in line:                        
                        if not 'default' in line:   
                            vrf = line.split()[0]
                            cmd +=  'no vrf context {vrf}\n'.format(vrf=vrf)

    log.info(banner("Default Eth interface to L3"))
    op = uut.configure("sh int br | exclu route")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'Eth' in line:
                if not 'Ethernet' in line:
                    intf = line.split()[0]
                    cmd +=  'default interface {intf}\n'.format(intf=intf)
                    cmd +=  'interface {intf}\n'.format(intf=intf)
                    cmd +=  'no switchport\n' 

    log.info(banner("Deleting Loopbacks/Eth Ip address"))
    op = uut.configure("show ip interface brief ")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'Lo' in line:
                intf = line.split()[0]
                cmd +=  'no interface {intf}\n'.format(intf=intf)
            elif 'Eth' in line:
                intf = line.split()[0]
                log.info('******** L3 intf is %r',intf)
                cmd +=  'default interface {intf}\n'.format(intf=intf)
            elif 'Po' in line:
                log.info('******** L3 Po intf is %r',intf)
                intf = line.split()[0]
                cmd +=  'no interface {intf}\n'.format(intf=intf)

    log.info(banner("Deleting community-list"))
    op = uut.execute("show run | incl community-list")
    op1 = op.splitlines()
    for line in op1:
        if not 'run' in line:
            if line:
                if 'community-list' in line:
                    cfg = "no {line}"
                    cmd +=  'no {line}\n'.format(line=line)


    log.info(banner("Deleting route-map"))
    op = uut.execute("show run | incl route-map")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'route-map' in line:
                if 'permit' in line:
                    cfg = "no {line}"
                    cmd +=  'no {line}\n'.format(line=line)


    #log.info(banner("Delete CLI's"))
    #log.info('cmd is %r',cmd)

    #uut.configure(cmd,timeout=200)
   
    feature_clean=\
    """
    no fabric forwarding anycast-gateway-mac 0000.2222.3333
    no feature isis
    no feature ngoam
    no feature sla sender
    no feature sflow
    no feature interface-vlan
    no feature lacp
    no feature tunnel
    no feature ngmvpn
    show clock
    no feature nv over
    show clock
    no feature bgp
    show clock
    no feature vpc
    show clock
    no feature ospf
    show clock
    no feature pim
    line console
    exec-timeout 0
    line vty
    exec-timeout 0
    show clock
    feature nv over
    show clock
    feature bgp
    show clock
    feature ospf
    show clock
    feature pim
    show clock
    #feature ngoam
    nv overlay evpn
    feature lacp
    feature vn-segment-vlan-based
    feature interface-vlan
    feature lacp
    """

    for line in feature_clean.splitlines():
        if line:
            cmd +=  line+'\n'

    log.info(banner("Delete CLI's"))
    #log.info('cmd is %r',cmd)

    try:
        uut.configure(cmd,timeout = 380)
    except:
        log.error('feature_clean failed for uut',uut)

    return 1


def SwVxlanPreCleanup(uut):
    log.info(banner("START SwVxlanPreCleanup"))


    cmd=""
    log.info(banner("Deleteing PO ------"))
    op = uut.execute('show port-channel summary | incl Eth',timeout = 180)
    op1 = op.splitlines()

    for line in op1:
        if 'Po' in line:
            Po = line.split()[0]
            cmd +=  'no interface Po{Po}\n'.format(Po=Po)
            #uut.configure('no interface Po{Po}'.format(Po=Po))

    log.info(banner("Deleteing VLAN ------"))
    op = uut.execute('show vlan brief | incl active',timeout = 180)
    op1 = op.splitlines()

    for line in op1:
        if not 'default' in line:
            if 'Po' in line:
                vlan = line.split()[0]
                cmd +=  'no vlan {vlan}\n'.format(vlan=vlan)
            #uut.configure('no interface Po{Po}'.format(Po=Po))




    log.info(banner("Deleteing Monitor session"))
    op = uut.execute('sh run monitor | incl sess')
    if op:
        op1 = op.splitlines()
        for line in op1:
            if 'session' in line:
                cmd +=  'no {line}\n'.format(line=line)

                #try:
                #    uut.configure('no {line}'.format(line=line))
                #except:
                #    log.error('Deleteing Monitor session failed for uut %r',uut)
                #    return 0



    log.info(banner("Deleteing PO"))
    op = uut.execute('show interface brief | include Po',timeout = 180)
    op1 = op.splitlines()
    po_list=[]
    for line in op1:
        list1 = line.split(" ")
        if 'Po' in list1[0]:
            po_list.append(list1[0])
        po_list = po_list[2:]
        if len(po_list) > 0:
            for po in po_list:
                if not 'port' in po:
                    cmd +=  'no interface {po}\n'.format(po=po)
                    #
                    #cfg1 = """#default interface {po}"""
                    #cfg2 = """no interface {po}"""
                    #try:
                    #    uut.configure(cfg1.format(po=po))
                    #    uut.configure(cfg2.format(po=po))
                    #except:
                    #    log.error('Deleteing PO failed for uut %r',uut)
                    #    return 0


    log.info(banner("Deleteing access lists"))
    op = uut.configure("sh run | incl 'ip access-list'")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'copp' in line:
                if not "sh run |" in line:
                    if "access-list" in line:

                        #cfg = "no {line}"
                        cmd +=  "no {line}\n".format(line=line)

                        #try:
                        #    uut.configure(cfg.format(line=line))
                        #except:
                        #    log.error('Deleteing ACL failed for uut %r',uut)
                        #    return 0


    log.info(banner("Delete static routes"))
    op = uut.configure("sh run | incl 'ip route '")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'run' in line:
                if not '10.127' in line:
                    if 'ip route ' in line:
                        #cfg = "no {line}"
                        cmd +=  "no {line}\n".format(line=line)

                        #try:
                        #    uut.configure(cfg.format(line=line))
                        #except:
                        #    log.error('Deleteing Static route failed for uut %r',uut)
                        #    return 0

    log.info(banner("Deleting vrf"))
    op = uut.configure("show vrf")
    op1 = op.splitlines()
    for line in op1:
        if line:
            #for key1 in ['VRF-Name','show','default','management']:
            if not 'VRF-Name' in line:
                if not 'show' in line:
                    if not 'management' in line:
                        if not 'default' in line:                        
                            vrf = line.split()[0]
                            cmd +=  'no vrf context {vrf}\n'.format(vrf=vrf)
                    #try:

                    #try:
                    #     uut.configure('no vrf context {vrf}'.format(vrf=vrf),timeout = 60)
                    #except:
                    #    log.error('Deleteing Static route failed for uut %r',uut)
                    #    return 0

    log.info(banner("Default Eth interface to L3"))
    op = uut.configure("sh int br | exclu route")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'Eth' in line:
                if not 'Ethernet' in line:
                    intf = line.split()[0]
                    cmd +=  'default interface {intf}\n'.format(intf=intf)
                    cmd +=  'interface {intf}\n'.format(intf=intf)
                    cmd +=  'no switchport\n' 
                    cfg = \
                        """
                        default interface {intf}
                        interface {intf}
                        no switchport
                        """
                    #try:
                    #     uut.configure(cfg.format(intf=intf),timeout = 60)
                    #except:
                    #    log.error('Default Eth interface to L3 failed for uut %r',uut)
                    #    return 0

    log.info(banner("Deleting Loopbacks"))
    op = uut.configure("show ip interface brief ")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'Lo' in line:
                intf = line.split()[0]
                cmd +=  'no interface {intf}\n'.format(intf=intf)
                #try:
                #     uut.configure('no interface {intf}'.format(intf=intf))
                #except:
                #    log.error('Deleting Loopbacks failed for uut %r',uut)
                #    return 0



    log.info(banner("Deleting community-list"))
    op = uut.execute("show run | incl community-list")
    op1 = op.splitlines()
    for line in op1:
        if not 'run' in line:
            if line:
                if 'community-list' in line:
                    cfg = "no {line}"
                    cmd +=  'no {line}\n'.format(line=line)
                    #try:
                    #    uut.configure(cfg.format(line=line))
                    #except:
                    #    log.error('community-list delete failed in uut',uut)
                    #    return 0

    log.info(banner("Deleting route-map"))
    op = uut.execute("show run | incl route-map")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'route-map' in line:
                if 'permit' in line:
                    cfg = "no {line}"
                    cmd +=  'no {line}\n'.format(line=line)

                    #try:
                    #    uut.configure(cfg.format(line=line))
                    #except:
                    #    log.error('route-map delete failed in uut',uut)
                    #    return 0

    log.info(banner("Delete CLI's"))
    #log.info('cmd is %r',cmd)

    feature_clean=\
    """
    no fabric forwarding anycast-gateway-mac 0000.2222.3333
    no feature nv over
    no feature bgp
    no feature ospf
    no feature pim
    no feature vpc
    no feature interface-vlan
    no feature bfd
    terminal session-timeout 0
    line console
    exec-timeout 0
    line vty
    exec-timeout 0
    feature interface-vlan
    feature lacp
    """
    #try:
    #uut.configure(cmd,timeout = 280)
    for line in feature_clean.splitlines():
        if line:
            cmd +=  line+'\n'

    log.info(banner("Delete CLI's"))
    #log.info('cmd is %r',cmd)

    try:
        uut.configure(cmd,timeout = 250)
    except:
        log.error('feature_clean failed for uut',uut)

    log.info(banner("END SwVxlanPreCleanup"))
    return 1

  

def vxlanL3NodeCommonConfig(uut):
    log.info(banner("Starting vxlanVtepCommonConfig"))
    feature_clean=\
    """
    no feature nv over
    feature nv over
    show clock
    no feature bgp
    feature bgp
    show clock
    no feature ospf
    feature ospf
    show clock
    spanning-tree mode mst
    no spanning-tree mst configuration
    feature lacp
    no ip igmp snooping
    no vlan 2-3831
 
    system no hap-reset
    nv overlay evpn
    """
    try:
        uut.configure(feature_clean,timeout = 200)
    except:
        log.error('Starting vxlanVtepCommonConfig failed in uut %r',uut)
        return 0



def vxlanVtepIGPConfig(uut,loop0_ip1,loop0_ip2,loop1_ip1,spine_intf_list,pim_rp_address):

    rid = str(loop1_ip1)[:-3]

    cmd=\
            '''
            fabric forwarding anycast-gateway-mac 0000.2222.3333
            feature ospf
            feature pim
            no router ospf 100
            router ospf 100
            router-id {rid}
            ip pim rp-address {pim_rp_address} group-list 224.0.0.0/4
            '''
    try:
        uut.configure(cmd.format(rid=rid,pim_rp_address=pim_rp_address),timeout = 200)
    except:
        log.error('OSPF config failed for node %r',uut)

    log.info(banner("Configureing Loopbacks"))

    if not 'Nil' in loop0_ip2:
        config_str = \
            """
            feature ospf
            no interf loopback0
            no interf loopback1
            interf loopback0
            no ip add
            ip add {loop0_ip1}
            ip add {loop0_ip2} second
            ip pim sparse-mode
            descr NVE loopback
            no shut
            ip router ospf 100 area 0.0.0.0
            interf loopback1
            no ip add
            ip add {loop1_ip1}
            descr General_IGP loopback
            no shut
            ip router ospf 100 area 0.0.0.0
            ip pim sparse-mode
            """
        try:
            uut.configure(config_str.format(loop0_ip1=loop0_ip1,loop0_ip2=loop0_ip2,loop1_ip1=loop1_ip1))
        except:
            log.error('Loop Config Failed on UUT %r',uut)

    else:
        config_str = \
            """
            feature ospf
            no interf loopback0
            no interf loopback1
            interf loopback0
            no ip add
            ip add {loop0_ip1}
            ip pim sparse-mode
            descr NVE loopback
            ip router ospf 100 area 0.0.0.0
            no shut
            interf loopback1
            no ip add
            ip add {loop1_ip1}
            descr General_IGP loopback
            no shut
            ip router ospf 100 area 0.0.0.0
            ip pim sparse-mode
            """
        try:
            uut.configure(config_str.format(loop0_ip1=loop0_ip1,loop1_ip1=loop1_ip1),timeout=120)
        except:
            log.error('Loop Config Failed on UUT %r',uut)


    for intf in spine_intf_list:
        cmd=\
                '''
                feature ospf
                default interface {intf}
                interf {intf}
                description VTEP_SPINE
                no switchport
                mtu 9216
                logging event port link-status
                medium p2p
                no ip redirects
                ip unnumbered loopback1
                ip ospf network point-to-point
                ip router ospf 100 area 0.0.0.0
                ip ospf cost 1
                ip pim sparse-mode
                no shutdown
                '''
        try:
            uut.configure(cmd.format(intf=intf),timeout=380)
        except:
            log.error('Uplink interface config failed for node %r intf %r',uut,intf)





def SwPortChannelconfigs(uut,port_list,vlan_range):
    cmd = """\
    default interface Po101
    default interface Po100
    no int po 101
    no int po 100
    vlan {vlan_range}
    interface po 101
    switchport
    shut
    switchport mode trunk
    switchport trunk allowed vlan {vlan_range}
    spanning-tree bpdufilter enable
    spanning-tree port type edge trunk
    sleep 1
    no shut

    """
    try:
        uut.configure(cmd.format(vlan_range=vlan_range),timeout=120)
    except:
        log.info("Switch TGN Port Configuration Failed")


    cfg = """\
    default interface {intf}
    interface {intf}
    channel-group 101 force mode active
    no shut
    """
    for intf in port_list:
        try:
            uut.configure(cfg.format(intf=intf),timeout=120)
        except:
            log.info("Switch TGN Port Configuration Failed")
            return 0

    return 1


def SviConfigs(uut1,uut2):

    cfg1 = \
    """
    feature interface-vlan
    vlan 10
    no interface vlan10
    interface vlan10
    mtu 9216
    ip pim sparse-mode
    ip address 12.12.1.1/24
    ip router ospf 1 area 0
    no shut
    vlan configuration 10
    ip igmp snooping
 
    """
    cfg2 = \
    """
    feature interface-vlan
    vlan 10
    no interface vlan10
    interface vlan10
    mtu 9216
    ip pim sparse-mode
    ip address 12.12.1.2/24
    ip router ospf 1 area 0
    no shut
    vlan configuration 10
    ip igmp snooping
 
    """

    try:
        uut1.configure(cfg1,timeout=120)
    except:
        log.info("vTEP L3 SVI for VPC Configuration Failed @ uut %r",uut1)
        return 0

    try:
        uut2.configure(cfg2,timeout=120)
    except:
        log.info("vTEP L3 SVI for VPC Configuration Failed @ uut %r",uut2)
        return 0



def SviConfigsall(uut1,uut2,prefix):

    ip1 = prefix+".1/24"
    ip2 = prefix+".2/24"

    cfg1 = \
    """
    feature interface-vlan
    vlan 10
    no interface vlan10
    interface vlan10
    mtu 9216
    ip pim sparse-mode
    ip address {ip1}
    ip router ospf 100 area 0
    no shut
    vlan configuration 10
    ip igmp snooping
 
    """
    cfg2 = \
    """
    feature interface-vlan
    vlan 10
    no interface vlan10
    interface vlan10
    mtu 9216
    ip pim sparse-mode
    ip address {ip2}
    ip router ospf 100 area 0
    no shut
    vlan configuration 10
    ip igmp snooping
 
    """

    try:
        uut1.configure(cfg1.format(ip1=ip1),timeout=120)
    except:
        log.info("vTEP L3 SVI for VPC Configuration Failed @ uut %r",uut1)
        return 0

    try:
        uut2.configure(cfg2.format(ip2=ip2))
    except:
        log.info("vTEP L3 SVI for VPC Configuration Failed @ uut %r",uut2)
        return 0

def NvePeerLearningIR(port_handle_list,vlan,uut_list,peer_count):
    log.info(banner(" In NvePeerLearning"))

    for uut in uut_list:
        op1=uut.execute("sh nve peers  | grep nve1 | count")
        if not int(op1) == peer_count:
            log.info("Nve peer check failed for UUT %r",uut)
            uut.execute("sh nve peers")
            return 0

    log.info(banner("NvePeerLearning Passed"))
    return 1


def NvePeerCheck(uut_list,peer_count):
    log.info(banner(" In NvePeerLearning"))

    for uut in uut_list:
        op1=uut.execute("sh nve peers  | grep nve1 | count")
        if not int(op1) >= peer_count:
            log.info("Nve peer check failed for UUT %r",uut)
            uut.execute("sh nve peers")
            return 0

    log.info(banner("NvePeerLearning Passed"))
    return 1




class VPCNodeGlobal(object):
    def __init__(self,node,vpc_domain,peer_ip,mct_mem_list1,src_ip):
        self.node=node
        self.vpc_domain=vpc_domain
        self.peer_ip=peer_ip
        self.mct_mem_list1=mct_mem_list1
        self.peer_ip=peer_ip
        self.src_ip=src_ip

    def vpc_global_conf(self):
        cmd = \
        '''
        spanning-tree mode mst
        no feature vpc
        feature vpc
        feature lacp
        vpc domain {vpc_domain}
        peer-keepalive destination {peer_ip} source {src_ip}
        peer-switch
        ip arp synchronize
        ipv6 nd synchronize
        auto-recovery
        peer-gateway
        '''
        try:
            self.node.configure(cmd.format(peer_ip=self.peer_ip,vpc_domain=self.vpc_domain,src_ip=self.src_ip))
        except:
            log.error('vpc gloabal config failed for node %r',self.node)

        cmd = \
        '''
        interface port-channel {vpc_domain}
        no shut
        switchport
        switchport mode trunk
        spanning-tree port type network
        vpc peer-link
        '''

        try:
            self.node.configure(cmd.format(vpc_domain=self.vpc_domain))
        except:
            log.error('vpc gloabal config failed for node %r',self.node)


        for intf in self.mct_mem_list1:
            cmd = \
                '''
                interface {intf}
                channel-group {vpc_domain} force mode active
                no shut
            '''
            try:
                self.node.configure(cmd.format(intf=intf,vpc_domain=self.vpc_domain))
            except:
                self.node.execute("show port-channel compatibility-parameters")
                log.error('222 vpc_peer_link member conf failed for uut/interface')




def pimConfigMultisite(spine_list,leaf_list):
    log.info(banner('START pimConfigMultisite'))
    for uut in spine_list:
        if 'spine1' in uut.alias:
            loopback1 = uut.interfaces['loopback1'].intf
            loopback1_ip = uut.interfaces['loopback1'].ipv4  
            pim_rp =str(loopback1_ip)[:-3]


    for uut in leaf_list:
        pim_intf_list = []
        for intf in [*uut.interfaces.keys()]:
            if 'loopback' in intf:
                intf=uut.interfaces[intf].intf
                pim_intf_list.append(intf)
            elif 'leaf_spine' in uut.interfaces[intf].alias:
                ntf=uut.interfaces[intf].intf
                pim_intf_list.append(intf)
        try:
            PimConfig(uut,pim_intf_list,pim_rp)
        except:
            log.error('PimConfig config failed for node %r',uut) 
            return 0

    log.info(banner('END pimConfigMultisite'))


def protocolStateCheck(uut,protocol_list):
    for proto in protocol_list:
        if 'isis' in proto:
            cmd = uut.execute("sh isis adjacency | incl N/A")
            op = cmd.splitlines()
            for line in op:
                if line:
                    if not '  UP ' in line:
                        log.info('isis neighbor found,Test failed for uut/neighbor %r',uut)
                        return 0
                    else:
                        log.info('isis neighbor test PASS for uut/neighbor %r',uut)
                        return 1

        elif 'vpc' in proto:
            op=uut.execute('show port-channel summary | incl Eth')
            op1=op.splitlines()
            result = 1
            for line in op1:
                if line:
                    if not "(P)" in line:
                        log.info('VPC Bringup Failed on device %r',str(uut))
                        uut.execute('show port-channel summary')
                        result = 0
                    else:
                        log.info('NVE Peer check passed for uut --------------')
                        result = 1
                        
            return result
            
    
        elif 'ospf' in proto:
            cmd = uut.execute("show ip ospf neighbors | json-pretty")
            if not "addr" in str(cmd):
                log.info('No OSPF neighbor found,Test failed for uut/neighbor %r',uut)
                return 0
            else:
                test1=json.loads(cmd)
                test11 = test1["TABLE_ctx"]["ROW_ctx"]
                if 'list' in str(type(test11)):
                    neig_list = test11[0]["TABLE_nbr"]["ROW_nbr"]
                    neig_count =  str(neig_list).count('addr')
                    if neig_count == 1:
                        if not 'FULL' in (neig_list)[0]['state']:
                            log.info('OSPF neighbor check failed for uut/neighbor %r',uut)
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            if not 'FULL' in (neig_list)[i]['state']:
                                log.info('OSPF neighbor check failed for uut/neighbor %r',uut)
                                return 0
                            else:
                                return 1

                else:
                    neig_list= test1["TABLE_ctx"]["ROW_ctx"]["TABLE_nbr"]["ROW_nbr"]
                    neig_count =  str(neig_list).count('addr')
                    if neig_count == 1:
                        if not 'FULL' in (neig_list)['state']:
                            log.info('OSPF neighbor check failed for uut/neighbor %r',uut)
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            if not 'FULL' in (neig_list)[i]['state']:
                                log.info('OSPF neighbor check failed for uut/neighbor %r',uut)
                                return 0
                            else:
                                return 1


        elif 'bgp' in proto:
            cmd = uut.execute(" show bgp l2 evpn summary | json-pretty")
            if not "state" in str(cmd):
                log.info('No BGP neighbor found,Test failed for uut/neighbor %r',uut)
                return 0
            else:
                test1=json.loads(cmd)
                test11 = test1["TABLE_vrf"]["ROW_vrf"]
                if 'list' in str(type(test11)):
                    neig_list= test11[0]["TABLE_af"]["ROW_af"][0]["TABLE_saf"][ "ROW_saf"][0]["TABLE_neighbor"]["ROW_neighbor"]
                    neig_count =  str(neig_list).count('neighborid')
                    if neig_count == 1:
                        if not 'Established' in (neig_list)[0]['state']:
                            log.info('BGP neighbor check failed for uut/neighbor %r',uut)
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            if not 'Established' in (neig_list)[i]['state']:
                                log.info('BGP neighbor check failed for uut/neighbor %r',uut)
                                return 0
                            else:
                                return 1

                else:
                    neig_list= test1["TABLE_vrf"]["ROW_vrf"]["TABLE_af"]["ROW_af"]["TABLE_saf"][ "ROW_saf"]["TABLE_neighbor"]["ROW_neighbor"]
                    neig_count =  str(neig_list).count('neighborid')
                    if neig_count == 1:
                        if not 'Established' in (neig_list)['state']:
                            log.info('BGP neighbor check failed for uut/neighbor %r',uut)
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            if not 'Established' in (neig_list)[i]['state']:
                                log.info('BGP neighbor check failed for uut/neighbor %r',uut)
                                return 0
                            else:
                                return 1

            log.info('BGP neighbor check passed for uut -------------- :')

        elif 'pim' in proto:
            cmd = uut.execute("show ip pim neighbor | json-pretty ")
            if not "vrf" in str(cmd):
                if not "nbr-add" in str(cmd):
                    log.info('No PIM neighbor found,Test failed for uut/neighbor %r',uut)
                    return 0
                else:
                    return 1

            elif "vrf" in str(cmd):
                test1=json.loads(cmd)
                test11 = test1["TABLE_vrf"]["ROW_vrf"]
                if 'list' in str(type(test11)):
                    neig_list= test11[0]["TABLE_neighbor"]["ROW_neighbor"]
                    neig_count =  str(neig_list).count('nbr-addr')
                    if neig_count == 1:
                        uptime = (neig_list)[0]['uptime']
                        uptime = uptime.replace(":","")
                        uptime = uptime.replace("d","")
                        uptime = uptime.replace("h","")
                        uptime = uptime.replace("s","")
                        if not int(uptime) > 1:
                            log.info('PIM neighbor check failed for uut/neighbor %r',uut)
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            uptime = (neig_list)[i]['uptime']
                            uptime = uptime.replace(":","")
                            uptime = uptime.replace("d","")
                            uptime = uptime.replace("h","")
                            uptime = uptime.replace("s","")
                            if not int(uptime) > 1:
                                log.info('PIM neighbor check failed for uut/neighbor %r',uut)
                                return 0
                            else:
                                return 1

                else:
                    neig_list= test1["TABLE_vrf"]["ROW_vrf"]["TABLE_neighbor"]["ROW_neighbor"]
                    neig_count =  str(neig_list).count('nbr-addr')
                    if neig_count == 1:
                        uptime = (neig_list)['uptime']
                        uptime = uptime.replace(":","")
                        uptime = uptime.replace("d","")
                        uptime = uptime.replace("h","")
                        uptime = uptime.replace("s","")
                        if not int(uptime) > 1:
                            log.info('PIM neighbor check failed for uut/neighbor %r',uut)
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            uptime = (neig_list)[i]['uptime']
                            uptime = uptime.replace(":","")
                            uptime = uptime.replace("d","")
                            uptime = uptime.replace("h","")
                            uptime = uptime.replace("s","")
                            if not int(uptime) > 1:
                                log.info('PIM neighbor check failed for uut/neighbor %r',uut)
                                return 0
                            else:
                                return 1
            else:
                pass

            log.info('PIM Neighbor check passed for uut --------------')

        elif 'nve-peer' in proto:
            #if not 'UnicastBGP' in uut.execute('show nve peers ')
            cmd = uut.execute("show nve peers | json-pretty")
            if not "peer-state" in str(cmd):
                log.info('No NVE neighbor found,Test failed for uut/neighbor,11111')
                time.sleep(20)
                cmd = uut.execute("show nve peers | json-pretty")
                if not "peer-state" in str(cmd):
                    log.info('No NVE neighbor found,Test failed for uut/neighbor,2222')
                    time.sleep(20)
                    cmd = uut.execute("show nve peers | json-pretty")
                    if not "peer-state" in str(cmd):
                        log.info('No NVE neighbor found,Test failed for uut/neighbor,33333')
                        cmd = uut.execute("show nve peers")
                        return 0
            else:
                test1=json.loads(cmd)
                test11 = test1["TABLE_nve_peers"]["ROW_nve_peers"]
                if 'list' in str(type(test11)):
                    neig_list= test11
                    neig_count =  str(neig_list).count('peer-ip')
                    if neig_count == 1:
                        state = (neig_list)[0]['peer-state']
                        if not 'Up' in state:
                            log.info('NVE Peer check failed for uut/neighbor %r',uut)
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            state = (neig_list)[i]['peer-state']
                            if not 'Up' in state:
                                log.info('NVE Peer check failed for uut/neighbor %r',uut)
                            else:
                                log.info('NVE Peer check passed for uut --------------')
                                return 1


                else:
                    neig_list= test1["TABLE_nve_peers"]["ROW_nve_peers"]
                    neig_count =  str(neig_list).count('peer-ip')
                    if neig_count == 1:
                        state = (neig_list)['peer-state']
                        if not 'Up' in state:
                            log.info('NVE Peer check failed for uut/neighbor %r',uut)
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            state = (neig_list)[i]['peer-state']
                            if not 'Up' in state:
                                log.info('NVE Peer check failed for uut/neighbor %r',uut)
                            else:
                                log.info('NVE Peer check passed for uut --------------')
                                return 1

        elif 'nve-vni' in proto:
            cmd = uut.execute("show nve vni")
            #test1=json.loads(uut.execute(cmd))
            if not "nve1" in str(cmd):
                log.info('No NVE VNI found,Test failed for uut/neighbor %r',uut)
                return 0

            if "Down" in str(cmd):
                log.info(' NVE VNI Down,Test failed for uut/neighbor %r',uut)
                return 0

            else:
                return 1



    log.info('Protocol check passed for uut -------------- :')



def vniCheck(uut,l2_scale,l3_scale):
    cmd = uut.execute("show nve vni")
    if not "nve1" in str(cmd):
        log.info('No NVE VNI found,Test failed for uut/neighbor %r',uut)
        return 0
    if "Down" in str(cmd):
        log.info(' NVE VNI Down,Test failed for uut/neighbor %r',uut)
        return 0
    l2_val = uut.execute("show nve vni | inc L2 | count")    
    l3_val = uut.execute("show nve vni | inc L3 | count")

    if l2_val != l2_scale:
        log.info(' l2_val != l2_scale %r',uut)
        return 0

    if l3_val != l3_scale:
        log.info(' l3_val != l3_scale %r',uut)
        return 0

    else:
        return 1


def leaf_ibgp_conf(uut,as_number,rid):

    cmd=\
            '''
            feature nv overlay
            nv overlay evpn
            feature bgp

            router bgp {as_number}
            router-id {rid}
            graceful-restart restart-time 200
            log-neighbor-changes
            address-family ipv4 unicast
             maximum-paths 32
             maximum-paths ibgp 32
            address-family l2vpn evpn
             maximum-paths ibgp 64
            '''
    try:
        uut.configure(cmd.format(rid=rid,as_number=as_number))
    except:
        log.error('iBGP config failed for uut %r',uut)

def leaf_neigh_template_conf(uut,as_number,update_src):
    cmd=\
            '''
            router bgp {as_number}
            template peer ibgp-vxlan
             remote-as {as_number}
             update-source {update_src}
             address-family ipv4 unicast
              soft-reconfiguration inbound always
             address-family l2vpn evpn
              send-community
              send-community extended
            '''
    try:
        uut.configure(cmd.format(update_src=update_src,as_number=as_number))
    except:
        log.error('iBGP config failed for uut %r',uut)

def spine_neigh_template_conf(uut,as_number,update_src,template_name):
    cmd=\
            '''
            router bgp {as_number}
            template peer {name}
            remote-as {as_number}
            update-source {update_src}
            address-family ipv4 unicast
            route-reflector-client
            soft-reconfiguration inbound always
            address-family l2vpn evpn
            send-community
            send-community extended
            route-reflector-client
            '''
    try:
        uut.configure(cmd.format(update_src=update_src,as_number=as_number,name=template_name))
    except:
        log.error('iBGP config failed for uut %r',uut)


def leaf_neigh_conf(uut,as_number,neigh_list,template_name):
    for neigh in neigh_list:
        cmd=\
            '''
            router bgp {as_number}
            neighbor {neigh}
             inherit peer {name}
            '''
        try:
            uut.configure(cmd.format(as_number=as_number,neigh=neigh,name=template_name))
        except:
            log.error('iBGP config failed for uut %r',uut)


def leaf_vrf_conf(uut,as_number,vrf_list):
        for vrf in vrf_list:
            cmd=\
            '''
            router bgp {as_number}
            vrf {vrf}
             address-family ipv4 unicast
             advertise l2vpn evpn
            '''
        try:
            uut.configure(cmd.format(as_number=as_number,vrf=vrf))
        except:
            log.error('iBGP config failed for uut %r',uut)

def ibgp_nwk_adv_conf(uut,as_number,adv_nwk_list):
    for nwk in adv_nwk_list:
        cmd=\
            '''
            router bgp {as_number}
            address-family ipv4 unicast
             network {nwk}
            '''
        try:
            uut.configure(cmd.format(as_number=as_number,nwk=nwk))
        except:
            log.error('iBGP config failed for uut %r',uut)

class IbgpSpineNode(object):
    def __init__(self,node,rid,as_number,adv_nwk_list,neigh_list,update_src,template_name):
        self.node=node
        self.rid=rid
        self.as_number=as_number
        self.adv_nwk_list=adv_nwk_list
        self.neigh_list=neigh_list
        self.update_src=update_src
        self.template_name=template_name

    def bgp_conf(self):
        leaf_ibgp_conf(self.node,rid=self.rid,as_number=self.as_number)
        if not 'Nil' in self.adv_nwk_list:
            ibgp_nwk_adv_conf(self.node,self.as_number,self.adv_nwk_list)
        spine_neigh_template_conf(self.node,self.as_number,self.update_src,self.template_name)
        leaf_neigh_conf(self.node,self.as_number,self.neigh_list,self.template_name)


class IbgpLeafNode(object):
    def __init__(self,node,rid,as_number,adv_nwk_list,neigh_list,update_src,template_name):
        self.node=node
        self.rid=rid
        self.as_number=as_number
        self.adv_nwk_list=adv_nwk_list
        self.neigh_list=neigh_list
        self.update_src=update_src
        self.template_name=template_name
        for neigh in self.neigh_list:
            if neigh==self.rid:
                log.info('Own RID removed from neigh list')
                self.neigh_list.remove(neigh)


    def bgp_conf(self):
        leaf_ibgp_conf(self.node,rid=self.rid,as_number=self.as_number)
        leaf_neigh_template_conf(self.node,self.as_number,self.update_src)
        if not 'Nil' in self.neigh_list:
            leaf_neigh_conf(self.node,self.as_number,self.neigh_list,self.template_name)
        if not 'Nil' in self.adv_nwk_list:
            ibgp_nwk_adv_conf(self.node,self.as_number,self.adv_nwk_list)




def spine_ibgp_conf(uut,as_number,rid,adv_nwk_list,update_src,neigh_list):
    cmd=\
            '''
            feature nv overlay
            nv overlay evpn

            router bgp {as_number}
            router-id {rid}
            graceful-restart restart-time 200
            log-neighbor-changes
            address-family ipv4 unicast
            address-family l2vpn evpn
            maximum-paths 64
            maximum-paths ibgp 64

            '''
    try:
        uut.configure(cmd.format(rid=rid,as_number=as_number,update_src=update_src))
    except:
        log.error('iBGP config failed for uut %r',uut)

    for neigh in neigh_list:
        cmd=\
            '''
            router bgp {as_number}
            neighbor {neigh}
            inherit peer ibgp-vxlan
            '''
    try:
        uut.configure(cmd.format(neigh=neigh,as_number=as_number))
    except:
        log.error('iBGP config failed for uut %r',uut)


    for nwk in adv_nwk_list:
        cmd=\
            '''
            router bgp {as_number}
            address-family ipv4 unicast
             network {nwk}
            '''
        try:
            uut.configure(cmd.format(as_number=as_number,nwk=nwk))
        except:
            log.error('iBGP config failed for uut %r',uut)

######
def vrf_configure(uut,routed_vni,count):
    cmd=""
    for i in range(0,count):
        cmd +=  'vrf context vxlan-{routed_vni}\n'.format(routed_vni=routed_vni)
        cmd +=  'vni {routed_vni}\n'.format(routed_vni=routed_vni)
        cmd +=  'rd auto\n'
        cmd +=  'address-family ipv4 unicast\n'
        cmd +=  'route-target import 1000:{routed_vni} \n'.format(routed_vni=routed_vni)
        cmd +=  'route-target import 1000:{routed_vni} evpn \n'.format(routed_vni=routed_vni)
        cmd +=  'route-target export 1000:{routed_vni} \n'.format(routed_vni=routed_vni)
        cmd +=  'route-target export 1000:{routed_vni} evpn \n'.format(routed_vni=routed_vni)
        cmd +=  'address-family ipv6 unicast\n'
        cmd +=  'route-target import 1000:{routed_vni} \n'.format(routed_vni=routed_vni)
        cmd +=  'route-target import 1000:{routed_vni} evpn\n'.format(routed_vni=routed_vni)
        cmd +=  'route-target export 1000:{routed_vni}\n'.format(routed_vni=routed_vni)
        cmd +=  'route-target export 1000:{routed_vni} evpn\n'.format(routed_vni=routed_vni)
        routed_vni = routed_vni + 1
    try:
        uut.configure(cmd)
    except:
        log.error('vrf configure failed for')


def vrf_configure_auto(uut,routed_vni,count):
    cmd=""
    for i in range(0,count):
        cmd +=  'vrf context vxlan-{routed_vni}\n'.format(routed_vni=routed_vni)
        cmd +=  'vni {routed_vni}\n'.format(routed_vni=routed_vni)
        cmd +=  'rd auto\n'
        cmd +=  'address-family ipv4 unicast\n'
        cmd +=  'route-target both auto\n' 
        cmd +=  'route-target both auto evpn\n' 
        cmd +=  'address-family ipv6 unicast\n'
        cmd +=  'route-target both auto\n' 
        cmd +=  'route-target both auto evpn\n' 
        routed_vni = routed_vni + 1
    try:
        uut.configure(cmd)
    except:
        log.error('vrf configure failed for')


def vlan_vni_configure(uut,vlan,vni,count):
    cmd=""
    for vlan,vni in zip(range(vlan,vlan+count),range(vni,vni+count)):
        #log.info('vlan ----------------- is %r vni is ----------------%r',vlan,vni)
        cmd +=  'vlan {vlan}\n'.format(vlan=vlan)
        cmd +=  'vn-segment {vni}\n'.format(vni=vni)
    try:
        uut.configure(cmd)
    except:
        log.error('vni/vlan configure failed for uut')


def vlan_vni_remove(uut,vlan,vni,count):
    for vlan,vni in zip(range(vlan,vlan+count+1),range(vni,vni+count+1)):
        log.info('vlan ----------------- is %r vni is ----------------%r',vlan,vni)
        cmd = \
            '''
            vlan {vlan}
            no vn-segment {vni}
            '''
        try:
            uut.configure(cmd.format(vni=vni,vlan=vlan))
        except:
            log.error('vni/vlan configure failed for uut',uut,'vlan/vni',vlan,vni)


def vlan_remove(uut,vlan,count):
    for vlan in range(vlan,vlan+count+1):
        log.info('vlan ----------------- is %r ',vlan)
        cmd = \
            '''
             no vlan {vlan}
            '''
        try:
            uut.configure(cmd.format(vlan=vlan))
        except:
            log.error('vlan remove configure failed')



def routed_svi_configure(uut,routed_vlan,routed_vni,count):
    cmd = ""
    for i in range(0,count):
        cmd += 'no interface Vlan{routed_vlan}\n'.format(routed_vlan=routed_vlan)
        cmd += 'interface Vlan{routed_vlan}\n'.format(routed_vlan=routed_vlan)
        cmd += 'no shutdown\n'
        cmd += 'mtu 9216\n'
        cmd += 'vrf member vxlan-{routed_vni}\n'.format(routed_vni=routed_vni)
        cmd += 'no ip redirects\n'
        cmd += 'no ipv6 redirects\n'
        cmd += 'ip forward\n'
        cmd += 'ipv6 forward\n'
        routed_vni = routed_vni + 1
        routed_vlan = routed_vlan + 1
    try:
        uut.configure(cmd)
    except:
        log.error('Routed SVI configure failed for uut')

def ConnectIxia (labserver_ip,tgn_ip,port_list):
    
    ixia_tcl_server_addr_str = str(labserver_ip) + ":" + str(8009)

    _result_ = ixiahlt.connect(
                                device = str(tgn_ip),
                                reset=1,
                                port_list = port_list,
                                ixnetwork_tcl_server= ixia_tcl_server_addr_str,
                                break_locks = 1
                                    )
    if _result_['status'] == '1':
        print("Ixia connection successfull")
        log.info("Ixia Connection is Successfull")
        return _result_
    else:
        print("Ixia Connection Failed")
        log.info("Ixia connection id Failed")
        return 0
        


def ConnectSpirent(labserver_ip,tgn_ip,port_list):
    """ function to configure vpc """
    logger.info(banner("connecting to <<<< Spirent >>>>"))
    try:
        lab_svr_sess = ixiangpf.labserver_connect(server_ip =labserver_ip,create_new_session = 1, session_name = "Stc",user_name = "danthoma")
        intStatus = ixiangpf.connect(device=tgn_ip, port_list = port_list,break_locks = 1, offline = 0 )
        #(' intStatus', {'status': '1', 'offline': '0', 'port_handle': {'10.127.62.251': {'1/7': 'port1', '1/4': 'port2'}}})
        #print("intStatus",intStatus)
        status=intStatus['status']
        
 
        if (status == '1') :
            spirent_port_handle=intStatus['port_handle'][tgn_ip]
            log.info("port_handle is %r",spirent_port_handle)
            return spirent_port_handle
        else :
            log.info('\nFailed to retrieve port handle!\n')
            return (0, tgn_port_dict)
    except:

        log.error('Spirect connection failed')
        log.error(sys.exc_info())


def svi_configure(uut,vlan,vlan_scale,ipv4_add,ipv6_add,routed_vni,routed_vni_scale):
    v4 = ip_address(ipv4_add)
    v6 = IPv6Address(ipv6_add)
    c2 = int(vlan_scale/routed_vni_scale)
    cmd = " "
    for j in range(0,routed_vni_scale):  # 5
        for i in range(0,c2):
            v4 = v4 + 65536
            v6 = v6 + 65536
            v4add = v4 + 1
            v6add = v6 + 1
            cmd += 'no interface Vlan{vlan}\n'.format(vlan=vlan)
            cmd += 'interface Vlan{vlan}\n'.format(vlan=vlan)
            cmd += 'no shutdown\n'
            cmd += 'mtu 9216\n'
            cmd += 'vrf member vxlan-{routed_vni}\n'.format(routed_vni=routed_vni)
            cmd += 'no ip redirects\n'
            cmd += 'ip address {v4add}/16\n'.format(v4add=v4add)
            cmd += 'ipv6 address {v6add}/112\n'.format(v6add=v6add)
            cmd += 'no ipv6 redirects\n'
            cmd += 'fabric forwarding mode anycast-gateway\n'
            vlan = vlan + 1
        routed_vni = routed_vni + 1
    try:
        uut.configure(cmd)
    except:
        log.error('SVI configure failed for vlan')



def nve_configure_bgp(uut,vni,count):

    cmd1 = \
    """
    interface nve1
    no shutdown
    host-reachability protocol bgp
    source-interface loopback0
    source-interface hold-down-time 30
    """
    uut.configure(cmd1)
    c1 = int(count/2)-1
    vni1 = vni
    vni2 = vni1 + c1
    cmd = " "
    cmd += 'interface nve1\n'
    for vni in range(vni1,vni2+1):
        cmd += 'member vni {vni}\n'.format(vni=vni)
        cmd += 'suppress-arp\n'
        cmd += 'ingress-replication protocol bgp\n'

    try:
        uut.configure(cmd)
    except:
        log.info('vni_configure failed for uut %r',uut)


def nve_configure_mcast222(uut,vni,count,mcast_group,mcast_group_scale):
    cmd = \
            '''
            interface nve1
            no shutdown
            host-reachability protocol bgp

            source-interface loopback0
            source-interface hold-down-time 30
            '''
    try:
        uut.configure(cmd)
    except:
        log.error('vni_configure failed for uut',uut)

    c1 = int(count/2)
    vni = vni + c1
    c2 = int(c1/mcast_group_scale)
    mcast = ip_address(mcast_group)
    cmd= " "
    cmd += 'interface nve1\n'
    for j in range(0,mcast_group_scale):
        mcast = mcast+1
        for i in range(0,c2):
            cmd += 'member vni {vni}\n'.format(vni=vni)
            cmd += 'suppress-arp\n'
            cmd += 'mcast-group {mcast}\n'.format(mcast=mcast)
            vni = vni + 1

    try:
        uut.configure(cmd)
    except:
        log.error('routed_vni_configure failed for mcast/vni')



def nve_configure_only_mcast(uut,vni,count,mcast_group):
    cmd1 = \
            '''
            interface nve1
            no shutdown
            host-reachability protocol bgp

            source-interface loopback0
            source-interface hold-down-time 30
            '''
    try:
        uut.configure(cmd1)
    except:
        log.info('vni_configure failed for uut %r',uut)

    if int(count)>500:
        c2 = int(count/20)
        a1 = 20
    else:
        c2 = int(count/4)
        a1 = 4
    mcast = ip_address(mcast_group)
    cmd = ""
    cmd +=  'interface nve1\n'
    for j in range(0,a1):
        mcast = mcast+1
        for i in range(0,c2):
            cmd += 'member vni {vni}\n'.format(vni=vni)
            cmd += 'suppress-arp\n'
            cmd += 'mcast-group {mcast}\n'.format(mcast=mcast)
            vni = vni + 1
    try:
        uut.configure(cmd)
    except:
        log.info('mcast_vni_configure failed')

def nve_configure_only_bgp(uut,vni,count):
    cmd1 = \
            '''
            no interface nve1
            interface nve1
            no shutdown
            host-reachability protocol bgp

            source-interface loopback0
            source-interface hold-down-time 30
            '''
    try:
        uut.configure(cmd1)
    except:
        log.info('vni_configure failed for uut %r',uut)

    vni1 = vni
    vni2 = vni1 + count - 1
    cmd = " "
    cmd += 'interface nve1\n'
    for vni in range(vni1,vni2+1):
        cmd += 'member vni {vni}\n'.format(vni=vni)
        cmd += 'suppress-arp\n'
        cmd += 'ingress-replication protocol bgp\n'
    try:
        uut.configure(cmd.format(vni1=vni1,vni2=vni2))
    except:
        log.error('vni_configure failed for uut %r',uut)


def routed_nve_configure(uut,routed_vni,count):
    cmd = " "
    cmd += 'interface nve1\n'
    for i in range(0,count):
        cmd += 'member vni {routed_vni} associate-vrf\n'.format(routed_vni=routed_vni)
        routed_vni = routed_vni + 1
    try:
        uut.configure(cmd)
    except:
        log.error('routed_vni_configure failed for uut',uut,'vlan/vni',routed_vni)


def evpn_vni_configure(uut,vni,count):
    cmd = ""
    cmd +=  'evpn\n'
    for i in range(0,count):
        cmd += 'vni {vni} l2\n'.format(vni=vni)
        cmd += 'rd auto\n'
        cmd += 'route-target import auto\n'
        cmd += 'route-target export auto\n'
        vni = vni + 1
    try:
        uut.configure(cmd)
    except:
        log.error('vni/vlan configure failed for uut ')



def vrf_bgp_configure(uut,as_number,routed_vni,count):
    print("Count issss",count)
    for i in range(0,count):

        #print(routed_vni)
        cmd = \
            '''
            router bgp {as_number}
            vrf vxlan-{routed_vni}
              graceful-restart restart-time 300
              address-family ipv4 unicast
                advertise l2vpn evpn
              address-family ipv6 unicast
               advertise l2vpn evpn
            '''
        #print(cmd.format(routed_vni=routed_vni,as_number=as_number))
        try:
            uut.configure(cmd.format(routed_vni=routed_vni,as_number=as_number))
        except:
            log.error('vni/vlan configure failed for uut %r vni %r',uut,routed_vni)

        routed_vni = routed_vni + 1

def pip_configure(uut):
    op = uut.execute("show run bgp | incl 'router bgp'")
    op = op.splitlines()
    for line in op:
        if line:
            if 'bgp' in line:
                as_number = line.split()[-1]

    cmd = \
        """
        router bgp {as_number}
        address-family l2vpn evpn 
        advertise-pip 
        interf nve 1
        advertise virtual-rmac 
        """
    try:
        uut.configure(cmd.format(as_number=as_number))
    except:
        log.error('pip_configure configure failed for uut %r vni %r',uut)
        return 0



class LeafObject2222(object):
    def __init__(self,node,vlan,vni,vlan_scale,routed_vlan,routed_vni,routed_vni_scale,\
    ipv4_add,ipv6_add,mcast_group,as_number,ir_mode,mcast_group_scale):
        self.node=node
        self.vlan=vlan
        self.vni=vni
        self.vlan_scale=vlan_scale
        self.routed_vlan=routed_vlan
        self.routed_vni=routed_vni
        self.routed_vni_scale=routed_vni_scale
        self.ipv4_add=ipv4_add
        self.ipv6_add=ipv6_add
        self.mcast_group=mcast_group
        self.as_number=as_number
        self.ir_mode=ir_mode
        self.mcast_group_scale=mcast_group_scale

        #ir_mode = bgp,mcast,mix

    def vxlan_conf(self):

        vrf_configure(self.node,self.routed_vni,self.routed_vni_scale)
        vlan_vni_configure(self.node,self.routed_vlan,self.routed_vni,self.routed_vni_scale)
        vlan_vni_configure(self.node,self.vlan,self.vni,self.vlan_scale)
        routed_svi_configure(self.node,self.routed_vlan,self.routed_vni,self.routed_vni_scale)
        svi_configure(self.node,self.vlan,self.vlan_scale,self.ipv4_add,self.ipv6_add,self.routed_vni,self.routed_vni_scale)

        if 'mix' in self.ir_mode:
            log.info(banner("Replication mode is BGP + MCAST"))
            nve_configure_bgp(self.node,self.vni,self.vlan_scale)
            nve_configure_mcast222(self.node,self.vni,self.vlan_scale,self.mcast_group,self.mcast_group_scale)
        elif 'bgp' in self.ir_mode:
            log.info(banner("Replication mode is BGP"))
            nve_configure_only_bgp(self.node,self.vni,self.vlan_scale)
        elif 'mcast' in self.ir_mode:
            log.info(banner("Replication mode is MCAST"))
            nve_configure_only_mcast(self.node,self.vni,self.vlan_scale,self.mcast_group)

        routed_nve_configure(self.node,self.routed_vni,self.routed_vni_scale)
        evpn_vni_configure(self.node,self.vni,self.vlan_scale)
        vrf_bgp_configure(self.node,self.as_number,self.routed_vni,self.routed_vni_scale)


class vxlanObject(object):
    def __init__(self,node,vlan,vni,vlan_scale,routed_vlan,routed_vni,routed_vni_scale,\
    ipv4_add,ipv6_add,mcast_group,as_number,ir_mode,mcast_group_scale):
        self.node=node
        self.vlan=vlan
        self.vni=vni
        self.vlan_scale=vlan_scale
        self.routed_vlan=routed_vlan
        self.routed_vni=routed_vni
        self.routed_vni_scale=routed_vni_scale
        self.ipv4_add=ipv4_add
        self.ipv6_add=ipv6_add
        self.mcast_group=mcast_group
        self.as_number=as_number
        self.ir_mode=ir_mode
        self.mcast_group_scale=mcast_group_scale

        #ir_mode = bgp,mcast,mix

    def vxlan_conf(self):
        vrf_configure_auto(self.node,self.routed_vni,self.routed_vni_scale)
        vlan_vni_configure(self.node,self.routed_vlan,self.routed_vni,self.routed_vni_scale)
        vlan_vni_configure(self.node,self.vlan,self.vni,self.vlan_scale)
        routed_svi_configure(self.node,self.routed_vlan,self.routed_vni,self.routed_vni_scale)
        svi_configure(self.node,self.vlan,self.vlan_scale,self.ipv4_add,self.ipv6_add,self.routed_vni,self.routed_vni_scale)

        if 'mix' in self.ir_mode:
            log.info(banner("Replication mode is BGP + MCAST"))
            nve_configure_bgp(self.node,self.vni,self.vlan_scale)
            nve_configure_mcast222(self.node,self.vni,self.vlan_scale,self.mcast_group,self.mcast_group_scale)
        elif 'bgp' in self.ir_mode:
            log.info(banner("Replication mode is BGP"))
            nve_configure_only_bgp(self.node,self.vni,self.vlan_scale)
        elif 'mcast' in self.ir_mode:
            log.info(banner("Replication mode is MCAST"))
            nve_configure_only_mcast(self.node,self.vni,self.vlan_scale,self.mcast_group)

        routed_nve_configure(self.node,self.routed_vni,self.routed_vni_scale)
        evpn_vni_configure(self.node,self.vni,self.vlan_scale)
        vrf_bgp_configure(self.node,self.as_number,self.routed_vni,self.routed_vni_scale)


class LeafObjectL2(object):
    def __init__(self,node,vlan,vni,vlan_scale,\
    mcast_group,ir_mode,mcast_group_scale):
        self.node=node
        self.vlan=vlan
        self.vni=vni
        self.vlan_scale=vlan_scale
        self.mcast_group=mcast_group
        self.ir_mode=ir_mode
        self.mcast_group_scale=mcast_group_scale

        #ir_mode = bgp,mcast,mix

    def vxlan_conf(self):
        vlan_vni_configure(self.node,self.vlan,self.vni,self.vlan_scale)

        if 'mix' in self.ir_mode:
            log.info(banner("Replication mode is BGP + MCAST"))
            nve_configure_bgp(self.node,self.vni,self.vlan_scale)
            nve_configure_mcast222(self.node,self.vni,self.vlan_scale,self.mcast_group,self.mcast_group_scale)
        elif 'bgp' in self.ir_mode:
            log.info(banner("Replication mode is BGP"))
            nve_configure_only_bgp(self.node,self.vni,self.vlan_scale)
        elif 'mcast' in self.ir_mode:
            log.info(banner("Replication mode is MCAST"))
            nve_configure_only_mcast(self.node,self.vni,self.vlan_scale,self.mcast_group)
        evpn_vni_configure(self.node,self.vni,self.vlan_scale)






def ArpTrafficGenerator2(port_handle,vlan,ip_sa,ip_da,mac_sa,rate_pps,count):

    log.info("port_handle %r vlan %r ip_sa %r ip_da %r mac_sa %r ",port_handle,vlan,ip_sa,ip_da,mac_sa)
    streamblock_ret1 = ixiangpf.traffic_config (
        mode = 'create',
        port_handle = port_handle,
        l2_encap = 'ethernet_ii_vlan',
        stream_id = vlan,
        vlan_id=vlan,
        l3_protocol = 'arp',
        ip_src_addr = ip_sa,
        ip_src_count = count,
        ip_src_mode = 'increment',
        ip_src_step ='0.0.0.1',
        ip_dst_addr = ip_da,
        ip_dst_count = count,
        ip_dst_mode = 'increment',
        ip_dst_step ='0.0.0.1',
        arp_src_hw_addr = mac_sa,
        arp_src_hw_mode = 'increment',
        arp_src_hw_count = count,
        arp_dst_hw_addr = "00:00:00:00:00:00",
        arp_dst_hw_mode = "fixed",
        arp_operation = "arpRequest",
        rate_pps = rate_pps,
        mac_src = mac_sa,
        mac_dst = 'ff:ff:ff:ff:ff:ff',
        mac_src_count= count,
        mac_src_mode='increment',
        mac_src_step='00:00:00:00:00:01',
        transmit_mode = 'continuous')

    status = streamblock_ret1['status']


def VxlanStArpGen(port_handle_list,vlan,ip_sa,ip_da,mac_sa,rate_pps,count):
    log.info(banner("Starting VxlanStArpGen"))

    for port_hdl in  port_handle_list:
        log.info("Resetting all Streams for Port %r",port_hdl)
        traffic_ctrl_ret = ixiangpf.traffic_control(port_handle = port_hdl, action = 'reset' ,db_file=0 )


    ip_sa1 = ip_address(ip_sa)
    ip_da1 = ip_address(ip_da)
    mac_sa1 = EUI(mac_sa)

    for port_hdl in  port_handle_list:
        #log.info("Adding ARP Stream for Port %r",port_hdl)
        ArpTrafficGenerator2(port_hdl,vlan,str(ip_sa1),str(ip_da1),str(mac_sa1),rate_pps,count)
        mac_sa2 = int(mac_sa1)+1
        mac_sa1 = EUI(mac_sa2)
        ip_sa1 =  ip_sa1+1
        ip_da1 =  ip_da1

    for port_hdl in  port_handle_list:
        log.info("Starting ARP Stream Traffic for Port %r",port_hdl)
        traffic_ctrl_ret = ixiangpf.traffic_control(port_handle = port_hdl, action = 'run')

    log.info(banner("Starting ARP for all streams"))
    for i in range(1,4):
        doarp = ixiangf.arp_control(arp_target='allstream',arpnd_report_retrieve='1')


def FloodTrafficGeneratorScale(port_handle,vlan,ip_sa,ip_da,rate_pps,count):

    log.info(banner('in FloodTrafficGeneratorScale '))

    str1=hex(randint(16,54))[2:]
    str2=hex(randint(55,104))[2:]
    str3=hex(randint(32,80))[2:]
    str4=hex(randint(50,95))[2:]

    mac1='00:'+str4+':'+str2+':'+str1+':'+str3+':02'
    #mac2='00:10:'+str1+':'+str2+':'+str4+':02'

    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        traffic_generator = 'ixnetwork_540',
        port_handle     =       port_handle,
        l2_encap        =      'ethernet_ii_vlan',
        vlan_id         =       vlan,
        stream_id       =       vlan,
        vlan_id_count   =       count,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip_sa,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       count,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip_da,
        mac_dst         =       'ff:ff:ff:ff:ff:ff',
        mac_src         =       mac1,
        mac_src_count   =       count,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')
    
    print("Floadtraffic", device_ret)

    status = device_ret['status']
    if (status == '0') :
        log.info("run ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** run ixiahlt.traffic_config successfully")
        return 1


def SpirentBidirStream222(port_hdl1,port_hdl2,vlan1,vlan2,scale,ip1,ip2,gw1,gw2,rate_pps):
    #log.info(banner("------SpirentHostBidirStream-----"))
    log.info('VLAN1 : %r,VLAN2 : %r,SCALE : %r,IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,vlan1,vlan2,scale,ip1,ip2,gw1,gw2)

    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        traffic_generator =    'ixnetwork_540',
        port_handle     =       port_hdl1,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan1,
        vlan_id_count   =       scale,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip1,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       scale,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip2,
        ip_dst_step     =       '0.1.0.0',
        ip_dst_count    =       scale,
        ip_dst_mode     =       'increment',
        mac_src         =       '00:12:94:aa:00:02',
        mac_dst         =       '00:13:94:bb:00:02',
        mac_src_count   =       scale,
        mac_src_mode    =       'increment',
        mac_src_step    =       '00:00:00:00:00:01',
        mac_dst_count   =       scale,
        mac_dst_mode    =       'increment',
        mac_dst_step    =       '00:00:00:00:00:01',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')
    print("Bidir Stream 222", device_ret)
    status = device_ret['status']
    if (status == '0'):
        log.info("port_hdl1 ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** port_hdl1 ixiahlt.traffic_config successfully")
        
        
        

    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        traffic_generator =  'ixnetwork_540',
        port_handle     =       port_hdl2,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan1,
        vlan_id_count   =       scale,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip2,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       scale,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip1,
        ip_dst_step     =       '0.1.0.0',
        ip_dst_count    =       scale,
        ip_dst_mode     =       'increment',
        mac_src         =       '00:13:94:bb:00:02',
        mac_dst         =       '00:12:94:aa:00:02',
        mac_src_count   =       scale,
        mac_src_mode    =       'increment',
        mac_src_step    =       '00:00:00:00:00:01',
        mac_dst_count   =       scale,
        mac_dst_mode    =       'increment',
        mac_dst_step    =       '00:00:00:00:00:01',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')
    print("Bidir Stream 222", device_ret)
    status = device_ret['status']
    if (status == '0'):
        log.info("port_hdl2 ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** port_hdl2 ixiahlt.traffic_config successfully")
        return 1


def BidirStream(port_hdl1,port_hdl2,vlan1,vlan2,scale,ip1,ip2,gw1,gw2,rate_pps):
    #log.info(banner("------SpirentHostBidirStream-----"))
    log.info('VLAN1 : %r,VLAN2 : %r,SCALE : %r,IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,vlan1,vlan2,scale,ip1,ip2,gw1,gw2)

    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        port_handle     =       port_hdl1,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan1,
        vlan_id_count   =       scale,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip1,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       scale,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip2,
        ip_dst_step     =       '0.1.0.0',
        ip_dst_count    =       scale,
        ip_dst_mode     =       'increment',
        mac_src         =       '00:12:94:aa:00:02',
        mac_dst         =       '00:13:94:bb:00:02',
        mac_src_count   =       scale,
        mac_src_mode    =       'increment',
        mac_src_step    =       '00:00:00:00:00:01',
        mac_dst_count   =       scale,
        mac_dst_mode    =       'increment',
        mac_dst_step    =       '00:00:00:00:00:01',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')

    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        port_handle     =       port_hdl2,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan1,
        vlan_id_count   =       scale,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip2,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       scale,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip1,
        ip_dst_step     =       '0.1.0.0',
        ip_dst_count    =       scale,
        ip_dst_mode     =       'increment',
        mac_src         =       '00:13:94:bb:00:02',
        mac_dst         =       '00:12:94:aa:00:02',
        mac_src_count   =       scale,
        mac_src_mode    =       'increment',
        mac_src_step    =       '00:00:00:00:00:01',
        mac_dst_count   =       scale,
        mac_dst_mode    =       'increment',
        mac_dst_step    =       '00:00:00:00:00:01',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')


def SpirentRoutedBidirStream(uut,port_hdl1,port_hdl2,pps):
    log.info(banner("------SpirentHostBidirStream-----"))

    op = uut.execute('show nve vni  | incl L3')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            if 'MS-IR' in line:
                vrf = line.split()[-2].replace("[","").replace("]","")
                vrf_list.append(vrf)
            else:    
                vrf = line.split()[-1].replace("[","").replace("]","")
                vrf_list.append(vrf)


    for vrf in vrf_list:
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        vlan_list = []
        ip_list = []
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        vlan_list.append(line.split()[0].replace("Vlan",""))
                        ip_list.append(line.split()[1])

        if not len(vlan_list) == len(ip_list):
            return 0
        else:
            gw1 = str(ip_address(ip_list[0]))
            ip1 = str(ip_address(gw1)+1)
            ip11= str(ip_address(ip1)+100)

            SpirentHostBidirStreamSmacSame(port_hdl1,port_hdl2,vlan_list[0],vlan_list[0],ip1,ip11,ip11,ip1,str(pps))

            for i in range(1,len(vlan_list)):
                vlan2 = vlan_list[i]
                gw2 = ip_list[i]
                ip2 = str(ip_address(gw2)+100)
                SpirentHostBidirStreamSmacSame(port_hdl1,port_hdl2,vlan_list[0],vlan2,ip1,ip2,gw1,gw2,str(pps))

    return 1



def SpirentRoutedBidirStreamScaled(uut,port_hdl1,port_hdl2,test_l3_vni_scale):
    log.info(banner("------SpirentHostBidirStream-----"))
    l3_vlan_count = uut.execute('show nve vni | inc L3 | count')
    op = uut.execute('show nve vni  | incl L3')
    op1 = op.splitlines()
    vrf_list=[]
 
    for line in op1:
        if line:
            if 'MS-IR' in line:
                vrf = line.split()[-2].replace("[","").replace("]","")
                vrf_list.append(vrf)
            else:    
                vrf = line.split()[-1].replace("[","").replace("]","")
                vrf_list.append(vrf)


    if l3_vlan_count  == test_l3_vni_scale:
        test_vrf_list = vrf_list

    elif 'Nil' in str(test_l3_vni_scale):
        test_vrf_list = vrf_list
    else:
        test_vrf_list = []
        for i in range(0,test_l3_vni_scale):
            test_vrf_list.append(choice(vrf_list))    

    for vrf in test_vrf_list:
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        vlan_list = []
        ip_list = []
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        vlan_list.append(line.split()[0].replace("Vlan",""))
                        ip_list.append(line.split()[1])
        
        vlan_per_vrf = len(vlan_list)
        lotal_streams = vlan_per_vrf*test_l3_vni_scale
        rate_per_stream = int(200000/lotal_streams)

        if not len(vlan_list) == len(ip_list):
            return 0
        else:
            gw1 = str(ip_address(ip_list[0]))
            ip1 = str(ip_address(gw1)+1)
            ip11= str(ip_address(ip1)+100)

            SpirentHostBidirStreamSmacSame(port_hdl1,port_hdl2,vlan_list[0],vlan_list[0],ip1,ip11,ip11,ip1,str(rate_per_stream))

            for i in range(1,len(vlan_list)):
                vlan2 = vlan_list[i]
                gw2 = ip_list[i]
                ip2 = str(ip_address(gw2)+100)
                SpirentHostBidirStreamSmacSame(port_hdl1,port_hdl2,vlan_list[0],vlan2,ip1,ip2,gw1,gw2,str(rate_per_stream))

    return 1

def SpirentHostBidirStreamSmacSame(port_hdl1,port_hdl2,vlan1,vlan2,ip1,ip2,gw1,gw2,rate_pps):
    log.info(banner("------SpirentHostBidirStream-----"))


    str11 = hex(int(vlan1))[2:][:2]
    str12 = hex(int(vlan1))[2:][1:]
    str21 = hex(int(vlan2))[2:][:2]
    str22 = hex(int(vlan2))[2:][1:]

    if vlan1==vlan2:
        mac1='00:10:'+str11+':'+str12+':'+str11+':22'
        mac2='00:11:'+str22+':'+str22+':'+str21+':44'
    else:
        mac1='00:10:'+str11+':'+str12+':'+str11+':22'
        mac2='00:10:'+str21+':'+str22+':'+str21+':22'

    print("port_hdl1", port_hdl1)
    log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)
    device_ret1 =ixiahlt.interface_config (mode = 'config',\
    port_handle = port_hdl1,vlan = 1, vlan_id  = vlan1,intf_ip_addr = ip1, netmask = '255.255.0.0',\
    gateway = gw1,src_mac_addr = mac1)
    
    print("port_hdl1 status", device_ret1)
    
    if device_ret1['status'] == '1':
        log.info('Successfully configured protocol interfaces')
    else:
        log.error('Failed to configure protocol interfaces')
    
    print("port_hdl2", port_hdl2)
    device_ret2 =ixiahlt.interface_config (mode = 'config',port_handle = port_hdl2,\
    vlan = 1, vlan_id  = vlan2, intf_ip_addr = ip2, netmask = '255.255.0.0',\
    gateway = gw2, src_mac_addr = mac2)
    
    print("port_hdl2 status",device_ret2)
    
    if device_ret2['status'] == '1':
        log.info('Successfully configured protocol interfaces')
    else:
        log.error('Failed to configure protocol interfaces')
        
    print("device_ret1 value is",device_ret1)
    print("device_ret2 value is",device_ret2)
    h1 = device_ret1['interface_handle']
    h2 = device_ret2['interface_handle']

    streamblock_ret1 = ixiahlt.traffic_config (mode= 'create',port_handle= port_hdl1,\
    emulation_src_handle=h1,emulation_dst_handle = h2,bidirectional='1',\
    port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps)
    
    status = streamblock_ret1['status']

    log.info('+-----------------------------------------------------------------------+')
    log.info('stream_id : %r, vlan1 : %r ,vlan2 : %r ,rate_pps : %r',streamblock_ret1['stream_id'],vlan1,vlan2,rate_pps)
    log.info('IP1 : %r,IP2 : %r, Host1 : %r ,Host2 : %r ',ip1,ip2,h1,h2)
    log.info('+-----------------------------------------------------------------------+')
    if (status == '0') :
        log.info('run ixiahlt.traffic_config failed for V4 %r', streamblock_ret1)
    else:
        log.info('***** run ixiahlt.traffic_config successful for V4')




def SpirentHostBidirStreamType5(port_hdl1,port_hdl2,vlan1,vlan2,ip1,ip2,gw1,gw2,rate_pps):
    log.info(banner("------SpirentHostBidirStreamType5-----"))

    #str11 = hex(int(1001))[2:][:2]
    #str12 = hex(int(1001))[2:][1:]
    #str21 = hex(int(vlan2))[2:][:2]
    #str22 = hex(int(vlan2))[2:][1:]

    #mac1='00:10:'+str11+':'+str12+':'+str11+':22'
    #mac2='00:10:'+str21+':'+str22+':'+str21+':22'

    mac1 = str(RandMac("00:00:00:00:00:00", True)).replace("'","")
    #mac1 = mac1.replace("'","")
    mac2 = str(RandMac("00:00:00:00:00:00", True)).replace("'","")
    #mac2 = mac2.replace("'","")


    if 'Nil' in vlan1:
        log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)
        device_ret1 =ixiahlt.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
        encapsulation = 'ethernet_ii',port_handle = port_hdl1,\
        resolve_gateway_mac = 'true',intf_ip_addr= ip1,intf_prefix_len = '24',\
        gateway_ip_addr = gw1,mac_addr= mac1);

    else:
        device_ret1 =ixiahlt.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
        encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan1,port_handle = port_hdl1,\
        resolve_gateway_mac = 'true',intf_ip_addr= ip1,intf_prefix_len = '24',\
        gateway_ip_addr = gw1,mac_addr= mac1);


    device_ret2 =ixiangpf.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan2,port_handle = port_hdl2,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip2,intf_prefix_len = '24',\
    gateway_ip_addr = gw2,mac_addr= mac2);

    h1 = device_ret1['handle']
    h2 = device_ret2['handle']

    streamblock_ret1 = ixiangpf.traffic_config (mode= 'create',port_handle= port_hdl1,\
    emulation_src_handle=h1,emulation_dst_handle = h2,bidirectional='1',\
    port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps)

    status = streamblock_ret1['status']

    log.info('+-----------------------------------------------------------------------+')
    log.info('stream_id : %r, vlan1 : %r ,vlan2 : %r ,rate_pps : %r',streamblock_ret1['stream_id'],vlan1,vlan2,rate_pps)
    log.info('IP1 : %r,IP2 : %r, Host1 : %r ,Host2 : %r ',ip1,ip2,h1,h2)
    log.info('+-----------------------------------------------------------------------+')
    if (status == '0') :
        log.error('run ixiangpf.traffic_config failed for V4 %r', streamblock_ret1)



def SpirentV6BidirStream(port_hdl1,port_hdl2,vlan1,vlan2,scale,ipv61,ipv62,rate_pps):
    log.info(banner("STARTING SpirentV6BidirStream "))
    log.info('VLAN1 : %r,VLAN2 : %r,SCALE : %r,IP1 : %r,IP2 : %r ' ,vlan1,vlan2,scale,ipv61,ipv62)

    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        port_handle     =       port_hdl1,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan1,
        vlan_id_count   =       scale,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv6',
        ipv6_src_addr   =       ipv61,
        ipv6_src_step   =       '0000:0000:0000:0000:0000:0000:0001:0000',
        ipv6_src_count  =       scale,
        ipv6_src_mode   =       'increment',
        ipv6_dst_addr   =       ipv62,
        ipv6_dst_step   =       '0000:0000:0000:0000:0000:0000:0001:0000',
        ipv6_dst_count  =       scale,
        ipv6_dst_mode   =       'increment',
        mac_src         =       '00:12:60:60:00:02',
        mac_dst         =       '00:13:60:60:00:02',
        mac_src_count   =       scale,
        mac_src_mode    =       'increment',
        mac_src_step    =       '00:00:00:00:00:01',
        mac_dst_count   =       scale,
        mac_dst_mode    =       'increment',
        mac_dst_step    =       '00:00:00:00:00:01',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')
    status = device_ret['status']
    if (status == '0'):
        log.info("port_hdl1 ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** port_hdl1 ixiahlt.traffic_config successfully")
        
        

    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        port_handle     =       port_hdl2,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan2,
        vlan_id_count   =       scale,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv6',
        ipv6_src_addr   =       ipv62,
        ipv6_src_step   =       '0000:0000:0000:0000:0000:0000:0001:0000',
        ipv6_src_count  =       scale,
        ipv6_src_mode   =       'increment',
        ipv6_dst_addr   =       ipv61,
        ipv6_dst_step   =       '0000:0000:0000:0000:0000:0000:0001:0000',
        ipv6_dst_count  =       scale,
        ipv6_dst_mode   =       'increment',
        mac_src         =       '00:13:60:60:00:02',
        mac_dst         =       '00:12:60:60:00:02',
        mac_src_count   =       scale,
        mac_src_mode    =       'increment',
        mac_src_step    =       '00:00:00:00:00:01',
        mac_dst_count   =       scale,
        mac_dst_mode    =       'increment',
        mac_dst_step    =       '00:00:00:00:00:01',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')
    status = device_ret['status']
    if (status == '0'):
        log.info("port_hdl2 ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** port_hdl2 ixiahlt.traffic_config successfully")



def SpirentRateTest22(port_hdl1,port_hdl2,rate_fps,diff):
    log.info(banner("  Starting Spirent Rate Test "))
    diff = 4*int(diff)
    result = 1
    for port_hdl in [port_hdl1,port_hdl2]:
        log.info("port_hdl %r,rate_fps %r,diff is %r", port_hdl,rate_fps,diff)
        try:            
            #res = ixiahlt.traffic_stats(port_handle = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            res = ixiahlt.traffic_stats(port_handle = port_hdl,mode = 'aggregate',traffic_generator = 'ixnetwork')
            print('traffic_status of res', res)
        except:
            log.info('Stats failed for port %r',port_hdl)
            return 0
        try:               
            # rx_rate = res['item0']['PortRxTotalFrameRate']
            # tx_rate = res['item0']['PortTxTotalFrameRate']
            rx_rate = int(res['aggregate']['rx']['raw_pkt_rate']['max'])*9
            tx_rate = int(res['aggregate']['tx']['total_pkt_rate']['max'])
        except:
            log.info('rx_rate failed for port %r',port_hdl)
            return 0
        log.info('+-----------------------------------------------------------------------+')
        log.info('rx_rate is %r,tx_rate is %r',rx_rate,tx_rate)
        log.info('+-----------------------------------------------------------------------+')
        if abs(int(rx_rate) - int(tx_rate)) > diff:
            log.info('Traffic  Rate Test failed - TX / RX difference is %r',abs(int(rx_rate) - int(tx_rate)))
            log.info('Streamblock is %r',res)
            result = 0
        if abs(int(rx_rate) - int(rate_fps)) > diff:
            log.info('Traffic  Rate Test failed, Rate & FPS diff is %r',abs(int(rx_rate) - int(rate_fps)))
            log.info('Streamblock is %r',res)
            result = 0
    log.info(banner(" Completed Spirent Rate Test "))
    return result


def AllTrafficTest(port_handle1,port_handle2,rate,pps,orphan_handle_list):
    rate3=int(rate)*4
    #diff = 4*int(pps)
    diff = int(rate3*.0125)
    test1=SpirentRateTest22(port_handle1,port_handle2,rate3,diff)

    if not test1:
        log.info(banner("Rate test Failed"))
        return 0

    for port_hdl in orphan_handle_list:
        if port_hdl:
            try:            
                res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            except:
                log.info('Stats failed for port %r',port_hdl)
                return 0
            try:               
                rx_rate = res['item0']['PortRxTotalFrameRate']
            except:
                log.info('rx_rate failed for port %r',port_hdl)
                return 0
            log.info('+----------------------------------------------------------------------+')
            log.info('+---- Actual RX rate at Port %r is : %r ------+',port_hdl,rx_rate)
            log.info('+---- Expected RX rate at Port %r is : %r ------+',port_hdl,int(rate)*2)
            log.info('+----------------------------------------------------------------------+')
            if abs(int(rx_rate) - int(rate)*2) > diff:
                log.info('Traffic  Rate Test failed for %r',port_hdl)
                log.info('Stats are %r',res)
                return 0
    return 1



def AllTrafficTestMsite(port_handle1,port_handle2,rate,pps,orphan_handle_list):

    rate3=int(rate)*4.5
    diff = int(rate3*.0125)
    test1=SpirentRateTest22(port_handle1,port_handle2,rate3,diff)

    if not test1:
        log.info(banner("Rate test Failed"))
        return 0

    # for port_hdl in orphan_handle_list:
    #     if port_hdl:
    #         try:            
    #             #res = ixiahlt.traffic_stats(port_handle = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
    #             res = ixiahlt.traffic_stats(port_handle = port_hdl,mode = 'aggregate',traffic_generator = 'ixnetwork')
    #         except:
    #             log.info('Stats failed for port %r',port_hdl)
    #             return 0
    #         try:               
    #             rx_rate = res['aggregate']['rx']['raw_pkt_rate']*9
    #         except:
    #             log.info('rx_rate failed for port %r',port_hdl)
    #             return 0
    #         log.info('+----------------------------------------------------------------------+')
    #         log.info('+---- Actual RX rate at Port %r is : %r ------+',port_hdl,rx_rate)
    #         log.info('+---- Expected RX rate at Port %r is : %r ------+',port_hdl,int(rate)*4)
    #         log.info('+----------------------------------------------------------------------+')
    #         if abs(int(rx_rate) - int(rate)*4) > diff:
    #             log.info('Traffic  Rate Test failed for %r',port_hdl)
    #             log.info('Stats are %r',res)
    #             return 0
    return 1


def SpirentRateTestFull(port_list,expected_rate):
    log.info(banner("  Starting Spirent Rate Test : SpirentRateTestFull "))
    log.info('+-----------------------------------------------------------------------+')
    log.info("port_list is  %r, expected_rate is %r",port_list,expected_rate)
    log.info('+-----------------------------------------------------------------------+')

    result = 1
    for port_hdl in port_list:
        log.info("port_hdl %r,rate_fps %r", port_hdl,expected_rate)
        try:            
            res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
        except:
            log.info('Stats failed for port %r',port_hdl)
            return 0
        try:               
            rx_rate = res['item0']['PortRxTotalFrameRate']
            tx_rate = res['item0']['PortTxTotalFrameRate']
        except:
            log.info('rx_rate failed for port %r',port_hdl)
            return 0
        log.info('+-----------------------------------------------------------------------+')
        log.info('rx_rate is %r,tx_rate is %r',rx_rate,tx_rate)
        log.info('+-----------------------------------------------------------------------+')
        if abs(int(rx_rate) - int(tx_rate)) > 50000:
            log.info('Traffic  Rate Test failed - TX / RX difference is %r',abs(int(rx_rate) - int(tx_rate)))
            log.info('Streamblock is %r',res)
            result = 0
        if abs(int(rx_rate) - int(expected_rate)) > 50000:
            log.info('Traffic  Rate Test failed, Rate & FPS diff is %r',abs(int(rx_rate) - int(expected_rate)))
            log.info('Streamblock is %r',res)
            result = 0
    log.info(banner(" Completed Spirent Rate Test "))
    return result


def AllTrafficTestFull(l3_port_list,l3_port_rate,l2_port_rate,\
    l2_port_list,orphan_port_list,orphan_port_rate):
    log.info('+-----------------------------------------------------------------------+')
    log.info("l3_port_list is  %r, l3_port_rate is %r",l3_port_list,l3_port_rate)
    log.info("l2_port_list is  %r, l2_port_rate is %r",l2_port_list,l2_port_rate)
    log.info("Orphan_port_list is  %r, Orphan_port_rate is %r",orphan_port_list,orphan_port_rate)
    log.info('+-----------------------------------------------------------------------+')

    test1=SpirentRateTestFull(l3_port_list,l3_port_rate)
    test2=SpirentRateTestFull(l2_port_list,l2_port_rate)
    test3=SpirentRateTestFull(orphan_port_list,orphan_port_rate)

    if not test1:
        log.info(banner("Rate test Failed for l3_port_list"))
        return 0
    if not test2:
        log.info(banner("Rate test Failed for l2_port_list"))
        return 0
    if not test3:
        log.info(banner("Rate test Failed for orphan_port_list"))
        return 0



def TriggerPortFlap(uut,port,count):
    for i in range(1,count):
        log.info("Shutting down Port %r",port)
        cfg = \
        """
        interface {port}
        shut
        """
        try:
            uut.configure(cfg.format(port=port))
        except:
            log.error(("Xconnect Orphan Port shut no shut Failed for port %r uut is %r",port,uut))
            return 0

        time.sleep(1)
        log.info("Un shutting down Port %r",port)
        cfg = \
        """
        interface {port}
        no shut
        """
        #log.info("cfg isssss %r",cfg.format(port=port))
        try:
            uut.configure(cfg.format(port=port))
        except:
            log.error(("Xconnect Orphan Port shut no shut Failed for port%r uut is %r",port,uut))
            return 0
    return 1





def VxlanStReset(uut_list):
    log.info(banner("starting VxlanStReset"))

    for uut in uut_list:
        #log.info(banner('remove add nve in VxlanStReset uut %r',uut))
        nve_conf = uut.execute('show run int nve 1 | be nve1')
        uut.configure(nve_conf)

    cfg_shut =  \
    """
    interface {intf}
    shut
    """
    cfg_no_shut =  \
    """
    interface {intf}
    no shut
    """

    for uut in uut_list:
        op = uut.execute('show port-channel summary | incl Eth',timeout = 180)
        op1 = op.splitlines()
        po_list = []
        for line in op1:
            if line:
                if not 'Po1(SU)' in line:
                    if 'Eth' in line:
                        if 'Po' in line:
                            po = line.split()[1].split('(')[0]
                            po_list.append(po)

        for intf in po_list+["nve1"]:
            uut.configure(cfg_shut.format(intf=intf),timeout = 180)

    countdown(60)

    for uut in uut_list:
        op = uut.execute('show port-channel summary | incl Eth',timeout = 180)
        op1 = op.splitlines()
        po_list = []
        for line in op1:
            if line:
                if not 'Po1(SU)' in line:
                    if 'Eth' in line:
                        po = line.split()[1].split('(')[0]
                        po_list.append(po)

        for intf in po_list+["nve1"]:
            uut.configure(cfg_no_shut.format(intf=intf),timeout = 180)


    TriggerCoreIfFlapOspf(uut_list)

    for uut in uut_list:
        intf_list = []
        for intf in [*uut.interfaces.keys()]:
            if 'Eth' in uut.interfaces[intf].intf:
                if 'bgw' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    intf_list.append(intf)                 
                elif 'leaf' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    intf_list.append(intf)    
        
        for intf in intf_list:
            cfg = \
            """
            interface {intf}
            shut
            sleep 1
            no shut
            """
            uut.configure(cfg.format(intf=intf))


    countdown(200)

    for uut in uut_list:
        for feature in ['pim','bgp']:
            test1 = leaf_protocol_check222(uut,[feature])
            if not test1:
                log.info('Feature %r neigborship on device %r Failed ',feature,str(uut))
                return 0

    log.info(banner("Passed VxlanStReset"))
    return 1


def vPCMemberFlap(uut_list,po_list):
    log.info(banner("Starting vPCMemberFlap "))
    for uut in uut_list:
        for po in po_list:
            cmd = uut.execute("show interface po {po} | json-pretty ".format(po=po))
            op=json.loads(cmd)
            op1=op["TABLE_interface"]["ROW_interface"]["eth_members"]
            intf_list = []
            if len(op1.split()) > 1:
                for mem in op1.split():
                    if mem:
                        mem1 = mem.strip(",""")
                        intf_list.append(mem1)
            else:
                intf_list.append(op1)


        cfg = \
            """
            interface {intf}
            shut
            sleep 1
            no sh
            """

        for intf in intf_list:
            for i in range(1,3):
                try:
                    uut.configure(cfg.format(intf=intf))
                except:
                    log.info('Trigger4CoreIfFlapStaticPo failed @ 11')
                    return 0
    return 1


def TriggerCoreIfFlapOspf(uut_list):
    log.info(banner("Starting TriggerCoreIfFlapOspf "))
    for uut in uut_list:
        intf_list = []
        cmd = uut.execute("show ip ospf int brie | be Area")
        op=cmd.splitlines()
        for line in op:
            if line:
                if not 'Area' in line:
                    intf = line.split()[0]
                    intf_list.append(intf)

        #for intf in intf_list:
        for i in range(1,4):
            for intf in intf_list:
                cfg = \
                """
                interface {intf}
                shut
                """
                try:
                    uut.configure(cfg.format(intf=intf))
                except:
                    log.info('TriggerCoreIfFlapOspf failed @ 11')
                    return 0

            countdown(1)
            for intf in intf_list:
                cfg = \
                """
                interface {intf}
                no shut
                """
                try:
                    uut.configure(cfg.format(intf=intf))
                except:
                    log.info('Trigger4CoreIfFlapStaticPo failed @ 11')
                    return 0

    log.info(banner("END - TriggerCoreIfFlapOspf "))

def TriggerCoreIfFlap222(uut_list):
    log.info(banner("Starting TriggerCoreIfFlap222 "))
    for uut in uut_list:
        cmd = uut.execute("show ip ospf neigh | json-pretty")
        op=json.loads(cmd)
        op11 = op["TABLE_ctx"]['ROW_ctx']
        if 'list' in str(type(op11)):
            op1 = op11[0]["TABLE_nbr"]['ROW_nbr']
            nbrcount = op11[0]['nbrcount']
            core_intf_list = []
            if int(nbrcount) == 1:
                intf = op1[0]["intf"]
                core_intf_list.append(intf)
            else:
                for i in range(0,len(op1)):
                    intf = op1[i]["intf"]
                    core_intf_list.append(intf)

        else:
            op1 = op["TABLE_ctx"]['ROW_ctx']["TABLE_nbr"]['ROW_nbr']
            nbrcount = op["TABLE_ctx"]['ROW_ctx']['nbrcount']
            core_intf_list = []

            if int(nbrcount) == 1:
                intf = op1["intf"]
                core_intf_list.append(intf)
            else:
                for i in range(0,len(op1)):
                    intf = op1[i]["intf"]
                    core_intf_list.append(intf)

        for i in range(1,4):
            for intf in core_intf_list:
                cfg = \
                """
                interface {intf}
                shut
                """
                try:
                    uut.configure(cfg.format(intf=intf))
                except:
                    log.info('TriggerCoreIfFlap222 failed @ 11')
                    return 0

            countdown(1)
            for intf in core_intf_list:
                cfg = \
                """
                interface {intf}
                no shut
                """
                try:
                    uut.configure(cfg.format(intf=intf))
                except:
                    log.info('TriggerCoreIfFlap222 failed @ 11')
                    return 0
    log.info(banner("END TriggerCoreIfFlap222 "))
    return 1


def L3InterfaceFlap(uut,igp):
    log.info(banner("Starting L3InterfaceFlap "))
    for uut in [uut]:
        if 'ospf' in igp:
            cmd = uut.execute("show ip ospf neigh | json-pretty")
            op=json.loads(cmd)
            op11 = op["TABLE_ctx"]['ROW_ctx']
            if 'list' in str(type(op11)):
                op1 = op11[0]["TABLE_nbr"]['ROW_nbr']
                nbrcount = op11[0]['nbrcount']
                core_intf_list = []
                if int(nbrcount) == 1:
                    intf = op1[0]["intf"]
                    core_intf_list.append(intf)
                else:
                    for i in range(0,len(op1)):
                        intf = op1[i]["intf"]
                        core_intf_list.append(intf)

            else:
                op1 = op["TABLE_ctx"]['ROW_ctx']["TABLE_nbr"]['ROW_nbr']
                nbrcount = op["TABLE_ctx"]['ROW_ctx']['nbrcount']
                core_intf_list = []

                if int(nbrcount) == 1:
                    intf = op1["intf"]
                    core_intf_list.append(intf)
                else:
                    for i in range(0,len(op1)):
                        intf = op1[i]["intf"]
                        core_intf_list.append(intf)

        elif 'isis' in igp:
            core_intf_list = []
            op = uut.execute('show isis adjacency')
            op1 = op.splitlines()
            for line in op1:
               if 'UP' in line:
                   intf = line.split()[-1] 
                   core_intf_list.append(intf)  

        for i in range(1,4):
            for intf in core_intf_list:
                cfg = \
                """
                interface {intf}
                shut
                """
                try:
                    uut.configure(cfg.format(intf=intf))
                except:
                    log.info('L3InterfaceFlap failed @ 11')
                    return 0

            countdown(1)
            for intf in core_intf_list:
                cfg = \
                """
                interface {intf}
                no shut
                """
                try:
                    uut.configure(cfg.format(intf=intf))
                except:
                    log.info('L3InterfaceFlap failed @ 12')
                    return 0
    log.info(banner("END L3InterfaceFlap "))
    return 1



def countdown(t):
    '''https://stackoverflow.com/questions/25189554/countdown-clock-0105'''
    #log.info(banner('++++  Starting countdown ++++ '))     
    log.info('Starting countdown : %r seconds',t) 
    while t:
        mins, secs = divmod(t, 60)
        timeformat = '{:02d}:{:02d}'.format(mins, secs)
        print(timeformat, end='\r')
        time.sleep(1)
        t -= 1
    log.info('Completed count : %r seconds',t) 
    #log.info(banner(' ++++ END countdown ++++ '))

class VPCPoConfig(object):
    def __init__(self,node,vpc_po,vpc_po_mem_list1,vlan_range,vpc_po_type):
        self.node=node
        self.vpc_po=vpc_po
        self.vpc_po_mem_list1=vpc_po_mem_list1
        self.vlan_range=vlan_range
        self.vpc_po_type=vpc_po_type

    def vpc_conf(self):
        if 'access' in self.vpc_po_type:
            cmd = \
                '''
                vlan {vlan_range}
                interface port-channe {vpc_po}
                switchport
                switchport mode access
                switchport access vlan {vlan_range}
                no shut
                vpc {vpc_po}
                '''
            try:
                self.node.configure(cmd.format(vlan_range=self.vlan_range,vpc_po=self.vpc_po))
            except:
                log.error('444 vpc conf failed for vlan_range',self.vlan_range)


        elif 'trunk' in self.vpc_po_type:
            cmd = \
                '''
                vlan {vlan_range}
                interface port-channe {vpc_po}
                switchport
                switchport mode trunk
                switchport trunk allowed vlan {vlan_range}
                no shut
                vpc {vpc_po}
                '''
            try:
                self.node.configure(cmd.format(vlan_range=self.vlan_range,vpc_po=self.vpc_po))
            except:
                log.error('444 vpc conf failed for vlan_range',self.vlan_range)

        for intf in self.vpc_po_mem_list1:
            cmd = \
            '''
            interface {intf}
            channel-group {vpc_po} force mode active
            no shut
            '''
            try:
                self.node.configure(cmd.format(intf=intf,vpc_po=self.vpc_po))
            except:
                self.node.execute("show port-channel compatibility-parameters")
                log.error('555 vpc_po_mem conf failed for interface',intf)


           #time.sleep(30)
    def vpc_check(self):
        for node in [self.node]:
            filter1 = "Po"+str(self.vpc_po)
            print("VPC Po is .............",filter1)
            check1 = self.node.execute("show vpc | incl {filter1}".format(filter1=filter1))
            if "down" in check1:
                log.error('VPC Bringup failed for node',node)
                node.execute("show vpc consistency-parameters global")
                node.execute("show vpc consistency-parameters vpc {vpc_po}".format(vpc_po=self.vpc_po))
                self.failed


def find_svi_ip222(uut,svi):
    cmd = uut.execute("show int vlan {vlan} | json-pretty".format(vlan=svi))
    if not "svi_ip_addr" in str(cmd):
        log.info('svi_ip_addr found,Test failed')
        return 0

    else:
        test1=json.loads(cmd)
        test11 = test1["TABLE_interface"]["ROW_interface"]
        if 'list' in str(type(test11)):
            ip = test1["TABLE_interface"]["ROW_interface"][0]["svi_ip_addr"]
        else:
            ip = test1["TABLE_interface"]["ROW_interface"]["svi_ip_addr"]
        return ip



def findIntfIpv6Addr(uut,interface):
    '''
    cmd = uut.execute("show ipv6 interface {interface} | json-pretty".format(interface=interface))
    if not "addr" in str(cmd):
        log.info('svi_ip_addr found,Test failed')
        return 0

    else:
        test1=json.loads(cmd)
        #test11 = test1["TABLE_intf"]["ROW_intf"]

        if "version 9" in uut.execute('show ver'):
            #if test1["TABLE_intf"]["ROW_intf"]["addr"]:
            ip6 = test1["TABLE_intf"]["ROW_intf"]["addr"]

        elif "version 6" in uut.execute('show ver'):
            ip6 = test1["TABLE_intf"]["ROW_intf"]["TABLE_addr"]["ROW_addr"]["addr"]

        elif "version 7" in uut.execute('show ver'):
            ip6 = test1["TABLE_intf"]["ROW_intf"]["TABLE_addr"]["ROW_addr"]["addr"]

        ip6 = sub("/(.*)",'',ip6)

    return ip6
    '''
    cmd = uut.execute("show running-config interface {interface}".format(interface=interface))


    #def findIntfIpv6Addr(cmd):
    op=cmd.splitlines()
    for line in op:
        if 'ipv6 address' in line:
            ipv6_add = line.split()[-1]
            ip6 = sub("/(.*)",'',ipv6_add)
    return ip6


def VxanTcamCheckCarve(uut):
    """ function to configure interface default Global """
    log.info(banner("Entering proc configure interface default "))

    cfg_n9k = \
            """
            hardware access-list tcam region ifacl 0
            hardware access-list tcam region ipv6-ifacl 0
            hardware access-list tcam region mac-ifacl 0
            hardware access-list tcam region qos 0
            hardware access-list tcam region ipv6-qos 0
            hardware access-list tcam region mac-qos 0
            hardware access-list tcam region fex-ifacl 0
            hardware access-list tcam region fex-ipv6-ifacl 0
            hardware access-list tcam region fex-mac-ifacl 0
            hardware access-list tcam region fex-qos 0
            hardware access-list tcam region fex-ipv6-qos 0
            hardware access-list tcam region fex-mac-qos 0
            hardware access-list tcam region vacl 0
            hardware access-list tcam region ipv6-vacl 0
            hardware access-list tcam region mac-vacl 0
            hardware access-list tcam region vqos 0
            hardware access-list tcam region ipv6-vqos 0
            hardware access-list tcam region mac-vqos 0
            hardware access-list tcam region racl 1536
            hardware access-list tcam region ipv6-racl 0
            hardware access-list tcam region qos-lite 0
            hardware access-list tcam region fex-qos-lite 0
            hardware access-list tcam region vqos-lite 0
            hardware access-list tcam region l3qos-lite 0
            hardware access-list tcam region e-qos 0
            hardware access-list tcam region e-ipv6-qos 0
            hardware access-list tcam region e-mac-qos 0
            hardware access-list tcam region e-racl 768
            hardware access-list tcam region e-ipv6-racl 0
            hardware access-list tcam region e-qos-lite 0
            hardware access-list tcam region l3qos 256
            hardware access-list tcam region ipv6-l3qos 0
            hardware access-list tcam region mac-l3qos 0
            hardware access-list tcam region span 256
            hardware access-list tcam region copp 256
            hardware access-list tcam region svi 0
            hardware access-list tcam region redirect 256
            hardware access-list tcam region vpc-convergence 512
            hardware access-list tcam region ipsg 0
            hardware access-list tcam region rp-qos-lite 0
            hardware access-list tcam region rp-qos 256
            hardware access-list tcam region rp-ipv6-qos 256
            hardware access-list tcam region rp-mac-qos 256
            hardware access-list tcam region nat 0
            hardware access-list tcam region mpls 0
            hardware access-list tcam region n3k-qos-ipv4 0
            hardware access-list tcam region n3k-qos-ipv6 0
            hardware access-list tcam region sflow 0
            hardware access-list tcam region mcast_bidir 0
            hardware access-list tcam region openflow 0
            hardware access-list tcam region racl-udf 0
            hardware access-list tcam region racl-lite 0
            hardware access-list tcam region qos-intra-lite 0
            hardware access-list tcam region l3qos-intra-lite 0
            hardware access-list tcam region ifacl-udf 0
            hardware access-list tcam region copp-system 0
            hardware access-list tcam region ifacl-lite 0
            hardware access-list tcam region vacl-lite 0
            hardware access-list tcam region vqos-intra-lite 0
            hardware access-list tcam region ing-ifacl 0
            hardware access-list tcam region vacl 0
            hardware access-list tcam region ing-racl 0
            hardware access-list tcam region ing-rbacl 0
            hardware access-list tcam region ing-l2-qos 0
            hardware access-list tcam region ing-l3-vlan-qos 0
            hardware access-list tcam region ing-sup 0
            hardware access-list tcam region ing-l2-span-filter 0
            hardware access-list tcam region ing-l3-span-filter 0
            hardware access-list tcam region ing-fstat 0
            hardware access-list tcam region span 0
            hardware access-list tcam region egr-racl 0
            hardware access-list tcam region egr-sup 0
            hardware access-list tcam region openflow-lite 0
            hardware access-list tcam region fcoe-ingress 0
            hardware access-list tcam region fcoe-egress 0
            hardware access-list tcam region ing-redirect 0
            hardware access-list tcam region redirect-tunnel 0
            hardware access-list tcam region span-sflow 0
            hardware access-list tcam region openflow-ipv6 0
            hardware access-list tcam region mcast-performance 0
            hardware access-list tcam region egr-l2-qos 0
            hardware access-list tcam region egr-l3-vlan-qos 0
            hardware access-list tcam region n9k-arp-acl 0
            hardware access-list tcam region ipv6-span-udf 0
            hardware access-list tcam region ipv6-span-l2-udf 0
            hardware access-list tcam region ing-netflow 0
            hardware access-list tcam region ing-nbm 0
            hardware access-list tcam region redirect_v4 0
            hardware access-list tcam region redirect_v6 0
            hardware access-list tcam region tcp-nat 0
            hardware access-list tcam region vxlan-p2p 0
            hardware access-list tcam region arp-ether 256 double-wide
            """
    cfg_th = """
         hardware access-list tcam region arp-ether 256
         hardware access-list tcam region copp 256
         hardware access-list tcam region e-ipv6-qos 0
         hardware access-list tcam region e-ipv6-racl 0
         hardware access-list tcam region e-mac-qos 0
         hardware access-list tcam region e-qos 0
         hardware access-list tcam region e-qos-lite 0
         hardware access-list tcam region e-racl 0
         hardware access-list tcam region flow 0
         hardware access-list tcam region ifacl 0
         hardware access-list tcam region ipsg 0
         hardware access-list tcam region ipv6-ifacl 0
         hardware access-list tcam region ipv6-l3qos 0
         hardware access-list tcam region ipv6-qos 0
         hardware access-list tcam region ipv6-racl 0
         hardware access-list tcam region ipv6-vacl 0
         hardware access-list tcam region ipv6-vqos 0
         hardware access-list tcam region l3qos 0
         hardware access-list tcam region mac-ifacl 0
         hardware access-list tcam region mac-l3qos 0
         hardware access-list tcam region mac-qos 0
         hardware access-list tcam region mac-vacl 0
         hardware access-list tcam region mac-vqos 0
         hardware access-list tcam region mcast_bidir 0
         hardware access-list tcam region mpls 0
         hardware access-list tcam region openflow 0
         hardware access-list tcam region qos 0
         hardware access-list tcam region racl 256
         hardware access-list tcam region redirect 0
         hardware access-list tcam region redirect-tunnel 0
         hardware access-list tcam region span 0
         hardware access-list tcam region svi 0
         hardware access-list tcam region vacl 0
         hardware access-list tcam region vpc-convergence 0
         hardware access-list tcam region vqos 0
         hardware access-list tcam region nat 1536
         """

    cfg_n3k = """\
        hardware profile tcam region e-ipv6-qos 0
        hardware profile tcam region e-mac-qos 0
        hardware profile tcam region e-qos 0
        hardware profile tcam region e-qos-lite 0
        hardware profile tcam region e-racl 0
        hardware profile tcam region e-vacl 0
        hardware profile tcam region fhs 0
        hardware profile tcam region ifacl 0
        hardware profile tcam region ipv6-e-racl 0
        hardware profile tcam region ipv6-pbr 0
        hardware profile tcam region ipv6-qos 0
        hardware profile tcam region ipv6-racl 0
        hardware profile tcam region ipv6-span 0
        hardware profile tcam region ipv6-span-l2 0
        hardware profile tcam region mcast-bidir 0
        hardware profile tcam region qos 0
        hardware profile tcam region racl 256
        hardware profile tcam region vacl 0

        """


    mode = uut.execute("show system switch-mode")
    module = uut.execute("show module")
    if "not applicable for this platform" in mode:
        if not 'N3K-C30' in module:
            tcam=uut.execute("show hardware access-list tcam region | incl nat")
            tcam1 = tcam.splitlines()
            for line in tcam1:
                if "[nat]" in line:
                    nattcam =line.split()[-1]
                    if int(nattcam) < 1500:
                        if 'N3K-C32' in module:
                            uut.configure(cfg_th)
                        else:
                            uut.configure(cfg_n9k)
                        uut.execute('copy running-config startup-config')
                        log.info(banner("Reloading of devices"))
                        results1 = uut.reload()
                        if results1 != 0:
                            log.info(banner("uut Reload Passed"))
                        else:
                            log.info(banner("uut Reload Failed"))

    elif 'n3k' in mode:
        tcam=uut.execute("show hardware profile tcam region | incl nat")
        tcam1 = tcam.splitlines()
        for line in tcam1:
            print("line TCAM issss",line)
            if "nat size" in line:
                nattcam =line.split()[-1]
                print("nat TCAM issss nattcam nattcam",nattcam)
                if int(nattcam) < 1500:
                    uut.configure(cfg_n3k)
                    uut.execute('copy running-config startup-config')
                    log.info(banner("Reloading of devices"))
                    results1 = uut.reload()
                    if results1 != 0:
                        log.info(banner("uut Reload Passed"))
                    else:
                        log.info(banner("uut Reload Failed"))



def ProcessRestart(uut,proc):
    """ function to configure vpc """
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
        #uut.transmit('run bash \r',timeout=40)
        #uut.receive('bash-4.3$',timeout=40)
        #uut.transmit('sudo su \r',timeout=40)
        #uut.receive('bash-4.3$',timeout=40)
        #uut.transmit('kill %s\r' %pid,timeout=40)
        #uut.receive('bash-4.3$',timeout=40)
        #uut.transmit('exit \r',timeout=40)
        #uut.receive('bash-4.3$',timeout=40)
        #uut.transmit('exit \r',timeout=40)
        #uut.receive('#',timeout=40)
        uut.transmit('run bash \r')
        uut.receive('bash-4.3$')
        uut.transmit('sudo su \r')
        uut.receive('bash-4.3#')
        uut.transmit('kill %s\r' %pid)
        uut.receive('bash-4.3#')
        uut.transmit('exit \r')
        uut.receive('bash-4.3$')
        uut.transmit('exit \r')
        uut.receive('#')
        log.info('-----Proc State AFTER Restart-----')
        config_str = '''sh system internal sysmgr service name {proc} '''
        out=uut.execute(config_str.format(proc=proc),timeout=40)
        log.info('----------------------------------------')
    except:
        log.error('proc restart test failed for %r',proc)
        log.error(sys.exc_info())





def NveChangeIrtoMcast(uut_list,mcast_group):
    log.info(banner("Starting NveChangeIrtoMcast "))

    for uut in uut_list:
        cmd = \
        """

        """
        op = uut.execute('show run interface nve 1')
        op1 = op.splitlines()
        for line in op1:
            cmd += line + '\n'
            if 'ingress-replication protocol bgp' in line:
                line = 'no ' +line
                cmd += line + '\n'
                line = '    mcast-group ' +str(mcast_group)
                cmd += line + '\n'
        #log.info("cmd is %r",cmd)
        uut.configure(cmd)
    return 1




def NveChangeMcastToIr(uut_list):
    log.info(banner("Starting NveChangeMcastToIr "))

    for uut in uut_list:
        cmd = \
        """

        """
        op = uut.execute('show run interface nve 1')
        op1 = op.splitlines()
        for line in op1:
            cmd += line + '\n'
            if 'mcast' in line:
                line = 'no ' +line
                cmd += line + '\n'
                line = 'ingress-replication protocol bgp'
                cmd += line + '\n'
        #log.info("cmd is %r",cmd)
        uut.configure(cmd)
    return 1



def svi_remove(uut,vlan,vlan_scale):
    for j in range(0,vlan_scale):  # 5
            cmd += 'no interface Vlan{vlan}\n'.format(vlan=vlan)
            vlan = vlan + 1
    try:
        uut.configure(cmd)
    except:
        log.error('SVI configure failed for vlan')

def vrf_remove(uut,routed_vni,count):
    cmd=""
    for i in range(0,count):
        cmd +=  'no vrf context vxlan-{routed_vni}\n'.format(routed_vni=routed_vni)
        routed_vni = routed_vni + 1
    try:
        uut.configure(cmd)
    except:
        log.error('vrf configure failed for')



class LeafObjectFnL(object):
    def __init__(self,node,vlan,vni,vlan_scale,mcast_group,ir_mode,mcast_group_scale,peer_list):
        self.node=node
        self.vlan=vlan
        self.peer_list=peer_list
        self.vni=vni
        self.vlan_scale=vlan_scale
        self.mcast_group=mcast_group
        self.ir_mode=ir_mode
        self.mcast_group_scale=mcast_group_scale

        #ir_mode = bgp,mcast,mix

    def vxlan_conf(self):
        vlan_vni_configure(self.node,self.vlan,self.vni,self.vlan_scale)
        if 'mix' in self.ir_mode:
            log.info(banner("Replication mode is Static + MCAST"))
            #nve_configure_fl_mix(uut,vni,scale,peer_list,mcast_group,mcast_group_scale):
            nve_configure_fl_mix(self.node,self.vni,self.vlan_scale,self.peer_list,self.mcast_group,self.mcast_group_scale)
            #nve_configure_fl_mcast(self.node,self.vni,self.vlan_scale,self.mcast_group,self.mcast_group_scale)
        elif 'static' in self.ir_mode:
            log.info(banner("Replication mode is Static + MCAST"))
            nve_configure_fl_static(self.node,self.vni,self.vlan_scale,self.peer_list)
        elif 'mcast' in self.ir_mode:
            log.info(banner("Replication mode is Static + MCAST"))
            nve_configure_fl_mcast(self.node,self.vni,self.vlan_scale,self.mcast_group,self.mcast_group_scale)




def nve_configure_fl_mix(uut,vni,scale,peer_list,mcast_group,mcast_group_scale):
    vni1 = vni
    static_count=int(scale/2)
    vni2=vni1+static_count
    cmd1 = \
    """
    interface nve1
    no shutdown
    source-interface loopback0
    source-interface hold-down-time 20
    member vni {vni1}-{vni2}
    ingress-replication protocol static
    peer-ip {peer}
    """
    for peer in peer_list:
        uut.configure(cmd1.format(vni1=vni,vni2=vni2-1,peer=peer))

    a = mcast_group_scale # 4
    b = int(scale/2)  # 16
    c = int(b/a) # 4
    vnia = vni2
    vnib = vnia + c - 1

    for i in range(0,b,c):
        cmd = \
            """
            interface nve1
            no shutdown
            source-interface loopback0
            source-interface hold-down-time 20
            member vni {vnia}-{vnib}
            mcast-group {mcast_group}
            """
        uut.configure(cmd.format(vnia=vnia,vnib=vnib,mcast_group=mcast_group))
        vnia = vnia+c
        vnib = vnib+c
        mcast_group = ip_address(mcast_group) + 1


def nve_configure_fl_static(uut,static_vni,scale,peer_list):
    cmd1 = \
    """
    interface nve1
    no shutdown
    source-interface loopback0
    source-interface hold-down-time 20
    member vni {vni1}-{vni2}
    ingress-replication protocol static
    peer-ip {peer}
    """
    for peer in peer_list:
        uut.configure(cmd1.format(vni1=static_vni,vni2=static_vni+scale-1,peer=peer))


def nve_configure_fl_mcast(uut,mcast_vni,mcast_group,scale,mcast_group_scale):
    if mcast_group_scale == 1:
        cmd = \
        """
        interface nve1
        no shutdown
        source-interface loopback0
        source-interface hold-down-time 20
        member vni {vni1}-{vni2}
        mcast-group {mcast_group}
        """
        uut.configure(cmd.format(vni1=mcast_vni,vni2=mcast_vni+scale,mcast_group=mcast_group))


def AllTrafficTestL2(port_handle1,port_handle2,rate,pps,orphan_handle_list):
    rate3=int(rate)*4
    diff = int(rate3*.025)
    test1=SpirentRateTest22(port_handle1,port_handle2,rate3,diff)

    if not test1:
        log.info(banner("Rate test Failed"))
        return 0

    for port_hdl in orphan_handle_list:
        if port_hdl:
            try:            
                res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            except:
                log.info('Stats failed for port %r',port_hdl)
                return 0
            try:               
                rx_rate = res['item0']['PortRxTotalFrameRate']
            except:
                log.info('rx_rate failed for port %r',port_hdl)
                return 0
            log.info('+----------------------------------------------------------------------+')
            log.info('+---- Actual RX rate at Port %r is : %r ------+',port_hdl,rx_rate)
            log.info('+---- Expected RX rate at Port %r is : %r ------+',port_hdl,int(rate)*3)
            log.info('+----------------------------------------------------------------------+')
            if abs(int(rx_rate) - int(rate)*3) > diff:
                log.info('Traffic  Rate Test failed for %r',port_hdl)
                log.info('Stats are %r',res)
                return 0
    return 1



def NvePeerLearning2(port_handle_list,vlan,uut_list,peer_count,exclude_prefix):
    log.info(banner(" In NvePeerLearning"))

    for uut in uut_list:
        op1=uut.execute("sh nve peers  | grep nve1 | count")
        if not int(op1) == peer_count:
            log.info("Nve peer check failed for UUT %r",uut)
            uut.execute("sh nve peers")
            return 0

        aa=uut.execute("sh nve peers  | grep nve1")
        bb=aa.splitlines()
        for line in bb:
            if not exclude_prefix in line:
                if line:
                    if 'n/a' in line:
                       log.info(banner("RMAC NOT LEARNED"))
                       log.info("RMAC not learened @ uut %r",uut)
                       return 0

    log.info(banner("NvePeerLearning Passed"))
    return 1




def PortVlanMappingConfAll(uut_list,vlan_start,vlan_scale):
    log.info(banner("Starting PortVlanMapping "))

    for uut in uut_list:
        intf_list = []
        if 'vpc' in uut.execute("show run | incl feature"):
            op1 =  uut.execute("show vpc | json-pretty")
            op=json.loads(op1)
            intf=op["TABLE_vpc"]["ROW_vpc"]["vpc-ifindex"]
            intf_list.append(intf)
        op = uut.execute('show spanning-tree vlan {vlan_start} | incl FWD'.format(vlan_start=vlan_start))
        op1 = op.splitlines()
        for line in op1:
            if 'FWD' in line:
                if not 'peer-link' in line:
                    intf_list.append(line.split()[0])

        for intf in intf_list:
            cmd1 = \
            """
            interface {intf}
            switchport vlan mapping enable
            """
            vlan1 = vlan_start
            vlan2 = vlan1 + vlan_scale
            for i in range(1,vlan_scale+1):
                cmd1 +=  ' switchport vlan mapping {vlan2} {vlan1}\n'.format(vlan1=vlan1,vlan2=vlan2)
                vlan1 = vlan1 + 1
                vlan2 = vlan2 + 1
           #cmd1 +=  'switchport trunk allowed vlan {vlanA}-{vlan2}\n'.format(vlanA=vlan_start+vlan_scale,vlan2=vlan2)
            #log.info("CMD ISSS -------------- %r",cmd1)
            try:
                uut.configure(cmd1.format(intf=intf))
            except:
                log.error('PVLAN Mapping failed for uut %r interface %r',uut,intf)
                return 0

    return 1





def PortVlanMappingRevertAll(uut_list,vlan_start,vlan_scale):
    log.info(banner("Starting PortVlanMapping "))
    vlan_end = vlan_start+vlan_scale
    for uut in uut_list:
        intf_list = []
        if 'vpc' in uut.execute("show run | incl feature"):
            op1 =  uut.execute("show vpc | json-pretty")
            op=json.loads(op1)
            intf=op["TABLE_vpc"]["ROW_vpc"]["vpc-ifindex"]
            intf_list.append(intf)
        op = uut.execute('show spanning-tree vlan {vlan_start} | incl FWD'.format(vlan_start=vlan_start))
        op1 = op.splitlines()
        for line in op1:
            if 'FWD' in line:
                if not 'peer-link' in line:
                    intf_list.append(line.split()[0])


        for intf in intf_list:
            cmd1 = \
            """
            interface {intf}
            shut
            """
            try:
                uut.configure(cmd1.format(intf=intf))
            except:
                log.error('PVLAN Mapping failed for uut %r interface %r',uut,intf)
                return 0

            countdown(5)

            cmd1 = \
            """
            interface {intf}
            """
            vlan1 = vlan_start
            vlan2 = vlan1 + vlan_scale
            for i in range(1,vlan_scale+1):
                cmd1 +=  ' no switchport vlan mapping {vlan2} {vlan1}\n'.format(vlan1=vlan1,vlan2=vlan2)
                vlan1 = vlan1 + 1
                vlan2 = vlan2 + 1
            cmd1 +=  'no switchport vlan mapping enable'
            #log.info("CMD ISSS -------------- %r",cmd1)
            try:
                uut.configure(cmd1.format(intf=intf))
            except:
                log.error('PVLAN Mapping failed for uut %r interface %r',uut,intf)
                return 0

            cmd4 = \
            """
            interface {intf}
            switchport
            switchport mode trunk
            switchport trunk allowed vlan {vlan_start}-{vlan_end}
            spanning-tree bpdufilter enable
            spanning-tree port type edge trunk
            no shut
            """
            try:
                uut.configure(cmd4.format(intf=intf,vlan_start=vlan_start,vlan_end=vlan_end))
            except:
                log.error('PVLAN Mapping Remove failed for uut %r interface %r',uut,intf)
                return 0

    return 1





def SpirentRoutedBidirStreamPvlan(uut,port_hdl1,port_hdl2,pps,vlan_vni_scale):
    log.info(banner("------SpirentHostBidirStream-----"))

    op = uut.execute('show vrf all | incl vxlan')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            vrf = line.split()[0]
            vrf_list.append(vrf)

    for vrf in vrf_list:
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        vlan_list = []
        ip_list = []
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        vlan_list.append(int(line.split()[0].replace("Vlan",""))+vlan_vni_scale)
                        ip_list.append(line.split()[1])

        if not len(vlan_list) == len(ip_list):
            return 0
        else:
            gw1 = str(ip_address(ip_list[0]))
            ip1 = str(ip_address(gw1)+1)
            ip11= str(ip_address(ip1)+100)

            SpirentHostBidirStreamSmacSame(port_hdl1,port_hdl2,vlan_list[0],vlan_list[0],ip1,ip11,ip11,ip1,str(pps))

            for i in range(1,len(vlan_list)):
                vlan2 = vlan_list[i]
                gw2 = ip_list[i]
                ip2 = str(ip_address(gw2)+100)
                SpirentHostBidirStreamSmacSame(port_hdl1,port_hdl2,vlan_list[0],vlan2,ip1,ip2,gw1,gw2,str(pps))

    return 1



def NveL3VniRemoveAdd(uut_list):
    log.info(banner("Starting NveL3VniRemoveAdd "))

    for uut in uut_list:
        cmd = \
        """
        interface nve1
        """
        op = uut.execute('show run int nve 1 | incl nve1|vrf')
        op1 = op.splitlines()
        for line in op1:
            if ' associate-vrf' in line:
                line = 'no ' + line
            cmd += line + '\n'
        log.info("removing L3 VNI  ")
        uut.configure(cmd)
        countdown(2)
        log.info("Adding  L3 VNI  ")
        uut.configure(op,timeout=120)

    return 1


def NveL3VniRemoveAddTrm(uut_list):
    log.info(banner("Starting NveL3VniRemoveAddTrm "))

    for uut in uut_list:
        op = uut.execute('show nve vni | incl L3')
        cmd_add = \
        """
        interface nve1
        """

        cmd_remove = \
        """
        interface nve1
        """
        for line in op.splitlines():
            elem = line.split()
            vni = elem[1]
            mcast_group = elem[2]
            vrf = elem[6].replace("[","").replace("]","")
            cmd_remove += 'no member vni {vni} associate-vrf\n'.format(vni=vni)            	
            cmd_add += 'member vni {vni} associate-vrf\n'.format(vni=vni)
            cmd_add += 'multisite ingress-replication optimized\n'
            cmd_add += 'mcast-group {mcast_group} \n'.format(mcast_group=mcast_group)  
        log.info("removing L3 VNI  ")
        uut.configure(cmd_remove)
        countdown(2)
        log.info("Adding  L3 VNI  ")
        uut.configure(cmd_add,timout=180)

    return 1



def NveRemAddReplicationOptimized(uut):
    log.info(banner("Starting NveL3VniRemoveAddTrm "))
    for uut in [uut]:
        op = uut.execute('show run interface nve 1',timout=180)
        cmd_add = \
        """
        interface nve1
        """
        cmd_remove = \
        """
        interface nve1
        """
        for line in op.splitlines():
            if not 'Command' in line:
                if not 'Running' in line:
                    if not 'Bios:version' in line:
                        if not 'Time:' in line:
                            if line:
                                if 'optimized' in line:
                                   cmd_remove += 'no {line}\n'.format(line=line)              
                                   cmd_add += '{line}\n'.format(line=line) 
                                cmd_remove += '{line}\n'.format(line=line)              
                                cmd_add += '{line}\n'.format(line=line) 
        log.info("removing L3 VNI  ")
        uut.configure(cmd_remove)
        countdown(2)
        log.info("Adding  L3 VNI  ")
        uut.configure(cmd_add,timout=180)

    return 1


def NveMcastGroupChange(uut_list):
    log.info(banner("Starting NveMcastGroupChange "))

    for uut in uut_list:
        cmd = \
        """

        """
        op = uut.execute('show run interface nve 1')
        op1 = op.splitlines()
        for line in op1:
            if 'mcast' in line:
                l = line.split()
                ip = ip_address(l[1])+10
                line = '    mcast-group ' +str(ip)
            cmd += line + '\n'

        #log.info("cmd is %r",cmd)
        uut.configure(cmd,timout=180)
    return 1


def VnSegmentRemoveAdd(uut_list,vlan_start):
    log.info(banner("Starting VnSegmentRemoveAdd "))

    for uut in uut_list:
        cmd = "show run vlan | begin 'vlan {vlan_start}'"

        vlan_run = uut.execute(cmd.format(vlan_start=vlan_start))

        cmd = " "

        #op = uut.execute('show run int nve 1 | incl nve1|vrf')
        op1 = vlan_run.splitlines()
        for line in op1:
            if 'vn-segment' in line:
                line = 'no ' + line
                cmd += line + '\n'
            else:
                if not 'arp' in line:
                    if not 'vlan configuration' in line:
                        cmd += line + '\n'

        #cmd += 'exit' + '\n'

        try:
            #log.info("removing vn-segment, cmd is ----- %r ",cmd)
            uut.configure(cmd,timeout=120)
            countdown(2)
        except:
            log.error('remove vn-segment failed , uut is %r',uut)
            return 0
        try:
            #log.info("adding vn-segment , vlan_run is %r",vlan_run)
            uut.configure(vlan_run,timeout=120)
        except:
            log.error('add vn-segment failed , uut is %r',uut)
            return 0


    return 1


def l3VnSegmentRemoveAdd(uut_list,vlan_start):
    log.info(banner("Starting l3VnSegmentRemoveAdd "))
    for uut in uut_list:
        l3_vlan_count = uut.execute('show nve vni | inc L3 | count')
        l3_vlan_end = str(int(vlan_start)+int(l3_vlan_count)-1)
        cmd = "show run vlan {vlan_start}-{l3_vlan_end}"
        vlan_start=str(vlan_start)
        vlan_run = uut.execute(cmd.format(vlan_start=vlan_start,l3_vlan_end=l3_vlan_end))
        cmd = " "
        op1 = vlan_run.splitlines()
        for line in op1:
            if 'vn-segment' in line:
                line = 'no ' + line
                cmd += line + '\n'
            else:
                if not 'arp' in line:
                    if not 'vlan configuration' in line:
                        cmd += line + '\n'
        try:
            uut.configure(cmd,timeout=120)
            countdown(2)
        except:
            log.error('remove vn-segment failed , uut is %r',uut)
            return 0
        try:
            uut.configure(vlan_run,timeout=120)
        except:
            log.error('add vn-segment failed , uut is %r',uut)
            return 0
    return 1


def ChangeIRtoMcast(uut_list,mode,scale,mcast_group_scale,group_start):

    #for uut in uut_list:
    #    uut.configure(['interface nve1','shutdown'])
    #countdown(5)
    #vlan_vni_scale = 128
    #routing_vlan_scale = 8
    #mcast_group_scale = 8
    #ir_mode = 'mix'


    group= ip_address(group_start)+mcast_group_scale+1


    if 'mix' in mode:
        ir_scale = int(scale/2)
        vni_per_group = int(ir_scale/mcast_group_scale)
        for uut in uut_list:
            for vni in range(201001,201001+vni_per_group):
                uut.configure(['interface nve1',' member vni {vni}'.format(vni=vni),\
                'no ingress-replication protocol bgp',' mcast-group {group}'.format(group=group)])

    elif 'bgp' in mode:
        ir_scale = scale
        vni_per_group = int(ir_scale/mcast_group_scale)
        for uut in uut_list:
            for vni in range(201001,201001+vni_per_group):
                uut.configure(['interface nve1',' member vni {vni}'.format(vni=vni),\
                'no ingress-replication protocol bgp',' mcast-group {group}'.format(group=group)])


    countdown(5)
    ##for uut in uut_list:
    #    uut.configure(['interface nve1', 'no shutdown'])
    #countdown(5)
    return 1


def FloodTrafficGeneratorScaleArp22(port_handle,vlan,ip_sa,ip_da,rate_pps,count,mac_src):
    #host_count = int(count)*100
    device_ret = ixiangpf.traffic_config (
        mode            =       'create',
        port_handle     =       port_handle,
        l2_encap        =       'ethernet_ii_vlan',
        stream_id       =       vlan,
        vlan_id         =       vlan,
        vlan_id_count   =       count,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip_sa,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       count,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip_da,
        mac_dst         =       'ff:ff:ff:ff:ff:ff',
        mac_src         =       mac_src,
        mac_src_count   =       arp_count,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')

    status = device_ret['status']
    if (status == '0') :
        log.info("run ixiangpf.emulation_device_config failed")
        return 0
    else:
        log.info("***** run ixiangpf.emulation_device_config successfully")
        return 1

def mcastTrafficGeneratorScale(port_handle,vlan,ip_sa,ip_da,rate_pps,count):
    log.info(banner('+++ mcastTrafficGeneratorScale +++ '))

    str1=hex(randint(16,54))[2:]
    str2=hex(randint(55,104))[2:]
    str3=hex(randint(32,80))[2:]
    str4=hex(randint(50,95))[2:]

    mac1='00:'+str4+':'+str2+':'+str1+':'+str3+':02'

    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        traffic_generator =  'ixnetwork_540',
        port_handle     =    port_handle,
        l2_encap        =       'ethernet_ii_vlan',
        stream_id       =       vlan,
        vlan_id         =       vlan,
        vlan_id_count   =       count,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip_sa,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       count,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip_da,
        mac_dst         =       '01:00:5E:00:00:01',
        mac_src         =       mac1,
        mac_src_count   =       count,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')
    print("Mcast traffic ",device_ret)

    status = device_ret['status']
    if (status == '0') :
        log.info("run ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** run ixiahlt.traffic_config successfully")
        return 1


def trmTrafficGeneratorScale(port_handle,vlan,ip_sa,ip_da,rate_pps,count):
    log.info(banner('+++ mcastTrafficGeneratorScale +++ '))

    str1=hex(randint(16,54))[2:]
    str2=hex(randint(55,104))[2:]
    str3=hex(randint(32,80))[2:]
    str4=hex(randint(50,95))[2:]

    mac_da=ip2mac(ip_da)
    #if '239.1.1.1' in ip_da:
    #    mac_da='01:00:5E:01:01:01' 
 
    #elif '239.2.2.2' in ip_da:
    #    mac_da='01:00:5E:02:02:02'

    #elif '239.5.5.5' in ip_da:
    #    mac_da='01:00:5E:05:05:05'

    #elif '239.6.6.6' in ip_da:
    #    mac_da='01:00:5E:06:06:06'
    #else:
    #    mac_da='01:00:5E:01:01:01'         

    mac1='00:'+str4+':'+str2+':'+str1+':'+str3+':02'

    device_ret = ixiangpf.traffic_config (
        mode            =       'create',
        port_handle     =       port_handle,
        l2_encap        =       'ethernet_ii_vlan',
        stream_id       =       vlan,
        vlan_id         =       vlan,
        vlan_id_count   =       count,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip_sa,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       count,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip_da,
        ip_dst_step     =       '0.1.0.0',
        ip_dst_count    =       count,
        ip_dst_mode     =       'increment',
        mac_dst         =       mac_da,
        mac_dst_count   =       count,
        mac_dst_mode    =       'increment',
        mac_src         =       mac1,
        mac_src_count   =       count,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')

    status = device_ret['status']
    if (status == '0') :
        log.info("run ixiangpf.emulation_device_config failed")
        return 0
    else:
        log.info("***** run ixiangpf.emulation_device_config successfully")
        return 1


 

def mcastTrafficConfig(port_handle,vlan,ip_sa,mcast_address,rate_pps):
    log.info(banner('+++ mcastTrafficConfig +++ '))

    #str1=hex(randint(16,54))[2:]
    #str2=hex(randint(55,104))[2:]
    #str3=hex(randint(32,80))[2:]
    #str4=hex(randint(50,95))[2:]

    mac_add1 = str(RandMac("00:00:00:00:00:00", True))
    mac_sa = mac_add1.replace("'","")


    mac_da=ip2mac(mcast_address)       
    #mac_sa='00:'+str4+':'+str2+':'+str1+':'+str3+':02'
    device_ret = ixiangpf.traffic_config (
        mode            =       'create',
        port_handle     =       port_handle,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan,
        vlan_id_count   =       1,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip_sa,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       1,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       mcast_address,
        ip_dst_step     =       '0.1.0.0',
        ip_dst_count    =       1,
        ip_dst_mode     =       'increment',
        mac_dst         =       mac_da,
        mac_dst_count   =       1,
        mac_dst_mode    =       'increment',
        mac_src         =       mac_sa,
        mac_src_count   =       1,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')

    status = device_ret['status']
    if (status == '0') :
        log.info("run ixiangpf.emulation_device_config failed")
        return 0
    else:
        log.info("***** run ixiangpf.emulation_device_config successfully")
        return 1

def mcastTrafficConfigExt(port_handle,ip_sa,mcast_address,rate_pps,**kwargs):
    log.info(banner('+++ mcastTrafficConfig +++ '))
    for arg in kwargs:
        if 'vlan' in arg:
            vlan = kwargs['vlan'] 


    #str1=hex(randint(16,54))[2:]
    #str2=hex(randint(55,104))[2:]
    #str3=hex(randint(32,80))[2:]
    #str4=hex(randint(50,95))[2:]

    mac_add1 = str(RandMac("00:00:00:00:00:00", True))
    mac_sa = mac_add1.replace("'","")


    mac_da=ip2mac(mcast_address)       
    #mac_sa='00:'+str4+':'+str2+':'+str1+':'+str3+':02'
    
    if not 'Nil' in vlan:
        device_ret = ixiangpf.traffic_config (
        mode            =       'create',
        port_handle     =       port_handle,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan,
        vlan_id_count   =       1,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip_sa,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       1,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       mcast_address,
        ip_dst_step     =       '0.1.0.0',
        ip_dst_count    =       1,
        ip_dst_mode     =       'increment',
        mac_dst         =       mac_da,
        mac_dst_count   =       1,
        mac_dst_mode    =       'increment',
        mac_src         =       mac_sa,
        mac_src_count   =       1,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')
    else: 
        device_ret = ixiangpf.traffic_config (
        mode            =       'create',
        port_handle     =       port_handle,
        l2_encap        =       'ethernet_ii',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip_sa,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       1,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       mcast_address,
        ip_dst_step     =       '0.1.0.0',
        ip_dst_count    =       1,
        ip_dst_mode     =       'increment',
        mac_dst         =       mac_da,
        mac_dst_count   =       1,
        mac_dst_mode    =       'increment',
        mac_src         =       mac_sa,
        mac_src_count   =       1,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')

    status = device_ret['status']
    if (status == '0') :
        log.info("run ixiangpf.emulation_device_config failed")
        return 0
    else:
        log.info("***** run ixiangpf.emulation_device_config successfully")
        return 1


def trmTrafficConfigureSpirent(uut,port_hdl_src,pps,mcast_address):
    log.info(banner("------trmTrafficConfigureSpirent-----"))

    op = uut.execute('show nve vni  | incl L3')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            for vrf in line.split():
                if 'vxlan-' in vrf:
                    vrf = vrf.replace("[","").replace("]","")
                    log.info('vrf is %r',vrf)
                    vrf_list.append(vrf)

    for vrf in vrf_list:
        log.info('---------vrf is %r-----------',vrf)
        #count = uut.execute('show ip int br vrf {vrf} | incl Vlan | exc forward | count'.format(vrf=vrf))
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        vlan_list = []
        ip_list = []
        check = 1
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        if check == 1:
                            vlan_list.append(line.split()[0].replace("Vlan",""))
                            vlan=line.split()[0].replace("Vlan","")
                            ip_list.append(line.split()[1])
                            ip1 = line.split()[1]
                            ip_sa= str(ip_address(ip1)+randint(10,149))
                            log.info('---------vlan is %r-----------',vlan)
                            log.info('---------ip_sa is %r-----------',ip_sa)
                            log.info('---------mcast_address is %r-----------',mcast_address)
                            log.info('---------Going to mcastTrafficConfig-----------')
                            mcastTrafficConfig(port_hdl_src,vlan,ip_sa,mcast_address,1000)
                            check = check + 1
                            mcast_address = str(ip_address(mcast_address)+1)



def Trm_igmp_host_scale(uut,port_handle,mcast_address):
    op = uut.execute('show nve vni  | incl L3')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            for vrf in line.split():
                if 'vxlan-' in vrf:
                    vrf = vrf.replace("[","").replace("]","")
                    log.info('vrf is %r',vrf)
                    vrf_list.append(vrf)

    for vrf in vrf_list:
        count = uut.execute('show ip int br vrf {vrf} | incl Vlan | exc forward | count'.format(vrf=vrf))
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        vlan_list = []
        ip_list = []
        check = 1
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        if check == 1:
                            vlan_list.append(line.split()[0].replace("Vlan",""))
                            vlan=line.split()[0].replace("Vlan","")
                            ip_list.append(line.split()[1])
                            ip1 = line.split()[1]
                            #host_ip= str(ip_address(ip1)+100)
                            host_ip= str(ip_address(ip1)+randint(150,250))
                            log.info('---------vlan is %r-----------',vlan)
                            log.info('---------host_ip is %r-----------',host_ip)
                            log.info('---------mcast_address is %r-----------',mcast_address)
                            log.info('---------Going to mcastTrafficConfig-----------')       

                            IgmpHostCreate(port_handle=port_handle,\
                            vlan = vlan,
                            vlan_scale = count,
                            host_ip =host_ip,
                            mcast_group = mcast_address,
                            mcast_group_scale = 1)
                        #check = check + 1
        mcast_address = str(ip_address(mcast_address)+1)



def arp_supp_add_final(uut):

    op = uut.execute('show run int nve1 | beg nve1')
    op1 = op.splitlines()
    cmd = " "
    for line in op1:
        if line:
            cmd += line + '\n'
            if 'ingress-replication' in line:
                line1 = 'suppress-arp'
                cmd += line1 + '\n'
            elif 'mcast-group ' in line:
                line2 = 'suppress-arp'
                cmd += line2 + '\n'
    try:
        uut.configure(cmd)
    except:
        log.error('arp_supp_add_final failed ')
        #return 0





def CheckOspfUplinkRate(uut_list,pps):
    log.info(banner("Starting CheckOspfUplinkRate "))
    for uut in uut_list:
        cmd = uut.execute("show ip ospf neigh | json-pretty")
        op=json.loads(cmd)
        #op11 = op["TABLE_ctx"]['ROW_ctx']
        op1 = op["TABLE_ctx"]['ROW_ctx']["TABLE_nbr"]['ROW_nbr']
        nbrcount = op["TABLE_ctx"]['ROW_ctx']['nbrcount']

        core_intf_list = []

        if int(nbrcount) == 1:
            intf = op1["intf"]
            if not 'lan' in intf:
                core_intf_list.append(intf)
        else:
            for i in range(0,len(op1)):
                intf = op1[i]["intf"]
                if not 'lan' in intf:
                    core_intf_list.append(intf)

        for intf in core_intf_list:
            cmd = uut.execute('show interface {intf} counters brief | json-pretty'.format(intf=intf))
            op=json.loads(cmd)
            rate= op['TABLE_interface']['ROW_interface']['eth_outrate1']
            if int(rate) > pps:
                return 0
    log.info(banner("END CheckOspfUplinkRate "))
    return 1





def CheckUplinkRate(uut_list,igp,pps):
    log.info(banner("Starting CheckOspfUplinkRate "))
    for uut in uut_list:
        if 'ospf' in igp:
            cmd = uut.execute("show ip ospf neigh | json-pretty")
            op=json.loads(cmd)
            #op11 = op["TABLE_ctx"]['ROW_ctx']
            op1 = op["TABLE_ctx"]['ROW_ctx']["TABLE_nbr"]['ROW_nbr']
            nbrcount = op["TABLE_ctx"]['ROW_ctx']['nbrcount']

            core_intf_list = []
   
            if int(nbrcount) == 1:
                intf = op1["intf"]
                if not 'lan' in intf:
                    core_intf_list.append(intf)
            else:
                for i in range(0,len(op1)):
                    intf = op1[i]["intf"]
                    if not 'lan' in intf:
                        core_intf_list.append(intf)
        elif 'isis' in igp:
            core_intf_list = []
            op = uut.execute('show isis adjacency')
            op1 = op.splitlines()
            for line in op1:
               if 'UP' in line:
                   intf = line.split()[-1] 
                   core_intf_list.append(intf)  


        for intf in core_intf_list:
            cmd = uut.execute('show interface {intf} counters brief | json-pretty'.format(intf=intf))
            op=json.loads(cmd)
            rate= op['TABLE_interface']['ROW_interface']['eth_outrate1']
            if int(rate) > pps:
                return 0
    log.info(banner("END CheckOspfUplinkRate "))
    return 1
def SpirentArpRateTest(port_hdl_list1,port_hdl_list2,rate_fps,diff,arp_sa_state):
    log.info(banner(" Starting SpirentArpRateTest "))

    result = 1
    if 'on' in arp_sa_state:
        for port_hdl in port_hdl_list1:
            log.info("port_hdl %r,rate_fps %r", port_hdl,rate_fps)
            try:            
                res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            except:
                log.info('Stats failed for port %r',port_hdl)
                return 0
            try:               
                rx_rate = res['item0']['PortRxTotalFrameRate']
                tx_rate = res['item0']['PortTxTotalFrameRate']
            except:
                log.info('rx_rate failed for port %r',port_hdl)
                return 0
            log.info('+-----------------------------------------------------------------------+')
            log.info('rx_rate is %r,tx_rate is %r',rx_rate,tx_rate)
            log.info('+-----------------------------------------------------------------------+')

            if abs(int(tx_rate) - int(rate_fps)) > diff:
                log.info('TX rate low with SA enabled, rate is %r',tx_rate)
                result = 0

            if int(rx_rate) > 5*int(diff):
                log.info('ARP Rate Test failed with SA enabled, rate is %r',rx_rate)
                result = 0

            if int(rx_rate) < int(diff):
                log.info('vTEP may not be sending out the Arp Response, rate is %r',rx_rate)
                result = 0


        for port_hdl in port_hdl_list2:
            log.info("port_hdl %r", port_hdl)
            try:            
                res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            except:
                log.info('Stats failed for port %r',port_hdl)
                return 0
            try:               
                rx_rate = res['item0']['PortRxTotalFrameRate']
                tx_rate = res['item0']['PortTxTotalFrameRate']
            except:
                log.info('rx_rate failed for port %r',port_hdl)
                return 0
            log.info('+-----------------------------------------------------------------------+')
            log.info('rx_rate is %r,tx_rate is %r',rx_rate,tx_rate)
            log.info('+-----------------------------------------------------------------------+')

            if int(rx_rate) > 2*(int(diff)):
                log.info('ARP Rate Test failed with SA enabled, rate at orphan port is %r',rx_rate)
                result = 0


    elif 'off' in arp_sa_state:
        for port_hdl in port_hdl_list1:
            log.info("port_hdl %r,rate_fps %r", port_hdl,rate_fps)
            try:            
                res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            except:
                log.info('Stats failed for port %r',port_hdl)
                return 0
            try:               
                rx_rate = res['item0']['PortRxTotalFrameRate']
                tx_rate = res['item0']['PortTxTotalFrameRate']
            except:
                log.info('rx_rate failed for port %r',port_hdl)
                return 0
            log.info('+-----------------------------------------------------------------------+')
            log.info('rx_rate is %r,tx_rate is %r',rx_rate,tx_rate)
            log.info('+-----------------------------------------------------------------------+')

            if abs(int(rx_rate) - int(tx_rate)) > 4*int(diff):
                log.info('Traffic  Rate Test failed - TX / RX difference is %r',abs(int(rx_rate) - int(tx_rate)))
                result = 0

            if abs(int(rx_rate) - int(rate_fps)) > 4*int(diff):
                log.info('Traffic  Rate Test failed, Rate & FPS diff is %r',abs(int(rx_rate) - int(rate_fps)))
                result = 0

        for port_hdl in port_hdl_list2:
            log.info("port_hdl %r", port_hdl)
            #res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            #rx_rate = res['item0']['PortRxTotalFrameRate']
            #tx_rate = res['item0']['PortTxTotalFrameRate']

            try:            
                res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            except:
                log.info('Stats failed for port %r',port_hdl)
                return 0
            try:               
                rx_rate = res['item0']['PortRxTotalFrameRate']
                tx_rate = res['item0']['PortTxTotalFrameRate']
            except:
                log.info('rx_rate failed for port %r',port_hdl)
                return 0




            log.info('+-----------------------------------------------------------------------+')
            log.info('rx_rate is %r,tx_rate is %r',rx_rate,tx_rate)
            log.info('+-----------------------------------------------------------------------+')

            if abs(int(rx_rate) - 2*(int(rate_fps))) > 5*int(diff):
                log.info('ARP Rate Test failed with SA Disabled, rate at orphan port is %r',rx_rate)
                result = 0

    return result



def ArpSuppressTrafficGenerator(port_handle,vlan,ip_sa,ip_da,mac_sa,rate_pps,count):
    #log.info("port_handle %r vlan %r ip_sa %r ip_da %r mac_sa %r ",port_handle,vlan,ip_sa,ip_da,mac_sa)
    log.info(banner("------in ArpSuppressTrafficGenerator-----"))

    #for vlan in range(int(vlan),int(vlan)+int(count)):
    vlan = str(vlan)

    streamblock_ret1 = ixiangpf.traffic_config (
        mode = 'create',
        port_handle = port_handle,
        l2_encap = 'ethernet_ii_vlan',
        stream_id       =       vlan,
        vlan_id=vlan,
        vlan_id_count=count,
        vlan_id_mode='increment',
        l3_protocol = 'arp',
        ip_src_addr = ip_sa,
        ip_src_count = count,
        ip_src_mode = 'increment',
        ip_src_step ='0.1.0.0',
        ip_dst_addr = ip_da,
        ip_dst_count = count,
        ip_dst_mode = 'increment',
        ip_dst_step ='0.1.0.0',
        arp_src_hw_addr = mac_sa,
        arp_src_hw_mode = 'increment',
        arp_src_hw_count = count,
        arp_dst_hw_addr = "00:00:00:00:00:00",
        arp_dst_hw_mode = "fixed",
        arp_operation = "arpRequest",
        rate_pps = rate_pps,
        mac_src = mac_sa,
        mac_dst = 'ff:ff:ff:ff:ff:ff',
        mac_src_count= count,
        mac_src_mode='increment',
        mac_src_step='00:00:00:00:00:01',
        transmit_mode = 'continuous')



def FloodTrafficGeneratorScaleArp(port_handle,vlan,ip_sa,ip_da,rate_pps,count,mac_src):
    #host_count = int(count)*100
    device_ret = ixiangpf.traffic_config (
        mode            =       'create',
        port_handle     =       port_handle,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan,
        stream_id       =       vlan,
        vlan_id_count   =       count,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip_sa,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       count,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip_da,
        mac_dst         =       'ff:ff:ff:ff:ff:ff',
        mac_src         =       mac_src,
        mac_src_count   =       count,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')

    status = device_ret['status']
    if (status == '0') :
        log.info("run ixiangpf.emulation_device_config failed")
        return 0
    else:
        log.info("***** run ixiangpf.emulation_device_config successfully")
        return 1


def arp_supp_remove_final(uut):

    op = uut.execute('show run int nve1 | beg nve1')
    op1 = op.splitlines()
    cmd = " "
    for line in op1:
        if line:
            if 'suppress-arp' in line:
                line = 'no suppress-arp'
        cmd += line + '\n'
    try:
        uut.configure(cmd)
    except:
        log.error('arp_supp_remove_final failed ')
        #return 0


def pingtest(uut,dest_ip):
    log.info("----------sw1.send(ping %r count unlimited timeout 0) -------------",dest_ip)
    try:
        uut.execute("ping {dest_ip} count 10000 timeout 0".format(dest_ip=dest_ip))
    except:
        log.error('ping failed')
        return 0
    return 1

def captest(uut):
    cmd1 = "ethanalyzer local interface inband detail | incl 'CFI: 0, ID: 1001'"
    cap1 = uut.execute(cmd1)
    #if '1001' in cap1:
    #    log.info('capture is %r',cap1)
    return str(cap1)
    #return 1


def SpirentRoutedBidirStreamInspur(port_hdl1,port_hdl2,vlan1,vlan2,ip1,ip2,gw1,gw2,rate_pps):
    log.info(banner("------SpirentRoutedBidirStreamInspur-----"))

    if 'Nil' in vlan1 and 'Nil' in vlan2:
        str11 = hex(int(1001))[2:][:2]
        str12 = hex(int(1001))[2:][1:]
        str21 = hex(int(1002))[2:][:2]
        str22 = hex(int(1002))[2:][1:]

        mac1='00:10:'+str11+':'+str12+':'+str11+':22'
        mac2='00:11:'+str22+':'+str22+':'+str21+':44'


        log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)
        device_ret1 =ixiangpf.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
        encapsulation = 'ethernet_ii',port_handle = port_hdl1,\
        resolve_gateway_mac = 'true',intf_ip_addr= ip1,intf_prefix_len = '16',\
        gateway_ip_addr = gw1,mac_addr= mac1);

        device_ret2 =ixiangpf.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
        encapsulation = 'ethernet_ii',port_handle = port_hdl2,\
        resolve_gateway_mac = 'true',intf_ip_addr= ip2,intf_prefix_len = '16',\
        gateway_ip_addr = gw2,mac_addr= mac2);

        h1 = device_ret1['handle']
        h2 = device_ret2['handle']

    elif not 'Nil' in vlan1 and 'Nil' in vlan2:
        str11 = hex(int(vlan1))[2:][:2]
        str12 = hex(int(vlan1))[2:][1:]
        str21 = hex(int(1001))[2:][:2]
        str22 = hex(int(1001))[2:][1:]

        mac1='00:10:'+str11+':'+str12+':'+str11+':22'
        mac2='00:11:'+str22+':'+str22+':'+str21+':44'

        log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)
        device_ret1 =ixiangpf.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
        encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan1,port_handle = port_hdl1,\
        resolve_gateway_mac = 'true',intf_ip_addr= ip1,intf_prefix_len = '16',\
        gateway_ip_addr = gw1,mac_addr= mac1);


        device_ret2 =ixiangpf.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
        encapsulation = 'ethernet_ii',port_handle = port_hdl2,\
        resolve_gateway_mac = 'true',intf_ip_addr= ip2,intf_prefix_len = '16',\
        gateway_ip_addr = gw2,mac_addr= mac2);

        h1 = device_ret1['handle']
        h2 = device_ret2['handle']

    elif not 'Nil' in vlan2 and 'Nil' in vlan1:
        str11 = hex(int(vlan2))[2:][:2]
        str12 = hex(int(vlan2))[2:][1:]
        str21 = hex(int(1001))[2:][:2]
        str22 = hex(int(1001))[2:][1:]

        mac1='00:10:'+str11+':'+str12+':'+str11+':22'
        mac2='00:11:'+str22+':'+str22+':'+str21+':44'

        log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)
        device_ret1 =ixiangpf.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
        encapsulation = 'ethernet_ii',port_handle = port_hdl1,\
        resolve_gateway_mac = 'true',intf_ip_addr= ip2,intf_prefix_len = '16',\
        gateway_ip_addr = gw2,mac_addr= mac2);

        device_ret2 =ixiangpf.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
        encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan2,port_handle = port_hdl2,\
        resolve_gateway_mac = 'true',intf_ip_addr= ip1,intf_prefix_len = '16',\
        gateway_ip_addr = gw1,mac_addr= mac1);


        h1 = device_ret1['handle']
        h2 = device_ret2['handle']


    streamblock_ret1 = ixiangpf.traffic_config (mode= 'create',port_handle= port_hdl1,\
    emulation_src_handle=h1,emulation_dst_handle = h2,bidirectional='1',\
    port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps)

    status = streamblock_ret1['status']

    log.info('+-----------------------------------------------------------------------+')
    log.info('stream_id : %r, vlan1 : %r ,vlan2 : %r ,rate_pps : %r',streamblock_ret1['stream_id'],vlan1,vlan2,rate_pps)
    log.info('IP1 : %r,IP2 : %r, Host1 : %r ,Host2 : %r ',ip1,ip2,h1,h2)
    log.info('+-----------------------------------------------------------------------+')
    if (status == '0') :
        log.info('run ixiangpf.traffic_config failed for V4 %r', streamblock_ret1)


def tgnHostCreate(port_hdl,ipv4_add,ipv4_gw,**kwargs):
    vlan = kwargs.get("vlan", None)
    mac_add = kwargs.get("mac_add", None)
    intf_prefix_len = kwargs.get("intf_prefix_len", None)

    if not intf_prefix_len:
        intf_prefix_len = '16'
    if not mac_add:
        mac_add1 = str(RandMac("00:00:00:00:00:00", True))
        mac_add = mac_add1.replace("'","")
    #try:
    if not vlan:
        device_ret =ixiangpf.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
        encapsulation = 'ethernet_ii',port_handle = port_hdl,\
        resolve_gateway_mac = 'true',intf_ip_addr= ipv4_add,intf_prefix_len = intf_prefix_len,\
        gateway_ip_addr = ipv4_gw,mac_addr= mac_add);
    else:
        device_ret =ixiangpf.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
        encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan,port_handle = port_hdl,\
        resolve_gateway_mac = 'true',intf_ip_addr= ipv4_add,intf_prefix_len = intf_prefix_len,\
        gateway_ip_addr = ipv4_gw,mac_addr= mac_add);

    host = device_ret['handle']
    log.info('Created host is %r, returning host ',host)
    return host

def tgnBidirStreamCreate(port_hdl1,port_hdl2,host_src_handle,host_dst_handle,rate_pps):
    streamblock_ret1 = ixiangpf.traffic_config (mode= 'create',port_handle= port_hdl1,\
    emulation_src_handle=host_src_handle,emulation_dst_handle = host_dst_handle,bidirectional='1',\
    port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps)

    status = streamblock_ret1['status']


def CreateSpirentStreams2223(port_hdl,ip_src,ip_dst,mac_src,mac_dst,stream_id,rate_pps,smac_count,dmac_count,dmac_step,dmac_mode,smac_mode,transmit_mode,smac_step,vlan_id):
    #self,port_hdl_list,ip_src_list,ip_dst_list,mac_src_list,mac_dst_list,stream_list,rate_pps,mac_count,mac_mode,mac_step,vlan_id):
    """ function to configure Stream """
    logger.info(banner("Entering proc to configure streams in Spirent"))
    try:
        streamblock_ret1 = ixiangpf.traffic_config (
                mode = 'create',
                port_handle = port_hdl,
                l2_encap = 'ethernet_ii_vlan',
                frame_size_min='500',
                frame_size_max='9000',
                frame_size_step='500',
                vlan_id=vlan_id,
                l3_protocol = 'ipv4',
                ip_id = '0',
                ip_src_addr = ip_src,
                ip_dst_addr = ip_dst,
                ip_dst_count = '20',
                ip_dst_mode = 'increment',
                ip_dst_step ='0.0.0.1',
                ip_ttl = '255',
                ip_hdr_length = '5',
                ip_protocol = '253',
                mac_src = mac_src,
                mac_dst = mac_dst,
                mac_dst_count = dmac_count,
                mac_dst_mode = dmac_mode,
                mac_dst_step = dmac_step,
                mac_src_count= smac_count,
                mac_src_mode=smac_mode,
                mac_src_step=smac_step,
                stream_id = stream_id,
                rate_pps = rate_pps,
                fill_type = 'constant',
                fcs_error = '0',
                fill_value = '0',
                traffic_state = '1',
                length_mode = 'fixed',
                disable_signature = '0',
                enable_stream_only_gen= '1',
                pkts_per_burst = '1',
                inter_stream_gap_unit= 'bytes',
                burst_loop_count = '30',
                transmit_mode = transmit_mode,
                inter_stream_gap = '12',
                mac_discovery_gw = ip_dst)

        status = streamblock_ret1['status']

        if (status == '0') :
            log.info('run ixiangpf.traffic_config failed for V4 %r', streamblock_ret1)

    except:
        log.error('Spirect traffic config failed')
        log.error(sys.exc_info())



def clearConsole(ts,port_list):
    switch = pexpect.spawn('telnet {ts}'.format(ts=ts))
    switch.logfile = sys.stdout
    switch.expect("Username:")
    switch.sendline("lab")
    switch.expect("Password:")
    switch.sendline("lab")
    switch.expect("#")
    for line in port_list:
        for i in range(1,10):
            switch.sendline("clear line {line}".format(line=int(line)))
            switch.expect('[confirm]')
            switch.sendline("\r\n")
            switch.expect("#")


def ConfigureEsiGlobal(uut):
    """ function to configure ESI Global """
    logger.info(banner("Entering proc configure ESI Nodes"))

    config_str = \
        """
        no feature vpc
        evpn esi multihoming
        ethernet-segment delay-restore time 30
        vlan-consistency-check
        """
    try:
        uut.configure(config_str)
        log.info('ESI global config PASSED in uut %r',uut)
    except:
        log.info('ESI global config FAILED in uut %r',uut)
        return 0

def mctsviConfigure(uut,igp):
            #leaf2mctsvi1:
            #    intf: "vlan10"
            #    link: link-2
            #    type: svi
            #    alias: "svimct"                              
            #    ipv4: 12.1.1.2/24
            #    pim: 'yes'
    #pdb.set_trace()
    #for bgw_intf in [*bgw_uut.interfaces.keys()]: 


     
    if 'isis' in igp:        
        for intf in [*uut.interfaces.keys()]:
            #log.info('intf is +++++ %r',intf)
            if 'svi' in uut.interfaces[intf].alias:
                intf_name = uut.interfaces[intf].intf
                ip_add = uut.interfaces[intf].ipv4
                vlan = intf_name.strip('vlan')
                if 'FX' in uut.execute('sh module | inc active'):
                    uut.configure('system nve infra-vlans {vlan}'.format(vlan=str(vlan)))  

                if not '9.3' in uut.execute('show version | inc NXOS'):
                    cfg = \
                     """
                     vlan {vlan}
                     interface vlan {vlan}
                     no sh
                     ip pim sparse-m
                     ip address {ip_add}
                     isis metric 100 level-1
                     isis circuit-type level-1
                     ip router isis UNDERLAY
                     isis authentication-type md5  
                     isis authentication key-chain KEYCHAIN-ISIS  
                     """
                else:
                    cfg = \
                     """
                     vlan {vlan}
                     interface vlan {vlan}
                     no sh
                     ip pim sparse-m
                     ip address {ip_add}
                     isis metric 100 level-1
                     isis circuit-type level-1
                     ip router isis UNDERLAY
                     isis authentication-type md5 level-1
                     isis authentication key-chain KEYCHAIN-ISIS level-1
                     """ 
                try:
                    uut.configure(cfg.format(vlan=str(vlan),ip_add=ip_add),timeout = 120)
                except:
                    log.error('ISIS  config failed for node  %r intf %r',uut,intf)
                    return 0
        return 1

    elif 'ospf' in igp:        
        for intf in [*uut.interfaces.keys()]:
            #log.info('intf is +++++ %r',intf)
            if 'svi' in uut.interfaces[intf].alias:
                intf_name = uut.interfaces[intf].intf
                ip_add = uut.interfaces[intf].ipv4
                vlan = intf_name.strip('vlan')
                cfg = \
                """
                vlan {vlan}
                interface vlan {vlan}
                no sh
                ip pim sparse-m
                ip address {ip_add}
                ip router ospf UNDERLAY area 0
                no shut
                """
                try:
                    uut.configure(cfg.format(vlan=str(vlan),ip_add=ip_add),timeout = 120)                    
                except:
                    log.error('ISIS  config failed for node  %r intf %r',uut,intf)
                    return 0
        return 1

def ConfigureEsiGlobal(uut):
    """ function to configure ESI Global """
    logger.info(banner("Entering proc configure ESI Nodes"))

    config_str = \
        """
        no feature vpc
        evpn esi multihoming
        ethernet-segment delay-restore time 30
        vlan-consistency-check
        """
    try:
        uut.configure(config_str)
        log.info('ESI global config PASSED in uut %r',uut)
    except:
        log.info('ESI global config FAILED in uut %r',uut)
        return 0



def ConfigureEsiPo(uut,esid,sys_mac,esi_po,vlan_range,mode,member_list):
    """ function to configure ESI Global """
    logger.info(banner("Entering proc configure ESI Po"))
    if 'access' in mode:
        config_str = \
        '''
        no interface port-channel {esi_po}
        interface port-channel {esi_po}
        #port-channel mode active
        no shut
        switchport
        switchport mode access
        no shut
        switchport access vlan {vlan_range}
        ethernet-segment {esid}
        system-mac {sys_mac}
        mtu 9216
        '''

    elif 'trunk' in mode:

        config_str = \
        """
        no interface port-channel {esi_po}
        interface port-channel {esi_po}
        #port-channel mode active
        no shut
        switchport
        switchport mode trunk
        no shut
        switchport trunk allowed vlan {vlan_range}
        ethernet-segment {esid}
        system-mac {sys_mac}
        mtu 9216
        """
    #try:
    uut.configure(config_str.format(esid=esid,sys_mac=sys_mac,esi_po=esi_po,vlan_range=vlan_range))
    log.info('ESI Po %r config PASSED in uut %r',esi_po,uut)
    #except:
    #log.info('ESI Po %r config FAILED in uut %r',esi_po,uut)
    #return 0

    for intf in member_list:
        config_str = \
        '''
        default interface {intf}
        interface {intf}
        channel-group {esi_po} force mode active
        no shut
        '''
        try:
            uut.configure(config_str.format(intf=intf,esi_po=esi_po),timeout=120)
        except:
            log.info('ESI Po %r member %r config FAILED in uut %r',esi_po,intf,uut)
            return 0

    return 1


class EsiNode(object):
    def __init__(self,node,esid,sys_mac,esi_po,esi_mem_list1,vlan_range,esi_po_type):
        self.node=node
        self.esid=esid
        self.sys_mac=sys_mac
        self.esi_po=esi_po
        self.esi_mem_list1=esi_mem_list1
        self.vlan_range=vlan_range
        self.esi_po_type=esi_po_type

    def esi_configure(self):
        result = ConfigureEsiPo(self.node,self.esid,self.sys_mac,self.esi_po,self.vlan_range,self.esi_po_type,self.esi_mem_list1)


class leaf(object):
    '''
    leaf1-
    loop - pri/sec
    access -  vpc/orp - acc/trunk
    uplink - po/ip/unnumb
    igp - ospf/isis / v6
    pim - rp
    bgp - as
    vxlan - mode
    bgw - type
    '''

    def __init__(self,node,vlan_range):
        self.node=node
        self.vlan_range=vlan_range

        log.info("leaf device is %r",self.node)
 

    def loopback_configure(self):
        for intf in self.node.interfaces.keys():
            if 'loopback' in intf:
                intf=self.node.interfaces[intf].intf
                log.info("loopback intf is %r  on leaf device  %r",intf,self.node)
                if 'ipv4_sec' in dir(self.node.interfaces[intf]):
                    ipv4_add_sec = self.node.interfaces[intf].ipv4_sec
                    ipv4_add=self.node.interfaces[intf].ipv4
                    log.info('ipv4_add is %r ipv4_add_sec is %r on leaf device %r',ipv4_add,ipv4_add_sec,self.node)
                    ConfigLoopback(self.node,intf,ipv4_add,ipv4_add_sec)

                else:
                    ipv4_add=self.node.interfaces[intf].ipv4
                    log.info('ipv4_add is %r on leaf device  %r ',ipv4_add,self.node)
                    ConfigLoopback(self.node,intf,ipv4_add,'Nil')

    def l3_port_configure(self):
        spine_leaf_intf_list = []
        log.info("+++++++++++++1111111++++++++++++++++++++++++++++++")
        log.info("uut.interfaces.keys() are %r",self.node.interfaces.keys())
        log.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        for intf in self.node.interfaces.keys():
            if 'Eth' in self.node.interfaces[intf].intf:
                if 'leaf_spine' in self.node.interfaces[intf].alias:
                    intf=self.node.interfaces[intf].intf
                    #log.info("leaf_spine intf is %r  on leaf device  %r",intf,self.node)
                    spine_leaf_intf_list.append(intf)

        #log.info("spine_leaf_intf_list is %r  on leaf device  %r",spine_leaf_intf_list,self.node)

        log.info("+++++++++++222222222+++++++++++++++++++++++++")
        log.info("uut.interfaces.keys() are %r",self.node.interfaces.keys())
        log.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++")



        for intf in spine_leaf_intf_list:
            eth = Interface(name=intf)
            eth.device = self.node
            eth.description = 'leaf_spine'
            eth.shutdown = False
            eth.mtu = 9216
            eth.medium = 'p2p'
            eth.unnumbered_intf_ref = 'loopback1'
            log.info("Configuring interface %r in device %r",intf,self.node)
            configuration = eth.build_config()


        log.info("+++++++++++333333333+++++++++++++++++++++++++")
        log.info("uut.interfaces.keys() are %r",self.node.interfaces.keys())
        log.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++")



    def underlay_igp_configure(self):
        ipv4_add=self.node.interfaces['loopback1'].ipv4.ip
        ospf1 = Ospf()
        self.node=add_feature(ospf1)
        ospf1.device_attr[self.node].vrf_attr["default"].instance = '1'
        ospf1.device_attr[self.node].vrf_attr["default"].router_id = ipv4_add

        for intf in self.node.interfaces.keys():
            intf=self.node.interfaces[intf].intf
            if "oopback" in intf.name or "leaf" in intf.alias:
                ospf1.device_attr[self.node].vrf_attr["default"].area_attr['0'].interface_attr[intf].if_admin_control = True
        
        ospf1.build_config()


    def access_port_configure(self):
        vpc_access_port_member_list = []
        esi_access_port_member_list = []
        mct_port_member_list = []



        log.info("+++++++++++444444444+++++++++++++++++++++++++")
        log.info("uut.interfaces.keys() are %r",self.node.interfaces.keys())
        log.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++")


        uut=self.node
        vlan_range = self.vlan_range
 
        log.info("+++++++++++55555555+++++++++++++++++++++++++")
        log.info("uut.interfaces.keys() are %r",self.node.interfaces.keys())
        log.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++")


        log.info(banner("-----FAILURE--66666---"))      
        log.info("uut.interfaces.keys() are %r",uut.interfaces.keys())

        for intf in uut.interfaces.keys():
            log.info("Checking port %r on leaf device %r for tgn connection",intf,uut)
            if not 'Eth' in str(intf):
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'tgn' in uut.interfaces[intf].alias:
                        log.info("Configuring port %r on leaf device %r for tgn connection",intf,uut)
                        intf=uut.interfaces[intf].intf
                        try:
                            AccesPortconfigs(uut,intf,vlan_range)
                        except:
                            log.error('AccesPortconfigs failed for port %r @ uut %r',intf,uut)
 
        for intf in uut.interfaces.keys():
            if 'mct_po' in uut.interfaces[intf].alias:
                log.info("mct port-channel is %r on leaf device  %r",intf,uut)
                mct_po_number = uut.interfaces[intf].intf
                src_ip = uut.interfaces[intf].src_ip
                peer_ip = uut.interfaces[intf].peer_ip

            elif 'vpc_po' in uut.interfaces[intf].alias:
                log.info("vpc port-channel is %r on leaf device  %r",intf,uut)
                vpc_po_number = uut.interfaces[intf].intf

        for intf in uut.interfaces.keys():            
            if 'Eth' in uut.interfaces[intf].intf:
                
                if 'esi_access' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    log.info("adding esi port-channel member %r on leaf device  %r",intf,uut)
                    esi_access_port_member_list.append(intf)

                elif 'vpc_access' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    log.info("adding vpc port-channel member %r on leaf device  %r",intf,uut)
                    vpc_access_port_member_list.append(intf)

                elif 'mct_link' in suut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    log.info("adding mct port-channel member %r on leaf device  %r",intf,uut)
                    mct_port_member_list.append(intf)

        for intf in uut.interfaces.keys():
            if 'vpc_po' in uut.interfaces[intf].alias:
                intf=uut.interfaces[intf].intf
                log.info("Configureing VPC port-channel  %r on leaf device  %r",intf,uut)
                try:
                    vtep_vpc_global_obj1 = VPCNodeGlobal(uut,mct_po_number,str(peer_ip),\
                    mct_port_member_list,str(src_ip))
                    vtep_vpc_global_obj1.vpc_global_conf()
                except:
                    log.error('vtep_vpc_global_obj1.vpc_global_conf failed')

                try:
                    vtep_vpc_obj1 = VPCPoConfig(uut,vpc_po_number,vpc_access_port_member_list,\
                    vlan_range,'trunk')
                    vtep_vpc_obj1.vpc_conf()
                except:
                    log.error('vtep_vpc_obj1.vpc_conf failed')





def leafGlobalConfig(uut):
    cmd=\
            '''
            fabric forwarding anycast-gateway-mac 0000.2222.3333
            '''
    try:
        uut.configure(cmd.format(rid=rid,pim_rp_address=pim_rp_address))
    except:
        log.error('OSPF config failed for node %r',uut)

def leafOspfConfig(uut):
    cmd=\
            '''
            fabric forwarding anycast-gateway-mac 0000.2222.3333
            feature ospf
            feature pim
            no router ospf 100
            router ospf 100
            router-id {rid}
            ip pim rp-address {pim_rp_address} group-list 224.0.0.0/4
            '''
    try:
        uut.configure(cmd.format(rid=rid,pim_rp_address=pim_rp_address))
    except:
        log.error('OSPF config failed for node %r',uut)

def leafPimConfig(uut):
    cmd=\
            '''
            fabric forwarding anycast-gateway-mac 0000.2222.3333
            feature ospf
            feature pim
            no router ospf 100
            router ospf 100
            router-id {rid}
            ip pim rp-address {pim_rp_address} group-list 224.0.0.0/4
            '''
    try:
        uut.configure(cmd.format(rid=rid,pim_rp_address=pim_rp_address))
    except:
        log.error('OSPF config failed for node %r',uut)


def l3UnnumberedIntfConf(uut,intf_list):
    for intf in intf_list:
        cmd=\
                '''
                default interface {intf}
                interf {intf}
                description VTEP_SPINE
                no switchport
                mtu 9216
                logging event port link-status
                medium p2p
                no ip redirects
                ip unnumbered loopback1
                ip ospf network point-to-point
                ip router ospf 100 area 0.0.0.0
                ip ospf cost 1
                ip pim sparse-mode
                no shutdown
                '''
        try:
            uut.configure(cmd.format(intf=intf),timeout=120)
        except:
            log.error('Uplink interface config failed for node %r,%r',uut,intf)


def AccesPortconfigs(uut,intf,vlan_range):
    cmd = """\
    default interface {intf}
    interface {intf}
    switchport
    shut
    #mtu 9216
    switchport mode trunk
    switchport trunk allowed vlan {vlan_range}
    spanning-tree port type edge trunk
    spanning-tree bpdufilter enable
    sleep 1
    no shut
    """
    try:
        uut.configure(cmd.format(intf=intf,vlan_range=vlan_range),timeout=160)
    except:
        log.error('AccesPortconfigs config failed for node %r,%r',uut,intf)

def ConfigLoopback(uut,interface_id,ipv4,ipv4_sec):
    if not 'Nil' in ipv4_sec:
        config_str = \
            """
            no interf {interface_id}
            interf {interface_id}
            no ip add
            ip add {ipv4}
            ip add {ipv4_sec} second
            descr NVE loopback
            no shut
            """
        try:
            uut.configure(config_str.format(interface_id=interface_id,ipv4=ipv4,ipv4_sec=ipv4_sec))
        except:
            log.error('Loop Config Failed on UUT %r',uut)

    else:
        config_str = \
            """
            no interf {interface_id}
            interf {interface_id}
            no ip add
            ip add {ipv4}
            no shut
            """
        try:
            uut.configure(config_str.format(interface_id=interface_id,ipv4=ipv4))
        except:
            log.error('Loop Config Failed on UUT %r',uut)

def OspfGlobalConfig(uut,rid,ospf_proc):
    cmd=\
        '''
        feature ospf
        no router ospf {ospf_proc}
        router ospf {ospf_proc}
        router-id {rid}
        '''
    try:
        uut.configure(cmd.format(ospf_proc=ospf_proc,rid=rid),timeout = 120)
    except:
        log.error('ospf config failed for node  %r',uut)


def OspfIntfConfig(uut,intf_list,ospf_proc,intf_type):
    if 'loop' in intf_type:
        for intf in intf_list:
            cfg = \
            """       
            interf {intf}
            ip router ospf {ospf_proc} area 0.0.0.0
            """
            try:
                uut.configure(cfg.format(intf=intf,ospf_proc=ospf_proc),timeout = 120)
            except:
                log.error('ospf loop config failed for node  %r',uut)

    elif 'p2p' in intf_type:
        for intf in intf_list:
            cfg = \
            """       
            interf {intf}
            ip router ospf {ospf_proc} area 0.0.0.0   
            ip ospf network point-to-point
            ip ospf cost 1
            """
            try:
                uut.configure(cfg.format(intf=intf,ospf_proc=ospf_proc),timeout = 120)
            except:
                log.error('ospf intf config failed for node  %r',uut)


def IsisGlobalConfig(uut):
    log.info(banner('IsisGlobalConfig'))
    #net 49.0001.0830.8803.3070.00
    #redistribute bgp 65003 route-map GLOB-BGP_TO_ISIS-REDIST
    id = str(randint(3000,3999))
    net = '49.0001.0830.8803.'+id+'.00'

    cmd=\
        '''
        feature isis
        key chain KEYCHAIN-ISIS
        key 100
        key-string 7 070c294d4d260b3202065d
        accept-lifetime 00:00:00 Jan 01 2016  infinite
        send-lifetime 00:00:00 Jan 01 2016  infinite
        router isis UNDERLAY
        net {net}
        is-type level-1
        max-lsp-lifetime 65535
        redistribute maximum-prefix 100
        log-adjacency-changes
        authentication-type md5 level-1
        authentication key-chain KEYCHAIN-ISIS level-1
        '''
    try:
        uut.configure(cmd.format(net=net,timeout = 120))
    except:
        log.error('ISIS IsisGlobalConfig  failed for node  %r',uut)
        return 0


def IsisIntfConfig(uut,intf_list,intf_type):
    if 'loop' in intf_type:
        for intf in intf_list:
            cfg = \
            """       
            interf {intf}
            isis metric 100 level-1
            isis circuit-type level-1
            ip router isis UNDERLAY
            """
            try:
                uut.configure(cfg.format(intf=intf),timeout = 120)
            except:
                log.error('ISIS loop config failed for node  %r intf %r',uut,intf)
                return 0

    elif 'p2p' in intf_type:
        for intf in intf_list:
            if not '9.3' in uut.execute('show version | inc NXOS'):
                cfg = \
                """       
                interf {intf}
                isis metric 100 level-1
                isis circuit-type level-1
                isis authentication-type md5   
                isis authentication key-chain KEYCHAIN-ISIS  
                ip router isis UNDERLAY
                """
            else:
                cfg = \
                """       
                interf {intf}
                isis metric 100 level-1
                isis circuit-type level-1
                isis authentication-type md5  level-1
                isis authentication key-chain KEYCHAIN-ISIS level-1
                ip router isis UNDERLAY
                """
            try:
                uut.configure(cfg.format(intf=intf),timeout = 120)
            except:
                log.error('ISIS  config failed for node  %r intf %r',uut,intf)
                return 0


def PimConfig(uut,intf_list,pim_rp_address):
    cmd=\
        '''
        ip pim rp-address {pim_rp_address} group-list 224.0.0.0/4
        ip pim ssm range 232.0.0.0/8
        '''
    try:
        uut.configure(cmd.format(pim_rp_address=pim_rp_address),timeout = 120)
    except:
        log.error('ip pim rp-address config failed for node %r',uut)

    for intf in intf_list:
        cfg = \
        """       
        interf {intf}
        ip pim sparse-mode       
        """
        try:
            uut.configure(cfg.format(intf=intf),timeout = 120)
        except:
            log.error('ip pim sparse-mode  config failed for node  %r',uut)


def anycastgatewayConfig(uut,gw):
    cmd=\
        '''
        fabric forwarding anycast-gateway-mac {gw}
        '''
    try:
        uut.configure(cmd.format(gw=gw),timeout = 120)
    except:
        log.error('anycastgatewayConfig config failed for node %r',uut)

def anycastgatewayConfig10(uut):
    cmd=\
        '''
        fabric forwarding anycast-gateway-mac 0000.2222.3333
        '''
    try:
        uut.configure(cmd,timeout = 120)
    except:
        log.error('anycastgatewayConfig10 config failed for node %r',uut)


def bfdEnable(uut):
    uut.configure('feature bfd')
    uut.configure('bfd interval 250 min_rx 250 multiplier 3')


def dciEbgpv4Bringup(bgw_uut_list,dci_uut_list,bgw_as_number,dci_as_number):
    log.info(banner("+++ dciEbgpv4Bringup START +++"))
    for bgw_uut in bgw_uut_list:
        log.info("bgw_uut is %r",bgw_uut)
        cfg_bgw = \
        """
        ip prefix-list redistribute-direct-underlay seq 5 permit 0.0.0.0/0 le 32 
        route-map redistribute-direct-underlay permit 10
        match ip address prefix-list redistribute-direct-underlay 
        router bgp {bgw_as_number}        
        log-neighbor-changes
        address-family ipv4 unicast
        redistribute direct route-map redistribute-direct-underlay
        maximum-paths 8
        """
        log.info("cfg_bgw @1 is %r",cfg_bgw.format(bgw_as_number=bgw_as_number))
        for bgw_intf in [*bgw_uut.interfaces.keys()]:   
            if 'loop_dci' in bgw_uut.interfaces[bgw_intf].alias:
                log.info("'loop_dci' in bgw_uut.interfaces[bgw_intf].alias: for intf %r",bgw_intf)
                bgw_rid1 = bgw_uut.interfaces[bgw_intf].ipv4
                bgw_rid =str(bgw_rid1)[:-3]
                bgw_loop_list.append(bgw_rid)
                cfg_bgw +=  'router-id {bgw_rid}\n'.format(bgw_rid=bgw_rid)                              
                log.info("bgw_rid %r",bgw_rid)

        log.info("cfg_bgw @2 is %r",cfg_bgw.format(bgw_as_number=bgw_as_number))
        for bgw_intf in [*bgw_uut.interfaces.keys()]:   
            if 'bgw_dci' in bgw_uut.interfaces[bgw_intf].alias:
                bgw_link_name1 = bgw_uut.interfaces[bgw_intf].alias
                for dci_uut in dci_uut_list:
                    cfg_dci = \
                    """
                    ip prefix-list redistribute-direct-underlay seq 5 permit 0.0.0.0/0 le 32 
                    route-map redistribute-direct-underlay permit 10
                    match ip address prefix-list redistribute-direct-underlay 

                    router bgp {dci_as_number}
                    log-neighbor-changes
                    address-family ipv4 unicast
                    redistribute direct route-map redistribute-direct-underlay
                    maximum-paths 8
                    neighbor {bgw_rid} 
                    remote-as {bgw_as_number}
                    update-source loopback100
                    ebgp-multihop 10
                    address-family l2vpn evpn
                    send-community
                    send-community extended
                    """
                    for dci_intf in [*dci_uut.interfaces.keys()]:            
                        if 'loop_dci' in dci_uut.interfaces[dci_intf].alias:
                            dci_rid1 = dci_uut.interfaces[dci_intf].ipv4
                            dci_rid =str(dci_rid1)[:-3]
                            cfg_dci +=  'router-id {dci_rid}\n'.format(dci_rid=dci_rid)  
                            cfg_bgw +=  'neighbor {dci_rid}\n'.format(dci_rid=dci_rid) 
                            cfg_bgw +=  'remote-as {dci_as_number}\n'.format(dci_as_number=dci_as_number)
                            cfg_bgw +=  'update-source loopback100\n'
                            cfg_bgw +=  'ebgp-multihop 10\n'
                            cfg_bgw +=  'peer-type fabric-external\n'
                            cfg_bgw +=  'address-family l2vpn evpn\n'
                            cfg_bgw +=  'send-community\n'
                            cfg_bgw +=  'send-community extended\n'
                            cfg_bgw +=  'rewrite-evpn-rt-asn\n' 
                        elif 'bgw_dci' in dci_uut.interfaces[dci_intf].alias:
                            dci_link_name1 = dci_uut.interfaces[dci_intf].alias
                            if dci_link_name1 == bgw_link_name1:
                                dci_ip_add1 = dci_uut.interfaces[dci_intf].ipv4
                                dci_ip_add=str(dci_ip_add1)[:-3]
                                dci_intf_name=dci_uut.interfaces[dci_intf].intf
                                bgw_ip_add1 = bgw_uut.interfaces[bgw_intf].ipv4
                                bgw_ip_add=str(bgw_ip_add1)[:-3]
                                bgw_intf_name=bgw_uut.interfaces[bgw_intf].intf
                                cfg_bgw +=  'neighbor {dci_ip_add}\n'.format(dci_ip_add=dci_ip_add)
                                cfg_bgw +=  'bfd\n'
                                cfg_bgw +=  'remote-as {dci_as_number}\n'.format(dci_as_number=dci_as_number)
                                cfg_bgw +=  'update-source {bgw_intf_name}\n'.format(bgw_intf_name=bgw_intf_name)
                                cfg_bgw +=  'address-family ipv4 unicast\n'
                                cfg_dci +=  'neighbor {bgw_ip_add}\n'.format(bgw_ip_add=bgw_ip_add)
                                cfg_dci +=  'bfd\n'
                                cfg_dci +=  'remote-as {bgw_as_number}\n'.format(bgw_as_number=bgw_as_number)
                                cfg_dci +=  'update-source {dci_intf_name}\n'.format(dci_intf_name=dci_intf_name)
                                cfg_dci +=  'address-family ipv4 unicast\n'
                
                    log.info("+------Config on dci_uut %r is : +",dci_uut)
                    log.info("cfg_dci %r",cfg_dci.format(bgw_rid=bgw_rid,dci_as_number=dci_as_number,bgw_as_number=bgw_as_number))
                    try:
                        dci_uut.configure(cfg_dci.format(bgw_rid=bgw_rid,dci_as_number=dci_as_number,bgw_as_number=bgw_as_number))
                    except:
                        log.error('iBGP config failed for uut %r',dci_uut)
                        return 0

        log.info("+------Config on bgw_uut %r is : +",bgw_uut)
        log.info("cfg_bgw %r",cfg_bgw.format(bgw_as_number=bgw_as_number,dci_as_number=dci_as_number))
        try:
            bgw_uut.configure(cfg_bgw.format(bgw_as_number=bgw_as_number,dci_as_number=dci_as_number))
        except:
            log.error('iBGP config failed for uut %r',bgw_uut)
            return 0

    log.info(banner("+++ dciEbgpv4Bringup END +++"))

def clearandconnect(uut):
        utils = Utils()
        if 'port' in uut.connections['a']:
            ts = str(uut.connections['a']['ip'])
            port=str(uut.connections['a']['port'])[-2:]
            log.info('UUT %r console clearing terminal server is %r and \
                port is %r',str(uut),ts,str(uut.connections['a']['port']))
            u = Utils()
            u.clear_line(ts, port, 'lab', 'lab')

        log.info('connect to %s' % uut.alias)
        try:
            uut.connect()
        except:
            return 1
        if not hasattr(uut, 'execute'):
            return 1
        if uut.execute != uut.connectionmgr.default.execute:
            return 1


def protocolStatusCheck(uut,protocol_list):
    log.info(banner("Starting protocolStatusCheck"))
    for proto in protocol_list:
        if 'v4bgp' in proto:
            if 'Idle' in uut.execute("show bgp ipv4 unicast summary"):
                log.info("Idle peer Seen")
                return 0
            elif 'Active' in uut.execute("show bgp ipv4 unicast summary"):
                log.info("Active peer Seen")
                return 0

            log.info("checking show bgp ipv4 unicast summary | json-prett @ uut %r",uut)
            cmd = uut.execute("show bgp ipv4 unicast summary | json-prett")
            if not "state" in str(cmd):
                log.info('No BGP neighbor found,Test failed for uut/neighbor %r',uut)
                return 0
            else:
                test1=json.loads(cmd)
                test11 = test1["TABLE_vrf"]["ROW_vrf"]
                if 'list' in str(type(test11)):
                    log.info("++++++Neig List is LIST for UUT %r+++",uut)

                    neig_list= test11[0]["TABLE_af"]["ROW_af"][0]["TABLE_saf"][ "ROW_saf"][0]["TABLE_neighbor"]["ROW_neighbor"]
                    neig_count =  str(neig_list).count('neighborid')
                    if neig_count == 1:
                        log.info("++++++Neig Count is 1 for UUT %r+++",uut)
                        if not 'Established' in (neig_list)[0]['state']:
                            log.info('BGP neighbor check failed for uut/neighbor %r',uut)
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:
                        log.info("++++++neig_count > 1 for UUT %r+++",uut)
                        for i in range(0,neig_count-1):
                            if not 'Established' in (neig_list)[i]['state']:
                                log.info('BGP neighbor check failed for uut/neighbor %r',uut)
                                return 0
                            else:
                                return 1

                else:
                    log.info("++++++neig_details NOT A LIST for UUT %r+++",uut)
                    neig_list= test1["TABLE_vrf"]["ROW_vrf"]["TABLE_af"]["ROW_af"]["TABLE_saf"][ "ROW_saf"]["TABLE_neighbor"]["ROW_neighbor"]
                    neig_count =  str(neig_list).count('neighborid')
                    if neig_count == 1:
                        log.info("++++++neig_details NOT A LIST c=1 for UUT %r+++",uut)
                        if not 'Established' in (neig_list)['state']:
                            log.info('BGP neighbor check failed for uut/neighbor %r',uut)
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:
                        log.info("++++++neig_details NOT A LIST c>1 for UUT %r+++",uut)
                        for i in range(0,neig_count-1):
                            if not 'Established' in (neig_list)[i]['state']:
                                log.info('BGP neighbor check failed for uut/neighbor %r',uut)
                                return 0
                            else:
                                return 1

            log.info('BGP neighbor check passed for uut -------------- :')



def multiSiteEnable(uut,vni,scale):
    cfg =\
    """
    interface {intf}
    no switchport
    ip address {ip_add}
    no shutdown
    mtu 9216
    """
    bgw_intf_list =[]
    spine_intf_list =[]


    for intf in [*uut.interfaces.keys()]:   
        if 'bgw_dci' in uut.interfaces[intf].alias:
            intf = uut.interfaces[intf].intf
            bgw_intf_list.append(intf)
        elif 'leaf_spine' in uut.interfaces[intf].alias:
            intf = uut.interfaces[intf].intf
            spine_intf_list.append(intf)    
    cfg = \
    """
    """ 
    op = uut.execute('show ip bgp su | incl identifier')
    op = op.splitlines()
    for line in op:
        if line:
            if 'identifier' in line:
                as_number = line.split()[-1]
                cfg +=  ' evpn multisite border-gateway {as_number}\n'.format(as_number=as_number)

    for intf in bgw_intf_list:
        cfg += 'interface {intf}\n'.format(intf=intf)
        cfg +=  'evpn multisite dci-tracking \n'
    for intf in spine_intf_list:
        cfg += 'interface {intf}\n'.format(intf=intf)
        cfg +=  'evpn multisite fabric-tracking\n'
 
    cfg +=  ' interface nve1\n'
    cfg +=  ' multisite border-gateway interface loopback100\n'    
    for vni in range(vni,vni+scale):
        vni = str(vni)
        cfg +=  ' member vni {vni}\n'.format(vni=vni)
        cfg +=  'multisite ingress-replication\n'

    log.info(banner("CFG is"))
    log.info("cfg is %r for UUT %r ",cfg,uut)    
    try:
        uut.configure(cfg)        
    except:
        log.error('multiSiteEnable failed for uut %r',uut)
        return 0

def multiSiteEnabletrm(uut,vni,scale):
    cfg =\
    """
    interface {intf}
    no switchport
    ip address {ip_add}
    no shutdown
    mtu 9216
    """
    bgw_intf_list =[]
    spine_intf_list =[]


    for intf in [*uut.interfaces.keys()]:   
        if 'bgw_dci' in uut.interfaces[intf].alias:
            intf = uut.interfaces[intf].intf
            bgw_intf_list.append(intf)
        elif 'leaf_spine' in uut.interfaces[intf].alias:
            intf = uut.interfaces[intf].intf
            spine_intf_list.append(intf)    
    cfg = \
    """
    """ 
    op = uut.execute('show ip bgp su | incl identifier')
    op = op.splitlines()
    for line in op:
        if line:
            if 'identifier' in line:
                as_number = line.split()[-1]
                cfg +=  ' evpn multisite border-gateway {as_number}\n'.format(as_number=as_number)

    for intf in bgw_intf_list:
        cfg += 'interface {intf}\n'.format(intf=intf)
        cfg +=  'evpn multisite dci-tracking \n'
    for intf in spine_intf_list:
        cfg += 'interface {intf}\n'.format(intf=intf)
        cfg +=  'evpn multisite fabric-tracking\n'
 
    cfg +=  ' interface nve1\n'
    cfg +=  ' multisite border-gateway interface loopback100\n'    
    for vni in range(vni,vni+scale):
        vni = str(vni)
        cfg +=  ' member vni {vni}\n'.format(vni=vni)
        cfg +=  'multisite ingress-replication\n'

    log.info(banner("CFG is"))
    log.info("cfg is %r for UUT %r ",cfg,uut)    
    try:
        uut.configure(cfg)        
    except:
        log.error('multiSiteEnabletrm failed for uut %r',uut)
        return 0


def ConfigureL3PortvxlanMultisite(uut):
    log.info(banner('ConfigureL3PortvxlanMultisite'))
    log.info('uut is %r', uut)
    log.info('+-------------START--------------------+')

    eth_intf_list = []
    for intf in uut.interfaces.keys():
        if 'Eth' in uut.interfaces[intf].intf:
            intf=uut.interfaces[intf].intf
            eth_intf_list.append(intf)

    cfg = \
    """
    interface {intf}
    no switchport
    """
    for intf in eth_intf_list:
        log.info("eth_intf_list intf  %r  on leaf device  %r to L3",intf,uut)
        uut.configure(cfg.format(intf=intf),timeout=30)
   
    countdown(1)   

    l3_bgw_intf_list = []
    l3_unnumbered_intf_list = []
    for intf in uut.interfaces.keys():
        if 'Eth' in uut.interfaces[intf].intf:
            if 'unnumbered' in uut.interfaces[intf].alias:
                intf=uut.interfaces[intf].intf
                log.info("leaf_spine intf is %r  on leaf device  %r",intf,uut)
                l3_unnumbered_intf_list.append(intf)

    for intf in l3_unnumbered_intf_list:
        log.info('uut is %r, intf is %r', uut,intf)
        eth = Interface(name=intf); eth.device = uut;eth.description = 'leaf_spine';eth.switchport_enable = False;\
        eth.shutdown = False;eth.mtu = 9216;eth.medium = 'p2p';eth.unnumbered_intf_ref = 'loopback1'
            
        log.info("Configuring interface %r in device %r",intf,uut)
        try:         
            configuration = eth.build_config()
        except:
            log.error("Failed interface %r configuration \
            on device %r ",intf,uut )
            return 0
    log.info('+-------------END l3_unnumbered_intf_list-------------+')

    for intf in [*uut.interfaces.keys()]:
        if 'dci' in intf:
            log.info("bgw intf is %r  on bgw/dci device  %r",intf,uut)            
            ip_add1 = uut.interfaces[intf].ipv4
            intf_name=uut.interfaces[intf].intf
            log.info("bgw intf_name is %r  on bgw/dci device  %r",intf_name,uut)
            eth = Interface(name=intf_name); eth.device = uut;eth.description = 'bgw_dci';eth.switchport_enable = False;\
            eth.shutdown = False;eth.mtu = 9216; eth.ipv4 = ip_add1
            
            log.info("Configuring intf_name l3_bgw_intf_list interface %r in device %r",intf_name,uut)
            try:
                configuration = eth.build_config()
            except:
                log.error("Failed interface intf_name %r configuration \
                on device %r ",intf_name,uut )
                return 0

    log.info(banner('END ConfigureL3PortvxlanMultisite'))
    log.info('uut is %r', uut)
    log.info('+-------------END------------------+')



def ConfigureLoopback(uut):
    for intf in uut.interfaces.keys():
        if 'loopback' in intf:
            intf=uut.interfaces[intf].intf
            log.info("loopback intf is %r  on device  %r",intf,uut)
            if 'ipv4_sec' in dir(uut.interfaces[intf]):
                ipv4_add_sec = uut.interfaces[intf].ipv4_sec
                ipv4_add=uut.interfaces[intf].ipv4
                log.info('ipv4_add is %r ipv4_add_sec is %r on device %r',ipv4_add,ipv4_add_sec,uut)
 
            else:
                ipv4_add=uut.interfaces[intf].ipv4
                ipv4_add_sec = 'Nil'
                log.info('ipv4_add is %r on  device  %r ',ipv4_add,uut)

            try:
                log.info("configuring loop %r with ip %r and ip_secondary %r \
                on device %r ",intf,ipv4_add,ipv4_add_sec,uut )
                ConfigLoopback(uut,intf,ipv4_add,ipv4_add_sec)
            except:
                log.error("Failed loop %r with ip %r and ip_secondary %r \
                on device %r ",intf,ipv4_add,ipv4_add_sec,uut )
                return 0


def ConfigureLoopbackbgwVPC(uut1,uut2):
    intf=uut1.interfaces['loopback0'].intf
    log.info("loopback intf is %r  on device  %r",intf,uut1)
    ip_add = uut1.interfaces[intf].ipv4
    ip_add1=str(ip_add)[:-3]
    ip_add_sec = str(ip_address(ip_add1)+10)+"/32"
    cfg = \
    """
    interf loopback0
    ip add {ip_add_sec} second
    no shut
    """
    for uut in [uut1,uut2]: 
        try:
            log.info("configuringin uut %r", uut )
            uut.configure(cfg.format(ip_add_sec=ip_add_sec))
        except:
            log.info("configuringin uut %r", uut )
            return 0
 

def removeLoopbackbgwVPC(uut1,uut2):
    intf=uut1.interfaces['loopback0'].intf
    log.info("loopback intf is %r  on device  %r",intf,uut1)
    ip_add = uut1.interfaces[intf].ipv4
    ip_add1=str(ip_add)[:-3]
    ip_add_sec = str(ip_address(ip_add1)+10)+"/32"
    cfg = \
    """
    interf loopback0
    no ip add {ip_add_sec} second
    no shut
    """
    for uut in [uut1,uut2]: 
        try:
            log.info("configuringin uut %r", uut )
            uut.configure(cfg.format(ip_add_sec=ip_add_sec))
        except:
            log.info("configuringin uut %r", uut )
            return 0


def vxlanConfigure(uut,l2_scale,l3_scale,mode,as_num):
    vtep_vxlan_obj1=LeafObject2222(uut,1001,101001,l2_scale,101,\
    90101,4,'5.0.0.1','5::1','225.5.0.1',as_num,mode,l3_scale)
    vtep_vxlan_obj1.vxlan_conf()
 
def vxlanConfigureAuto(uut,l2_scale,l3_scale,mcast_group_scale,mode,as_num):
    vtep_vxlan_obj1=vxlanObject(uut,1001,101001,l2_scale,101,\
    90101,mcast_group_scale,'5.0.0.1','5::1','225.5.0.1',as_num,mode,l3_scale)
    vtep_vxlan_obj1.vxlan_conf()
 

def vxlanConfigureAuto222(uut,l2_scale,l3_scale,mcast_group_scale,mode):
    op = uut.execute("show run bgp | incl 'router bgp'")
    op = op.splitlines()
    for line in op:
        if line:
            if 'bgp' in line:
                as_num = line.split()[-1]

    vtep_vxlan_obj1=vxlanObject(uut,1001,101001,l2_scale,101,\
    90101,mcast_group_scale,'5.0.0.1','5::1','225.5.0.1',as_num,mode,l3_scale)
    vtep_vxlan_obj1.vxlan_conf()




def accessPortConfigure(uut,vlan_range):
    log.info(banner("Configuring Ports to TGN"))
    for intf in [*uut.interfaces.keys()]:
        if 'tgn' in uut.interfaces[intf].alias:
            intf=uut.interfaces[intf].intf
            try:
                AccesPortconfigs(uut,intf,vlan_range)
            except:
                log.error('AccesPortconfigs failed for port %r @ uut %r',intf,uut)
                return 0
     
def swPoConfigure(uut,vlan_range):
    log.info(banner('Starting swPoConfigure'))
    log.info('uut inn swPoConfigure is %r',uut)
    sw_po_mem_list_101 = []
    sw_po_mem_list_122 = []
    sw_po_mem_list_133 = []
    sw_po_mem_list_111 = []
    sw_po_mem_list = []
    
    for intf in [*uut.interfaces.keys()]:
        if 'leaf_po_101' in uut.interfaces[intf].alias:
            intf=uut.interfaces[intf].intf
            sw_po_mem_list_101.append(intf)
        elif 'leaf_po_122' in uut.interfaces[intf].alias:
            intf=uut.interfaces[intf].intf
            sw_po_mem_list_122.append(intf)
        elif 'leaf_po_133' in uut.interfaces[intf].alias:
            intf=uut.interfaces[intf].intf
            sw_po_mem_list_133.append(intf)
        elif 'leaf_po_111' in uut.interfaces[intf].alias:
            intf=uut.interfaces[intf].intf
            sw_po_mem_list_111.append(intf)
        elif 'vtep' in uut.interfaces[intf].alias:
            intf=uut.interfaces[intf].intf
            sw_po_mem_list.append(intf)
        elif 'leaf' in uut.interfaces[intf].alias:
            intf=uut.interfaces[intf].intf
            sw_po_mem_list.append(intf)


    if 'Eth' in str(sw_po_mem_list_101):
        if not SwPortChannelconfigsfull(uut,'101',sw_po_mem_list_101,vlan_range):
            log.info('SwPortChannelconfigsfull failed @ %r')
            return 0

    if 'Eth' in str(sw_po_mem_list_122):
        if not SwPortChannelconfigsfull(uut,'122',sw_po_mem_list_122,'none'):
            log.info('SwPortChannelconfigsfull failed @ %r')
            return 0
    if 'Eth' in str(sw_po_mem_list_133):
        if not SwPortChannelconfigsfull(uut,'133',sw_po_mem_list_133,'none'):
            log.info('SwPortChannelconfigsfull failed @ %r')
            return 0
    if 'Eth' in str(sw_po_mem_list_111):
        if not SwPortChannelconfigsfull(uut,'111',sw_po_mem_list_111,'none'):
            log.info('SwPortChannelconfigsfull failed @ %r')
            return 0
            
    if 'Eth' in str(sw_po_mem_list):
        if not SwPortChannelconfigsfull(uut,'101',sw_po_mem_list,vlan_range):
            log.info('SwPortChannelconfigsfull failed @ %r')
            return 0

    log.info(banner('END swPoConfigure'))

def SwPortChannelconfigsfull(uut,po_number,port_list,vlan_range):
    log.info(banner('Starting SwPortChannelconfigsfull'))
    log.info('UUT is %r',uut)
    cfg = """\
            default interface {intf}
            interface {intf}
            channel-group {po_number} force mode active
            no shut
            """
    for intf in port_list:
        try:
            uut.configure(cfg.format(intf=intf,po_number=po_number),timeout=120)
        except:
            log.info("Switch TGN Port Configuration Failed")
            return 0

    if not 'none' in vlan_range:
        cmd = """\
        default interface Po{po_number}
        vlan {vlan_range}
        interface po {po_number}
        switchport
        shut
        switchport mode trunk
        switchport trunk allowed vlan {vlan_range}
        spanning-tree bpdufilter enable
        spanning-tree port type edge trunk
        sleep 1
        no shut
        """
        try:
            uut.configure(cmd.format(vlan_range=vlan_range,po_number=po_number),timeout=120)
        except:
            log.info("Switch TGN Port Configuration Failed")

    else:
        cmd = """\
        default interface Po{po_number}
        interface po {po_number}
        switchport
        shut
        switchport mode trunk
        switchport trunk allowed vlan none
        spanning-tree bpdufilter enable
        spanning-tree port type edge trunk
        sleep 1
        no shut
        """
        try:
            uut.configure(cmd.format(po_number=po_number),timeout=120)
        except:
            log.info("Switch TGN Port Configuration Failed")

    log.info(banner('END SwPortChannelconfigsfull'))
    return 1


def swBgwPoConfigure(uut,po_number,vlan_range):
    log.info(banner('swBgwPoConfigure'))
    sw_po_intf_list = []
    for intf in [*uut.interfaces.keys()]:
        log.info('intf is %r @ uut %r',intf,uut)
        if 'bgw_vpc' in uut.interfaces[intf].alias:
            intf=uut.interfaces[intf].intf
            log.info('bgw_vpc intf is %r @ uut %r',intf,uut)
            sw_po_intf_list.append(intf)
    
    log.info('sw_po_intf_list is %r',sw_po_intf_list)

    if not SwBgwPortChannelconfigs(uut,po_number,sw_po_intf_list,vlan_range):
        return 0

 

def vlanRemoveAddPo(uut,po_number,vlan_range):
    cmd = """\
    interface po {po_number}
    switchport trunk allowed vlan {vlan_range}
    """
    try:
        uut.configure(cmd.format(vlan_range=vlan_range,po_number=po_number),timeout=120)
    except:
        log.info("Switch TGN Port Configuration Failed")




def SwBgwPortChannelconfigs(uut,po_number,port_list,vlan_range):
    log.info(banner('START SwBgwPortChannelconfigs'))

    cmd = """\
    vlan {vlan_range}
    interface po {po_number}
    switchport
    shut
    switchport mode trunk
    switchport trunk allowed vlan {vlan_range}
    spanning-tree bpdufilter enable
    spanning-tree port type edge trunk
    sleep 1
    no shut
    """

    log.info('cmd in SwBgwPortChannelconfigs is %r',cmd)
    for port in port_list:
        cmd += 'interface {port}\n'.format(port=port)
        cmd += 'channel-group {po_number} force mode active\n'.format(po_number=po_number) 

    log.info('cmd full in SwBgwPortChannelconfigs is %r',cmd)


    try:
        uut.configure(cmd.format(vlan_range=vlan_range,po_number=po_number),timeout=120)
    except:
        log.info("Switch TGN Port Configuration Failed")
    log.info(banner('END SwBgwPortChannelconfigs'))


 

def PimEnable(uut):
    pim_intf_list = []
    for intf in [*uut.interfaces.keys()]:
        if 'loopback' in intf:
            intf=uut.interfaces[intf].intf
            pim_intf_list.append(intf)
        elif 'leaf_spine' in uut.interfaces[intf].alias:
            intf=uut.interfaces[intf].intf
            pim_intf_list.append(intf)

    for intf in intf_list:
        cfg = \
        """       
        interf {intf}
        ip pim sparse-mode       
        """
        try:
            uut.configure(cfg.format(intf=intf),timeout = 120)
        except:
            log.error('ip pim sparse-mode  config failed for node  %r',uut)

def multisiteDcibgpEvpn(uut):

    loopback100 = uut.interfaces['loopback100'].intf
    loopback100_ip = uut.interfaces['loopback100'].ipv4  
    loopback1 = uut.interfaces['loopback1'].intf
    loopback1_ip = uut.interfaces['loopback1'].ipv4  
    rid =str(loopback1_ip)[:-3]
    rid100 =str(loopback100_ip)[:-3]
    log.info("----multisiteDcibgpEvpn-----")

    cfg = \
    """
    route-map NHS permit 10
    set ip next-hop unchanged

    router bgp 99
    router-id {rid}
    log-neighbor-changes
 
    address-family l2vpn evpn
    nexthop route-map NHS
    retain route-target all

    neighbor 1.1.1.11
    remote-as 65001
    update-source loopback1
    ebgp-multihop 10
    address-family l2vpn evpn
    send-community
    send-community extended
    route-map NHS out
    rewrite-evpn-rt-asn
    neighbor 2.1.1.11
    remote-as 65002
    update-source loopback1
    ebgp-multihop 10
    address-family l2vpn evpn
      send-community
      send-community extended
      route-map NHS out
      rewrite-evpn-rt-asn
    neighbor 2.1.1.12
    remote-as 65002
    update-source loopback1
    ebgp-multihop 10
    address-family l2vpn evpn
      send-community
      send-community extended
      route-map NHS out
      rewrite-evpn-rt-asn
    neighbor 3.1.1.11
    remote-as 65003
    update-source loopback1
    ebgp-multihop 10
    address-family l2vpn evpn
      send-community
      send-community extended
      route-map NHS out
      rewrite-evpn-rt-asn
    neighbor 3.1.1.12
    remote-as 65003
    update-source loopback1
    ebgp-multihop 10
    address-family l2vpn evpn
      send-community
      send-community extended
      route-map NHS out
      rewrite-evpn-rt-asn
    """
    uut.configure(cfg.format(rid=rid))


def multisiteDcibgpEvpntrmall4(uut):

    loopback100 = uut.interfaces['loopback100'].intf
    loopback100_ip = uut.interfaces['loopback100'].ipv4  
    loopback1 = uut.interfaces['loopback1'].intf
    loopback1_ip = uut.interfaces['loopback1'].ipv4  
    rid =str(loopback1_ip)[:-3]
    rid100 =str(loopback100_ip)[:-3]
    log.info("----multisiteDcibgpEvpntrmall-----")

    cfg = \
    """
    route-map NHS permit 10
    set ip next-hop unchanged

    router bgp 99
    router-id {rid}
    log-neighbor-changes
 
    address-family l2vpn evpn
    nexthop route-map NHS
    retain route-target all

    neighbor 1.1.1.11
    remote-as 65001
    update-source loopback1
    ebgp-multihop 10
    address-family l2vpn evpn
    send-community
    send-community extended
    route-map NHS out
    rewrite-evpn-rt-asn

    neighbor 1.1.1.12
    remote-as 65001
    update-source loopback1
    ebgp-multihop 10
    address-family l2vpn evpn
    send-community
    send-community extended
    route-map NHS out
    rewrite-evpn-rt-asn

    neighbor 2.1.1.11
    remote-as 65002
    update-source loopback1
    ebgp-multihop 10
    address-family l2vpn evpn
      send-community
      send-community extended
      route-map NHS out
      rewrite-evpn-rt-asn

    neighbor 3.1.1.11
    remote-as 65003
    update-source loopback1
    ebgp-multihop 10
    address-family l2vpn evpn
      send-community
      send-community extended
      route-map NHS out
      rewrite-evpn-rt-asn

    neighbor 4.1.1.11
    remote-as 65004
    update-source loopback1
    ebgp-multihop 10
    address-family l2vpn evpn
      send-community
      send-community extended
      route-map NHS out
      rewrite-evpn-rt-asn
    """
    uut.configure(cfg.format(rid=rid))


def multisiteDcibgpEvpntrmall(uut):

    loopback100 = uut.interfaces['loopback100'].intf
    loopback100_ip = uut.interfaces['loopback100'].ipv4  
    loopback1 = uut.interfaces['loopback1'].intf
    loopback1_ip = uut.interfaces['loopback1'].ipv4  
    rid =str(loopback1_ip)[:-3]
    rid100 =str(loopback100_ip)[:-3]
    log.info("----multisiteDcibgpEvpntrmall-----")

    cfg = \
    """
    route-map NHS permit 10
    set ip next-hop unchanged

    router bgp 99
    router-id {rid}
    log-neighbor-changes
 
    address-family l2vpn evpn
    nexthop route-map NHS
    retain route-target all

    neighbor 1.1.1.11
    remote-as 65001
    update-source loopback1
    ebgp-multihop 10
    address-family l2vpn evpn
    send-community
    send-community extended
    route-map NHS out
    rewrite-evpn-rt-asn

    neighbor 1.1.1.12
    remote-as 65001
    update-source loopback1
    ebgp-multihop 10
    address-family l2vpn evpn
    send-community
    send-community extended
    route-map NHS out
    rewrite-evpn-rt-asn

    neighbor 2.1.1.11
    remote-as 65002
    update-source loopback1
    ebgp-multihop 10
    address-family l2vpn evpn
      send-community
      send-community extended
      route-map NHS out
      rewrite-evpn-rt-asn

    neighbor 2.1.1.12
    remote-as 65002
    update-source loopback1
    ebgp-multihop 10
    address-family l2vpn evpn
      send-community
      send-community extended
      route-map NHS out
      rewrite-evpn-rt-asn

    neighbor 3.1.1.11
    remote-as 65003
    update-source loopback1
    ebgp-multihop 10
    address-family l2vpn evpn
      send-community
      send-community extended
      route-map NHS out
      rewrite-evpn-rt-asn

    """
    uut.configure(cfg.format(rid=rid))

def multisitebgwbgpEvpn(uut,as_num):

    loopback100 = uut.interfaces['loopback100'].intf
    loopback100_ip = uut.interfaces['loopback100'].ipv4  
    loopback1 = uut.interfaces['loopback1'].intf
    loopback1_ip = uut.interfaces['loopback1'].ipv4  
    rid =str(loopback1_ip)[:-3]
    rid100 =str(loopback100_ip)[:-3]

    log.info("----multisitebgwbgpEvpn-----")

    cfg_dci1 = \
    """
    router bgp {as_num}
    router-id {rid}
    graceful-restart restart-time 200
    log-neighbor-changes
 
 
    address-family l2vpn evpn
    maximum-paths ibgp 64
 
    neighbor 10.1.1.1
    remote-as 99
    update-source loopback1
    ebgp-multihop 10
    peer-type fabric-external
    address-family l2vpn evpn
      send-community
      send-community extended
      rewrite-evpn-rt-asn

    neighbor 10.1.1.2
    remote-as 99
    update-source loopback1
    ebgp-multihop 10
    peer-type fabric-external
    address-family l2vpn evpn
      send-community
      send-community extended
      rewrite-evpn-rt-asn
    """
    uut.configure(cfg_dci1.format(as_num=as_num,rid=rid))  
 

def multisitebgwbgpEvpn44(uut):

    op = uut.execute("show run bgp | incl 'router bgp'")
    op = op.splitlines()
    for line in op:
        if line:
            if 'bgp' in line:
                as_num = line.split()[-1]

    loopback100 = uut.interfaces['loopback100'].intf
    loopback100_ip = uut.interfaces['loopback100'].ipv4  
    loopback1 = uut.interfaces['loopback1'].intf
    loopback1_ip = uut.interfaces['loopback1'].ipv4  
    rid =str(loopback1_ip)[:-3]
    rid100 =str(loopback100_ip)[:-3]

    log.info("----multisitebgwbgpEvpn-----")

    cfg_dci1 = \
    """
    router bgp {as_num}
    router-id {rid}
    graceful-restart restart-time 200
    log-neighbor-changes
 
 
    address-family l2vpn evpn
    maximum-paths ibgp 64
 
    neighbor 10.1.1.1
    remote-as 99
    update-source loopback1
    ebgp-multihop 10
    peer-type fabric-external
    address-family l2vpn evpn
      send-community
      send-community extended
      rewrite-evpn-rt-asn

    neighbor 10.1.1.2
    remote-as 99
    update-source loopback1
    ebgp-multihop 10
    peer-type fabric-external
    address-family l2vpn evpn
      send-community
      send-community extended
      rewrite-evpn-rt-asn
    """
    uut.configure(cfg_dci1.format(as_num=as_num,rid=rid))  
 


def bgwdciebgpv4(uut):
    log.info(banner("+++ dciEbgpv4Bringup START +++")) 


    loopback100 = uut.interfaces['loopback100'].intf
    loopback100_ip = uut.interfaces['loopback100'].ipv4  
    loopback1 = uut.interfaces['loopback1'].intf
    loopback1_ip = uut.interfaces['loopback1'].ipv4  
    rid =str(loopback1_ip)[:-3]
    rid100 =str(loopback100_ip)[:-3]


    log.info("loopback100 @ 11111 is %r",loopback100)
    log.info("loopback100_ip @ 11111 is %r",loopback100_ip)
    log.info("loopback1 @ 11111 is %r",loopback1)
    log.info("loopback1_ip @ 11111 is %r",loopback1_ip)

    cfg = \
    """
    ip prefix-list redistribute-direct-underlay seq 5 permit 0.0.0.0/0 le 32 
    route-map redistribute-direct-underlay permit 10
    match ip address prefix-list redistribute-direct-underlay 
    router bgp {as_num}
    router-id {rid}
    log-neighbor-changes
    address-family ipv4 unicast
    redistribute direct route-map redistribute-direct-underlay
    address-family ipv4 unicast
    #network {rid} mask 255.255.255.255
    network {rid100} mask 255.255.255.255  
    """
    
    for intf in [*uut.interfaces.keys()]:   
        if 'bgw_dci' in uut.interfaces[intf].alias:
            intf_name=uut.interfaces[intf].intf
            ip_add1 = uut.interfaces[intf].ipv4
            ip_add=str(ip_add1)[:-3]
            ip_add = str(ip_address(ip_add)+1)
            if '111' in ip_add:
                as_num = '65001'
            elif '112' in ip_add:
                as_num = '65002'
            elif '113' in ip_add:
                as_num = '65003'
            elif '114' in ip_add:
                as_num = '65004'
            cfg +=  'neighbor {ip_add}\n'.format(ip_add=ip_add)
            cfg +=  'bfd\n'
            cfg +=  'remote-as 99\n'
            cfg +=  'update-source {intf_name}\n'.format(intf_name=intf_name)
            cfg +=  'address-family ipv4 unicast\n'
 
    try:
        uut.configure(cfg.format(as_num=as_num,rid=rid,rid100=rid100))
    except:
        log.error('iBGP config failed for uut %r',uut)
        return 0

    log.info(banner("+++ dciEbgpv4Bringup END +++"))



def dcibgwebgpv4(uut):
    log.info(banner("+++ dciEbgpv4Bringup START +++")) 
    loopback100 = uut.interfaces['loopback100'].intf
    loopback100_ip = uut.interfaces['loopback100'].ipv4  
    loopback1 = uut.interfaces['loopback1'].intf
    loopback1_ip = uut.interfaces['loopback1'].ipv4  
    rid =str(loopback1_ip)[:-3]
    rid100 =str(loopback100_ip)[:-3]

    log.info("loopback100 @ 2222 is %r",loopback100)
    log.info("loopback100_ip @ 2222 is %r",loopback100_ip)
    log.info("loopback1 @ 2222 is %r",loopback1)
    log.info("loopback1_ip @ 2222 is %r",loopback1_ip)

    cfg = \
    """
    ip prefix-list redistribute-direct-underlay seq 5 permit 0.0.0.0/0 le 32 
    route-map redistribute-direct-underlay permit 10
    match ip address prefix-list redistribute-direct-underlay 

    router bgp 99
    router-id {rid}
    log-neighbor-changes
    address-family ipv4 unicast
    redistribute direct route-map redistribute-direct-underlay
    address-family ipv4 unicast
    network {rid} mask 255.255.255.255
    network {rid100} mask 255.255.255.255    
    """  
    for intf in [*uut.interfaces.keys()]:   
        if 'bgw_dci' in uut.interfaces[intf].alias:
            intf_name=uut.interfaces[intf].intf
            ip_add1 = uut.interfaces[intf].ipv4
            ip_add=str(ip_add1)[:-3]
            ip_add = str(ip_address(ip_add)-1)
            if '111' in ip_add:
                remote_as = '65001'
            elif '112' in ip_add:
                remote_as = '65002'
            elif '113' in ip_add:
                remote_as = '65003'
            elif '114' in ip_add:
                remote_as = '65004'
            cfg +=  'neighbor {ip_add}\n'.format(ip_add=ip_add)
            cfg +=  'bfd\n'
            cfg +=  'remote-as {remote_as}\n'.format(remote_as=remote_as) 
            cfg +=  'update-source {intf_name}\n'.format(intf_name=intf_name)
            cfg +=  'address-family ipv4 unicast\n'
 
    try:
        uut.configure(cfg.format(rid=rid,rid100=rid100))
    except:
        log.error('iBGP config failed for uut %r',uut)
        return 0

    log.info(banner("+++ dciEbgpv4Bringup END +++")) 



def cs_check_vxlan(uut_list):
    log.info(banner("S T A R T I N G ^^^^^^ csvxlanall ^^^^^^ "))
    result = []
    for uut in uut_list:
        csl2module = uut.execute('show consistency-checker l2 module 1',timeout = 120)
        result.append(csl2module)

    if 'FAILED' in str(result):
        if not 'xconnect consistency checker FAILED' in str(result):
            log.info('csvxlanall failed ------------')
            log.info('result is %r ------------',result)
            return 0
    elif 'Exception' in str(result):
        if not 'not implemented' in str(result):
            log.info('csvxlanall failed Exception ------------')
            log.info('result is %r ------------',result)
            return 0

    elif 'Consistency-Checker: FAIL for ALL' in str(result):
        #if not 'not implemented' in str(result):
        log.info('csvxlanall failed Exception ------------')
        log.info('result is %r ------------',result)
        return 0

    elif 'Route inconsistent in' in str(result):
        #if not 'not implemented' in str(result):
        log.info('csvxlanall failed Exception ------------')
        log.info('result is %r ------------',result)
        return 0

    log.info(banner("ENG ^^^^^^ csvxlanall ^^^^^^ "))   
    return 1


def vxlan_cc_test(uut_list):
    log.info(banner("S T A R T I N G ^^^^^^ csvxlanall ^^^^^^ "))
    result = []
    for uut in uut_list:
        csl2module = uut.execute('show consistency-checker l2 module 1',timeout = 120)
        result.append(csl2module)
        if not 'NXOS: version 7.0' in uut.execute('show version'):
            csvxlanconfcheck = uut.execute('show consistency-checker vxlan config-check',timeout = 120)
            result.append(csvxlanconfcheck)
            csvxlanl2m = uut.execute('show consistency-checker vxlan l2 module 1',timeout = 120)
            result.append(csvxlanl2m)
            csvxlanl3vrfstartscan = uut.execute('show consistency-checker vxlan l3 vrf all start-scan',timeout = 120)
            result.append(csvxlanl3vrfstartscan)
            csvxlanl3vrfrepo = uut.execute('show consistency-checker vxlan l3 vrf all report ',timeout = 120)
            result.append(csvxlanl3vrfrepo)
            if not 'FX' in uut.execute("show mod | incl active"):
                csvxlanmhmac = uut.execute('show consistency-checker vxlan mh mac-addresses',timeout = 120) 
                result.append(csvxlanmhmac)
            csvxlanvlan = uut.execute('show consistency-checker vxlan vlan 1001',timeout = 120)
            result.append(csvxlanvlan)
            csvxlanpv = uut.execute('show consistency-checker vxlan pv ',timeout = 120)
            result.append(csvxlanpv)
            csvxlanxc = uut.execute('show consistency-checker vxlan xconnect ',timeout = 120)
            result.append(csvxlanxc)   

    if 'FAILED' in str(result):
        if not ' consistency checker FAILED' in str(result):
            log.info('csvxlanall failed ------------')
            log.info('result is %r ------------',result)
            return 0
    elif 'Exception' in str(result):
        if not 'not implemented' in str(result):
            log.info('csvxlanall failed Exception ------------')
            log.info('result is %r ------------',result)
            return 0

    elif 'Consistency-Checker: FAIL for ALL' in str(result):
        #if not 'not implemented' in str(result):
        log.info('csvxlanall failed Exception ------------')
        log.info('result is %r ------------',result)
        return 0

    elif 'Route inconsistent in' in str(result):
        #if not 'not implemented' in str(result):
        log.info('csvxlanall failed Exception ------------')
        log.info('result is %r ------------',result)
        return 0

    log.info(banner("ENG ^^^^^^ csvxlanall ^^^^^^ "))   
    return 1



def SviConfigsallbgw(uut1,uut2,prefix):

    ip1 = prefix+".1/24"
    ip2 = prefix+".2/24"

    cfg1 = \
    """
    feature interface-vlan
    vlan 10
    no interface vlan10
    interface vlan10
    mtu 9216
    ip pim sparse-mode
    ip address {ip1}
    ip router ospf UNDERLAY area 0
    isis metric 100 level-1
    isis circuit-type level-1
    isis authentication-type md5 level-1
    isis authentication key-chain KEYCHAIN-ISIS level-1
    ip router isis UNDERLAY
    no shut
    vlan configuration 10
    ip igmp snooping



    system nve infra-vlans 10
 
    """
    cfg2 = \
    """
    feature interface-vlan
    vlan 10
    no interface vlan10
    interface vlan10
    mtu 9216
    ip pim sparse-mode
    ip address {ip2}
    isis metric 100 level-1
    isis circuit-type level-1
    isis authentication-type md5 level-1
    isis authentication key-chain KEYCHAIN-ISIS level-1
    ip router isis UNDERLAY

    ip router ospf UNDERLAY area 0
    no shut
    vlan configuration 10
    ip igmp snooping

    system nve infra-vlans 10 
    """

    try:
        uut1.configure(cfg1.format(ip1=ip1),timeout=120)
    except:
        log.info("vTEP L3 SVI for VPC Configuration Failed @ uut %r",uut1)
        return 0

    try:
        uut2.configure(cfg2.format(ip2=ip2))
    except:
        log.info("vTEP L3 SVI for VPC Configuration Failed @ uut %r",uut2)
        return 0




def portShutNoshut(uut,intf,action):
    log.info(banner("Start portShutNoshut"))
    cfg_shut =  \
    """
    interface {intf}
    shut
    """
    cfg_no_shut =  \
    """
    interface {intf}
    no shut
    """
    try:
        if 'down' in action:
            log.info('shuting intf %r on uut %r',intf,uut)
            uut.configure(cfg_shut.format(intf=intf))
        elif 'up' in action:
            log.info('unshut intf %r on uut %r',intf,uut)
            uut.configure(cfg_no_shut.format(intf=intf))
    except:
        log.info("portShutNoshut Failed @ uut %r",uut)
        return 0
    log.info(banner("END portShutNoshut"))



def nodeIsolate(uut):
    log.info(banner('S T A R T nodeIsolate'))
    cfg = \
    """
    interface {intf}
    shut
    """
    for uut in [uut]:
        for intf in uut.interfaces.keys():           
            if 'Eth' in uut.interfaces[intf].intf:
                intf=uut.interfaces[intf].intf
                log.info('shutting intf %r @ uut %r',intf,uut)
                try:
                    uut.configure(cfg.format(intf=intf))
                except:
                    log.info('intf %r shut @ uut %r failed',intf,uut)
                    return 0

            elif 'loopback' in uut.interfaces[intf].intf:
                intf=uut.interfaces[intf].intf
                log.info('shutting intf %r @ uut %r',intf,uut)
                try:
                    uut.configure(cfg.format(intf=intf))
                except:
                    log.info('intf %r shut @ uut %r failed',intf,uut)
                    return 0

    log.info(banner('E N D nodeIsolate'))
    return 1


def nodeNoIsolate(uut):
    log.info(banner('S T A R T nodeNoIsolate'))
    cfg = \
    """
    interface {intf}
    no shut
    """
    for uut in [uut]:
        for intf in uut.interfaces.keys():           
            if 'Eth' in uut.interfaces[intf].intf:
                intf=uut.interfaces[intf].intf
                log.info('UN shutting intf %r @ uut %r',intf,uut)
                try:
                    uut.configure(cfg.format(intf=intf))
                except:
                    log.info('intf %r NO shut @ uut %r failed')
                    return 0

            elif 'loopback' in uut.interfaces[intf].intf:
                intf=uut.interfaces[intf].intf
                log.info('UN shutting intf %r @ uut %r',intf,uut)
                try:
                    uut.configure(cfg.format(intf=intf))
                except:
                    log.info('intf %r NO shut @ uut %r failed')
                    return 0

    log.info(banner('E N D nodeNoIsolate'))
    return 1

 
class CLI_PortChannel(object):
    def __init__(self,device,po_num,vlan_range,po_type,member_list,ipv4_add):
        #CLI_PortChannel(sw3,vpc1_number,'100-110','trunk',sw3_po1_mem_list,'Nil')
        self.vlan_range=vlan_range
        self.device=device
        self.po_num=po_num
        self.po_type=po_type
        self.member_list=member_list
        self.ipv4_add=ipv4_add

        #log.info("Entering %r to configure port channel %r",self.device,self.po_num)

 
    def ConfigurePo(self):
        log.info("Entering %r to configure port channel %r",self.device,self.po_num)

        if 'layer3' in self.po_type:
            config_str = \
                """
                #no interface Port-Channel {po_num}
                interface Port-Channel {po_num}
                #port-channel mode active
                no switchport
                ip address {ipv4_add}
                mtu 9216
                no shut
                """
            try:
                self.device.configure(config_str.format(po_num=self.po_num,ipv4_add=self.ipv4_add),timeout=180)
            except:
                log.error('Port Channel Config Failed on UUT')
            
        elif 'trunk' in self.po_type:
            config_str = \
                """
                vlan {vlan_range}
                no interface Port-Channel {po_num}
                interface Port-Channel {po_num}
                #port-channel mode active
                switchport
                switchport mode trunk
                switchport trunk allowed vlan {vlan_range}
                no shut
                """
            try:
                self.device.configure(config_str.format(po_num=self.po_num,vlan_range=self.vlan_range),timeout=180)
            except:
                log.error('Port Channel Config Failed on UUT')

        elif 'access' in self.po_type:
            config_str = \
                """
                vlan {vlan_range}
                no interface Port-Channel {po_num}
                interface Port-Channel {po_num}
                #port-channel mode active
                switchport
                switchport mode access
                switchport access vlan {vlan_range}
                no shut
                """
            try:
                self.device.configure(config_str.format(po_num=self.po_num,vlan_range=self.vlan_range))
            except:
                log.error('Port Channel Config Failed on UUT')


        #def add_po_member(self):
        for intf in self.member_list:
            try:
                self.device.configure('''
                #default interface {intf}
                interface {intf}
                channel-group {po_num} force mode active
                no shut
                '''.format(intf=intf,po_num=self.po_num),timeout=120)        
            except:
                log.error('Port Channel member Config Failed on UUT')


    def remove_po_member(self):
        for intf in self.member_list:
            self.device.configure('''
            interface {intf}
            no channel-group {po_num} force mode active
            no shut
            '''.format(intf=intf,po_num=self.po_num),timeout=120) 
 


def macmoveOverPo(uut,po_number,action,vlan_range):
    log.info(banner('START macMoveoverPo'))

    cmdadd = """\
    interface po {po_number}
    no shut
    switchport trunk allowed vlan {vlan_range} 
    """

    cmdremove = """\
    interface po {po_number}
    no shut
    switchport trunk allowed vlan none
    """
    
    if 'add' in action:
        try:
            uut.configure(cmdadd.format(po_number=po_number,\
                vlan_range=vlan_range),timeout=120)
        except:
            log.info("macMoveoverPo Configuration add Failed")

    elif 'remove' in action:
        try:
            uut.configure(cmdremove.format(po_number=po_number),timeout=120)
        except:
            log.info("SmacMoveoverPo Configuration remove Failed")

    log.info(banner('END macMoveoverPo'))


 


def evpnType5routeAdd(uut,prefix,as_num,nh):
    log.info(banner('START macMoveoverPo'))
    cmd = \
        """
        vrf context vxlan-90101
        ip route {prefix} {nh}

        ip access-list TYPE5
        10 permit ip {prefix} any 
        20 permit ip any {prefix}
        route-map TYPE5 permit 10
        match ip address TYPE5 
        router bgp {as_num}
        vrf vxlan-90101
        address-family ipv4 unicast
        advertise l2vpn evpn
        redistribute static route-map TYPE5
        """
    try:
        uut.configure(cmd.format(prefix=prefix,nh=nh,as_num=as_num),timeout=120)
    except:
        log.info('evpnType5routeAdd failed for %r',uut)
        return 0

    return 1    



def vlanflapp(uut):
    cfg = \
    """
    vlan 1001-1032
    shut
    exit
    vlan 1001-1032
    no sh
    exit 
    """
    for i in range(1,10):
        try:
            uut.configure(cfg)
        except:
            log.info("vlanflapp Failed")
            return 0
    return 1  


def secodaryipremove(uut):
    log.info(banner("starting VxlanStReset"))
    cfg = \
    """
    interface loopback0
    no {ip_sec}
    """
    op = uut.execute('show run inter lo0 | incl secondary')
    for line in op.splitlines():
        if 'secondary' in line:
            ip_sec = line
            uut.configure(cfg.format(ip_sec=ip_sec))    
 

def underlayl3bringup(uut,linktype):
    log.info('start underlayl3bringup, node %r',uut)
    if 'l3po' in linktype:
        l3pospineleaf(uut)
    elif 'unnumbered' in linktype:
        ConfigureL3Portvxlan(uut)
    elif 'l3_single_po' in linktype:
        Singlel3pospineleaf(uut)
        
    log.info('end underlayl3bringup, node %r',uut)

def ConfigureL3Portvxlan(uut):
    log.info(banner('ConfigureL3Portvxlan'))
    log.info('uut is %r', uut)
    log.info('+-------------START--------------------+')

    l3_leaf_spine_intf_list = []
    for intf in uut.interfaces.keys():
        if 'Eth' in uut.interfaces[intf].intf:
            if 'leaf_spine' in uut.interfaces[intf].alias:
                intf=uut.interfaces[intf].intf
                log.info("leaf_spine intf is %r  on leaf device  %r",intf,uut)
                l3_leaf_spine_intf_list.append(intf)

    for intf in l3_leaf_spine_intf_list:
        log.info('uut is %r, intf is %r', uut,intf)
        cfg = \
        """
        interface {intf}
        no switchport
        """
        uut.configure(cfg.format(intf=intf))

    for intf in l3_leaf_spine_intf_list:
        log.info('uut is %r, intf is %r', uut,intf)
        eth = Interface(name=intf); eth.device = uut;eth.description = 'leaf_spine';eth.switchport_enable = False;\
        eth.shutdown = False;eth.medium = 'p2p';eth.unnumbered_intf_ref = 'loopback1'
            
        log.info("Configuring interface %r in device %r",intf,uut)
        try:
            configuration = eth.build_config()
        except:
            log.error("Failed interface %r configuration \
            on device %r ",intf,uut )
            return 0
    log.info('+-------------END l3_unnumbered_intf_list-------------+')
 
    log.info(banner('END ConfigureL3Portvxlan'))
    log.info('uut is %r', uut)
    log.info('+-------------END------------------+')

 
def l3pospineleaf(uut):       
    log.info("Configuring L3 Port Channels")
    po_member_list = []
    for intf in uut.interfaces.keys():
        if 'Eth' in uut.interfaces[intf].intf:
            if 'leaf_spine' in uut.interfaces[intf].alias:
                #intf  = uut.interfaces[intf].intf
                po_member_list.append(intf)

    log.info('l3 po mem list for uut %r is %r',str(uut),po_member_list)                                        
    for intf in uut.interfaces.keys():
        if 'l3_po' in uut.interfaces[intf].type:
            Po = uut.interfaces[intf].intf
            ipv4_add = uut.interfaces[intf].ipv4                   
            po_mem_list=[]
            for intf in po_member_list:
                member = uut.interfaces[intf].alias
                if member.strip("leaf_spine") == Po:
                    po_mem_list.append(uut.interfaces[intf].intf)                                  
            log.info('l3 po mem list for po %r uut %r is %r',Po,str(uut),po_mem_list)   
            uut_l3Po_obj = CLI_PortChannel(uut,Po,'Nil','layer3',po_mem_list,ipv4_add)
            uut_l3Po_obj.ConfigurePo()



def Singlel3pospineleaf(uut):       
    log.info("Configuring L3 Port Channels")
    po_member_list = []
    for intf in uut.interfaces.keys():
        if 'Eth' in uut.interfaces[intf].intf:
            if 'leaf_spine' in uut.interfaces[intf].alias:
                #intf  = uut.interfaces[intf].intf
                po_member_list.append(intf)

    log.info('l3 po mem list for uut %r is %r',str(uut),po_member_list)                                        
    for intf in uut.interfaces.keys():
        if 'l3_single_po' in uut.interfaces[intf].type:
            Po = uut.interfaces[intf].intf
            ipv4_add = uut.interfaces[intf].ipv4                   
            po_mem_list=[]
            for intf in po_member_list:
                log.info("Intf is ^^^^^^^ %r",intf)
                member = str(uut.interfaces[intf].link)
                log.info("member is ^^^^^^^ %r",member)
                if member.strip("Link leaf_spine_") == Po:
                    po_mem_list.append(uut.interfaces[intf].intf)                                  
            log.info('l3 po mem list for po %r uut %r is %r',Po,str(uut),po_mem_list)   
            uut_l3Po_obj = CLI_PortChannel(uut,Po,'Nil','layer3',po_mem_list,ipv4_add)
            uut_l3Po_obj.ConfigurePo()


def vxlanunderlayigp(uut,linktype):
    loop_intf_list = []
    l3_intf_list = []
    loopback1 = uut.interfaces['loopback1'].intf
    loopback1_ip = uut.interfaces['loopback1'].ipv4  
    rid =str(loopback1_ip)[:-3]
    for intf in [*uut.interfaces.keys()]:
        if 'loopback' in intf:
            intf=uut.interfaces[intf].intf
            loop_intf_list.append(intf)

    for intf in [*uut.interfaces.keys()]:
        if 'l3po' in linktype:
            if 'l3_po' in uut.interfaces[intf].type:
                intf='port-channel'+uut.interfaces[intf].intf
                l3_intf_list.append(intf)
      
        elif 'unnumbered' in linktype:    
            if 'Eth' in uut.interfaces[intf].type:
                if 'leaf_spine' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    l3_intf_list.append(intf)

    log.info("loop_intf_list is %r",loop_intf_list)       
    log.info("l3_intf_list is %r",l3_intf_list)
    try:
        OspfGlobalConfig(uut,rid,'UNDERLAY')
        OspfIntfConfig(uut,loop_intf_list,'UNDERLAY','loop')
        OspfIntfConfig(uut,l3_intf_list,'UNDERLAY','p2p')
    except:
        log.error('Ospf config failed for node %r',uut) 
        return 0


def vxlanunderlayigp10(uut,linktype,igp):
    loop_intf_list = []
    l3_intf_list = []
    loopback1 = uut.interfaces['loopback1'].intf
    loopback1_ip = uut.interfaces['loopback1'].ipv4  
    rid =str(loopback1_ip)[:-3]
    for intf in [*uut.interfaces.keys()]:
        if 'loopback' in intf:
            intf=uut.interfaces[intf].intf
            loop_intf_list.append(intf)

    for intf in [*uut.interfaces.keys()]:
        if 'l3po' in linktype:
            if 'l3_po' in uut.interfaces[intf].type:
                intf='port-channel'+uut.interfaces[intf].intf
                l3_intf_list.append(intf)

        elif 'l3_single_po' in linktype:
            if 'l3_single_po' in uut.interfaces[intf].type:
                intf='port-channel'+uut.interfaces[intf].intf
                l3_intf_list.append(intf)      
      
        elif 'unnumbered' in linktype:    
            if 'Eth' in uut.interfaces[intf].type:
                if 'leaf_spine' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    l3_intf_list.append(intf)

    log.info("loop_intf_list is %r",loop_intf_list)       
    log.info("l3_intf_list is %r",l3_intf_list)
    if 'ospf' in igp:
        try:
            OspfGlobalConfig(uut,rid,'UNDERLAY')
            OspfIntfConfig(uut,loop_intf_list,'UNDERLAY','loop')
            OspfIntfConfig(uut,l3_intf_list,'UNDERLAY','p2p')
        except:
            log.error('isis config failed for node %r',uut) 
            return 0

    elif 'isis' in igp:
        try:
            IsisGlobalConfig(uut)
            IsisIntfConfig(uut,loop_intf_list,'loop')
            IsisIntfConfig(uut,l3_intf_list,'p2p')
        except:
            log.error('isis config failed for node %r',uut) 
            return 0

def ConfigureIgpvxlanMultisite(uut,igp):
    loop_intf_list = []
    l3_intf_list = []
    loopback1 = uut.interfaces['loopback1'].intf
    loopback1_ip = uut.interfaces['loopback1'].ipv4  
    rid =str(loopback1_ip)[:-3]
    for intf in [*uut.interfaces.keys()]:
        if 'loopback' in intf:
            intf=uut.interfaces[intf].intf
            loop_intf_list.append(intf)
        elif 'leaf_spine' in uut.interfaces[intf].alias:
            intf=uut.interfaces[intf].intf
            l3_intf_list.append(intf)
    log.info("loop_intf_list is %r",loop_intf_list)       
    log.info("l3_intf_list is %r",l3_intf_list)
    #try:
    #    OspfGlobalConfig(uut,rid,'UNDERLAY')
    #    OspfIntfConfig(uut,loop_intf_list,'UNDERLAY','loop')
    #    OspfIntfConfig(uut,l3_intf_list,'UNDERLAY','p2p')
    #except:
    #    log.error('Ospf config failed for node %r',uut) 
    #    return 0

    if 'ospf' in igp:
        try:
            OspfGlobalConfig(uut,rid,'UNDERLAY')
            OspfIntfConfig(uut,loop_intf_list,'UNDERLAY','loop')
            OspfIntfConfig(uut,l3_intf_list,'UNDERLAY','p2p')
        except:
            log.error('isis config failed for node %r',uut) 
            return 0

    elif 'isis' in igp:
        try:
            IsisGlobalConfig(uut)
            IsisIntfConfig(uut,loop_intf_list,'loop')
            IsisIntfConfig(uut,l3_intf_list,'p2p')
        except:
            log.error('isis config failed for node %r',uut) 
            return 0

def vxlanpimconfigure111(uut):    
    pim_intf_list = []              
    ip1 = '10.1.1.1'
    rp_add = '100.1.1.2'
    for intf in [*uut.interfaces.keys()]:
        if 'loopback' in intf:
            intf=uut.interfaces[intf].intf
            pim_intf_list.append(intf)
        elif 'leaf_spine' in uut.interfaces[intf].alias:
            intf=uut.interfaces[intf].intf
            pim_intf_list.append(intf)
        try:
            PimConfig(uut,pim_intf_list,rp_add)
        except:
            log.error('PimConfig config failed for node %r',uut) 
            return 0             

def vxlanpimconfigure(uut,linktype): 
    log.info(" U U T    IS     %r", uut) 
    pim_intf_list = []              
    #ip1 = (str(testbed.devices['spine1'].interfaces['loopback1'].ipv4))[:-3]
    #rp_add = (str(testbed.devices['spine1'].interfaces['loopback2'].ipv4))[:-3]
    ip1 = '10.1.1.1'
    rp_add = '100.1.1.2'
    for intf in [*uut.interfaces.keys()]:
        if 'loopback' in intf:
            intf=uut.interfaces[intf].intf
            pim_intf_list.append(intf)
    if 'l3po' in linktype:
        for intf in [*uut.interfaces.keys()]:
            if 'l3_po' in uut.interfaces[intf].type:
                intf='port-channel'+uut.interfaces[intf].intf
                pim_intf_list.append(intf)

    elif 'l3_single_po' in linktype:
        for intf in [*uut.interfaces.keys()]:
            if 'l3_single_po' in uut.interfaces[intf].type:
                intf='port-channel'+uut.interfaces[intf].intf
                pim_intf_list.append(intf)   

    elif 'unnumbered' in linktype:
        for intf in [*uut.interfaces.keys()]:
            if 'Eth' in uut.interfaces[intf].type:
                if 'leaf_spine' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    pim_intf_list.append(intf)     

    log.info("pim_intf_list is %r",pim_intf_list)
    try:
        PimConfig(uut,pim_intf_list,rp_add)
    except:
        log.error('PimConfig config failed for node %r',uut) 
        return 0             


def shutunderlayecmp(uut,linktype):      
    intf_list = []  
    if 'unnumbered' in linktype:
        for intf in [*uut.interfaces.keys()]:
            if 'Eth' in uut.interfaces[intf].type:
                if 'leaf_spine' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    intf_list.append(intf)  
   
    for i in range (0,len(intf_list)-1):
        intf = intf_list[i]
        cfg = \
        """
        interface {intf}
        shut
        """
        try:
            uut.configure(cfg.format(intf=intf))
        except:
            log.error('shutunderlayecmp config failed for node %r',uut) 
            return 0             
    return 1   



        

def evpnmultihomingcoretracking(uut,linktype):    
    intf_list=[]
    if 'l3po' in linktype:
        for intf in [*uut.interfaces.keys()]:
            if 'l3_po' in uut.interfaces[intf].type:
                intf='port-channel'+uut.interfaces[intf].intf
                intf_list.append(intf)

    elif 'l3_single_po' in linktype:
        for intf in [*uut.interfaces.keys()]:
            if 'l3_single_po' in uut.interfaces[intf].type:
                intf='port-channel'+uut.interfaces[intf].intf
                intf_list.append(intf)   

    elif 'unnumbered' in linktype:
        for intf in [*uut.interfaces.keys()]:
            if 'Eth' in uut.interfaces[intf].type:
                if 'leaf_spine' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    intf_list.append(intf)     

    for intf in intf_list:
        cfg = \
        """
        interface {intf}
        evpn multihoming core-tracking
        """
        try:
            uut.configure(cfg.format(intf=intf))        
        except:
            log.info('ESI evpn multihoming core-tracking conf  failed')
            return 0
    return 1



def esiconfcheck(uut,linktype):   
    intf_list=[]
    if 'l3po' in linktype:
        for intf in [*uut.interfaces.keys()]:
            if 'l3_po' in uut.interfaces[intf].type:
                intf='port-channel'+uut.interfaces[intf].intf
                intf_list.append(intf)
                
    elif 'l3_single_po' in linktype:
        for intf in [*uut.interfaces.keys()]:
            if 'l3_single_po' in uut.interfaces[intf].type:
                intf='port-channel'+uut.interfaces[intf].intf
                intf_list.append(intf)   

    elif 'unnumbered' in linktype:
        for intf in [*uut.interfaces.keys()]:
            if 'Eth' in uut.interfaces[intf].type:
                if 'leaf_spine' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    intf_list.append(intf)    

    for intf in intf_list:
        if not 'evpn multihoming core-tracking' in \
        uut.execute('show run interface {intf}'.format(intf=intf)):
            log.info('ESI evpn multihoming core-tracking conf  failed')
            return 0
    return 1 


def vxlanevpndebuging(uut,route):   
    intf_list=[]
    if 'l3po' in linktype:
        for intf in [*uut.interfaces.keys()]:
            if 'l3_po' in uut.interfaces[intf].type:
                intf='port-channel'+uut.interfaces[intf].intf
                intf_list.append(intf)
    elif 'unnumbered' in linktype:
        for intf in [*uut.interfaces.keys()]:
            if 'Eth' in uut.interfaces[intf].type:
                if 'leaf_spine' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    intf_list.append(intf)    

    for intf in intf_list:
        if not 'evpn multihoming core-tracking' in \
        uut.execute('show run interface {intf}'.format(intf=intf)):
            log.info('ESI evpn multihoming core-tracking conf  failed')
            return 0
    return 1 
   
def enableFeaturengoam(uut):  
    log.info('START enableFeaturengoam  @ %r',uut)  
    cfg = \
    """
    feature ngoam
    ngoam profile 1
    oam-channel 2
    !
    ngoam install acl 
    """
    try:
        uut.configure(cfg)
    except:
        log.info('enableFeaturengoam Failed @ %r',uut)     
        return 0
    log.info('PASSED enableFeaturengoam  @ %r',uut)  

 


 


def nxosVxlanEvpnCheck(uut,**kwargs):
    log.info(banner('nxosVxlanEvpnCheck'))
    path_local = "mac > L2FM > L2RIB > BGP_L2VPN ---Spine---\
      BGP_L2VPN > L2RIB > L2FM > mac "
   
    path_remote = 'BGP_L2VPN > L2RIB > L2FM > mac '
    'BGP_L2VPN > peer/vni notif > vxlan_mgr > udfm '
    'L2RIB<--->udfm '
     
    
    log.info('path_local----- %r',path_local)   
    log.info('path_remote----- %r',path_remote)   
        
    for arg in kwargs:
        if 'mac' in arg:
            mac = kwargs['mac']
            log.info('STEP_1 : checking mac add table  %r for uut %r ',mac,uut)
            op =  uut.execute('show mac address-table addr {mac}'.format(mac=mac))
            for line in op.splitlines():
                if 'dynamic' in line:
                    if mac in line:
                        log.info('+------------------------------------------------------+')  
                        log.info('|                 mac %r learned         | ',mac)                          
                        log.info('|                       mac > L2FM                     |')     
                        log.info('|                  checking l2fm logs                  |') 
                        log.info('+------------------------------------------------------+') 
                        log.info('STEP_2 : L2FM installs the MAC in the L2RIB Mac %r in RIB of  %r ',mac,uut)                           
                        op2 =  uut.execute('show sys inter l2fm event-hist deb | incl {mac}'.format(mac=mac))
                        check = 'To L2RIB: topo-id: 1001, macaddr: {mac}'.format(mac=mac)
                        if check in op2:
                            log.info('+-------------------------------------------------------+') 
                            log.info('|          l2fm sends mac %r to L2RIB     | ',mac)                          
                            log.info('|                       mac > L2FM > L2RIB              |')     
                            log.info('|                      checking l2rib                   |') 
                            log.info('+------------------------------------------------------+') 
                            log.info('STEP_3 : Check Mac %r in L2RIB  ',mac)                           
                            op3 =  uut.execute('show l2route evpn mac evi 1001 | incl {mac}'.format(mac=mac))
                            if mac in op3:
                                log.info('+-------------------------------------------------------+') 
                                log.info('|               mac %r found in L2RIB    | ',mac)                          
                                log.info('|                       mac > L2FM > L2RIB              |')     
                                log.info('|                      checking l2rib logs              |') 
                                log.info('+------------------------------------------------------+') 
                                log.info('STEP_4 : Check Mac %r in L2RIB logs  ',mac)                                     
                                op4 =  uut.execute(' show system internal l2rib event-history mac | incl {mac}'.format(mac=mac))
                                if 'Encoding MAC best route (ADD, client id' in op4:
                                    log.info('+------------------------------------------------------+') 
                                    log.info('|     mac  %r ADD  in L2RIB ev history   | ',mac)                          
                                    log.info('|                       mac > L2FM > L2RIB > bgp       |')     
                                    log.info('|                      checking bgp logs               |') 
                                    log.info('+------------------------------------------------------+') 
                                    log.info('STEP_5 : Check Mac %r in BGP logs  ',mac)                                     
                                    op5 =  uut.execute('show bgp internal event-history events | incl {mac}'.format(mac=mac))
                                    if 'EVT: Received from L2RIB MAC-IP route:' in op5:
                                        log.info('+-------------------------------------------------------+') 
                                        log.info('|              mac %r  in BGP ev history  | ',mac)                          
                                        log.info('|                       mac > L2FM > L2RIB              |')     
                                        log.info('|                      checking bgp l2vpn table         |') 
                                        log.info('+-------------------------------------------------------+') 
                                        log.info('STEP_6 : Check Mac %r in BGP   ',mac) 
                                        op6 =  uut.execute('sh bgp l2 evpn {mac} | json-pretty | incl best'.format(mac=mac))
                                        #for line in op6.splitlines():
                                        #    if line:
                                        if '"pathbest": "true",' in op6:
                                            log.info('+-------------------------------------------------------+') 
                                            log.info('|                  mac  %r found in BGP   | ',mac,)                          
                                            log.info('|                       mac > L2FM > L2RIB>BGP          |')     
                                            log.info('|                      PASSED for MAC LOCAL             |') 
                                            log.info('+-------------------------------------------------------+') 
                                            return 1   
                                        elif 'Path type: local, path is valid, is best path:' not in op6:
                                            log.info('mac %r Not in in BGP @ uut %r ',mac,uut) 
                                            return 0
                                    else:
                                        log.info('mac %r not in bgp internal event-history  @ uut %r ',mac,uut) 
                                        return 0
                                else:
                                    log.info('mac %r NOT in l2rib event-history @ uut %r ',mac,uut) 
                                    return 0
                            else:
                                log.info('mac %r NOT sent to L2RIB @ uut %r ',mac,uut) 
                                return 0
                        else:
                            log.info('mac %r NOT sent to L2RIB @ uut %r ',mac,uut) 
                            return 0
                    else:
                        log.info('mac %r NOT learned @ uut %r ',mac,uut) 
                        return 0
                  

        elif 'ip' in arg:
            ip = kwargs['ip']
            log.info('ip is %r',ip)
        elif 'vlan' in arg:
            vlan = kwargs['vlan']
            log.info('vlan is %r',vlan) 

    
     


    '''
    2mac_l2fm_ev_hist = 'show sys inter l2fm event-hist deb | in {mac}'.format(mac=mac)
    
    4mac_l2rib = 'show l2route evpn mac evi {vlan}'.format(mac=mac)
    5mac_l2rib_ev_hist = 'sh system internal l2rib event-history mac | in {mac}'.format(mac=mac)
    6mac_bgp_vni = 'show bgp l2vpn evpn vni-id {vni}'.format(vni=vni)
    7mac_bgp_ev_hist = 'show bgp internal event-history events | in {mac}'.format(mac=mac)
    8mac_bgp = 'show bgp l2vpn evpn {mac}'.format(mac=mac)
    rem_mac_bgp = 'show bgp l2vpn evpn {mac}'.format(mac=mac)
    rem_peer_notif_vxlan_mgr = 'show nve internal bgp rnh database'
    rem_mac_l2rib = 'show l2route evpn mac evi {vlan}'.format(mac=mac)
    rem_fwd_nve_l3 = 'show forwarding nve l3 peers' #rmac 
    rem_nve_pee_det = 'show nve peers detail' # rmac , add-complete
    rem_l2fm_ev_deb = 'show system internal l2fm debugs |  in {mac}'.format(mac=mac)



    06/01/16 22:31:55.201 UTC 5 9954] Received MAC ROUTE msg: addr: (100, 8c60.4f93.5ffc) vni: 0
    [06/01/16 22:31:55.202 UTC 9 9954] (100,8c60.4f93.5ffc,3):MAC route created with seq num:0, flags:L (),
    [06/01/16 22:31:55.207 UTC 3 9954] (100,8c60.4f93.5ffc):Bound MAC-IP(100.1.1.1) to MAC, Total MAC-IP


    if mac:
        log.info('checking mac address-table entry for mac %r',mac)
        op = uut.execute('show mac address-table addr {mac}'.format(mac=mac))
            if mac in op:
                log.info('mac address %r found in address table',mac)
                log.info('checking mac address %r l2fm event-hist',mac)                

            else:
                log.info('mac address %r NOT found in address table',mac)
                return 0

    '''
def leafBgpbringup(uut,spine_rid):  
    log.info('Start leafBgpbringup ')
    for intf in uut.interfaces.keys():
        if 'loopback1' in intf:
            intf=uut.interfaces[intf].intf
            rid1=uut.interfaces[intf].ipv4
            rid=str(rid1)[:-3]
            leaf_bgp_obj1=IbgpLeafNode(uut,rid,'65001',\
            ['Nil'],[spine_rid],'Loopback1','ibgp-vxlan')
            try:
                leaf_bgp_obj1.bgp_conf()
            except:
                log.info('leafBgpbringup Failed')
                return 0
    return 1   




def leaf_protocol_check222(uut,protocol_list):
    for proto in protocol_list:
        fail_list = []
        if 'isis' in proto:
            cmd = uut.execute("sh isis adjacency | incl N/A")
            op = cmd.splitlines()
            for line in op:
                if line:
                    if not '  UP ' in line:
                        log.info('isis neighbor found,Test failed for uut/neighbor %r',uut)
                        fail_list.append('fail')
            
            if 'fail' in fail_list:
                log.info('isis neighbor test FAIL for uut/neighbor %r',uut)
                return 0
            else:
                log.info('isis neighbor test PASS for uut/neighbor %r',uut)
                return 1            

        elif 'vpc' in proto:
            op=uut.execute('show port-channel summary | incl Eth')
            op1=op.splitlines()
            for line in op1:
                if line:
                    if not "(P)" in line:
                        log.info('VPC Bringup Failed on device %r',str(uut))
                        uut.execute('show port-channel summary')
                        return 0
    
        elif 'ospf' in proto:
            cmd = uut.execute("show ip ospf neighbors | json-pretty")
            if not "addr" in str(cmd):
                log.info('No OSPF neighbor found,Test failed for uut/neighbor %r',uut)
                return 0
            else:
                test1=json.loads(cmd)
                test11 = test1["TABLE_ctx"]["ROW_ctx"]
                if 'list' in str(type(test11)):
                    neig_list = test11[0]["TABLE_nbr"]["ROW_nbr"]
                    neig_count =  str(neig_list).count('addr')
                    if neig_count == 1:
                        if not 'FULL' in (neig_list)[0]['state']:
                            log.info('OSPF neighbor check failed for uut/neighbor %r',uut)
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            if not 'FULL' in (neig_list)[i]['state']:
                                log.info('OSPF neighbor check failed for uut/neighbor %r',uut)
                                return 0
                            else:
                                return 1

                else:
                    neig_list= test1["TABLE_ctx"]["ROW_ctx"]["TABLE_nbr"]["ROW_nbr"]
                    neig_count =  str(neig_list).count('addr')
                    if neig_count == 1:
                        if not 'FULL' in (neig_list)['state']:
                            log.info('OSPF neighbor check failed for uut/neighbor %r',uut)
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            if not 'FULL' in (neig_list)[i]['state']:
                                log.info('OSPF neighbor check failed for uut/neighbor %r',uut)
                                return 0
                            else:
                                return 1


        elif 'bgp' in proto:
            cmd = uut.execute(" show bgp l2 evpn summary | json-pretty |inc state")
            if not "state" in str(cmd):
                log.info('No BGP neighbor found,Test failed for uut/neighbor %r',uut)
                return 0
            '''
            else:
                test1=json.loads(cmd)
                test11 = test1["TABLE_vrf"]["ROW_vrf"]
                if 'list' in str(type(test11)):
                    neig_list= test11[0]["TABLE_af"]["ROW_af"][0]["TABLE_saf"][ "ROW_saf"][0]["TABLE_neighbor"]["ROW_neighbor"]
                    neig_count =  str(neig_list).count('neighborid')
                    if neig_count == 1:
                        if not 'Established' in (neig_list)[0]['state']:
                            log.info('BGP neighbor check failed for uut/neighbor %r',uut)
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            if not 'Established' in (neig_list)[i]['state']:
                                log.info('BGP neighbor check failed for uut/neighbor %r',uut)
                                return 0
                            else:
                                return 1

                else:
                    neig_list= test1["TABLE_vrf"]["ROW_vrf"]["TABLE_af"]["ROW_af"]["TABLE_saf"][ "ROW_saf"]["TABLE_neighbor"]["ROW_neighbor"]
                    neig_count =  str(neig_list).count('neighborid')
                    if neig_count == 1:
                        if not 'Established' in (neig_list)['state']:
                            log.info('BGP neighbor check failed for uut/neighbor %r',uut)
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            if not 'Established' in (neig_list)[i]['state']:
                                log.info('BGP neighbor check failed for uut/neighbor %r',uut)
                                return 0
                            else:
                                return 1
            '''

            op = cmd.splitlines()
            for line in op:
                if 'state' in line:
                    if not "Established" in line:
                        log.info("BGP neighbor check passed for uut %r",uut)
                        return 0
 
            log.info('BGP neighbor check passed for uut -------------- :')
            return 1

        elif 'pim' in proto:
            cmd = uut.execute("show ip pim neighbor | json-pretty ")
            if not "vrf" in str(cmd):
                if not "nbr-add" in str(cmd):
                    log.info('No PIM neighbor found,Test failed for uut/neighbor %r',uut)
                    return 0
                else:
                    return 1

            elif "vrf" in str(cmd):
                test1=json.loads(cmd)
                test11 = test1["TABLE_vrf"]["ROW_vrf"]
                if 'list' in str(type(test11)):
                    neig_list= test11[0]["TABLE_neighbor"]["ROW_neighbor"]
                    neig_count =  str(neig_list).count('nbr-addr')
                    if neig_count == 1:
                        uptime = (neig_list)[0]['uptime']
                        uptime = uptime.replace(":","")
                        uptime = uptime.replace("d","")
                        uptime = uptime.replace("h","")
                        uptime = uptime.replace("s","")
                        if not int(uptime) > 1:
                            log.info('PIM neighbor check failed for uut/neighbor %r',uut)
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            uptime = (neig_list)[i]['uptime']
                            uptime = uptime.replace(":","")
                            uptime = uptime.replace("d","")
                            uptime = uptime.replace("h","")
                            uptime = uptime.replace("s","")
                            if not int(uptime) > 1:
                                log.info('PIM neighbor check failed for uut/neighbor %r',uut)
                                return 0
                            else:
                                return 1

                else:
                    neig_list= test1["TABLE_vrf"]["ROW_vrf"]["TABLE_neighbor"]["ROW_neighbor"]
                    neig_count =  str(neig_list).count('nbr-addr')
                    if neig_count == 1:
                        uptime = (neig_list)['uptime']
                        uptime = uptime.replace(":","")
                        uptime = uptime.replace("d","")
                        uptime = uptime.replace("h","")
                        uptime = uptime.replace("s","")
                        if not int(uptime) > 1:
                            log.info('PIM neighbor check failed for uut/neighbor %r',uut)
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            uptime = (neig_list)[i]['uptime']
                            uptime = uptime.replace(":","")
                            uptime = uptime.replace("d","")
                            uptime = uptime.replace("h","")
                            uptime = uptime.replace("s","")
                            if not int(uptime) > 1:
                                log.info('PIM neighbor check failed for uut/neighbor %r',uut)
                                return 0
                            else:
                                return 1
            else:
                pass

            log.info('PIM Neighbor check passed for uut --------------')

        elif 'nve-peer' in proto:
            #if not 'UnicastBGP' in uut.execute('show nve peers ')
            cmd = uut.execute("show nve peers | json-pretty")
            if not "peer-state" in str(cmd):
                log.info('No NVE neighbor found,Test failed for uut/neighbor,11111')
                time.sleep(20)
                cmd = uut.execute("show nve peers | json-pretty")
                if not "peer-state" in str(cmd):
                    log.info('No NVE neighbor found,Test failed for uut/neighbor,2222')
                    time.sleep(20)
                    cmd = uut.execute("show nve peers | json-pretty")
                    if not "peer-state" in str(cmd):
                        log.info('No NVE neighbor found,Test failed for uut/neighbor,33333')
                        cmd = uut.execute("show nve peers")
                        return 0
            else:
                test1=json.loads(cmd)
                test11 = test1["TABLE_nve_peers"]["ROW_nve_peers"]
                if 'list' in str(type(test11)):
                    neig_list= test11
                    neig_count =  str(neig_list).count('peer-ip')
                    if neig_count == 1:
                        state = (neig_list)[0]['peer-state']
                        if not 'Up' in state:
                            log.info('NVE Peer check failed for uut/neighbor %r',uut)
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            state = (neig_list)[i]['peer-state']
                            if not 'Up' in state:
                                log.info('NVE Peer check failed for uut/neighbor %r',uut)
                            else:
                                log.info('NVE Peer check passed for uut --------------')
                                return 1


                else:
                    neig_list= test1["TABLE_nve_peers"]["ROW_nve_peers"]
                    neig_count =  str(neig_list).count('peer-ip')
                    if neig_count == 1:
                        state = (neig_list)['peer-state']
                        if not 'Up' in state:
                            log.info('NVE Peer check failed for uut/neighbor %r',uut)
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            state = (neig_list)[i]['peer-state']
                            if not 'Up' in state:
                                log.info('NVE Peer check failed for uut/neighbor %r',uut)
                            else:
                                log.info('NVE Peer check passed for uut --------------')
                                return 1

        elif 'nve-vni' in proto:
            cmd = uut.execute("show nve vni")
            #test1=json.loads(uut.execute(cmd))
            if not "nve1" in str(cmd):
                log.info('No NVE VNI found,Test failed for uut/neighbor %r',uut)
                return 0

            if "Down" in str(cmd):
                log.info(' NVE VNI Down,Test failed for uut/neighbor %r',uut)
                return 0

            else:
                return 1

    log.info('Protocol check passed for uut -------------- :')

def trmEnablevtep(uut):
    op = uut.execute("sh run bgp | incl 'router bgp'")
    as_num = op.split()[-1]

    cfg_global = \
    """
    feature ngmvpn
    ip igmp snooping
    ip igmp snooping vxlan
    ip multicast overlay-spt-only
    ip igmp snooping 
    route-map ssm-1 permit 10
    match ip multicast group 232.0.0.0/8 

    route-map sendall permit 10
    set path-selection all advertise
    ip prefix-list anyip seq 5 permit 0.0.0.0/0 le 32 
    route-map no-pim-neighbor deny 10
    match ip address prefix-list anyip 

    router bgp {as_num}
    address-family ipv4 mvpn
    maximum-paths 32
    additional-paths send
    additional-paths receive
    additional-paths selection route-map sendall
    send-community extended

    template peer ibgp-vxlan
    remote-as {as_num}
    address-family ipv4 mvpn
    maximum-paths 32
    additional-paths send
    additional-paths receive
    additional-paths selection route-map sendall
    send-community extended
    address-family ipv6 mvpn     
    """
    uut.configure(cfg_global.format(as_num=as_num)) 


    op = uut.execute('show vrf all | incl vxlan')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            vrf = line.split()[0]
            vrf_list.append(vrf)

    loop_num1 = 111
    mc1 = 1
    for vrf in vrf_list:
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        l3_vlan_list = []
        l2_vlan_list = []
        ip_list = []
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        l2_vlan_list.append(int(line.split()[0].replace("Vlan","")))
                        ip_list.append(line.split()[1])
                    elif 'forward-enabled' in line:
                        l3_vlan_list.append(int(line.split()[0].replace("Vlan","")))

        mc = str(mc1) 
        #mc_ip =  '239.0.23.{mc}'.format(mc=mc)
        mc_ip = str(ip_address('239.0.23.0')+int(mc))
        if '.255' in mc_ip:
            mc_ip = str(ip_address(mc_ip)+2)
        loop_num = str(loop_num1)    
        rt = str(vrf.strip('vxlan-'))
        #ip_add = '1.2.3.{loop_num}'.format(loop_num=loop_num)
        ip_add = str(ip_address('1.2.3.0')+int(loop_num))
        if '.255' in ip_add:
            ip_add = str(ip_address(ip_add)+2)
       


        cfg_loop_svi_vrf = \
        """
        interface loopb {loop_num}
        description Overlay VRF RP Loopback interface
        vrf member {vrf}
        ip address {ip_add}/32
        ip pim sparse-mode
        vrf context {vrf}
        ip pim rp-address {ip_add} group-list 224.0.0.0/4
        ip pim ssm route-map ssm-1
        address-family ipv4 unicast
        route-target both auto mvpn
        route-target both auto evpn
        route-target both auto  

        interface nve 1
        member vni {rt} associate-vrf
        mcast-group {mc_ip}
        """
        for vlan in l3_vlan_list:
            cfg_loop_svi_vrf +=  'interface vlan {vlan}\n'.format(vlan=vlan)
            cfg_loop_svi_vrf +=  'ip forward\n'            
            cfg_loop_svi_vrf +=  'ip pim sparse-mode\n' 

        for vlan in l2_vlan_list:
            cfg_loop_svi_vrf +=  'interface vlan {vlan}\n'.format(vlan=vlan)
            cfg_loop_svi_vrf +=  'ip pim neighbor-policy no-pim-neighbor\n'            
            cfg_loop_svi_vrf +=  'ip pim sparse-mode\n' 

        uut.configure(cfg_loop_svi_vrf.format(loop_num=loop_num,vrf=vrf,ip_add=ip_add,rt=rt,mc_ip=mc_ip),timeout=300)
        loop_num1 = loop_num1+1
        mc1 = mc1 +1
        ip_add = str(ip_address(ip_add)+1)
        mc_ip = str(ip_address(mc_ip)+1)

def mstrmLeafConfigure(uut):
    op = uut.execute("sh run bgp | incl 'router bgp'")
    as_num = op.split()[-1]

    cfg_global = \
    """
    feature ngmvpn
    ip igmp snooping vxlan
    ip multicast overlay-spt-only
    ip igmp snooping 
    router bgp {as_num}
    address-family ipv4 unicast
    maximum-paths 32
    maximum-paths ibgp 32
    address-family ipv4 mvpn
    maximum-paths 32
    additional-paths send
    additional-paths receive
    additional-paths selection route-map sendall
    address-family l2vpn evpn
    maximum-paths ibgp 64

    template peer ibgp-vxlan
    remote-as {as_num}
    update-source loopback1
    address-family ipv4 unicast
      soft-reconfiguration inbound always
    address-family ipv4 mvpn
      send-community extended
    address-family ipv6 mvpn
    address-family l2vpn evpn
      send-community
      send-community extended

    """
    uut.configure(cfg_global.format(as_num=as_num),timeout=500) 


    op = uut.execute('show vrf all | incl vxlan')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            vrf = line.split()[0]
            vrf_list.append(vrf)

    loop_num1 = 111
    mc1 = 1
    for vrf in vrf_list:
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        l3_vlan_list = []
        l2_vlan_list = []
        ip_list = []
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        l2_vlan_list.append(int(line.split()[0].replace("Vlan","")))
                        ip_list.append(line.split()[1])
                    elif 'forward-enabled' in line:
                        l3_vlan_list.append(int(line.split()[0].replace("Vlan","")))

        mc = str(mc1) 
        #mc_ip =  '239.0.23.{mc}'.format(mc=mc)
        mc_ip = str(ip_address('239.0.23.0')+int(mc))
        if '.255' in mc_ip:
            mc_ip = str(ip_address(mc_ip)+2)
        loop_num = str(loop_num1)    
        rt = str(vrf.strip('vxlan-'))
        #ip_add = '1.2.3.{loop_num}'.format(loop_num=loop_num)
        ip_add = str(ip_address('1.2.3.0')+int(loop_num))
        if '.255' in ip_add:
            ip_add = str(ip_address(ip_add)+2)
       
        cfg_loop_svi_vrf = \
        """
        route-map ssm-1 permit 10
        match ip multicast group 232.0.0.0/8     
        ip prefix-list anyip seq 5 permit 0.0.0.0/0 le 32     
        route-map no-pim-neighbor deny 10
        match ip address prefix-list anyip 

        interface loopb {loop_num}
        description Overlay VRF RP Loopback interface
        vrf member {vrf}
        ip address {ip_add}/32
        ip pim sparse-mode

        vrf context {vrf}
        ip pim rp-address {ip_add} group-list 224.0.0.0/4
        ip pim ssm route-map ssm-1
        rd auto
        address-family ipv4 unicast
        route-target both auto
        route-target both auto mvpn
        route-target both auto evpn
        address-family ipv6 unicast
        route-target both auto

        interface nve 1
        member vni {rt} associate-vrf
        mcast-group {mc_ip}
        """
        for vlan in l3_vlan_list:
            cfg_loop_svi_vrf +=  'interface vlan {vlan}\n'.format(vlan=vlan)
            cfg_loop_svi_vrf +=  'ip forward\n'            
            cfg_loop_svi_vrf +=  'ip pim sparse-mode\n' 

        for vlan in l2_vlan_list:
            cfg_loop_svi_vrf +=  'interface vlan {vlan}\n'.format(vlan=vlan)
            cfg_loop_svi_vrf +=  'ip pim neighbor-policy no-pim-neighbor\n'            
            cfg_loop_svi_vrf +=  'ip pim sparse-mode\n' 

        uut.configure(cfg_loop_svi_vrf.format(loop_num=loop_num,vrf=vrf,ip_add=ip_add,rt=rt,mc_ip=mc_ip),timeout=500)
        loop_num1 = loop_num1+1
        mc1 = mc1 +1
        ip_add = str(ip_address(ip_add)+1)
        mc_ip = str(ip_address(mc_ip)+1)

def mstrmSpineConfigure(uut):
    op = uut.execute("sh run bgp | incl 'router bgp'")
    as_num = op.split()[-1]

    cfg_global = \
    """
    router bgp {as_num}
    log-neighbor-changes
    address-family ipv4 unicast
    maximum-paths 32
    maximum-paths ibgp 32
    address-family ipv4 mvpn
    maximum-paths 32
    address-family l2vpn evpn
    maximum-paths ibgp 64

    template peer ibgp-vxlan
    remote-as {as_num}
    update-source loopback1
    address-family ipv4 unicast
      route-reflector-client
      soft-reconfiguration inbound always
    address-family ipv4 mvpn
      send-community extended
      route-reflector-client
    address-family l2vpn evpn
      send-community
      send-community extended
      route-reflector-client

    """
    uut.configure(cfg_global.format(as_num=as_num),timeout=300)   


def mstrmBgwConfigure(uut):
    op = uut.execute("sh run bgp | incl 'router bgp'")
    as_num = op.split()[-1]
    cfg_global = \
    """
    feature ngmvpn
    feature fabric forwarding

    ip pim pre-build-spt
    ip igmp snooping vxlan
    ip igmp snooping 
    ip prefix-list redistribute-direct-underlay seq 5 permit 0.0.0.0/0 le 32 
    route-map redistribute-direct-underlay permit 10
    match ip address prefix-list redistribute-direct-underlay 


    router bgp {as_num}
    address-family ipv4 unicast
    redistribute direct route-map redistribute-direct-underlay
    maximum-paths 32
    maximum-paths ibgp 32
    address-family ipv6 unicast
    maximum-paths 32
    maximum-paths ibgp 32
    address-family ipv4 mvpn
    maximum-paths 32
    retain route-target all
    address-family l2vpn evpn
    maximum-paths 32
    maximum-paths ibgp 32
    retain route-target all

    template peer dcioverlay
    remote-as 99
    update-source loopback1
    ebgp-multihop 10
    peer-type fabric-external
 
    address-family ipv4 mvpn
      maximum-paths 32
      send-community
      send-community extended
      rewrite-rt-asn
    address-family l2vpn evpn
      send-community
      send-community extended
      rewrite-evpn-rt-asn
    
    template peer ibgp-vxlan
    remote-as {as_num}
    update-source loopback1
    address-family ipv4 unicast
      soft-reconfiguration inbound always
    address-family ipv4 mvpn
      send-community extended
    address-family l2vpn evpn
      send-community
      send-community extended
    no neighbor 10.1.1.1
    no neighbor 10.1.1.2
    neighbor 10.1.1.1
    inherit peer dcioverlay
    neighbor 10.1.1.2
    inherit peer dcioverlay
    """
    uut.configure(cfg_global.format(as_num=as_num),timeout=120) 

    op = uut.execute('show vrf all | incl vxlan')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            vrf = line.split()[0]
            vrf_list.append(vrf)

    loop_num1 = 111
    mc1 = 1
    for vrf in vrf_list:
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        l3_vlan_list = []
        l2_vlan_list = []
        ip_list = []
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        l2_vlan_list.append(int(line.split()[0].replace("Vlan","")))
                        ip_list.append(line.split()[1])
                    elif 'forward-enabled' in line:
                        l3_vlan_list.append(int(line.split()[0].replace("Vlan","")))

        mc = str(mc1) 
        #mc_ip =  '239.0.23.{mc}'.format(mc=mc)
        mc_ip = str(ip_address('239.0.23.0')+int(mc))
        if '.255' in mc_ip:
            mc_ip = str(ip_address(mc_ip)+2)
        loop_num = str(loop_num1)    
        rt = str(vrf.strip('vxlan-'))
        #ip_add = '1.2.3.{loop_num}'.format(loop_num=loop_num)
        ip_add = str(ip_address('1.2.3.0')+int(loop_num))
        if '.255' in ip_add:
            ip_add = str(ip_address(ip_add)+2)
        
        cfg_loop_svi_vrf = \
        """
        route-map ssm-1 permit 10
        match ip multicast group 232.0.0.0/8 
        route-map ssm-1 permit 11
        match ip multicast group 233.0.0.0/8 

        ip prefix-list anyip seq 5 permit 0.0.0.0/0 le 32 
        route-map no-pim-neighbor deny 10
        match ip address prefix-list anyip 

        interface loopb {loop_num}
        description Overlay VRF RP Loopback interface
        vrf member {vrf}
        ip address {ip_add}/32
        ip pim sparse-mode

        vrf context {vrf}
        ip pim rp-address {ip_add} group-list 224.0.0.0/4
        ip pim ssm route-map ssm-1
        address-family ipv4 unicast
        route-target both auto mvpn
        route-target both auto evpn
        route-target both auto  

        interface nve 1
        member vni {rt} associate-vrf
        mcast-group {mc_ip}
        multisite ingress-replication optimized
        """
        for vlan in l3_vlan_list:
            cfg_loop_svi_vrf +=  'interface vlan {vlan}\n'.format(vlan=vlan)
            cfg_loop_svi_vrf +=  'ip forward\n'            
            cfg_loop_svi_vrf +=  'ip pim sparse-mode\n' 

        for vlan in l2_vlan_list:
            cfg_loop_svi_vrf +=  'interface vlan {vlan}\n'.format(vlan=vlan)
            cfg_loop_svi_vrf +=  'ip pim neighbor-policy no-pim-neighbor\n'            
            cfg_loop_svi_vrf +=  'ip pim sparse-mode\n' 

        uut.configure(cfg_loop_svi_vrf.format(loop_num=loop_num,vrf=vrf,ip_add=ip_add,rt=rt,mc_ip=mc_ip),timeout=300)
        loop_num1 = loop_num1+1
        mc1 = mc1 +1
        ip_add = str(ip_address(ip_add)+1)
        mc_ip = str(ip_address(mc_ip)+1)

def trmEnablebgwOLD(uut):
    op = uut.execute("sh run bgp | incl 'router bgp'")
    as_num = op.split()[-1]
    cfg_global = \
    """
    feature ngmvpn
    feature fabric forwarding

    ip pim pre-build-spt
    ip igmp snooping vxlan
    ip igmp snooping 

    ip multicast overlay-spt-only
    ip prefix-list anyip seq 5 permit 0.0.0.0/0 le 32 

    route-map sendall permit 10
    set path-selection all advertise

    route-map no-pim-neighbor deny 10
    match ip address prefix-list anyip 


    ip prefix-list directallow seq 20 permit 0.0.0.0/0 le 32 
    ip prefix-list directdeny seq 10 deny 1.1.0.0/16 le 32 
    ip prefix-list directdeny seq 15 deny 100.0.0.0/24 le 32 
    route-map allowall permit 10
    route-map directroute-rpm deny 10
    match ip address prefix-list directdeny 
    route-map directroute-rpm permit 20
    match ip address prefix-list directallow 
    route-map extroute-policy permit 10
    set local-preference 200
    route-map filter_ext_route permit 10
    set community no-advertise 

    route-map mvpn-permitall permit 10
    set path-selection all advertise

    route-map ssm-1 permit 10
    match ip multicast group 232.0.0.0/8 

    route-map ssm-1 permit 11
    match ip multicast group 233.0.0.0/8 

    ip prefix-list redistribute-direct-underlay seq 5 permit 0.0.0.0/0 le 32 
    route-map redistribute-direct-underlay permit 10
    match ip address prefix-list redistribute-direct-underlay 


    router bgp {as_num}
    address-family ipv4 unicast
    redistribute direct route-map redistribute-direct-underlay
    maximum-paths 32
    maximum-paths ibgp 32
    address-family ipv6 unicast
    maximum-paths 32
    maximum-paths ibgp 32
    address-family ipv4 mvpn
    maximum-paths 32
    retain route-target all
    address-family l2vpn evpn
    maximum-paths 32
    maximum-paths ibgp 32
    retain route-target all

    template peer dcioverlay
    remote-as 99
    update-source loopback1
    ebgp-multihop 10
    peer-type fabric-external
 
    address-family ipv4 mvpn
    maximum-paths 32
      send-community
      send-community extended
      rewrite-rt-asn
    address-family l2vpn evpn
      send-community
      send-community extended
      rewrite-evpn-rt-asn
    
    template peer ibgp-vxlan
    remote-as {as_num}
    update-source loopback1
    address-family ipv4 unicast
      soft-reconfiguration inbound always
    address-family ipv4 mvpn
    maximum-paths 32
      send-community extended
    address-family l2vpn evpn
      send-community
      send-community extended
    no neighbor 10.1.1.1
    no neighbor 10.1.1.2
    neighbor 10.1.1.1
    inherit peer dcioverlay
    neighbor 10.1.1.2
    inherit peer dcioverlay
    """
    uut.configure(cfg_global.format(as_num=as_num)) 

    op = uut.execute('show vrf all | incl vxlan')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            if 'vxlan' in line:
                vrf = line.split()[0]
                vrf_list.append(vrf)

    loop_num1 = 111
    mc1 = 1
    for vrf in vrf_list:
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        l3_vlan_list = []
        l2_vlan_list = []
        ip_list = []
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        l2_vlan_list.append(int(line.split()[0].replace("Vlan","")))
                        ip_list.append(line.split()[1])
                    elif 'forward-enabled' in line:
                        l3_vlan_list.append(int(line.split()[0].replace("Vlan","")))

        mc = str(mc1) 
        mc_ip =  '239.0.23.{mc}'.format(mc=mc)
        loop_num = str(loop_num1)
    
        rt = str(vrf.strip('vxlan-'))
        ip_add = '1.2.3.{loop_num}'.format(loop_num=loop_num)
        
        cfg_loop_svi_vrf = \
        """
        interface loopb {loop_num}
        description Overlay VRF RP Loopback interface
        vrf member {vrf}
        ip address {ip_add}/32
        ip pim sparse-mode
        vrf context {vrf}
        ip pim rp-address {ip_add} group-list 224.0.0.0/4
        ip pim ssm route-map ssm-1
        address-family ipv4 unicast
        route-target both auto mvpn
        route-target both auto evpn
        route-target both auto  
        interface nve 1
        member vni {rt} associate-vrf
        mcast-group 239.0.23.{mc}
        multisite ingress-replication optimized
        """
        for vlan in l3_vlan_list:
            cfg_loop_svi_vrf +=  'interface vlan {vlan}\n'.format(vlan=vlan)
            cfg_loop_svi_vrf +=  'ip forward\n'            
            cfg_loop_svi_vrf +=  'ip pim sparse-mode\n' 

        for vlan in l2_vlan_list:
            cfg_loop_svi_vrf +=  'interface vlan {vlan}\n'.format(vlan=vlan)
            cfg_loop_svi_vrf +=  'ip pim neighbor-policy no-pim-neighbor\n'            
            cfg_loop_svi_vrf +=  'ip pim sparse-mode\n' 

        uut.configure(cfg_loop_svi_vrf.format(loop_num=loop_num,vrf=vrf,ip_add=ip_add,rt=rt,mc=mc))
        loop_num1 = loop_num1+1
        mc1 = mc1 +1
        ip_add = str(ip_address(ip_add)+1)
        mc_ip = str(ip_address(mc_ip)+1)


def trmEnabledciOLD(uut):
    op = uut.execute("sh run bgp | incl 'router bgp'")
    as_num = op.split()[-1]

    cfg_global = \
    """
    route-map sendall permit 10
    set path-selection all advertise

    ip prefix-list anyip seq 5 permit 0.0.0.0/0 le 32 
    route-map sendall permit 10
    set path-selection all advertise
    route-map no-pim-neighbor deny 10
    match ip address prefix-list anyip 


    ip prefix-list directallow seq 20 permit 0.0.0.0/0 le 32 
    ip prefix-list directdeny seq 10 deny 1.1.0.0/16 le 32 
    ip prefix-list directdeny seq 15 deny 100.0.0.0/24 le 32 
    route-map allowall permit 10
    route-map directroute-rpm deny 10
    match ip address prefix-list directdeny 
    route-map directroute-rpm permit 20
    match ip address prefix-list directallow 
    route-map extroute-policy permit 10
    set local-preference 200
    route-map filter_ext_route permit 10
    set community no-advertise 

    route-map mvpn-permitall permit 10
    set path-selection all advertise

    route-map ssm-1 permit 10
    match ip multicast group 232.0.0.0/8 

    route-map ssm-1 permit 11
    match ip multicast group 233.0.0.0/8 


    router bgp 99
    address-family ipv4 mvpn
    maximum-paths 32
    nexthop route-map allowall
    retain route-target all
    additional-paths send
    additional-paths receive
    additional-paths selection route-map mvpn-permitall    
    send-community extended

     
    neighbor 1.1.1.11
    address-family ipv4 mvpn
      send-community
      send-community extended
      route-map permitall out
      #rewrite-rt-asn

    neighbor 2.1.1.11
    address-family ipv4 mvpn
      send-community
      send-community extended
      route-map permitall out
      #rewrite-rt-asn
     
    neighbor 2.1.1.12
    address-family ipv4 mvpn
      send-community
      send-community extended
      route-map permitall out
      #rewrite-rt-asn
     
    neighbor 3.1.1.11
    address-family ipv4 mvpn
      send-community
      send-community extended
      route-map permitall out
      #rewrite-rt-asn
     
    neighbor 3.1.1.12
    address-family ipv4 mvpn
      send-community
      send-community extended
      route-map permitall out
      #rewrite-rt-asn     
    """
    uut.configure(cfg_global.format(as_num=as_num))      

def mstrmDciConfigure4(uut):
    op = uut.execute("sh run bgp | incl 'router bgp'")
    as_num = op.split()[-1]

    cfg_global = \
    """
    ip prefix-list redistribute-direct-underlay seq 5 permit 0.0.0.0/0 le 32 
    route-map redistribute-direct-underlay permit 10
    match ip address prefix-list redistribute-direct-underlay 

    route-map unchanged permit 10
    set ip next-hop unchanged

    router bgp 99
    log-neighbor-changes
    address-family ipv4 unicast
    redistribute direct route-map redistribute-direct-underlay
  
    address-family ipv4 mvpn
    maximum-paths 32
    retain route-target all
  
    address-family l2vpn evpn
    nexthop route-map unchanged
    retain route-target all
    
    template peer dcioverlay
    update-source loopback1
    ebgp-multihop 10
    
    address-family ipv4 mvpn
      maximum-paths 32
      disable-peer-as-check
      send-community
      send-community extended
      route-map unchanged out
      rewrite-rt-asn
    
    address-family l2vpn evpn
      disable-peer-as-check
      send-community
      send-community extended
      route-map unchanged out
      rewrite-evpn-rt-asn

    no neighbor 1.1.1.11
    no neighbor 1.1.1.12
    no neighbor 2.1.1.11
    no neighbor 4.1.1.11
    no neighbor 3.1.1.11

    neighbor 1.1.1.11
    inherit peer dcioverlay
    remote-as 65001
    neighbor 1.1.1.12
    inherit peer dcioverlay
    remote-as 65001
    neighbor 2.1.1.11
    inherit peer dcioverlay
    remote-as 65002
    neighbor 3.1.1.11
    inherit peer dcioverlay
    remote-as 65003   
    neighbor 4.1.1.11
    inherit peer dcioverlay
    remote-as 65004 
    """
    uut.configure(cfg_global.format(as_num=as_num),timeout=300)      

def mstrmDciConfigure(uut):
    op = uut.execute("sh run bgp | incl 'router bgp'")
    as_num = op.split()[-1]

    cfg_global = \
    """
    ip prefix-list redistribute-direct-underlay seq 5 permit 0.0.0.0/0 le 32 
    route-map redistribute-direct-underlay permit 10
    match ip address prefix-list redistribute-direct-underlay 

    route-map unchanged permit 10
    set ip next-hop unchanged

    router bgp 99
    log-neighbor-changes
    address-family ipv4 unicast
    redistribute direct route-map redistribute-direct-underlay
  
    address-family ipv4 mvpn
    maximum-paths 32
    retain route-target all
  
    address-family l2vpn evpn
    nexthop route-map unchanged
    retain route-target all
    
    template peer dcioverlay
    update-source loopback1
    ebgp-multihop 10
    
    address-family ipv4 mvpn
      maximum-paths 32
      disable-peer-as-check
      send-community
      send-community extended
      route-map unchanged out
      rewrite-rt-asn
    
    address-family l2vpn evpn
      disable-peer-as-check
      send-community
      send-community extended
      route-map unchanged out
      rewrite-evpn-rt-asn

    no neighbor 1.1.1.11
    no neighbor 1.1.1.12
    no neighbor 2.1.1.11
    no neighbor 2.1.1.12
    no neighbor 3.1.1.11

    neighbor 1.1.1.11
    inherit peer dcioverlay
    remote-as 65001
    neighbor 1.1.1.12
    inherit peer dcioverlay
    remote-as 65001
    neighbor 2.1.1.11
    inherit peer dcioverlay
    remote-as 65002
    neighbor 2.1.1.12
    inherit peer dcioverlay
    remote-as 65002
    neighbor 3.1.1.11
    inherit peer dcioverlay
    remote-as 65003    
    """
    uut.configure(cfg_global.format(as_num=as_num))      


def trmallEnabledci(uut):
    op = uut.execute("sh run bgp | incl 'router bgp'")
    as_num = op.split()[-1]

    cfg_global = \
    """
    ip prefix-list anyip seq 5 permit 0.0.0.0/0 le 32 
    route-map sendall permit 10
    set path-selection all advertise
    route-map no-pim-neighbor deny 10
    match ip address prefix-list anyip 


    ip prefix-list directallow seq 20 permit 0.0.0.0/0 le 32 
    ip prefix-list directdeny seq 10 deny 1.1.0.0/16 le 32 
    ip prefix-list directdeny seq 15 deny 100.0.0.0/24 le 32 
    route-map allowall permit 10
    route-map directroute-rpm deny 10
    match ip address prefix-list directdeny 
    route-map directroute-rpm permit 20
    match ip address prefix-list directallow 
    route-map extroute-policy permit 10
    set local-preference 200
    route-map filter_ext_route permit 10
    set community no-advertise 

    route-map mvpn-permitall permit 10
    set path-selection all advertise

    route-map ssm-1 permit 10
    match ip multicast group 232.0.0.0/8 

    route-map ssm-1 permit 11
    match ip multicast group 233.0.0.0/8 


    route-map sendall permit 10
    set path-selection all advertise
    router bgp {as_num}
    address-family ipv4 mvpn
    retain route-target all
    maximum-paths 32
    additional-paths send
    additional-paths receive
    additional-paths selection route-map sendall
    send-community extended
 

    neighbor 1.1.1.11
    address-family ipv4 mvpn
      send-community
      send-community extended
      route-map permitall out
      #rewrite-rt-asn
 
    neighbor 1.1.1.12
    address-family ipv4 mvpn
      send-community
      send-community extended
      route-map permitall out
      #rewrite-rt-asn
 
    neighbor 2.1.1.11
    address-family ipv4 mvpn
      send-community
      send-community extended
      route-map permitall out
      #rewrite-rt-asn
 

    neighbor 2.1.1.12
    address-family ipv4 mvpn
      send-community
      send-community extended
      route-map permitall out
      #rewrite-rt-asn

    neighbor 3.1.1.11
    address-family ipv4 mvpn
      send-community
      send-community extended
      route-map permitall out
      #rewrite-rt-asn
 
    """
    uut.configure(cfg_global.format(as_num=as_num))      


def anycastBgwBgpConfgure(site_bgw_uut_list):
    cfg = \
    """
    router bgp {as_num}
    neighbor {nei_ip}
    remote-as {as_num}
    update-source loopback1
    address-family ipv4 mvpn
      send-community
      send-community extended
    address-family l2vpn evpn
      send-community
      send-community extended
    """
    intf1=site_bgw_uut_list[0].interfaces['loopback1'].intf
    intf2=site_bgw_uut_list[1].interfaces['loopback1'].intf
    ip1=site_bgw_uut_list[0].interfaces['loopback1'].ipv4
    ip1=str(ip1)[:-3]
    ip2=site_bgw_uut_list[1].interfaces['loopback1'].ipv4
    ip2=str(ip2)[:-3]

    op = site_bgw_uut_list[0].execute("sh run bgp | incl 'router bgp'")
    as_num = op.split()[-1]
    site_bgw_uut_list[0].configure(cfg.format(as_num=as_num,nei_ip=ip2))

    op = site_bgw_uut_list[1].execute("sh run bgp | incl 'router bgp'")
    as_num = op.split()[-1]
    site_bgw_uut_list[1].configure(cfg.format(as_num=as_num,nei_ip=ip1))

 


def unShutall(uut):
    cfg = \
    """

    """
    op = uut.execute(" show interf br | incl Ad")
    for line in op.splitlines():
        if line:
            if not 'Vlan1 ' in line:
                if 'dmin' in line:
                    intf = line.split()[0]
                    cfg +=  'interface {intf}\n'.format(intf=intf)
                    cfg +=  'no switchp\n'            
                    cfg +=  'no shut\n'       

    uut.configure(cfg)





def check_mvpn_type5_route(uut,route):
    cmd1 = \
            '''
            interface nve1
            no shutdown
            host-reachability protocol bgp

            source-interface loopback0
            source-interface hold-down-time 30
            '''

def check_mvpn_type6_route(uut,route):
    cmd1 = \
            '''
            interface nve1
            no shutdown
            host-reachability protocol bgp

            source-interface loopback0
            source
            '''
 
def check_mvpn_type7_route(uut,route):
    cmd1 = \
            '''
            interface nve1
            no shutdown
            host-reachability protocol bgp

            source-interface loopback0
            source
            '''

def convert_multicast_ip_to_mac(ip_address):
    """Convert the Multicast IP to it's equivalent Multicast MAC.
    Source info: https://technet.microsoft.com/en-us/library/cc957928.aspx
    """
    # Convert the IP String to a bit sequence string
    try:
        ip_binary = socket.inet_pton(socket.AF_INET, ip_address)
        log.info('ip_binary is -----%r',ip_binary)
        ip_bit_string = ''.join(['{0:08b}'.format(ord(x)) for x in ip_binary])
        log.info('ip_bit_string is -----%r',ip_bit_string)
    except socket.error:
        raise RuntimeError('Invalid IP Address to convert.')
    lower_order_23 = ip_bit_string[-23:]
    log.info('lower_order_23 is -----%r',lower_order_23)
    high_order_25 = '0000000100000000010111100'
    mac_bit_string = high_order_25 + lower_order_23
    log.info('mac_bit_string is -----%r',mac_bit_string)
    final_string = '{0:012X}'.format(int(mac_bit_string, 2))
    log.info('final_string is -----%r',final_string)
    mac_string = ':'.join(s.encode('hex') for s in final_string.decode('hex'))
    return mac_string.upper()

def spirentIgmpHosts(port_handle,igmp_version,scale,vlan_start,ip_start):
    mgroups  = ixiangpf.emulation_multicast_group_config (
        mode = 'create',
        ip_prefix_len = '32',
        ip_addr_start = '239.1.1.1',
        ip_addr_step = '1',
        num_groups = '1',
        pool_name = 'Ipv4Group_1')   

    group_name = mgroups['handle']
    
    for vlan in range(int(vlan_start),int(vlan_start)+scale):
        str4=hex(randint(16,54))[2:]
        str3=hex(randint(55,104))[2:]
        str2=hex(randint(32,80))[2:]
        str1=hex(randint(50,95))[2:]
        nei_ip = '5.1.0.2'
        mac1='00:'+str4+':'+str2+':'+str1+':'+str3+':02'
        op1 = ixiangpf.emulation_igmp_config (
                mode = 'create',
                source_mac = mac1,
                igmp_version = igmp_version,
                port_handle = port_handle,
                ip_router_alert=1,
                count = 1,
                vlan_id=vlan,
                intf_ip_addr = ip_start,
                neighbor_intf_ip_addr = nei_ip,
                )
        ip_start = str(ip_address(ip_start)+65536)
        nei_ip = str(ip_address(nei_ip)+65536)

        if op1['status']:
            log.info('IGMP Host created')
            host1 = op1['handle']
            macstgroup = str("239.1.1.1"),
            device_ret0_group_config = ixiangpf.emulation_igmp_group_config (
                session_handle = host1,
                mode = 'create',
                group_pool_handle = group_name,
                )
            if device_ret0_group_config['status']:
                log.info('IGMP Host created , and group added')

def spirentIgmpHostsControll(port_handle_list,mode):
    # mode - join /leave/restart
    for port_handle in port_handle_list:
        start_igmp = ixiangpf.emulation_igmp_control(
        port_handle = port_handle,
        mode = mode,
        )

def spirentIgmpHostCreate(port_handle,**kwargs):
    log.info(banner('spirentIgmpHostCreate')) 
    #log.info('1111  kwargs are %r',kwargs)

    mcast_group_scale = 1  
    mcast_group = '239.1.1.1'
    vlan = '1001'
    nei_ip = '5.1.0.2'
    vlan_scale = 1
    igmp_version = 'v3'
    
    for arg in kwargs:
        if 'igmp_version' in arg:
            igmp_version = kwargs['igmp_version']
        elif 'vlan' in arg:
            vlan = kwargs['vlan']
        elif 'vlan_scale' in arg:
            vlan_scale = kwargs['vlan_scale']
        elif 'host_ip' in arg:
            host_ip = kwargs['host_ip']
        elif 'mcast_group' in arg:
            mcast_group = kwargs['mcast_group']
        elif 'mcast_group_scale' in arg:
            mcast_group_scale = kwargs['mcast_group_scale']

    #log.info('2222 kwargs are %r',kwargs)
   
    log.info(banner('In spirentIgmpHostCreate, Start emulation_multicast_group_config'))   
    create_groups  = ixiangpf.emulation_multicast_group_config (
        mode = 'create',
        ip_prefix_len = '32',
        ip_addr_start = mcast_group,
        ip_addr_step = '1',
        num_groups = mcast_group_scale,
        pool_name = 'TRM')  

    group_pool_name = create_groups['handle']
            
    log.info(banner('In spirentIgmpHostCreate, Start igmp host create'))      
    for vlan in range(int(vlan),int(vlan) + vlan_scale):
        str4=hex(randint(16,54))[2:]
        str3=hex(randint(55,104))[2:]
        str2=hex(randint(32,80))[2:]
        str1=hex(randint(50,95))[2:]
        
        mac1='00:'+str4+':'+str2+':'+str1+':'+str3+':02'
        log.info('igmp host SMAC : %r',mac1)   
        host_create = ixiangpf.emulation_igmp_config (
                mode = 'create',
                source_mac = mac1,
                igmp_version = igmp_version,
                port_handle = port_handle,
                ip_router_alert=1,
                count = 1,
                vlan_id=vlan,
                intf_ip_addr = host_ip,
                neighbor_intf_ip_addr = nei_ip,
                )
        host_ip = str(ip_address(host_ip)+65536)
        nei_ip = str(ip_address(nei_ip)+65536)

        if host_create['status']:
            log.info('IGMP Host created')
            host_handle = host_create['handle']
            device_ret0_group_config = ixiangpf.emulation_igmp_group_config (
                session_handle = host_handle,
                mode = 'create',
                group_pool_handle = group_pool_name,
                )
            if device_ret0_group_config['status']:
                log.info('IGMP Host created , and group added')


def IgmpHostCreate1111(port_handle,**kwargs):
    log.info(banner('IgmpHostCreate')) 
    #log.info('1111  kwargs are %r',kwargs)

    mcast_group_scale = 1  
    mcast_group = '239.1.1.1'
    #vlan = '1001'
    nei_ip = '5.1.0.2'
    vlan_scale = 1
    igmp_version = choice(['v3','v2'])
    
    for arg in kwargs:
        if 'igmp_version' in arg:
            igmp_version = kwargs['igmp_version']
        elif 'vlan' in arg:
            vlan = kwargs['vlan']
        elif 'nei_ip' in arg:
            nei_ip = kwargs['nei_ip']
        elif 'vlan_scale' in arg:
            vlan_scale = kwargs['vlan_scale']
        elif 'host_ip' in arg:
            host_ip = kwargs['host_ip']
        elif 'mcast_group' in arg:
            mcast_group = kwargs['mcast_group']
        elif 'mcast_group_scale' in arg:
            mcast_group_scale = kwargs['mcast_group_scale']
        elif 'ssm_source' in arg:
            ssm_source = kwargs['ssm_source']


    #log.info('2222 kwargs are %r',kwargs)
   
    log.info(banner('In IgmpHostCreate, Start emulation_multicast_group_config'))   
    create_groups  = ixiangpf.emulation_multicast_group_config (
        mode = 'create',
        ip_prefix_len = '32',
        ip_addr_start = mcast_group,
        ip_addr_step = '1',
        num_groups = mcast_group_scale,
        pool_name = 'TRM')  

    group_pool_name = create_groups['handle']
            
    log.info(banner('In IgmpHostCreate, Start igmp host create'))      
    if not 'Nil' in vlan:
        for vlan in range(int(vlan),int(vlan) + vlan_scale):
            mac_add1 = str(RandMac("00:00:00:00:00:00", True))
            mac1 = mac_add1.replace("'","")
            host_create = ixiangpf.emulation_igmp_config (
                mode = 'create',
                source_mac = mac1,
                igmp_version = igmp_version,
                port_handle = port_handle,
                ip_router_alert=1,
                count = 1,
                vlan_id=vlan,
                intf_ip_addr = host_ip,
                neighbor_intf_ip_addr = nei_ip,
                )
            host_ip = str(ip_address(host_ip)+65536)
            nei_ip = str(ip_address(nei_ip)+65536)

            if host_create['status']:
                log.info('IGMP Host created')
                host_handle = host_create['handle']
                device_ret0_group_config = ixiangpf.emulation_igmp_group_config (
                session_handle = host_handle,
                mode = 'create',
                group_pool_handle = group_pool_name,
                )
                if device_ret0_group_config['status']:
                    log.info('IGMP Host created , and group added')

    else:
        str4=hex(randint(16,54))[2:]
        str3=hex(randint(55,104))[2:]
        str2=hex(randint(32,80))[2:]
        str1=hex(randint(50,95))[2:]       
        mac1='00:'+str4+':'+str2+':'+str1+':'+str3+':02'
        log.info('igmp host SMAC : %r',mac1)   
        host_create = ixiangpf.emulation_igmp_config (
                mode = 'create',
                source_mac = mac1,
                igmp_version = igmp_version,
                port_handle = port_handle,
                ip_router_alert=1,
                count = 1,
                intf_ip_addr = host_ip,
                neighbor_intf_ip_addr = nei_ip,
                )
        host_ip = str(ip_address(host_ip)+65536)
        nei_ip = str(ip_address(nei_ip)+65536)

        if host_create['status']:
            log.info('IGMP Host created')
            host_handle = host_create['handle']
            device_ret0_group_config = ixiangpf.emulation_igmp_group_config (
                session_handle = host_handle,
                mode = 'create',
                group_pool_handle = group_pool_name,
                )
            if device_ret0_group_config['status']:
                log.info('IGMP Host created , and group added')


class LeafObjectXconnect(object):
    def __init__(self,node,vlan,vni,vlan_scale,routed_vlan,routed_vni,routed_vni_scale,\
    ipv4_add,ipv6_add,mcast_group,as_number,ir_mode,mcast_group_scale):
        self.node=node
        self.vlan=vlan
        self.vni=vni
        self.vlan_scale=vlan_scale
        self.routed_vlan=routed_vlan
        self.routed_vni=routed_vni
        self.routed_vni_scale=routed_vni_scale
        self.ipv4_add=ipv4_add
        self.ipv6_add=ipv6_add
        self.mcast_group=mcast_group
        self.as_number=as_number
        self.ir_mode=ir_mode
        self.mcast_group_scale=mcast_group_scale
        
        #ir_mode = bgp,mcast,mix
        
    def vxlan_conf(self):
        vrf_configure(self.node,self.routed_vni,self.routed_vni_scale) 
        vlan_vni_configure(self.node,self.routed_vlan,self.routed_vni,self.routed_vni_scale)  
        vlan_vni_configure(self.node,self.vlan,self.vni,self.vlan_scale) 
        routed_svi_configure(self.node,self.routed_vlan,self.routed_vni,self.routed_vni_scale)
        svi_configure(self.node,self.vlan,self.vlan_scale,self.ipv4_add,self.ipv6_add,self.routed_vni,self.routed_vni_scale)
        if 'mix' in self.ir_mode:
            log.info(banner("Replication mode is BGP + MCAST"))
            nve_configure_bgp_xconnect(self.node,self.vni,self.vlan_scale)
            nve_configure_mcast222(self.node,self.vni,self.vlan_scale,self.mcast_group,self.mcast_group_scale)
        elif 'bgp' in self.ir_mode:         
            log.info(banner("Replication mode is BGP"))
            nve_configure_only_bgp_xconnect(self.node,self.vni,self.vlan_scale)
        elif 'mcast' in self.ir_mode:
            log.info(banner("Replication mode is MCAST"))
            nve_configure_only_mcast(self.node,self.vni,self.vlan_scale,self.mcast_group)            
        routed_nve_configure(self.node,self.routed_vni,self.routed_vni_scale)
        evpn_vni_configure(self.node,self.vni,self.vlan_scale)
        vrf_bgp_configure(self.node,self.as_number,self.routed_vni,self.routed_vni_scale)


def nve_configure_bgp_xconnect(uut,vni,count):

    cmd1 = \
    """
    interface nve1
    no shutdown
    host-reachability protocol bgp
    source-interface loopback0
    source-interface hold-down-time 30
    """
    #uut.configure(cmd1)
    c1 = int(count/2)-1
    vni1 = vni
    vni2 = vni1 + c1 
    for vni in range(vni,vni+c1):
        #cmd = " "
        #cmd += 'interface nve1\n' 
        cmd1 += 'member vni {vni}\n'.format(vni=vni)
        cmd1 += 'suppress-arp\n' 
        cmd1 += 'ingress-replication protocol bgp\n' 
 
    try:
        uut.configure(cmd1)
    except:
        log.info('vni_configure failed for uut %r',uut)

def nve_configure_only_bgp_xconnect(uut,vni,count):
    cmd1 = \
            '''
            no interface nve1
            interface nve1
            no shutdown
            host-reachability protocol bgp

            source-interface loopback0
            source-interface hold-down-time 30
            '''
 

    vni1 = vni 
    vni2 = vni1 + count - 1
    for vni in range(vni1,vni2):
        #cmd = " "
        #cmd += 'interface nve1\n' 
        cmd1 += 'member vni {vni}\n'.format(vni=vni)
        cmd1 += 'suppress-arp\n' 
        cmd1 += 'ingress-replication protocol bgp\n' 
    try:
        uut.configure(cmd1)
    except:
        log.error('vni_configure failed for uut %r',uut)

 
def ipAddRemoveAdd(uut,intf): 
    log.info(banner("Starting ipAddRemoveAdd "))     
    
    op = uut.execute('show run interface {intf}'.format(intf=intf))  
    cfg1 = \
    """
    interface {intf}
    """
    cfg2 = \
    """
    interface {intf}
    """
    op1 = op.splitlines()
    for line in op1:
        if 'ip address' in line:
            cfg1 += 'no {line}\n'.format(line=line)
            cfg1 += 'sleep 2\n'
            cfg1 += '{line}\n'.format(line=line)                
        elif 'ip unnumbered' in line:
            cfg1 += 'no {line}\n'.format(line=line)
            cfg1 += 'sleep 2\n'
            cfg1 += '{line}\n'.format(line=line)   


    uut.configure(cfg1.format(intf=intf),timeout=40)


 
def ipAddRemoveClearIprouteIpAdd(uut,intf): 
    log.info(banner("Starting ipAddRemoveAdd "))     
    
    op = uut.execute('show run interface {intf}'.format(intf=intf))  
    cfg1 = \
    """
    interface {intf}
    """
    cfg2 = \
    """
    interface {intf}
    """
    op1 = op.splitlines()
    for line in op1:
        if 'ip address' in line:
            cfg1 += 'no {line}\n'.format(line=line)
            cfg1 += 'sleep 2\n'
            cfg2 += '{line}\n'.format(line=line)                
        elif 'ip unnumbered' in line:
            cfg1 += 'no {line}\n'.format(line=line)
            cfg1 += 'sleep 2\n'
            cfg2 += '{line}\n'.format(line=line)  

    
    uut.configure(cfg1.format(intf=intf),timeout=40)
    uut.execute('clear ip route *')
    uut.configure(cfg2.format(intf=intf),timeout=40)

 
def ipAddRemoveClearIpBgpIpAdd(uut,intf): 
    log.info(banner("Starting ipAddRemoveAdd "))     
    
    op = uut.execute('show run interface {intf}'.format(intf=intf))  
    cfg1 = \
    """
    interface {intf}
    """
    cfg2 = \
    """
    interface {intf}
    """
    op1 = op.splitlines()
    for line in op1:
        if 'ip address' in line:
            cfg1 += 'no {line}\n'.format(line=line)
            cfg1 += 'sleep 2\n'
            cfg2 += '{line}\n'.format(line=line)                
        elif 'ip unnumbered' in line:
            cfg1 += 'no {line}\n'.format(line=line)
            cfg1 += 'sleep 2\n'
            cfg2 += '{line}\n'.format(line=line)  

    
    uut.configure(cfg1.format(intf=intf),timeout=40)
    uut.execute('clear ip bgp *')
    uut.configure(cfg2.format(intf=intf),timeout=40)



def ipAddRemoveClearBgpallIpAdd(uut,intf): 
    log.info(banner("Starting ipAddRemoveAdd "))     
    
    op = uut.execute('show run interface {intf}'.format(intf=intf))  
    cfg1 = \
    """
    interface {intf}
    """
    cfg2 = \
    """
    interface {intf}
    """
    op1 = op.splitlines()
    for line in op1:
        if 'ip address' in line:
            cfg1 += 'no {line}\n'.format(line=line)
            cfg1 += 'sleep 2\n'
            cfg2 += '{line}\n'.format(line=line)                
        elif 'ip unnumbered' in line:
            cfg1 += 'no {line}\n'.format(line=line)
            cfg1 += 'sleep 2\n'
            cfg2 += '{line}\n'.format(line=line)   
    
    uut.configure(cfg1.format(intf=intf),timeout=40)
    uut.execute('clear bgp all *')
    uut.configure(cfg2.format(intf=intf),timeout=40)


def CoreIPAddressChange(uut_list): 
    log.info(banner("Starting PortVlanMappingCleanup "))     
    cfg = \
    """
    interface {intf}
    ip address {ip}/24
    """  
    
    for uut in uut_list:
        intf_list = []
        op = uut.execute('show ip ospf nei ')
        op1 = op.splitlines()
        for line in op1:
            if 'Eth' in line:
                intf=line.split()[-1]
                intf_list.append(intf)
                op3=uut.execute('show run int {intf}'.format(intf=intf))
                if 'unnumbered' in op3:
                    return 1

            elif 'Po' in line:
                intf=line.split()[-1]
                intf_list.append(intf)
                op4=uut.execute('show run int {intf}'.format(intf=intf))                
                if 'unnumbered' in op4:
                    return 1    

        show_ip_int = uut.execute('show ip interface brief | json-pretty ')
        ip_int_list=json.loads(show_ip_int)  
        int_list=ip_int_list['TABLE_intf']['ROW_intf']
        for i in range(0,len(int_list)):
            if "Po" in int_list[i]["intf-name"]:
                ip = ip_address(int_list[i]['prefix'])
                intf = int_list[i]["intf-name"]
                ip_new = ip+256
                try:
                    uut.configure(cfg.format(intf=intf,ip=ip_new))
                except:    
                    log.info('IP Address change uut is %r, intf is %r',uut,intf)
                    return 0

            elif "Eth" in int_list[i]["intf-name"]:
                ip = ip_address(int_list[i]['prefix'])
                intf = int_list[i]["intf-name"]
                ip_new = ip+256
                try:
                    uut.configure(cfg.format(intf=intf,ip=ip_new))
                except:    
                    log.info('IP Address change uut is %r, intf is %r',uut,intf)
                    return 0


    return 1
   

def CoreIPAddressChangeNew(uut_list,igp): 
    log.info(banner("Starting PortVlanMappingCleanup "))     
    cfg = \
    """
    interface {intf}
    ip address {ip}/24
    """  
    
    for uut in uut_list:
        intf_list = []
        if 'ospf' in igp:
            op = uut.execute('show ip ospf nei ')
        elif 'isis' in igp:
            op = uut.execute('show isis adjacency')
        op1 = op.splitlines()
        for line in op1:
            if 'UP' in line:
                intf = line.split()[-1] 
                intf_list.append(intf) 
                op3=uut.execute('show run int {intf}'.format(intf=intf))
                if 'unnumbered' in op3:
                    return 1

        show_ip_int = uut.execute('show ip interface brief | json-pretty ')
        ip_int_list=json.loads(show_ip_int)  
        int_list=ip_int_list['TABLE_intf']['ROW_intf']
        for i in range(0,len(int_list)):
            if "Po" in int_list[i]["intf-name"]:
                ip = ip_address(int_list[i]['prefix'])
                intf = int_list[i]["intf-name"]
                ip_new = ip+256
                try:
                    uut.configure(cfg.format(intf=intf,ip=ip_new))
                except:    
                    log.info('IP Address change uut is %r, intf is %r',uut,intf)
                    return 0

            elif "Eth" in int_list[i]["intf-name"]:
                ip = ip_address(int_list[i]['prefix'])
                intf = int_list[i]["intf-name"]
                ip_new = ip+256
                try:
                    uut.configure(cfg.format(intf=intf,ip=ip_new))
                except:    
                    log.info('IP Address change uut is %r, intf is %r',uut,intf)
                    return 0


    return 1
def NveSourceIpChange(uut_list,asn,intf): 
    log.info(banner("Starting PortVlanMappingCleanup "))

    shut = \
        """
        interface nve 1
        shut
        """

    no_shut = \
        """
        interface nve 1
        no shut
        """

    for uut in uut_list:
        try:
            uut.configure(shut)
        except:    
            log.info('INVE  SHUT failed uut  %r', uut)
            return 0

    for uut in uut_list:
        cmd =  "interface {intf}"
        op = uut.execute('show run interface {intf}'.format(intf=intf))
        op=op.splitlines()
        for line in op: 
            if "address" in line:
                if not "secondary" in line:
                    ip = line.split()[2][:-3]
                    ip1= ip_address(ip)+100
                elif "secondary" in line:
                    ip_2 = line.split()[2][:-3]
                    ip2 = ip_address(ip_2)+100

        cfgvpc = \
            """
            interface {intf}
            ip address {ip1}/32
            no ip address {ip_2}/32 secondary
            ip address {ip2}/32 secondary
            ip router ospf 1 area 0.0.0.0


            ##router bgp {asn}
            #address-family ipv4 unicast
            #network {ip1}/32
            #network {ip2}/32
            """

        cfgsa = \
            """
            interface {intf}
            ip address {ip1}/32
            ip router ospf 1 area 0.0.0.0


            #router bgp {asn}
            #address-family ipv4 unicast
            #network {ip1}/32
            """
        
        op11 = uut.execute("show run | incl feature")

        if "vpc" in op11:
            try: 
                uut.configure(cfgvpc.format(intf=intf,ip1=ip1,ip2=ip2,ip_2=ip_2,asn=asn))  
            except:    
                log.info('IP change failed uut  %r, intf is %r',uut,intf)
                return 0

        else:
            try: 
                uut.configure(cfgsa.format(intf=intf,ip1=ip1,asn=asn))  
            except:    
                log.info('IP change failed uut  %r, intf is %r',uut,intf)
                return 0


    for uut in uut_list:
        try:
            uut.configure(no_shut)
        except:    
            log.info('INVE No SHUT failed uut  %r', uut)
            return 0
 
    return 1

 
def NveSourceIpChangeFnL(uut_list,intf): 
    log.info(banner("Starting NveSourceIpChangeFnL "))

    shut = \
        """
        interface nve 1
        shut
        """

    no_shut = \
        """
        interface nve 1
        no shut
        """

    for uut in uut_list:
        try:
            log.info("shutting nve")
            uut.configure(shut)
        except:    
            log.info('INVE  SHUT failed uut  %r', uut)
            return 0

    for uut in uut_list:
        cmd =  "interface {intf}"
        op = uut.execute('show run interface {intf}'.format(intf=intf))
        op=op.splitlines()
        for line in op: 
            if "address" in line:
                if not "secondary" in line:
                    ip = line.split()[2][:-3]
                    ip1= ip_address(ip)+100
                elif "secondary" in line:
                    ip_2 = line.split()[2][:-3]
                    ip2 = ip_address(ip_2)+100

        cfgvpc = \
            """
            interface {intf}
            ip address {ip1}/32
            no ip address {ip_2}/32 secondary
            ip address {ip2}/32 secondary
            ip router ospf 1 area 0.0.0.0
            """

        cfgsa = \
            """
            interface {intf}
            ip address {ip1}/32
            ip router ospf 1 area 0.0.0.0
            """

        op11 = uut.execute("show run | incl feature")


        log.info("adding new loop ")
        if "vpc" in op11:
            try: 
                uut.configure(cfgvpc.format(intf=intf,ip1=ip1,ip2=ip2,ip_2=ip_2))  
                #uut.configure(cmd)
            except:    
                log.info('IP change failed uut  %r, intf is %r',uut,intf)
                return 0

        else:
            try: 
                uut.configure(cfgsa.format(intf=intf,ip1=ip1))  
                #uut.configure(cmd)
            except:    
                log.info('IP change failed uut  %r, intf is %r',uut,intf)
                return 0

        cmd = " "
        #cmd += 'interface nve1\n' 
        op3 = uut.execute('show run interface nve 1 | beg nve')
        op33=op3.splitlines()
        for line in op33:
            if line:
                if 'peer-ip' in line:
                    cmd += 'no '+line + '\n'                    
                    ip111 = line.split()[-1]
                    ip222= ip_address(ip111)+100
                    line = 'peer-ip {ip222}'.format(ip222=ip222)
                    #cmd += line + '\n'    
            cmd += line + '\n'  
        #cmd += 'shut \n'
        log.info("--------------------------------------")
        log.info("-------------cmd is %r",cmd)
        log.info("--------------------------------------")
        uut.configure(cmd)  

    for uut in uut_list:
        try:
            uut.configure(no_shut)
        except:    
            log.info('INVE No SHUT failed uut  %r', uut)
            return 0
 
    return 1


 
def NveSourceInterfaceChange(uut_list,asn): 
    log.info(banner("Starting PortVlanMappingCleanup "))
    for uut in uut_list:
        #cmd =  "interface {intf}"


        op = uut.execute("show run interface nve1 | incl loopback")
        log.info("++++++++++++++++++++++++++++++++++++++++++++")
        log.info("OP is %r",op)
        log.info("++++++++++++++++++++++++++++++++++++++++++++")
        #op=op.splitlines()
        #for line in op:
        if 'loop' in str(op):
             intf_num = (findall(r'\d+',str(op)))[0]

        log.info("++++++++++++++++++++++++++++++++++++++++++++")
        log.info("intf_num is %r",intf_num)
        log.info("++++++++++++++++++++++++++++++++++++++++++++")

        #intf_num = findall(r'\d+',op.split())[0]
        op = uut.execute('show run interface loopback {intf_num}'.format(intf_num=intf_num))
        op=op.splitlines()
        for line in op: 
            if "address" in line:
                if not "secondary" in line:
                    ip = line.split()[2][:-3]
                    ip1= ip_address(ip)+20
                elif "secondary" in line:
                    ip22 = line.split()[2][:-3]
                    ip2 = ip_address(ip22)+20

        intf = str(int(intf_num)+100)


        cfgvpc = \
        """
        no interface loopback{intf}
        interface loopback{intf}
        description NVE_New loopback
        ip address {ip1}/32
        ip address {ip2}/32 secondary
        ip pim sparse-mode
        ip router ospf 1 area 0.0.0.0 
        no shut

        #router bgp {asn}
        #address-family ipv4 unicast
        #network {ip1}/32
        #network {ip2}/32
        
        interface nve1
        shut
        sleep 1
        source-interface loopback{intf}
        no shut
        """

        cfgsa = \
        """
        no interface loopback{intf}
        interface loopback{intf}
        description NVE_New loopback
        ip address {ip1}/32
        ip router ospf 1 area 0.0.0.0
        ip pim sparse-mode
        no shut


        #router bgp {asn}
        #address-family ipv4 unicast
        #network {ip1}/32
        
        interface nve1
        shut
        sleep 1
        source-interface loopback{intf}
        no shut
        """
        op11 = uut.execute("show run | incl feature")

        if "vpc" in op11:
            try: 
                log.info("cfgvpc is %r",cfgvpc.format(intf=intf,ip1=ip1,ip22=ip22,ip2=ip2,asn=asn))                
                uut.configure(cfgvpc.format(intf=intf,ip1=ip1,ip2=ip2,ip22=ip22,asn=asn))  
            except:    
                log.info('IP change failed vpc node uut  %r, intf is loopback %r',uut,intf)
                return 0

        else:
            try: 
                log.info("cfgsa is %r",cfgsa.format(intf=intf,ip1=ip1,asn=asn))   
                uut.configure(cfgsa.format(intf=intf,ip1=ip1,asn=asn))  
            except:    
                log.info('IP change failed uut  %r, intf is loopback%r',uut,intf)
                return 0
 
    return 1



def NveSourceInterfaceChangeFnL(uut_list): 
    log.info(banner("Starting PortVlanMappingCleanup "))

    cmd_shut = \
        """
        interface nve1
        shut
        sleep 1
        """    
    cmd_no_shut = \
        """
        interface nve1
        no shut
        sleep 1
        """    

    for uut in uut_list:
        uut.configure(cmd_shut)
    
    for uut in uut_list:
        op = uut.execute("show run interface nve1 | incl loopback")
        log.info("++++++++++++++++++++++++++++++++++++++++++++")
        log.info("OP is %r",op)
        log.info("++++++++++++++++++++++++++++++++++++++++++++")
        #op=op.splitlines()
        #for line in op:
        if 'loop' in str(op):
             intf_num = (findall(r'\d+',str(op)))[0]

        log.info("++++++++++++++++++++++++++++++++++++++++++++")
        log.info("intf_num is %r",intf_num)
        log.info("++++++++++++++++++++++++++++++++++++++++++++")

        #intf_num = findall(r'\d+',op.split())[0]
        op = uut.execute('show run interface loopback {intf_num}'.format(intf_num=intf_num))
        op=op.splitlines()
        for line in op: 
            if "address" in line:
                if not "secondary" in line:
                    ip = line.split()[2][:-3]
                    ip1= ip_address(ip)+20
                elif "secondary" in line:
                    ip22 = line.split()[2][:-3]
                    ip2 = ip_address(ip22)+20

        intf = str(int(intf_num)+100)


        cfgvpc = \
        """
        no interface loopback{intf}
        interface loopback{intf}
        description NVE_New loopback
        ip address {ip1}/32
        ip address {ip2}/32 secondary
        ip pim sparse-mode
        ip router ospf 1 are 0
        no shut
        interface nve1
        source-interface loopback{intf}
        """

        cfgsa = \
        """
        no interface loopback{intf}
        interface loopback{intf}
        description NVE_New loopback
        ip address {ip1}/32
        ip pim sparse-mode
        ip router ospf 1 are 0
        no shut
        interface nve1
        source-interface loopback{intf}
        """
 
        op11 = uut.execute("show run | incl feature")

        if "vpc" in op11:
            try: 
                log.info("cfgvpc is %r",cfgvpc.format(intf=intf,ip1=ip1,ip22=ip22,ip2=ip2))                
                uut.configure(cfgvpc.format(intf=intf,ip1=ip1,ip2=ip2,ip22=ip22))  
            except:    
                log.info('IP change failed vpc node uut  %r, intf is loopback %r',uut,intf)
                return 0

        else:
            try: 
                log.info("cfgsa is %r",cfgsa.format(intf=intf,ip1=ip1))   
                uut.configure(cfgsa.format(intf=intf,ip1=ip1))  
            except:    
                log.info('IP change failed uut  %r, intf is loopback%r',uut,intf)
                return 0


    for uut in uut_list:
        cmd = " "
        op3 = uut.execute('show run interface nve 1 | beg nve')
        op33=op3.splitlines()
        for line in op33:
            if line:
                if 'peer-ip' in line:
                    cmd += 'no '+line + '\n'                    
                    ip111 = line.split()[-1]
                    ip222= ip_address(ip111)+20
                    line = 'peer-ip {ip222}'.format(ip222=ip222)
                    #cmd += line + '\n'    
            cmd += line + '\n'  
        #cmd += 'shut \n'
        log.info("--------------------------------------")
        log.info("-------------cmd is %r",cmd)
        log.info("--------------------------------------")
        uut.configure(cmd)  

    for uut in uut_list:
        uut.configure(cmd_no_shut)

 
    return 1


 

def msTrmTrafficTest(port_handle_rx_list,orphan_handle_list,expected_rate):
    diff = int(expected_rate*.05)
    for port_hdl in port_handle_rx_list:
        if port_hdl:   
            #res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            #rx_rate = res['item0']['PortRxTotalFrameRate']
            try:            
                res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            except:
                log.info('Stats failed for port %r',port_hdl)
                return 0
            try:               
                rx_rate = res['item0']['PortRxTotalFrameRate']
            except:
                log.info('rx_rate failed for port %r',port_hdl)
                return 0

            log.info('+----------------IGMP HOSTS CONNECTED ---------------------------------+')
            log.info('+-------------  DIFF  at Port %r is : %r ------+',port_hdl,diff)
            log.info('+---- Actual RX rate at Port %r is : %r ------+',port_hdl,rx_rate)
            log.info('+---- Expected RX rate at Port %r is : %r ------+',port_hdl,expected_rate)
            log.info('+----------------------------------------------------------------------+')
            if abs(int(rx_rate) - int(expected_rate)) > diff:
                log.info('Traffic  Rate Test failed for %r',port_hdl)
                log.info('Stats are %r',res)
                return 0

    for port_hdl in orphan_handle_list:
        if port_hdl:
            #res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            #rx_rate = res['item0']['PortRxTotalFrameRate']

            try:            
                res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            except:
                log.info('Stats failed for port %r',port_hdl)
                return 0
            try:               
                rx_rate = res['item0']['PortRxTotalFrameRate']
            except:
                log.info('rx_rate failed for port %r',port_hdl)
                return 0

            log.info('+---------------NO IGMP HOSTS CONNECTED,NO TRAFFIC EXPECTED------------+')
            log.info('+---- Actual RX rate at Port %r is : %r ------+',port_hdl,rx_rate)
            log.info('+---- Expected RX rate at Port %r is : %r ------+',port_hdl,'0')
            log.info('+----------------------------------------------------------------------+')
            if abs(int(rx_rate)) > 1000:
                log.info('Traffic  Rate Test failed for %r',port_hdl)
                log.info('Stats are %r',res)
                return 0
    return 1

 

def msTrmTrafficTestFull(**kwargs):
    log.info(banner('msTrmTrafficTest')) 
    #log.info('1111  kwargs are %r',kwargs)

    port_handle_list = []
    rx_rate_list = []

    for arg in kwargs:
        if 'port001' in arg:
            port1 = kwargs['port001']
            port_handle_list.append(port1)
        elif 'rx_rate001' in arg:
            rx_rate1 = kwargs['rx_rate001']
            rx_rate_list.append(rx_rate1)
        elif 'port002' in arg:
            port2 = kwargs['port002']
            port_handle_list.append(port2)
        elif 'rx_rate002' in arg:
            rx_rate2 = kwargs['rx_rate002']
            rx_rate_list.append(rx_rate2)
        elif 'port003' in arg:
            port3 = kwargs['port003']
            port_handle_list.append(port3)
        elif 'rx_rate003' in arg:
            rx_rate3 = kwargs['rx_rate003']
            rx_rate_list.append(rx_rate3)
        elif 'port004' in arg:
            port4 = kwargs['port004']
            port_handle_list.append(port4)
        elif 'rx_rate004' in arg:
            rx_rate4 = kwargs['rx_rate004']
            rx_rate_list.append(rx_rate4)

    log.info('port_handle_list is %r',port_handle_list)
    log.info('rx_rate_list is %r',rx_rate_list)

    for port_hdl,exp_rate in zip(port_handle_list,rx_rate_list):
        diff = int(exp_rate*.035)
        if port_hdl:   
            #res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            #rx_rate = res['item0']['PortRxTotalFrameRate']
            try:            
                res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            except:
                log.info('Stats failed for port %r',port_hdl)
                return 0
            try:               
                rx_rate = res['item0']['PortRxTotalFrameRate']
            except:
                log.info('rx_rate failed for port %r',port_hdl)
                return 0

            log.info('+------------------------------------------------------+')
            log.info('+-------------  DIFF  at Port %r is : %r ------+',port_hdl,diff)
            log.info('+---- Actual RX rate at Port %r is : %r ------+',port_hdl,rx_rate)
            log.info('+---- Expected RX rate at Port %r is : %r ------+',port_hdl,exp_rate)
            log.info('+----------------------------------------------------------------------+')
            if abs(int(rx_rate) - int(exp_rate)) > diff:
                log.info('Traffic  Rate Test failed for %r',port_hdl)
                log.info('Stats are %r',res)
                return 0
    return 1



def msTrmTrafficTestFullTimed(**kwargs):
    log.info(banner('msTrmTrafficTest')) 
    port_handle_list = []
    rx_rate_list = []
    for arg in kwargs:
        if 'port001' in arg:
            port1 = kwargs['port001']
            port_handle_list.append(port1)
        elif 'rx_rate001' in arg:
            rx_rate1 = kwargs['rx_rate001']
            rx_rate_list.append(rx_rate1)
        elif 'port002' in arg:
            port2 = kwargs['port002']
            port_handle_list.append(port2)
        elif 'rx_rate002' in arg:
            rx_rate2 = kwargs['rx_rate002']
            rx_rate_list.append(rx_rate2)
        elif 'port003' in arg:
            port3 = kwargs['port003']
            port_handle_list.append(port3)
        elif 'rx_rate003' in arg:
            rx_rate3 = kwargs['rx_rate003']
            rx_rate_list.append(rx_rate3)
        elif 'port004' in arg:
            port4 = kwargs['port004']
            port_handle_list.append(port4)
        elif 'rx_rate004' in arg:
            rx_rate4 = kwargs['rx_rate004']
            rx_rate_list.append(rx_rate4)
    log.info('port_handle_list is %r',port_handle_list)
    log.info('rx_rate_list is %r',rx_rate_list)

    fail_list = []

    for port_hdl,exp_rate in zip(port_handle_list,rx_rate_list):
        diff = int(exp_rate*.035)
        #if port_hdl:   
        for i in range(1,50):            
            #res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            #rx_rate = res['item0']['PortRxTotalFrameRate']
            try:            
                res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            except:
                log.info('Stats failed for port %r',port_hdl)
                return 0
            try:               
                rx_rate = res['item0']['PortRxTotalFrameRate']
            except:
                log.info('rx_rate failed for port %r',port_hdl)
                return 0


            log.info('+------------------------------------------------------+')
            log.info('+-------------  DIFF  at Port %r is : %r ------+',port_hdl,diff)
            log.info('+---- Actual RX rate at Port %r is : %r ------+',port_hdl,rx_rate)
            log.info('+---- Expected RX rate at Port %r is : %r ------+',port_hdl,exp_rate)
            log.info('+----------------------------------------------------------------------+')
            if abs(int(rx_rate) - int(exp_rate)) < diff:
                log.info('Passed msTrmTrafficTestFullTimed for port %r, Time is  %r , breaking loop',port_hdl,i)
                break    
            else:                     
                countdown(10)                        
                log.info('repeating test @ port %r , Time elapsed ++ %r',port_hdl,int(i)*10)
            if i > 48:
                if abs(int(rx_rate) - int(exp_rate)) > diff:           
                    log.info('completed 800 sec , failed test @ port %r',port_hdl)           
                    fail_list.append('fail')

            if 'fail' in fail_list:
                return 0

    else:
        log.info('Passed msTrmTrafficTestFullTimed, Time is ++++++ %r',i)        
        return 1    

           

def rateTest(port_hdl,exp_rate):
    #log.info(banner('rateTest'))
    diff = int(exp_rate*.035)
    for i in range(1,50):
        #countdown(1)
        try:            
            res = ixiangpf.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
        except:
            log.error('Stats failed for port %r',port_hdl)
            #return 0
        try:               
            rx_rate = res['item0']['PortRxTotalFrameRate']
            #log.info('+-------------------------------------------------------------------------+')
            log.info('+ + + + + Port:%r,diff: %r,RX:%r, Exp: %r + + + + + ',port_hdl,diff,rx_rate,exp_rate)
            #log.info('+-------------------------------------------------------------------------+')

        except:
            log.error('rx_rate failed for port %r',port_hdl)
            #return 0

        if i < 48:
            if abs(int(rx_rate) - int(exp_rate)) < diff:         
                #log.info('Passed rateTest for port %r, Time is  %r , breaking loop',port_hdl,i)
                return 1 
            else:                     
                countdown(10)                        
                #log.info('repeating test @ port %r , Time elapsed ++ %r',port_hdl,int(i)*10)       
        else:
            if abs(int(rx_rate) - int(exp_rate)) > diff:         
                #log.info('completed 480 sec , failed test @ port %r',port_hdl)           
                return 0



def bgw_peer_check(bgw_uut_list):
 
    peer_list = []

    for uut in bgw_uut_list:
        loopback100_ip = str(uut.interfaces['loopback100'].ipv4)[:-3]
        loopback0_ip = str(uut.interfaces['loopback0'].ipv4)[:-3]
        peer_list.append(loopback100_ip)
        peer_list.append(loopback0_ip)

    for uut in bgw_uut_list:
        loopback100_ip = str(uut.interfaces['loopback100'].ipv4)[:-3]
        loopback0_ip = str(uut.interfaces['loopback0'].ipv4)[:-3]
        op=uut.execute('show nve peers')
        for peer in peer_list:
            if not loopback100_ip in peer:
                if not loopback0_ip in peer:
                    if not '2.0.0.112' in peer:
                        if not peer in op:
                            log.info('peer ip %r not found for UUT %r',peer,uut)
                            return 0

    return 1  
            


def multiSitetrmClicheck(uut):
    fail_list = []
    cli1 = 'multisite border-gateway'
    cli2 = 'multisite ingress-replication optimized'
    op1 = uut.execute('show run | incl multisite')
    if not cli1 in op1:
        fail_list.append('fail')
    if not cli2 in op1:
        fail_list.append('fail')
    
    if 'fail' in fail_list:
        return 0
    else:
        return 1
        


def verify_ip(mcast_ip):
    """
    This function takes a multicast IP (string) as an argument
    and returns True if IP address is correct
    """
    if len(mcast_ip) < 9 or len(mcast_ip) > 15:
        #log.info('Multicast IP address length is incorrect !')
        return False
    octets = mcast_ip.split(".")
    if len(octets) < 4:
        #log.info('Incorrect number of octets in multicast IP address !')
        return False
    for idx in range(0,4):
        if not(verify_octet(octets[idx])):
            log.info('One of the octets is incorrect !')
            return False
    # Check if first octet is from mcast range     
    if int(octets[0]) < 224 or int(octets[0]) > 239:
        #log.info('First octet isn’t from multicast range ! Should be 224 … 239 !')
        return False
    return True

def verify_octet(octet):
    """
    This function returns True if string parameter ‘octet’ is a number in the range 0…255
    """
    if octet.isdigit:
        octet_num = int(octet)
        if octet_num >= 0 and octet_num <=255:
            return True
        return False

def ip2mac(mcast_ip):
    """
    Function ip2mac takes multicast IP address as an argument and returns multicast MAC address
    """
    if not(verify_ip(mcast_ip)):
        log.info('Parameter provided is not a valid multicast IP ! Should be 224.0.0.1 … 239.255.255.255')
        sys.exit(0)
    mcast_mac =  "01:00:5e:"
    octets = mcast_ip.split(".")
    second_oct = int(octets[1]) & 127
    third_oct = int(octets[2])
    fourth_oct = int(octets[3])
    mcast_mac = mcast_mac + format(second_oct,"02x") + ":" + format(third_oct, "02x") + ":" + format(fourth_oct, "02x")
    return mcast_mac


   
def trmCheck(fhr_list,lhr_list,bgw_list,l3_scale,group_list):
    log.info(banner('++++++++ trmCheck++++++++'))
    fail_list = []
    
    for group in group_list:
        for uut in fhr_list:
            if not trmcheckFhr(fhr_list,l3_scale,group):
                fail_list.append('fail')            
        for uut in lhr_list:
            if not trmcheckLhr(lhr_list,l3_scale,group):
                fail_list.append('fail')  
        for uut in bgw_list:
            if not trmcheckBgw(bgw_list,l3_scale,group):
                fail_list.append('fail')                 
           
    if 'fail' in fail_list:
        return 0
    else:
        return 1
   

def trmcheckFhr(uut_list,l3_scale,group):
    fail_list = []
    for uut in uut_list:
        op1 = uut.execute('show ip mroute vrf all  | inc {group} | count'.format(group=group),timeout=40)
        op2 = uut.execute('show bgp ipv4 mvpn route-type 5 | inc {group} |  count'.format(group=group),timeout=40)
        op3 = uut.execute('show bgp ipv4 mvpn route-type 5 detail | incl "Path-id 1 advertised to peers" | count')
        op4 = uut.execute('show bgp ipv4 mvpn route-type 7 | inc {group} |  count'.format(group=group),timeout=40)

        if not int(l3_scale)  <=  int(op1):
            log.info('MRIB Not Full @ Node %r',uut)
            fail_list.append('fail') 

        if not int(l3_scale) <=  int(op2):
            log.info('mvpn Type5 Not Full @ Node %r',uut)
            fail_list.append('fail') 

        if not int(l3_scale) <=  int(op3):
            log.info('mvpn Type5 Not advertised  Full @ Node %r',uut)
            fail_list.append('fail') 

        if not int(l3_scale) <=  int(op4):
            log.info('mvpn7routecheck trmcheckFhr fail in Node %r',uut)
            fail_list.append('fail')


    if 'fail' in fail_list:
        return 0
    else:
        return 1

def trmcheckLhr(uut_list,l3_scale,group):
    fail_list = []
    for uut in uut_list:
        op1 = uut.execute('show ip mroute vrf all  | inc {group} | count'.format(group=group),timeout=40)
        op2 = uut.execute('show bgp ipv4 mvpn route-type 5 | inc {group} |  count'.format(group=group),timeout=40)
        op3 = uut.execute('show bgp ipv4 mvpn route-type 7 | inc {group} |  count'.format(group=group),timeout=40)
        op4 = uut.execute('show bgp ipv4 mvpn route-type 7 detail | incl "Path-id 1 advertised to peers" | count')
        op5 = uut.execute('show ip igmp groups vrf all | incl 23 | count')
   
        if not int(l3_scale)  <=  int(op1):
            log.info('MRIB Not Full @ Node %r',uut)
            fail_list.append('fail') 

        if not int(l3_scale) <=  int(op2):
            log.info('mvpn Type5 Not Full @ Node %r',uut)
            fail_list.append('fail') 

        if not int(l3_scale) <=  int(op3):
            log.info('mvpn Type7 Not Full @ Node %r',uut)
            fail_list.append('fail') 

        if not int(l3_scale) <=  int(op4):
            log.info('mvpn Type7 Not advertised Full @ Node %r',uut)
            fail_list.append('fail')

        if not int(l3_scale*8)  <=  int(op5):
            log.info('igmp groups Not Full @ Node %r',uut)
            fail_list.append('fail') 


    if 'fail' in fail_list:
        return 0
    else:
        return 1
 

def trmcheckBgw(uut_list,l3_scale,group):
    fail_list = []
    for uut in uut_list:
        op1 = uut.execute('show ip mroute vrf all  | inc {group} | count'.format(group=group),timeout=40)
        op2 = uut.execute('show bgp ipv4 mvpn route-type 5 | inc {group} |  count'.format(group=group),timeout=40)
        op3 = uut.execute('show bgp ipv4 mvpn route-type 5 detail | incl "Path-id 1 advertised to peers" | count')
        op4 = uut.execute('show bgp ipv4 mvpn route-type 7 | inc {group} |  count'.format(group=group),timeout=40)
        op5 = uut.execute('show bgp ipv4 mvpn route-type 7 detail | incl "Path-id 1 advertised to peers" | count')

        if not int(l3_scale)  <=  int(op1):
            log.info('MRIB Not Full @ Node %r',uut)
            fail_list.append('fail') 

        if not int(l3_scale) <=  int(op2):
            log.info('mvpn Type5 Not Full @ Node %r',uut)
            fail_list.append('fail') 

        if not int(l3_scale) <=  int(op3):
            log.info('mvpn Type5 Not advertised Full @ Node %r',uut)
            fail_list.append('fail')

        if not int(l3_scale) <=  int(op4):
            log.info('mvpn Type7 Not Full @ Node %r',uut)
            fail_list.append('fail') 

        if not int(l3_scale) <=  int(op5):
            log.info('mvpn Type7 Not advertised Full @ Node %r',uut)
            fail_list.append('fail')

    if 'fail' in fail_list:
        return 0
    else:
        return 1


def igmpRouteCheckLhr(uut,l2_scale,l3_scale,group):
    fail_list = []
    op1 = uut.execute('sh ip igmp groups vrf all | incl {group} | count'.format(group=group),timeout=40)
    if not op1==scale:
        log.info('IGMP entry not full at LHR %r',uut)
        fail_list.append('fail')

    op = uut.execute('show nve vni  | incl L3')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            for vrf in line.split():
                if 'vxlan-' in vrf:
                    vrf = vrf.replace("[","").replace("]","")
                    log.info('vrf is %r',vrf)
                    vrf_list.append(vrf) 

    if 'fail' in fail_list:
        return 0
    else:
        return 1
        

def randomVrfForTrmTest(uut,number_of_l3_vrf):
    op = uut.execute('show nve vni  | incl L3')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            for vrf in line.split():
                if 'vxlan-' in vrf:
                    vrf = vrf.replace("[","").replace("]","")
                    log.info('vrf is %r',vrf)
                    vrf_list.append(vrf)

    test_vrf_list = []
    for i in range(1,number_of_l3_vrf+1):
        vrf = choice(vrf_list) 
        test_vrf_list.append(vrf) 
    log.info('test_vrf_list is %r',test_vrf_list)
    return test_vrf_list
                       
 


def vtepEmulationmSite(uut,vtep_scale,port_handle_spine1):
    threads = []
    for uut in [uut]:
        for intf in uut.interfaces.keys():
            if 'tgn1_intf1' in intf:
                intf_1 = uut.interfaces[intf].intf
                ipv4_1 = uut.interfaces[intf].ipv4
                cfg = """\
                        interface {intf}
                        no switchport
                        ip address {ipv4}
                        no shut
                        """
                uut.configure(cfg.format(intf=intf_1,ipv4=ipv4_1))

    for uut in [uut]:
        adv_nwk_list_tgn =[]
        neight_list_spine_tgn = []
        for intf in uut.interfaces.keys():
            if 'loopback1' in intf:
                intf = uut.interfaces[intf].intf
                bgp_rid=(str(uut.interfaces[intf].ipv4))[:-3]
                
            elif 'tgn' in intf:
                intf_tgn = uut.interfaces[intf].intf
                leaf_tgn_ip=str(uut.interfaces[intf].ipv4) 
                leaf_neigh=leaf_tgn_ip.split('/')[0][:-1]+'0/8'
                neight_list_spine_tgn.append(leaf_neigh)
                adv_nwk_list_tgn.append(leaf_neigh)

        #if 'yes' in vtep_emulation_spirent:
        spine_bgp_obj2=IbgpSpineNode(uut,bgp_rid,'99',adv_nwk_list_tgn,neight_list_spine_tgn,intf_tgn,'ibgp-vxlan-tgn')
        t3 = threading.Thread(target= spine_bgp_obj2.bgp_conf)
        threads.append(t3)

    for t in threads: 
        t.start()
    for t in threads: 
        t.join(100)  

    cfg = \
    """
      router bgp 99
      template peer ibgp-vxlan-tgn
      address-family ipv4 mvpn
      disable-peer-as-check
      send-community
      send-community extended
      route-map unchanged out
      rewrite-rt-asn
    """
    uut.configure(cfg)

    
    log.info(banner("S T A R T I N G     vTEP     E M U L A T I O N "))       
    log.info(" Configuration time depends on scale , Current Scale is %r",vtep_scale)
    start_time = time.time()
                    

    scale = vtep_scale
    leaf_tgn_ip1 = leaf_tgn_ip.split('/')[0]
    bgp_host1_ip1 = leaf_tgn_ip.split('/')[0][:-1]+'2'

    bgp1 = ixiangpf.emulation_bgp_config (
                mode='enable',
                port_handle=port_handle_spine1,
                count=scale,
                active_connect_enable=1,
                ip_version=4,
                local_ip_addr=bgp_host1_ip1,
                netmask='8',
                remote_ip_addr=leaf_tgn_ip1,
                next_hop_ip=leaf_tgn_ip1,
                local_as=99,
                local_router_id=bgp_host1_ip1,
                remote_as=99,
                local_addr_step='0.0.0.1',
                retry_time=30,
                retries=10,
                routes_per_msg=20,
                hold_time=180,
                update_interval=45,
                ipv4_unicast_nlri=1,
                ipv4_e_vpn_nlri=1,
                graceful_restart_enable=1,
                restart_time=200)


 


    bgp_dev_list = []
    bgp_dev = 'emulateddevice'
    for i in range(1,(scale+1)):
        bgp_dev1 = bgp_dev+str(i)
        bgp_dev_list.append(bgp_dev1)
 

    ip = IPv4Address(bgp_host1_ip1)
    ip2 = IPv4Address(bgp_host1_ip1)+500
    ip_list = []
    ip_list2 = []
    for i in range(0,scale):
        ip_list.append(ip)
        ip = ip + i

    for i in range(0,scale):
        ip_list.append(ip2)
        ip2 = ip2 + i

    mac_add1 = str(RandMac("00:00:00:00:00:00", True))
    mac_add = mac_add1.replace("'","")
 
    for router,ip in zip(bgp_dev_list,ip_list):

        type3 = ixiangpf.emulation_bgp_route_config (
                mode = 'add',
                handle = router,
                evpn_type3_agg_ip = str(ip),
                route_type = 'evpn_type3',
                evpn_type3_community='65001:1',
                evpn_type3_data_plane_encap='vxlan',
                evpn_type3_encap_label='101001',
                evpn_type3_origin='igp',
                evpn_type3_route_target='65001:101001',
                )
        type2 = ixiangpf.emulation_bgp_route_config (
                mode = 'add',
                handle = router,
                evpn_type2_mac_addr_start =mac_add,
                route_type = 'evpn_type2',
                evpn_type2_community='65001:1',
                evpn_type2_data_plane_encap ='vxlan',
                evpn_type2_encap_label='101001',
                evpn_type2_origin='igp',
                evpn_type2_route_target ='65001:101001',
                )

        #type5 = ixiangpf.emulation_bgp_route_config (
        #        mode = 'add',
        #        handle = router,
        #        evpn_type5_agg_ip = str(ip2),
        #        route_type = 'evpn_type5',
        #        evpn_type5_community='65001:1',
        #        evpn_type5_data_plane_encap ='vxlan',
        #        evpn_type5_encap_label='101001',
        #        evpn_type5_origin='incomplete',
        #        evpn_type5_route_target ='65001:101001',
        #        )

    bgp1_start1 = ixiangpf.emulation_bgp_control (
            handle = bgp_dev_list,
            mode = 'start')

    elapsed_time = time.time() - start_time
    log.info(banner("C O M P L E A T E D    vTEP   E M U L A T I O N  "))
    log.info("Time taken for Simulating %r vTEP's is %r",vtep_scale,elapsed_time)
    return 1


def vtepEmulationBgpConf(uut,vtep_scale):
    threads = []
    for uut in [uut]:
        for intf in uut.interfaces.keys():
            if 'tgn1_intf1' in intf:
                intf_1 = uut.interfaces[intf].intf
                ipv4_1 = uut.interfaces[intf].ipv4
                cfg = """\
                        interface {intf}
                        no switchport
                        ip address {ipv4}
                        no shut
                        """
                uut.configure(cfg.format(intf=intf_1,ipv4=ipv4_1))

    for uut in [uut]:
        adv_nwk_list_tgn =[]
        neight_list_spine_tgn = []
        for intf in uut.interfaces.keys():
            if 'loopback1' in intf:
                intf = uut.interfaces[intf].intf
                bgp_rid=(str(uut.interfaces[intf].ipv4))[:-3]
                
            elif 'tgn' in intf:
                intf_tgn = uut.interfaces[intf].intf
                leaf_tgn_ip=str(uut.interfaces[intf].ipv4) 
                leaf_neigh=leaf_tgn_ip.split('/')[0][:-1]+'0/8'
                neight_list_spine_tgn.append(leaf_neigh)
                adv_nwk_list_tgn.append(leaf_neigh)

        #if 'yes' in vtep_emulation_spirent:
        spine_bgp_obj2=IbgpSpineNode(uut,bgp_rid,'99',adv_nwk_list_tgn,neight_list_spine_tgn,intf_tgn,'ibgp-vxlan-tgn')
        t3 = threading.Thread(target= spine_bgp_obj2.bgp_conf)
        threads.append(t3)

    for t in threads: 
        t.start()
    for t in threads: 
        t.join(100)  

    cfg = \
    """
      router bgp 99
      template peer ibgp-vxlan-tgn
      address-family ipv4 mvpn
      disable-peer-as-check
      send-community
      send-community extended
      route-map unchanged out
      rewrite-rt-asn
    """
    uut.configure(cfg)



def SpirentVtepEmulation(port_handle_spine1):    
    log.info(banner("S T A R T I N G     vTEP     E M U L A T I O N "))       
    log.info(" Configuration time depends on scale , Current Scale is %r",vtep_scale)
    start_time = time.time()
                    

    scale = vtep_scale
    leaf_tgn_ip1 = leaf_tgn_ip.split('/')[0]
    bgp_host1_ip1 = leaf_tgn_ip.split('/')[0][:-1]+'2'

    bgp1 = ixiangpf.emulation_bgp_config (
                mode='enable',
                port_handle=port_handle_spine1,
                count=scale,
                active_connect_enable=1,
                ip_version=4,
                local_ip_addr=bgp_host1_ip1,
                netmask='8',
                remote_ip_addr=leaf_tgn_ip1,
                next_hop_ip=leaf_tgn_ip1,
                local_as=99,
                local_router_id=bgp_host1_ip1,
                remote_as=99,
                local_addr_step='0.0.0.1',
                retry_time=30,
                retries=10,
                routes_per_msg=20,
                hold_time=180,
                update_interval=45,
                ipv4_unicast_nlri=1,
                ipv4_e_vpn_nlri=1,
                graceful_restart_enable=1,
                restart_time=200)


    bgp_dev_list = []
    bgp_dev = 'emulateddevice'
    for i in range(1,(scale+1)):
        bgp_dev1 = bgp_dev+str(i)
        bgp_dev_list.append(bgp_dev1)
 

    ip = IPv4Address(bgp_host1_ip1)
    ip2 = IPv4Address(bgp_host1_ip1)+500
    ip_list = []
    ip_list2 = []
    for i in range(0,scale):
        ip_list.append(ip)
        ip = ip + i

    for i in range(0,scale):
        ip_list.append(ip2)
        ip2 = ip2 + i

    mac_add1 = str(RandMac("00:00:00:00:00:00", True))
    mac_add = mac_add1.replace("'","")
 
    for router,ip in zip(bgp_dev_list,ip_list):

        type3 = ixiangpf.emulation_bgp_route_config (
                mode = 'add',
                handle = router,
                evpn_type3_agg_ip = str(ip),
                route_type = 'evpn_type3',
                evpn_type3_community='65001:1',
                evpn_type3_data_plane_encap='vxlan',
                evpn_type3_encap_label='101001',
                evpn_type3_origin='igp',
                evpn_type3_route_target='65001:101001',
                )
        type2 = ixiangpf.emulation_bgp_route_config (
                mode = 'add',
                handle = router,
                evpn_type2_mac_addr_start =mac_add,
                route_type = 'evpn_type2',
                evpn_type2_community='65001:1',
                evpn_type2_data_plane_encap ='vxlan',
                evpn_type2_encap_label='101001',
                evpn_type2_origin='igp',
                evpn_type2_route_target ='65001:101001',
                )

    bgp1_start1 = ixiangpf.emulation_bgp_control (
            handle = bgp_dev_list,
            mode = 'start')

    elapsed_time = time.time() - start_time
    log.info(banner("C O M P L E A T E D    vTEP   E M U L A T I O N  "))
    log.info("Time taken for Simulating %r vTEP's is %r",vtep_scale,elapsed_time)
    return 1




def vtepEmulation(uut,vtep_scale,port_handle_spine1):
    threads = []
    for uut in [uut]:
        for intf in uut.interfaces.keys():
            if 'tgn1_intf1' in intf:
                intf_1 = uut.interfaces[intf].intf
                ipv4_1 = uut.interfaces[intf].ipv4
                cfg = """\
                        interface {intf}
                        no switchport
                        ip address {ipv4}
                        no shut
                        """
                uut.configure(cfg.format(intf=intf_1,ipv4=ipv4_1))

    for uut in [uut]:
        adv_nwk_list_tgn =[]
        neight_list_spine_tgn = []
        for intf in uut.interfaces.keys():
            if 'loopback1' in intf:
                intf = uut.interfaces[intf].intf
                bgp_rid=(str(uut.interfaces[intf].ipv4))[:-3]
                
            elif 'tgn' in intf:
                intf_tgn = uut.interfaces[intf].intf
                leaf_tgn_ip=str(uut.interfaces[intf].ipv4) 
                leaf_neigh=leaf_tgn_ip.split('/')[0][:-1]+'0/8'
                neight_list_spine_tgn.append(leaf_neigh)
                adv_nwk_list_tgn.append(leaf_neigh)

        #if 'yes' in vtep_emulation_spirent:
        spine_bgp_obj2=IbgpSpineNode(uut,bgp_rid,'65001',adv_nwk_list_tgn,neight_list_spine_tgn,intf_tgn,'ibgp-vxlan-tgn')
        t3 = threading.Thread(target= spine_bgp_obj2.bgp_conf)
        threads.append(t3)

    for t in threads: 
        t.start()
    for t in threads: 
        t.join(100)  
    
    log.info(banner("S T A R T I N G     vTEP     E M U L A T I O N "))       
    log.info(" Configuration time depends on scale , Current Scale is %r",vtep_scale)
    start_time = time.time()
                    

    scale = vtep_scale
    leaf_tgn_ip1 = leaf_tgn_ip.split('/')[0]
    bgp_host1_ip1 = leaf_tgn_ip.split('/')[0][:-1]+'2'

    bgp1 = ixiangpf.emulation_bgp_config (
                mode='enable',
                port_handle=port_handle_spine1,
                count=scale,
                active_connect_enable=1,
                ip_version=4,
                local_ip_addr=bgp_host1_ip1,
                netmask='8',
                remote_ip_addr=leaf_tgn_ip1,
                next_hop_ip=leaf_tgn_ip1,
                local_as=65001,
                local_router_id=bgp_host1_ip1,
                remote_as=65001,
                local_addr_step='0.0.0.1',
                retry_time=30,
                retries=10,
                routes_per_msg=20,
                hold_time=180,
                update_interval=45,
                ipv4_unicast_nlri=1,
                ipv4_e_vpn_nlri=1,
                graceful_restart_enable=1,
                restart_time=200)


    bgp_dev_list = []
    bgp_dev = 'emulateddevice'
    for i in range(1,(scale+1)):
        bgp_dev1 = bgp_dev+str(i)
        bgp_dev_list.append(bgp_dev1)
 

    ip = IPv4Address(bgp_host1_ip1)
    ip_list = []
    for i in range(0,scale):
        ip_list.append(ip)
        ip = ip + i

    mac = 'aa:bb:cc:dd:ee:01' 
 
    for router,ip in zip(bgp_dev_list,ip_list):
        type3 = ixiangpf.emulation_bgp_route_config (
                mode = 'add',
                handle = router,
                evpn_type3_agg_ip = str(ip),
                route_type = 'evpn_type3',
                evpn_type3_community='65001:1',
                evpn_type3_data_plane_encap='vxlan',
                evpn_type3_encap_label='101001',
                evpn_type3_origin='igp',
                evpn_type3_route_target='65001:101001',
                )
        type2 = ixiangpf.emulation_bgp_route_config (
                mode = 'add',
                handle = router,
                evpn_type2_mac_addr_start =mac,
                route_type = 'evpn_type2',
                evpn_type2_community='65001:1',
                evpn_type2_data_plane_encap ='vxlan',
                evpn_type2_encap_label='101001',
                evpn_type2_origin='igp',
                evpn_type2_route_target ='65001:101001',
                )


    bgp1_start1 = ixiangpf.emulation_bgp_control (
            handle = bgp_dev_list,
            mode = 'start')

    elapsed_time = time.time() - start_time
    log.info(banner("C O M P L E A T E D    vTEP   E M U L A T I O N  "))
    log.info("Time taken for Simulating %r vTEP's is %r",vtep_scale,elapsed_time)
    return 1



def trmTrafficTestConfigure1111(uut,port_hdl_src,port_hdl_rcver_list,pps,mcast_address,test_vlan_scale):
    log.info(banner("------trmTrafficConfigureSpirent-----"))
    l3_vlan_count = uut.execute('show nve vni  | incl L3 | count')
    op = uut.execute('show nve vni  | incl L3')
    op1 = op.splitlines()
    mcast_address1 = mcast_address
    mcast_address2 = mcast_address
    vrf_list=[]
    for line in op1:
        if line:
            for vrf in line.split():
                if 'vxlan-' in vrf:
                    if not 'vxlan-90101' in vrf:
                        vrf = vrf.replace("[","").replace("]","")
                        vrf_list.append(vrf)

    if l3_vlan_count  == test_vlan_scale:
        test_vrf_list = vrf_list
        test_vrf_list.remove('vxlan-90101')
        
    elif 'Nil' in str(test_vlan_scale):
        test_vrf_list = vrf_list
        test_vrf_list.remove('vxlan-90101')

    else:
        test_vrf_list = []
        for i in range(0,test_vlan_scale):
            test_vrf_list.append(choice(vrf_list))

    log.info('test_vrf_list is %r',test_vrf_list)
    for vrf in test_vrf_list:
        log.info('---------vrf is %r-----------',vrf)
        count = uut.execute('show ip int br vrf {vrf} | incl Vlan | exc forward | count'.format(vrf=vrf))
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        vlan_list = []
        ip_list = []
        check = 1
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        if check == 1:
                            vlan_list.append(line.split()[0].replace("Vlan",""))
                            vlan=line.split()[0].replace("Vlan","")
                            ip_list.append(line.split()[1])
                            ip1 = line.split()[1]
                            ip_sa= str(ip_address(ip1)+randint(10,32000))
                            log.info('vlan : %r ip : %r ip_sa :%r ',vlan,ip1,ip_sa)
                            check11 = str(255)
                            if check11 in ip_sa:
                                log.info('________ ip_sa is_______ : %r ',ip_sa)
                                ip_sa = str(ip_address(ip_sa)+2)
                            log.info('---------vlan is %r-----------',vlan)
                            log.info('---------ip_sa is %r-----------',ip_sa)
                            log.info('---------mcast_address is %r-----------',mcast_address1)
                            log.info('---------Going to mcastTrafficConfig-----------')
                            mcastTrafficConfig(port_hdl_src,vlan,ip_sa,mcast_address1,1000)
                            check = check + 1
                            mcast_address1 = str(ip_address(mcast_address1)+1)

    for vrf in test_vrf_list:
        count = uut.execute('show ip int br vrf {vrf} | incl Vlan | exc forward | count'.format(vrf=vrf))
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        vlan_list = []
        ip_list = []
        check = 1
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        if check == 1:
                            vlan_list.append(line.split()[0].replace("Vlan",""))
                            vlan=line.split()[0].replace("Vlan","")
                            ip_list.append(line.split()[1])
                            ip1 = line.split()[1]
                            for port_handle in port_hdl_rcver_list:
                                host_ip= str(ip_address(ip1)+randint(32001,64000))
                                log.info('host_ip is ------ %r',host_ip)
                                check11 = str(255)
                                if check11 in host_ip:
                                    host_ip = str(ip_address(host_ip)+2)
                                log.info('---------vlan is %r-----------',vlan)
                                log.info('---------host_ip is %r-----------',host_ip)
                                log.info('---------mcast_address is %r-----------',mcast_address2)
                                log.info('---------Going to mcastTrafficConfig-----------')       
                                IgmpHostCreate1111(port_handle=port_handle,\
                                vlan = vlan,
                                vlan_scale = count,
                                host_ip =host_ip,
                                mcast_group = mcast_address2,
                                mcast_group_scale = 1)

        mcast_address2 = str(ip_address(mcast_address2)+1)




def extTrmTraffic(uut,port_hdl_ext,port_hdl_internal_list,mcast_address,ip_sa,**kwargs):
    log.info(banner("------trmTrafficConfigureSpirent-----"))
    for arg in kwargs:
        if 'vlan1' in arg:
            vlan1 = kwargs['vlan1'] 

    mcast_address1 = mcast_address
    mcast_address2 = mcast_address

    log.info(banner("------mcastTrafficConfigExt--Source EXT--Hosts Internal-")) 
    mcastTrafficConfigExt(port_hdl_ext,ip_sa,mcast_address1,10000,vlan='Nil')

    log.info(banner("------IGMP--Source EXT--Hosts Internal-")) 
    for vrf in ['vxlan-90101']:
        count = uut.execute('show ip int br vrf {vrf} | incl Vlan | exc forward | count'.format(vrf=vrf))
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        vlan_list = []
        ip_list = []
        check = 1

        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        if check == 1:
                            vlan_list.append(line.split()[0].replace("Vlan",""))
                            vlan=line.split()[0].replace("Vlan","")
                            ip_list.append(line.split()[1])
                            ip1 = line.split()[1]
                            for port_handle in port_hdl_internal_list:
                                host_ip= str(ip_address(ip1)+randint(32001,64000))
                                log.info('host_ip is ------ %r',host_ip)
                                check11 = str(255)
                                if check11 in host_ip:
                                    host_ip = str(ip_address(host_ip)+2)
                                log.info('---------vlan is %r-----------',vlan)
                                log.info('---------host_ip is %r-----------',host_ip)
                                log.info('---------mcast_address is %r-----------',mcast_address2)
                                log.info('---------Going to IgmpHostCreate-----------')       
                                IgmpHostCreate(port_handle=port_handle,\
                                vlan = vlan,vlan_scale = count,host_ip =host_ip,\
                                mcast_group = mcast_address2,mcast_group_scale = 1)

        mcast_address2 = str(ip_address(mcast_address2)+1)

 

def extTrmTrafficBiDir(uut,port_hdl_ext,port_hdl_internal_list,mcast_address,ip_sa,**kwargs):
    log.info(banner("------trmTrafficConfigureSpirent-----"))
    for arg in kwargs:
        if 'vlan1' in arg:
            vlan1 = kwargs['vlan1'] 

    mcast_address1 = mcast_address
    mcast_address2 = mcast_address

    log.info(banner("------mcastTrafficConfigExt--Source EXT--Hosts Internal-")) 
    mcastTrafficConfigExt(port_hdl_ext,ip_sa,mcast_address1,10000,vlan='Nil')

    log.info(banner("------IGMP--Source EXT--Hosts Internal-")) 
    for vrf in ['vxlan-90101']:
        count = uut.execute('show ip int br vrf {vrf} | incl Vlan | exc forward | count'.format(vrf=vrf))
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        vlan_list = []
        ip_list = []
        check = 1

        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        if check == 1:
                            vlan_list.append(line.split()[0].replace("Vlan",""))
                            vlan=line.split()[0].replace("Vlan","")
                            ip_list.append(line.split()[1])
                            ip1 = line.split()[1]
                            for port_handle in port_hdl_internal_list:
                                host_ip= str(ip_address(ip1)+randint(32001,64000))
                                log.info('host_ip is ------ %r',host_ip)
                                check11 = str(255)
                                if check11 in host_ip:
                                    host_ip = str(ip_address(host_ip)+2)
                                log.info('---------vlan is %r-----------',vlan)
                                log.info('---------host_ip is %r-----------',host_ip)
                                log.info('---------mcast_address is %r-----------',mcast_address2)
                                log.info('---------Going to IgmpHostCreate-----------')       
                                IgmpHostCreate(port_handle=port_handle,\
                                vlan = vlan,vlan_scale = count,host_ip =host_ip,\
                                mcast_group = mcast_address2,mcast_group_scale = 1)

        mcast_address2 = str(ip_address(mcast_address2)+1)

    log.info(banner("------mcastTrafficConfigExt--Source Internal---Host esternal")) 
    ip1001 = '5.1.0.33' 
    src_ip01= str(ip_address(ip1001)+randint(32001,42000))
    src_ip02= str(ip_address(ip1001)+randint(42001,52000))
    src_ip03= str(ip_address(ip1001)+randint(52001,64000))
    #mcastTrafficConfigExt(port_hdl_ext,ip_sa,mcast_address1,10000)

    mcast_add_ext01 = str(ip_address(mcast_address)+10)
    mcastTrafficConfigExt(port_hdl_internal_list[0],src_ip01,\
        mcast_add_ext01,10000,vlan='1001')
    mcastTrafficConfigExt(port_hdl_internal_list[1],src_ip02,\
        mcast_add_ext01,10000,vlan='1001')
    mcastTrafficConfigExt(port_hdl_internal_list[2],src_ip03,\
        mcast_add_ext01,10000,vlan='1001')

    log.info(banner("------IGMP--Source Int--Hosts Ext-")) 
    IgmpHostCreate(port_handle=port_handle,\
        nei_ip = '144.1.1.1',host_ip = '144.1.1.100',\
        mcast_group = mcast_add_ext01,mcast_group_scale = 1,vlan='Nil')



def MsTrmReset(uut):
    log.info(banner("starting VxlanStReset"))

    for i in range(1,3):
        nve_conf = uut.execute('clear bgp ipv4 mvpn *')
        nve_conf = uut.execute('clear bgp all *')
        nve_conf = uut.execute('clear ip mroute * vrf all')
        nve_conf = uut.execute('clear ip os neighbor *')
        nve_conf = uut.execute('clear isis adjacency *')

    op = uut.execute('show ip int br')
    op1 = op.splitlines()
    intf_list = []
    for line in op1:
        if 'Eth' in line:
            intf = line.split()[0]
            intf_list.append(intf)
        if 'Lo' in line:
            intf = line.split()[0]
            intf_list.append(intf)
        if 'Po' in line:
            intf = line.split()[0]
            intf_list.append(intf)
    cfg_shut =  \
    """
    interface {intf}
    shut
    no shut
    """
    for intf in intf_list:
        for i in range(1,3):
            uut.configure(cfg_shut.format(intf=intf),timeout=50)

    cfg_shut =  \
    """
    interface nve 1
    shut
    interface loop 1
    shut
    interface loop 0
    shut
    interface loop 100
    shut
    """
    cfg_no_shut =  \
    """
    interface nve 1
    no shut
    interface loop 1
    no shut
    interface loop 0
    no shut
    interface loop 100
    no shut
    """
    for i in range(1,3):
       uut.configure(cfg_shut)
       uut.configure(cfg_no_shut)

    #nve_conf = uut.execute('show run interface nve 1')
    #log.info('remove nve @ %r',uut)
    #uut.configure('no interface nve 1',timeout=300)
    #log.info('add nve @ %r',uut)
    #uut.configure(nve_conf,timeout=300)

    return 1

def findvrfList(uut): 
    op = uut.execute('show nve vni  | incl L3')
    vrf_list=[]
    op1 = op.splitlines()
    for line in op1:
        if line:
            for vrf in line.split():
                if 'vxlan-' in vrf:
                    vrf = vrf.replace("[","").replace("]","")
                    log.info('vrf is %r',vrf)
                    vrf_list.append(vrf)

    return  vrf_list                   




def findl3VlanList(uut): 
    op = uut.execute('show ip int br vrf all | incl forward-enabled')
    vlan_list=[]
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'Vlan' in line:
                vlan = line.split()[0].replace("Vlan","")
                log.info('vlan is %r',vlan)
                vlan_list.append(vlan)

    return  vlan_list                   


def pimRemoveAddvrf(uut): 
    log.info(banner("Starting ipAddRemoveAdd "))         
    vrf_list = findvrfList(uut)
 
    for vrf in vrf_list:
        cfg1 = \
        """
        vrf context {vrf}
        """

        cfg2 = \
        """
        vrf context {vrf}
        """

        op = uut.execute("show running-config vrf {vrf} | sec 'vrf context {vrf}'".format(vrf=vrf))
        op1 = op.splitlines()
        for line in op1:
            if 'pim' in line:
                cfg1 += 'no {line}\n'.format(line=line)
                cfg2 += '{line}\n'.format(line=line)                
    try:
        uut.configure(cfg1.format(vrf=vrf),timeout=40)
        uut.configure(cfg2.format(vrf=vrf),timeout=40)
    except:    
        log.info('pimRemoveAddvrffailed uut  %r',uut)
        return 0

    return 1    

 

def pimRemoveAddvrf(uut): 
    log.info(banner("Starting ipAddRemoveAdd "))         
    vrf_list = findvrfList(uut)

    for vrf in vrf_list:
        cfg1 = \
        """
        vrf context {vrf}
        """

        cfg2 = \
        """
        vrf context {vrf}
        """

        op = uut.execute("show running-config vrf {vrf} | sec 'vrf context {vrf}'".format(vrf=vrf))
        op1 = op.splitlines()
        for line in op1:
            if 'pim' in line:
                cfg1 += 'no {line}\n'.format(line=line)
                cfg2 += '{line}\n'.format(line=line)                
    try:
        uut.configure(cfg1.format(vrf=vrf),timeout=40)
        uut.configure(cfg2.format(vrf=vrf),timeout=40)
    except:    
        log.info('pimRemoveAddvrffailed uut  %r',uut)
        return 0

    return 1    


def vniRemoveAddfromvrf(uut): 
    log.info(banner("Starting ipAddRemoveAdd "))         
    vrf_list = findvrfList(uut)
 
    for vrf in vrf_list:
        cfg1 = \
        """
        vrf context {vrf}
        """

        cfg2 = \
        """
        vrf context {vrf}
        """

        op = uut.execute("show running-config vrf {vrf} | sec 'vrf context {vrf}'".format(vrf=vrf))
        op1 = op.splitlines()
        for line in op1:
            if 'vni' in line:
                cfg1 += 'no {line}\n'.format(line=line)
                cfg2 += '{line}\n'.format(line=line)                
            else:
            	cfg2 += '{line}\n'.format(line=line) 

    try:
        uut.configure(cfg1.format(vrf=vrf),timeout=40)
        uut.configure(cfg2.format(vrf=vrf),timeout=40)
    except:    
        log.info('pimRemoveAddvrffailed uut  %r',uut)
        return 0

    return 1  


#def reloadnode(uut):
#    reload_proceed_anyway = r'^(.*)This command will reboot the system\. \(y\/n\)\?  \[n\]'
#    response = Dialog([Statement(pattern=reload_proceed_anyway,
#                             action='sendline('y')',
#                             args=None,
#                             loop_continue=True,
#                             continue_timer=False)])
#    uut.reload(dialog=response)


def loadmstrm(uut):
    log.info(banner('------ in reloadUUT ------ '))
    uut.transmit('write erase\n')
    uut.transmit("y\n")
    countdown(1)
    uut.configure('copy bootflash:ms_trm_1023_l2_256_l3_feb_20 start',timeout=120)
    #uut.execute('copy run start',timeout=200)
    dialog1 = Dialog ([
        Statement(pattern = r'This command will reboot the system\. \(y\/n\)\?  \[n\]',action = lambda spawn: spawn.sendline('y'), loop_continue = True, continue_timer = True),
        #Statement(pattern = r'Reload scheduled after 6 seconds',action = None, loop_continue = True, continue_timer = True),
        Statement(pattern = r'.*login\:',action = lambda spawn: spawn.sendline('admin'), loop_continue = True, continue_timer = True),
        Statement(pattern = r'Password\:',action = lambda spawn: spawn.sendline('nbv12345'), loop_continue = True, continue_timer = True),
        Statement(pattern = r'This command will reboot the system\. \(y\/n\)\?  \[n\] \(yes/no\)\:.*',action = lambda spawn: spawn.sendline('y'), loop_continue = True, continue_timer = True),
        Statement(pattern = '.*# ',action = None, loop_continue = False, continue_timer = False),
        ])

    uut.execute ("reload",reply =dialog1, timeout = 2000)


def loadmstrm256(uut):
    log.info(banner('------ in reloadUUT ------ '))
    uut.transmit('write erase\n')
    uut.transmit("y\n")
    countdown(1)
    uut.configure('copy bootflash:ib_mstrm_l2_256_l3_32_mc_32 start',timeout=120)
    #uut.execute('copy run start',timeout=200)
    dialog1 = Dialog ([
        Statement(pattern = r'This command will reboot the system\. \(y\/n\)\?  \[n\]',action = lambda spawn: spawn.sendline('y'), loop_continue = True, continue_timer = True),
        #Statement(pattern = r'Reload scheduled after 6 seconds',action = None, loop_continue = True, continue_timer = True),
        Statement(pattern = r'.*login\:',action = lambda spawn: spawn.sendline('admin'), loop_continue = True, continue_timer = True),
        Statement(pattern = r'Password\:',action = lambda spawn: spawn.sendline('nbv12345'), loop_continue = True, continue_timer = True),
        Statement(pattern = r'This command will reboot the system\. \(y\/n\)\?  \[n\] \(yes/no\)\:.*',action = lambda spawn: spawn.sendline('y'), loop_continue = True, continue_timer = True),
        Statement(pattern = '.*# ',action = None, loop_continue = False, continue_timer = False),
        ])

    uut.execute ("reload",reply =dialog1, timeout = 2000)


def loadmsvpc(uut,filename):
    log.info(banner('------ in reloadUUT ------ '))
    uut.transmit('write erase\n')
    uut.transmit("y\n")
    countdown(1)
    uut.configure('copy bootflash:{filename} start'.format(filename=filename),timeout=120)
    #uut.execute('copy run start',timeout=200)
    dialog1 = Dialog ([
        Statement(pattern = r'This command will reboot the system\. \(y\/n\)\?  \[n\]',action = lambda spawn: spawn.sendline('y'), loop_continue = True, continue_timer = True),
        #Statement(pattern = r'Reload scheduled after 6 seconds',action = None, loop_continue = True, continue_timer = True),
        Statement(pattern = r'.*login\:',action = lambda spawn: spawn.sendline('admin'), loop_continue = True, continue_timer = True),
        Statement(pattern = r'Password\:',action = lambda spawn: spawn.sendline('nbv12345'), loop_continue = True, continue_timer = True),
        Statement(pattern = r'This command will reboot the system\. \(y\/n\)\?  \[n\] \(yes/no\)\:.*',action = lambda spawn: spawn.sendline('y'), loop_continue = True, continue_timer = True),
        Statement(pattern = '.*# ',action = None, loop_continue = False, continue_timer = False),
        ])

    uut.execute ("reload",reply =dialog1, timeout = 2000)


def reloaduut(uut):
    log.info(banner('------ in reloadUUT ------ '))
    uut.execute('copy run start',timeout=200)
    dialog1 = Dialog ([
        Statement(pattern = r'This command will reboot the system\. \(y\/n\)\?  \[n\]',action = lambda spawn: spawn.sendline('y'), loop_continue = True, continue_timer = True),
        #Statement(pattern = r'Reload scheduled after 6 seconds',action = None, loop_continue = True, continue_timer = True),
        Statement(pattern = r'.*login\:',action = lambda spawn: spawn.sendline('admin'), loop_continue = True, continue_timer = True),
        Statement(pattern = r'Password\:',action = lambda spawn: spawn.sendline('nbv12345'), loop_continue = True, continue_timer = True),
        Statement(pattern = r'This command will reboot the system\. \(y\/n\)\?  \[n\] \(yes/no\)\:.*',action = lambda spawn: spawn.sendline('y'), loop_continue = True, continue_timer = True),
        Statement(pattern = '.*# ',action = None, loop_continue = False, continue_timer = False),
        ])

    uut.execute ("reload",reply =dialog1, timeout = 2000)

def Asciireloaduut(uut):
    log.info(banner('------ in Asciireloaduut ------ '))
    uut.execute('copy run start',timeout=200)
    tm = uut.execute("show clock | excl Time")
    log.info("time is ----- %r",tm)
    tm1 =  tm.replace(":","").replace(".","").replace(" ","")
    uut.configure('copy run bootflash:{name}'.format(name=tm1))
    #uut.transmit('write erase\n')
    #uut.transmit("y\n",)
    #countdown(2)
    #uut.configure('copy  bootflash:{name} start'.format(name=tm1))                 
    dialog1 = Dialog ([
        Statement(pattern = r'This command will reboot the system\. \(y\/n\)\?  \[n\]',action = lambda spawn: spawn.sendline('y'), loop_continue = True, continue_timer = True),
        #Statement(pattern = r'Reload scheduled after 6 seconds',action = None, loop_continue = True, continue_timer = True),
        Statement(pattern = r'.*login\:',action = lambda spawn: spawn.sendline('admin'), loop_continue = True, continue_timer = True),
        Statement(pattern = r'Password\:',action = lambda spawn: spawn.sendline('nbv12345'), loop_continue = True, continue_timer = True),
        Statement(pattern = r'This command will reboot the system\. \(y\/n\)\?  \[n\] \(yes/no\)\:.*',action = lambda spawn: spawn.sendline('y'), loop_continue = True, continue_timer = True),
        Statement(pattern = '.*# ',action = None, loop_continue = False, continue_timer = False),
        ])

    uut.execute ("reload",reply =dialog1, timeout = 2000)


def Asciireloaduut111(uut):
    log.info(banner('------ in Asciireloaduut ------ '))
    uut.execute('copy run start',timeout=200)
    log.info("Reloading now Asciireloaduut")
    uut.transmit('reload ascii\n')
    uut.transmit("y\n", timeout = 2000)

def checkModuleState(uut):
    for i in range(1,1000):
        time.sleep(1)
        op = uut.execute('show module  | incl Module|Ether')
        if 'active' in op:
            log.info('module up, Time take is %r seconds',i)        	
            return i

def checkL3LinkState(uut):
    for i in range(1,1000):
        time.sleep(1)
        op = uut.execute('show ip int brief')
        if 'Eth' in op:
                if not 'own' in op:
                    log.info('L3 interfaces are Up, Time taken is %r seconds',i)        	
                    return i

def checkIgpState(uut,igp):
    for i in range(1,1000):
        time.sleep(1)
        if 'ospf' in igp:
            op = uut.execute('show ip ospf neighbors')
            if 'FULL' in op:
                log.info('OSPF up, Time taken of OSPF to come up is %r seconds',i)        	
                return i
        elif 'isis' in igp: 
            op = uut.execute('show isis adjacency')
            #for line in op.splitlines():
            #    if 'ETh'              
            if 'UP' in op:
                log.info('ISIS up, Time taken of ISIS to come up is %r seconds',i)          
                return i

def checkbgpState(uut):
    for i in range(1,1000):
        time.sleep(1)
        test1 = protocolStateCheck(uut,['bgp'])
        if test1:
            log.info('bgp up, Time taken of BGP to come up is %r seconds',i)        	
            return i

def checknvePeerState(uut):
    for i in range(1,1000):
        time.sleep(1)
        test1 = NvePeerCheck([uut],2)
        if test1:
            log.info('nve peer up, Time taken of nve-peer to come up is %r seconds',i)        	
            return i

def nodeStateCheck(uut,igp):
    try:
        uut.execute('termin length 0')
        log.info('+-------------nodeStateCheck start-----------------------------+') 
        module_uptime = checkModuleState(uut)
        log.info(' + ---------  module_uptime for uut is %r --------- + ',module_uptime)
        l3_link_uptime = checkL3LinkState(uut)
        log.info(' + ---------  l3_link_uptime for uut is %r --------- + ',l3_link_uptime)
        ospf_uptime = checkIgpState(uut,igp)
        log.info(' + ---------  igp_uptime for uut is %r --------- + ',ospf_uptime)
        bgp_uptime = checkbgpState(uut)
        log.info(' + ---------  bgp_uptime for uut is %r --------- + ',bgp_uptime)
        nve_peer_uptime = checknvePeerState(uut)
        log.info(' + ---------  nve_peer_uptime for uut is %r --------- + ',nve_peer_uptime)
        total_uptime = module_uptime+l3_link_uptime+ospf_uptime+bgp_uptime+nve_peer_uptime
        log.info(' + ---------  total_uptime for uut is %r --------- + ',total_uptime)        
        log.info('+-------------nodeStateCheck end-----------------------------+') 
    except:
        log.info('nodeStateCheck failed for %r', uut)
        return 0
    
    return 1


def vxlantrafficSetupfull(uut,port_handle1,port_handle2,vlan_start,vlan_vni_scale,rate):
    pps = int(int(rate)/vlan_vni_scale)
    log.info(banner("Finding the IP address"))
    ip_sa1=str(ip_address(find_svi_ip222(uut,vlan_start))+10)
    ip_sa2=str(ip_address(ip_sa1)+10)
    ip_sa11=str(ip_address(ip_sa1)+40)
    ip_sa22=str(ip_address(ip_sa2)+40)   
    log.info(banner("----Generating hosts and flood traffic----"))
    test1= FloodTrafficGeneratorScale(port_handle1,vlan_start,ip_sa1,'100.100.100.100',rate,str(vlan_vni_scale))
    test2= FloodTrafficGeneratorScale(port_handle2,vlan_start,ip_sa2,'200.200.200.200',rate,str(vlan_vni_scale))
    log.info(banner("----Generating hosts Unicast Bidir Traffic----"))
    SpirentBidirStream222(port_hdl1=port_handle1,port_hdl2=port_handle2,vlan1=vlan_start,vlan2=vlan_start,\
    scale=vlan_vni_scale,ip1=ip_sa11,ip2=ip_sa22,gw1=ip_sa22,gw2=ip_sa11,rate_pps=rate)
    log.info(banner("----Generating Routed Bidir Traffic----"))
    if not SpirentRoutedBidirStream(uut,port_handle1,port_handle2,pps):
        return 0
    log.info(banner("----Generating IPV6 Unicast Traffic----"))
    vlan = 'vlan' + str(vlan_start)
    ipv6_sa1=str(ip_address(findIntfIpv6Addr(uut,vlan))+10)
    ipv6_sa2=str(ip_address(ipv6_sa1)+100)
    SpirentV6BidirStream(port_handle1,port_handle2,vlan_start,vlan_start,vlan_vni_scale,\
        ipv6_sa1,ipv6_sa2,rate)
    log.info(banner("Starting Traffic after ARP"))
    for i in range(1,5):
        doarp = ixiangpf.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
    ixiangpf.traffic_control(port_handle = 'all', action = 'run')
 
 

def vxlantrafficSetupfullScaled(uut,port_handle1,port_handle2,vlan_start,vlan_vni_scale,rate,test_l3_vni_scale):
    pps = int(int(rate)/vlan_vni_scale)
    log.info(banner("Finding the IP address"))
    ip_sa1=str(ip_address(find_svi_ip222(uut,vlan_start))+10)
    ip_sa2=str(ip_address(ip_sa1)+10)
    ip_sa11=str(ip_address(ip_sa1)+40)
    ip_sa22=str(ip_address(ip_sa2)+40)   
    log.info(banner("----Generating hosts and flood traffic----"))
    test1= FloodTrafficGeneratorScale(port_handle1,vlan_start,ip_sa1,'100.100.100.100',rate,str(vlan_vni_scale))
    test2= FloodTrafficGeneratorScale(port_handle2,vlan_start,ip_sa2,'200.200.200.200',rate,str(vlan_vni_scale))
    log.info(banner("----Generating hosts Unicast Bidir Traffic----"))
    SpirentBidirStream222(port_hdl1=port_handle1,port_hdl2=port_handle2,vlan1=vlan_start,vlan2=vlan_start,\
    scale=vlan_vni_scale,ip1=ip_sa11,ip2=ip_sa22,gw1=ip_sa22,gw2=ip_sa11,rate_pps=rate)
    log.info(banner("----Generating Routed Bidir Traffic----"))
    #if not SpirentRoutedBidirStream(uut,port_handle1,port_handle2,pps):
    if not SpirentRoutedBidirStreamScaled(uut,port_handle1,port_handle2,test_l3_vni_scale):
        return 0
    log.info(banner("----Generating IPV6 Unicast Traffic----"))
    vlan = 'vlan' + str(vlan_start)
    ipv6_sa1=str(ip_address(findIntfIpv6Addr(uut,vlan))+10)
    ipv6_sa2=str(ip_address(ipv6_sa1)+100)
    SpirentV6BidirStream(port_handle1,port_handle2,vlan_start,vlan_start,vlan_vni_scale,\
        ipv6_sa1,ipv6_sa2,rate)
    log.info(banner("Starting Traffic after ARP"))
    for i in range(1,5):
        doarp = ixiangpf.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
    ixiangpf.traffic_control(port_handle = 'all', action = 'run')



def vxlantrafficSetupfullScaledMS(uut,port_handle1,port_handle2,vlan_start,vlan_vni_scale,rate,test_l3_vni_scale):
    pps = int(int(rate)/vlan_vni_scale)
    log.info(banner("Finding the IP address"))
    ip_sa1=str(ip_address(find_svi_ip222(uut,vlan_start))+10)
    ip_sa2=str(ip_address(ip_sa1)+10)
    ip_sa11=str(ip_address(ip_sa1)+40)
    ip_sa22=str(ip_address(ip_sa2)+40)   
    log.info(banner("----Generating mcast flood traffic----"))
    test1= mcastTrafficGeneratorScale(port_handle1,vlan_start,ip_sa1,'239.1.1.1',rate,str(vlan_vni_scale))
    test2= mcastTrafficGeneratorScale(port_handle2,vlan_start,ip_sa2,'239.11.11.11',rate,str(vlan_vni_scale))
    log.info(banner("----Generating hosts and flood traffic----"))
    test1= FloodTrafficGeneratorScale(port_handle1,vlan_start,ip_sa1,'100.100.100.100',rate,str(vlan_vni_scale))
    test2= FloodTrafficGeneratorScale(port_handle2,vlan_start,ip_sa2,'200.200.200.200',rate,str(vlan_vni_scale))
    log.info(banner("----Generating hosts Unicast Bidir Traffic----"))
    SpirentBidirStream222(port_hdl1=port_handle1,port_hdl2=port_handle2,vlan1=vlan_start,vlan2=vlan_start,\
    scale=vlan_vni_scale,ip1=ip_sa11,ip2=ip_sa22,gw1=ip_sa22,gw2=ip_sa11,rate_pps=rate)
    log.info(banner("----Generating Routed Bidir Traffic----"))
    #if not SpirentRoutedBidirStream(uut,port_handle1,port_handle2,pps):
    if not SpirentRoutedBidirStreamScaled(uut,port_handle1,port_handle2,test_l3_vni_scale):
        return 0
    log.info(banner("----Generating IPV6 Unicast Traffic----"))
    vlan = 'vlan' + str(vlan_start)
    ipv6_sa1=str(ip_address(findIntfIpv6Addr(uut,vlan))+10)
    ipv6_sa2=str(ip_address(ipv6_sa1)+100)
    SpirentV6BidirStream(port_handle1,port_handle2,vlan_start,vlan_start,vlan_vni_scale,\
        ipv6_sa1,ipv6_sa2,rate)
    log.info(banner("Starting Traffic after ARP"))
    for i in range(1,5):
        doarp = ixiangpf.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
    ixiangpf.traffic_control(port_handle = 'all', action = 'run')


def vxlanTrafficConfigure(uut,port_handle1,port_handle2,vlan_start,test_l3_vlan_scale,rate):
    #def trmTrafficTestConnfigure(uut,port_hdl_src\
    #,port_hdl_rcver_list,pps,mcast_address,test_vlan_scale):
 
    log.info(banner("------trmTrafficConfigureSpirent-----"))
    l3_vlan_count = uut.execute('show nve vni  | incl L3 | count')
    op = uut.execute('show nve vni  | incl L3')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            for vrf in line.split():
                if 'vxlan-' in vrf:
                    vrf = vrf.replace("[","").replace("]","")
                    log.info('vrf is %r',vrf)
                    vrf_list.append(vrf)

    if l3_vlan_count  == test_vlan_scale:
        test_vrf_list = vrf_list

    elif 'Nil' in str(test_vlan_scale):
        test_vrf_list = vrf_list
    else:
        test_vrf_list = []
        for i in range(0,test_vlan_scale):
            test_vrf_list.append(choice(vrf_list))

    for vrf in test_vrf_list:
        log.info('---------vrf is %r-----------',vrf)
        count = uut.execute('show ip int br vrf {vrf} | incl Vlan | exc forward | count'.format(vrf=vrf))
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        vlan_list = []
        ip_list = []
        check = 1
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        if check == 1:
                            vlan_list.append(line.split()[0].replace("Vlan",""))
                            vlan=line.split()[0].replace("Vlan","")
                            ip_list.append(line.split()[1])
                            ip1 = line.split()[1]
                            ip_sa= str(ip_address(ip1)+randint(10,32000))
                            log.info('vlan : %r ip : %r ip_sa :%r ',vlan,ip1,ip_sa)
                            check11 = str(255)
                            if check11 in ip_sa:
                                log.info('________ ip_sa is_______ : %r ',ip_sa)
                                ip_sa = str(ip_address(ip_sa)+2)
                            log.info('---------vlan is %r-----------',vlan)
                            log.info('---------ip_sa is %r-----------',ip_sa)
                            log.info('---------mcast_address is %r-----------',mcast_address1)
                            log.info('---------Going to mcastTrafficConfig-----------')
                            mcastTrafficConfig(port_hdl_src,vlan,ip_sa,mcast_address1,1000)
                            check = check + 1
                            mcast_address1 = str(ip_address(mcast_address1)+1)




    pps = int(int(rate)/vlan_vni_scale)
    log.info(banner("Finding the IP address"))
    ip_sa1=str(ip_address(find_svi_ip222(uut,vlan_start))+10)
    ip_sa2=str(ip_address(ip_sa1)+10)
    ip_sa11=str(ip_address(ip_sa1)+40)
    ip_sa22=str(ip_address(ip_sa2)+40)   
    log.info(banner("----Generating hosts and flood traffic----"))
    test1= FloodTrafficGeneratorScale(port_handle1,vlan_start,ip_sa1,'100.100.100.100',rate,str(vlan_vni_scale))
    test2= FloodTrafficGeneratorScale(port_handle2,vlan_start,ip_sa2,'200.200.200.200',rate,str(vlan_vni_scale))
    log.info(banner("----Generating hosts Unicast Bidir Traffic----"))
    SpirentBidirStream222(port_hdl1=port_handle1,port_hdl2=port_handle2,vlan1=vlan_start,vlan2=vlan_start,\
    scale=1,ip1=ip_sa11,ip2=ip_sa22,gw1=ip_sa22,gw2=ip_sa11,rate_pps=rate)
    log.info(banner("----Generating Routed Bidir Traffic----"))
    if not SpirentRoutedBidirStream(uut,port_handle1,port_handle2,pps):
        return 0
    log.info(banner("----Generating IPV6 Unicast Traffic----"))
    vlan = 'vlan' + str(vlan_start)
    ipv6_sa1=str(ip_address(findIntfIpv6Addr(uut,vlan))+10)
    ipv6_sa2=str(ip_address(ipv6_sa1)+100)
    SpirentV6BidirStream(port_handle1,port_handle2,vlan_start,vlan_start,vlan_vni_scale,\
        ipv6_sa1,ipv6_sa2,rate)
    log.info(banner("Starting Traffic after ARP"))
    for i in range(1,5):
        doarp = ixiangpf.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
    ixiangpf.traffic_control(port_handle = 'all', action = 'run')
 


def clearMultisitevxlanCC(uut):
    cfg = \
    """
    int nve 1
    shut
    no sh
    clear mac add dynamic 
    clear ip mroute * vrf all
    """
    for i in range(1,3):
        uut.configure(cfg)
   

def filterloop1ibgp(uut):
    loopback1 = uut.interfaces['loopback1'].intf
    loopback1_ip = uut.interfaces['loopback1'].ipv4  
    ip1 =str(loopback1_ip)[:-3]

    op = uut.execute("show run bgp | incl 'router bgp'")
    op = op.splitlines()
    for line in op:
        if line:
            if 'bgp' in line:
                as_num = line.split()[-1]

    cfg =\
    """
    no ip prefix-list blockloop1 
    ip prefix-list blockloop1 seq 5 permit {ip1}/32 
    route-map blockloop1 deny 10
    match ip address prefix-list blockloop1 
    route-map blockloop1 permit 20
    router bgp  {as_num}
    template peer ibgp-vxlan
    address-family ipv4 unicast
      route-map blockloop1 out 
    """
    uut.configure(cfg.format(ip1=ip1,as_num=as_num))

 

def bgw_peering(uut1,uut2):
    loopback1 = uut1.interfaces['loopback1'].intf
    loopback1_ip = uut1.interfaces['loopback1'].ipv4  
    ip1 =str(loopback1_ip)[:-3] 
    loopback2 = uut2.interfaces['loopback1'].intf
    loopback2_ip = uut2.interfaces['loopback1'].ipv4  
    ip2 =str(loopback2_ip)[:-3] 

    op = uut1.execute('show ip bgp su | incl identifier')
    op = op.splitlines()
    for line in op:
        if line:
            if 'identifier' in line:
                as_num = line.split()[-1]
   
    cfg =\
    """
    router bgp  {as_num}
    neighbor {neigh}
    inherit peer ibgp-vxlan
    """
    uut1.configure(cfg.format(as_num=as_num,neigh=ip2)) 
    uut2.configure(cfg.format(as_num=as_num,neigh=ip1)) 


def execute_parallel_reload_traffic_test(uut,port_hdl_list,rate_list,device_flag):
    log.info(banner(' $$ execute_parallel_reload_traffic_test $$ '))
    log.info('$$$$$$ uut is %r',uut)
    log.info('$$$$$$ port_hdl_list is %r',port_hdl_list)
    log.info('  $$$$$$ rate_list is %r',rate_list)
    if device_flag == 1: 
        log.info(banner("S T A R T I N G    R E L O A D"))       
        start_time = time.time()                    
        try:
            Asciireloaduut(uut)       
            countdown(100)
            uut.execute('termin len 0')  
            if not nodeStateCheck(uut):
                log.info('nodeStateCheck Failed in execute_parallel')   
        except:
            log.info('uut reload failed ')
            return 0
        elapsed_time = time.time() - start_time
        log.info(banner("C O M P L E A T E D    vTEP  R E L O A D"))
        log.info("Time taken for reloading vTEP's is %r",elapsed_time)

    if device_flag == 2:
        if not msTrmTrafficTestFull(port001=port_hdl_list[0],rx_rate001=rate_list[0],\
            port002=port_hdl_list[1],rx_rate002=rate_list[1],\
            port003=port_hdl_list[2],rx_rate003=rate_list[2]):
            log.info('msTrmTrafficTest failed in execute_parallel')
            return 0
    
    return 1
 


def execute_parallel_reload_traffic_test1(obj1,device_flag):
    log.info(banner(' $$ execute_parallel_reload_traffic_test $$ '))
    log.info('$$$$$$ obj1 is %r',obj1)
    #log.info('$$$$$$ port_hdl_list is %r',port_hdl_list)
    #log.info('  $$$$$$ rate_list is %r',rate_list)
    if device_flag == 1: 
        log.info(banner("S T A R T I N G    R E L O A D"))       
        start_time = time.time()                    
        try:
            Asciireloaduut(obj1)       
            countdown(100)
            obj1.execute('termin len 0')  
            if not nodeStateCheck(obj1):
                log.info('nodeStateCheck Failed in execute_parallel')   
        except:
            log.info('obj1 reload failed ')
            return 0
        elapsed_time = time.time() - start_time
        log.info(banner("C O M P L E A T E D    vTEP  R E L O A D"))
        log.info("Time taken for reloading vTEP's is %r",elapsed_time)

    if device_flag == 2:
        port_hdl_list = obj1[0]
        rate_list = obj1[1]
        fail_list = []
        for i in range(1,30):
            if not msTrmTrafficTestFull(port001=port_hdl_list[0],rx_rate001=rate_list[0],\
                port002=port_hdl_list[1],rx_rate002=rate_list[1],\
                port003=port_hdl_list[2],rx_rate003=rate_list[2],\
                port004=port_hdl_list[3],rx_rate004=rate_list[3]):
                log.info('msTrmTrafficTest failed in execute_parallel count : %r',i)
                fail_list.append('fail') 
                countdown(10) 
        if 'fail' in  fail_list:     
            return 0
    
    return 1
 


def saveConfigtoBootflash(uut):
    #hostname = uut.execute('show hostname')
    #scale = str(routing_vlan_scale)+"_"+str(vlan_vni_scale)
    #filename = "mstrm"+"_"+timestamp
    try:
        uut.configure('delete bootflash:mstrm_iplusb_latest_working no-prompt')
        uut.configure('copy run bootflash:mstrm_iplusb_latest_working')
    except:
        log.info('saveConfigtoBootflash failed')
        return 0
 

def saveConfigtoBootflash1(uut,filename):
    #hostname = uut.execute('show hostname')
    #scale = str(routing_vlan_scale)+"_"+str(vlan_vni_scale)
    #filename = "mstrm"+"_"+timestamp
    try:
        uut.configure('delete bootflash:{filename} no-prompt'.format(filename=filename))
        uut.configure('copy run bootflash:{filename}'.format(filename=filename))
    except:
        log.info('saveConfigtoBootflash failed')
        return 0





def saveConfigfromBootflash(uut):
    #hostname = uut.execute('show hostname')
    #scale = str(routing_vlan_scale)+"_"+str(vlan_vni_scale)
    #filename = "mstrm"+"_"+timestamp
    try:
        op1 =uut.configure('configure replace bootflash:mstrm_iplusb_latest_working verbose',timeout=300)
        if not 'successfully' in op1:
             return 0
        op1 =uut.configure('copy bootflash:mstrm_iplusb_latest_working startup-config',timeout=300)
        if not 'successfully' in op1:
             return 0
    except:
        log.info('CR saveConfigfromBootflash failed')
        return 0

def extl3interfaceConf(uut):
    for intf in [*uut.interfaces.keys()]:
        if 'ext' in intf:
            log.info("bgw ext intf is %r  on  device  %r",intf,uut)            
            ip_add1 = uut.interfaces[intf].ipv4
            intf_name=uut.interfaces[intf].intf
            eth = Interface(name=intf_name); eth.device = uut;eth.description = 'external';eth.switchport_enable = False;\
            eth.shutdown = False;eth.mtu = 9216; eth.ipv4 = ip_add1
            log.info("Configuring intf_name l3_bgw_intf_list interface %r in device %r",intf_name,uut)
            try:
                configuration = eth.build_config()
            except:
                log.error("Failed interface intf_name %r configuration \
                on device %r ",intf_name,uut )
                return 0 



def vrfLitebgwExtconnection(bgw1,ext1):
    ip1 = '44.1.1.1/24'
    ip1_gw = '44.1.1.1'
    ip2 = '44.1.1.2/24'
    ip2_gw = '44.1.1.2'
    ip22 = '144.1.1.1/24'
    nwk1 = '44.1.1.0/24'
    nwk22 = '144.1.1.0/24'
    mcast_src = '144.1.1.111'
    mcast_grp = '239.111.111.111'


    for intf in [*bgw1.interfaces.keys()]:
        if 'ext' in intf:
            log.info("bgw ext intf is %r  on  device  %r",intf,bgw1)            
            #ip_add1 = uut.interfaces[intf].ipv4
            intf_name=bgw1.interfaces[intf].intf
        
        cfg =\
            """
            ip pim evpn-border-leaf
            default interface {intf_name}
            interface {intf_name}
            no switchp
            vrf member vxlan-90101
            ip address {ip1}
            ip pim sparse-mode
            no shut

            ip access-list ANY
            statistics per-entry
            10 permit ip any any 
            match ip address ANY 
 
            route-map static-to-bgp-all permit 10
            match ip address ANY 

            router bgp 65001
            vrf vxlan-90101
            address-family ipv4 unicast
            network {nwk1}
            redistribute static route-map static-to-bgp-all

            vrf context vxlan-90101
            address-family ipv4 unicast
            ip route {nwk22} {ip2_gw}
            ip route 111.111.111.111/32 {ip2_gw}
            """
    bgw1.configure(cfg.format(intf_name=intf_name,\
        ip1=ip1,nwk1=nwk1,nwk22=nwk22,ip2_gw=ip2_gw))


    for intf in [*ext1.interfaces.keys()]:
        if 'ext' in intf:
            log.info("bgw ext intf is %r  on  device  %r",intf,ext1)            
            #ip_add1 = uut.interfaces[intf].ipv4
            intf_name1=ext1.interfaces[intf].intf
        if 'tgn' in intf:
            log.info("bgw ext intf is %r  on  device  %r",intf,ext1)            
            #ip_add2 = uut.interfaces[intf].ipv4
            intf_name2=ext1.interfaces[intf].intf

    cfg1 =\
            """
            no feature pim
            feature pim

            no interf lo 0
            interf loo 0
            ip addr 111.111.111.111/32
            ip pim sparse-mode
            no shut

            default interface {intf_name1}
            interface {intf_name1}
            no switchp
            ip address {ip2}
            ip pim sparse-mode
            no shut

            interface {intf_name2}
            no switchp
            ip address {ip22}
            ip pim sparse-mode
            no shut

            ip pim rp-address 111.111.111.111 group-list 224.0.0.0/4
            """
    ext1.configure(cfg1.format(intf_name1=intf_name1,intf_name2=intf_name2,\
        ip2=ip2,ip22=ip22,ip1_gw=ip1_gw))

    return 1

def mstrmExtRpConfig(uut):
    cfg = \
    """
    vrf context vxlan-90101
    no ip pim rp-address 1.2.3.111 group-list 224.0.0.0/4
    ip pim rp-address 111.111.111.111 group-list 224.0.0.0/4
    """
    try:
        uut.configure(cfg)
    except:
        log.error('mstrmExtRpConfig failed for %r',uut)
        return 0 


def traffictest1(trm_port_handle_list,rate_list_trm):
    for port_hdl,exp_rate in zip(trm_port_handle_list,rate_list_trm):
        if not rateTest(port_hdl,exp_rate):
            #log.info('rateTest failed for Starting Resets %r',port_hdl)
            return 0
        else:
            log.info('traffictest1 PASSED for port @1 %r',port_hdl)

    log.info('traffictest1 PASSED for ports %r',trm_port_handle_list)        
    return 1

def setupTrafficTest(trm_port_handle_list,rate_list_trm,bgw_uut_list,filename):

    filename_list = []

    for i in bgw_uut_list:
        filename_list.append(filename)

    if traffictest1(trm_port_handle_list,rate_list_trm):
        return 1
    else:
        log.info('+++++load_from_bootflash+++++')
        pcall(loadmsvpc,uut=tuple(bgw_uut_list),filename=tuple(filename_list))
        log.info('countdown 300 in setupTrafficTest after loadmsvpc ')
        countdown(300)
      
        if traffictest1(trm_port_handle_list,rate_list_trm):
            return 1
        else:
            log.info(banner('TRAFFIC FAILED AFTER RESET'))
            return 0


def setupTrafficTest1(trm_port_handle_list,rate_list_trm,bgw_uut_list):    
    cfg = \
    """
    interface nve 1
    shut
    interface loop0
    shut
    interface loop1
    shut
    interface loop100
    shut
    sleep 1
    interface nve 1
    no shut
    interface loop0
    no shut
    interface loop1
    no shut
    interface loop100
    no shut
    """
    for uut in bgw_uut_list:
        uut.configure(cfg)
    countdown(240)
    if traffictest1(trm_port_handle_list,rate_list_trm):
        return 1
    else:
        log.info(banner('TRAFFIC FAILED AFTER RESET'))
        return 0


def igmpHostCreate(port_hdl,**kwargs):
    mcast_group_scale = 1  
    vlan_scale = 1
    igmp_version = choice(['v3','v2'])    
    for arg in kwargs:
        if 'igmp_version' in arg:
            igmp_version = kwargs['igmp_version']
        elif 'vlan' in arg:
            vlan = kwargs['vlan']
        elif 'nei_ip' in arg:
            nei_ip = kwargs['nei_ip']
        elif 'host_ip' in arg:
            host_ip = kwargs['host_ip']
        elif 'mcast_group' in arg:
            mcast_group = kwargs['mcast_group']
        elif 'ssm_source' in arg:
            ssm_source = kwargs['ssm_source']



    log.info(banner('In IgmpHostCreate, Start emulation_multicast_group_config'))   
    create_groups  = ixiangpf.emulation_multicast_group_config (
        mode = 'create',
        ip_prefix_len = '32',
        ip_addr_start = mcast_group,
        ip_addr_step = '1',
        num_groups = 1,
        pool_name = 'MS_TRM')  

    group_pool_name = create_groups['handle']   
 
    mac_add1 = str(RandMac("00:00:00:00:00:00", True))
    mac1 = mac_add1.replace("'","")

    if vlan:
        host_create = ixiangpf.emulation_igmp_config (
                mode = 'create',
                source_mac = mac1,
                igmp_version = igmp_version,
                port_handle = port_handle,
                ip_router_alert=1,
                count = 1,
                vlan_id=vlan,
                intf_ip_addr = host_ip,
                neighbor_intf_ip_addr = nei_ip,
                )
    else:
        host_create = ixiangpf.emulation_igmp_config (
                mode = 'create',
                source_mac = mac1,
                igmp_version = igmp_version,
                port_handle = port_handle,
                ip_router_alert=1,
                count = 1,
                intf_ip_addr = host_ip,
                neighbor_intf_ip_addr = nei_ip,
                )

    if host_create['status']:
        log.info('IGMP Host created')
        host_handle = host_create['handle']
        device_ret0_group_config = ixiangpf.emulation_igmp_group_config (
            session_handle = host_handle,
            mode = 'create',
            group_pool_handle = group_pool_name,
            )
    if device_ret0_group_config['status']:
        log.info('IGMP Host created , and group added')


def mcastSourceCreate(port_hdl):
    pass


def vxlanMsiteCC(uut_list):
    for uut in uut_list:
        check = uut.execute('show consistency-checker l2 module 1')
        if not 'PASSED' in check:
            for uut in uut_list:
                uut.execute("clear mac address-table dynamic")
            for i in range(1,3):
                doarp = ixiangpf.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
            return 0

    for uut in uut_list:
        check = uut.execute('show consistency-checker vxlan l2 module 1')
        if not 'PASSED' in check:
            for uut in uut_list:
                uut.execute("clear mac address-table dynamic")
            for i in range(1,3):
                doarp = ixiangpf.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
            return 0

    for uut in uut_list:
        check1 = uut.execute('show consistency-checker vxlan l3 vrf all start-scan',timeout=100)
        check2 = uut.execute('show consistency-checker vxlan l3 vrf all report ',timeout=100)
        if 'Consistency-Checker: FAIL for ALL' in check2:
            for uut in uut_list:
                for i in range(1,3):
                    uut.execute(" clear ip route vrf all *")
            for i in range(1,3):
                doarp = ixiangpf.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
            return 0 

    return 1   


def vxlanMsiteCChecker(uut):
    #for uut in uut_list:
    check = uut.execute('show consistency-checker l2 module 1')
    if not 'PASSED' in check:
        if ' not found in HW table on slice' in check:
            cmd1 = uut.execute('show run vlan')
            cmd2 = uut.execute('show run vlan | inc 101-') 
            for line in cmd2.splitlines():
                if not 'nve-overlay' in line:
                    log.info('remove add vlan %r', line)
                    uut.configure('no {line}'.format(line=line),timeout=120)          
                    uut.configure(cmd1)

        for uut in [uut]:
            uut.execute("clear mac address-table dynamic")
        #for i in range(1,1):
        #    doarp = ixiangpf.arp_control(arp_target='allstream',arpnd_report_retrieve='0')
        return 0

    #for uut in uut_list:
    check = uut.execute('show consistency-checker vxlan l2 module 1')
    if not 'PASSED' in check:
        for uut in [uut]:
            uut.execute("clear mac address-table dynamic")
        #for i in range(1,3):
        #    doarp = ixiangpf.arp_control(arp_target='allstream',arpnd_report_retrieve='0')
        return 0

    #for uut in uut_list:
    check1 = uut.execute('show consistency-checker vxlan l3 vrf all start-scan',timeout=100)
    check2 = uut.execute('show consistency-checker vxlan l3 vrf all report ',timeout=100)
    if 'Consistency-Checker: FAIL for ALL' in check2:
        for uut in [uut]:
            for i in range(1,3):
                uut.execute(" clear ip route vrf all *")
        #for i in range(1,3):
        #    doarp = ixiangpf.arp_control(arp_target='allstream',arpnd_report_retrieve='0')
        return 0 

    return 1   


def vxlanMsiteCCheckerAll1(uut_list):
    fail_list = []
    
    for uut in uut_list:
        if 'NXOS: version 7.0' in uut.execute('show version'):
            try:
                check = uut.execute('show consistency-checker l2 module 1')
            except:
                log.error('show consistency-checker l2 module 1 fail for %r',uut)
                fail_list.append('fail')


def vxlanMsiteCCheckerAll(uut_list):
    fail_list = []
    for uut in uut_list:
        check = uut.execute('show consistency-checker l2 module 1')
        if not 'PASSED' in check:
            if ' not found in' in check:
                cmd1 = uut.execute('show run vlan')
                cmd2 = uut.execute('show run vlan | inc 101-') 
                for line in cmd2.splitlines():
                    if not 'nve-overlay' in line:
                        log.info('remove add vlan %r', line)
                        uut.configure('no {line}'.format(line=line),timeout=120)          
                        uut.configure(cmd1)

            for uut in [uut]:
                uut.execute("clear mac address-table dynamic")            
            fail_list.append('fail')

    for uut in uut_list:
        check = uut.execute('show consistency-checker vxlan l2 module 1')
        if not 'PASSED' in check:
            for uut in [uut]:
                uut.execute("clear mac address-table dynamic")
            fail_list.append('fail')

    for uut in uut_list:
        check1 = uut.execute('show consistency-checker vxlan l3 vrf all start-scan',timeout=100)
        check2 = uut.execute('show consistency-checker vxlan l3 vrf all report ',timeout=100)
        if 'Consistency-Checker: FAIL for ALL' in check2:
            for uut in [uut]:
                for i in range(1,3):
                    uut.execute(" clear ip route vrf all *")

            fail_list.append('fail')

    if 'fail' in fail_list:
        log.info("---CC FAIL----")
        return 0
    else:
        return 1




def StreamCreate(port_hdl,ip_src,ip_dst,gw,rate_pps):
    streamblock_ret1 = ixiangpf.traffic_config (
                mode = 'create',
                port_handle = port_hdl,
                l2_encap = 'ethernet_ii',
                frame_size_min='500',
                frame_size_max='1000',
                frame_size_step='500',
                #vlan_id=vlan_id,
                l3_protocol = 'ipv4',
                ip_id = '0',
                ip_src_addr = ip_src,
                ip_dst_addr = ip_dst,
                ip_ttl = '255',
                ip_hdr_length = '5',
                ip_protocol = '253',
                rate_pps = rate_pps,
                mac_discovery_gw = gw)

    status = streamblock_ret1['status']



def LoopIpAddChange(uut,intf_name,action): 
    log.info(banner("Starting PortVlanMappingCleanup "))

    op = uut.execute('show ip bgp su | incl identifier')
    op = op.splitlines()
    for line in op:
        if line:
            if 'identifier' in line:
                as_num = line.split()[-1]

    shut_nve= \
        """
        interface nve 1
        shut
        """
    no_shut_nve= \
        """
        interface nve 1
        no shut
        """
    for uut in [uut]:
        uut.configure(shut_nve)

    for uut in [uut]:
        op = uut.execute('show run interface {intf_name}'.format(intf_name=intf_name))
        op=op.splitlines()
        for line in op: 
            if "address" in line:
                if not "secondary" in line:
                    ip = line.split()[2][:-3]
                    if 'incr' in action:
                        ip1= ip_address(ip)+20
                    elif 'decr' in action:
                        ip1= ip_address(ip)-20


    cfgsa = \
        """
        interface {intf_name}
        ip address {ip1}/32
        no shut
        router bgp {as_num}
        address-family ipv4 unicast
        network {ip1}/32        
        """
    #op11 = uut.execute("show run | incl feature")

    #if "vpc" in op11:
    #try: 
    #        log.info("cfgvpc is %r",cfgvpc.format(intf=intf,ip1=ip1,ip22=ip22,ip2=ip2,asn=asn))                
    #            uut.configure(cfgvpc.format(intf=intf,ip1=ip1,ip2=ip2,ip22=ip22,asn=asn))  
    #        except:    
    #            log.info('IP change failed vpc node uut  %r, intf is loopback %r',uut,intf)
    #            return 0

    #else:
    try: 
        log.info("cfgsa is %r",cfgsa.format(intf_name=intf_name,ip1=ip1,as_num=as_num))   
        uut.configure(cfgsa.format(intf_name=intf_name,ip1=ip1,as_num=as_num))  
        uut.configure(no_shut_nve)
    except:    
        log.info('IP change failed uut  %r, intf is loopback%r',uut,intf_name)
        return 0
 
    return 1


def NodeIssu(uut,img_name):

    dialog1 = Dialog ([
        Statement(pattern = r'Do you want to continue with the installation\. \(y\/n\)\?  \[n\]',action = lambda spawn: spawn.sendline('y'), loop_continue = True, continue_timer = True),
        #Statement(pattern = r'Reload scheduled after 6 seconds',action = None, loop_continue = True, continue_timer = True),
        Statement(pattern = r'.*login\:',action = lambda spawn: spawn.sendline('admin'), loop_continue = True, continue_timer = True),
        Statement(pattern = r'Password\:',action = lambda spawn: spawn.sendline('nbv12345'), loop_continue = True, continue_timer = True),
        Statement(pattern = r'This command will reboot the system\. \(y\/n\)\?  \[n\] \(yes/no\)\:.*',action = lambda spawn: spawn.sendline('y'), loop_continue = True, continue_timer = True),
        Statement(pattern = '.*# ',action = None, loop_continue = False, continue_timer = False),
        ])




    check_cmd = 'show install all impact nxos %s non-disruptive' %(img_name)
    install_cmd = 'install all nxos %s non-disruptive non-interruptive' %(img_name)
    response = collections.OrderedDict()
    response[r"Do you want to continue with the installation \(y\/n\)?"] = "econ_sendline y;exp_continue"
    response[r"Do you want to save the configuration \(y\/n\)"] = "econ_sendline y;exp_continue"
    
    response = collections.OrderedDict()
    response[r"Do you want to continue with the installation \(y\/n\)?"] = "econ_sendline y;exp_continue"
    response[r"Do you want to save the configuration \(y\/n\)"] = "econ_sendline y;exp_continue"
    #output = uut.execute(install_cmd, reply=response, timeout=2000)


    #output =uut.reload(reload_command=install_cmd,timeout=800,prompt_recovery=True,return_output=True)
    uut.execute ("reload",reply =dialog1, timeout = 2000)
    output =uut.reload(reload_command=install_cmd,reply =dialog1, timeout = 2000)

    time.sleep(60)
    uut.disconnect()
    try:
        uut.connect()
        log.info("Connection to uut Successful...Starting Test cases on uut")
    except:
        log.info("Connection to UUT Unsucces")
        return False
            
    #output = uut.execute(install_cmd,timeout = 40000,reply =response)

    #check2 = uut.execute('show consistency-checker vxlan l3 vrf all report ',timeout=100)


    str1 = 'switch will reboot in 10 seconds.'
    str3 = 'Install all currently is not supported'
    str4 = 'Switch is not ready for Install all yet'


    if str1 in output:
        log.info("Install all Done and logged in back")
        return True
    elif str3 in output:
        log.warning("Install all failed as currently not supported")
        return False
    elif str4 in output:
        log.warning("Install all failed as Switch is not ready for install all yet")
        return False
    else:
        log.warning("Install all Command Failed")
        return False 


def xconnecEnablefcs(uut,intf):
    log.info('uut is _________ %r',uut)


    cfg = \
    """
    default interface {intf}
    interface {intf} 
    shut
    mtu 9216
    switchport
    switchport mode dot1q-tunnel
    switchport access vlan 50
    spanning-tree port type edge 
    no shut
    mtu 9216 
    vlan 50
    vn-segment 990050
    xconn
    interface nve1
    member vni 990050
    ingress-replication protocol bgp
    evpn
    vni 990050 l2
    rd auto
    route-target import auto
    route-target export auto
    """
    uut.configure(cfg.format(intf=intf))


def xconnecNgomEnablefcs(uut):
    log.info('uut is _________ %r',uut)
    cfg = \
    """
    feature ngoam
    ngoam install acl
    ngoam xconnect hb-interval 5000  
    """
    uut.configure(cfg)



def xconnStreamConf(port_handle,source_mac,protocol,rate_pps):
    log.info("Entering the function to generate %r stream",protocol)

    if 'cdp' in protocol:
        mac_dst_add = '01:00:0c:cc:cc:cc'
        name = "CDP"

    elif 'lacp' in protocol:
        mac_dst_add = '01:80:c2:00:00:02'
        name = "LACP"  
 
    elif 'mvrp' in protocol:
        mac_dst_add = '01:80:c2:00:00:21'
        name = "LACP"  

    elif 'mmrp' in protocol:
        mac_dst_add = '01:80:c2:00:00:21'
        name = "MMRP"  


    elif 'stp' in protocol:
        mac_dst_add = '01:80:c2:00:00:00'
        name = "STP"  

    elif 'igmp' in protocol:
        mac_dst_add = '01:00:5e:00:00:01'
        name = "IGMP"  

    elif '802.1x' in protocol:
        mac_dst_add = '01:80:c2:00:00:03'
        name = "EAP" 

    elif 'hsrp' in protocol:
        mac_dst_add = '01:00:5e:00:00:02'
        name = "HSRP" 

    elif 'pagp' in protocol:
        mac_dst_add = '01:00:0c:cc:cc:cc'
        name = "PAGP"  

    elif 'vstp' in protocol:
        mac_dst_add = '01:cc:cc:cc:cc:cd'
        name = "VSTP"  




    try:
        streamblock_ret1 = ixiangpf.traffic_config (
            mode ='create',\
            transmit_mode   =  'continuous',\
            port_handle =port_handle,\
            l2_encap ='ethernet_ii',\
            mac_src =source_mac,\
            ether_type ='2000',\
            mac_dst = mac_dst_add ,\
            name = name,\
            frame_size_min='128',\
            frame_size_max='9000',\
            frame_size_step='500',\
            rate_pps =rate_pps,\
            length_mode ='random')

        status = streamblock_ret1['status']
        log.info("tunnel stream block create status %r",status)
        if (status == '0') :
            log.info('run ixiangpf.traffic_config failed for V4 %r', streamblock_ret1)
            
    except:
        log.error('tunnel stream block config failed')
        log.error(sys.exc_info())


def checkcdpall(uut):
    intf_list = []
    cfg = \
    """
    default interface {intf}
    interface {intf}
    no switchp
    no shut
    """

    log.info('uut is _________ %r',uut)
    op =  uut.execute('show inter brief')
    op1 = op.splitlines()
    for line in op1:
        if 'Eth' in line:
            intf_list.append(line.split()[0])
    for intf in intf_list:
        uut.configure(cfg.format(intf=intf)) 
 

    log.info('++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    uut.execute('show cdp neighbor')           
    log.info('++++++++++++++++++++++++++++++++++++++++++++++++++++++++')







def ConnectIxia (labserver_ip,tgn_ip,port_list):    
    ixia_tcl_server_addr_str = str(labserver_ip) + ":" + str(8009)
    _result_ = ixiahlt.connect(
                                device = str(tgn_ip),
                                reset=1,
                                port_list = port_list,
                                ixnetwork_tcl_server= ixia_tcl_server_addr_str,
                                break_locks = 1
                                    )
    if _result_['status'] == '1':
        print("Ixia connection successfull")
        log.info("Ixia Connection is Successfull")
        return _result_
    else:
        print("Ixia Connection Failed")
        log.info("Ixia connection id Failed")
        return 0
        
'''

def ixia_flood_traffic_config(port_handle,vlan,ip_sa,ip_da,rate_pps,count):
    log.info(banner('in ixia_flood_traffic_config '))
    str1=hex(randint(16,54))[2:]
    str2=hex(randint(55,104))[2:]
    str3=hex(randint(32,80))[2:]
    str4=hex(randint(50,95))[2:]

    mac1='00:'+str4+':'+str2+':'+str1+':'+str3+':02'
    #mac2='00:10:'+str1+':'+str2+':'+str4+':02'

    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        traffic_generator = 'ixnetwork_540',
        port_handle     =       port_handle,
        l2_encap        =      'ethernet_ii_vlan',
        vlan_id         =       vlan,
        stream_id       =       vlan,
        vlan_id_count   =       count,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip_sa,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       count,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip_da,
        mac_dst         =       'ff:ff:ff:ff:ff:ff',
        mac_src         =       mac1,
        mac_src_count   =       count,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')
    
    print("Floadtraffic", device_ret)

    status = device_ret['status']
    if (status == '0') :
        log.info("run ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** run ixiahlt.traffic_config successfully")
        return 1

def ixia_mcast_traffic_config(port_handle,vlan,ip_sa,ip_da,rate_pps,count):
    log.info(banner('+++ ixia_mcast_traffic_config +++ '))

    str1=hex(randint(16,54))[2:]
    str2=hex(randint(55,104))[2:]
    str3=hex(randint(32,80))[2:]
    str4=hex(randint(50,95))[2:]

    mac1='00:'+str4+':'+str2+':'+str1+':'+str3+':02'

    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        traffic_generator =  'ixnetwork_540',
        port_handle     =    port_handle,
        l2_encap        =       'ethernet_ii_vlan',
        stream_id       =       vlan,
        vlan_id         =       vlan,
        vlan_id_count   =       count,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip_sa,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       count,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip_da,
        mac_dst         =       '01:00:5E:00:00:01',
        mac_src         =       mac1,
        mac_src_count   =       count,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')
    print("Mcast traffic ",device_ret)

    status = device_ret['status']
    if (status == '0') :
        log.info("run ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** run ixiahlt.traffic_config successfully")
        return 1

def ixia_unicast_bidir_traffic_config(port_hdl1,port_hdl2,vlan1,vlan2,scale,ip1,ip2,gw1,gw2,rate_pps):
    #log.info(banner("------SpirentHostBidirStream-----"))
    log.info('VLAN1 : %r,VLAN2 : %r,SCALE : %r,IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,vlan1,vlan2,scale,ip1,ip2,gw1,gw2)

    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        traffic_generator =    'ixnetwork_540',
        port_handle     =       port_hdl1,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan1,
        vlan_id_count   =       scale,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip1,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       scale,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip2,
        ip_dst_step     =       '0.1.0.0',
        ip_dst_count    =       scale,
        ip_dst_mode     =       'increment',
        mac_src         =       '00:12:94:aa:00:02',
        mac_dst         =       '00:13:94:bb:00:02',
        mac_src_count   =       scale,
        mac_src_mode    =       'increment',
        mac_src_step    =       '00:00:00:00:00:01',
        mac_dst_count   =       scale,
        mac_dst_mode    =       'increment',
        mac_dst_step    =       '00:00:00:00:00:01',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')
    print("Bidir Stream 222", device_ret)
    status = device_ret['status']
    if (status == '0'):
        log.info("port_hdl1 ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** port_hdl1 ixiahlt.traffic_config successfully")        


def ixia_routed_bidir_traffic_config(uut,port_hdl1,port_hdl2,pps):
    log.info(banner("------ixia_routed_bidir_traffic_config-----"))

    op = uut.execute('show nve vni  | incl L3')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            if 'MS-IR' in line:
                vrf = line.split()[-2].replace("[","").replace("]","")
                vrf_list.append(vrf)
            else:    
                vrf = line.split()[-1].replace("[","").replace("]","")
                vrf_list.append(vrf)


    for vrf in vrf_list:
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        vlan_list = []
        ip_list = []
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        vlan_list.append(line.split()[0].replace("Vlan",""))
                        ip_list.append(line.split()[1])

        if not len(vlan_list) == len(ip_list):
            return 0
        else:
            gw1 = str(ip_address(ip_list[0]))
            ip1 = str(ip_address(gw1)+1)
            ip11= str(ip_address(ip1)+100)

            ixis_host_bidir_stream_smac_same(port_hdl1,port_hdl2,vlan_list[0],vlan_list[0],ip1,ip11,ip11,ip1,str(pps))

            for i in range(1,len(vlan_list)):
                vlan2 = vlan_list[i]
                gw2 = ip_list[i]
                ip2 = str(ip_address(gw2)+100)
                ixis_host_bidir_stream_smac_same(port_hdl1,port_hdl2,vlan_list[0],vlan2,ip1,ip2,gw1,gw2,str(pps))

    return 1




def ixia_v6_unicast_bidir_stream(port_hdl1,port_hdl2,vlan1,vlan2,scale,ipv61,ipv62,rate_pps):
    log.info(banner("STARTING SpirentV6BidirStream "))
    log.info('VLAN1 : %r,VLAN2 : %r,SCALE : %r,IP1 : %r,IP2 : %r ' ,vlan1,vlan2,scale,ipv61,ipv62)

    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        port_handle     =       port_hdl1,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan1,
        vlan_id_count   =       scale,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv6',
        ipv6_src_addr   =       ipv61,
        ipv6_src_step   =       '0000:0000:0000:0000:0000:0000:0001:0000',
        ipv6_src_count  =       scale,
        ipv6_src_mode   =       'increment',
        ipv6_dst_addr   =       ipv62,
        ipv6_dst_step   =       '0000:0000:0000:0000:0000:0000:0001:0000',
        ipv6_dst_count  =       scale,
        ipv6_dst_mode   =       'increment',
        mac_src         =       '00:12:60:60:00:02',
        mac_dst         =       '00:13:60:60:00:02',
        mac_src_count   =       scale,
        mac_src_mode    =       'increment',
        mac_src_step    =       '00:00:00:00:00:01',
        mac_dst_count   =       scale,
        mac_dst_mode    =       'increment',
        mac_dst_step    =       '00:00:00:00:00:01',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')
    status = device_ret['status']
    if (status == '0'):
        log.info("port_hdl1 ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** port_hdl1 ixiahlt.traffic_config successfully")
        
        

    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        port_handle     =       port_hdl2,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan2,
        vlan_id_count   =       scale,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv6',
        ipv6_src_addr   =       ipv62,
        ipv6_src_step   =       '0000:0000:0000:0000:0000:0000:0001:0000',
        ipv6_src_count  =       scale,
        ipv6_src_mode   =       'increment',
        ipv6_dst_addr   =       ipv61,
        ipv6_dst_step   =       '0000:0000:0000:0000:0000:0000:0001:0000',
        ipv6_dst_count  =       scale,
        ipv6_dst_mode   =       'increment',
        mac_src         =       '00:13:60:60:00:02',
        mac_dst         =       '00:12:60:60:00:02',
        mac_src_count   =       scale,
        mac_src_mode    =       'increment',
        mac_src_step    =       '00:00:00:00:00:01',
        mac_dst_count   =       scale,
        mac_dst_mode    =       'increment',
        mac_dst_step    =       '00:00:00:00:00:01',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous')
    status = device_ret['status']
    if (status == '0'):
        log.info("port_hdl2 ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** port_hdl2 ixiahlt.traffic_config successfully")





def ixis_host_bidir_stream_smac_same(port_hdl1,port_hdl2,vlan1,vlan2,ip1,ip2,gw1,gw2,rate_pps):
    log.info(banner("------ixis_host_bidir_stream_smac_same-----"))

    str11 = hex(int(vlan1))[2:][:2]
    str12 = hex(int(vlan1))[2:][1:]
    str21 = hex(int(vlan2))[2:][:2]
    str22 = hex(int(vlan2))[2:][1:]

    if vlan1==vlan2:
        mac1='00:10:'+str11+':'+str12+':'+str11+':22'
        mac2='00:11:'+str22+':'+str22+':'+str21+':44'
    else:
        mac1='00:10:'+str11+':'+str12+':'+str11+':22'
        mac2='00:10:'+str21+':'+str22+':'+str21+':22'

    print("port_hdl1", port_hdl1)
    log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)
    device_ret1 =ixiahlt.interface_config (mode = 'config',\
    port_handle = port_hdl1,vlan = 1, vlan_id  = vlan1,intf_ip_addr = ip1, netmask = '255.255.0.0',\
    gateway = gw1,src_mac_addr = mac1)
    
    print("port_hdl1 status", device_ret1)
    
    if device_ret1['status'] == '1':
        log.info('Successfully configured protocol interfaces')
    else:
        log.error('Failed to configure protocol interfaces')
    
    print("port_hdl2", port_hdl2)
    device_ret2 =ixiahlt.interface_config (mode = 'config',port_handle = port_hdl2,\
    vlan = 1, vlan_id  = vlan2, intf_ip_addr = ip2, netmask = '255.255.0.0',\
    gateway = gw2, src_mac_addr = mac2)
    
    print("port_hdl2 status",device_ret2)
    
    if device_ret2['status'] == '1':
        log.info('Successfully configured protocol interfaces')
    else:
        log.error('Failed to configure protocol interfaces')
        
    print("device_ret1 value is",device_ret1)
    print("device_ret2 value is",device_ret2)
    h1 = device_ret1['interface_handle']
    h2 = device_ret2['interface_handle']

    streamblock_ret1 = ixiahlt.traffic_config (mode= 'create',port_handle= port_hdl1,\
    emulation_src_handle=h1,emulation_dst_handle = h2,bidirectional='1',\
    port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps)
    
    status = streamblock_ret1['status']

    log.info('+-----------------------------------------------------------------------+')
    log.info('stream_id : %r, vlan1 : %r ,vlan2 : %r ,rate_pps : %r',streamblock_ret1['stream_id'],vlan1,vlan2,rate_pps)
    log.info('IP1 : %r,IP2 : %r, Host1 : %r ,Host2 : %r ',ip1,ip2,h1,h2)
    log.info('+-----------------------------------------------------------------------+')
    if (status == '0') :
        log.info('run ixiahlt.traffic_config failed for V4 %r', streamblock_ret1)
    else:
        log.info('***** run ixiahlt.traffic_config successful for V4')


 
def ixia_vxlan_traffic_test(port_handle1,port_handle2,rate,pps,orphan_handle_list):
    rate3=int(rate)*4.5
    diff = int(rate3*.0125)
    test1=ixia_rate_test(port_handle1,port_handle2,rate3,diff)

    if not test1:
        log.info(banner("Rate test Failed"))
        return 0
    return 1


def ixia_rate_test(port_hdl1,port_hdl2,rate_fps,diff):
    log.info(banner("  Starting ixia_rate_test "))
    diff = 4*int(diff)
    result = 1
    for port_hdl in [port_hdl1,port_hdl2]:
        log.info("port_hdl %r,rate_fps %r,diff is %r", port_hdl,rate_fps,diff)
        try:            
            res = ixiahlt.traffic_stats(port_handle = port_hdl,mode = 'aggregate',traffic_generator = 'ixnetwork')
            print('traffic_status of res', res)
        except:
            log.info('Stats failed for port %r',port_hdl)
            return 0
        try:               
            rx_rate = int(res['aggregate']['rx']['raw_pkt_rate']['max'])*9
            tx_rate = int(res['aggregate']['tx']['total_pkt_rate']['max'])
        except:
            log.info('rx_rate failed for port %r',port_hdl)
            return 0
        log.info('+-----------------------------------------------------------------------+')
        log.info('rx_rate is %r,tx_rate is %r',rx_rate,tx_rate)
        log.info('+-----------------------------------------------------------------------+')
        if abs(int(rx_rate) - int(tx_rate)) > diff:
            log.info('Traffic  Rate Test failed - TX / RX difference is %r',abs(int(rx_rate) - int(tx_rate)))
            log.info('Streamblock is %r',res)
            result = 0
        if abs(int(rx_rate) - int(rate_fps)) > diff:
            log.info('Traffic  Rate Test failed, Rate & FPS diff is %r',abs(int(rx_rate) - int(rate_fps)))
            log.info('Streamblock is %r',res)
            result = 0
    log.info(banner(" Completed Spirent Rate Test "))
    return result


'''
   


