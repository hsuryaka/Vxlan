#!/usr/bin/env python
import re
import pdb 
import logging
import time
from time import sleep
import hashlib
import sys 
from ipaddress import *
import json
from ats.log.utils import banner
from random import *
from ats.topology import Device
#import sth
#from sth import StcPython
import requests
from ats import aetest, log
from ats.log.utils import banner
from netaddr import *
from re import *

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
 
 
import general_lib
 
def CopyRsReload(uut):
    log.info(banner("Vlan XCONNECT configurations"))       
    uut.execute('copy running-config startup-config')
    log.info('+-------------------------------+')
    log.info('|  Reloading of UUT %r',str(uut))
    log.info('+-------------------------------+')
    results1 = uut.reload()
    if results1 != 0:
        log.info(banner("uut Reload Passed "))
        return 1
    else:
        log.info(banner("uut Reload Failed "))
        return 0 
    
                            
                             
def VlanXconnectConfig(uut,vlan_start,scale,vni):
    log.info(banner("Vlan XCONNECT configurations"))       
    for vlan in range(vlan_start,vlan_start+scale+1):
        cfg = \
            """
            no interface vlan {vlan}
            interface nve 1
            member vni {vni}
            no suppress-arp
            vlan {vlan}
            xconnect
            """
        uut.configure(cfg.format(vlan=vlan,vni=vni))

 
def XconnectTcamConfig(uut):
    log.info(banner("XCONNECT TCAM configurations"))       
    op1=uut.execute('show hardware access-list tcam region | incl vxlan-p2p')
    op2=op1.splitlines()
    for line in op2:
        if line:
            if 'vxlan-p2p' in line:
                if int(line.split()[-1])<256:
                    cfg1 = \
                    """
                    hardware access-list tcam region racl 256
                    hardware access-list tcam region e-racl 256
                    hardware access-list tcam region redirect 0
                    hardware access-list tcam region vpc-convergence 256
                    hardware access-list tcam region arp-ether 256 double-wide
                    hardware access-list tcam region vxlan-p2p 256
                    """
                    cli1=uut.configure(cfg1)
                    if not 'ERROR:' in cli1:
                        uut.execute('copy running-config startup-config')
                        log.info(banner("Reloading of UUT after Xconnect TCAM Conf"))
                        results1 = uut.reload()
                        if results1 != 0:
                            log.info(banner("uut Reload Passed during Xconnect Tcam carve"))
                            return 1
                        else:
                            log.info(banner("uut Reload Failed during Xconnect Tcam carve"))
                            return 0                  
                    elif 'ERROR:' in cli1:
                        cli2=uut.execute("show run | incl tcam")
                        cli3=cli2.splitlines()
                        for line in cli3:
                            if line:
                                if not 'double-wide' in line:
                                    if int(line.split()[-1])>256:
                                        cfg2 = (line[:-4]+" 256")
                                        cli4=uut.configure(cfg2)
                                        if not 'ERROR:' in cli4:
                                            cli5=uut.configure(cfg1)
                                            if not 'ERROR:' in cli5:
                                                uut.execute('copy running-config startup-config')
                                                log.info(banner("Reloading of devices"))
                                                results1 = uut.reload()
                                                if results1 != 0:
                                                    log.info(banner("uut Reload Passed during Xconnect Tcam carve"))
                                                    return 1
                                                else:
                                                    log.info(banner("uut Reload Failed during Xconnect Tcam carve"))                  
                                                    return 0       
                                            elif 'ERROR:' in cli5:                                   
                                                log.info(banner("Failed Xconnect Tcam carve @ cli5"))                  
                                                return 0    
                                        elif 'ERROR:' in cli4:                                   
                                            log.info(banner("Failed Xconnect Tcam carve @ cli4"))                  
                                            return 0  

                elif int(line.split()[-1])>=256:
                    log.info(banner("TCAM For Xconnect Allready Carved"))
                    return 1


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
        hardware profile tcam region nat 2048
        hardware profile tcam region pbr 256
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
 




def feature_enable(uut,feature_list):
    op = uut.execute("show run | incl feature")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not "no feature" in line:
                cmd=line.replace('feature ','')
                if not cmd in ['telnet','nxapi','bash-shell','scp-server','sftp-server','ssh']:
                #if not feature in line:
                    uut.configure("no {line}".format(line=line))   

    for feature in feature_list:
        uut.configure('feature {feature}'.format(feature=feature))








def config_loopback(uut,loop,ipv4,ipv4_sec):
    if not 'Nil' in ipv4_sec:
        config_str = \
            """
            #no interf {loop}            
            interf {loop}
            no ip add
            ip add {ipv4}
            ip add {ipv4_sec} second
            descr NVE loopback
            no shut
            """
        try:
            uut.configure(config_str.format(loop=loop,ipv4=ipv4,ipv4_sec=ipv4_sec))
        except:
            log.error('Loop Config Failed on UUT',uut)

    else:
        config_str = \
            """
            no interf {loop}
            interf {loop}
            no ip add
            ip add {ipv4}
            no shut
            """
        try:
            uut.configure(config_str.format(loop=loop,ipv4=ipv4))
        except:
            log.error('Loop Config Failed on UUT',uut)



class L3Interface(object):
    def __init__(self,device,name,ipv4_add):
        self.name=name
        self.device=device
        self.ipv4_add=ipv4_add
                

class CLI_L3Interface(L3Interface):
    def ipv4_configure(self):
        cmd = \
        '''
        interface {intf}
        ip address {ipv4_add}
        no shut
        '''           
        self.device.configure(cmd.format(intf=self.name,ipv4_add=self.ipv4_add))
        
                

class Interface(object):
    def __init__(self,device,name,ipv4_add):
        self.name=name
        self.device=device
        self.ipv4_add=ipv4_add

class CLI_Interface(Interface):
    def shutdown(self):
        cmd = \
        '''
        interface {intf}
        shutdown
        '''           
        self.device.configure(cmd.format(intf=self.name))
        
    def no_shutdown(self):
        self.device.configure('''
            interface {intf}
            no shutdown
            '''.format(intf=self.name))

    def ipv4_configure(self):
        cmd = \
        '''
        interface {intf}
        ip address {ipv4_add}
        no shut
        '''           
        self.device.configure(cmd.format(intf=self.name,ipv4_add=self.ipv4_add))
            
 

class VPCPairs(object):
    def __init__(self,node1,node2,vpc_domain,node1_mgmt_ip,node2_mgmt_ip,mct_mem_list1,mct_mem_list2,vpc_po,vpc_po_mem_list1,vpc_po_mem_list2,vlan_range,vpc_po_type):
        self.node1=node1
        self.vpc_domain=vpc_domain
        self.node1_mgmt_ip=node1_mgmt_ip
        self.mct_mem_list1=mct_mem_list1
        self.vpc_po=vpc_po
        self.vpc_po_mem_list1=vpc_po_mem_list1
        self.vlan_range=vlan_range
        self.vpc_po_type=vpc_po_type
        self.node2=node2
        self.node2_mgmt_ip=node2_mgmt_ip
        self.mct_mem_list2=mct_mem_list2
        self.vpc_po_mem_list2=vpc_po_mem_list2


 
class VPCobject(VPCPairs):
    def vpc_conf(self):
        cmd = \
        '''
        spanning-tree mode mst 
        no feature vpc 
		feature vpc
        feature lacp
        vpc domain {vpc_domain}
        peer-switch
        peer-keepalive destination {node2_mgmt_ip}
        ip arp synchronize
        ipv6 nd synchronize 
        auto-recovery
        peer-gateway
        interface port-channel {vpc_domain}
        #port-channel mode active
        no shut
        switchport
        switchport mode trunk
        spanning-tree port type network
        vpc peer-link
        '''
        try:
            self.node1.configure(cmd.format(node2_mgmt_ip=self.node2_mgmt_ip,vpc_domain=self.vpc_domain))
        except:
            log.error('111 vpc gloabal config failed')

        cmd = \
        '''
        no feature vpc 
        feature vpc
        vpc domain {vpc_domain}
        peer-switch
        peer-keepalive destination {node1_mgmt_ip}
        ip arp synchronize
        ipv6 nd synchronize 
        auto-recovery
        peer-gateway
        interface port-channel {vpc_domain}
        #port-channel mode active
        no shut
        switchport
        switchport mode trunk
        spanning-tree port type network
        vpc peer-link
        '''
        try:
            self.node2.configure(cmd.format(node1_mgmt_ip=self.node1_mgmt_ip,vpc_domain=self.vpc_domain))
        except:
            log.error('111 vpc gloabal config failed for uut',self.node2) 

        for intf in self.mct_mem_list1:
            cmd = \
            '''
            default interface {intf}
            interface {intf}
            channel-group {vpc_domain} force mode active
            no shut
            '''
            try:
                self.node1.configure(cmd.format(intf=intf,vpc_domain=self.vpc_domain))
            except:
                self.node1.execute("show port-channel compatibility-parameters") 
                log.error('222 vpc_peer_link member conf failed for uut/interface',self.node1,intf)   
                
        for intf in self.mct_mem_list2:
            cmd = \
            '''
            #default interface {intf}
            interface {intf}
            channel-group {vpc_domain} force mode active
            no shut
            '''
            try:
                self.node2.configure(cmd.format(intf=intf,vpc_domain=self.vpc_domain))
            except:
                self.node2.execute("show port-channel compatibility-parameters") 
                log.error('222 vpc_peer_link member conf failed for uut/interface',self.node2,intf)  

        if 'access' in self.vpc_po_type:
            cmd = \
                '''
                vlan {vlan_range}
                no interface port-channe {vpc_po}
                interface port-channe {vpc_po}
                #port-channel mode active
                switchport
                switchport mode access
                switchport access vlan {vlan_range} 
                no shut
                vpc {vpc_po}
                '''

             
        elif 'trunk' in self.vpc_po_type:
            cmd = \
                '''
                vlan {vlan_range}
                no interface port-channe {vpc_po}
                interface port-channe {vpc_po}
                #port-channel mode active
                switchport
                switchport mode trunk
                switchport trunk allowed vlan {vlan_range} 
                no shut
                vpc {vpc_po}
                '''
        for node in [self.node1,self.node2]:                
            try:   
                node.configure(cmd.format(vlan_range=self.vlan_range,vpc_po=self.vpc_po))
            except:
                log.error('444 vpc conf failed for vlan_range',self.vlan_range)
 
        for intf in self.vpc_po_mem_list1:
            cmd = \
            '''
            #default interface {intf}
            interface {intf}
            channel-group {vpc_po} force mode active
            no shut
            '''
            try:
                self.node1.configure(cmd.format(intf=intf,vpc_po=self.vpc_po))        
            except:
                self.node1.execute("show port-channel compatibility-parameters") 
                log.error('555 vpc_po_mem conf failed for interface',intf)   

        for intf in self.vpc_po_mem_list2:
            cmd = \
            '''
            #default interface {intf}
            interface {intf}
            channel-group {vpc_po} force mode active
            no shut
            '''
            try:
                self.node2.configure(cmd.format(intf=intf,vpc_po=self.vpc_po))        
            except:
                self.node2.execute("show port-channel compatibility-parameters") 
                log.error('vpc_po_mem conf failed for node',self.node2)    
        #time.sleep(30)
    def vpc_check(self):
        for node in [self.node1,self.node2]:
            filter1 = "Po"+str(self.vpc_po)
            print("VPC Po is .............",filter1) 
            check1 = node.execute("show vpc | incl {filter1}".format(filter1=filter1))
            if "down" in check1:
                log.error('VPC Bringup failed for node',node)    
                node.execute("show vpc consistency-parameters global")
                node.execute("show vpc consistency-parameters vpc {vpc_po}".format(vpc_po=vpc_po))
                self.failed

         
 
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
 

def DeviceVxlanPreCleanupAll1(uut):
    log.info(banner('Starting DeviceVxlanPreCleanupAll'))

    cmd=""
    log.info(banner("Deleteing PO ------"))
    op = uut.execute('show port-channel summary | incl Eth')
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
                        #cfg = "no {line}"
                        cmd +=  "no {line}\n".format(line=line)


    log.info(banner("Deleting vrf"))
    op = uut.configure("show vrf")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'default' in line:
                if not 'management' in line:
                    if not 'show' in line:
                        if not 'VRF-Name' in line:
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


    log.info(banner("Deleting Loopbacks"))
    op = uut.configure("show ip interface brief ")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'Lo' in line:
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

    log.info(banner("Delete CLI's"))
    log.info('cmd is %r',cmd)

   
    feature_clean=\
    """
    no feature ngoam
    no feature interface-vlan
    no feature lacp
    no feature tunnel
    show clock
    no feature nv over
    show clock
    no feature bgp
    show clock
    no feature ospf
    show clock
    no feature pim
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
    nv overlay evpn
    feature lacp
    feature vn-segment-vlan-based
    feature interface-vlan
    """

    for line in feature_clean.splitlines():
        if line:
            cmd +=  line+'\n'

    log.info(banner("Delete CLI's"))
    log.info('cmd is %r',cmd)

    try:
        uut.configure(cmd,timeout = 180)
    except:
        log.error('feature_clean failed for uut',uut)

    return 1


def SwVxlanPreCleanup1(uut):
    log.info(banner("Deleteing adding vxlan features"))


    cmd=""
    log.info(banner("Deleteing PO ------"))
    op = uut.execute('show port-channel summary | incl Eth')
    op1 = op.splitlines()

    for line in op1:
        if 'Po' in line:
            Po = line.split()[0]
            cmd +=  'no interface Po{Po}\n'.format(Po=Po)
            #uut.configure('no interface Po{Po}'.format(Po=Po))

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


    log.info(banner("Deleting vrf"))
    op = uut.configure("show vrf")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'default' in line:
                if not 'management' in line:
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
                    cfg = \
                        """
                        default interface {intf}
                        interface {intf}
                        no switchport
                        """


    log.info(banner("Deleting Loopbacks"))
    op = uut.configure("show ip interface brief ")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'Lo' in line:
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


    log.info(banner("Delete CLI's"))
    log.info('cmd is %r',cmd)

    feature_clean=\
    """
    no fabric forwarding anycast-gateway-mac 0000.2222.3333
    no feature nv over
    no feature bgp
    no feature ospf
    no feature pim
    no feature interface-vlan
    no feature bfd
    terminal session-timeout 0
    line con
    exec-timeout 0
    line vty
    exec-timeout 0
    feature interface-vlan
    feature lacp
    no feature nv over
    no feature bgp
    no feature ospf
    """

    for line in feature_clean.splitlines():
        if line:
            cmd +=  line+'\n'

    log.info(banner("Delete CLI's"))
    log.info('cmd is %r',cmd)

    try:
        uut.configure(cmd,timeout = 250)
    except:
        log.error('feature_clean failed for uut',uut)

    return 1 

def DevicePreClean(uut_list):
    try:
        for uut in uut_list:
            log.info(banner("Staring Pre clean "))
            uut.configure('no interface nve1')

            for intf in uut.interfaces.keys():
                intf = uut.interfaces[intf].intf
                if 'Eth' in intf:
                    try:
                        uut.configure("#default interface {intf}".format(intf=intf))
                    except:
                        log.info("Default Interface configure failed in device \
                                {uut} interface {intf}".format(uut=uut,intf=intf))
                        self.failed()


            op = uut.execute('sh vrf detail | incl Name')
            op1 = op.splitlines()
            for line in op1:
                if not 'default' in line and not 'management' in line:
                    if line:
                        list1=line.split(" ")
                        vrf_id= list1[1][:-1]
                        cfg = """no vrf context  {vrf_id}"""
                        try:
                            uut.configure(cfg.format(vrf_id=vrf_id))
                        except:
                            log.error('vrf_id delete failed in uut',uut,'vrf id is',vrf_id)


            op = uut.execute("sh run | incl 'ip route '")
            op1 = op.splitlines()
            for line in op1:
                if line:
                    if not 'run' in line:
                        if not '10.127' in line:
                            if 'ip route ' in line: 
                                cfg = "no {line}"
                                #uut.configure(cfg.format(line=line))   
                                try:
                                    uut.configure(cfg.format(line=line))  
                                except:
                                    log.error('static route delete failed in uut',uut)
                         
            op = uut.execute("show run | incl community-list")
            op1 = op.splitlines()
            for line in op1:
                if line:
                    cfg = "no {line}"
                    try:
                        uut.configure(cfg.format(line=line))  
                    except:
                        log.error('community-list delete failed in uut',uut)

            op = uut.execute("show run | incl 'interface port-channel'")
            op1 = op.splitlines()
            for line in op1:
                if line:
                    cfg = "no {line}"
                    try:
                        uut.configure(cfg.format(line=line))  
                    except:
                        log.error('port-channel delete failed in uut',uut)


            op = uut.execute("show run | incl route-map")
            op1 = op.splitlines()
            for line in op1:
                if line:
                    if 'permit' in line:
                        cfg = "no {line}"
                        try:
                            uut.configure(cfg.format(line=line))  
                        except:
                           log.error('route-map delete failed in uut',uut)


            op = uut.execute("show ip interface brief vrf all")
            op1 = op.splitlines()
            for line in op1:
                if line:
                    if 'Eth' in line:
                        intf = line.split()[0]
                        if '.' in intf:
                            uut.configure('no interface {intf}'.format(intf=intf))
                        else:    
                            cfg = \
                            """
                            #default interface {intf}
                            interface {intf}
                            no shut
                            """
                            uut.configure(cfg.format(intf=intf))  
            op = uut.execute("show ip interface brief | incl '100.1.1.1'")
            op1 = op.splitlines()
            for line in op1:
                if line:
                    if 'Eth' in line:
                        intf = line.split()[0]
                        cfg = \
                        """
                        #default interface {intf}
                        interface {intf}
                        no shut
                        """
                        uut.configure(cfg.format(intf=intf))  
                    elif 'Lo' in line:
                        intf = line.split()[0]
                        cfg = \
                        """
                        no interface {intf}
                        """
                        uut.configure(cfg.format(intf=intf))  

            op = uut.execute("show spanning-tree | incl P2p")
            op1 = op.splitlines()
            for line in op1:
                if line:
                    if 'Eth' in line:
                        intf = line.split()[0]
                        cfg = \
                        """
                        #default interface {intf}
                        interface {intf}
                        no switchport
                        """
                        uut.configure(cfg.format(intf=intf))  


        for uut in uut_list:
            for intf in uut.interfaces.keys():
                intf = uut.interfaces[intf].intf
                if 'Eth' in intf:
                    try:
                        uut.configure("#default interface {intf}".format(intf=intf))
                    except:
                        log.info("Default Interface configure failed in device \
                                {uut} interface {intf}".format(uut=uut,intf=intf))
                        self.failed()

            op = uut.execute('show ip interface brief | include up.')
            op1 = op.splitlines()
            int_list=[]
            for line in op1:
                list1 = line.split(" ")
                if 'Eth' in list1[0]:
                    int_list.append(list1[0])
            print(int_list)

            for intf in int_list:
                cfg = """#default interface {intf}"""
                try:
                    uut.configure(cfg.format(intf=intf))
                except:
                    log.error('Invalid CLI given')
 
    except:
        log.error('Common_Cleanup_failed')
        log.error(sys.exc_info())


class BGPNode(object):
    def __init__(self,node,local_as,peer_as,bgp_id,neig_v4,update_source,community,vrf,nwk_list):
        self.node=node
        self.local_as=local_as
        self.peer_as=peer_as
        self.bgp_id=bgp_id
        self.neig_v4=neig_v4
        self.update_source=update_source
        self.vrf=vrf
        self.community=community
        self.nwk_list=nwk_list

 
    def config_leaf_bgp(self):
        cfg = \
            """
            feature bgp
            nv overlay evpn 
            ip community-list standard LOOPBACK seq 999 permit {community}
            ip community-list standard LOOPBACK permit {community}
            route-map ORIGINATE_LOOPBACKS permit 999
            description "set origin and community for loopback prefixes"
            set origin igp 
            set community {community}
            route-map ALLOW_LOOPBACKS permit 999
            
            match community LOOPBACK 
            route-map NEXT_HOP_UNCHANGED permit 10
            
            set ip next-hop unchanged
            router bgp {local_as}
            router-id {bgp_id}
        
            address-family ipv4 unicast
            maximum-paths 2
            maximum-paths ibgp 2
        
            address-family ipv6 unicast
            maximum-paths 2
            maximum-paths ibgp 2
        
            address-family l2vpn evpn
            maximum-paths 2
            maximum-paths ibgp 2
            nexthop route-map NEXT_HOP_UNCHANGED
    
            template peer SPINE_V4
            address-family ipv4 unicast
            allowas-in 1
            send-community
            send-community extended
            route-map ALLOW_LOOPBACKS in
            route-map ALLOW_LOOPBACKS out
       
            address-family l2vpn evpn
            allowas-in 3
            send-community
            send-community extended
            route-map NEXT_HOP_UNCHANGED out
 
            neighbor {neig_v4}
            inherit peer SPINE_V4
            remote-as {peer_as}
            update-source {update_source}
        
            address-family l2vpn evpn
            allowas-in 3
            send-community
            send-community extended
            route-map NEXT_HOP_UNCHANGED out
            """
    
        try:
            self.node.configure(cfg.format(\
                community=self.community,\
                local_as=self.local_as,\
                bgp_id=self.bgp_id,\
                neig_v4=self.neig_v4,\
                peer_as=self.peer_as,\
                update_source=self.update_source))       
        except:
            log.info('BGP conf failed for node',self.node)

    def check_bgp(self):
        op = self.node.execute("show bgp l2vpn evpn summary")
        if 'Idle' in op:
            log.info('BGP L2VPN neighbor failed for node',self.node)
            self.failed
        op = self.node.execute("show ip bgp sum")
        if 'Idle' in op:
            log.info('BGP V4 neighbor failed for node',self.node)
            self.failed


    def bgp_nwk_advt(self):
        for nwk in self.nwk_list:
            cfg = \
            """
            router bgp {local_as}
            router-id {bgp_id}
            address-family ipv4 unicast
            network {nwk} route-map ORIGINATE_LOOPBACKS 
            """
            try:
                self.node.configure(cfg.format(\
                local_as=self.local_as,\
                bgp_id=self.bgp_id,\
                nwk=nwk))
            except:
                log.info('BGP conf failed for node',self.node)

      

class SpineNode(object):
    def __init__(self,node,loop0_ipv4,loop0_ipv4_sec,anycast_gw_mac):
        self.node=node
        self.loop0_ipv4=loop0_ipv4
        self.loop0_ipv4_sec=loop0_ipv4_sec
        self.anycast_gw_mac=anycast_gw_mac
        print("Args are",self.node,self.loop0_ipv4,self.loop0_ipv4_sec)

    def config_loop(self):
        if not 'Nil' in self.loop0_ipv4_sec:
            print("Args are $$$$$$$$$$",self.node,self.loop0_ipv4,self.loop0_ipv4_sec)
            config_str = \
                """
                fabric forwarding anycast-gateway-mac {anycast_gw_mac}
                int loopback0
                ip add {loop0_ipv4}
                ip add {loop0_ipv4_sec} second
                descr NVE loopback
                no shut
                """
            try:
                self.node.configure(config_str.format(loop0_ipv4=self.loop0_ipv4,loop0_ipv4_sec=self.loop0_ipv4_sec,anycast_gw_mac=self.anycast_gw_mac))    
            except:
                log.error('Loop Config Failed on UUT',self.node)

        else:
            config_str = \
                """
                int loopback0
                ip add {loop0_ipv4}
                descr NVE loopback
                no shut
                """
            try:
                self.node.configure(config_str.format(loop0_ipv4=self.loop0_ipv4))
            except:
                log.error('Loop Config Failed on UUT',self.node)


 #########################################
 #########################################



class LeafObject(object):
    def __init__(self,node,vlan_start,vn_segment_start,vlan_vni_scale,routed_vlan,routed_vni,routed_vrf,vrf_rt_exp_list,vrf_rt_imp_list,bgp_local_as):
        self.node=node
        self.vlan_start=vlan_start
        self.vn_segment_start=vn_segment_start
        self.vlan_vni_scale=vlan_vni_scale
        self.routed_vlan=routed_vlan
        self.routed_vni=routed_vni
        self.routed_vrf=routed_vrf
        self.vrf_rt_exp_list=vrf_rt_exp_list
        self.vrf_rt_imp_list=vrf_rt_imp_list
        self.bgp_local_as=bgp_local_as

 
    def vxlan_conf(self):
        for rt in self.vrf_rt_imp_list:
            print('rt/routed_vni isss',rt,self.routed_vni)
            cmd=\
            '''
            vrf context {routed_vrf}
            vni {routed_vni}
            rd auto
            address-family ipv4 unicast
            route-target import {rt}:{routed_vni}
            route-target import {rt}:{routed_vni} evpn
            route-target import {rt}:{routed_vni}
            route-target import {rt}:{routed_vni} evpn
            '''
        try:
            self.node.configure(cmd.format(routed_vni=self.routed_vni,rt=rt,routed_vrf=self.routed_vrf))
        except:
            log.error('routed vlan vrf import config failed') 

        for rt in self.vrf_rt_exp_list:
            cmd=\
            '''
            vrf context {routed_vrf}
            vni {routed_vni}
            rd auto
            address-family ipv4 unicast
            route-target export {rt}:{routed_vni}
            route-target export {rt}:{routed_vni} evpn
            route-target export {rt}:{routed_vni}
            route-target export {rt}:{routed_vni} evpn
            '''
        try:
            self.node.configure(cmd.format(routed_vni=self.routed_vni,rt=rt,routed_vrf=self.routed_vrf))
        except:
            log.error('routed vlan vrf  export config failed') 

        cmd = \
            '''
            vlan {routed_vlan} 
            vn-segment {vni}
 
            interface Vlan{routed_vlan}
            no shutdown
            vrf member {routed_vrf}
            no ip redirects
            ip forward
            ipv6 address use-link-local-only
            no ipv6 redirects
 
            interface nve1
            member vni {routed_vni} associate-vrf
        
            router bgp {bgp_local_as}
            vrf {routed_vrf}
            bestpath as-path multipath-relax
            address-family ipv4 unicast
            advertise l2vpn evpn
            maximum-paths 2
            maximum-paths ibgp 2
            address-family ipv6 unicast
            advertise l2vpn evpn
            maximum-paths 2
            maximum-paths ibgp 2
            '''
        try:
            self.node.configure(cmd.format(routed_vni=self.routed_vni,routed_vlan=self.routed_vlan,\
                routed_vrf=self.routed_vrf,bgp_local_as=self.bgp_local_as))
        except:
            log.error('routed vlan vrf  export config failed') 
 
        for i in range(0,self.vlan_vni_scale):
            vlan=self.vlan_start+i
            vni=self.vn_segment_start+i
            cmd = \
            '''
            vlan {vlan} 
            vn-segment {vni}
 
            interface Vlan{vlan}
            no shutdown
            vrf member {routed_vrf}
            ip address {vlan}.1.1.1/24
            ipv6 address {vlan}::1/64
            fabric forwarding mode anycast-gateway
 
            interface nve1
            no shutdown
            source-interface loopback0
            host-reachability protocol bgp
            member vni {vni}
            ingress-replication protocol bgp
            '''
        try:
            self.node.configure(cmd.format(vlan=vlan,vni=vni,routed_vrf=self.routed_vrf))
        except:
            log.error('111 vpc gloabal config failed')
        for rt_imp in self.vrf_rt_imp_list:
            cmd=\
                '''
                evpn
                vni {vni} l2
                rd auto
                route-target import {rt_imp}:{vni}
                '''
            try:
                self.node.configure(cmd.format(rt_imp=rt_imp,vni=vni))
            except:
                log.error('111 vpc gloabal config failed')     

        for rt_exp in self.vrf_rt_exp_list:
            cmd=\
                '''
                evpn
                vni {vni} l2
                rd auto
                route-target export {rt_exp}:{vni}
                '''
            try:
                self.node.configure(cmd.format(rt_exp=rt_exp,vni=vni))
            except:
                log.error('111 vpc gloabal config failed') 


class LeafObject1(object):
    def __init__(self,node,vlan_list,vn_segment_list,routed_vlan,routed_vni,routed_vrf):
        self.node=node
        self.vlan_list=vlan_list
        self.vn_segment_list=vn_segment_list
        self.routed_vlan=routed_vlan
        self.routed_vni=routed_vni
        self.routed_vrf=routed_vrf
 
    def ibgp_vxlan_conf(self):
        for vlan,vni in zip(self.vlan_list,self.vn_segment_list):
            cmd = \
            '''
            vlan {vlan} 
            vn-segment {vni}
 
            interface Vlan{vlan}
            no shutdown
            vrf member {routed_vrf}
            ip address {vlan}.1.1.1/24
            ipv6 address {vlan}::1/64
            fabric forwarding mode anycast-gateway
 
            interface nve1
            no shutdown
            source-interface loopback0
            host-reachability protocol bgp
            member vni {vni}
            ingress-replication protocol bgp
            '''
            try:
                self.node.configure(cmd.format(vlan=vlan,vni=vni,routed_vrf=self.routed_vrf))
            except:
                log.error('111 vpc gloabal config failed')

        for vni in self.vn_segment_list: 
            cmd=\
                '''
                evpn
                vni {vni} l2
                rd auto
                route-target import auto
                route-target export auto
                '''
            try:
                self.node.configure(cmd.format(vni=vni))
            except:
                log.error('111 vpc gloabal config failed')     
        cmd=\
            '''
            vrf context {routed_vrf}
            vni {routed_vni}
            rd auto
            address-family ipv4 unicast
            route-target both auto
            route-target both auto evpn 
            '''
        try:
            self.node.configure(cmd.format(routed_vni=self.routed_vni,routed_vrf=self.routed_vrf))
        except:
            log.error('routed vlan vrf import config failed') 
            
        cmd = \
            '''
            vlan {routed_vlan} 
            vn-segment {vni}
 
            interface Vlan{routed_vlan}
            no shutdown
            vrf member {routed_vrf}
            no ip redirects
            ip forward
            ipv6 address use-link-local-only
            no ipv6 redirects

            interface nve1
            member vni {routed_vni} associate-vrf
            '''
        try:
            self.node.configure(cmd.format(routed_vni=self.routed_vni,routed_vlan=self.routed_vlan,\
                routed_vrf=self.routed_vrf))
        except:
            log.error('routed vlan vrf  export config failed') 
 

class OspfV4Router(object):
    def __init__(self,node,proc_id,router_id,if_list):
        self.node=node
        self.proc_id=proc_id
        self.if_list=if_list
        self.router_id=router_id

    def ospf_conf(self):
        cmd=\
            '''
            feature ospf
            router ospf {proc_id}
            router-id {router_id}
            '''
        try:
            self.node.configure(cmd.format(proc_id=self.proc_id,router_id=self.router_id),timeout=120)

        except:
            log.error('OSPF config failed for node',self.node)

        for intf in self.if_list:
            cmd=\
                '''
                interface {intf}
                ip router ospf {proc_id} area 0
                '''
            try:
                self.node.configure(cmd.format(intf=intf,proc_id=self.proc_id))
            except:
                log.error('PIM config failed for node',self.node,intf) 




class PimV4Router(object):
    def __init__(self,node,rp_add,if_list):
        self.node=node
        self.rp_add=rp_add
        self.if_list=if_list


    def pim_conf(self):
        cmd=\
            '''
            feature pim
            ip pim rp-address {rp_add}
            '''
        try:
            self.node.configure(cmd.format(rp_add=self.rp_add))

        except:
            log.error('PIM config failed for node',self.node)

        for intf in self.if_list:
            cmd=\
                '''
                interface {intf}
                ip pim sparse-mode
                '''
            try:
                self.node.configure(cmd.format(intf=intf))
            except:
                log.error('PIM config failed for node',self.node,intf) 



class IbgpRouter(object):
    def __init__(self,node,proc_id,router_id,if_list):
        self.node=node
        self.proc_id=proc_id
        self.router_id=router_id
        self.if_list=if_list
        #self.adv_nwk_list=adv_nwk_list



#####
#####
#####
class VPCNode(object):
    def __init__(self,node,vpc_domain,peer_ip,mct_mem_list1,vpc_po,vpc_po_mem_list1,vlan_range,vpc_po_type,src_ip):
        self.node=node
        self.vpc_domain=vpc_domain
        self.peer_ip=peer_ip
        self.mct_mem_list1=mct_mem_list1
        self.vpc_po=vpc_po
        self.vpc_po_mem_list1=vpc_po_mem_list1
        self.vlan_range=vlan_range
        self.vpc_po_type=vpc_po_type
        self.peer_ip=peer_ip
        self.src_ip=src_ip

    def vpc_conf(self):
        cmd = \
        '''
        spanning-tree mode mst 
        no feature vpc 
        feature vpc
        feature lacp
        vpc domain {vpc_domain}
        peer-switch
        peer-keepalive destination {peer_ip} source {src_ip}
        ip arp synchronize
        ipv6 nd synchronize 
        auto-recovery
        peer-gateway
        interface port-channel {vpc_domain}
        #port-channel mode active
        no shut
        switchport
        switchport mode trunk
        spanning-tree port type network
        vpc peer-link
        '''
        try:
            self.node.configure(cmd.format(peer_ip=self.peer_ip,vpc_domain=self.vpc_domain,src_ip=self.src_ip))
        except:
            log.error('111 vpc gloabal config failed')

        for intf in self.mct_mem_list1:
            cmd = \
                '''
                #default interface {intf}
                interface {intf}
                channel-group {vpc_domain} force mode active
                no shut
            '''
            try:
                self.node.configure(cmd.format(intf=intf,vpc_domain=self.vpc_domain))
            except:
                self.node.execute("show port-channel compatibility-parameters") 
                log.error('222 vpc_peer_link member conf failed for uut/interface')   
        
                 
  
        if 'access' in self.vpc_po_type:
            cmd = \
                '''
                vlan {vlan_range}
                #interface port-channe {vpc_po}
                interface port-channe {vpc_po}
                #port-channel mode active
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
                #interface port-channe {vpc_po}
                interface port-channe {vpc_po}
                #port-channel mode active
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
            ##default interface {intf}
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
        peer-switch
        peer-keepalive destination {peer_ip} source {src_ip}
        ip arp synchronize
        ipv6 nd synchronize 
        auto-recovery
        peer-gateway
        interface port-channel {vpc_domain}
        #port-channel mode active
        no shut
        switchport
        switchport mode trunk
        spanning-tree port type network
        vpc peer-link
        '''
        try:
            self.node.configure(cmd.format(peer_ip=self.peer_ip,vpc_domain=self.vpc_domain,src_ip=self.src_ip))
        except:
            log.error('111 vpc gloabal config failed')

        for intf in self.mct_mem_list1:
            cmd = \
                '''
                #default interface {intf}
                interface {intf}
                channel-group {vpc_domain} force mode active
                no shut
            '''
            try:
                self.node.configure(cmd.format(intf=intf,vpc_domain=self.vpc_domain))
            except:
                self.node.execute("show port-channel compatibility-parameters") 
                log.error('222 vpc_peer_link member conf failed for uut/interface')   

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
                #interface port-channe {vpc_po}
                interface port-channe {vpc_po}
                #port-channel mode active
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
                #interface port-channe {vpc_po}
                interface port-channe {vpc_po}
                #port-channel mode active
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
            ##default interface {intf}
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




def leaf_ibgp_conf(uut,as_number,rid):

    cmd=\
            '''
            feature nv overlay 
            nv overlay evpn 

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
        log.error('iBGP config failed for uut',uut)  

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
        log.error('iBGP config failed for uut',uut)  

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
        log.error('iBGP config failed for uut',uut)  


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
            log.error('iBGP config failed for uut',uut)   

    
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
            log.error('iBGP config failed for uut',uut) 

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
            log.error('iBGP config failed for uut',uut) 
           
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
  
    def bgp_conf(self):
        leaf_ibgp_conf(self.node,rid=self.rid,as_number=self.as_number)        
        leaf_neigh_template_conf(self.node,self.as_number,self.update_src)
        leaf_neigh_conf(self.node,self.as_number,self.neigh_list,self.template_name)
        if not 'Nil' in self.adv_nwk_list:
            ibgp_nwk_adv_conf(self.node,self.as_number,self.adv_nwk_list)


 

def spine_ibgp_conf(uut,as_number,rid,adv_nwk_list,update_src,neigh_list):
    cmd=\
            '''
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
        log.error('iBGP config failed for uut',uut)

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
        log.error('iBGP config failed for uut',uut)   

  
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
            log.error('iBGP config failed for uut',uut) 

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

 
def routed_svi_configure(uut,routed_vlan,routed_vni,count):
    cmd = ""
    for i in range(0,count):
        cmd += 'no interface Vlan{routed_vlan}\n'.format(routed_vlan=routed_vlan)
        cmd += 'interface Vlan{routed_vlan}\n'.format(routed_vlan=routed_vlan)
        cmd += 'no shutdown\n'
        # cmd += 'mtu 9216\n'
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
 
 
 
 
 
def svi_configure_old(uut,vlan,count1,count2,routed_vni,ipv4_add,ipv6_add):
    """>>> for j in range(0,20):
    ...     b = b + 1
    ...     for i in range(0,5):
    ...         a = a + 1
    ...         print("vlan",a)
    ...         print('vrf',b)
    ... 
    cou 1 = 1000
    cput = 20
    0-20

    vlan 101
    vrf 10001
    vlan 102
    vrf 10001
    vlan 103"""
    v4 = ip_address(ipv4_add)
    v6 = ip_address(ipv6_add)
    c2 = int(count1/count2)
    for i in range(0,count2):
        routed_vni = routed_vni + 1
        for j in range(0,c2):
            vlan = vlan + 1
            v4 = v4+1
            v6 = v6+1
            cmd = \
            '''
            no interface Vlan{vlan}
            interface Vlan{vlan}
            no shutdown
            vrf member vxlan-{routed_vni}
            no ip redirects
            ip address {j}.{i}.1.1/16
            ipv6 address 1:{j}:{i}::1/64
            no ipv6 redirects
            fabric forwarding mode anycast-gateway
            '''
            #print(cmd.format(vlan=vlan,routed_vni=routed_vni,i=i,j=j))
            try:
                uut.configure(cmd.format(vlan=vlan,routed_vni=routed_vni,i=i,j=j))
            except:
                log.error('SVI configure failed for uut',uut,'vlan/vni',vlan,routed_vni)            


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
            # cmd += 'mtu 9216\n'
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



def arp_supp_remove(uut,vni,count,mode):        
    if 'mix' in mode:
        c1 = int(count/2)-1
        vni1 = vni
        vni2 = vni1 + c1 
        vni3 = vni2 + 1
        vni4 = vni3 + c1
        cmd = " "
        cmd += 'interface nve1\n' 
        cmd += 'member vni {vni1}-{vni2}\n'.format(vni1=vni1,vni2=vni2)
        cmd += 'no suppress-arp\n'  
        try:
            uut.configure(cmd)
        except:
            log.info('vni_configure failed for uut %r',uut)

        cmd= " "
        cmd += 'interface nve1\n'
        for vni in range(vni3,vni4): 
            cmd += 'member vni {vni}\n'.format(vni=vni)
            cmd += 'no suppress-arp\n'
            vni = vni + 1
        try:
            uut.configure(cmd)
        except:
            log.error('routed_vni_configure failed for mcast/vni')

    if 'bgp' in mode:
        vni1 = vni
        vni2 = vni1 + int(count) - 1
        cmd = " "
        cmd += 'interface nve1\n' 
        cmd += 'member vni {vni1}-{vni2}\n'.format(vni1=vni1,vni2=vni2)
        cmd += 'no suppress-arp\n'  
        try:
            uut.configure(cmd)
        except:
            log.info('vni_configure failed for uut %r',uut)

    if 'mcast' in mode:
        vni1 = vni
        vni2 = vni1 + int(count) 
        cmd= " "
        cmd += 'interface nve1\n'
        for vni in range(vni1,vni2): 
            cmd += 'member vni {vni}\n'.format(vni=vni)
            cmd += 'no suppress-arp\n'
            vni = vni + 1
        try:
            uut.configure(cmd)
        except:
            log.error('routed_vni_configure failed for mcast/vni')





def arp_supp_add(uut,vni,count,mode):        
    if 'mix' in mode:
        c1 = int(count/2)-1
        vni1 = vni
        vni2 = vni1 + c1 
        vni3 = vni2 + 1
        vni4 = vni3 + c1
        cmd = " "
        cmd += 'interface nve1\n' 
        cmd += 'member vni {vni1}-{vni2}\n'.format(vni1=vni1,vni2=vni2)
        cmd += 'suppress-arp\n'  
        try:
            uut.configure(cmd)
        except:
            log.info('vni_configure failed for uut %r',uut)

        cmd= " "
        cmd += 'interface nve1\n'
        for vni in range(vni3,vni4): 
            cmd += 'member vni {vni}\n'.format(vni=vni)
            cmd += 'suppress-arp\n'
            vni = vni + 1
        try:
            uut.configure(cmd)
        except:
            log.error('routed_vni_configure failed for mcast/vni')

    if 'bgp' in mode:
        vni1 = vni
        vni2 = vni1 + int(count) - 1
        cmd = " "
        cmd += 'interface nve1\n' 
        cmd += 'member vni {vni1}-{vni2}\n'.format(vni1=vni1,vni2=vni2)
        cmd += 'suppress-arp\n'  
        try:
            uut.configure(cmd)
        except:
            log.info('vni_configure failed for uut %r',uut)

    if 'mcast' in mode:
        vni1 = vni
        vni2 = vni1 + int(count)
        cmd= " "
        cmd += 'interface nve1\n'
        for vni in range(vni1,vni2): 
            cmd += 'member vni {vni}\n'.format(vni=vni)
            cmd += 'suppress-arp\n'
            vni = vni + 1
        try:
            uut.configure(cmd)
        except:
            log.error('routed_vni_configure failed for mcast/vni')


def nve_configure_bgp(uut,vni,count):

    cmd1 = \
    """
    interface nve1
    no shutdown
    host-reachability protocol bgp
    source-interface loopback0
    source-interface hold-down-time 250
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
 

def nve_configure_bgp_xconnect(uut,vni,count):

    cmd1 = \
    """
    interface nve1
    no shutdown
    host-reachability protocol bgp
    source-interface loopback0
    source-interface hold-down-time 250
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
            source-interface hold-down-time 250
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
    '''
    else:    
        cmd = " "
        cmd += 'interface nve1\n' 
        cmd += 'no shut\n' 
        cmd += 'source-interface loopback0\n'         
        cmd += 'source-interface hold-down-time 20\n'   

        c1 = int(scale/mcast_group_scale) 5
        #c2 = int(c1/5) 1
        #mcast = ip_address(mcast_group) 
 
        for j in range(0,c1):
            vni1 =  
            mcast = mcast+1
            for i in range(0,c2):
                cmd += 'member vni {vni1}-{vni2}\n'.format(vni=vni)
                cmd += 'mcast-group {mcast}\n'.format(mcast=mcast) 
                vni = vni + 1
    try:
        uut.configure(cmd)
    except:
        log.error('routed_vni_configure failed for mcast/vni')

    '''



 
def nve_configure_only_bgp(uut,vni,count):
    cmd1 = \
            '''
            no interface nve1
            interface nve1
            no shutdown
            host-reachability protocol bgp

            source-interface loopback0
            source-interface hold-down-time 250
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


def nve_configure_mcast(uut,vni,count,mcast_group):
    cmd = \
            '''
            interface nve1
            no shutdown
            host-reachability protocol bgp

            source-interface loopback0
            source-interface hold-down-time 250
            '''
    try:
        uut.configure(cmd)
    except:
        log.error('vni_configure failed for uut',uut)

    c1 = int(count/2)
    vni = vni + c1 + 1
    c2 = int(c1/5)
    mcast = ip_address(mcast_group) 
    cmd= " "
    cmd += 'interface nve1\n'
    for j in range(0,5): 
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


def nve_configure_mcast222(uut,vni,count,mcast_group,mcast_group_scale):
    cmd = \
            '''
            interface nve1
            no shutdown
            host-reachability protocol bgp

            source-interface loopback0
            source-interface hold-down-time 250
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
            source-interface hold-down-time 250
            '''
    try:
        uut.configure(cmd1)
    except:
        log.info('vni_configure failed for uut %r',uut)

    if int(count)>500:
        c2 = int(count/20)
        a1 = 20
    else:  
        c2 = int(count/5)  
        a1 = 5              
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
            

def L3RouteCheck(uut,route,vrf_name):
    """ function to configure vpc """
    log.info("Entering proc to check L3 route")
    if 'default' in vrf_name:
        config_str="""
                show ip route {route}
   	        """
        try:
            cliout= uut.configure(config_str.format(route=route))
            #cliout=json.loads(cliout1)
            if route in cliout:
                return 1
            elif "Route not found" in cliout:
                log.error('RouteCheck failed for',uut,route)
                log.error(sys.exc_info()) 
                return 0
        except:
            log.error('Traffic test failed')
            log.error(sys.exc_info())
            #self.failed('Spirect traffic test failed')
    else:
        config_str="""
                show ip route {route} vrf {vrf_name}
   	        """
        try:
            cliout= uut.configure(config_str.format(route=route,vrf_name=vrf_name))
            #cliout=json.loads(cliout1)
            if route in cliout:
                return 1
            else:
                log.error('RouteCheck failed for',uut,route)
                log.error(sys.exc_info()) 
                return 0
        except:
            log.error('Traffic test failed')
            log.error(sys.exc_info())
            #self.failed('Spirect traffic test failed') 






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
 


def nvenhicheck(uut):
    cmd = "run bash /lc/isan/bcm/bcm-shell d EGR_DGPP_TO_NHI | grep NEXT_HOP_INDEX=0x"
    op1 =  uut.execute(cmd)
    log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
    log.info("Node is ----- %r",uut)
    log.info("output is Danish2----- %r",op1)
    log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")




class LeafObject2(object):
    def __init__(self,node,vlan,vni,vlan_scale,routed_vlan,routed_vni,routed_vni_scale,\
    ipv4_add,ipv6_add,mcast_group,as_number):
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

                                    
    def vxlan_conf(self):
        vrf_configure(self.node,self.routed_vni,self.routed_vni_scale) 
        #cmd = "run bash /lc/isan/bcm/bcm-shell d chg egr_l3_next_hop | grep INTF_NUM=8"
        #op1 =  self.node.execute(cmd)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        #log.info("Node is ----- %r",self.node)
        ##log.info("output is Danish1----- %r",op1)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        vlan_vni_configure(self.node,self.routed_vlan,self.routed_vni,self.routed_vni_scale)  
        #cmd = "run bash /lc/isan/bcm/bcm-shell d chg egr_l3_next_hop | grep INTF_NUM=8"
        #op1 =  self.node.execute(cmd)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        #log.info("Node is ----- %r",self.node)
        #log.info("output is Danish2----- %r",op1)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        vlan_vni_configure(self.node,self.vlan,self.vni,self.vlan_scale) 
        #cmd = "run bash /lc/isan/bcm/bcm-shell d chg egr_l3_next_hop | grep INTF_NUM=8"
        #log.info("Node is ----- %r",self.node)
        #op1 =  self.node.execute(cmd)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        #log.info("Node is ----- %r",self.node)
        #log.info("output is Danish3 ----- %r",op1)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        routed_svi_configure(self.node,self.routed_vlan,self.routed_vni,self.routed_vni_scale)
        #cmd = "run bash /lc/isan/bcm/bcm-shell d chg egr_l3_next_hop | grep INTF_NUM=8"
        #log.info("Node is ----- %r",self.node)
        #op1 =  self.node.execute(cmd)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        #log.info("Node is ----- %r",self.node)
        #log.info("output is Danish4----- %r",op1)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        #svi_configure(self.node,self.vlan,self.vlan_scale,self.count2,self.routed_vni,self.ipv4_add,self.ipv6_add)
        svi_configure(self.node,self.vlan,self.vlan_scale,self.ipv4_add,self.ipv6_add,self.routed_vni,self.routed_vni_scale)
        #cmd = "run bash /lc/isan/bcm/bcm-shell d chg egr_l3_next_hop | grep INTF_NUM=8"
        #log.info("Node is ----- %r",self.node)
        #op1 =  self.node.execute(cmd)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        #log.info("Node is ----- %r",self.node)
        #log.info("output is Danish5----- %r",op1)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        nve_configure_bgp(self.node,self.vni,self.vlan_scale)
        #cmd = "run bash /lc/isan/bcm/bcm-shell d chg egr_l3_next_hop | grep INTF_NUM=8"
        #log.info("Node is ----- %r",self.node)
        #op1 =  self.node.execute(cmd)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        #log.info("Node is ----- %r",self.node)
        #log.info("output is Danish6----- %r",op1)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        nve_configure_mcast(self.node,self.vni,self.vlan_scale,self.mcast_group)
        #cmd = "run bash /lc/isan/bcm/bcm-shell d chg egr_l3_next_hop | grep INTF_NUM=8"
        #op1 =  self.node.execute(cmd)
        #log.info("Node is ----- %r",self.node)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        #log.info("Node is ----- %r",self.node)
        #log.info("output is Danish7----- %r",op1)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        routed_nve_configure(self.node,self.routed_vni,self.routed_vni_scale)
        #log.info("Node is ----- %r",self.node)
        #cmd = "run bash /lc/isan/bcm/bcm-shell d chg egr_l3_next_hop | grep INTF_NUM=8"
        #op1 =  self.node.execute(cmd)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        #log.info("Node is ----- %r",self.node)
        #log.info("output is Danish8----- %r",op1)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        evpn_vni_configure(self.node,self.vni,self.vlan_scale)
        #cmd = "run bash /lc/isan/bcm/bcm-shell d chg egr_l3_next_hop | grep INTF_NUM=8"
        #log.info("Node is ----- %r",self.node)
        #op1 =  self.node.execute(cmd)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        #log.info("Node is ----- %r",self.node)        
        #log.info("output is Danish9----- %r",op1)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        vrf_bgp_configure(self.node,self.as_number,self.routed_vni,self.routed_vni_scale)
        #op1 =  self.node.execute(cmd)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
        #log.info("Node is ----- %r",self.node)
        #log.info("output is Danish9----- %r",op1)
        #log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++")
 

class LeafObject222(object):
    def __init__(self,node,vlan,vni,vlan_scale,routed_vlan,routed_vni,routed_vni_scale,\
    ipv4_add,ipv6_add,mcast_group,as_number,ir_mode):
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
        '''
        ir_mode = bgp,mcast,mix
        '''

                                    
    def vxlan_conf(self):
        vrf_configure(self.node,self.routed_vni,self.routed_vni_scale) 
        vlan_vni_configure(self.node,self.routed_vlan,self.routed_vni,self.routed_vni_scale)  
        vlan_vni_configure(self.node,self.vlan,self.vni,self.vlan_scale) 
        routed_svi_configure(self.node,self.routed_vlan,self.routed_vni,self.routed_vni_scale)
        svi_configure(self.node,self.vlan,self.vlan_scale,self.ipv4_add,self.ipv6_add,self.routed_vni,self.routed_vni_scale)
        if 'mix' in self.ir_mode:
            log.info(banner("Replication mode is BGP + MCAST"))
            nve_configure_bgp(self.node,self.vni,self.vlan_scale)
            nve_configure_mcast(self.node,self.vni,self.vlan_scale,self.mcast_group)
        elif 'bgp' in self.ir_mode:         
            log.info(banner("Replication mode is BGP"))
            nve_configure_only_bgp(self.node,self.vni,self.vlan_scale)
        elif 'mcast' in self.ir_mode:
            log.info(banner("Replication mode is MCAST"))
            nve_configure_only_mcast(self.node,self.vni,self.vlan_scale,self.mcast_group)            
        routed_nve_configure(self.node,self.routed_vni,self.routed_vni_scale)
        evpn_vni_configure(self.node,self.vni,self.vlan_scale)
        vrf_bgp_configure(self.node,self.as_number,self.routed_vni,self.routed_vni_scale)
  

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




class LeafObjectL2(object):
    def __init__(self,node,vlan,vni,vlan_scale,\
    mcast_group,as_number,ir_mode,mcast_group_scale):
        self.node=node
        self.vlan=vlan
        self.vni=vni
        self.vlan_scale=vlan_scale
        self.mcast_group=mcast_group
        self.as_number=as_number
        self.ir_mode=ir_mode
        self.mcast_group_scale=mcast_group_scale
        
        #ir_mode = bgp,mcast,mix
        
    def vxlan_conf(self):
        #vrf_configure(self.node,self.routed_vni,self.routed_vni_scale) 
        #vlan_vni_configure(self.node,self.routed_vlan,self.routed_vni,self.routed_vni_scale)  
        vlan_vni_configure(self.node,self.vlan,self.vni,self.vlan_scale) 
        #routed_svi_configure(self.node,self.routed_vlan,self.routed_vni,self.routed_vni_scale)
        #svi_configure(self.node,self.vlan,self.vlan_scale,self.ipv4_add,self.ipv6_add,self.routed_vni,self.routed_vni_scale)
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
        #routed_nve_configure(self.node,self.routed_vni,self.routed_vni_scale)
        evpn_vni_configure(self.node,self.vni,self.vlan_scale)
        #vrf_bgp_configure(self.node,self.as_number,self.routed_vni,self.routed_vni_scale)




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

 

def DevicePreCleanUut(uut):
    try:
        uut.configure('no feature interface-vlan')
        uut.configure('feature interface-vlan')
        log.info(banner("Staring Pre clean "))
        uut.configure('no interface nve1')
        uut.configure('terminal session-timeout 0')
        cmd  =  uut.configure('sh run | incl vlan')
        cmd1  = cmd.splitlines()
        for line in cmd1:
            if line:
                if 'vlan' in line.split()[0]:
                    if ',' in line:
                        line1 = 'no '+line
                        log.info('deleting vlans %r from uut %r',line,str(uut))
                        uut.configure(line1)


        for intf in uut.interfaces.keys():
            intf = uut.interfaces[intf].intf
            if 'Eth' in intf:
                try:
                    uut.configure("default interface {intf}".format(intf=intf))
                except:
                    log.info("Default Interface configure failed in device \
                    {uut} interface {intf}".format(uut=uut,intf=intf))
                    self.failed()


        op = uut.execute('sh vrf detail | incl Name')
        op1 = op.splitlines()
        for line in op1:
            if not 'default' in line and not 'management' in line:
                if line:
                    list1=line.split(" ")
                    vrf_id= list1[1][:-1]
                    cfg = """no vrf context  {vrf_id}"""
                    try:
                        uut.configure(cfg.format(vrf_id=vrf_id))
                    except:
                        log.error('vrf_id delete failed in uut',uut,'vrf id is',vrf_id)


        op = uut.execute("sh run | incl 'ip route '")
        op1 = op.splitlines()
        for line in op1:
            if line:
                if not 'run' in line:
                    if not '10.127' in line:
                        if 'ip route ' in line: 
                            cfg = "no {line}"
                            #uut.configure(cfg.format(line=line))   
                            try:
                                uut.configure(cfg.format(line=line))  
                            except:
                                log.error('static route delete failed in uut',uut)
                         
        op = uut.execute("show run | incl community-list")
        op1 = op.splitlines()
        for line in op1:
            if line:
                cfg = "no {line}"
                try:
                    uut.configure(cfg.format(line=line))  
                except:
                    log.error('community-list delete failed in uut',uut)

        op = uut.execute("show run | incl 'interface port-channel'")
        op1 = op.splitlines()
        for line in op1:
            if line:
                cfg = "no {line}"
                try:
                    uut.configure(cfg.format(line=line))  
                except:
                    log.error('port-channel delete failed in uut',uut)


        op = uut.execute("show run | incl route-map")
        op1 = op.splitlines()
        for line in op1:
            if line:
                if 'permit' in line:
                    cfg = "no {line}"
                    try:
                        uut.configure(cfg.format(line=line))  
                    except:
                        log.error('route-map delete failed in uut',uut)


        op = uut.execute("show ip interface brief vrf all")
        op1 = op.splitlines()
        for line in op1:
            if line:
                if 'Eth' in line:
                    intf = line.split()[0]
                    if '.' in intf:
                        uut.configure('no interface {intf}'.format(intf=intf))
                    else:    
                        cfg = \
                            """
                            default interface {intf}
                            interface {intf}
                            no shut
                            """
                        uut.configure(cfg.format(intf=intf))  
        op = uut.execute("show ip interface brief | incl '100.1.1.1'")
        op1 = op.splitlines()
        for line in op1:
            if line:
                if 'Eth' in line:
                    intf = line.split()[0]
                    cfg = \
                        """
                        default interface {intf}
                        interface {intf}
                        no shut
                        """
                    uut.configure(cfg.format(intf=intf))  
                elif 'Lo' in line:
                    intf = line.split()[0]
                    cfg = \
                        """
                        no interface {intf}
                        """
                    uut.configure(cfg.format(intf=intf))  

        op = uut.execute("show spanning-tree | incl P2p")
        op1 = op.splitlines()
        for line in op1:
            if line:
                if 'Eth' in line:
                    intf = line.split()[0]
                    cfg = \
                        """
                        default interface {intf}
                        interface {intf}
                        no switchport
                        """
                    uut.configure(cfg.format(intf=intf))  



        for intf in uut.interfaces.keys():
            intf = uut.interfaces[intf].intf
            if 'Eth' in intf:
                try:
                    uut.configure("default interface {intf}".format(intf=intf))
                except:
                    log.info("Default Interface configure failed in device \
                            {uut} interface {intf}".format(uut=uut,intf=intf))
                    self.failed()

        op = uut.execute('show ip interface brief | include up.')
        op1 = op.splitlines()
        int_list=[]
        for line in op1:
            list1 = line.split(" ")
            if 'Eth' in list1[0]:
                int_list.append(list1[0])
        print(int_list)

        for intf in int_list:
            cfg = """default interface {intf}"""
            try:
                uut.configure(cfg.format(intf=intf))
            except:
                log.error('Invalid CLI given')
 
    except:
        log.error('Common_Cleanup_failed')
        log.error(sys.exc_info())





def ConnectSpirent(labserver_ip,tgn_ip,port_list):
    """ function to configure vpc """
    logger.info(banner("Entering proc to connect to Spirent"))
    try:
        lab_svr_sess = sth.labserver_connect(server_ip =labserver_ip,create_new_session = 1, session_name = "Stc",user_name = "danthoma")
        intStatus = sth.connect(device=tgn_ip, port_list = port_list,break_locks = 1, offline = 0 )
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
 

def DisConnectSpirent(labserver_ip):
    """ function to configure vpc """
    logger.info(banner("Entering proc to Disconnect to Spirent"))
    try:
        lab_svr_sess = sth.labserver_disconnect(server_ip =labserver_ip,user_name = "danthoma",terminate_session = 1)
    except:

        log.error('Spirect Diconnection failed')
        log.error(sys.exc_info())


def SpirentTunnelStreamConfOLD(port_handle,source_mac,protocol):
    log.info("Entering the function to generate %r stream",protocol)

    if 'cdp' in protocol:
        mac_dst_add = '01:00:0c:cc:cc:cc'
        name = "CDP"

    elif 'lacp' in protocol:
        mac_dst_add = '01:00:0c:cc:cc:cc'
        name = "LACP"  

    elif 'stp' in protocol:
        mac_dst_add = '01:80:c2:00:00:00'
        name = "STP"  

    elif 'igmp' in protocol:
        mac_dst_add = '01:00:5e:00:00:01'
        name = "IGMP"  

    try:
        streamblock_ret1 = sth.traffic_config (
            mode ='create',\
            port_handle =port_handle,\
            l2_encap ='ethernet_ii',\
            mac_src =source_mac,\
            ether_type ='2000',\
            mac_dst = mac_dst_add ,\
            name = name,\
            length_mode ='fixed',\
            rate_pps ='1000')

        status = streamblock_ret1['status']
        log.info("tunnel stream block create status %r",status)
        if (status == '0') :
            log.info('run sth.traffic_config failed for V4 %r', streamblock_ret1)
            
    except:
        log.error('tunnel stream block config failed')
        log.error(sys.exc_info())
 


def CreateSpirentStreams(port_hdl,ip_src,ip_dst,mac_src,mac_dst,stream_id,rate_pps,mac_count,mac_mode,mac_step,vlan_id):
    #self,port_hdl_list,ip_src_list,ip_dst_list,mac_src_list,mac_dst_list,stream_list,rate_pps,mac_count,mac_mode,mac_step,vlan_id): 
    """ function to configure Stream """
    log.info(banner("Entering proc to configure streams in Spirent"))
    try:
        streamblock_ret1 = sth.traffic_config (
                mode = 'create',
                port_handle = port_hdl,
                l2_encap = 'ethernet_ii_vlan',
                vlan_id=vlan_id,
                l3_protocol = 'ipv4',
                ip_src_addr = ip_src,
                ip_dst_addr = ip_dst,
                #ip_dst_count = '20',
                #ip_dst_mode = 'increment',
                #ip_dst_step ='0.0.0.1',
                ip_ttl = '255',
                ip_hdr_length = '5',
                ip_protocol = '253',
                mac_src = mac_src,
                mac_dst = mac_dst,
                #mac_dst_count = mac_count,
                #mac_dst_mode = mac_mode,
                #mac_dst_step = mac_step,
                mac_src_count= mac_count,
                mac_src_mode=mac_mode,
                mac_src_step=mac_step,
                stream_id = stream_id,
                rate_pps = rate_pps,
                mac_discovery_gw = ip_dst)
         
        status = streamblock_ret1['status']

        if (status == '0') :
            log.info('run sth.traffic_config failed for V4 %r', streamblock_ret1)
        else:
            log.info(banner("CreateSpirentStreams PASS"))

            
    except:
        log.error('Spirect traffic config failed')
        log.error(sys.exc_info())
 






def CreateSpirentStreamsVlan(port_hdl,ip_src,ip_dst,mac_src,mac_dst,stream_id,rate_pps,mac_count,mac_mode,mac_step,vlan_id,vlan_count,vlan_mode,vlan_step):
    #self,port_hdl_list,ip_src_list,ip_dst_list,mac_src_list,mac_dst_list,stream_list,rate_pps,mac_count,mac_mode,mac_step,vlan_id): 
    """ function to configure Stream """

    logger.info(banner("Entering proc to configure streams in Spirent"))
    try:
        streamblock_ret1 = sth.traffic_config (
                mode = 'create',
                port_handle = port_hdl,
                l2_encap = 'ethernet_ii_vlan',
                frame_size_min='500',
                frame_size_max='9000',
                frame_size_step='500',
                vlan_id=vlan_id,
                vlan_id_count=vlan_count,
                vlan_id_mode=vlan_mode,
                vlan_id_step=vlan_step,
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
                mac_dst_count = mac_count,
                mac_dst_mode = mac_mode,
                mac_dst_step = mac_step,
                mac_src_count= mac_count,
                mac_src_mode=mac_mode,
                mac_src_step=mac_step,
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
                transmit_mode = 'multi_burst',
                inter_stream_gap = '12',
                mac_discovery_gw = ip_dst)
         
        status = streamblock_ret1['status']

        if (status == '0') :
            log.info('run sth.traffic_config failed for V4 %r', streamblock_ret1)
            
    except:
        log.error('Spirect traffic config failed')
        log.error(sys.exc_info())


def countdown(t):
    '''https://stackoverflow.com/questions/25189554/countdown-clock-0105'''
    while t:
        mins, secs = divmod(t, 60)
        timeformat = '{:02d}:{:02d}'.format(mins, secs)
        print(timeformat, end='\r')
        time.sleep(1)
        t -= 1


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
            uut.configure(config_str.format(intf=intf,esi_po=esi_po))        
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

        #def ConfigureEsiPo(uut,esid,sys_mac,esi_po,vlan_range,mode,member_list):

def CreateSpirentStreamsVlan222(port_hdl,ip_dst_addr,ip_dst_count,ip_dst_mode,ip_dst_step,\
                                         ip_src_addr,ip_src_count,ip_src_mode,ip_src_step,\
                                         mac_src,mac_src_count,mac_src_mode,mac_src_step,\
                                         mac_dst,mac_dst_count,mac_dst_mode,mac_dst_step,\
                                         vlan_id,vlan_id_count,vlan_id_mode,vlan_id_step,\
                                         stream_id,rate_pps,transmit_mode):

    logger.info(banner("Entering CreateSpirentStreamsVlan222 to configure streams in Spirent"))
    try:
        streamblock_ret1 = sth.traffic_config (
                mode = 'create',
                port_handle = port_hdl,
                l2_encap = 'ethernet_ii_vlan',
                frame_size_min='500',
                frame_size_max='9000',
                frame_size_step='500',
                vlan_id=vlan_id,
                vlan_id_count=vlan_id_count,
                vlan_id_mode=vlan_id_mode,
                vlan_id_step=vlan_id_step,
                l3_protocol = 'ipv4',
                ip_id = '0',
                ip_src_addr = ip_src_addr,
                ip_src_count = ip_src_count,
                ip_src_mode = ip_src_mode,
                ip_src_step =ip_src_step,
                ip_dst_addr = ip_dst_addr,
                ip_dst_count = ip_dst_count,
                ip_dst_mode = ip_dst_mode,
                ip_dst_step =ip_dst_step,
                ip_ttl = '255',
                ip_hdr_length = '5',
                ip_protocol = '253',
                mac_src = mac_src,
                mac_dst = mac_dst,
                mac_dst_count = mac_dst_count,
                mac_dst_mode = mac_dst_mode,
                mac_dst_step = mac_dst_step,
                mac_src_count= mac_src_count,
                mac_src_mode=mac_src_mode,
                mac_src_step=mac_src_step,
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
                mac_discovery_gw = ip_dst_addr)
         
        status = streamblock_ret1['status']

        log.info('+-----------------------------------------------------------------------+')
        log.info('stream_id : %r vlan_id : %r rate_pps : %r',streamblock_ret1['stream_id'],vlan_id,rate_pps)                
        log.info('+-----------------------------------------------------------------------+')

        if (status == '0') :
            log.info('run sth.traffic_config failed for V4 %r', streamblock_ret1)
            
    except:
        log.error('Spirect traffic config failed')
        log.error(sys.exc_info())
    

def SpirentFrameCountTest222(port_hdl1,peer_scale,port_handle_list):
    for port_hdl in [port_hdl1]:
        traffic_ctrl_ret = sth.traffic_control (port_handle = port_hdl, action = 'stop', db_file=0 ) 

    for port_hdl in port_handle_list:
        log.info("Clearing Stats in CountTest222 for port %r",port_hdl) 
        sth.traffic_control(port_handle = port_hdl, action = 'clear_stats')
        sth.traffic_control(port_handle = port_hdl, action = 'clear_stats')

    #for port_hdl in [port_hdl1]:        
    traffic_ctrl_ret = sth.traffic_control(port_handle = port_hdl1, action = 'run')
    log.info("Traffic restarting in CountTest222 before countdown for port %r",port_hdl1) 

    countdown(60)

    for port_hdl in [port_hdl1]: 
        log.info("Traffic Stopping in CountTest222 after countdown for port %r",port_hdl)    
        traffic_ctrl_ret = sth.traffic_control (port_handle = port_hdl, action = 'stop', db_file=0 ) 
    
    for port_hdl in [port_hdl1]:
        res1 = sth.traffic_stats(port_handle = port_hdl, mode = 'streams') 
        log.info('Traffic status on Spirent Port Hdl %r is %r',port_hdl,res1)
     

        stream_list =  list(res1[port_hdl]['stream'].keys())
        for stream_id in stream_list:
            if not 'unknown' in stream_id:  
                #rx_count = res1['port6']['stream'][stream_id]['rx']['rx_sig_count'] 
                #tx_count = res1['port6']['stream'][stream_id]['tx']['total_pkts']
                rx_count = res1[port_hdl]['stream'][stream_id]['rx']['rx_sig_count'] 
                tx_count = res1[port_hdl]['stream'][stream_id]['tx']['total_pkts']
                log.info('+-----------------------------------------------------------------------+')
                log.info('rx_count is %r,tx_count is %r,stream_id %r',rx_count,tx_count,stream_id)
                log.info('Port handle is %r',port_hdl)                
                log.info('+-----------------------------------------------------------------------+')

                if abs(int(rx_count) - int(peer_scale)*int(tx_count)) > 50:                    
                    if int(peer_scale)*int(tx_count)-int(rx_count) > 100:
                        log.info('Traffic Test failed for stream : %r - RX Count is Less than Expected',stream_id )
                        log.info('RX expected for a TX  %r is %r , actual  %r',tx_count, int(peer_scale)*int(tx_count),rx_count)
                        log.info("+-----Failed Stream Details----%r",res1[port_hdl]['stream'][stream_id])
                        return 0 
                    elif int(rx_count)-int(peer_scale)*int(tx_count) > 100:
                        log.info('Traffic Test failed for stream : %r - RX Count is More than Expected',stream_id)
                        log.info('RX expected for a TX  %r is %r , actual  %r',tx_count, int(peer_scale)*int(tx_count),rx_count)
                        log.info("+-----Failed Stream Details----%r",res1[port_hdl]['stream'][stream_id])
                        return 0 
                else:
                    log.info('Streamblock of PASSED Stream is %r , port is %r',stream_id,port_hdl)

                
    log.info(banner("SpirentFrameCountTest Passed" ))
    return 1


def SwPreCleanup(uut):
    log.info(banner("Deleteing adding vxlan features"))
    feature_clean=\
    """
    no feature nv over
    show clock
    no feature bgp
    show clock
    no feature ospf
    show clock
    no feature pim
    show clock
    no feature interface-vlan
    show clock    
    no feature bfd
    show clock
    terminal session-timeout 0
    show clock
    no vlan 2-3600
    show clock
    line con
    exec-timeout 0
    line vty
    exec-timeout 0
    """ 
    uut.configure(feature_clean,timeout=180) 


    log.info(banner("Deleteing access lists"))
    op = uut.configure("sh run | incl 'ip access-list'")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'copp' in line:
                if not "sh run |" in line:
                    if "access-list" in line:
                        cfg = "no {line}"
                        uut.configure(cfg.format(line=line)) 

    log.info(banner("Delete static routes"))          
    op = uut.configure("sh run | incl 'ip route '")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'run' in line:
                if not '10.127' in line:
                    if 'ip route ' in line: 
                        cfg = "no {line}"
                        uut.configure(cfg.format(line=line))   

    log.info(banner("Deleting vrf"))                  
    op = uut.configure("show vrf |  be vxlan")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'default' in line:
                if not 'management' in line:
                    vrf = line.split()[0]
                    uut.configure('no vrf context {vrf}'.format(vrf=vrf))
                                
    log.info(banner("Deleting Port Channels"))  

    op = uut.configure("sh run | incl 'interface port-channel'")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'run' in line:
                if not "source" in line:
                    if "port-channel" in line:
                        cfg = "no {line}"
                        uut.configure(cfg.format(line=line)) 


 
    log.info(banner("Default Eth interface to L3"))  
    op = uut.configure("sh int br | exclu route")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'Eth' in line:
                if not 'Ethernet' in line:
                    intf = line.split()[0]
                    cfg = \
                        """
                        interface {intf}
                        no switchport
                        """
                    uut.configure(cfg.format(intf=intf))

    log.info(banner("Deleting Loopbacks")) 
    op = uut.configure("show ip interface brief ")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'Lo' in line:
                intf = line.split()[0]
                uut.configure('no interface {intf}'.format(intf=intf))

 
    log.info(banner("Deleting community-list"))                    
    op = uut.execute("show run | incl community-list")
    op1 = op.splitlines()
    for line in op1:
        if not 'run' in line:
            if line:
                if 'community-list' in line:
                    cfg = "no {line}"
                    try:
                        uut.configure(cfg.format(line=line))  
                    except:
                        log.error('community-list delete failed in uut',uut)

    log.info(banner("Deleting route-map"))             
    op = uut.execute("show run | incl route-map")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'route-map' in line:
                if 'permit' in line:
                    cfg = "no {line}"
                    try:
                        uut.configure(cfg.format(line=line))  
                    except:
                        log.error('route-map delete failed in uut',uut)






def CreateSpirentHostBidirStreamScale(port_hdl1,port_hdl2,vlan1,vlan2,ip1,ip2,gw1,gw2,rate_pps,host_scale):
    log.info(banner("In CreateSpirentHostBidirStreamScale"))

    log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)     
    device_ret1 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan1,port_handle = port_hdl1,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip1,intf_ip_addr_step='0.0.0.1',intf_prefix_len = '16',\
    gateway_ip_addr = gw1,count=host_scale); 
     
    log.info("device_ret2---------,%r",device_ret1)        
    device_ret2 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan2,port_handle = port_hdl2,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip2,intf_ip_addr_step='0.0.0.1',intf_prefix_len = '16',\
    gateway_ip_addr = gw2,count=host_scale);
            
    log.info("device_ret2---------,%r",device_ret2)  

    h1 = device_ret1['handle']
    h2 = device_ret2['handle']
       
    streamblock_ret1 = sth.traffic_config (mode= 'create',port_handle= port_hdl1,\
    emulation_src_handle=h1,emulation_dst_handle = h2,bidirectional='1',\
    port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps)

    status = streamblock_ret1['status']

    log.info('+-----------------------------------------------------------------------+')
    log.info('stream_id : %r, vlan1 : %r ,vlan2 : %r ,rate_pps : %r',streamblock_ret1['stream_id'],vlan1,vlan2,rate_pps)                
    log.info('IP1 : %r,IP2 : %r, Host1 : %r ,Host2 : %r ',ip1,ip2,h1,h2)                
    log.info('+-----------------------------------------------------------------------+')

    #ip1 = str(ip_address(ip1)+1) 
    #ip2 = str(ip_address(ip2)+1) 

    if (status == '0') :
        log.info('run sth.traffic_config failed for V4 %r', streamblock_ret1)

'''
-mac_addr
-mac_addr_step
-count
-intf_ip_addr
-intf_ip_addr_step
-mac_addr
-mac_addr_step
-vlan_id
-vlan_id_step
-vlan_user_pri
'''



def TrafficToTriggerPeerLearning(port_handle_list,vlan):
    log.info(banner("------TrafficToTriggerPeerLearning-----"))
    for port_hdl in port_handle_list:
        sth.traffic_control(port_handle = port_hdl, action = 'clear_stats')
        #sth.traffic_config(mode = 'reset',port_handle = port_hdl) 
        
        str1 = hex(randint(16,154))[2:]
        str2 = hex(randint(16,155))[2:] 
        ip1 =  str(randint(1,20))
        ip2 =  str(randint(21,40))

        ip='1.'+ip1+'.'+ip2+'.21'
        gw='1.'+ip1+'.'+ip2+'.1'  
        log.info("Creating Host %r in vlan %r @  port_hdl %r",ip,vlan,port_hdl)   
        device_ret1 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
        encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan,port_handle = port_hdl,\
        intf_ip_addr= ip,intf_prefix_len = '16',gateway_ip_addr = gw)
        log.info("device_ret1 is %r",device_ret1)
            

    for port_hdl in [port_handle_list]:
        for i in range(1,3):
            log.info("ARPing for hosts in port_hdl %r",port_hdl)
            doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1',port_handle=port_hdl)


    #for port_hdl in [port_handle_list]:
    log.info("Deleting hosts in port_hdl ")
    device_ret1 =sth.emulation_device_config(mode='delete',handle='all') 


def NvePeerLearning(port_handle_list,vlan,uut_list,peer_count):
    log.info(banner(" In NvePeerLearning"))
    '''
    for port_hdl in port_handle_list:
        sth.traffic_control(port_handle = port_hdl, action = 'clear_stats')
        #sth.traffic_config(mode = 'reset',port_handle = port_hdl) 
        
        str1 = hex(randint(16,154))[2:]
        str2 = hex(randint(16,155))[2:] 
        ip1 =  str(randint(1,20))
        ip2 =  str(randint(21,40))

        ip='1.'+ip1+'.'+ip2+'.21'
        gw='1.'+ip1+'.'+ip2+'.1'  
        log.info("Creating Host %r in vlan %r @  port_hdl %r",ip,vlan,port_hdl)   
        device_ret1 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
        encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan,port_handle = port_hdl,\
        intf_ip_addr= ip,intf_prefix_len = '16',gateway_ip_addr = gw)
        log.info("device_ret1 is %r",device_ret1)
            

    for port_hdl in port_handle_list:
        for i in range(1,3):
            log.info("ARPing for hosts in port_hdl %r",port_hdl)
            doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1',port_handle=port_hdl)


    #for port_hdl in port_handle_list:
    log.info("Deleting hosts in port_hdl ")
    device_ret1 =sth.emulation_device_config(mode='delete',handle='all') 
    
    countdown(5)
    '''
    for uut in uut_list:
        op1=uut.execute("sh nve peers  | grep nve1 | count")
        if not int(op1) == peer_count:
            log.info("Nve peer check failed for UUT %r",uut)
            uut.execute("sh nve peers")
            return 0
      
        aa=uut.execute("sh nve peers  | grep nve1")
        bb=aa.splitlines()
        for line in bb:
            if line:
                if 'n/a' in line:
                    log.info(banner("RMAC NOT LEARNED"))
                    log.info("RMAC not learened @ uut %r",uut)
                    #for i in range(1,5):
                    #    uut.execute('clear ip route *')
                    #    countdown(2)
                    #countdown(20)
                    #uut.execute("show tech BGP >> bootflash:bgp-tech-post2")
                    #uut.execute("show tech vxlan-evpn >> bootflash:vxlan-evpn-tech-post2")
                    #uut.execute("show tech routing ipv4 unicast >> bootflash:routingn-tech-post2")
                    return 0
     
    log.info(banner("NvePeerLearning Passed"))    
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




def FloodTrafficGenerator(port_handle,vlan,ip_sa,ip_da,mac_sa,rate_pps,count):
    #'00:10:94:00:00:01'
    log.info("port_handle %r vlan %r ip_sa %r ip_da %r mac_sa %r ",port_handle,vlan,ip_sa,ip_da,mac_sa)
    devcie_ret1 = sth.emulation_device_config(
        mode = 'create',
        ip_version = 'ipv4',
        encapsulation ='ethernet_ii_vlan',
        vlan_id  = vlan,
        port_handle=port_handle,
        count = count,
        mac_addr = mac_sa, 
        mac_addr_step = '00:00:00:00:00:01', 
        resolve_gateway_mac = 'true', 
        intf_ip_addr = ip_sa, 
        intf_prefix_len = '16', 
        gateway_ip_addr = ip_da,
        intf_ip_addr_step = '0.0.0.1')



    streamblock_ret1 = sth.traffic_config (
        mode = 'create',
        port_handle = port_handle,
        l2_encap = 'ethernet_ii_vlan',
        vlan_id=vlan,
        l3_protocol = 'ipv4',
        ip_src_addr = ip_sa,
        ip_src_count = count,
        ip_src_mode = 'increment',
        ip_src_step ='0.0.0.1',
        ip_dst_addr = ip_da,
        mac_src = mac_sa,
        mac_dst = 'ff:ff:ff:ff:ff:ff',
        mac_src_count= count,
        mac_src_mode='increment',
        mac_src_step='00:00:00:00:00:01',
        rate_pps = rate_pps,
        transmit_mode = 'continuous')
         
    status = streamblock_ret1['status']
    
 

def TriggerVlanRemoveAddFromPort(uut,port,vlan,count):
    for i in range(1,count):
        cfg = \
        """
        interface {port}
        switchport trunk allowed vlan remove {vlan}
        """
        log.info("cfg isssss %r",cfg.format(vlan=vlan,port=port))
        try:
            uut.configure(cfg.format(vlan=vlan,port=port)) 
            #uut.execute('show vpc brief')
            countdown(5)
            #uut.execute('show vpc brief')
            
        except:
            log.error((" vlan remov add Failed for port %r uut is %r",port,uut)) 
            return 0
        cfg = \
        """
        interface {port}
        switchport trunk allowed vlan add {vlan}
        """
        log.info("cfg isssss %r",cfg.format(vlan=vlan,port=port))
        try:
            uut.configure(cfg.format(vlan=vlan,port=port))
            #uut.execute('show vpc brief')
            countdown(5)
            #uut.execute('show vpc brief')
        except:
            log.error(("vlan remov add Failed for port %r uut is %r",port,uut)) 
            return 0
    return 1    


def VxlanRestore(uut_list):

    cfg = \
        """
        interface nve 1
        shut
        """ 
    uut.configure(cfg.format(vlan=vlan,port=port)) 
    return 1  



def TriggerCoreIfFlap(uut_list): 
    log.info(banner("Starting TriggerCoreIfFlapStaticPo "))     
    for uut in uut_list:
        cmd = uut.execute("show ip ospf neigh | json-pretty")
        op=json.loads(cmd)  
        op11 = op["TABLE_ctx"]['ROW_ctx']
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
                    log.info('Trigger4CoreIfFlapStaticPo failed @ 11')
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
                    log.info('Trigger4CoreIfFlapStaticPo failed @ 11')
                    return 0

    return 1


def TriggerCoreIfFlap222(uut_list): 
    log.info(banner("Starting TriggerCoreIfFlapStaticPo "))     
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
                    log.info('Trigger4CoreIfFlapStaticPo failed @ 11')
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
                    log.info('Trigger4CoreIfFlapStaticPo failed @ 11')
                    return 0

    return 1

 


def TriggerCoreIfBounce(uut,action): 
    log.info(banner("Starting TriggerCoreIfFlapStaticPo "))     
    cmd = uut.execute("show ip ospf neigh | json-pretty")
    op=json.loads(cmd)  
    op1 = op["TABLE_ctx"]['ROW_ctx']["TABLE_nbr"]['ROW_nbr']
    nbrcount = op["TABLE_ctx"]['ROW_ctx']['nbrcount']
    core_intf_list = []
 
    if int(nbrcount) == 1:
        intf = op1["intf"]
        if 'Po' in intf:
            core_intf_list.append(intf)
    else:    
        for i in range(0,len(op1)):
            intf = op1[i]["intf"]
            if 'Po' in intf:
                core_intf_list.append(intf)

    if "shutdown" in action:
        for intf in core_intf_list:
            cfg = \
            """
            interface {intf}
            shut
            """
        try:
            uut.configure(cfg.format(intf=intf))
        except:    
            log.info('Trigger4CoreIfFlapStaticPo failed @ 11')
            return 0
    
    if "bringup" in action:
        for intf in core_intf_list:
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

    return 1



def SpirentCreateHosts(port_handle,vlan,ip_sa,ip_da,mac_sa,count):
    log.info("port_handle %r vlan %r ip_sa %r ip_da %r mac_sa %r ",port_handle,vlan,ip_sa,ip_da,mac_sa)
    devcie_ret1 = sth.emulation_device_config(
        mode = 'create',
        ip_version = 'ipv4',
        encapsulation ='ethernet_ii_vlan',
        vlan_id  = vlan,
        port_handle=port_handle,
        count = count,
        ip_stack_count=count,
        mac_addr = mac_sa, 
        mac_addr_step = '00:00:00:00:00:01', 
        mac_addr_count= count,
        resolve_gateway_mac = 'true', 
        intf_ip_addr = ip_sa, 
        intf_prefix_len = '16', 
        gateway_ip_addr = ip_da,
        intf_ip_addr_step = '0.0.0.1')



def ArpTrafficGenerator(port_handle,vlan,ip_sa,ip_da,mac_sa,rate_pps,count):
    #'00:10:94:00:00:01'
    """
    If you specify "arp" as the Layer 3 protocol, use
    "-ip_src_addr" for the source protocol address and
    "-ip_dst_addr" for the destination protocol address.
    Also, only the fixed, increment, and decrement modes are
    supported in these two arguments when the Layer 3
    protocol is "arp".
    If you specify GRE
    """
    log.info("port_handle %r vlan %r ip_sa %r ip_da %r mac_sa %r ",port_handle,vlan,ip_sa,ip_da,mac_sa)
    streamblock_ret1 = sth.traffic_config (
        mode = 'create',
        port_handle = port_handle,
        l2_encap = 'ethernet_ii_vlan',
        vlan_id=vlan,
        l3_protocol = 'arp',
        ip_src_addr = ip_sa, 
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



def ArpTrafficGenerator2(port_handle,vlan,ip_sa,ip_da,mac_sa,rate_pps,count):
    #'00:10:94:00:00:01'
    """
    If you specify "arp" as the Layer 3 protocol, use
    "-ip_src_addr" for the source protocol address and
    "-ip_dst_addr" for the destination protocol address.
    Also, only the fixed, increment, and decrement modes are
    supported in these two arguments when the Layer 3
    protocol is "arp".
    If you specify GRE
    """
    log.info("port_handle %r vlan %r ip_sa %r ip_da %r mac_sa %r ",port_handle,vlan,ip_sa,ip_da,mac_sa)
    streamblock_ret1 = sth.traffic_config (
        mode = 'create',
        port_handle = port_handle,
        l2_encap = 'ethernet_ii_vlan',
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




def CreateSpirentHostBidirStreamBfdScale(port_hdl1,port_hdl2,vlan1,vlan2,ip1,ip2,gw1,gw2,rate_pps,host_scale):
    log.info(banner("In CreateSpirentHostBidirStreamScale"))
    #            ip2 = str(ip_address(ip2)+65536) 
    #for i in range(1,host_scale):
    log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)     
    device_ret1 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan1,port_handle = port_hdl1,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip1,intf_ip_addr_step='0.0.0.1',intf_prefix_len = '16',\
    gateway_ip_addr = gw1,count=host_scale); 
     
    log.info("device_ret2---------,%r",device_ret1)        
    device_ret2 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan2,port_handle = port_hdl2,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip2,intf_ip_addr_step='0.0.0.1',intf_prefix_len = '16',\
    gateway_ip_addr = gw2,count=host_scale);
            
    log.info("device_ret2---------,%r",device_ret2)  

    h1 = device_ret1['handle']
    h2 = device_ret2['handle']
 
    udp_src_port = str(randint(49152,65535))
    udp_dst_port = '3784'

    streamblock_ret1 = sth.traffic_config (mode= 'create',port_handle= port_hdl1,\
    emulation_src_handle=h1,emulation_dst_handle = h2,bidirectional='1',\
    port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps,l4_protocol='udp',\
    udp_src_port=udp_src_port,udp_dst_port=udp_dst_port)

    status = streamblock_ret1['status']

    log.info('+-----------------------------------------------------------------------+')
    log.info('stream_id : %r, vlan1 : %r ,vlan2 : %r ,rate_pps : %r',streamblock_ret1['stream_id'],vlan1,vlan2,rate_pps)                
    log.info('IP1 : %r,IP2 : %r, Host1 : %r ,Host2 : %r ',ip1,ip2,h1,h2)                
    log.info('+-----------------------------------------------------------------------+')

    #ip1 = str(ip_address(ip1)+1) 
    #ip2 = str(ip_address(ip2)+1) 

    if (status == '0') :
        log.info('run sth.traffic_config failed for V4 %r', streamblock_ret1)


def SpirentHostBidirStreamBfd(port_hdl1,port_hdl2,vlan1,vlan2,ip1,ip2,gw1,gw2,rate_pps):
    log.info(banner("------SpirentHostBidirStreamBfd-----"))

    log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)     
    device_ret1 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan1,port_handle = port_hdl1,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip1,intf_prefix_len = '16',\
    gateway_ip_addr = gw1); 
            
    device_ret2 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan2,port_handle = port_hdl2,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip2,intf_prefix_len = '16',\
    gateway_ip_addr = gw2);
            
    h1 = device_ret1['handle']
    h2 = device_ret2['handle']
 
    udp_src_port = str(randint(49152,65535))
    udp_dst_port = '3784'

    streamblock_ret1 = sth.traffic_config (mode= 'create',port_handle= port_hdl1,\
    emulation_src_handle=h1,emulation_dst_handle = h2,bidirectional='1',\
    port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps,l4_protocol='udp',\
    udp_src_port=udp_src_port,udp_dst_port=udp_dst_port)

    status = streamblock_ret1['status']

    log.info('+-----------------------------------------------------------------------+')
    log.info('stream_id : %r, vlan1 : %r ,vlan2 : %r ,rate_pps : %r',streamblock_ret1['stream_id'],vlan1,vlan2,rate_pps)                
    log.info('IP1 : %r,IP2 : %r, Host1 : %r ,Host2 : %r ',ip1,ip2,h1,h2)                
    log.info('+-----------------------------------------------------------------------+')
    if (status == '0') :
        log.info('run sth.traffic_config failed for V4 %r', streamblock_ret1)
 

def leaf_protocol_check222(uut,protocol_list):
    for proto in protocol_list:
        #result = 1
        if 'ospf' in proto:
            cmd = uut.execute("show ip ospf neighbors | json-pretty")
            if not "addr" in str(cmd):
                log.info('No OSPF neighbor found,Test failed for uut/neighbor')
                return 0
            else: 
                test1=json.loads(cmd) 
                test11 = test1["TABLE_ctx"]["ROW_ctx"]
                if 'list' in str(type(test11)):
                    neig_list = test11[0]["TABLE_nbr"]["ROW_nbr"]
                    neig_count =  str(neig_list).count('addr')
                    if neig_count == 1:
                        if not 'FULL' in (neig_list)[0]['state']:
                            log.info('OSPF neighbor check failed for uut/neighbor')
                            return 0                            
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            if not 'FULL' in (neig_list)[i]['state']:
                                log.info('OSPF neighbor check failed for uut/neighbor')
                                return 0
                            else:
                                return 1

                else:
                    neig_list= test1["TABLE_ctx"]["ROW_ctx"]["TABLE_nbr"]["ROW_nbr"]
                    neig_count =  str(neig_list).count('addr')
                    if neig_count == 1:
                        if not 'FULL' in (neig_list)['state']:
                            log.info('OSPF neighbor check failed for uut/neighbor')
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            if not 'FULL' in (neig_list)[i]['state']:
                                log.info('OSPF neighbor check failed for uut/neighbor')
                                return 0
                            else:
                                return 1
                        

        elif 'bgp' in proto:
            cmd = uut.execute(" show bgp l2 evpn summary | json-pretty")
            if not "state" in str(cmd):
                log.info('No BGP neighbor found,Test failed for uut/neighbor')
                return 0
            else:
                test1=json.loads(cmd)
                test11 = test1["TABLE_vrf"]["ROW_vrf"]
                if 'list' in str(type(test11)):
                    neig_list= test11[0]["TABLE_af"]["ROW_af"][0]["TABLE_saf"][ "ROW_saf"][0]["TABLE_neighbor"]["ROW_neighbor"]
                    neig_count =  str(neig_list).count('neighborid')
                    if neig_count == 1:
                        if not 'Established' in (neig_list)[0]['state']:
                            log.info('BGP neighbor check failed for uut/neighbor')
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:        
                        for i in range(0,neig_count-1):
                            if not 'Established' in (neig_list)[i]['state']:
                                log.info('BGP neighbor check failed for uut/neighbor')
                                return 0
                            else:
                                return 1     

                else: 
                    neig_list= test1["TABLE_vrf"]["ROW_vrf"]["TABLE_af"]["ROW_af"]["TABLE_saf"][ "ROW_saf"]["TABLE_neighbor"]["ROW_neighbor"]
                    neig_count =  str(neig_list).count('neighborid')
                    if neig_count == 1:
                        if not 'Established' in (neig_list)['state']:
                            log.info('BGP neighbor check failed for uut/neighbor')
                            return 0
                        else:
                            return 1

                    elif neig_count > 1:        
                        for i in range(0,neig_count-1):
                            if not 'Established' in (neig_list)[i]['state']:
                                log.info('BGP neighbor check failed for uut/neighbor')
                                return 0
                            else:
                                return 1    
        
            log.info('BGP neighbor check passed for uut -------------- :')

        elif 'pim' in protocol_list:
            cmd = uut.execute("show ip pim neighbor | json-pretty ")
            if not "vrf" in str(cmd):
                if not "nbr-add" in str(cmd):
                    log.info('No PIM neighbor found,Test failed for uut/neighbor')
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
                            log.info('PIM neighbor check failed for uut/neighbor') 
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
                                log.info('PIM neighbor check failed for uut/neighbor') 
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
                            log.info('PIM neighbor check failed for uut/neighbor') 
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
                                log.info('PIM neighbor check failed for uut/neighbor') 
                                return 0
                            else:
                                return 1    
            else:
                pass 

            log.info('PIM Neighbor check passed for uut --------------')

        elif 'nve-peer' in protocol_list:
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
                            log.info('NVE Peer check failed for uut/neighbor') 
                        else:
                            return 1
             
                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            state = (neig_list)[i]['peer-state']
                            if not 'Up' in state:
                                log.info('NVE Peer check failed for uut/neighbor')                         
                            else:
                                log.info('NVE Peer check passed for uut --------------')
                                return 1


                else:
                    neig_list= test1["TABLE_nve_peers"]["ROW_nve_peers"]
                    neig_count =  str(neig_list).count('peer-ip')
                    if neig_count == 1:
                        state = (neig_list)['peer-state']
                        if not 'Up' in state:
                            log.info('NVE Peer check failed for uut/neighbor') 
                        else:
                            return 1
             
                    elif neig_count > 1:
                        for i in range(0,neig_count-1):
                            state = (neig_list)[i]['peer-state']
                            if not 'Up' in state:
                                log.info('NVE Peer check failed for uut/neighbor')                         
                            else:
                                log.info('NVE Peer check passed for uut --------------')
                                return 1

        elif 'nve-vni' in protocol_list:
            cmd = uut.execute("show nve vni")
            #test1=json.loads(uut.execute(cmd))
            if not "nve1" in str(cmd):
                log.info('No NVE VNI found,Test failed for uut/neighbor')
                return 0

            if "Down" in str(cmd):
                log.info(' NVE VNI Down,Test failed for uut/neighbor')
                return 0

            else:
                return 1

 

    log.info('Protocol check passed for uut -------------- :')
   
def FloodTrafficGeneratorScale(port_handle,vlan,ip_sa,ip_da,rate_pps,count):
    
    log.info(banner('in FloodTrafficGeneratorScale '))

    str1=hex(randint(16,54))[2:]
    str2=hex(randint(55,104))[2:]
    str3=hex(randint(32,80))[2:]
    str4=hex(randint(50,95))[2:]

    mac1='00:'+str4+':'+str2+':'+str1+':'+str3+':02'
    #mac2='00:10:'+str1+':'+str2+':'+str4+':02'

    device_ret = sth.traffic_config (
        mode            =       'create',
        port_handle     =       port_handle,
        l2_encap        =       'ethernet_ii_vlan',
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
        mac_src         =       mac1,
        mac_src_count   =       count,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps, 
        transmit_mode   =       'continuous')

    status = device_ret['status']
    if (status == '0') :
        log.info("run sth.emulation_device_config failed")
        return 0
    else:
        log.info("***** run sth.emulation_device_config successfully")
        return 1

        #mac_src         =       '00:10:01:11:0a:01',,

def FloodTrafficGeneratorMacScale(port_handle,vlan,ip_sa,ip_da,rate_pps,count,mac_scale):
    mac_count = int(count)*int(mac_scale)
    device_ret = sth.traffic_config (
        mode            =       'create',
        port_handle     =       port_handle,
        l2_encap        =       'ethernet_ii_vlan',
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
        mac_src_count   =       mac_count,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps, 
        transmit_mode   =       'continuous')

    status = device_ret['status']
    if (status == '0') :
        log.info("run sth.emulation_device_config failed")
        return 0
    else:
        log.info("***** run sth.emulation_device_config successfully")
        return 1




def nve_configure_only_mcast_test_scale(uut,vni,count,mcast_group):
    if int(count)>500:
        c2 = int(count/20)
        a1 = 20
    else:  
        c2 = int(count/5)  
        a1 = 5              
    mcast = ip_address(mcast_group)
    cmd = "" 
    cmd +=  'interface nve1\n'    
    for j in range(0,a1): 
        mcast = mcast+1
        for i in range(0,c2):
            cmd += 'member vni {vni}\n'.format(vni=vni,mcast=mcast)
            cmd += 'suppress-arp\n'
            cmd += 'mcast-group {mcast}\n'.format(vni=vni,mcast=mcast)
            vni = vni + 1
    try:
        uut.configure(cmd)
    except:
        log.info('mcast_vni_configure failed')


class LeafL2McastVniObject(object):
    def __init__(self,node,vlan,vni,vlan_scale,mcast_group):
        self.node=node
        self.vni=vni
        self.vlan_scale=vlan_scale
        self.mcast_group=mcast_group
                                    
    def vxlan_conf(self):
        nve_configure_only_mcast_test_scale(self.node,self.vni,self.vlan_scale,self.mcast_group) 



def SpirentRateTest22(port_hdl1,port_hdl2,rate_fps,diff):
    log.info(banner("  Starting Spirent Rate Test "))
    diff = 4*int(diff)
    result = 1
    for port_hdl in [port_hdl1,port_hdl2]:    
        log.info("port_hdl %r,rate_fps %r,diff is %r", port_hdl,rate_fps,diff)
        res = sth.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
        rx_rate = res['item0']['PortRxTotalFrameRate']    
        tx_rate = res['item0']['PortTxTotalFrameRate']
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
    

def SpirentHostBidirStream222(port_hdl1,port_hdl2,vlan1,vlan2,scale,ip1,ip2,gw1,gw2,rate_pps):
    #log.info(banner("------SpirentHostBidirStream-----"))
    log.info('VLAN1 : %r,VLAN2 : %r,SCALE : %r,IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,vlan1,vlan2,scale,ip1,ip2,gw1,gw2)     
    device_ret1 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan1,port_handle = port_hdl1,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip1,intf_ip_addr_step='0.1.0.0',intf_prefix_len = '16',\
    gateway_ip_addr = gw1,gateway_ip_addr_step='0.1.0.0',count=scale)
            
    device_ret2 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan2,port_handle = port_hdl2,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip2,intf_ip_addr_step='0.1.0.0',intf_prefix_len = '16',\
    gateway_ip_addr = gw2,gateway_ip_addr_step='0.1.0.0',count=scale)
            
    h1 = device_ret1['handle']
    h2 = device_ret2['handle']

    vlan_id_count = scale
    ip_src_count  = scale

    for host in [h1,h2]:
        sth.invoke('stc::config %s -vlanif.IfCountPerLowerIf %s' %(host, vlan_id_count))
        sth.invoke('stc::config %s -vlanif.IfCountPerLowerIf %s' %(host, vlan_id_count)) 
       
    #streamblock_ret1 = sth.traffic_config (mode= 'create',port_handle= port_hdl1,\
    #emulation_src_handle=h1,emulation_dst_handle = h2,bidirectional='1',\
    #port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps)

    device_ret = sth.traffic_config (
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
        rate_pps        =       rate_pps, 
        transmit_mode   =       'continuous')

    device_ret = sth.traffic_config (
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
        rate_pps        =       rate_pps, 
        transmit_mode   =       'continuous')



    #status = streamblock_ret1['status']

    #log.info('+-----------------------------------------------------------------------+')
    #log.info('stream_id : %r, vlan1 : %r ,vlan2 : %r ,rate_pps : %r',streamblock_ret1['stream_id'],vlan1,vlan2,rate_pps)                
    #log.info('IP1 : %r,IP2 : %r, Host1 : %r ,Host2 : %r ',ip1,ip2,h1,h2)                
    #log.info('+-----------------------------------------------------------------------+')
    #if (status == '0') :
        #log.info('run sth.traffic_config failed for V4 %r', streamblock_ret1)


def SpirentHostBidirStreamRouted(port_hdl1,port_hdl2,vlan1,vlan2,scale,ip1,ip2,anycastgw,rate_pps):
    #log.info(banner("------SpirentHostBidirStream-----"))
    #log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)     
    str1=hex(randint(16,54))[2:]
    str2=hex(randint(55,104))[2:]

    mac1='00:10:94:'+str1+':00:02'
    mac2='00:10:95:'+str2+':00:02'
    #SpirentHostBidirStreamRouted(port_hdl1,port_hdl2,vlan1,vlan2,scale,ip1,ip2,gw1,gw2,rate_pps)
    #log.info(banner("------SpirentHostBidirStream-----"))
    #log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)     


    device_ret1 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan1,port_handle = port_hdl1,mac_addr_step='00:00:00:00:00:01',mac_addr=mac1,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip1,intf_ip_addr_step='0.1.0.0',intf_prefix_len = '16',\
    gateway_mac = anycastgw,gateway_ip_addr_step='0.1.0.0',count=1,ip_stack_count=1)
            
    device_ret2 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan2,port_handle = port_hdl2,mac_addr_step='00:00:00:00:00:01',mac_addr=mac1,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip2,intf_ip_addr_step='0.1.0.0',intf_prefix_len = '16',\
    gateway_mac = anycastgw,gateway_ip_addr_step='0.1.0.0',count=scale,ip_stack_count=scale)
            
    h1 = device_ret1['handle']
    h2 = device_ret2['handle']

    vlan_id_count = scale

    for host in [h2]:
        sth.invoke('stc::config %s -vlanif.IfCountPerLowerIf %s' %(host, vlan_id_count))
      
    streamblock_ret1 = sth.traffic_config (mode= 'create',port_handle= port_hdl1,\
    emulation_src_handle=h1,emulation_dst_handle = h2,bidirectional='1',\
    port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps)

    status = streamblock_ret1['status']

    #log.info('+-----------------------------------------------------------------------+')
    #log.info('stream_id : %r, vlan1 : %r ,vlan2 : %r ,rate_pps : %r',streamblock_ret1['stream_id'],vlan1,vlan2,rate_pps)                
    #log.info('IP1 : %r,IP2 : %r, Host1 : %r ,Host2 : %r ',ip1,ip2,h1,h2)                
    #log.info('+-----------------------------------------------------------------------+')
    if (status == '0') :
        log.info('run sth.traffic_config failed for V4 %r', streamblock_ret1)



def CreateSpirentHostBidirStreamScale222(port_hdl1,port_hdl2,vlan1,vlan2,ip1,ip2,gw1,gw2,rate_pps,host_scale):
    #log.info(banner("In CreateSpirentHostBidirStreamScale"))
    #            ip2 = str(ip_address(ip2)+65536) 
    #for i in range(1,host_scale):
    #log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)     
    device_ret1 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan1,port_handle = port_hdl1,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip1,intf_ip_addr_step='0.0.0.1',intf_prefix_len = '16',\
    gateway_ip_addr = gw1,count=host_scale); 
     
    #log.info("device_ret2---------,%r",device_ret1)        
    device_ret2 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan2,port_handle = port_hdl2,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip2,intf_ip_addr_step='0.0.0.1',intf_prefix_len = '16',\
    gateway_ip_addr = gw2,count=host_scale);
            
    #log.info("device_ret2---------,%r",device_ret2)  

    h1 = device_ret1['handle']
    h2 = device_ret2['handle']
       
    streamblock_ret1 = sth.traffic_config (mode= 'create',port_handle= port_hdl1,\
    emulation_src_handle=h1,emulation_dst_handle = h2,bidirectional='1',\
    port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps)

    status = streamblock_ret1['status']

    #log.info('+-----------------------------------------------------------------------+')
    #log.info('stream_id : %r, vlan1 : %r ,vlan2 : %r ,rate_pps : %r',streamblock_ret1['stream_id'],vlan1,vlan2,rate_pps)                
    #log.info('IP1 : %r,IP2 : %r, Host1 : %r ,Host2 : %r ',ip1,ip2,h1,h2)                
    #log.info('+-----------------------------------------------------------------------+')

    #ip1 = str(ip_address(ip1)+1) 
    #ip2 = str(ip_address(ip2)+1) 

    if (status == '0') :
        log.info('run sth.traffic_config failed for V4 %r', streamblock_ret1)

def EsiIdChange222(uut,intf):
    """ function to configure vpc """
    logger.info(banner("Entering proc to configure Int shut no shut"))
    esi1 = uut.execute("sh run interface {intf}".format(intf=intf))
    esi2 = esi1.splitlines()
    for line in esi2:
        if 'ethernet-segmen' in line:
            es = line.split()[1]
    for line in esi2:
        if 'system-mac' in line:
            smac = line.split()[1]            
    es2=str(int(es)+1)

    unconfig_str = \
    """
    interface {intf}
    no ethernet-segment {es}
    """
    config_str = \
    """
    interface {intf}
    ethernet-segment {es}
    system-mac {smac}
    """

    try:
        output  = uut.config(unconfig_str.format(intf=intf,es=es))
        time.sleep(20)
        output  = uut.config(config_str.format(intf=intf,es=es2,smac=smac))
    except:
        log.error(sys.exc_info())
        return 0
    return 1
    

     
def CheckPoState(uut):
    log.info('checking port channel status in uut %r',uut)
    op = uut.execute()

 


def CleanupWithNxapi(uut):
    log.info(banner("Start Vlan Xconnect configurations via NXA= API")) 
      
    ip1 = uut.execute('sh int mgmt 0 | json-pretty')
    ip2 = json.loads(ip1) 
    MgIP = ip2["TABLE_interface"]["ROW_interface"]['eth_ip_addr']


    switchuser='admin'
    switchpassword='nbv12345'
    #MgIP = str(ip)

 
    myheaders={'content-type':'application/json'}
    payload = {
                  "ins_api": {
                  "version": "1.0",
                  "type": "cli_conf",
                  "chunk": "0",
                  "sid": "1",
                  "output_format": "json",
                  "rollback": "stop-on-error"
                    }
                  }

    payload['ins_api']['input'] ="no feature bgp;no feature nv overlay "
    log.info(" payload is ~~~~~~~~~~~~~~~~~~~~ %r",payload)
    url = "http://%s:8080/ins" % (MgIP)
                #response = requests.post(url, data = json.dumps(payload), headers = myheaders,\
                #             auth = (switchuser, switchpassword)).json()
                
    response = requests.post(url, data = json.dumps(payload),headers = myheaders,auth = (switchuser, switchpassword)).json()            

    #response = requests.post(url, data = json.dumps(payload), headers = myheaders,auth = (switchuser, switchpassword)).json()            

    log.info("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    log.info("Response is -------------%r",response)
    log.info("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")



def SpirentBidirStreamScale(port_hdl1,port_hdl2,vlan1,vlan2,scale,host_scale,ip1,ip2,gw1,gw2,rate_pps):
    #log.info(banner("------SpirentHostBidirStream-----"))
    log.info('VLAN1 : %r,VLAN2 : %r,SCALE : %r,IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,vlan1,vlan2,scale,ip1,ip2,gw1,gw2)     

      
    device_ret = sth.traffic_config (
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
 
    device_ret = sth.traffic_config (
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


def SpirentBidirStream222(port_hdl1,port_hdl2,vlan1,vlan2,scale,ip1,ip2,gw1,gw2,rate_pps):
    #log.info(banner("------SpirentHostBidirStream-----"))
    log.info('VLAN1 : %r,VLAN2 : %r,SCALE : %r,IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,vlan1,vlan2,scale,ip1,ip2,gw1,gw2)     
  
    device_ret = sth.traffic_config (
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
 
    device_ret = sth.traffic_config (
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


#anycastgw


def SpirentBidirStreamRouted222(port_hdl1,port_hdl2,vlan1,vlan2,scale,ip1,ip2,anycastgw,rate_pps):
    #log.info(banner("------SpirentHostBidirStream-----"))
    log.info('VLAN1 : %r,VLAN2 : %r,SCALE : %r,IP1 : %r,IP2 : %r GW1 :%r' ,vlan1,vlan2,scale,ip1,ip2,anycastgw)     

    for vlan in range(vlan1,vlan1+scale):
        str1=hex(randint(16,54))[2:]
        str2=hex(randint(55,104))[2:]

        mac1='00:10:94:'+str1+':00:02'
        mac2='00:10:95:'+str2+':00:02'
    #SpirentHostBidirStreamRouted(port_hdl1,port_hdl2,vlan1,vlan2,scale,ip1,ip2,gw1,gw2,rate_pps)
    #log.info(banner("------SpirentHostBidirStream-----"))
    #log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)     
        device_ret1 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
        encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan1,port_handle = port_hdl1,mac_addr_step='00:00:00:00:00:01',mac_addr=mac1,\
        resolve_gateway_mac = 'true',intf_ip_addr= ip1,intf_ip_addr_step='0.1.0.0',intf_prefix_len = '16',\
        gateway_mac = anycastgw,gateway_ip_addr_step='0.1.0.0',count=1)
            
        device_ret2 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
        encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan2,port_handle = port_hdl2,mac_addr_step='00:00:00:00:00:01',mac_addr=mac2,\
        resolve_gateway_mac = 'true',intf_ip_addr= ip2,intf_ip_addr_step='0.1.0.0',intf_prefix_len = '16',\
        gateway_mac = anycastgw,gateway_ip_addr_step='0.1.0.0',count=1)
            
    #h1 = device_ret1['handle']
    #h2 = device_ret2['handle']

    #for host in [h1,h2]:
    #    sth.invoke('stc::config %s -vlanif.IfCountPerLowerIf %s' %(host, scale))

    device_ret = sth.traffic_config (
        mode            =       'create',
        port_handle     =       port_hdl1,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan1,
        vlan_id_count   =       1,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',  
        ip_src_addr     =       ip1,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip2, 
        ip_dst_step     =       '0.1.0.0',
        ip_dst_count    =       scale, 
        ip_dst_mode     =       'increment',
        mac_src         =       mac1,
        mac_dst         =       anycastgw,
        mac_dst_count   =       1,
        rate_pps        =       rate_pps, 
        transmit_mode   =       'continuous')
 
    device_ret = sth.traffic_config (
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
        mac_src         =       mac2,
        mac_dst         =       anycastgw,
        mac_dst_count   =       1,
        mac_src_count   =       scale,
        mac_src_mode    =       'increment',
        mac_src_step    =       '00:00:00:00:00:01', 
        rate_pps        =       rate_pps, 
        transmit_mode   =       'continuous')



def SpirentHostBidirStreamRouted22222(port_hdl1,port_hdl2,vlan1,vlan2,scale,ip1,ip2,anycastgw,rate_pps):
    #log.info(banner("------SpirentHostBidirStream-----"))
    #log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)     
    str1=hex(randint(16,54))[2:]
    str2=hex(randint(55,104))[2:]

    mac1='00:10:94:'+str1+':00:02'
    mac2='00:10:95:'+str2+':00:02'
    #SpirentHostBidirStreamRouted(port_hdl1,port_hdl2,vlan1,vlan2,scale,ip1,ip2,gw1,gw2,rate_pps)
    #log.info(banner("------SpirentHostBidirStream-----"))
    #log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)     


    device_ret1 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan1,port_handle = port_hdl1,mac_addr_step='00:00:00:00:00:01',mac_addr=mac1,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip1,intf_ip_addr_step='0.1.0.0',intf_prefix_len = '16',\
    gateway_mac = anycastgw,gateway_ip_addr_step='0.1.0.0',count=1,ip_stack_count=1)

    h1 = device_ret1['handle']

    for vlan in range(vlan1,vlan1+scale):
        str1=hex(randint(16,54))[2:]
        str2=hex(randint(55,104))[2:]

        mac1='00:10:94:'+str1+':00:02'
        mac2='00:10:95:'+str2+':00:02'
            
        device_ret2 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
        encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan2,port_handle = port_hdl2,mac_addr_step='00:00:00:00:00:01',mac_addr=mac1,\
        resolve_gateway_mac = 'true',intf_ip_addr= ip2,intf_ip_addr_step='0.1.0.0',intf_prefix_len = '16',\
        gateway_mac = anycastgw,gateway_ip_addr_step='0.1.0.0',count=1,ip_stack_count=1)
    
        h2 = device_ret2['handle']

        streamblock_ret1 = sth.traffic_config (mode= 'create',port_handle= port_hdl1,\
        emulation_src_handle=h1,emulation_dst_handle = h2,bidirectional='1',\
        port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps)


    #h2 = device_ret2['handle']

    #vlan_id_count = scale

    #for host in [h2]:
    #    sth.invoke('stc::config %s -vlanif.IfCountPerLowerIf %s' %(host, vlan_id_count))
      
    #streamblock_ret1 = sth.traffic_config (mode= 'create',port_handle= port_hdl1,\
    #emulation_src_handle=h1,emulation_dst_handle = h2,bidirectional='1',\
    #port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps)

    #status = streamblock_ret1['status']

    #pdb.set_trace()

    #log.info('+-----------------------------------------------------------------------+')
    #log.info('stream_id : %r, vlan1 : %r ,vlan2 : %r ,rate_pps : %r',streamblock_ret1['stream_id'],vlan1,vlan2,rate_pps)                
    #log.info('IP1 : %r,IP2 : %r, Host1 : %r ,Host2 : %r ',ip1,ip2,h1,h2)                
    #log.info('+-----------------------------------------------------------------------+')
    #if (status == '0') :
    #   log.info('run sth.traffic_config failed for V4 %r', streamblock_ret1)





def DevicePreCleanupAll(uut):
    log.info(banner('Starting DevicePreCleanupAll'))
    log.info(banner("##########Deleteing adding vxlan features ( ######### "))
    feature_clean=\
    """
    no feature interface-vlan  
    feature interface-vlan  
    """ 
    uut.configure(feature_clean) 

    log.info(banner("Deleted added vxlan features"))

    log.info(banner("Deleteing Monitor session"))
    op = uut.execute('sh run monitor | incl sess')
    if op:
        op1 = op.splitlines()
        for line in op1:
            if 'session' in line:
                uut.configure('no {line}'.format(line=line))

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
                    cfg1 = """#default interface {po}"""
                    cfg2 = """no interface {po}"""
                    #try:
                    uut.configure(cfg1.format(po=po))
                    uut.configure(cfg2.format(po=po))                        
                    #except:
                    #    log.error('Invalid CLI given')
    uut.configure("no feature lacp")        
    uut.configure("feature lacp")  
    log.info(banner("Deleteing access lists"))
    op = uut.configure("sh run | incl 'ip access-list'")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'copp' in line:
                if not "sh run |" in line:
                    if "access-list" in line:
                        cfg = "no {line}"
                        uut.configure(cfg.format(line=line)) 

    log.info(banner("Delete static routes"))          
    op = uut.configure("sh run | incl 'ip route '")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'run' in line:
                if not '10.127' in line:
                    if 'ip route ' in line: 
                        cfg = "no {line}"
                        uut.configure(cfg.format(line=line))   

    log.info(banner("Deleting vrf"))                  
    op = uut.configure("show vrf")
    op1 = op.splitlines()
    for line in op1:
        if line:
            #if not 'default' in line:
            #    if not 'management' in line:
            if 'vxlan' in line:
                #if not 'VRF-Name' in line:
                vrf = line.split()[0]
                uut.configure('no vrf context {vrf}'.format(vrf=vrf))
                                
    log.info(banner("Deleting Port Channels"))  

    op = uut.configure("sh run | incl 'interface port-channel'")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'run' in line:
                if "port-channel" in line:
                    cfg1 = "default {line}"
                    uut.configure(cfg1.format(line=line)) 
                    cfg2 = "no {line}"
                    uut.configure(cfg2.format(line=line)) 




 
    log.info(banner("Default Eth interface to L3"))  
    op = uut.configure("sh int br | exclu route")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'Eth' in line:
                if not 'Ethernet' in line:
                    intf = line.split()[0]
                    cfg = \
                        """
                        interface {intf}
                        no switchport
                        """
                    uut.configure(cfg.format(intf=intf))

    log.info(banner("Deleting Loopbacks")) 
    op = uut.configure("show ip interface brief ")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'Lo' in line:
                intf = line.split()[0]
                uut.configure('no interface {intf}'.format(intf=intf))

 
    log.info(banner("Deleting community-list"))                    
    op = uut.execute("show run | incl community-list")
    op1 = op.splitlines()
    for line in op1:
        if not 'run' in line:
            if line:
                if 'community-list' in line:
                    cfg = "no {line}"
                    #try:
                    uut.configure(cfg.format(line=line))  
                    #except:
                    #    log.error('community-list delete failed in uut',uut)

    log.info(banner("Deleting route-map"))             
    op = uut.execute("show run | incl route-map")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'route-map' in line:
                if 'permit' in line:
                    cfg = "no {line}"
                    #try:
                    uut.configure(cfg.format(line=line))  
                    #except:
                    #log.error('route-map delete failed in uut',uut)

    feature_clean=\
    """
    no feature ngoam
    show clock
    no feature nv over
    show clock
    no feature bgp
    show clock
    no feature ospf
    show clock
    no feature pim
    no vlan 2-600
    line con
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
    nv overlay evpn
    feature vn-segment-vlan-based
    """ 
    uut.configure(feature_clean,timeout=180) 



def Arp_Suppression_test(port_hdl1,vlan_start,vlan_scale,ip1):
    device_ret0 = sth.emulation_device_config (
        mode                                             = 'create',
        ip_version                                       = 'ipv4',
        count                                            = '1',
        router_id                                        = ip1,
        enable_ping_response                             = '1',
        encapsulation                                    = 'ethernet_ii_vlan',
        port_handle                                      = port_hdl1,
        vlan_id                                          = vlan_start,
        intf_ip_addr                                     = ip1,
        ip_stack_count                                   = vlan_scale,
        intf_prefix_len                                  = '16',
        resolve_gateway_mac                              = 'true',
        gateway_ip_addr                                  = '10.1.1.1',
        gateway_ip_addr_step                             = '0.0.0.0',
        intf_ip_addr_step                                = '0.0.0.1',
        mac_addr                                         = '00:01:02:55:00:01',
        mac_addr_step                                    = '00:00:00:00:00:01');


    h2 = device_ret0['handle']

    for host in [h2]:
        sth.invoke('stc::config %s -vlanif.IfCountPerLowerIf %s' %(host, vlan_scale))



def FloodTrafficGeneratorScaleArp(port_handle,vlan,ip_sa,ip_da,rate_pps,count,mac_src):
    #host_count = int(count)*100
    device_ret = sth.traffic_config (
        mode            =       'create',
        port_handle     =       port_handle,
        l2_encap        =       'ethernet_ii_vlan',
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
        mac_src_count   =       count,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps, 
        transmit_mode   =       'continuous')

    status = device_ret['status']
    if (status == '0') :
        log.info("run sth.emulation_device_config failed")
        return 0
    else:
        log.info("***** run sth.emulation_device_config successfully")
        return 1



def FloodTrafficGeneratorScaleArp22(port_handle,vlan,ip_sa,ip_da,rate_pps,count,mac_src):
    #host_count = int(count)*100
    device_ret = sth.traffic_config (
        mode            =       'create',
        port_handle     =       port_handle,
        l2_encap        =       'ethernet_ii_vlan',
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
        log.info("run sth.emulation_device_config failed")
        return 0
    else:
        log.info("***** run sth.emulation_device_config successfully")
        return 1


def ArpTrafficGenerator2Suppres(port_handle,vlan,ip_sa,ip_da,mac_sa,rate_pps,count):
    #'00:10:94:00:00:01'
    """
    If you specify "arp" as the Layer 3 protocol, use
    "-ip_src_addr" for the source protocol address and
    "-ip_dst_addr" for the destination protocol address.
    Also, only the fixed, increment, and decrement modes are
    supported in these two arguments when the Layer 3
    protocol is "arp".
    If you specify GRE
    """
    log.info("port_handle %r vlan %r ip_sa %r ip_da %r mac_sa %r ",port_handle,vlan,ip_sa,ip_da,mac_sa)
    streamblock_ret1 = sth.traffic_config (
        mode = 'create',
        port_handle = port_handle,
        l2_encap = 'ethernet_ii_vlan',
        vlan_id=vlan,
        vlan_id_count=count,        
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
         
    status = streamblock_ret1['status']



 
def ArpTrafficGenerator22Suppres(port_handle,vlan,ip_sa,ip_da,mac_sa,rate_pps,count):
    #log.info("port_handle %r vlan %r ip_sa %r ip_da %r mac_sa %r ",port_handle,vlan,ip_sa,ip_da,mac_sa)
    log.info(banner("------in ArpTrafficGenerator22Suppres-----"))

    for vlan in range(int(vlan),int(vlan)+int(count)):
        vlan = str(vlan)
        streamblock_ret1 = sth.traffic_config (
        mode = 'create',
        port_handle = port_handle,
        l2_encap = 'ethernet_ii_vlan',
        vlan_id=vlan,
        #vlan_id_count=count,        
        l3_protocol = 'arp',
        ip_src_addr = ip_sa, 
        #ip_src_count = count,
        ip_src_mode = 'increment',
        ip_src_step ='0.1.0.0',
        ip_dst_addr = ip_da,
        #ip_dst_count = count,
        ip_dst_mode = 'increment',
        ip_dst_step ='0.1.0.0',
        arp_src_hw_addr = mac_sa,
        arp_src_hw_mode = 'increment',
        #arp_src_hw_count = count,
        arp_dst_hw_addr = "00:00:00:00:00:00",
        arp_dst_hw_mode = "fixed",
        arp_operation = "arpRequest",
        rate_pps = rate_pps,
        mac_src = mac_sa,
        mac_dst = 'ff:ff:ff:ff:ff:ff',
        #mac_src_count= count,
        mac_src_mode='increment',
        mac_src_step='00:00:00:00:00:01',
        transmit_mode = 'continuous')

        ip_sa = str(ip_address(ip_sa)+65536)
        ip_da = str(ip_address(ip_da)+65536)         
        mac_sa1 = EUI(mac_sa)
        mac_sa2 = int(mac_sa1)+1
        mac_sa3 = str(EUI(mac_sa2))
        mac_sa = mac_sa3.replace("-",":")
 


def ScaleSpirentHostBidirStream(port_hdl1,port_hdl2,vlan1,vlan2,ip1,ip2,gw1,gw2,rate_pps,scale):
    log.info(banner("------SpirentHostBidirStream-----"))

    log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)     
    device_ret1 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan1,port_handle = port_hdl1,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip1,intf_prefix_len = '16',\
    gateway_ip_addr = gw1); 
            
    device_ret2 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan2,port_handle = port_hdl2,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip2,intf_ip_addr_step='0.1.0.0',intf_prefix_len = '16',\
    gateway_ip_addr = gw2,gateway_ip_addr_step='0.1.0.0',count=scale,ip_stack_count=scale)
            
    h1 = device_ret1['handle']
    h2 = device_ret2['handle']
 


    h2 = device_ret2['handle']

    vlan_id_count = scale

    for host in [h2]:
        sth.invoke('stc::config %s -vlanif.IfCountPerLowerIf %s' %(host, vlan_id_count))
      
    streamblock_ret1 = sth.traffic_config (mode= 'create',port_handle= port_hdl1,\
    emulation_src_handle=h1,emulation_dst_handle = h2,bidirectional='1',\
    port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps)

    status = streamblock_ret1['status']

    log.info('+-----------------------------------------------------------------------+')
    log.info('stream_id : %r, vlan1 : %r ,vlan2 : %r ,rate_pps : %r',streamblock_ret1['stream_id'],vlan1,vlan2,rate_pps)                
    log.info('IP1 : %r,IP2 : %r, Host1 : %r ,Host2 : %r ',ip1,ip2,h1,h2)                
    log.info('+-----------------------------------------------------------------------+')
    if (status == '0') :
        log.info('run sth.traffic_config failed for V4 %r', streamblock_ret1)




def VxlanStReset(uut_list):
    log.info(banner("Deleteing adding vxlan features"))
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
        op = uut.execute('show port-channel summary | incl Eth')
        op1 = op.splitlines()
        po_list = []
        for line in op1:
            if line:
                if not 'Po1(SU)' in line:
                    po = line.split()[1].split('(')[0]
                    po_list.append(po)
        for intf in po_list+["nve1"]:
            uut.configure(cfg_shut.format(intf=intf))

    countdown(60)

    for uut in uut_list:
        op = uut.execute('show port-channel summary | incl Eth')
        op1 = op.splitlines()
        po_list = []
        for line in op1:
            if line:
                if not 'Po1(SU)' in line:
                    po = line.split()[1].split('(')[0]
                    po_list.append(po)
        for intf in po_list+["nve1"]:
            uut.configure(cfg_no_shut.format(intf=intf))        
    
    countdown(200)
        
    for uut in uut_list:
        for feature in ['ospf','pim','bgp']:
            test1 = leaf_protocol_check222(uut,[feature])
            if not test1:
                log.info('Feature %r neigborship on device %r Failed ',feature,str(uut))
                return 0
          
    log.info(banner("Passed VxlanStReset"))
    return 1



def VxlanStResetFnL(uut_list):
    log.info(banner("Deleteing adding vxlan features"))


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
        op = uut.execute('show port-channel summary | incl Eth')
        op1 = op.splitlines()
        po_list = []
        for line in op1:
            if line:
                if not 'Po1(SU)' in line:
                    po = line.split()[1].split('(')[0]
                    po_list.append(po)
        for intf in po_list:
            uut.configure(cfg_shut.format(intf=intf))

    for uut in uut_list:
        uut.configure(['interface nve1','shutdown'])

    countdown(60)

    for uut in uut_list:
        op = uut.execute('show port-channel summary | incl Eth')
        op1 = op.splitlines()
        po_list = []
        for line in op1:
            if line:
                if not 'Po1(SU)' in line:
                    po = line.split()[1].split('(')[0]
                    po_list.append(po)
        for intf in po_list:
            uut.configure(cfg_no_shut.format(intf=intf))        
    
    for uut in uut_list:
        uut.configure(['interface nve1','no shutdown'])

    countdown(200)
        
    for uut in uut_list:
        for feature in ['ospf','pim']:
            test1 = leaf_protocol_check222(uut,[feature])
            if not test1:
                log.info('Feature %r neigborship on device %r Failed ',feature,str(uut))
                return 0
          
    log.info(banner("Passed VxlanStResetFnL"))
    return 1



#def BumTrafficTest(port_handle_sw1,port_handle_sw2,rate,pps,orphan_handle_list):


def BumTrafficTest(port_handle1,port_handle2,rate,pps,orphan_handle_list):

    test1=SpirentRateTest22(port_handle1,port_handle2,rate,pps)
        
    if not test1:
        log.info(banner("Rate test Failed"))
        return 0

    for port_hdl in orphan_handle_list:
        res = sth.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
        rx_rate = res['item0']['PortRxTotalFrameRate']
        log.info('+--------------------------------------+')  
        log.info('+---- RX rate at Port %r is : %r ------+',port_hdl,rx_rate) 
        log.info('+--------------------------------------+') 
        if abs(int(rx_rate) - int(rate)*2) > int(pps):
            log.info('Traffic  Rate Test failed for %r',port_hdl)
            log.info('Stats are %r',res)
            return 0
    return 1
                



def KucTrafficTest(port_handle1,port_handle2,rate,pps,orphan_handle_list):

    test1=SpirentRateTest22(port_handle1,port_handle2,rate,pps)      
    if not test1:
        log.info(banner("Rate test Failed @ KucTrafficTest"))
        return 0

    for port_hdl in orphan_handle_list:
        res = sth.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
        rx_rate = res['item0']['PortRxTotalFrameRate']
        log.info('+--------------------------------------+')  
        log.info('+---- RX rate at Port %r is : %r ------+',port_hdl,rx_rate) 
        log.info('+--------------------------------------+') 
        if abs(int(rx_rate) - int(rate)*2) < int(pps):
            log.info('Traffic  Rate Test failed for %r',port_hdl)
            log.info('Stats are %r',res)
            return 0
    return 1
                
 
def AllTrafficTest(port_handle1,port_handle2,rate,pps,orphan_handle_list):
    rate3=int(rate)*4
    #diff = 4*int(pps)
    diff = int(rate3*.025)
    test1=SpirentRateTest22(port_handle1,port_handle2,rate3,diff)
        
    if not test1:
        log.info(banner("Rate test Failed"))
        return 0

    for port_hdl in orphan_handle_list:
        if port_hdl:
            res = sth.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            rx_rate = res['item0']['PortRxTotalFrameRate']
            log.info('+----------------------------------------------------------------------+')  
            log.info('+---- Acutual RX rate at Port %r is : %r ------+',port_hdl,rx_rate) 
            log.info('+---- Expected RX rate at Port %r is : %r ------+',port_hdl,int(rate)*2)         
            log.info('+----------------------------------------------------------------------+') 
            if abs(int(rx_rate) - int(rate)*2) > diff:
                log.info('Traffic  Rate Test failed for %r',port_hdl)
                log.info('Stats are %r',res)
                return 0
    return 1
 

def AllTrafficTestL2(port_handle1,port_handle2,rate,pps,orphan_handle_list):
    rate3=int(rate)*3
    diff = int(rate3*.025)
    test1=SpirentRateTest22(port_handle1,port_handle2,rate3,diff)
        
    if not test1:
        log.info(banner("Rate test Failed"))
        return 0

    for port_hdl in orphan_handle_list:
        if port_hdl:
            res = sth.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            rx_rate = res['item0']['PortRxTotalFrameRate']
            log.info('+----------------------------------------------------------------------+')  
            log.info('+---- Acutual RX rate at Port %r is : %r ------+',port_hdl,rx_rate) 
            log.info('+---- Expected RX rate at Port %r is : %r ------+',port_hdl,int(rate)*2)         
            log.info('+----------------------------------------------------------------------+') 
            if abs(int(rx_rate) - int(rate)*2) > diff:
                log.info('Traffic  Rate Test failed for %r',port_hdl)
                log.info('Stats are %r',res)
                return 0
    return 1


def ArpSuppOnTrafficTest(port_handle1,port_handle2,rate,pps,orphan_handle_list):
    #rate3=int(rate)*3
    test1=SpirentRateTest22(port_handle1,port_handle2,rate,pps)
        
    if test1:
        log.info(banner("Rate test Failed"))
        return 0

    for port_hdl in orphan_handle_list:
        res = sth.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
        rx_rate = res['item0']['PortRxTotalFrameRate']
        log.info('+----------------------------------------------------------------------+')  
        log.info('+---- Acutual RX rate at Port %r is : %r ------+',port_hdl,rx_rate) 
        log.info('+---- Expected RX rate at Port %r is : %r ------+',port_hdl,0)         
        log.info('+----------------------------------------------------------------------+') 
        if int(rx_rate) > int(pps):
            log.info('Traffic  Rate Test failed for %r',port_hdl)
            log.info('Stats are %r',res)
            return 0
    return 1


def ArpSuppOffTrafficTest(port_handle1,port_handle2,rate,pps,orphan_handle_list):
    #rate3=int(rate)*3
    test1=SpirentRateTest22(port_handle1,port_handle2,rate,2*int(pps))
        
    if not test1:
        log.info(banner("Rate test Failed"))
        return 0

    for port_hdl in orphan_handle_list:
        res = sth.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
        rx_rate = res['item0']['PortRxTotalFrameRate']
        log.info('+----------------------------------------------------------------------+')  
        log.info('+---- Acutual RX rate at Port %r is : %r ------+',port_hdl,rx_rate) 
        log.info('+---- Expected RX rate at Port %r is : %r ------+',port_hdl,int(rate)*2)         
        log.info('+----------------------------------------------------------------------+') 
        if abs(int(rx_rate) - int(rate)*2) > 4*(int(pps)):
            log.info('Traffic  Rate Test failed for %r',port_hdl)
            log.info('Stats are %r',res)
            return 0
    return 1



def VxlanStArpGen(port_handle_list,vlan,ip_sa,ip_da,mac_sa,rate_pps,count):
    log.info(banner("Starting VxlanStArpGen"))

    for port_hdl in  port_handle_list:
        log.info("Resetting all Streams for Port %r",port_hdl)
        traffic_ctrl_ret = sth.traffic_control(port_handle = port_hdl, action = 'reset') 


    ip_sa1 = ip_address(ip_sa)
    ip_da1 = ip_address(ip_da)
    mac_sa1 = EUI(mac_sa)

    for port_hdl in  port_handle_list:
        log.info("Adding ARP Stream for Port %r",port_hdl)
        ArpTrafficGenerator2(port_hdl,vlan,str(ip_sa1),str(ip_da1),str(mac_sa1),rate_pps,count)
        mac_sa2 = int(mac_sa1)+1
        mac_sa1 = EUI(mac_sa2)
        ip_sa1 =  ip_sa1+1
        ip_da1 =  ip_da1

    for port_hdl in  port_handle_list:
        log.info("Starting ARP Stream Traffic for Port %r",port_hdl)
        traffic_ctrl_ret = sth.traffic_control(port_handle = port_hdl, action = 'run')

    log.info(banner("Starting ARP for all streams"))   
    for i in range(1,4): 
        doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')

def SpirentRoutedBidirStream(uut,port_hdl1,port_hdl2,pps):
    log.info(banner("------SpirentHostBidirStream-----"))

    #op = uut.execute('show vrf all | incl vxlan')
    op = uut.execute('show nve vni  | incl L3')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            if 'own' in line:
                return 0
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



def SpirentRoutedBidirStreamPvlan(uut,port_hdl1,port_hdl2,pps,vlan_vni_scale):
    log.info(banner("------SpirentHostBidirStream-----"))

    op = uut.execute('show vrf all | incl vxlan')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            if 'own' in line:
                return 0
            else:
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





def SpirentHostBidirStreamSmacSame(port_hdl1,port_hdl2,vlan1,vlan2,ip1,ip2,gw1,gw2,rate_pps):
    log.info(banner("------SpirentHostBidirStream-----"))

    #mac1         =       '00:12:94:aa:00:02',
    #mac2         =       '00:13:94:bb:00:02',
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


    log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)     
    device_ret1 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan1,port_handle = port_hdl1,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip1,intf_prefix_len = '16',\
    gateway_ip_addr = gw1,mac_addr= mac1); 

    device_ret2 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan2,port_handle = port_hdl2,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip2,intf_prefix_len = '16',\
    gateway_ip_addr = gw2,mac_addr= mac2);
            
    h1 = device_ret1['handle']
    h2 = device_ret2['handle']
       
    streamblock_ret1 = sth.traffic_config (mode= 'create',port_handle= port_hdl1,\
    emulation_src_handle=h1,emulation_dst_handle = h2,bidirectional='1',\
    port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps)

    status = streamblock_ret1['status']

    log.info('+-----------------------------------------------------------------------+')
    log.info('stream_id : %r, vlan1 : %r ,vlan2 : %r ,rate_pps : %r',streamblock_ret1['stream_id'],vlan1,vlan2,rate_pps)                
    log.info('IP1 : %r,IP2 : %r, Host1 : %r ,Host2 : %r ',ip1,ip2,h1,h2)                
    log.info('+-----------------------------------------------------------------------+')
    if (status == '0') :
        log.info('run sth.traffic_config failed for V4 %r', streamblock_ret1)


def SpirentHostBidirStream(port_hdl1,port_hdl2,vlan1,vlan2,ip1,ip2,gw1,gw2,rate_pps):
    log.info(banner("------SpirentHostBidirStream-----"))

    #mac1         =       '00:12:94:aa:00:02',
    #mac2         =       '00:13:94:bb:00:02',

    str1=hex(randint(16,54))[2:]
    str2=hex(randint(55,104))[2:]
    str3=hex(randint(32,80))[2:]
    str4=hex(randint(50,95))[2:]

    mac1='00:10:'+str2+':'+str1+':'+str3+':02'
    mac2='00:10:'+str1+':'+str2+':'+str4+':02'


    #mac_sa1 = EUI(mac_sa)
    #mac_sa2 = int(mac_sa1)+1
    #mac_sa = EUI(mac_sa2)

    log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)     
    device_ret1 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan1,port_handle = port_hdl1,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip1,intf_prefix_len = '16',\
    gateway_ip_addr = gw1,mac_addr= mac1); 

    device_ret2 =sth.emulation_device_config (mode = 'create', ip_version = 'ipv4',\
    encapsulation = 'ethernet_ii_vlan',vlan_id  = vlan2,port_handle = port_hdl2,\
    resolve_gateway_mac = 'true',intf_ip_addr= ip2,intf_prefix_len = '16',\
    gateway_ip_addr = gw2,mac_addr= mac2);
            
    h1 = device_ret1['handle']
    h2 = device_ret2['handle']
       
    streamblock_ret1 = sth.traffic_config (mode= 'create',port_handle= port_hdl1,\
    emulation_src_handle=h1,emulation_dst_handle = h2,bidirectional='1',\
    port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps)

    status = streamblock_ret1['status']

    log.info('+-----------------------------------------------------------------------+')
    log.info('stream_id : %r, vlan1 : %r ,vlan2 : %r ,rate_pps : %r',streamblock_ret1['stream_id'],vlan1,vlan2,rate_pps)                
    log.info('IP1 : %r,IP2 : %r, Host1 : %r ,Host2 : %r ',ip1,ip2,h1,h2)                
    log.info('+-----------------------------------------------------------------------+')
    if (status == '0') :
        log.info('run sth.traffic_config failed for V4 %r', streamblock_ret1)


def ArpSuppressTrafficGenerator(port_handle,vlan,ip_sa,ip_da,mac_sa,rate_pps,count):
    #log.info("port_handle %r vlan %r ip_sa %r ip_da %r mac_sa %r ",port_handle,vlan,ip_sa,ip_da,mac_sa)
    log.info(banner("------in ArpSuppressTrafficGenerator-----"))

    #for vlan in range(int(vlan),int(vlan)+int(count)):
    vlan = str(vlan)

    streamblock_ret1 = sth.traffic_config (
        mode = 'create',
        port_handle = port_handle,
        l2_encap = 'ethernet_ii_vlan',
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

 

def CheckOspfUplinkRate(uut_list,pps): 
    log.info(banner("Starting TriggerCoreIfFlapStaticPo "))     
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

    return 1            

 

def SpirentArpRateTest(port_hdl_list1,port_hdl_list2,rate_fps,diff,arp_sa_state):
    log.info(banner(" Starting SpirentArpRateTest "))

    result = 1
    if 'on' in arp_sa_state:
        for port_hdl in port_hdl_list1:   
            log.info("port_hdl %r,rate_fps %r", port_hdl,rate_fps)
            res = sth.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            rx_rate = res['item0']['PortRxTotalFrameRate']    
            tx_rate = res['item0']['PortTxTotalFrameRate']
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
            res = sth.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            rx_rate = res['item0']['PortRxTotalFrameRate']    
            tx_rate = res['item0']['PortTxTotalFrameRate']
            log.info('+-----------------------------------------------------------------------+')
            log.info('rx_rate is %r,tx_rate is %r',rx_rate,tx_rate)
            log.info('+-----------------------------------------------------------------------+')

            if int(rx_rate) > 2*(int(diff)):
                log.info('ARP Rate Test failed with SA enabled, rate at orphan port is %r',rx_rate)
                result = 0


    elif 'off' in arp_sa_state:
        for port_hdl in port_hdl_list1:   
            log.info("port_hdl %r,rate_fps %r", port_hdl,rate_fps)
            res = sth.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            rx_rate = res['item0']['PortRxTotalFrameRate']    
            tx_rate = res['item0']['PortTxTotalFrameRate']
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
            res = sth.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            rx_rate = res['item0']['PortRxTotalFrameRate']    
            tx_rate = res['item0']['PortTxTotalFrameRate']
            log.info('+-----------------------------------------------------------------------+')
            log.info('rx_rate is %r,tx_rate is %r',rx_rate,tx_rate)
            log.info('+-----------------------------------------------------------------------+')

            if abs(int(rx_rate) - 2*(int(rate_fps))) > 5*int(diff):
                log.info('ARP Rate Test failed with SA Disabled, rate at orphan port is %r',rx_rate)
                result = 0

    return result
 


def PortVlanMappingConf(uut_list,vlan_start,map_scale): 
    log.info(banner("Starting PortVlanMapping "))     
    for uut in uut_list:
        intf_list = []
        op = uut.execute('show spanning-tree vlan 1001 | incl FWD')
        op1 = op.splitlines()
        for line in op1:
            if 'FWD' in line:
                if not 'peer-link' in line:
                    intf_list.append(line.split()[0])

        for intf in intf_list:
            cmd = \
            """
            interface {intf}
            switchport vlan mapping enable
            """    
            vlan1 = vlan_start
            vlan2 = vlan1 + map_scale
            for i in range(1,int(map_scale)+1):
                cmd +=  ' switchport vlan mapping {vlan1} {vlan2}\n'.format(vlan1=vlan1,vlan2=vlan2) 
                vlan1 = vlan1 + 1 
                vlan2 = vlan2 + 1 
            try:
                uut.configure(cmd.format(intf=intf))        
            except:
                log.error('PVLAN Mapping failed for uut %r interface %r',uut,intf)
                return 0  
    return 1




def PortVlanMappingConfAllOld(uut_list,vlan_start,map_scale,mode): 
    log.info(banner("Starting PortVlanMapping ")) 

    for uut in uut_list:
        #op = uut.execute('sh nve vni | incl [1001]')
        #op1 = op.splitlines()
        ##for line in op1:
        #    if 'UnicastBGP' in line:
        #            if 'Up' in line:
        #                bgp_vlan_start = line.split()[-2].replace("[","").replace("]","")

        ##for uut in uut_list:
        bgp_vni_scale = int(uut.execute('sh nve vni | incl UnicastBGP | count'))
        #op1 = op.splitlines()
        #for line in op1:
        #    if '225.5.0' in line:
        #            if 'Up' in line:
        #                mcast_vlan_start = line.split()[-2].replace("[","").replace("]","")


        #for uut in uut_list:
        intf_list = []
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
            if 'mix' in mode:
                vlan1 = int(vlan_start)
                vlan11 = vlan1 + bgp_vni_scale
                vlan2 = vlan1 + int(map_scale/2)
                vlan22 = vlan11 + int(map_scale/2)
                for i in range(1,int((map_scale)/2)+1):
                    cmd1 +=  ' switchport vlan mapping {vlan1} {vlan2}\n'.format(vlan1=vlan1,vlan2=vlan2) 
                    cmd1 +=  ' switchport vlan mapping {vlan11} {vlan22}\n'.format(vlan11=vlan11,vlan22=vlan22) 
                    vlan1 = vlan1 + 1 
                    vlan2 = vlan2 + 1 
                    vlan11 = vlan11 + 1 
                    vlan22 = vlan22 + 1                     
            
            log.info("CMD ISSS %r",cmd1)
            try:
                uut.configure(cmd1.format(intf=intf))        
            except:
                log.error('PVLAN Mapping failed for uut %r interface %r',uut,intf)
                return 0  

            if 'bgp' in mode:
                vlan1 = int(vlan_start)
            elif 'mcast' in mode:    
                vlan1 = int(vlan_start)
            vlan2 = vlan1 + map_scale
            #vlan22 = vlan11 + map_scale
            for i in range(1,int(map_scale)+1):
                cmd1 +=  ' switchport vlan mapping {vlan1} {vlan2}\n'.format(vlan1=vlan1,vlan2=vlan2) 
                #cmd1 +=  ' switchport vlan mapping {vlan11} {vlan22}\n'.format(vlan11=vlan11,vlan22=vlan22) 
                vlan1 = vlan1 + 1 
                vlan2 = vlan2 + 1 
                    #vlan11 = vlan11 + 1 
                    #vlan22 = vlan22 + 1                     
            try:
                uut.configure(cmd1.format(intf=intf))        
            except:
                log.error('PVLAN Mapping failed for uut %r interface %r',uut,intf)
                return 0  

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
            log.info("CMD ISSS -------------- %r",cmd1)
            try:
                uut.configure(cmd1.format(intf=intf))        
            except:
                log.error('PVLAN Mapping failed for uut %r interface %r',uut,intf)
                return 0   

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
        uut.configure(cmd)        
    return 1


def NveL3VniRemoveAdd(uut_list): 
    log.info(banner("Starting NveMcastGroupChange ")) 

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
        uut.configure(op)         

    return 1



def VnSegmentRemoveAdd(uut_list,vlan_start): 
    log.info(banner("Starting NveMcastGroupChange ")) 

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
                cmd += line + '\n'


        cmd += 'exit' + '\n'  
        try:          
            log.info("removing vn-segment ")
            uut.configure(cmd) 
            countdown(2)
            log.info("vn-segment  ")        
            uut.configure(vlan_run)         
        except:
            log.error('remove /add  vn-segment failed , uut is %r',uut)
            return 0  

    return 1



def PortVlanMappingCleanup(uut_list,vlan_start): 
    log.info(banner("Starting PortVlanMappingCleanup "))     
    for uut in uut_list:
        intf_list = []
        op = uut.execute('show spanning-tree vlan {vlan} | incl FWD'.format(vlan=vlan_start))
        op1 = op.splitlines()
        for line in op1:
            if 'FWD' in line:
                if not 'peer-link' in line:
                    intf_list.append(line.split()[0])            
        for intf in intf_list:
            op = uut.configure('show run int {intf} | incl mapping'.format(intf=intf)) 
            op1 = op.splitlines()
            cmd = \
            """
            interface {intf}
            """ 
            for line in op1:
                if 'mapping' in line:
                    if not 'run' in line:
                        cmd +=  ' no {line}\n'.format(line=line) 
            try:
                uut.configure(cmd.format(intf=intf))        
            except:
                log.error('PVLAN Removal failed for uut %r interface %r',uut,intf)
                return 0  
    return 1




def PvlanTrafficTest(port_handle1,port_handle2,rate,pps,orphan_handle_list):
    rate2=int(rate)*2
    test1=SpirentRateTest22(port_handle1,port_handle2,rate2,pps)
        
    if not test1:
        log.info(banner("Rate test Failed"))
        return 0

    for port_hdl in orphan_handle_list:
        res = sth.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
        rx_rate = res['item0']['PortRxTotalFrameRate']
        log.info('+----------------------------------------------------------------------+')  
        log.info('+---- Acutual RX rate at Port %r is : %r ------+',port_hdl,rx_rate) 
        log.info('+---- Expected RX rate at Port %r is : %r ------+',port_hdl,int(rate)*2)         
        log.info('+----------------------------------------------------------------------+') 
        if abs(int(rx_rate) - int(rate)*2) > int(pps):
            log.info('Traffic  Rate Test failed for %r',port_hdl)
            log.info('Stats are %r',res)
            return 0
    return 1




def PortVlanMappingOverlapConf(uut_list,vlan_start,map_scale): 
    log.info(banner("Starting PortVlanMapping "))     
    for uut in uut_list:
        intf_list = []
        op = uut.execute('show spanning-tree vlan 1001 | incl FWD')
        op1 = op.splitlines()
        for line in op1:
            if 'FWD' in line:
                if not 'peer-link' in line:
                    intf_list.append(line.split()[0])

        for intf in intf_list:
            cmd = \
            """
            interface {intf}
            switchport vlan mapping enable
            """    
            vlan1 = vlan_start
            vlan2 = vlan1 + 1
            for i in range(1,int(map_scale)+1):
                cmd +=  ' switchport vlan mapping {vlan1} {vlan2}\n'.format(vlan1=vlan1,vlan2=vlan2) 
                vlan1 = vlan1 + 1 
                vlan2 = vlan2 + 1 
            try:
                uut.configure(cmd.format(intf=intf))        
            except:
                log.error('PVLAN Mapping failed for uut %r interface %r',uut,intf)
                return 0  
    return 1




def SpirentV6BidirStream(port_hdl1,port_hdl2,vlan1,vlan2,scale,ipv61,ipv62,rate_pps):
    log.info(banner("STARTING SpirentV6BidirStream "))    
    log.info('VLAN1 : %r,VLAN2 : %r,SCALE : %r,IP1 : %r,IP2 : %r ' ,vlan1,vlan2,scale,ipv61,ipv62)     
  
    device_ret = sth.traffic_config (
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
 
    device_ret = sth.traffic_config (
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



def CatchVpcBug(uut):

    str1=randint(1000,2000)
    folder = 'aaaaaa'+str(str1)
    log.info("Folder name is %r",folder)
    uut.transmit('run bash \r')
    uut.receive('bash-4.2$')
    uut.transmit('sudo su \r')
    uut.receive('bash-4.2$')
    uut.transmit('cd /bootflash\r')
    uut.receive('bash-4.2$')
    uut.transmit('mkdir %s\r' %folder)
    uut.receive('bash-4.2$')
    uut.transmit('cd /tmp\r')
    uut.receive('bash-4.2$')
    uut.transmit(' mv ap_* /bootflash/%s/\r' %folder)
    uut.receive('bash-4.2$')
    uut.transmit('exit\r')
    uut.receive('bash-4.2$')
    uut.transmit('exit\r')
    uut.receive('bash-4.2$')
    

    op = uut.execute("show port-channel summary interface port-channel 1 | incl Eth")
    if not "1/25" in op:
        return 0
    
    op = uut.execute("slot 1 quoted 'show system internal iftmc info interface port-channel 1' | grep -A 10 'BCM INFO:'")
    if not "TrunkID = 3" in op:
        return 0

    cmd1 = 'run bash /lc/isan/bcm/bcm-shell trunk show'
    op = uut.execute(cmd1)    



    if "trunk 3: (front panel, 0 ports)" in op:
        return 0
   
    return 1




def VniRemoveAdd(uut,vlan,vni):
    cfg = \
        """
        vlan {vlan}
        no vni {vni}
        """
    try:
        uut.configure(cfg.format(vlan=vlan,vni=vni)) 
        countdown(5)
    except:
        log.error((" vni remov add Failed for vlan %r vni is %r",vlan,vni)) 
        return 0
    cfg = \
        """
        vlan {vlan}
        vni {vni}
        """
    try:
        uut.configure(cfg.format(vlan=vlan,vni=vni)) 
        countdown(5)
            
    except:
        log.error((" vni remov add Failed for vlan %r vni is %r",vlan,vni)) 
        return 0
    
    return 1  



def vPCMemberFlap(uut_list,po_list):     
    log.info(banner("Starting TriggerCoreIfFlapStaticPo "))     
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
        op3 = uut.execute('show run interface nve 1 | beg nve | end peer')
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
        op3 = uut.execute('show run interface nve 1 | beg nve | end peer')
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




def ChangeMcastToIR(uut_list,mode,scale,mcast_group_scale,group_start): 

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
                'no mcast-group {group}'.format(group=group),'ingress-replication protocol bgp',])

    elif 'bgp' in mode:
        ir_scale = scale            
        vni_per_group = int(ir_scale/mcast_group_scale)
        for uut in uut_list:
            for vni in range(201001,201001+vni_per_group):
                uut.configure(['interface nve1',' member vni {vni}'.format(vni=vni),\
                'no mcast-group {group}'.format(group=group),'ingress-replication protocol bgp',])


    #countdown(5)    
    #for uut in uut_list:
    #    uut.configure(['interface nve1', 'no shutdown'])
    countdown(5) 
    return 1   


def DevicePreCleanup(uut):
    log.info(banner("Deleteing adding vxlan features"))
    feature_clean=\
    """
    #no router bgp 65001
    #no router ospf 1
    #no interface nve1
    no feature ngoam
    show clock
    no feature nv over
    show clock
    no feature bgp
    show clock
    no feature ospf
    show clock
    no feature pim
    no feature interface-vlan
    no vlan 2-600
    line con
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
    feature interface-vlan  
    show clock
    nv overlay evpn
    feature vn-segment-vlan-based
    ##default interface po101
    """ 
    uut.configure(feature_clean,timeout=180) 

    log.info(banner("Deleteing Monitor session"))
    op = uut.execute('sh run monitor | incl sess')
    if op:
        op1 = op.splitlines()
        for line in op1:
            if 'session' in line:
                uut.configure('no {line}'.format(line=line))

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
                    cfg1 = """#default interface {po}"""
                    cfg2 = """no interface {po}"""
                    try:
                        uut.configure(cfg1.format(po=po))
                        uut.configure(cfg2.format(po=po))                        
                    except:
                        log.error('Invalid CLI given')
    uut.configure("no feature lacp")        
    uut.configure("feature lacp")  
    log.info(banner("Deleteing access lists"))
    op = uut.configure("sh run | incl 'ip access-list'")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'copp' in line:
                if not "sh run |" in line:
                    if "access-list" in line:
                        cfg = "no {line}"
                        uut.configure(cfg.format(line=line)) 

    log.info(banner("Delete static routes"))          
    op = uut.configure("sh run | incl 'ip route '")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'run' in line:
                if not '10.127' in line:
                    if 'ip route ' in line: 
                        cfg = "no {line}"
                        uut.configure(cfg.format(line=line))   

    log.info(banner("Deleting vrf"))                  
    op = uut.configure("show vrf")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'default' in line:
                if not 'management' in line:
                    vrf = line.split()[0]
                    uut.configure('no vrf context {vrf}'.format(vrf=vrf))
                                
    log.info(banner("Deleting Port Channels"))  

    op = uut.configure("sh run | incl 'interface port-channel'")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if not 'run' in line:
                if "port-channel" in line:
                    cfg1 = "default {line}"
                    uut.configure(cfg1.format(line=line)) 
                    cfg2 = "no {line}"
                    uut.configure(cfg2.format(line=line)) 




 
    log.info(banner("Default Eth interface to L3"))  
    op = uut.configure("sh int br | exclu route")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'Eth' in line:
                if not 'Ethernet' in line:
                    intf = line.split()[0]
                    cfg = \
                        """
                        interface {intf}
                        no switchport
                        """
                    uut.configure(cfg.format(intf=intf))

    log.info(banner("Deleting Loopbacks")) 
    op = uut.configure("show ip interface brief ")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'Lo' in line:
                intf = line.split()[0]
                uut.configure('no interface {intf}'.format(intf=intf))

 
    log.info(banner("Deleting community-list"))                    
    op = uut.execute("show run | incl community-list")
    op1 = op.splitlines()
    for line in op1:
        if not 'run' in line:
            if line:
                if 'community-list' in line:
                    cfg = "no {line}"
                    try:
                        uut.configure(cfg.format(line=line))  
                    except:
                        log.error('community-list delete failed in uut',uut)

    log.info(banner("Deleting route-map"))             
    op = uut.execute("show run | incl route-map")
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'route-map' in line:
                if 'permit' in line:
                    cfg = "no {line}"
                    try:
                        uut.configure(cfg.format(line=line))  
                    except:
                        log.error('route-map delete failed in uut',uut)


def ChangeStaticRtoMcastR(uut_list,mode,scale,mcast_group_scale,group_start): 

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




def ChangeStaticRtoMcastR(uut_list,mode,scale,mcast_group_scale,group_start): 

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
                'no mcast-group {group}'.format(group=group),'ingress-replication protocol bgp',])

    elif 'bgp' in mode:
        ir_scale = scale            
        vni_per_group = int(ir_scale/mcast_group_scale)
        for uut in uut_list:
            for vni in range(201001,201001+vni_per_group):
                uut.configure(['interface nve1',' member vni {vni}'.format(vni=vni),\
                'no mcast-group {group}'.format(group=group),'ingress-replication protocol bgp',])


    #countdown(5)    
    #for uut in uut_list:
    #    uut.configure(['interface nve1', 'no shutdown'])
    countdown(5) 
    return 1   





def SpirentRoutedBidirStreamVsg(uut,port_hdl1,port_hdl2,pps):
    log.info(banner("------SpirentHostBidirStream-----"))

    #op = uut.execute('show vrf all | incl vxlan')
    op = uut.execute('show nve vni  | incl L3')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            if 'own' in line:
                return 0
            else:
                vrf = line.split()[-1].replace("[","").replace("]","")
                vrf_list.append(vrf)
    
    for i in range(0,20):
        vrf = vrf_list[i]
        #for vrf in vrf_list:
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


def base_configs_uut(uut):     
    log.info(banner("Base configurations"))       
    cfg = \
            """
            #default interface po 100
            #default interface po 101
            #no interf po 100
            #no interf po 101
            spanning-tree mode mst
            no spanning-tree mst configuration
            feature lacp
            no ip igmp snooping
            no vlan 2-3831
            terminal session-timeout 0
            system no hap-reset 
            """
    uut.configure(cfg)




def vxlan_configs_pcall_uut(uut,vlan_vni_scale,routing_vlan_scale,ir_mode,mcast_group_scale):     
    for intf in uut.interfaces.keys():
        if 'vxlan' in intf:
            intf = uut.interfaces[intf].intf
            vni=201001
            vlan_start = 1001
            routed_vlan = 101
            routed_vni = 90101
            ipv4_add1 = (str(uut.interfaces[intf].ipv4_add))[:-3]
            ipv4_add = sub("/(.*)",'',ipv4_add1)
            ipv6_add1 = (str(uut.interfaces[intf].ipv6_add))[:-4]
            ipv6_add = sub("/(.*)",'',ipv6_add1)
            log.info("IR mode is ================= %r",ir_mode)
            mcast_group = (str(uut.interfaces[intf].mcast_group))[:-3]
            vtep_vxlan_obj1=LeafObject2222(uut,vlan_start,vni,vlan_vni_scale,routed_vlan,routed_vni,routing_vlan_scale,ipv4_add,ipv6_add,mcast_group,'65001',ir_mode,mcast_group_scale)
            vtep_vxlan_obj1.vxlan_conf()


def vsg_loop_scale_configure(uut_list,ipv4_add,scale):
    v4 = ip_address(ipv4_add)
    cmd = " "
    j = 101
    for i in range(1,scale):   
        cmd += 'no interface loopb{j}\n'.format(j=j)
        cmd += 'interface loopb{j}\n'.format(j=j)
        cmd += 'no shutdown\n'
        cmd += 'ip address {v4}/32\n'.format(v4=v4)
        cmd += 'ip router ospf 1 area 0.0.0.0\n'
        cmd += 'ip pim sparse-mode\n'
        v4 = v4 + 1  
        j = j + 1 
    for uut in uut_list: 
        try:   
            uut.configure(cmd)
        except:
            log.info("vsg_loop_scale_configure failed")
            return 0
    return 1


    #def vsg_nve_scale_configure(uut):

def vsg_nve_scale_configure(uut,peer_scale,ir_vni_scale,vni_start,ipv4_add,remote_peer):
    #peer_scale = 256
    #ir_vni_scale = 640
    #vni_start = 201001
    #ipv4_add = '111.1.1.1'


    cmd = \
    """
    interface nve1
    no member vni {vni1}-{vni2}
    """
    try:
        uut.configure(cmd.format(vni1=vni_start,vni2=vni_start+ir_vni_scale-1))
    except:
        log.error("VNI delete Failed in Scale conf")
        return 0

    v4 = ip_address(ipv4_add)
    peer_per_vni = 16
    num_of_static_vni = int(peer_scale/peer_per_vni)
    cmd = \
    """
    interface nve1
    no shutdown
    """
    for vni in range(vni_start,vni_start+num_of_static_vni):
        cmd += 'member vni {vni}\n'.format(vni=vni)
        for i in range(1,peer_per_vni+1):            
            cmd += 'ingress-replication protocol static\n' 
            cmd += 'peer-ip {v4}\n'.format(v4=v4)
            cmd += 'peer-ip {remote_peer}\n'.format(remote_peer=remote_peer)
            v4 = v4 + 1


    try:        
        uut.configure(cmd)
    except:
        log.error("cmd failed @ vsg_nve_scale_configure")
        return 0


    cmd2 = \
    """
    interface nve1
    no shutdown
    """   
    for vni in range(vni_start+num_of_static_vni,vni_start+ir_vni_scale):     
        cmd2 += 'member vni {vni}\n'.format(vni=vni)
        #cmd2 += 'peer-ip {v4}\n'.format(v4=v4)
        cmd2 += 'ingress-replication protocol static\n' 
        cmd2 += 'peer-ip {v4}\n'.format(v4=v4)
        cmd2 += 'peer-ip {remote_peer}\n'.format(remote_peer=remote_peer)


    try:        
        uut.configure(cmd2)
    except:
        log.error("cmd2 failed @ vsg_nve_scale_configure")
        return 0




def catchEncapbug(uut_list,vlan,scale):
    for uut in uut_list:
        for vlan in range(vlan,vlan + 20):
            op1= uut.execute('slot 1 show system internal iftmc info vlan all | grep {vlan}'.format(vlan=vlan))
            op2=op1.split()
            a = op2.index('ipmc_idx')+2
            ipmc_idx=op2[a]
            op10= uut.execute('run bash /lc/isan/bcm/bcm-shell mc show group={id}'.format(id=ipmc_idx))
            count = op10.count('port')
            if vlan==1001:
                if count<26:
                    log.info('VLAN :%r, count less that 26, UUT : %r',vlan, uut)
                    return 0
            else:
                if count<5:
                    log.info('VLAN :%r , count less that 5,UUT : %r',vlan, uut)
                    return 0
                       
    return 1       
                            


def vsg_nve_scale_configureTEST(ipv4_add,peer_scale,ir_vni_scale,vni_start):
    v4 = ip_address(ipv4_add)
    peer_per_vni = 16
    num_of_static_vni = int(peer_scale/peer_per_vni)
    cmd = \
    """
    interface nve1
    no shutdown
    """
    for vni in range(vni_start,vni_start+num_of_static_vni):
        cmd += 'vni {vni}\n'.format(vni=vni)
        for i in range(1,peer_per_vni+1):    
            cmd += 'peer-ip {v4}\n'.format(v4=v4)
            v4 = v4 + 1
    print(cmd)
    cmd2 = \
    """
    interface nve1
    no shutdown
    """   
    for vni in range(vni_start+num_of_static_vni,vni_start+ir_vni_scale):     
        cmd2 += 'vni {vni}\n'.format(vni=vni)
        cmd2 += 'peer-ip {v4}\n'.format(v4=v4)
    print(cmd2)


def checkMacCount(uut,mac_type):
    op=uut.execute('show mac add count')
    op1=op.splitlines()
    for line in op1:
        if 'Overlay' in line:
            Overlay_mac_count = int(line.split()[-1])
        elif 'Dynamic' in line:
            Dynamic_mac_count = int(line.split()[-1])
        elif 'Total' in line:
            Total_mac_count = int(line.split()[-1])
    if 'Overlay' in mac_type: 
        return  Overlay_mac_count
    if 'Access' in mac_type: 
        acc_mac_count = Dynamic_mac_count-Overlay_mac_count
        return  acc_mac_count





def TriggerCoreIfShut(uut_list): 
    log.info(banner("Starting TriggerCoreIfShut"))     
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
                if not 'Vlan' in intf:
                    cfg = \
                    """
                    interface {intf}
                    shut
                    """
                    try:
                        uut.configure(cfg.format(intf=intf))
                    except:    
                        log.info('Trigger4CoreIfFlapStaticPo failed @ 11')
                        return 0
 


def TriggerCoreIfNoShut(uut_list): 
    log.info(banner("Starting TriggerCoreIfShut"))     
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
                    log.info('Trigger4CoreIfFlapStaticPo failed @ 11')
                    return 0

    return 1

 
