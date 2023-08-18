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

from ats.topology import Device
import sth
from sth import StcPython
from pexpect import *


from ats import aetest, log
from ats.log.utils import banner

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
    for vlan,vni in zip(range(vlan_start,vlan_start+scale+1),range(vni,vni+scale+1)):
        log.info('vlan ----------------- is %r vni is ----------------%r',vlan,vni)
        cfg = \
            """
            no interface vlan {vlan}
            interface nve 1
            member vni {vni}
            no suppress-arp
            vlan {vlan}
            xconnect
            """
        try:
            uut.configure(cfg.format(vlan=vlan,vni=vni))
        except:
            log.info("uut %r Xconnect Failed %r",uut)
            return 0 
 
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
                log.info("line in feature_enable isss --------- %r",line)
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
        peer-keepalive destination {node2_mgmt_ip}
        ip arp synchronize
        ipv6 nd synchronize 
        auto-recovery
        peer-gateway
        interface port-channel {vpc_domain}
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
        peer-keepalive destination {node1_mgmt_ip}
        ip arp synchronize
        ipv6 nd synchronize 
        auto-recovery
        peer-gateway
        interface port-channel {vpc_domain}
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
            default interface {intf}
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
            default interface {intf}
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
            default interface {intf}
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

        print("111111Entering proc configure port channel /uu........ ",self.device,self.po_num)
 
    def ConfigurePo(self):
        print("222222Entering proc configure port channel uut--------- ",self.device,self.po_num)

        if 'layer3' in self.po_type:
            config_str = \
                """
                no interface Port-Channel {po_num}
                interface Port-Channel {po_num}
                no switchport
                ip address {ipv4_add}
                mtu 9216
                """
            try:
                self.device.configure(config_str.format(po_num=self.po_num,ipv4_add=self.ipv4_add))
            except:
                log.error('Port Channel Config Failed on UUT')
            
        elif 'trunk' in self.po_type:
            print("Hereeeeeeeeeeeeeee")
            config_str = \
                """
                vlan {vlan_range}
                no interface Port-Channel {po_num}
                interface Port-Channel {po_num}
                mtu 9216
                switchport
                switchport mode trunk
                switchport trunk allowed vlan {vlan_range}
                no shut
                """
            try:
                self.device.configure(config_str.format(po_num=self.po_num,vlan_range=self.vlan_range))
            except:
                log.error('Port Channel Config Failed on UUT')

        elif 'access' in self.po_type:
            config_str = \
                """
                vlan {vlan_range}
                no interface Port-Channel {po_num}
                interface Port-Channel {po_num}
                mtu 9216
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
                default interface {intf}
                interface {intf}
                channel-group {po_num} force mode active
                no shut
                '''.format(intf=intf,po_num=self.po_num))        
            except:
                log.error('Port Channel member Config Failed on UUT')


    def remove_po_member(self):
        for intf in self.member_list:
            self.device.configure('''
            interface {intf}
            no channel-group {po_num} force mode active
            no shut
            '''.format(intf=intf,po_num=self.po_num)) 
 

def DevicePreClean(uut_list):
    try:
        for uut in uut_list:
            log.info(banner("Staring Pre clean "))
            uut.configure('no interface nve1')

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


        for uut in uut_list:
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
            mtu 9216
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
            mtu 9216
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
            mtu 9216
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
            mtu 9216
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
            self.node.configure(cmd.format(proc_id=self.proc_id,router_id=self.router_id))

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
    def __init__(self,node,vpc_domain,peer_ip,mct_mem_list1,vpc_po,vpc_po_mem_list1,vlan_range,vpc_po_type):
        self.node=node
        self.vpc_domain=vpc_domain
        self.peer_ip=peer_ip
        self.mct_mem_list1=mct_mem_list1
        self.vpc_po=vpc_po
        self.vpc_po_mem_list1=vpc_po_mem_list1
        self.vlan_range=vlan_range
        self.vpc_po_type=vpc_po_type
        self.peer_ip=peer_ip

    def vpc_conf(self):
        cmd1 = \
        '''
        spanning-tree mode mst 
        no feature vpc 
        feature vpc
        feature lacp
        vpc domain {vpc_domain}
        peer-keepalive destination {peer_ip}
        ip arp synchronize
        ipv6 nd synchronize 
        auto-recovery
        peer-gateway
        interface port-channel {vpc_domain}
        no shut
        switchport
        switchport mode trunk
        spanning-tree port type network
        vpc peer-link
        '''

        cmd2 = \
        '''
        vlan {vlan_range}
        interface port-channe {vpc_po}
        mtu 9216
        switchport
        switchport mode access
        switchport access vlan {vlan_range} 
        no shut
        vpc {vpc_po}
        '''
        cmd3 = \
        '''
        vlan {vlan_range}
        interface port-channe {vpc_po}
        switchport
        switchport mode trunk
        switchport trunk allowed vlan {vlan_range} 
        no shut
        vpc {vpc_po}
        '''

        cmd11 = \
        '''
        spanning-tree mode mst 
        no feature vpc 
        feature vpc
        feature lacp
        vpc domain {vpc_domain}
        peer-keepalive destination {peer_ip}
        ip arp synchronize
        ipv6 nd synchronize 
        auto-recovery
        peer-gateway
        interface port-channel {vpc_domain}
        no shut
        switchport
        switchport mode trunk
        spanning-tree port type network
        vpc peer-link
        policy-map type network-qos jumbo
        class type network-qos class-default
        system qos
        service-policy type network-qos jumbo
        '''

        cmd22 = \
        '''
        vlan {vlan_range}
        interface port-channe {vpc_po}
        switchport
        switchport mode access
        switchport access vlan {vlan_range} 
        no shut
        vpc {vpc_po}
        '''
        cmd33 = \
        '''
        vlan {vlan_range}
        interface port-channe {vpc_po}
        switchport
        switchport mode trunk
        switchport trunk allowed vlan {vlan_range} 
        no shut
        vpc {vpc_po}
        '''
        op1 = self.node.execute("show module ")
        op2 = self.node.execute("show system switch-mode")
        if 'N9K' in op1:
            try:
                self.node.configure(cmd1.format(peer_ip=self.peer_ip,vpc_domain=self.vpc_domain))
            except:
                log.error('111 vpc gloabal config failed')

            for intf in self.mct_mem_list1:
                cmd = \
                '''
                default interface {intf}
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
                try:   
                    self.node.configure(cmd2.format(vlan_range=self.vlan_range,vpc_po=self.vpc_po))
                except:
                    log.error('444 vpc conf failed for vlan_range',self.vlan_range)


            elif 'trunk' in self.vpc_po_type:
                try:   
                    self.node.configure(cmd3.format(vlan_range=self.vlan_range,vpc_po=self.vpc_po))
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

        elif 'N3K-C30' in op1:
            try:
                self.node.configure(cmd11.format(peer_ip=self.peer_ip,vpc_domain=self.vpc_domain))
            except:
                log.error('111 vpc gloabal config failed')

            for intf in self.mct_mem_list1:
                cmd = \
                '''
                default interface {intf}
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
                try:   
                    self.node.configure(cmd22.format(vlan_range=self.vlan_range,vpc_po=self.vpc_po))
                except:
                    log.error('444 vpc conf failed for vlan_range',self.vlan_range)


            elif 'trunk' in self.vpc_po_type:
                try:   
                    self.node.configure(cmd33.format(vlan_range=self.vlan_range,vpc_po=self.vpc_po))
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

        elif 'N3K-C31' in op1:
            if 'n3k' in op2:
                try:
                    self.node.configure(cmd11.format(peer_ip=self.peer_ip,vpc_domain=self.vpc_domain))
                except:
                    log.error('111 vpc gloabal config failed')

                for intf in self.mct_mem_list1:
                    cmd = \
                        '''
                        default interface {intf}
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
                    try:   
                        self.node.configure(cmd22.format(vlan_range=self.vlan_range,vpc_po=self.vpc_po))
                    except:
                        log.error('444 vpc conf failed for vlan_range',self.vlan_range)


                elif 'trunk' in self.vpc_po_type:
                    try:   
                        self.node.configure(cmd33.format(vlan_range=self.vlan_range,vpc_po=self.vpc_po))
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
            else:
                try:
                    self.node.configure(cmd1.format(peer_ip=self.peer_ip,vpc_domain=self.vpc_domain))
                except:
                    log.error('111 vpc gloabal config failed')

                for intf in self.mct_mem_list1:
                    cmd = \
                        '''
                        default interface {intf}
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
                    try:   
                        self.node.configure(cmd2.format(vlan_range=self.vlan_range,vpc_po=self.vpc_po))
                    except:
                        log.error('444 vpc conf failed for vlan_range',self.vlan_range)


                elif 'trunk' in self.vpc_po_type:
                    try:   
                        self.node.configure(cmd3.format(vlan_range=self.vlan_range,vpc_po=self.vpc_po))
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
    for i in range(0,count):
        routed_vni = routed_vni + 1 
        cmd = \
            '''
            vrf context vxlan-{routed_vni}
            vni {routed_vni}
            rd auto
            address-family ipv4 unicast
            route-target import 1000:{routed_vni}
            route-target import 1000:{routed_vni} evpn
            route-target export 1000:{routed_vni}
            route-target export 1000:{routed_vni} evpn
            address-family ipv6 unicast
            route-target import 1000:{routed_vni}
            route-target import 1000:{routed_vni} evpn
            route-target export 1000:{routed_vni}
            route-target export 1000:{routed_vni} evpn
            '''
        try:
            uut.configure(cmd.format(routed_vni=routed_vni))
        except:
            log.error('vrf configure failed for uut %r',uut)

def vlan_vni_configure(uut,vlan,vni,count):
    for vlan,vni in zip(range(vlan,vlan+count+1),range(vni,vni+count+1)):
        log.info('vlan ----------------- is %r vni is ----------------%r',vlan,vni)
        cmd = \
            '''
            vlan {vlan}
            vn-segment {vni}
            '''
        try:
            uut.configure(cmd.format(vni=vni,vlan=vlan))
        except:
            log.error('vni/vlan configure failed for uut %r',uut)


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
            log.error('vni/vlan remove failed for uut %r',uut)

 

 
def routed_svi_configure(uut,routed_vlan,routed_vni,count):
    print("Count issss",count)
    for i in range(0,count):
        print(i)
        routed_vni = routed_vni + 1
        routed_vlan = routed_vlan + 1
        cmd = \
        '''
        no interface Vlan{routed_vlan}
        interface Vlan{routed_vlan}
        no shutdown
        mtu 9216
        vrf member vxlan-{routed_vni}
        no ip redirects
        no ipv6 redirects     
        '''
        print("cmd iss-----",cmd.format(routed_vni=routed_vni,routed_vlan=routed_vlan))
        try:
            uut.configure(cmd.format(routed_vni=routed_vni,routed_vlan=routed_vlan))
        except:
            log.error('SVI configure failed for uut',uut,'vlan/vni',routed_vlan,routed_vni)
 
 
 
 
 
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
            mtu 9216
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
    v6 = ip_address(ipv6_add)
    c2 = int(vlan_scale/routed_vni_scale)  
    for j in range(0,routed_vni_scale):  # 5
        routed_vni = routed_vni + 1
        for i in range(0,c2):
            vlan = vlan + 1
            v4 = v4 + 65536
            v6 = v6 + 65536
            v4add = v4 + 1
            v6add = v6 + 1            
            cmd = \
                '''
                no interface Vlan{vlan}
                interface Vlan{vlan}
                no shutdown
                mtu 9216
                vrf member vxlan-{routed_vni}
                no ip redirects
                ip address {v4add}/16
                ipv6 address {v6add}/64
                no ipv6 redirects
                fabric forwarding mode anycast-gateway
                '''
            print(cmd.format(vlan=vlan,routed_vni=routed_vni,v4add=v4add,v6add=v6add))
            try:
                uut.configure(cmd.format(vlan=vlan,routed_vni=routed_vni,v4add=v4add,v6add=v6add))
            except:
                log.error('SVI configure failed for vlan %r routed vni %r',vlan,routed_vni)  







def routed_nve_configure(uut,routed_vni,count):
    for i in range(0,count):
        routed_vni = routed_vni + 1
        cmd = \
            '''
            interface nve1
            member vni {routed_vni} associate-vrf
            '''
        print(cmd.format(routed_vni=routed_vni))
        try:
            uut.configure(cmd.format(routed_vni=routed_vni))
        except:
            log.error('routed_vni_configure failed for uut',uut,'vlan/vni',routed_vni)



def find_svi_ip(uut,svi):
    cmd = uut.execute("show int vlan {vlan} | json-pretty".format(vlan=svi))
    if not "svi_ip_addr" in str(cmd):
        log.info('svi_ip_addr found,Test failed')
        return 0
                
    else: 
        test1=json.loads(cmd)   
        ip = test1["TABLE_interface"]["ROW_interface"]["svi_ip_addr"]
        return ip 


def nve_configure_bgp(uut,vni,count):
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
        log.error('vni_configure failed for uut %r',uut)
    c1 = int(count/2)       
    for vni in range(int(vni),int(vni)+c1):
        cmd = \
            '''
            interface nve1
            member vni {vni}
            suppress-arp
            ingress-replication protocol bgp
            '''
        try:
            uut.configure(cmd.format(vni=vni))
        except:
            log.error('routed_vni_configure failed for uut %r vni %r',uut,vni)
            

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
    vni = vni + c1
    c2 = int(c1/5)
    mcast = ip_address(mcast_group) 
    for j in range(0,5): 
        mcast = mcast+1
        for i in range(0,c2):
            vni = vni + 1
            cmd = \
            '''
            interface nve1
            member vni {vni}
            suppress-arp
            mcast-group {mcast}
            '''
            try:
                uut.configure(cmd.format(vni=vni,mcast=mcast))
            except:
                log.error('routed_vni_configure failed for mcast/vni %r uut %r',mcast,vni)
            

def evpn_vni_configure(uut,vni,count):
    for i in range(0,count):
        vni = vni + 1
        cmd = \
            '''
            evpn 
            vni {vni} l2
            rd auto
            route-target import auto
            route-target export auto
            '''
        try:
            uut.configure(cmd.format(vni=vni))
        except:
            log.error('vni/vlan configure failed for uut %r vni %r',uut,vni)
            

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

def leaf_protocol_check(uut,protocol_list):
    for proto in protocol_list:
        #result = 1
        if 'ospf' in proto:
            cmd = uut.execute("show ip ospf neighbors | json-pretty")
            if not "addr" in str(cmd):
                log.info('No OSPF neighbor found,Test failed for uut/neighbor')
                return 0
            else: 
                test1=json.loads(cmd)   
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
            if not "nbr-add" in str(cmd):
                log.info('No PIM neighbor found,Test failed for uut/neighbor')
                return 0

            else:       
                test1=json.loads(cmd)
                neig_list= test1["TABLE_vrf"]["ROW_vrf"]["TABLE_neighbor"]["ROW_neighbor"]
                neig_count =  str(neig_list).count('nbr-addr')
                if neig_count == 1:
                    uptime = (neig_list)['uptime']
                    uptime = uptime.replace(":","")
                    if not int(uptime) > 1:
                        log.info('PIM neighbor check failed for uut/neighbor') 
                        return 0
                    else:
                        return 1

                elif neig_count > 1:
                    for i in range(0,neig_count-1):
                        uptime = (neig_list)[i]['uptime']
                        uptime = uptime.replace(":","")
                        if not int(uptime) > 1:
                            log.info('PIM neighbor check failed for uut/neighbor') 
                            return 0
                        else:
                            return 1    

            log.info('PIM Neighbor check passed for uut --------------')


        elif 'nve-peer' in protocol_list:
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
                neig_list= test1["TABLE_nve_peers"]["ROW_nve_peers"]
                print("111111111")
                neig_count =  str(neig_list).count('peer-ip')
                if neig_count == 1:
                    state = (neig_list)['peer-state']
                    if not 'Up' in state:
                        log.info('NVE Peer check failed for uut/neighbor') 
                    else:
                        return 1
             
                elif neig_count > 1:
                    print("22222222")
                    for i in range(0,neig_count-1):
                        state = (neig_list)[i]['peer-state']
                        if not 'Up' in state:
                            print("33333333")
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

            '''
            else:
                test1=json.loads(cmd)  
                vni_list= test1["TABLE_nve_vni"]["ROW_nve_vni"]
                vni_count =  str(vni_list).count('vni-state')
                if vni_count == 1:
                    state = (vni_list)['vni-state']
                    if not 'Up' in state:
                        log.info('NVE VNI check failed for uut')
                        uut.execute("show nve vni") 
                        return 0
                    else:
                        return 1
                elif vni_count > 1:
                    #for i in range(0,vni_count-1):
                    #    state = (vni_list)[i]['vni-state']
                    if 'own' in str(cmd):
                        log.info('NVE VNI check failed for uut') 
                        uut.execute("show nve vni") 
                        return 0
                    else:
                        return 1

            log.info('NVE VNI check passed for uut --------------')
            '''


    log.info('Protocol check passed for uut -------------- :')
   
     
 


def vrf_bgp_configure(uut,as_number,routed_vni,count):
    print("Count issss",count)
    for i in range(0,count):
        routed_vni = routed_vni + 1
        print(routed_vni)
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
        print(cmd.format(routed_vni=routed_vni,as_number=as_number))
        try:
            uut.configure(cmd.format(routed_vni=routed_vni,as_number=as_number))
        except:
            log.error('vni/vlan configure failed for uut %r vni %r',uut,routed_vni) 
                         
 
                           
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
        vlan_vni_configure(self.node,self.routed_vlan,self.routed_vni,self.routed_vni_scale)  
        vlan_vni_configure(self.node,self.vlan,self.vni,self.vlan_scale) 
        routed_svi_configure(self.node,self.routed_vlan,self.routed_vni,self.routed_vni_scale)
        #svi_configure(self.node,self.vlan,self.vlan_scale,self.count2,self.routed_vni,self.ipv4_add,self.ipv6_add)
        svi_configure(self.node,self.vlan,self.vlan_scale,self.ipv4_add,self.ipv6_add,self.routed_vni,self.routed_vni_scale)
        nve_configure_bgp(self.node,self.vni,self.vlan_scale)
        nve_configure_mcast(self.node,self.vni,self.vlan_scale,self.mcast_group)
        routed_nve_configure(self.node,self.routed_vni,self.routed_vni_scale)
        evpn_vni_configure(self.node,self.vni,self.vlan_scale)
        vrf_bgp_configure(self.node,self.as_number,self.routed_vni,self.routed_vni_scale)

 
  


def DevicePreCleanUut(uut):
    try:
        uut.configure('no feature interface-vlan')
        uut.configure('feature interface-vlan')
        log.info(banner("Staring Pre clean "))
        uut.configure('no interface nve1')
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
                    log.info("Default Interface configure failed in device %r interface %r",uut,intf)
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
                        log.error('vrf_id delete failed in uut %r vrf id is %r',uut,vrf_id)


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
                                log.error('static route delete failed in uut %r',uut)
                         
        op = uut.execute("show run | incl community-list")
        op1 = op.splitlines()
        for line in op1:
            if line:
                cfg = "no {line}"
                try:
                    uut.configure(cfg.format(line=line))  
                except:
                    log.error('community-list delete failed in uut %r',uut)

        op = uut.execute("show run | incl 'interface port-channel'")
        op1 = op.splitlines()
        for line in op1:
            if line:
                cfg = "no {line}"
                try:
                    uut.configure(cfg.format(line=line))  
                except:
                    log.error('port-channel delete failed in uut %r',uut)


        op = uut.execute("show run | incl route-map")
        op1 = op.splitlines()
        for line in op1:
            if line:
                if 'permit' in line:
                    cfg = "no {line}"
                    try:
                        uut.configure(cfg.format(line=line))  
                    except:
                        log.error('route-map delete failed in uut %r',uut)


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
                    log.info("Default Interface configure failed in device %r interface  %r",uut,intf)
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
        lab_svr_sess = sth.labserver_connect(server_ip =labserver_ip,create_new_session = 1, session_name = "Stc88",user_name = "danthoma")
        intStatus = sth.connect(device=tgn_ip, port_list = port_list,break_locks = 1, offline = 0 )
        #(' intStatus', {'status': '1', 'offline': '0', 'port_handle': {'10.127.62.251': {'1/7': 'port1', '1/4': 'port2'}}})
        #print("intStatus",intStatus)
        status=intStatus['status']
        if (status == '1') :
            spirent_port_handle=intStatus['port_handle'][tgn_ip]
            print("port_handle is",spirent_port_handle)
            return spirent_port_handle
        else :
            log.info('\nFailed to retrieve port handle!\n')
            return (0, tgn_port_dict)
    except:

        log.error('Spirect connection failed')
        log.error(sys.exc_info())
 


def SpirentTunnelStreamConf(port_handle,source_mac,protocol,rate_pps):
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
        streamblock_ret1 = sth.traffic_config (
            mode ='create',\
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
            log.info('run sth.traffic_config failed for V4 %r', streamblock_ret1)
            
    except:
        log.error('tunnel stream block config failed')
        log.error(sys.exc_info())
 


def CreateSpirentStreams(port_hdl,ip_src,ip_dst,mac_src,mac_dst,stream_id,rate_pps,mac_count,mac_mode,mac_step,vlan_id):
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


def XconnectTrafficTest2(port_handle_list):
    log.info("Starting XconnTrafficTest, port_handle_list is %r",port_handle_list)
    traffic_ctrl_ret = sth.traffic_control(port_handle = port_handle_list, action = 'run',traffic_start_mode = 'sync',  duration = '30')
    countdown(10)
    traffic_ctrl_ret = sth.traffic_control (port_handle = port_handle_list, action = 'stop', db_file=0 ) 
    traffic_ctrl_ret = sth.traffic_control(port_handle = 'all', action = 'clear_stats')
    log.info("Started and stopped Xconnect Traffic")  

    for port_hdl in port_handle_list:
        log.info("Clearing the stats in port %r",port_hdl)
        sth.traffic_control(port_handle = port_hdl, action = 'clear_stats')

    log.info("Starting traffic again")
    traffic_ctrl_ret = sth.traffic_control(port_handle = port_handle_list, action = 'run',traffic_start_mode = 'sync',  duration = '10')
    countdown(20)
    traffic_ctrl_ret = sth.traffic_control(port_handle = port_handle_list, action = 'stop', db_file=0 ) 

    for port_hdl in port_handle_list:
        res1 = sth.traffic_stats(port_handle = port_hdl, mode = 'streams')
        log.info('-------------------------------------')
        log.info('|       Spirent Port is %r        |',port_hdl)
        log.info('-------------------------------------')
            
        stream_list =  list(res1[port_hdl]['stream'].keys())

        for stream_id in stream_list:    
            rx_count = res1[port_hdl]['stream'][stream_id]['rx']['rx_sig_count'] 
            tx_count = res1[port_hdl]['stream'][stream_id]['tx']['total_pkts']
            log.info('+-----------------------------------------------------------------------+')
            log.info('rx_count is %r,tx_count is %r,stream_id %r',rx_count,tx_count,stream_id)
            log.info('+-----------------------------------------------------------------------+')
            if abs(int(rx_count))  < 4000:
                log.info('Traffic Test failed - Low packet RX count ')
                return 0

            if abs(int(rx_count) - int(tx_count)) > 1000:
                log.info('Traffic Test failed - Diff is high')
                print('Streamblock is',res1[port_hdl]['stream'][stream_id])
                return 0


    return 1 



def XconnectTrafficTest(orph_port_handle_list,vpc_port_handle_list):
    port_handle_list = orph_port_handle_list + vpc_port_handle_list
    log.info("Starting XconnTrafficTest, orph_port_handle_list is %r",orph_port_handle_list)
 
    traffic_ctrl_ret = sth.traffic_control(port_handle = port_handle_list, action = 'run',traffic_start_mode = 'sync',  duration = '30')
    countdown(10)
    traffic_ctrl_ret = sth.traffic_control (port_handle = port_handle_list, action = 'stop', db_file=0 ) 
    traffic_ctrl_ret = sth.traffic_control(port_handle = 'all', action = 'clear_stats')
    log.info("Started and stopped Xconnect Traffic")  

    for port_hdl in port_handle_list:
        log.info("Clearing the stats in port %r",port_hdl)
        sth.traffic_control(port_handle = port_hdl, action = 'clear_stats')

    log.info("Starting traffic again")
    traffic_ctrl_ret = sth.traffic_control(port_handle = port_handle_list, action = 'run',traffic_start_mode = 'sync',  duration = '10')
    countdown(20)
    traffic_ctrl_ret = sth.traffic_control(port_handle = port_handle_list, action = 'stop', db_file=0 ) 

    for port_hdl in orph_port_handle_list:
        res1 = sth.traffic_stats(port_handle = port_hdl, mode = 'streams')
        log.info('-------------------------------------')
        log.info('|       Spirent Port is %r        |',port_hdl)
        log.info('-------------------------------------')            
        stream_list =  list(res1[port_hdl]['stream'].keys())
        for stream_id in stream_list:    
            rx_count = res1[port_hdl]['stream'][stream_id]['rx']['rx_sig_count'] 
            tx_count = res1[port_hdl]['stream'][stream_id]['tx']['total_pkts']
            log.info('+-----------------------------------------------------------------------+')
            log.info('rx_count is %r,tx_count is %r,stream_id %r',rx_count,tx_count,stream_id)
            log.info('+-----------------------------------------------------------------------+')
            if abs(int(rx_count))  < 4000:
                log.info('Traffic Test failed - Low packet RX count ')
                return 0
            if abs(int(rx_count) - int(tx_count)) > 1000:
                log.info('Traffic Test failed - Diff is high')
                print('Streamblock is',res1[port_hdl]['stream'][stream_id])
                return 0


    return 1 


def TriggerPortVlanRemoveAdd(uut,port,vlan,count):
    for i in range(1,count):
        cfg = \
        """
        interface {port}
        no switchport access vlan {vlan}
        no switchport mode dot1q-tunnel
        """
        log.info("cfg isssss %r",cfg.format(vlan=vlan,port=port))
        try:
            uut.configure(cfg.format(vlan=vlan,port=port)) 
        except:
            log.error(("Xconnect Orphan Port vlan remov add Failed for port %r uut is %r",port,uut)) 
            return 0
        cfg = \
        """
        interface {port}
        switchport access vlan {vlan}
        switchport mode dot1q-tunnel
        """
        log.info("cfg isssss %r",cfg.format(vlan=vlan,port=port))
        try:
            uut.configure(cfg.format(vlan=vlan,port=port)) 
        except:
            log.error(("Xconnect Orphan Port vlan remov add Failed for port %r uut is %r",port,uut)) 
            return 0
    return 1        



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

def XconnRemoveAdd(uut,vlan,count):
    log.info("Starting XconnRemoveAdd @ uut %r for vlan %r ",uut,vlan)

    cfg1 = \
    '''
    vlan {vlan}
    no xconnect
    exit
    '''

    cfg2 = \
    '''
    vlan {vlan}
    xconnect
    exit
    '''
    #try:
    for i  in range(1,count):
        try:
            uut.configure(cfg1.format(vlan=vlan)) 
        except:
            log.info(" Vlan Xconnect remove  Failed uut %r vlan %r",uut,vlan)
            return 0

        time.sleep(1)
            #log.info("config is %r",cfg.format(vlan=vlan))
        try:
            uut.configure(cfg2.format(vlan=vlan))                                 
        except:
            log.info(" vlan Xconnect add Failed uut %r vlan %r",uut,vlan)
            return 0
    #    else:    
    return 1        


def XconnPortCheck(vpc_uut_list):
    for uut in vpc_uut_list:
        tunn_intf_list = []    
        for intf in uut.interfaces.keys():
            if 'tgn' in intf:
                intf=uut.interfaces[intf].intf                        
                tunn_intf_list.append(intf)

        for intf in tunn_intf_list:
            log.info("Starting XconnPortCheck @ uut %r for intf %r ",uut,intf)
            op =uut.execute('show interface {intf} | json-pretty'.format(intf=intf))
            op1=json.loads(op)   
            if 'down' in op1["TABLE_interface"]["ROW_interface"]["state"]:
                log.info("Interface %r is down in uut %r",intf,uut)
                return 0
    return 1
                

def XconnPortInit(vpc_uut_list):

    shut = \
        """
        interface {intf}
        shut 
        """                 

    no_shut = \
        """
        interface {intf}
        no shut 
        """      
    for uut in vpc_uut_list:
        tunn_intf_list = []
        op = uut.execute("sh port-channel summary | incl NONE")
        for line in op.splitlines():
            if line:
                if 'Po' in line:
                    po = line.split()[1].split('(')[0]
                    tunn_intf_list.append(po)

        for intf in uut.interfaces.keys():
            if 'tgn' in intf:
                intf=uut.interfaces[intf].intf                        
                tunn_intf_list.append(intf)

        for intf in tunn_intf_list:
            try:
                uut.configure(shut.format(intf=intf))
            except:
                log.info("Port %r flap failed at %r",intf,uut)
                return 0

    countdown(2)

    for uut in vpc_uut_list:
        tunn_intf_list = []
        op = uut.execute("sh port-channel summary | incl NONE")
        for line in op.splitlines():
            if line:
                if 'Po' in line:
                    po = line.split()[1].split('(')[0]
                    tunn_intf_list.append(po)

        for intf in uut.interfaces.keys():
            if 'tgn' in intf:
                intf=uut.interfaces[intf].intf                        
                tunn_intf_list.append(intf)

        for intf in tunn_intf_list:
            try:
                uut.configure(no_shut.format(intf=intf))
            except:
                log.info("Port %r flap failed at %r",intf,uut)
                return 0


    return 1
        
 


def XconnectTCountersTest(uut,port_handle_list,vni,port):
 
    #traffic_ctrl_ret = sth.traffic_control(port_handle = port_handle_list, action = 'run',traffic_start_mode = 'sync',  duration = '30')
    #traffic_ctrl_ret = sth.traffic_control (port_handle = port_handle_list, action = 'stop', db_file=0 ) 
    #traffic_ctrl_ret = sth.traffic_control(port_handle = 'all', action = 'clear_stats')
    #log.info("Started and stopped CDP Traffic")  

    for port_hdl in port_handle_list:
        log.info("Clearing the stats in port %r",port_hdl)
        sth.traffic_control(port_handle = port_hdl, action = 'clear_stats')

    log.info("++++++++++++++++++++++++++++++++++++++")

    log.info("UUT %r Port %r vni %r",uut,port,vni)

    log.info("++++++++++++++++++++++++++++++++++++++")

    uut.execute("clear counters") 
    uut.execute("clear nve vni all counters") 
    uut.execute("clear counters interface nve 1")

    log.info("Starting traffic for 10 seconds")
    traffic_ctrl_ret = sth.traffic_control(port_handle = port_handle_list, action = 'run',traffic_start_mode = 'sync',  duration = '10')
    countdown(10)
    traffic_ctrl_ret = sth.traffic_control(port_handle = port_handle_list, action = 'stop', db_file=0 ) 

    for port_hdl in port_handle_list:
        res1 = sth.traffic_stats(port_handle = port_hdl, mode = 'streams')
        log.info('---------------------------------')
        log.info('|      Spirent port is %r       |',port_hdl)
        log.info('---------------------------------')
            
        stream_list =  list(res1[port_hdl]['stream'].keys())

        for stream_id in stream_list:    
            rx_count = res1[port_hdl]['stream'][stream_id]['rx']['rx_sig_count'] 
            tx_count = res1[port_hdl]['stream'][stream_id]['tx']['total_pkts']

            cmd = uut.execute("show nve vni {vni} counters | json-pretty".format(vni=vni))
            op1=json.loads(cmd)   
            rx_mcastpkts = op1["rx_mcastpkts"]
            tx_mcastpkts = op1["tx_mcastpkts"]
            rx_ucastpkts = op1["rx_ucastpkts"]
            tx_ucastpkts = op1["tx_ucastpkts"]

            cmd = uut.execute("show interface {port} counters detailed | json-pretty".format(port=port))
            op1=json.loads(cmd)   
            if "eth_inpkts" in op1: 
                eth_inpkts=op1["TABLE_interface"]["ROW_interface"]["eth_inpkts"]
                log.info("eth_inpkts ----------------------------------->%r",eth_inpkts)
            elif "eth_inmcast" in op1: 
                eth_inmcast=op1["TABLE_interface"]["ROW_interface"]["eth_inmcast"]
                log.info("eth_inmcast ---------------------------------->%r",eth_inmcast)
            elif "eth_outpkts" in op1:                 
                eth_outpkts=op1["TABLE_interface"]["ROW_interface"]["eth_outpkts"]
                log.info("eth_outpkts ---------------------------------->%r",eth_outpkts)
            elif "eth_inmcast" in op1:             
                eth_outmcast=op1["TABLE_interface"]["ROW_interface"]["eth_outmcast"]
                log.info("eth_outmcast---------------------------------->%r",eth_outmcast)


            cmd = uut.execute("show interface nve 1 counters | json-pretty")
            op1=json.loads(cmd)   
    
            op2= op1["TABLE_nve_counters"]["ROW_nve_counters"]
            for i in range(0,len(op2)):
                if 'ucast_outpkts' in op2[i]:
                    ucast_outpkts = op2[i]["ucast_outpkts"]
                elif 'mcast_inpkts' in op2[i]:
                    mcast_inpkts = op2[i]["mcast_inpkts"]
                elif 'ucast_inpkts' in op2[i]:
                    ucast_inpkts = op2[i]["ucast_inpkts"]

            log.info("+++++++++++++Spirent Stream Counters+++++++++++++++++++++++++")
            log.info("rx_count ----------------------->%r",rx_count)
            log.info("rx_count ----------------------->%r",rx_count)
            
            #log.info("+++++++++++++Ethernet Interface Counters+++++++++++++++++++++++++")
            #if eth_inpkts:
            #    log.info("eth_inpkts ----------------------------------->%r",eth_inpkts)
            #if eth_inmcast:    
            #    log.info("eth_inmcast ---------------------------------->%r",eth_inmcast)
            #if eth_outpkts:   
            #    log.info("eth_outpkts ---------------------------------->%r",eth_outpkts)
            #if eth_outmcast:    
            #    log.info("eth_outmcast---------------------------------->%r",eth_outmcast)
            
            log.info("+++++++++++++nve vni counters+++++++++++++++++++++++++")
            if rx_mcastpkts:
                log.info("rx_mcastpkts------------------>%r",rx_mcastpkts)
            if tx_mcastpkts:
                log.info("tx_mcastpkts------------------>%r",tx_mcastpkts)
            if rx_ucastpkts:    
                log.info("rx_ucastpkts------------------>%r",rx_ucastpkts)
            if tx_ucastpkts:
                log.info("tx_ucastpkts------------------>%r",tx_ucastpkts)

            log.info("+++++++++++interface nve 1 counters+++++++++++++++++++++++")
            if ucast_outpkts:
                log.info("ucast_outpkts------------------>%r",ucast_outpkts)
            if mcast_inpkts:    
                log.info("mcast_inpkts------------------>%r",mcast_inpkts)
            if mcast_inpkts:    
                log.info("ucast_inpkts------------------>%r",ucast_inpkts)

            log.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

            #log.info('+-----------------------------------------------------------------------+')
            #log.info('rx_count is %r,tx_count is %r,stream_id %r',rx_count,tx_count,stream_id)
            #log.info('+-----------------------------------------------------------------------+')
            #if abs(int(rx_count) - int(tx_count)) > 100:
            #    log.info('Traffic Test failed')
            #    log.info('Streamblock is %r',res1[port_hdl]['stream'][stream_id])
            #    return 0
            #else:
            #    return 1 


def ProcessRestart(uut,mgmt_ip,proc):
    """ function to configure vpc """
    log.info(banner("Entering proc to restart the processes"))
    try:
        config_str = '''sh system internal sysmgr service name {proc} | grep PID'''
        out=uut.execute(config_str.format(proc=proc))
        pid  = out.split()[5].strip(',')
        log.info("pid is ----------------%r",pid)
        log.info("mgmt_ip is -------%r",mgmt_ip)
        log.info(banner("Connecting to UUT"))
        uut1 = spawn('telnet {ip}'.format(ip=mgmt_ip))
        uut1.logfile = sys.stdout.buffer
        uut1.expect("login:")
        uut1.sendline("admin")
        uut1.expect("Password:")
        uut1.sendline("nbv12345") 
        uut1.sendline('run bash \r')
        uut1.expect('bash-4.3$')
        uut1.sendline('sudo su \r')
        uut1.expect('bash-4.3$')
        uut1.sendline('kill %s\r' %pid)
        uut1.expect('bash-4.3$')
        uut1.sendline('exit \r')
        uut1.expect('bash-4.3$')
        uut1.sendline('exit \r')
        uut1.expect('#')

    except:
        log.info('proc restart test failed for PID %r uut %r ',proc,uut)
 

def ProcessRestart2(uut,proc):
    """ function to configure vpc """
    logger.info(banner("Entering proc to restart the processes"))
    try:
        config_str = '''sh system internal sysmgr service name {proc} | grep PID'''
        out=uut.execute(config_str.format(proc=proc))
        pid  = out.split()[5].strip(',')
        uut.transmit('run bash \r')
        uut.receive('bash-4.3$')
        uut.transmit('sudo su \r')
        uut.receive('bash-4.3$')
        uut.transmit('kill %s\r' %pid)
        uut.receive('bash-4.3$')
        uut.transmit('exit \r')
        uut.receive('bash-4.3$')
        uut.transmit('exit \r')
        uut.receive('#')

    except:
        log.error('proc restart test failed for %r',proc)
        log.error(sys.exc_info())



     
class LeafObjectL2(object):
    def __init__(self,node,vlan,vni,vlan_scale,mcast_group,as_number):
        self.node=node
        self.vlan=vlan
        self.vni=vni
        self.vlan_scale=vlan_scale
        self.mcast_group=mcast_group
        self.as_number=as_number

                                    
    def vxlan_conf(self):
        vlan_vni_configure(self.node,self.vlan,self.vni,self.vlan_scale) 
        nve_configure_bgp(self.node,self.vni,self.vlan_scale)
        nve_configure_mcast(self.node,self.vni,self.vlan_scale,self.mcast_group)
        evpn_vni_configure(self.node,self.vni,self.vlan_scale)
        #vrf_bgp_configure(self.node,self.as_number,self.routed_vni,self.routed_vni_scale)






def DevicePreCleanupXconnect(uut):
    log.info(banner("Deleteing adding vxlan features"))
    feature_clean=\
    """
    no feature ngoam
    no feature nv over
    no feature bgp
    no feature ospf
    no feature pim
    no feature interface-vlan
    no vlan 2-600
    no feature lacp
    line con
    exec-timeout 0
    line vty
    exec-timeout 0
    feature nv over
    feature lacp
    feature bgp
    feature ospf
    feature pim
    feature interface-vlan  
    nv overlay evpn
    feature vn-segment-vlan-based
    """ 
    uut.configure(feature_clean) 


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






 




 
