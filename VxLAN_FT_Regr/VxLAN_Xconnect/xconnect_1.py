#!/usr/bin/python
# -*- coding: utf-8 -*-

###################################################################
# connection_example.py : A test script example which includes:
#     common_seup section - device connection, configuration
#     Tescase section with testcase setup and teardown (cleanup)
#     subtestcase section with subtestcase setup and teardown (cleanup)
#     common_cleanup section - device cleanup
# The purpose of this sample test script is to show how to connect the
# devices/UUT in the common setup section. How to run few simple testcases
# (testcase might contain subtests).And finally, recover the test units in
# the common cleanup section. Script also provides an example on how to invoke
# TCL interpreter to call existing TCL functionalities.
###################################################################

#* Author: Danish Thomas
#* Feature Info : https://wiki.cisco.com/pages/viewpage.action?pageId=120270136
#*
#*   This feature is used to enable Vxlan P2P functionality on Trident based N9K & N3K(N9K mode only) TORs 
#*   This will enable tunnelling of all control frames (CDP, LLDP, LACP, STP, etc) across Vxlan cloud.
#*
#*
#*
#*
#* ------------- V X L A N    X C O N N E C T    T O P O L O G Y------------
#*
#*  
#*
#*                           +-------+ 
#*                           | spine | 
#*                           |       |
#*                           +---+---+
#*        +--------------+-------+------+-------------+---------------+
#*        |              |              |             |               |
#*    +-------+      +-------+      +---+---+     +---+---+       +---+---+
#*    |       |      |       |      |       |     |       |       |       | 
#*    | leaf1 |<---->| leaf2 |      | leaf3 |<--->| leaf4 |       |saVTEP | 
#*    |       |      |       |      |       |     |       |       | 95xx  | 
#*    +---+---+      +---+---+      +----+--+     +----+--+       +---+---+
#*      |      \ vpc /               |      \ vpc /                   |
#tunn acc port  \   /    tunn acc port       \   /                    |
#*        +------+-------+            +-------+--------+          Spirent Port
#*        |   switch     |            |      switch    |
#*        +------+-------+            +--------+-------+      
#*               |                             | 
#*               |                             |
#*            Spirent Port                  Spirent Port
#*
#*      * There are 8 tunnel ports  each in leaf 2 and leaf 4(but script can scale automatically)
#*      * Please follow the naming/alias of the interfaces in testbed file
#*
#*
#*
#*************************************************************************
#*  --------------- NEW CLIs:---------------    
#*      hardware access-list tcam region vxlan-p2p <tcam-size)          
#*      This is used to carve-out tcam space for Vxlan-P2P. Its advised to carve out minimum 256 size. This will require a reload of the box.           
#*      Each vlan where xconnect is enabled with need two FP entries to be programmed into this TCAM region. One for traffic from Access-to-Network direction and other for Network-to-Access direction.            
#*      e.g.            
#*           hardware access-list tcam region vxlan-p2p 256         
#*      xconnect            
#*      This is configured in vlan to enable xconnect in the corresponding vlan.            
#*      e.g.            
#*           vlan 1503          
#*           vn-segment 300103          
#*           xconnect           
#*                  
#*  --------------- Configuration:---------------   
#*      Global Config for TCAM Carving:         
#*          hardware access-list tcam region vxlan-p2p 256          
#*                  
#*      Vlan Config to enable xconnect (Vxlan P2P)          
#*                  
#*          vlan 1501           
#*              vn-segment 300100           
#*              xconnect            
#*                  
#*  --------------- Access Port Config:     --------------- 
#*                  
#*          interface Ethernet1/10          
#*              switchport mode dot1q-tunnel            
#*              switchport access vlan 1501         
#*                  
#*  --------------- SCLAE support:          ---------------
#*      Max no. of Vlan where xconnect is supported: 127    
#*          
#*  --------------- Platforms supported:            ---------------
#*      N9K TORs (T2 based) where Vxlan is supported            
#*      N3K TORs (T2 & T2P based). In N9K mode only 
#*          
#*  --------------- Restrictions:           ---------------
#*      This feature is supported only for Vxlan BGP EVPN model.            
#*      LACP bundling of Access Port will not be supported as none of the tunnel_vlan_startol packets for the Vlan will be punted to CPU.           
#*      Only 1 Access port can be per VNI on a given VTEP.          
#*      A VNI can only be stretched in a point-to-point fashion. Point-to-multipoint is undefined behavior, and is not supported.           
#*************************************************************************


import sys
import os
import pdb
import time
import json
import threading
from ats import aetest
#from ats.log.utils import banner
#from ats import tcl
#import sth
#from sth import StcPython

from ats import topology
#from dtcli import *
#from vxlan_macmove_lib import *
from vxlan_xconnect_lib import *
#from vxlan_lib import *
from vxlan_all_lib_no_sth import *
from ipaddress import *
from random import *
from string import *
import requests
from pexpect import *
from pyats.async_ import pcall
import re
import logging
import general_lib
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
from ixia_vxlan_lib import *

#tcl.q.package('require', 'router_show')

#from upgrade_lib import *

from unicon.utils import Utils
#from rest_util import RestAction
#from routing_util import compare_string

# define variables scale numbers  feature list etc here

leaf4 = leaf5 = leaf3 = leaf4 = sw3 = sw2 = spine1 = port_handle1 = tgn1 =  0

 
## Scale number should be an even number

 
vlan_vni_scale = 10
routing_vlan_scale = 1
vlan = 500
mac_scale = 200

vpc_vlan_start = 500
vlan_end=vlan+vlan_vni_scale
#vlan_range=str(vlan_start)+"-"+str(vlan_end)
traffic_to_be_tested_on_number_of_vlans= 5

tunnel_vlan_scale = 4
tunnel_vlan_start =  vpc_vlan_start


nonxc_vlan_start = tunnel_vlan_start+tunnel_vlan_scale+1
nonxc_scale = 5
nonxc_pps=10000
nonxc_rate=str(int(nonxc_scale)*nonxc_pps) 
nonxc_tol=int(float(nonxc_rate)*0.015)

 
vpc_vlan_range=str(tunnel_vlan_start+tunnel_vlan_scale+1)+"-"+str(vlan+vlan_vni_scale)

vxlan_traffic_test_vlan1=tunnel_vlan_start+tunnel_vlan_scale+2
vxlan_traffic_test_vlan2=vxlan_traffic_test_vlan1+1

log.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
log.info("vlan_vni_scale -------------------->%r",vlan_vni_scale)
log.info("routing_vlan_scale ---------------->%r",routing_vlan_scale)
log.info("vlan ------------------------------>%r",vlan)
log.info("mac_scale ------------------------->%r",mac_scale)
log.info("vpc_vlan_start -------------------->%r",vpc_vlan_start)
log.info("vlan_end--------------------------->%r",vlan_end)
log.info("tunnel_vlan_scale------------------>%r",tunnel_vlan_scale)
log.info("tunnel_vlan_start------------------>%r",tunnel_vlan_start)
log.info("vpc_vlan_range--------------------->%r",vpc_vlan_range)
log.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

#countdownHours(5) 

sw_feature_list = ['vrrp','private-vlan','port-security','interface-vlan','hsrp','lacp','lldp']
l3_feature_list = ['nv overlay','vn-segment-vlan-based','ospf','bgp','vtp','interface-vlan','bfd','pim','lacp']
anycastgw = "0000.2222.3333"
stp_mode = "mst"

issu_image = 'nxos.9.3.5.48.bin.upg'
test_issu = 'yes'
config_replece_test = 'yes'


vxlan_xconn_config =  'vxlan_xconn_config'

#countdownHours(4)
#vxlan_evpn_config =  'vxlan_evpn_config' 
###################################################################
###                  COMMON SETUP SECTION                       ###
###################################################################

# Configure and setup all devices and test equipment in this section.
# This should represent the BASE CONFIGURATION that is applicable
# for the bunch of test cases that would follow.

class common_setup(aetest.CommonSetup):

    """ Common Setup for Sample Test """
 
    @aetest.subsection
    def testbed_init(self, testscript, testbed):
    #def connect(self, testscript, testbed):
        """ common setup subsection: connecting devices """

        global vxlan_xconn_config,config_replece_test,issu_image,issu_image,tgen, tgen_port_handle_list, leaf5, leaf6, leaf3, leaf4, sw3, sw1, spine1,spine2, port_handle1, port_handle2,mac_scale2,tgn1_spine1_intf1,port_handle_spine1,\
        leaf3_spine1_intf1,leaf4_spine1_intf1,vlan_vni_scale,routing_vlan_scale,vlan_range,spine1_tgn1_intf1,uutList,vpc_vlan_range,\
        uut_list,vpc_uut_list,spine_uut_list,leaf_uut_list,l3_uut_list,vpc_uut_list,sw_uut_list,tgn1_sw1_intf1,tgn1_sw3_intf1,nonxc_vlan_start,nonxc_scale,nonxc_pps,nonxc_rate,nonxc_tol,\
        port_handle_sw1,port_handle_sw3,leaf_scale,leaf_emulation_spirent,leaf_tgn_ip,sw_feature_list,traffic_to_be_tested_on_number_of_vlans,\
        tunnel_vlan_start,tunnel_vlan_scale,tgn1_intf_list,tgn1_leaf3_intf1,tgn1_leaf5_intf1,port_handle_leaf3_1,port_handle_leaf5_1,xcon_port_handle_list,\
        labserver_ip,tgn_ip,port_handle_leaf4_1,port_handle_leaf6_1,port_handle_leaf3_2,port_handle_leaf5_2,tgn1_leaf3_intf2,tgn1_leaf5_intf2,tgn1_leaf4_intf1,tgn1_leaf6_intf1,\
        vpc_port_handle_list,xcon_po_port_handle_list,xcon_orphan_port_handle_list,port_handle_list,vxlan_traffic_test_vlan1,vxlan_traffic_test_vlan2
 

        leaf3 = testbed.devices['leaf3']
        leaf4 = testbed.devices['leaf4']
        leaf5 = testbed.devices['leaf5']
        leaf6 = testbed.devices['leaf6']
        sw1 = testbed.devices['sw1']
        sw3 = testbed.devices['sw3']
        spine1 = testbed.devices['spine1']
        tgn = testbed.devices['tgn1']
        uut_list = [leaf3,leaf5,leaf6,sw3,leaf4,sw1,spine1]
        l3_uut_list = [leaf5,leaf6,leaf3,leaf4,spine1] 
        log.info("l3_uut_list isss %r",l3_uut_list)       
        sw_uut_list = [sw1,sw3]
        #esi_uut_list = [leaf3,leaf4]
        vpc_uut_list = [leaf3,leaf4,leaf5,leaf6]
        spine_uut_list = [spine1]
        leaf_uut_list = [leaf3,leaf4,leaf5,leaf6]

        #tgn1_spine1_intf1 = testbed.devices['tgn1'].interfaces['tgn1_spine1_intf1'].intf 

        sw3_tgn1_intf1 = testbed.devices['sw3'].interfaces['sw3_tgn1_intf1'].intf
        sw1_tgn1_intf1 = testbed.devices['sw1'].interfaces['sw1_tgn1_intf1'].intf
        #spine1_tgn1_intf1 = testbed.devices['spine1'].interfaces['spine1_tgn1_intf1'].intf
        #tgn1_spine1_intf1 = testbed.devices['tgn1'].interfaces['tgn1_spine1_intf1'].intf 

        tgn1_sw1_intf1 = testbed.devices['tgn1'].interfaces['tgn1_sw1_intf1'].intf
        tgn1_sw3_intf1 = testbed.devices['tgn1'].interfaces['tgn1_sw3_intf1'].intf 
        tgn1_leaf3_intf1 = testbed.devices['tgn1'].interfaces['tgn1_leaf3_intf1'].intf
        tgn1_leaf5_intf1 = testbed.devices['tgn1'].interfaces['tgn1_leaf5_intf1'].intf

        tgn1_leaf3_intf2 = testbed.devices['tgn1'].interfaces['tgn1_leaf3_intf2'].intf
        tgn1_leaf5_intf2 = testbed.devices['tgn1'].interfaces['tgn1_leaf5_intf2'].intf
        tgn1_leaf4_intf1 = testbed.devices['tgn1'].interfaces['tgn1_leaf4_intf1'].intf
        tgn1_leaf6_intf1 = testbed.devices['tgn1'].interfaces['tgn1_leaf6_intf1'].intf


        labserver_ip = str(testbed.devices['tgn1'].connections['labsvr'].ip)
        tgn_ip = str(testbed.devices['tgn1'].connections['a'].ip)
        
        
        
        tgn1_intf_list = []
        for key in testbed.devices['tgn1'].interfaces.keys():
            intf = testbed.devices['tgn1'].interfaces[key].intf
            tgn1_intf_list.append(intf)

 
  
 
    @aetest.subsection
    def connect(self, testscript, testbed):
        for uut in uut_list : 
            log.info('connect to %s' % uut.alias)
            try:
                uut.connect()
            except:
                log.info(banner('connect failed once ; clearing console'))
                if 'port' in uut.connections['a']:
                    ts = str(uut.connections['a']['ip'])
                    port=str(uut.connections['a']['port'])[-2:]
                    u = Utils()
                    u.clear_line(ts, port, 'lab', 'lab')
                try:
                    uut.connect()
                except:
                    self.failed(goto=['common_cleanup'])
            if not hasattr(uut, 'execute'):
                self.failed(goto=['common_cleanup'])
            if uut.execute != uut.connectionmgr.default.execute:
                self.failed(goto=['common_cleanup'])
 
    '''    
    @aetest.subsection
    def pre_clean(self, testscript, testbed):
        
        log.info(banner("Clean the testbed configuration"))


        #if not pcall(reloaduut,uut=tuple(vpc_uut_list)):
        #    self.failed(goto=['common_cleanup']) 
 

        try: 
            pcall(DeviceVxlanPreCleanupAll,uut=tuple(l3_uut_list))
            pcall(SwVxlanPreCleanup,uut=tuple(sw_uut_list))
        except:
            log.info('precleanup Failed ')
            #self.failed(goto=['common_cleanup'])   
 
        log.info("Testbed pre-clean passed")
    
      
    @aetest.subsection
    def base_configs(self, testscript, testbed):          
        log.info(banner("Base configurations"))
    
        cfg = \
            """
            default interface po 100
            default interface po 101
            no interf po 100
            no interf po 101
            spanning-tree mode mst
            no spanning-tree mst configuration
            feature lacp
            no ip igmp snooping
            no vlan 2-3831
            terminal session-timeout 0
            system no hap-reset 
            """
        for uut in uut_list:
            uut.configure(cfg,timeout=120)

        log.info(banner("NV Overlay configurations"))
        
        cfg = \
            """
            nv overlay evpn
            fabric forwarding anycast-gateway-mac {gw}
            """
        for uut in leaf_uut_list:
            uut.configure(cfg.format(gw=anycastgw),timeout=120)

        for uut in spine_uut_list:
            uut.configure('nv overlay evpn')
 
    
 
        log.info(banner("Configuring loopbacks in VPC switches"))  
        
                    
        for uut in vpc_uut_list:
            for intf in uut.interfaces.keys():
                if 'loopback' in intf:
                    if 'loopback0' in intf:
                        intf=uut.interfaces[intf].intf                        
                        ipv4_add=uut.interfaces[intf].ipv4
                        ipv4_add_sec=uut.interfaces[intf].ipv4_sec
                        try:
                            config_loopback(uut,intf,ipv4_add,ipv4_add_sec)
                        except:
                            log.info('Loopback configuration failed in device : %r',uut) 
                            self.failed(goto=['common_cleanup']) 
 
                    else:
                        intf=uut.interfaces[intf].intf
                        ipv4_add=uut.interfaces[intf].ipv4
                        
                        try:
                            config_loopback(uut,intf,ipv4_add,"Nil")
                        except:
                            log.info('Loopback configuration failed in device : %r',uut) 
                            self.failed(goto=['common_cleanup']) 
 

        log.info(banner("Configuring loopbacks in Spine switches"))
        for uut in spine_uut_list:
            for intf in uut.interfaces.keys():
                if 'loopback' in intf:
                    intf=uut.interfaces[intf].intf
                    ipv4_add=uut.interfaces[intf].ipv4
                    try:
                        config_loopback(uut,intf,ipv4_add,"Nil")
                    except:
                        log.info('Loopback configuration failed in device : %r',uut) 
                        self.failed(goto=['common_cleanup'])

 
    @aetest.subsection
    def l3_po_configs(self, testscript, testbed):         
        log.info("Configuring L3 Port Channels")
        for uut in l3_uut_list:
            po_member_list = []
            for intf in uut.interfaces.keys():
                log.info("11111111111uut,intf is %r,%r",uut,intf)
                if 'Eth' in uut.interfaces[intf].intf:
                    log.info("22222222222uut,intf is %r,%r",uut,intf)
                    if 'Po' in uut.interfaces[intf].alias:
                        po_member_list.append(intf)

                log.info('l3 po mem list for uut %r is %r',str(uut),po_member_list)      
                                  
            for intf in uut.interfaces.keys():
                if 'l3_po' in uut.interfaces[intf].type:
                    Po = uut.interfaces[intf].intf
                    ipv4_add = uut.interfaces[intf].ipv4
                    
                    po_mem_list=[]
                    for intf in po_member_list:
                        member = uut.interfaces[intf].alias
                        if member.strip("Po") == Po:
                            po_mem_list.append(uut.interfaces[intf].intf)                                  
                    log.info('l3 po mem list for po %r uut %r is %r',Po,str(uut),po_mem_list)   
                    uut_l3Po_obj = CLI_PortChannel(uut,Po,'Nil','layer3',po_mem_list,ipv4_add)
                    uut_l3Po_obj.ConfigurePo()
        
                     
        countdown(20)
        
      
        for uut in l3_uut_list:
            op=uut.execute('show port-channel summary | incl Eth')
            op1=op.splitlines()
            for line in op1:
                if line:
                    if not "(P)" in line:
                        log.info('L3 port Channel Bringup Failed on device %r',str(uut)) 
                        uut.execute('show port-channel summary')
                        #self.failed
                        self.failed(goto=['common_cleanup'])

    @aetest.subsection
    def ospf_configs(self, testscript, testbed):  
        log.info("Configuring OSPF and adding interfaces")
        for uut in l3_uut_list:
            intf_list=[]
            for intf in uut.interfaces.keys():
                if 'l3_po' in uut.interfaces[intf].type:
                    intf= 'Port-Channel' + uut.interfaces[intf].intf
                    intf_list.append(intf)

                if 'loopback' in intf:
                    if not 'loopback0' in intf:
                        if 'loopback1' in intf:
                            intf = uut.interfaces[intf].intf
                            ospf_rid=(str(uut.interfaces[intf].ipv4))[:-3]
                            intf_list.append(intf)
                        else:
                            intf = uut.interfaces[intf].intf
                            intf_list.append(intf)

            uut_ospf_obj=OspfV4Router(uut,'1',ospf_rid,intf_list)
            uut_ospf_obj.ospf_conf()
        
        cfg = \
        """
        int po 41
        ip ospf cost 100
        """
        for uut in [leaf4,spine1]:
            uut.configure(cfg)
     
    @aetest.subsection
    def pim_configs(self, testscript, testbed):  
                              
        log.info("Configuring PIM and adding interfaces")
        rp_add = (str(testbed.devices['spine1'].interfaces['loopback2'].ipv4))[:-3]
        log.info("RP Address isssss %r",rp_add)
        try: 
             
            for uut in l3_uut_list:
                intf_list=[]
                for intf in uut.interfaces.keys():
                    if 'l3_po' in uut.interfaces[intf].type:
                        intf= 'Port-Channel' + uut.interfaces[intf].intf
                        intf_list.append(intf)

                    if 'loopback' in intf:
                            intf = uut.interfaces[intf].intf
                            intf_list.append(intf)
                
                uut_pim_obj=PimV4Router(uut,rp_add,intf_list) 
                uut_pim_obj.pim_conf()


        except:
            log.info("PIMv4 configuration failed") 
            #self.failed(goto=['common_cleanup'])

 
        log.info(banner("Configuring PIM Anycast")) 
        #for uut in spine_uut_list:
        ip1 = (str(testbed.devices['spine1'].interfaces['loopback1'].ipv4))[:-3]
        #ip2 = (str(testbed.devices['spine2'].interfaces['loopback1'].ipv4))[:-3]

        cfg = \
            """
            ip pim ssm range 232.0.0.0/8
            ip pim anycast-rp {rp_add} {ip1}
            """

        for uut in spine_uut_list:
            try:
                uut.configure(cfg.format(rp_add=rp_add,ip1=ip1),timeout=120)
            except:
                log.info("PIM ANYCAST configuration failed") 
                #self.failed(goto=['common_cleanup'])
    '''  
    @aetest.subsection
    def igp_verify(self, testscript, testbed):  
                              
        countdown(45) 
          
        log.info(banner("Starting OSPF / PIM verify Section"))       
        for uut in l3_uut_list:
            for feature in ['ospf','pim']:
                test1 = leaf_protocol_check222(uut,[feature])
                if not test1:
                    log.info('Feature %r neigborship on device %r Failed ',feature,str(uut))
                    self.failed(goto=['common_cleanup'])             
        
 
    '''
    @aetest.subsection
    def sw_po_bringup(self, testscript, testbed):
        log.info("Configuring Port Channels in Switch and adding interfaces for vPC/TGN")        
        for uut in sw_uut_list:
            sw_po_member_list = [] 
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'Po' in uut.interfaces[intf].alias:
                        sw_po_member_list.append(intf)
                        
            for intf in uut.interfaces.keys():
                if 'po_to_leaf' in uut.interfaces[intf].type:  
                    Po = uut.interfaces[intf].intf   
                    vlan = vpc_vlan_range
                    mode = uut.interfaces[intf].mode
                    sw_po_members = []
                    for intf in sw_po_member_list:
                        member = uut.interfaces[intf].alias
                        if member.strip("Po") == Po:
                            sw_po_members.append(uut.interfaces[intf].intf) 

                    sw_po_obj = CLI_PortChannel(uut,Po,vlan,mode,sw_po_members,'Nil')                     
                    sw_po_obj.ConfigurePo()
        
        for uut in sw_uut_list:
            for intf in uut.interfaces.keys():
                if 'tgn' in uut.interfaces[intf].alias:
                    intf = uut.interfaces[intf].intf
                    cfg = """\
                        interface {intf}
                        switchport
                        switchport mode trunk
                        switchport trunk allowed vlan {vlan_range}
                        spanning-tree bpdufilter enable
                        spanning-tree port type edge trunk 
                        no shut
                        """
                    #print(cfg.format(intf=intf,vlan_range=vpc_vlan_range))
                    
                    try:    
                        uut.configure(cfg.format(intf=intf,vlan_range=vpc_vlan_range))
                    except:
                        log.info("Switch TGN Port Configuration Failed")
                        self.failed(goto=['common_cleanup'])
 
 
    @aetest.subsection
    def vpc_global_configs(self, testscript, testbed):
        log.info(banner("VPC configurations"))  
          
        for uut in vpc_uut_list:
            mct_member_list = [] 
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'mct' in uut.interfaces[intf].alias:
                        mct_member_list.append(uut.interfaces[intf].intf) 

            for intf in uut.interfaces.keys():
                if 'mct_po' in uut.interfaces[intf].type:
                    mct_po = uut.interfaces[intf].intf
                    peer_ip = uut.interfaces[intf].peer_ip
                    src_ip = uut.interfaces[intf].src_ip                     
                    leaf_vpc_global_obj1 = VPCNodeGlobal(uut,mct_po,peer_ip,mct_member_list,src_ip)         
                    leaf_vpc_global_obj1.vpc_global_conf()
    
    @aetest.subsection
    def vpc_po_bringup(self, testscript, testbed):
        log.info(banner("VPC configurations"))  

        for uut in vpc_uut_list:
            vpc_po_member_list = [] 
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'Po' in uut.interfaces[intf].alias:
                        vpc_po_member_list.append(intf) 
            

            #pdb.set_trace()            
            for intf in uut.interfaces.keys():
                if 'vpc_po' in uut.interfaces[intf].type:
                    Po = uut.interfaces[intf].intf
                    mode = uut.interfaces[intf].mode                   
                    vpc_members = []

                    for intf in vpc_po_member_list:
                        member = uut.interfaces[intf].alias
                        if member.strip("Po") == Po:
                            intf=uut.interfaces[intf].intf
                            vpc_members.append(intf) 
                     
                    leaf_vpc_obj1 = VPCPoConfig(uut,Po,vpc_members,vpc_vlan_range,mode)         
                    leaf_vpc_obj1.vpc_conf()
     
     

   
    @aetest.subsection
    def l3_svi_bringup(self, testscript, testbed):
        log.info(banner("Adding L3 SVI for vTEP's"))

        for uut in vpc_uut_list:   
            for intf in uut.interfaces.keys():               
                if 'svi1' in intf:
                    svi = uut.interfaces[intf].intf
                    ipv4 = uut.interfaces[intf].ipv4
            cfg = \
                    """
                    vlan 10
                    no interface vlan10
                    interface vlan10
                    mtu 9216
                    ip address {ipv4}
                    ip router ospf 1 area 0
                    no shut
                    """
            try:
                uut.configure(cfg.format(ipv4=ipv4))
            except:
                log.info("vTEP L3 SVI for VPC Configuration Failed @ uut %r",uut)
                self.failed(goto=['common_cleanup'])
    '''

    @aetest.subsection
    def vpc_verify(self, testscript, testbed):       
        countdown(100)
       
        for uut in vpc_uut_list:
            op=uut.execute('show port-channel summary | incl Eth')
            op1=op.splitlines()
            for line in op1:
                if line:
                    if not "(P)" in line:
                        log.info('VPC Bringup Failed on device %r',str(uut)) 
                        uut.execute('show port-channel summary')
                        self.failed(goto=['common_cleanup'])
         

 
    '''              
    @aetest.subsection
    def bgp_configurations(self, testscript, testbed):
        log.info(banner("BGP configurations"))

        neight_list_leaf =[]         
        for uut in spine_uut_list:      
            for intf in uut.interfaces.keys():
                if 'loopback1' in intf:
                    intf = uut.interfaces[intf].intf
                    spine_neigh=(str(uut.interfaces[intf].ipv4))[:-3]
                    neight_list_leaf.append(spine_neigh)

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
        
        log.info("neight_list_leaf -----for uut %r",neight_list_leaf) 
        for uut in vpc_uut_list:
            adv_nwk_list =[]
            for intf in uut.interfaces.keys():
                if 'loopback0' in intf:
                    intf = uut.interfaces[intf].intf
                    nwk1 = uut.interfaces[intf].ipv4
                    adv_nwk_list.append(nwk1)
                    nwk2 = uut.interfaces[intf].ipv4_sec
                    adv_nwk_list.append(nwk2)

                elif 'loopback1' in intf:
                    intf = uut.interfaces[intf].intf
                    upd_src = intf
                    bgp_rid=(str(uut.interfaces[intf].ipv4))[:-3]

            #try:  
            leaf_bgp_obj=IbgpLeafNode(uut,bgp_rid,'65001',adv_nwk_list,neight_list_leaf,upd_src,'ibgp-vxlan')
            leaf_bgp_obj.bgp_conf()

                   
        log.info("neight_list_leaf -----for uut %r",neight_list_leaf) 
      
        neight_list_spine =[]

        for uut in leaf_uut_list:      
            for intf in uut.interfaces.keys():
                if 'loopback1' in intf:
                    intf = uut.interfaces[intf].intf
                    leaf_neigh=(str(uut.interfaces[intf].ipv4))[:-3]
                    neight_list_spine.append(leaf_neigh)

        log.info("neight_list -----for uut %r",neight_list_spine) 

        for uut in spine_uut_list:
            adv_nwk_list =[]
            for intf in uut.interfaces.keys():
                if 'loopback0' in intf:
                    intf = uut.interfaces[intf].intf
                    nwk1 = uut.interfaces[intf].ipv4
                    adv_nwk_list.append(nwk1)

                elif 'loopback1' in intf:
                    intf = uut.interfaces[intf].intf
                    upd_src = intf
                    bgp_rid=(str(uut.interfaces[intf].ipv4))[:-3]
                
            spine_bgp_obj=IbgpSpineNode(uut,bgp_rid,'65001',adv_nwk_list,neight_list_spine,upd_src,'ibgp-vxlan')
            spine_bgp_obj.bgp_conf()
    '''   
    @aetest.subsection
    def common_verify(self, testscript, testbed):
        countdown(60)
     

        log.info(banner("Starting Common verify Section"))       
        for uut in leaf_uut_list:
            for feature in ['ospf','pim','bgp']:
                test1 = leaf_protocol_check222(uut,[feature])
                if not test1:
                    log.info('Feature %r neigborship on device %r Failed ',feature,str(uut))
                    self.failed(goto=['common_cleanup'])
      
 
 


#######################################################################
###                          TESTCASE BLOCK                         ###
#######################################################################
#
# Place your code that implements the test steps for the test case.
# Each test may or may not contains sections:
#           setup   - test preparation
#           test    - test action
#           cleanup - test wrap-up
 



 
class TC0001_Vxlan_Tunnel_Bringup(aetest.Testcase):
    ###    This is description for my testcase one
  
    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
    
        
    @aetest.test
    def vxlan_configs(self, testscript, testbed):
        log.info(banner("VXLAN configurations")) 
        threads = []           
        for uut in leaf_uut_list:
            for intf in uut.interfaces.keys():
                if 'vxlan' in intf:
                    intf = uut.interfaces[intf].intf
                    vni=201001
                    routed_vlan = 101
                    routed_vni = 90101
                    ipv4_add1 = (str(uut.interfaces[intf].ipv4_add))[:-3]
                    ipv4_add = sub("/(.*)",'',ipv4_add1)
                    ipv6_add1 = (str(uut.interfaces[intf].ipv6_add))[:-4]
                    ipv6_add = sub("/(.*)",'',ipv6_add1)
                    log.info("IR mode is ================= %r",'bgp')
                    mcast_group = (str(uut.interfaces[intf].mcast_group))[:-3]
                    #leaf_vxlan_obj1=LeafObjectXconnect(uut,tunnel_vlan_start,vni,vlan_vni_scale,mcast_group,'65001','bgp',1)
                    leaf_vxlan_obj1=LeafObjectXconnect(uut,tunnel_vlan_start,vni,vlan_vni_scale,routed_vlan,routed_vni,\
                        routing_vlan_scale,ipv4_add,ipv6_add,mcast_group,'65001','bgp',1)
                    t = threading.Thread(target=leaf_vxlan_obj1.vxlan_conf())
                    threads.append(t)
 
        for t in threads: 
            t.start()
        for t in threads: 
            t.join()
 
        cfg = \
        """
        interface nve1
        advertise virtual-rmac 
        router bgp 65001
        address-family l2vpn evpn
        advertise-pip
        """
        for uut in leaf_uut_list:
            uut.configure(cfg)

        log.info("Testbed pre-clean")
   
    @aetest.test
    def VxlanXconnectTcamConf(self, testscript, testbed):    
       # for uut in leaf_uut_list:
       #     try:       
       #         XconnectTcamConfig(uut)
       #     except:
       #         log.info(banner("TC01_Vxlan Xconnect_Tcam_Config Failed")) 
       #         self.failed(goto=['common_cleanup'])

        log.info(banner(" Starting Vxlan Xconnect TCAM configuration Verification")) 
        for uut in leaf_uut_list:
            cli1=uut.execute("show hardware access-list tcam region | incl vxlan-p2p")    
            if cli1:
                if not int(cli1.split()[-1])>=256:
                    log.info("Vxlan Xconnect TCAM configuration not found in uut %r ",str(uut))                   
                    #self.failed(goto=['common_cleanup'])
                else:
                    log.info("Vxlan Xconnect TCAM configuration d for uut %r ",str(uut))                   
             
 
    @aetest.test
    def VxlanXconnectConf(self, testscript, testbed):
        log.info("tunnel_vlan_start is ========================== %r",tunnel_vlan_start)

 

        for uut in leaf_uut_list:
            op = uut.execute('show run vlan {vlan} | grep vn-seg'.format(vlan=tunnel_vlan_start))
            vni = op.split()[-1]
            log.info('vni issss------------%r',vni)
            
            try:
                VlanXconnectConfig(uut,tunnel_vlan_start,tunnel_vlan_scale,int(vni))
            except:
                log.info(banner( " Vlan Xconnect Config Failed")) 
                self.failed(goto=['common_cleanup'])


            for vlan,vni in zip(range(tunnel_vlan_start,tunnel_vlan_start+tunnel_vlan_scale+1),range(int(vni),int(vni)+tunnel_vlan_scale+1)):
                log.info('Remove SVI and arp suppression for Xconnect VLANs')
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
                    log.info(banner( " Vlan Xconnect Config Failed")) 
                    self.failed(goto=['common_cleanup'])

        
    @aetest.test
    def VxlanXconnectPoStaticConf(self, testscript, testbed):
        vlan = tunnel_vlan_start+1
        for uut in [leaf3,leaf4,leaf5,leaf6]:
            cfg = \
                """
                no interface po 101                
                interface po 101
                mtu 9216
                switchport 
                switchport mode dot1q-tunnel
                switchport access vlan {vlan}
                vpc 101
                mtu 9216
                no shut
                """
            log.info("tunnel Po config is %r",cfg.format(vlan=vlan))    
            try:
                uut.configure(cfg.format(vlan=vlan))
            except:
                log.info(banner("TC11 Xconnect VPC Port Config Failed")) 
                self.failed(goto=['common_cleanup'])

        for uut in [leaf3,leaf4,leaf5,leaf6]:
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelVpc' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf

                        cfg = \
                        """
                        default interface {port}
                        interface {port} 
                        switchport
                        channel-group 101 force mode on
                        shut
                        no shut
                        interf po 101
                        shut
                        mtu 9216
                        no shut
                        """ 
                        log.info("tunnel Po Member config is %r",cfg.format(port=port)) 
                        try:
                            uut.configure(cfg.format(port=port)) 
                        except:
                            log.info(banner("TC11 Xconnect VPC Member Config Failed")) 
                            self.failed(goto=['common_cleanup'])  
            
    
    @aetest.test
    def VxlanXconnectPortOrphan(self, testscript, testbed):
        vlan = tunnel_vlan_start+2            
        for uut in [leaf3,leaf5]:
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelOrphan1' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf
                        
                        cfg = \
                        """
                        default interface {port}
                        interface {port} 
                        shut
                        mtu 9216
                        switchport
                        switchport mode dot1q-tunnel
                        switchport access vlan {vlan}
                        spanning-tree port type edge 
                        no shut
                        mtu 9216                        
                        """
                        log.info("cfg isssss %r",cfg.format(vlan=vlan,port=port))
                        try:
                            uut.configure(cfg.format(vlan=vlan,port=port)) 
                        except:
                            log.info(banner("TC12 Xconnect Orphan Port Config Failed")) 
                            self.failed(goto=['common_cleanup'])  
                                           
    
    @aetest.test
    def VxlanXconnectVerifications(self, testscript, testbed):

        countdown(60)
         
        for uut in vpc_uut_list:
            log.info(banner(" step1: Verify VXLAN VPC | L3 Po | Xconnect PO ")) 
            op=uut.execute('show port-channel summary | incl Eth')
            op1=op.splitlines()
            for line in op1:
                if line:
                    if not "(P)" in line:
                        log.info('VPC  PO Failed on device %r after vxlan configs',str(uut)) 
                        uut.execute('show port-channel summary')
                        self.failed(goto=['common_cleanup'])
        
        log.info(banner("Vlan Xconnect vlan STP state verifcation on Static Po")) 
        vlan = tunnel_vlan_start+1
        for uut in [leaf3,leaf4,leaf5,leaf6]:
            op1 = uut.execute('show spanning-tree vlan {vlan} | incl FWD'.format(vlan=vlan))
            if not 'Po101' in op1:
                log.info("Port not in STP FWD - UUT is %r and VLAN is %r",uut,vlan) 
                self.failed(goto=['common_cleanup']) 

        
        log.info(banner("Vlan Xconnect vlan STP state verifcation on Orphan Port")) 
        vlan = tunnel_vlan_start+2
        for uut in [leaf3,leaf5]:
             for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelOrphan1' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf
                        op1 = uut.execute('show spanning-tree vlan {vlan} | incl FWD'.format(vlan=vlan))
                        if not port in op1:
                            log.info("Port not in STP FWD - UUT is %r and VLAN is %r and Ethernet is %r",uut,vlan,port) 
                            self.failed(goto=['common_cleanup']) 


        log.info(banner("Vlan Xconnect Check for Core/Crash ")) 
        for uut in leaf_uut_list:
            op = uut.execute('show core | json-pretty')
            if 'process_name' in op:
                log.info('Core found while Vlan Xconnect Config in uut%r',uut) 
                #self.failed(goto=['common_cleanup'])
        if not XconnPortCheck(leaf_uut_list):
            self.failed()
            if not XconnPortInit(leaf_uut_list):
                self.failed()
            countdown(10)
            if not XconnPortCheck(leaf_uut_list):
                self.failed(goto=['common_cleanup'])
                
        countdown(100)


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
 

 
 
class TC0002_Nve_Peer_State_Verify(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
 
        if not XconnPortCheck(leaf_uut_list):
            if not XconnPortInit(leaf_uut_list):
                self.failed()
            countdown(10)
            if not XconnPortCheck(leaf_uut_list):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test      
    def check_nve_peer_state(self):
        countdown(100)
        for uut in leaf_uut_list:
            test1 = leaf_protocol_check(uut,['nve-peer'])
            if not test1:
                result = 'fail'
                #if 'fail' in result:
                self.failed(goto=['common_cleanup'])
        if not XconnPortCheck(leaf_uut_list):
            self.failed()
            if not XconnPortInit(leaf_uut_list):
                self.failed()
            countdown(10)
            if not XconnPortCheck(leaf_uut_list):
                self.failed(goto=['common_cleanup'])



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
    

 
class TC0003_Nve_Vni_State_Verify(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
 

    @aetest.test
    def check_nve_vni_state(self):
        for uut in leaf_uut_list:
            uut.execute('terminal length 0')
            test1 = leaf_protocol_check(uut,['nve-vni'])
            if not test1:
                self.failed(goto=['common_cleanup'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
    

 
class TC0001_VXLAN_XC_TGN_CONNECT(aetest.Testcase):
    ###    This is description for my testcase two
    
    @aetest.setup
    def setup(self):
        pass

     
    @aetest.test
    def configureTgn(self, testscript, testbed):
        """ common setup subsection: connecting devices """

        global tgen, tgen_port_handle_list, leaf1, leaf2, leaf3, leaf4,leaf5,leaf6, \
            sw1, sw2, sw3, spine1, port_handle1, port_handle2, port_handle,labserver_ip,port_list,\
            port_hdl_list,ip_src_list,ip_dst_list,mac_src_list,mac_dst_list,stream_list,port_handle_sw1,\
            port_handle_sw3,port_handle_spine1,leaf_scale,tgn1_intf_list,port_handle_leaf3_1,port_handle_leaf5_1,\
            port_handle_leaf4_1,port_handle_leaf6_1,port_handle_leaf3_2,port_handle_leaf5_2,xcon_port_handle_list,\
            vpc_port_handle_list,xcon_po_port_handle_list,xcon_orphan_port_handle_list,port_handle_list
  
        

        
        #port_handle = ConnectSpirent(labserver_ip,tgn_ip,[tgn1_sw1_intf1,tgn1_sw3_intf1,tgn1_leaf3_intf1,tgn1_leaf5_intf1,tgn1_leaf4_intf1,tgn1_leaf6_intf1,tgn1_leaf3_intf2,tgn1_leaf5_intf2])
            
        port_list = [tgn1_sw1_intf1,tgn1_sw3_intf1,tgn1_leaf3_intf1,tgn1_leaf5_intf1,tgn1_leaf4_intf1,tgn1_leaf6_intf1,tgn1_leaf3_intf2,tgn1_leaf5_intf2]
        
        result = ixia_connect(labserver_ip,tgn_ip,port_list)
        if result == 0:
            log.info("Ixia Connection is failed")
            
        print(result)
        ports = result['vport_list'].split()   
        
        port_handle_sw1 = ports[0]
        port_handle_sw3 = ports[1]

        port_handle_leaf3_1 = ports[2]
        port_handle_leaf5_1 = ports[3]

        port_handle_leaf4_1 = ports[4]
        port_handle_leaf6_1 = ports[5]

        port_handle_leaf3_2 = ports[6]
        port_handle_leaf5_2 = ports[7]
                
            # port_handle_sw1 = port_handle[tgn1_sw1_intf1]
            # port_handle_sw3 = port_handle[tgn1_sw3_intf1]
            # 
            # port_handle_leaf3_1 = port_handle[tgn1_leaf3_intf1]
            # port_handle_leaf5_1 = port_handle[tgn1_leaf5_intf1]
            # 
            # port_handle_leaf4_1 = port_handle[tgn1_leaf4_intf1]
            # port_handle_leaf6_1 = port_handle[tgn1_leaf6_intf1]
            # 
            # port_handle_leaf3_2 = port_handle[tgn1_leaf3_intf2]
            # port_handle_leaf5_2 = port_handle[tgn1_leaf5_intf2]  

        vpc_port_handle_list = [port_handle_sw1,port_handle_sw3]
        xcon_port_handle_list = [port_handle_leaf3_1,port_handle_leaf4_1,port_handle_leaf5_1,port_handle_leaf6_1,port_handle_leaf3_2,port_handle_leaf5_2] 
        xcon_po_port_handle_list = [port_handle_leaf3_1,port_handle_leaf4_1,port_handle_leaf5_1,port_handle_leaf6_1]

        xcon_orphan_port_handle_list = [port_handle_leaf3_2,port_handle_leaf5_2] 
        port_handle_list = [port_handle_sw1,port_handle_sw3,port_handle_leaf3_1,port_handle_leaf4_1,port_handle_leaf5_1,port_handle_leaf6_1,port_handle_leaf3_2,port_handle_leaf5_2]
    
    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """   
 
 
class TC0004_VXLAN_Traffic_All_with_xconnect(aetest.Testcase):
    ###    This is description for my testcase two
  
    @aetest.setup
    def setup(self):   
        for uut in leaf_uut_list+sw_uut_list:
            uut.configure('system no hap-reset ')
            for i in range(1,2):
                uut.execute('clear mac address-table dynamic')
                uut.execute('clear ip arp vrf all')
 

        

        log.info(banner("Finding the IP address"))

        ip_sa1=str(ip_address(find_svi_ip222(leaf3,nonxc_vlan_start))+10) 
        ip_sa2=str(ip_address(ip_sa1)+10) 
        ip_sa11=str(ip_address(ip_sa1)+40) 
        ip_sa22=str(ip_address(ip_sa2)+40) 
    
        log.info(banner("----Generating hosts and flood traffic----"))
       
        test1= ixia_flood_traffic_config(port_handle_sw1,nonxc_vlan_start,ip_sa1,'100.100.100.100',nonxc_rate,str(nonxc_scale))
        test2= ixia_flood_traffic_config(port_handle_sw3,nonxc_vlan_start,ip_sa2,'200.200.200.200',nonxc_rate,str(nonxc_scale))
  
        log.info(banner("----Generating hosts Unicast Bidir Traffic----")) 

        ixia_unicast_bidir_traffic_config(port_hdl1=port_handle_sw1,port_hdl2=port_handle_sw3,vlan1=nonxc_vlan_start,vlan2=nonxc_vlan_start,\
        scale=nonxc_scale,ip1=ip_sa11,ip2=ip_sa22,gw1=ip_sa22,gw2=ip_sa11,rate_pps=nonxc_rate)

        log.info(banner("Finding the IPv6 address & creating v6 bidir streams"))
        vlan = 'vlan' + str(nonxc_vlan_start)
        ipv6_sa1=str(ip_address(findIntfIpv6Addr(leaf3,vlan))+10) 
        ipv6_sa2=str(ip_address(ipv6_sa1)+100) 

        ixia_v6_unicast_bidir_stream(port_handle_sw1,port_handle_sw3,nonxc_vlan_start,nonxc_vlan_start,nonxc_scale,\
            ipv6_sa1,ipv6_sa2,nonxc_rate)
    

        log.info(banner("Starting Traffic and counting 120 seconds")) 
        #sth.traffic_control(port_handle = 'all', action = 'run')
        _result_ = ixiahlt.traffic_control(action='run',traffic_generator='ixnetwork_540',type='l23')
        
        countdown(50)

    # @aetest.test
    # def vxlan_traffic_test_all(self):
    #    
    #     if not traffic_test_ixia(port_handle_list,nonxc_rate): 
    #         self.failed(goto=['common_cleanup'])
    #     else:            
    #         pcall(config_to_bootflash1,uut=tuple(leaf_uut_list),filename=(vxlan_evpn_config,vxlan_evpn_config,vxlan_evpn_config))



    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """
    
'''
class TC0100_Xconnect_traffic(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Port State Test @ TC04_Xconnect_ Setup "))

        
        for port_hdl in port_handle_list:
            streamblock_ret1 = sth.traffic_config(mode = 'reset',port_handle = port_hdl) 
 

        for uut in leaf_uut_list:
            uut.configure('no feature ngoam')

        log.info(banner("Starting Trigger2PortFlap @ 8"))          
        for uut in [leaf3,leaf5,leaf4,leaf6]:
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelVpc' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf                        
                        if not TriggerPortFlap(uut,port,3):
                            log.info("TriggerPortFlap failed @ 4")
                            self.failed(goto=['cleanup'])


        for uut in [leaf3,leaf5]:
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelOrphan1' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf
                        if not TriggerPortFlap(uut,port,3):
                            log.info("TriggerPortFlap failed @ 4")
                            self.failed(goto=['cleanup'])
                  

        countdown(40)

        if not XconnPortCheck(leaf_uut_list):
            self.failed(goto=['common_cleanup'])
        
        log.info(banner("Traffic streams for Xconnect PO")) 
        xconnectStreams(port_handle_leaf4_1,'00:10:94:00:00:01',1000)
        xconnectStreams(port_handle_leaf6_1,'00:10:94:00:00:02',1000)
        xconnectStreams(port_handle_leaf3_1,'00:10:94:00:00:03',1000)
        xconnectStreams(port_handle_leaf5_1,'00:10:94:00:00:04',1000)

        log.info(banner(" creating Streams for orphan  ")) 
        xconnectStreams(port_handle_leaf3_2,'00:10:94:00:00:05',1000)
        xconnectStreams(port_handle_leaf5_2,'00:10:94:00:00:05',1000)


        #for protocol in ['cdp','lacp','stp','igmp','802.1x','hsrp','pagp','vstp','mvrp']:
        #    SpirentTunnelStreamConfNew(port_handle_leaf4_1,'00:10:94:00:00:32',protocol,1000)
        #    SpirentTunnelStreamConfNew(port_handle_leaf6_1,'00:10:94:00:00:52',protocol,1000)
        #    log.info("Configured %r stream in Spirent",protocol) 

        #for protocol in ['cdp','lacp','stp','igmp','802.1x','hsrp','pagp','vstp','mvrp']:
        #    SpirentTunnelStreamConfNew(port_handle_leaf3_1,'00:10:94:00:00:32',protocol,1000)
        #    SpirentTunnelStreamConfNew(port_handle_leaf5_1,'00:10:94:00:00:52',protocol,1000)
        #    log.info("Configured %r stream in Spirent",protocol) 

        #for protocol in ['cdp','lacp','stp','igmp','802.1x','hsrp','pagp','vstp','mvrp']:
        #    SpirentTunnelStreamConfNew(port_handle_leaf3_2,'00:10:94:00:00:32',protocol,1000)
        #    SpirentTunnelStreamConf(port_handle_leaf5_2,'00:10:94:00:00:52',protocol,1000)
        #    log.info("SpirentTunnelStreamConfNew %r stream in Spirent",protocol) 


    @aetest.test
    def TrafficTest(self, testscript, testbed):
        log.info(banner("Starting Traffic Test ")) 

        log.info(banner("Starting Traffic and counting 80 seconds")) 
        sth.traffic_control(port_handle = 'all', action = 'run')
        countdown(80)
 
        if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
            pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
                filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
            countdown(300)
            if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()   
        else:
            pcall(config_to_bootflash,uut=tuple(vpc_uut_list),filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))


    @aetest.cleanup
    def cleanup(self):
        log.info("Pass testcase cleanup")
'''
 

class TC0117_Xconnect_Ngoam_enable(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Start Xconnect Tunnel Port configurations"))  
        pass


    @aetest.test
    def ngoam_enable(self):
        log.info(banner("Start ngoam_enable"))  

        result_list = []    
        ngoam_enable = \
        """
        feature ngoam
        ngoam install acl
        ngoam xconnect hb-interval 5000        
        """
        for uut in leaf_uut_list:
            try:
                uut.configure(ngoam_enable)    
            except:
                log.info("NGOAM enable failed in uut %r",uut)    
                result_list.append("fail")

        for uut in leaf_uut_list:
            state = uut.configure("show run ngoam")
            for string in ["feature ngoam","ngoam install acl"]:
                if not string in state:
                    log.info("NGOAM config string %r not found in uut %r",string,uut)
                    result_list.append("fail")

        if 'fail' in result_list:
            self.failed()


        countdown(10)

    @aetest.test
    def portCheckAfterNgoam(self):
        if not XconnPortCheck(leaf_uut_list):
            self.failed()
            

    @aetest.test
    def XconnetNgoamOrphanState(self, testscript, testbed):
        log.info(banner("XconnetNgoamOrphanState")) 

        result_list = []    
        for uut in [leaf3,leaf5]:
            state_json=json.loads(uut.execute("show ngoam xconnect session 502 | json-pretty"))
            state = state_json['ENTRY_xc_db_detail'] 
            #for value in ["d-local-if-state","remote-if-detail-state"]:
            #    if not "UP" in state[value]:
            #        log.info("NGOAM Json state down in uut %r for value %r",uut,value)               
            #        result_list.append("fail")

            if not "UP" in state['d-local-if-state']:
                log.info("NGOAM Json state down in uut d-local-if-state %r",uut)
                result_list.append("fail") 
 

            if not "UP" in state['remote-if-detail-state'] + state['remote-vpc-if-state']:
                log.info("NGOAM Json state down in uut remote-if-detail-state %r",uut)
                result_list.append("fail") 


        if 'fail' in result_list:
            self.failed()


    @aetest.test
    def XconnetNgoamPoState(self, testscript, testbed):
        log.info(banner("XconnetNgoamPoState")) 

        result_list = []    
        for uut in leaf_uut_list:  
            state_json=json.loads(uut.execute("show ngoam xconnect session 501 | json-pretty"))
            for value in ["d-local-if-state","vpc-if-state","remote-if-detail-state","remote-vpc-if-state"]:
                if not "UP" in state_json['ENTRY_xc_db_detail'][value]:
                    log.info("NGOAM Json state down in uut %r for value %r",uut,value)                
                    result_list.append("fail")

        if 'fail' in result_list:
            self.failed()

    # @aetest.test
    # def TrafficTest(self, testscript, testbed):
    #     log.info(banner("Starting Traffic Test After Ngoam ")) 
    #     #if not XconnectTrafficTest(xcon_port_handle_list):
    #     #    self.failed()
    #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
    #         pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
    #             filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
    #         countdown(300)
    #         if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
    #             self.failed(goto=['common_cleanup'])
    #         self.failed()   


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
 
  
 
class TC0118_Xconnect_Ngoam_remote_failure_Orphan(aetest.Testcase):
    @aetest.setup
    def setup(self):
        for uut in [leaf5]:
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelOrphan1' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf
                        cfg = \
                        """
                        interface {port}
                        shut
                        """
                        uut.configure(cfg.format(port=port))

        countdown(100)

    @aetest.test
    def XconnetNgoamOrphanRemoteFail(self, testscript, testbed):
        log.info(banner("XconnetNgoamOrphanRemoteFail Verfication")) 
        remote_down="Heartbeat loss"
        result_list = []    
        for uut in [leaf3]:
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelOrphan1' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf
                        int_state_json=json.loads(uut.execute("show inter {port} | json-pretty".format(port=port))) 
            
                        if not "down" in int_state_json["TABLE_interface"]["ROW_interface"]["state"]:
                            log.info("Interface %r not down in uut %r",port,uut)
                            result_list.append("fail")             
    

            state_json=json.loads(uut.execute("show ngoam xconnect session 502 | json-pretty")) 
            state = state_json['ENTRY_xc_db_detail']              
            if not remote_down in state['d-db-state']:
                log.info("NGOAM Json state not Heartbeat in uut d-db-state %r",uut)
                result_list.append("fail") 

            if not "ERR" in state["d-local-if-state"]:
                log.info("NGOAM Json state not ERR  in uut d-local-if-state %r",uut)
                result_list.append("fail") 


        for uut in leaf_uut_list:  
            state_json=json.loads(uut.execute("show ngoam xconnect session 501 | json-pretty"))
            for value in ["d-local-if-state","vpc-if-state","remote-if-detail-state","remote-vpc-if-state"]:
                if not "UP" in state_json['ENTRY_xc_db_detail'][value]:
                    log.info("NGOAM state for PO DOWN @ ORPHAN Test in uut %r for value %r",uut,value)                
                    result_list.append("fail")


        if 'fail' in result_list:
            self.failed()


    @aetest.test
    def XconnetNgoamOrphanRemoteFailRevert(self, testscript, testbed):
        log.info(banner("XconnetNgoamOrphanRemoteFailRevert Verfication")) 
        for uut in [leaf5,leaf3]:
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelOrphan1' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf
                        cfg = \
                        """
                        interface {port}
                        shut 
                        no shut
                        sleep 5
                        """
                        uut.configure(cfg.format(port=port))

        countdown(100)
        result_list = []    
        for uut in [leaf3,leaf5]:
            state_json=json.loads(uut.execute("show ngoam xconnect session 502 | json-pretty"))
            state = state_json['ENTRY_xc_db_detail']     
            if not "UP" in state['d-local-if-state']:
                log.info("NGOAM Json state down in uut d-local-if-state %r",uut)
                result_list.append("fail") 
 

            if not "UP" in state['remote-if-detail-state'] + state['remote-vpc-if-state']:
                log.info("NGOAM Json state down in uut remote-if-detail-state %r",uut)
                result_list.append("fail") 

            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelOrphan1' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf
                        int_state_json=json.loads(uut.execute("show inter {port} | json-pretty".format(port=port))) 
            
                        if not "up" in int_state_json["TABLE_interface"]["ROW_interface"]["state"]:
                            log.info("Interface %r not up in uut %r",port,uut)
                            result_list.append("fail")             
    

        if 'fail' in result_list:
            self.failed()


    # @aetest.test
    # def TrafficTest(self, testscript, testbed):
    #     log.info(banner("Starting Traffic Test After Ngoam Orphan Fail & revert")) 
    #     #if not XconnectTrafficTest(xcon_port_handle_list):
    #     #    self.failed()
    #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
    #         pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
    #             filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
    #         countdown(300)
    #         if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
    #             self.failed(goto=['common_cleanup'])
    #         self.failed()           


    @aetest.cleanup
    def cleanup(self):
        log.info("Pass testcase cleanup")
        pass 


class TC0119_Xconnect_Ngoam_remote_failure_Po(aetest.Testcase):
    @aetest.setup
    def setup(self):
        for uut in [leaf5,leaf6]:                        
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelVpc' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf
                        cfg = \
                        """
                        interface {port}
                        shut
                        """
                        uut.configure(cfg.format(port=port)) 
        countdown(100)

    @aetest.test
    def XconnetNgoamPoRemoteFail(self, testscript, testbed):
        log.info(banner("XconnetNgoamPoRemoteFail Verfication")) 
        result_list = []   
        remote_down="Heartbeat loss"
        for uut in [leaf3,leaf4]:
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelVpc' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf
                        int_state_json=json.loads(uut.execute("show inter {port} | json-pretty".format(port=port))) 
            
                        if not "down" in int_state_json["TABLE_interface"]["ROW_interface"]["state"]:
                            log.info("Interface %r not down in uut %r",port,uut)
                            result_list.append("fail")             
    

            state_json=json.loads(uut.execute("show ngoam xconnect session 501 | json-pretty")) 
            state = state_json['ENTRY_xc_db_detail']              

            if not remote_down in state['d-db-state']:
                log.info("NGOAM Json state not Heartbeat in uut d-db-state %r",uut)
                result_list.append("fail") 

            if not "ERR" in state["d-local-if-state"]:
                log.info("NGOAM Json state not ERR  in uut d-local-if-state %r",uut)
                result_list.append("fail")  

        for uut in [leaf3,leaf5]:
            state_json=json.loads(uut.execute("show ngoam xconnect session 502 | json-pretty"))
            state = state_json['ENTRY_xc_db_detail'] 
            #for value in ["d-local-if-state","remote-if-detail-state"]:
            #    if not "UP" in state[value]:
            #        log.info("NGOAM Json state for Orphan down @ PO Test uut %r for value %r",uut,value)               
            #        result_list.append("fail")

            if not "UP" in state['d-local-if-state']:
                log.info("NGOAM Json state down in uut d-local-if-state %r",uut)
                result_list.append("fail") 
 

            if not "UP" in state['remote-if-detail-state'] + state['remote-vpc-if-state']:
                log.info("NGOAM Json state down in uut remote-if-detail-state %r",uut)
                result_list.append("fail") 



        if 'fail' in result_list:
            self.failed()



    @aetest.test
    def XconnetNgoamPoRemoteFailRevert(self, testscript, testbed):
        log.info(banner("L2 Unicast Traffic Tunnelling Verfication")) 
        result_list = []   
        cfg = \
        """
        interface {port}
        shut
        no shut
        sleep 2
        """
        for uut in [leaf5,leaf6]:                        
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelVpc' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf
                        uut.configure(cfg.format(port=port))
        countdown(2) 
        for uut in [leaf3,leaf4]:                        
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelVpc' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf
                        uut.configure(cfg.format(port=port))
        countdown(100) 

        for uut in leaf_uut_list:  
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelVpc' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf
                        int_state_json=json.loads(uut.execute("show inter {port} | json-pretty".format(port=port))) 
            
                        if not "up" in int_state_json["TABLE_interface"]["ROW_interface"]["state"]:
                            log.info("Interface %r not up in uut %r",port,uut)
                            result_list.append("fail") 


            state_json=json.loads(uut.execute("show ngoam xconnect session 501 | json-pretty"))


            for value in ["d-local-if-state","vpc-if-state","remote-if-detail-state","remote-vpc-if-state"]:
                if not "UP" in state_json['ENTRY_xc_db_detail'][value]:
                    log.info("NGOAM Json state down in uut %r for value %r",uut,value)                
                    result_list.append("fail")


        if 'fail' in result_list:
            self.failed()

    # @aetest.test
    # def TrafficTest(self, testscript, testbed):
    #     log.info(banner("Starting Traffic Test After Ngoam Po Remote Fail & revert")) 
    #     #if not XconnectTrafficTest(xcon_port_handle_list):
    #     #    self.failed()
    #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
    #         pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
    #             filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
    #         countdown(300)
    #         if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
    #             self.failed(goto=['common_cleanup'])
    #         self.failed()   



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup") 
        pass
 
 
 
class TC0101_Xconnect_Trigger_BGP_Restart(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Start test case TC21_Xconnect_Triggers")) 


    @aetest.test
    def Trigger1BgpProcRestart(self, testscript, testbed):
        log.info(banner("Starting TriggerBgpProcRestart @ 11"))     
        for uut in [leaf4,leaf6]:
            for i in range(1,2):
                ProcessRestart(uut,'bgp')
          
         
        log.info(banner("Starting Traffic Test after TriggerBgpProcRestart @ 13")) 
        countdown(60)

        log.info(banner("Starting Traffic Test ")) 
        #if not XconnectTrafficTest(xcon_port_handle_list):
        #    self.failed()
        if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
            pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
                filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
            countdown(300)
            if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()   

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
 
class TC0102_Xconnect_Trigger_Nve_Restart(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Start test case TC21_Xconnect_Triggers")) 

    @aetest.test
    def Trigger2NveProcRestart(self, testscript, testbed):
        log.info(banner("Starting TriggerNveProcRestart @ 11"))     
        for uut in [leaf4,leaf6]:
            for i in range(1,2):
                ProcessRestart(uut,'nve')
   

        log.info(banner("Starting Traffic Test after TriggerNveProcRestart @ 13")) 
        countdown(60)

        # log.info(banner("Starting Traffic Test ")) 
        # #if not XconnectTrafficTest(xcon_port_handle_list):
        # #    self.failed()
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     self.failed()   


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")


class TC0103_Xconnect_Trigger_Vlan_Remove_Add(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Start test case TC21_Xconnect_Triggers")) 
     
    @aetest.test
    def Trigger1VlanAddRemovePort(self, testscript, testbed):
        log.info(banner("Starting Trigger1VlanAddRemovePort @ 5")) 

        result_list =  []
         
        for uut in [leaf3,leaf5,leaf4,leaf6]:
            vlan = tunnel_vlan_start+1
            if not TriggerPortVlanRemoveAdd(uut,'Po101',vlan,3):
                log.info("TriggerPortVlanRemoveAdd failed @ 2")
                self.failed()

        vlan = tunnel_vlan_start+2            
        for uut in [leaf3,leaf5]:
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelOrphan1' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf
                        if not TriggerPortVlanRemoveAdd(uut,port,vlan,3):
                            log.info("TriggerPortVlanRemoveAdd failed @ 2")
                            self.failed()


        log.info(banner("Starting Traffic Test after Trigger1VlanAddRemovePort @ 6")) 
        countdown(40)

        # log.info(banner("Starting Traffic Test ")) 
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     self.failed()   


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
 
 
class TC0104_Xconnect_Trigger_Port_Flap(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Start test case TC21_Xconnect_Triggers")) 

      
    @aetest.test
    def Trigger2PortFlap(self, testscript, testbed):
        log.info(banner("Starting Trigger2PortFlap @ 8"))          
        for uut in [leaf3,leaf5,leaf4,leaf6]:
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelVpc' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf                        
                        if not TriggerPortFlap(uut,port,3):
                            log.info("TriggerPortFlap failed @ 4")
                            self.failed(goto=['cleanup'])


        for uut in [leaf3,leaf5]:
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'TunnelOrphan1' in uut.interfaces[intf].alias:
                        port = uut.interfaces[intf].intf
                        if not TriggerPortFlap(uut,port,3):
                            log.info("TriggerPortFlap failed @ 4")
                            self.failed()



        log.info(banner("Starting Traffic Test after TriggerPortFlap @ 9")) 
        countdown(40)

        # log.info(banner("Starting Traffic Test ")) 
        # #if not XconnectTrafficTest(xcon_port_handle_list):
        # #    self.failed()
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     self.failed()   

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

 
class TC0105_Xconnect_Trigger_Xconn_Remove_Add(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Start test case TC21_Xconnect_Triggers")) 


    @aetest.test
    def Trigger3XconRemovAdd(self, testscript, testbed):
 
        log.info(banner("Starting Trigger3XconRemovAdd @ 11"))  
        for vlan in [tunnel_vlan_start+1,tunnel_vlan_start+2]:  
            for uut in [leaf3,leaf5,leaf4,leaf6]:
                if not XconnRemoveAdd(uut,vlan,3):
                    log.info("XconnRemoveAdd failed @ 6")
                    self.failed()

        log.info(banner("Starting Traffic Test after XconnRemoveAdd @ 12")) 
        countdown(40)

        # log.info(banner("Starting Traffic Test ")) 
        # #if not XconnectTrafficTest(xcon_port_handle_list):
        # #    self.failed()
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     self.failed()   



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

 

class TC0106_Xconnect_Trigger_Core_Flap(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Start test case TC21_Xconnect_Triggers")) 

    @aetest.test
    def Trigger4CoreIfFlap(self, testscript, testbed):

        log.info(banner("Starting Trigger3XconRemovAdd @ 11"))     
        for uut in [leaf3,leaf5,leaf4,leaf6]:
            cmd = uut.execute("show ip ospf neigh | json-pretty")
            op=json.loads(cmd)  
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
                        log.info('Trigger4CoreIfFlap failed @ 11')
                        self.failed(goto=['cleanup'])
    
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
                        log.info('Trigger4CoreIfFlap failed @ 12')
                        self.failed(goto=['cleanup'])
    

        log.info(banner("Starting Traffic Test after Trigger4CoreIfFlap @ 13")) 
        countdown(100)

        # log.info(banner("Starting Traffic Test ")) 
        # #if not XconnectTrafficTest(xcon_port_handle_list):
        # #    self.failed()
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     self.failed()   


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")


class TC0107_Xconnect_Triggers_Clear_Ip_Route(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Start test case TC21_Xconnect_Triggers"))  


    @aetest.test
    def TriggerClearIpRoute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))     
        for uut in [leaf3,leaf5,leaf4,leaf6]:
            for i in range(1,3):
                uut.execute("clear ip route *")

        log.info(banner("Starting Traffic Test after TriggerClearIpRoute @ 13")) 
        countdown(60)

        # log.info(banner("Starting Traffic Test ")) 
        # #if not XconnectTrafficTest(xcon_port_handle_list):
        # #    self.failed()
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     self.failed()   


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

class TC0108_Xconnect_Trigger_Clear_Ip_Mroute(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Start test case TC21_Xconnect_Triggers")) 


    @aetest.test
    def TriggerClearIpMroute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))     
        for uut in [leaf3,leaf5,leaf4,leaf6]:
            for i in range(1,3):
                uut.execute("clear ip mroute *")

        log.info(banner("Starting Traffic Test after TriggerClearIpMroute @ 13")) 
        countdown(60)

        # log.info(banner("Starting Traffic Test ")) 
        # #if not XconnectTrafficTest(xcon_port_handle_list):
        # #    self.failed()
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     self.failed()   

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")


class TC0109_Xconnect_Trigger_Clear_Ospf(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Start test case TC21_Xconnect_Triggers")) 
 

    @aetest.test
    def TriggerClearOspfNeigh(self, testscript, testbed):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))     
        for uut in [leaf3,leaf5,leaf4,leaf6]:
            for i in range(1,3):
                uut.execute("clear ip ospf neighbor *")

        log.info(banner("Starting Traffic Test after TriggerClearOspfNeigh @ 13")) 
        countdown(80)

        # log.info(banner("Starting Traffic Test ")) 
        # #if not XconnectTrafficTest(xcon_port_handle_list):
        # #    self.failed()
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     self.failed()   


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")


class TC0110_Xconnect_Trigger_Clear_BGP(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Start test case TC21_Xconnect_Triggers")) 

    @aetest.test
    def TriggerClearIpBgp(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))     
        for uut in [leaf3,leaf5,leaf4,leaf6]:
            for i in range(1,3):
                uut.execute("clear ip bgp *")

        log.info(banner("Starting Traffic Test after TriggerClearIpBgp @ 13")) 
        countdown(80)

        # log.info(banner("Starting Traffic Test ")) 
        # #if not XconnectTrafficTest(xcon_port_handle_list):
        # #    self.failed()
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     self.failed()   


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")


class TC0111_Xconnect_Triggers_ClearL2Vpn(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Start test case TC21_Xconnect_Triggers")) 


    @aetest.test
    def TriggerClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting TriggerClearBgpL2vpnEvpn @ 11"))     
        for uut in [leaf3,leaf5,leaf4,leaf6]:
            for i in range(1,3):
                uut.execute("clear bgp l2vpn evpn *")

        log.info(banner("Starting Traffic Test after TriggerClearBgpL2vpnEvpn @ 13")) 
        countdown(80)

        # log.info(banner("Starting Traffic Test ")) 
        # #if not XconnectTrafficTest(xcon_port_handle_list):
        # #    self.failed()
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     self.failed()   

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")


class TC0112_Xconnect_Trigger_Clear_Nve_Flap(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Start test case TC21_Xconnect_Triggers")) 


    @aetest.test
    def TriggerNveFlapp(self, testscript, testbed):
        log.info(banner("Starting TriggerClearBgpL2vpnEvpn @ 11"))     
        for uut in [leaf3,leaf5,leaf4,leaf6]:
            for i in range(1,3):
                cfg = \
                    """
                    interface nve1
                    shut
                    """
                try:
                    uut.configure(cfg)
                except:    
                    log.info('TriggerNveFlapp failed @ 11')
                    self.failed(goto=['cleanup'])
    
                countdown(1)
                cfg = \
                    """
                    interface nve1
                    no shut
                    """
                try:
                    uut.configure(cfg)
                except:    
                    log.info('TriggerNveFlapp failed @ 12')
                    self.failed(goto=['cleanup'])


        log.info(banner("Starting Traffic Test after TriggerNveFlapp @ 13")) 
        countdown(60)

        # log.info(banner("Starting Traffic Test ")) 
        # #if not XconnectTrafficTest(xcon_port_handle_list):
        # #    self.failed()
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     self.failed()   

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")


class TC0113_Xconnect_Trigger_Vlan_Shut_NoShut(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Start test case TC21_Xconnect_Triggers")) 


    @aetest.test
    def TriggerVlanShutNoShut(self, testscript, testbed):
        #vlan = tunnel_vlan_start+2  
        #for vlan in [tunnel_vlan_start+1,tunnel_vlan_start+2]:  
        log.info(banner("Starting TriggerVlanShutNoShut @ 11"))     
        for i in range(1,2):
            for uut in [leaf3,leaf5,leaf4,leaf6]:
                cfg = \
                    """
                    vlan {vlan1}-{vlan2}
                    shut
                    exit
                    """
                try:
                    uut.configure(cfg.format(vlan1=tunnel_vlan_start+1,vlan2=tunnel_vlan_start+2))
                except:    
                    log.info('TriggerVlanShutNoShut failed @ 11')
                    #self.failed(goto=['cleanup'])
    
                countdown(1)
            for uut in [leaf3,leaf5,leaf4,leaf6]:
                cfg = \
                    """
                    vlan {vlan1}-{vlan2}
                    no shut
                    exit
                    """
                try:
                    uut.configure(cfg.format(vlan1=tunnel_vlan_start+1,vlan2=tunnel_vlan_start+2))
                except:    
                    log.info('TriggerVlanShutNoShut failed @ 12')
                    #self.failed(goto=['cleanup'])
    


        log.info(banner("Starting Traffic Test after TriggerVlanShutNoShut @ 13")) 
        countdown(60)

        # log.info(banner("Starting Traffic Test ")) 
        # #if not XconnectTrafficTest(xcon_port_handle_list):
        # #    self.failed()
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     self.failed()   

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")



class TC0114_Xconnect_Trigger_Nve_Remove_Add(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Start test case TC21_Xconnect_Triggers")) 


    @aetest.test
    def TriggerNveRemoveAdd(self, testscript, testbed):
        log.info(banner("Starting TriggerNveRemoveAdd @ 11"))     
        for uut in [leaf3,leaf5,leaf4,leaf6]:
            cfg = uut.execute("show run interface nve1")
            try:
                uut.configure("no interface nve1")
            except:    
                log.info('NVE remove failed @ 1')
                self.failed(goto=['cleanup'])
    
            try:
                uut.configure(cfg)
            except:    
                log.info('NVE Add failed @ 12')
                self.failed(goto=['cleanup'])


        log.info(banner("Starting Traffic Test after TriggerNveRemoveAdd @ 13")) 
        countdown(60)
        # log.info(banner("Starting Traffic Test ")) 
        # #if not XconnectTrafficTest(xcon_port_handle_list):
        # #    self.failed()
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     self.failed()   



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
 

class TC0115_Xconnect_McastGroupChange(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Port State Test @ TC04_Xconnect_ Setup "))


    @aetest.test
    def GroupChangeTrafficTestPo(self, testscript, testbed):
        
        result_list = []
        if not NveMcastGroupChange(leaf_uut_list):
            result_list.append("fail")
        
        countdown(30)

        # log.info(banner("Starting Traffic Test ")) 
        # #if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     result_list.append("fail")
        # if 'fail' in result_list:
        #     self.failed()
            
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """ 
        log.info("Pass testcase cleanup") 
 
   
 
class TC01151_xconnect_nve_source_Ip_change(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        log.info(banner("Port State Test @ TC04_Xconnect_ Setup "))


    @aetest.test
    def GroupChangeTrafficTestPo(self, testscript, testbed):
        
        result_list = []
        if not NveSourceIpChange(leaf_uut_list,'65001','Loopback0'):
            self.failed() 
    
        countdown(500)

        # log.info(banner("Starting Traffic Test ")) 
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     result_list.append("fail")
        # if 'fail' in result_list:
        #     self.failed()
            
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """ 
        log.info("Pass testcase cleanup") 
  
class TC01152_xconnect_nve_source_loop_change(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        log.info(banner("Port State Test @ TC04_Xconnect_ Setup "))


    @aetest.test
    def GroupChangeTrafficTestPo(self, testscript, testbed):
        
        result_list = []

        if not NveSourceInterfaceChange(leaf_uut_list,'65001'):
            self.failed() 
    
    
        countdown(300)

        # log.info(banner("Starting Traffic Test ")) 
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     result_list.append("fail")
        # if 'fail' in result_list:
        #     self.failed()
            
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """ 
        log.info("Pass testcase cleanup")  
 
class TC01152_xconnect_config_replace(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        log.info(banner("Port State Test @ TC04_Xconnect_ Setup "))


    @aetest.test
    def xconnectConfigReplace(self, testscript, testbed):
        
        result_list = []

        for uut in leaf_uut_list:
            tm = uut.execute("show clock | excl Time")
            log.info("time is ----- %r",tm)
            tm1 =  tm.replace(":","").replace(".","").replace(" ","")
            uut.configure('copy run bootflash:{name}'.format(name=tm1))
            countdown(2)
            uut.configure("no feature nv overlay")
            countdown(2)                 
            op = uut.configure('configure replace bootflash:{name}'.format(name=tm1))
            if not "successfully" in op:
                self.failed()


        countdown(500)


        # log.info(banner("Starting Traffic Test ")) 
        # if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #     pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
        #         filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
        #     countdown(300)
        #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
        #         self.failed(goto=['common_cleanup'])
        #     result_list.append("fail")
        # 
        # if 'fail' in result_list:
        #     self.failed()
            
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """ 
        log.info("Pass testcase cleanup")  

 
 


class TC0116_Vlan_Xconnect_Config_Nxapi(aetest.Testcase):
    @aetest.setup
    def setup(self):
        log.info(banner("Start Vlan Xconnect configurations via NXA= API")) 
        log.info("tunnel_vlan_start is ========================== %r",tunnel_vlan_start)
        log.info("tunnel_vlan_scale is ========================== %r",tunnel_vlan_scale)
    
        result_list =[]
        for uut in leaf_uut_list:
            uncfg = \
                """
                no feature nxapi
                """
            uut.configure(uncfg)    
        countdown(10)
        for uut in leaf_uut_list:
            cfg = \
                """
                feature nxapi
                nxapi http port 8080
                """ 
            try:
                uut.configure(cfg)  
            except:
                log.info("Enable feature NXAPI failed on UUT %r",str(uut))
                result_list.append('fail')

        countdown(10)    
        for uut in leaf_uut_list:
            switchuser=uut.tacacs['username']
            switchpassword=uut.passwords['enable']
            if not 'alt' in uut.connections:
                log.info("UUT %r do not have Mgmt IP defined",str(uut))
                result_list.append('fail')
            else:
                MgIP = str(uut.connections['alt']['ip'])

 

            client_cert='PATH_TO_CLIENT_CERT_FILE'
            client_private_key='PATH_TO_CLIENT_PRIVATE_KEY_FILE'
            ca_cert='PATH_TO_CA_CERT_THAT_SIGNED_NXAPI_SERVER_CERT'


            myheaders={'content-type':'application/json-rpc'}
            payload=[
               {
               "jsonrpc": "2.0",
               "method": "cli",
               "params": {
                   "cmd": "show version",
                   "version": 1
                    },
                "id": 1
                }
            ]

            url = "http://%s/ins" % (MgIP)

            log.info("url isssssss %r",url)
 
   
            #response = requests.post(url,data=json.dumps(payload), headers=myheaders,auth=(switchuser,switchpassword),cert=(client_cert,client_private_key),verify=ca_cert).json()

            response = requests.post(url, data = json.dumps(payload), headers = myheaders,auth = (switchuser, switchpassword)).json()            

            version = response['result']['body']['rr_sys_ver']
            log.info("Switch %r version ~~~~~via NX API ~~~~~~~~ %r",MgIP,version)

 
        countdown(10)

    
        if 'fail' in result_list:
            self.failed()


    @aetest.test
    def VxlanXconnectRemoveAddViaNXAPI(self, testscript, testbed):
        log.info(banner("Vlan Xconnect configuration via NXAPI")) 
        countdown(5)
        result_list = []
        for uut in leaf_uut_list:
            switchuser=uut.tacacs['username']
            switchpassword=uut.passwords['enable']
            if not 'alt' in uut.connections:
                log.info("UUT %r do not have Mgmt IP defined",str(uut))
                result_list.append('fail')
            else:
                MgIP = str(uut.connections['alt']['ip'])

 
            myheaders={'content-type':'application/json'}
            for vlan in range(tunnel_vlan_start,tunnel_vlan_start+tunnel_vlan_scale):
                log.info("vlan is+++++++++++++%r",vlan)
                vlan = vlan
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

                #pdb.set_trace()  
                log.info("payload is %r",payload)

                payload['ins_api']['input'] ="vlan {vlan} ;no xconnect ".format(vlan=vlan)
                log.info("No xconnect payload is ~~~~~~~~~~~~~~~~~~~~ %r",payload)
                url = "http://%s/ins" % (MgIP)
                #response = requests.post(url, data = json.dumps(payload), headers = myheaders,\
                #             auth = (switchuser, switchpassword)).json()
                
                response = requests.post(url, data = json.dumps(payload), headers = myheaders,auth = (switchuser, switchpassword)).json()            

                countdown(2)
                op = uut.execute('show run vlan {vlan}'.format(vlan=vlan))
                if 'xconnect' in op:
                    log.info("xconnect not removed from vlan %r",vlan)
                    result_list.append('fail')

                payload['ins_api']['input'] ="vlan {vlan} ;xconnect".format(vlan=vlan)

                log.info("Xconnect payload is ~~~~~~~~~~~~~~~~~~~~ %r",payload)

                response = requests.post(url, data = json.dumps(payload), headers = myheaders,\
                             auth = (switchuser, switchpassword)).json()
                countdown(2)
                op = uut.execute('show run vlan {vlan}'.format(vlan=vlan))

                if not 'xconnect' in op:
                    log.info("xconnect not added in vlan %r",vlan)
                    result_list.append('fail')



                log.info("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                log.info("Response is -------------%r",response)
                log.info("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")



        if 'fail' in result_list:
            self.failed()

        log.info("Vlan Xconnect Remov Add NXAPI configs d")
        countdown(70)
    

    # @aetest.test
    # def TrafficTest(self, testscript, testbed):
    #     log.info(banner("Starting Traffic Test ")) 
    #     #if not XconnectTrafficTest(xcon_port_handle_list):
    #     #    self.failed()
    #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
    #         pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
    #             filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
    #         countdown(300)
    #         if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
    #             self.failed(goto=['common_cleanup'])
    #         self.failed()   



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        #for port_hdl in port_handle_list:
        #    streamblock_ret1 = sth.traffic_config(mode = 'reset',port_handle = port_hdl) 
 
        log.info("Pass testcase cleanup")
        pass



class TC0111119_Xconnect_Ngoam_ISSU1(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass


    @aetest.test
    def XconnectISSU(self, testscript, testbed):
        log.info(banner("Starting Trigger issu_1 @ 1"))

        device = leaf3
        if 'yes' in test_issu:
            res = start_nd_issu(device, issu_image)
  
            if not res:
                self.failed()
 
            countdown(40)

        countdown(100)

    # @aetest.test
    # def TrafficTest(self, testscript, testbed):
    #     log.info(banner("Starting Traffic Test After Ngoam Po Remote Fail & revert")) 
    #     #if not XconnectTrafficTest(xcon_port_handle_list):
    #     #    self.failed()
    #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
    #         pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
    #             filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
    #         countdown(300)
    #         if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
    #             self.failed(goto=['common_cleanup'])
    #         self.failed()   

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup") 
        pass


class TC0111119_Xconnect_Ngoam_ISSU2(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass


    @aetest.test
    def XconnectISSU(self, testscript, testbed):
        log.info(banner("Starting Trigger issu_1 @ 1"))

        device = leaf5
        if 'yes' in test_issu:
            res = start_nd_issu(device, issu_image)
  
            if not res:
                self.failed()
 
            countdown(40)

        countdown(100)

    # @aetest.test
    # def TrafficTest(self, testscript, testbed):
    #     log.info(banner("Starting Traffic Test After Ngoam Po Remote Fail & revert")) 
    #     #if not XconnectTrafficTest(xcon_port_handle_list):
    #     #    self.failed()
    #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
    #         pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
    #             filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
    #         countdown(300)
    #         if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
    #             self.failed(goto=['common_cleanup'])
    #         self.failed()   

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup") 
        pass


class TC0111119_Xconnect_Ngoam_conf_repl(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def XconnectCR(self, testscript, testbed):
        result_list = []
        
        if 'yes' in config_replece_test:
            for uut in [leaf4,leaf6]:
                tm = uut.execute("show clock | excl Time")
                log.info("time is ----- %r",tm)
                tm1 =  tm.replace(":","").replace(".","").replace(" ","")
                uut.configure('copy run bootflash:{name}'.format(name=tm1))
                countdown(2)
                uut.configure("no feature nv overlay")
                countdown(2)                 
                op = uut.configure('configure replace bootflash:{name}'.format(name=tm1),timeout=120)
                if not "successfully" in op:
                    self.failed(goto=['common_cleanup'])

            countdown(100)

    # @aetest.test
    # def TrafficTest(self, testscript, testbed):
    #     log.info(banner("Starting Traffic Test After Ngoam Po Remote Fail & revert")) 
    #     #if not XconnectTrafficTest(xcon_port_handle_list):
    #     #    self.failed()
    #     if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
    #         pcall(reload_with_valid_config,uut=tuple(vpc_uut_list),\
    #             filename=(vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config,vxlan_xconn_config))
    #         countdown(300)
    #         if not XconnectTrafficRateTestNew(xcon_orphan_port_handle_list,xcon_po_port_handle_list):
    #             self.failed(goto=['common_cleanup'])
    #         self.failed()   

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup") 
        pass
 
###################################################################
####                  COMMON CLEANUP SECTION                    ###
###################################################################
#
## R the BASE CONFIGURATION that was applied earlier in the
## c cleanup section, clean the left over

# cla_common_cleanup(aetest.CommonCleanup):
#   Common Cleanup for Sample Test """
#
#   est.subsection
#   common_cleanup_1(self):
#   """ Common Cleanup subsection """
#   log.info(banner("script common cleanup starts here"))
#   pass
  
 
class common_cleanup(aetest.CommonCleanup):

    @aetest.subsection
    def stop_tgn_streams(self):
        pass

    @aetest.subsection
    def disconnect_from_tgn(self):
        pass

if __name__ == '__main__':  # pragma: no cover
    aetest.main()        
 
