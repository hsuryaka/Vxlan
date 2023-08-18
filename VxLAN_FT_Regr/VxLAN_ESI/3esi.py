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
#* ------------- V X L A N  ESI  T O P O L O G Y------------
#*
#*
#*
#*                           +---+---+       
#*                           | spine1|       
#*                           |       | 
#*                           +---+---+       
#*                               |               
#*        +--------------+-------+---------+ 
#*        |              |                 |                               
#*    +-------+      +-------+         +-------+               
#*    |       |      |       |         |       |           
#*    | leaf1 |<---->| leaf2 |         | leaf3 |               
#*    |       |      |       |         |       |                  
#*    +---+---+      +---+---+         +-------+                   
#*        |  \          |   |           |                    
#*        |   \         |   |           |                        
#*        |    \        |   |           |             
#*        |     \       |   |          Orph3    
#*      Orp11    \      |   Orp21    Spirent     
#*     Spirent    \     |   Spirent              
#*                 vpc x 2                
#*                   \ |                        
#*                    \|                        
#*            +-------------+            
#*            |  switch 1   |              
#*            +-----+-------+                                                          
#*                  |                          
#*                  |                          
#*                  |                          
#*               Spirent                     
#*                                              
#*             
#*                              
#*
#*
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
#from vxlan_xconnect_lib import *
from vxlan_lib import *
from vxlan_all_lib import *

from ipaddress import *
from random import *
from string import *
import requests

#import re
from re import *
import logging
import general_lib
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

#tcl.q.package('require', 'router_show')

from pyats.async_ import pcall
 

from unicon.utils import Utils
#from rest_util import RestAction
#from routing_util import compare_string

# define variables scale numbers  feature list etc here

#vtep4 = vtep1 = vtep3 = vtep4  = sw1 = spine1 = port_handle1 = tgn1 =  0

## Scale number should be an even number

 
#countdown(13300) 

esi_id1 = '1001'
esi_id2 = '1022'
esi_id11 = '1011'
esi_id22 = '1222'
esi_mac1 = '0000.1001.1001'
esi_mac2 = '0000.1001.1022'
  
 
 

parameters = {
    'vlan_start' : 1001,
    'vni' : 201001,
    'vlan_vni_scale' : 16,
    'routed_vlan' : 101,
    'routed_vni' : 90101,
    'routing_vlan_scale': 4,
    'ipv4_add' : '5.0.0.1',
    'ipv6_add' : '5::1',
    'mcast_group': '225.5.0.1',
    'mcast_group_scale' : 4,
    'vpc_po' : '101',
    'bgp_as_number' : '65001',
    'pim_rp_address' : '1.1.1.100',
    'vtep1_mg0_ip1' : '10.127.62.235',
    'vtep2_mg0_ip1' : '10.127.62.232',
    'anycastgw' : '0000.2222.3333',
    'stp_mode' : 'mst',
    'ir_mode': 'mix',
    'test_mac1' : '00a7.0001.0001',
    'rate' : '200000'
    }

esi_po_num = "101"
esi_id =  "1100"
esi_sys_mac =  "0000.0000.1100" 
linktype = 'l3po'
igp = 'ospf'
 
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

        global linktype,pps,rate,tol,tgen,tgen_port_handle_list,vtep1,vtep2,vtep3,vtep4,sw1,activePo1,vtep8,sw2,spine1,spine2,port_handle1,port_handle2,mac_scale2,tgn1_spine1_intf1,port_handle_spine1,\
        vtep3_spine1_intf1,vtep4_spine1_intf1,vlan_vni_scale,routing_vlan_scale,vlan_range,spine1_tgn1_intf1,uutList,vlan_range,vlan_start,\
        uut_list,esi_uut_list,spine_uut_list,vtep_uut_list,l3_uut_list,esi_uut_list,sw_uut_list,tgn1_sw1_intf1,esi_uut_list,sa_vtep_uut_list,\
        port_handle_sw1,vtep_scale,leaf_tgn_ip,sw_feature_list,traffic_to_be_tested_on_number_of_vlans,port_handle_vtep5,\
        tunnel_vlan_start,tunnel_vlan_scale,tgn1_intf_list,tgn1_vtep3_intf1,tgn1_vtep5_intf1,tgn1_vtep1_intf1,port_handle_vtep1_1,port_handle_vtep1_1,mcast_group_scale,\
        labserver_ip,tgn_ip,port_handle_vtep2_1,port_handle_vtep2_1,port_handle_vtep1_2,tgn1_vtep3_intf2,tgn1_vtep1_intf2,tgn1_vtep4_intf1,tgn1_vtep2_intf1,\
        vpc_port_handle_list,xcon_po_port_handle_list,xcon_orphan_port_handle_list,port_handle_list,vxlan_traffic_test_vlan1,vxlan_traffic_test_vlan2,\
        main_uut_list,labserver_ip,tgn1_sw2_intf1,ir_mode,sw1_tgn1_intf1,vtep1_tgn1_intf1,vtep2_tgn1_intf1,map_scale,l3_uut_list,\
        vtep3_tgn1_intf1,vtep4_tgn1_intf1,vtep5_tgn1_intf1,tgn1_spine1_intf1,orphan_handle_list,vtep5,esi_vtep_uut_list,esi_po_num,esi_id,esi_sys_mac,\
        port_handle_sw1,port_handle_vtep3,port_handle_vtep1,port_handle_vtep2,port_handle_vtep3,port_handle_vtep4,port_handle_vtep5 
        #vtep3 = testbed.devices['vtep3']
        #vtep4 = testbed.devices['vtep4']
        vtep1 = testbed.devices['vtep1']
        vtep2 = testbed.devices['vtep2']
        vtep3 = testbed.devices['vtep3']
        sw1 = testbed.devices['sw1']
        spine1 = testbed.devices['spine1']
        tgn = testbed.devices['tgn1']
        uut_list = [vtep1,vtep2,vtep3,sw1,spine1]
        l3_uut_list = [vtep1,vtep2,vtep3,spine1] 
        sw_uut_list = [sw1]
        esi_uut_list = [vtep1,vtep2] 
        esi_vtep_uut_list = [vtep1,vtep2]
        spine_uut_list = [spine1]
        vtep_uut_list = [vtep1,vtep2,vtep3]
        sa_vtep_uut_list = [vtep3] 
        sw1_tgn1_intf1 = testbed.devices['sw1'].interfaces['sw1_tgn1_intf1'].intf
        vtep1_tgn1_intf1 = testbed.devices['vtep1'].interfaces['vtep1_tgn1_intf1'].intf
        vtep2_tgn1_intf1 = testbed.devices['vtep2'].interfaces['vtep2_tgn1_intf1'].intf        
        vtep3_tgn1_intf1 = testbed.devices['vtep3'].interfaces['vtep3_tgn1_intf1'].intf
        tgn1_sw1_intf1 = testbed.devices['tgn1'].interfaces['tgn1_sw1_intf1'].intf
        tgn1_vtep1_intf1 = testbed.devices['tgn1'].interfaces['tgn1_vtep1_intf1'].intf
        tgn1_vtep2_intf1 = testbed.devices['tgn1'].interfaces['tgn1_vtep2_intf1'].intf
        tgn1_vtep3_intf1 = testbed.devices['tgn1'].interfaces['tgn1_vtep3_intf1'].intf


        labserver_ip = str(testbed.devices['tgn1'].connections['labsvr'].ip)
        tgn_ip = str(testbed.devices['tgn1'].connections['a'].ip)
       
        
        tgn1_intf_list = []
        for key in testbed.devices['tgn1'].interfaces.keys():
            intf = testbed.devices['tgn1'].interfaces[key].intf
            tgn1_intf_list.append(intf)


        vlan_start=parameters['vlan_start']
        vlan_vni_scale=parameters['vlan_vni_scale']
        rate = parameters['rate']
        vni = parameters['vni']
        routed_vlan = parameters['routed_vlan']
        routed_vni = parameters['routed_vni']
        routing_vlan_scale = parameters['routing_vlan_scale']
        ipv4_add = parameters['ipv4_add']
        ipv6_add = parameters['ipv6_add']
        mcast_group = parameters['mcast_group']
        ir_mode = parameters['ir_mode']
        mcast_group_scale = parameters['mcast_group_scale']
        bgp_as_number=parameters['bgp_as_number']
        pps = int(int(rate)/vlan_vni_scale)
        vlan_range= str(vlan_start)+"-"+str(vlan_start+vlan_vni_scale-1)
        log.info('vlan_range iss-----%r',vlan_range)
 
    @aetest.subsection
    def connect(self, testscript, testbed):        
        utils = Utils()
        for uut in uut_list:
            log.info('connect to %s' % uut.alias)
            try:
                uut.connect()
                uut.execute('show version')
            except:
                log.info(banner('connect failed once ; clearing console'))
                if 'port' in uut.connections['a']:
                    ts = str(uut.connections['a']['ip'])
                    port=str(uut.connections['a']['port'])[-2:]
                    u = Utils()
                    u.clear_line(ts, port, 'lab', 'lab')
                try:
                    uut.connect()
                    uut.execute('show version')
                except:
                    self.failed(goto=['common_cleanup'])
            if not hasattr(uut, 'execute'):
                self.failed(goto=['common_cleanup'])
            if uut.execute != uut.connectionmgr.default.execute:
                self.failed(goto=['common_cleanup'])
 
 
    @aetest.subsection
    def tcam_check(self, testscript, testbed):
        for uut in vtep_uut_list: 
            if not 'FX' in uut.execute('show mod | incl Modul'):
                if 'size =    0' in uut.execute('sh hardware access-list tcam region | incl vpc-c'):
                    log.info(banner('NO VPC-CONVERGENCE TCAM'))
                if 'size =    0' in uut.execute('sh hardware access-list tcam region | incl arp-eth'):
                    log.info(banner('NO ARP-ETHER TCAM')) 
   
    
    @aetest.subsection
    def precleanup(self, testscript, testbed):
        log.info(banner("Base cleanup"))
        result = pcall(DeviceVxlanPreCleanupAll,uut=(vtep1,vtep2,vtep3,spine1))
        if not result:
            log.info('DeviceVxlanPreCleanupAll Failed ')
            self.failed(goto=['common_cleanup']) 
    
        result =  SwVxlanPreCleanup(sw1)
        if not result:
            log.info('SwVxlanPreCleanup Failed ')
            self.failed(goto=['common_cleanup'])  
    
    @aetest.subsection
    def base_configs(self, testscript, testbed):
        log.info(banner("Base configurations"))
    
        log.info(banner("Base vxlanL3NodeCommonConfig"))       
        result = pcall(vxlanL3NodeCommonConfig,uut=(vtep1,vtep2,vtep3,spine1))
    
        if not result:
            log.info('vxlanL3NodeCommonConfig Failed ')
            self.failed(goto=['common_cleanup'])           
    
    @aetest.subsection
    def gwandLoopconfigs(self, testscript, testbed):
        log.info(banner("Base configurations"))
    
        log.info(banner("Base anycastgatewayConfig"))    
        pcall(anycastgatewayConfig10,uut=(vtep1,vtep2,vtep3))
    
        log.info(banner("Base ConfigureLoopback"))    
        pcall(ConfigureLoopback,uut=(vtep1,vtep2,vtep3,spine1)) 
        pcall(secodaryipremove,uut=(vtep1,vtep2))        
    
    @aetest.subsection
    def l3_port_configs(self, testscript, testbed):
        log.info(banner(" l3_port_configs configurations"))
        pcall(underlayl3bringup,uut=(vtep1,vtep2,vtep3,spine1),\
            linktype=(linktype,linktype,linktype,linktype))
    
    @aetest.subsection
    def igp_configure(self):
        log.info(banner("igp_configure vxlanunderlayigp"))  
    
        pcall(vxlanunderlayigp,uut=(vtep1,vtep2,vtep3,spine1),\
            linktype=(linktype,linktype,linktype,linktype))
    
    @aetest.subsection
    def pim_configs(self, testscript, testbed):                                
        log.info("Configuring PIM and adding interfaces")
        pcall(vxlanpimconfigure,uut=(vtep1,vtep2,vtep3,spine1),\
            linktype=(linktype,linktype,linktype,linktype))
    
    @aetest.subsection
    def igp_verify(self, testscript, testbed):                                
        countdown(45)           
        log.info(banner("Starting IGP / PIM verify Section"))       
        for uut in l3_uut_list:
            for feature in [igp,'pim']:
                test1 = leaf_protocol_check222(uut,[feature])
                if not test1:
                    log.info('Feature %r neigborship on device %r Failed ',feature,str(uut))
                    self.failed(goto=['common_cleanup'])                     
    
    @aetest.subsection
    def shutecmp(self, testscript, testbed):      
        pcall(shutunderlayecmp,uut=(vtep1,vtep2,vtep3),\
            linktype=(linktype,linktype,linktype))
    
    
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
                
        for uut in vtep_uut_list:
            uut.configure("no feature vpc")
            countdown(5)
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
    
            #try:  
            leaf_bgp_obj=IbgpLeafNode(uut,bgp_rid,'65001',adv_nwk_list,neight_list_leaf,upd_src,'ibgp-vxlan')
            leaf_bgp_obj.bgp_conf()
        
        neight_list_spine =[]
    
        for uut in vtep_uut_list:      
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
    
    
    @aetest.subsection
    def common_verify(self, testscript, testbed):
        countdown(60)
     
        log.info(banner("Starting Common verify Section"))       
        for uut in vtep_uut_list:
            for feature in [igp,'pim','bgp']:
                test1 = leaf_protocol_check222(uut,[feature])
                if not test1:
                    log.info('Feature %r neigborship on device %r Failed ',feature,str(uut))
                    self.failed(goto=['common_cleanup'])
    
    @aetest.subsection
    def vxlan_configs(self, testscript, testbed):
        log.info(banner("VXLAN configurations")) 
    
        pcall(vxlanConfigure,uut=(vtep1,vtep2,vtep3,spine1),\
            l2_scale =(vlan_vni_scale,vlan_vni_scale,vlan_vni_scale),\
            l3_scale =(routing_vlan_scale,routing_vlan_scale,routing_vlan_scale),\
            mode=(ir_mode,ir_mode,ir_mode),\
            as_num=('65001','65001','65001'))
    
    @aetest.subsection
    def access_port_configure(self):
        log.info(banner("Configuring Ports to TGN"))
        pcall(accessPortConfigure,uut=(sw1,vtep1,vtep2,vtep3),\
            vlan_range=(vlan_range,vlan_range,vlan_range,vlan_range))
        log.info(banner("Configuring Ports Channel in Switches"))
        swPoConfigure(uut=sw1,vlan_range=vlan_range)
    
    @aetest.subsection
    def esi_bringup(self, testscript, testbed):
        log.info(banner("ESI configurations"))  
        try:
            pcall(ConfigureEsiGlobal,uut=(vtep1,vtep2))
        except:
            log.info('ConfigureEsiGlobal failed in uut %r',uut)
            self.failed(goto=['common_cleanup'])
    
        for uut in esi_uut_list: 
            esi_po_member_list = [] 
            for intf in uut.interfaces.keys():
                if 'Eth' in uut.interfaces[intf].intf:
                    if 'Po101' in uut.interfaces[intf].alias:
                        intf = uut.interfaces[intf].intf                        
                        esi_po_member_list.append(intf)  
            try:
                vtep_esi_obj1 = EsiNode(uut,esi_id,esi_sys_mac,esi_po_num,esi_po_member_list,vlan_range,'trunk')        
                vtep_esi_obj1.esi_configure()                         
            except:
                log.info('ESI Configs failed')
                return 0
        try:
            pcall(evpnmultihomingcoretracking,uut=(vtep1,vtep2),linktype=(linktype,linktype))
        except:
            log.info('ConfigureEsiGlobal failed in uut %r',uut)
            self.failed(goto=['common_cleanup'])
    
        try:
            if not pcall(esiconfcheck,uut=(vtep1,vtep2),linktype=(linktype,linktype)):
                log.info('esiconfcheck failed in uut %r',uut)
                self.failed(goto=['common_cleanup'])                
        except:
            log.info('esiconfcheck failed in uut %r',uut)
            self.failed(goto=['common_cleanup'])
    
    
    @aetest.subsection
    def esi_verify(self, testscript, testbed):       
        countdown(90)
       
        for uut in esi_uut_list:
            op=uut.execute('show port-channel summary | incl Eth')
            op1=op.splitlines()
            for line in op1:
                if line:
                    if not "(P)" in line:
                        log.info('ESI Bringup Failed on device %r',str(uut)) 
                        uut.execute('show port-channel summary')
                        self.failed(goto=['common_cleanup'])


    
    @aetest.subsection
    def configureTgn(self, testscript, testbed):
        """ common setup subsection: connecting devices """

        global tgen, tgen_port_handle_list, vtep1, vtep2, vtep3, vtep4,vtep1,vtep2, \
            sw1, sw2, spine1, port_handle1, port_handle2, port_handle,labserver_ip,port_list,\
            port_hdl_list,ip_src_list,ip_dst_list,mac_src_list,mac_dst_list,stream_list,port_handle_sw1,port_handle_vtep3,\
            port_handle_spine1,vtep_scale,tgn1_intf_list,port_handle_vtep1,port_handle_vtep2,\
            port_handle_vtep2_1,port_handle_vtep2_1,port_handle_vtep1_2,port_handle_vtep1_2,orphan_handle_list,\
            vpc_port_handle_list,port_handle_list,tgn1_vtep7_intf1,port_handle_vtep4,port_handle_vtep3,\
            port_handle_vtep5,port_handle_vtep3,tgn1_sw2_intf1,tgn1_vtep8_intf1,tgn1_spine1_intf1,\
            port_handle_sw1,port_handle_vtep3,port_handle_vtep1,port_handle_vtep2,port_handle_vtep3,port_handle_vtep4,port_handle_vtep5
  

        #port_handle = ConnectSpirent(labserver_ip,tgn_ip,[tgn1_sw1_intf1,tgn1_vtep1_intf1,tgn1_vtep2_intf1,tgn1_vtep3_intf1])
        port_list = [tgn1_sw1_intf1,tgn1_vtep1_intf1,tgn1_vtep2_intf1,tgn1_vtep3_intf1]
        result = ConnectIxia(labserver_ip,tgn_ip,port_list)
        if result == 0:
            log.info("Ixia Connection is failed")

        print(result)
        ports = result['vport_list'].split()
        port_handle_sw1 = ports[0]
        port_handle_vtep1 = ports[1]
        port_handle_vtep2 = ports[2]
        port_handle_vtep3 = ports[3]
        
        print(port_handle_sw1)
        print(port_handle_vtep1)
        print(port_handle_vtep2)
        print(port_handle_vtep3)

 
        port_handle_list = [port_handle_sw1,port_handle_vtep1,port_handle_vtep2,port_handle_vtep3]
        orphan_handle_list = [port_handle_vtep1,port_handle_vtep2]

        ip1 = '5.1.0.100'
        ip2 = '5.1.0.200'
        mac1='0011.9400.0002'
        mac2='0033.9400.0002'     
         

  
#################
  ######################################################
###                          TESTCASE BLOCK                         ###
#######################################################################
#
# Place your code that implements the test steps for the test case.
# Each test may or may not contains sections:
#           setup   - test preparation
#           test    - test action
#           cleanup - test wrap-up


class TC0002_Nve_Peer_State_Verify(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        
        log.info("Pass testcase setup")

    @aetest.test
    def check_nve_peer_state(self):

        test1 = NvePeerCheck(vtep_uut_list,1)
        if not test1:
            log.info(banner("NvePeerCheck F A I L E D"))
            #self.failed()

    @aetest.cleanup
    def cleanup(self):
        pass

class TC0003_Nve_Vni_State_Verify(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.test
    def check_nve_vni_state(self):
        for uut in vtep_uut_list:
            uut.execute('terminal length 0')

            test1 = protocolStateCheck(uut,['nve-vni'])
            if not test1:
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

 
class TC03_Vxlan_Consistency_check(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
 

    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
 
class TC04_vxlan_esi_BC_UC_Routed_Vpc_Esi_Po(aetest.Testcase):
    ###    This is description for my testcase two
  
    @aetest.setup
    def setup(self):
   

        ###################################################################
        # GENERATING BIDIR BC / MC TRAFFIC
        ###################################################################

        log.info(banner("Finding the IP address"))
        ip_sa1=str(ip_address(find_svi_ip222(vtep1,vlan_start))+10) 
        ip_sa2=str(ip_address(ip_sa1)+10) 
        ip_sa11=str(ip_address(ip_sa1)+40) 
        ip_sa22=str(ip_address(ip_sa2)+40)
        
        
        
        

        log.info(banner("----Generating hosts and flood traffic----"))
        test1= FloodTrafficGeneratorScale(port_handle_sw1,vlan_start,ip_sa1,'100.100.100.100',rate,str(vlan_vni_scale))
        test2= FloodTrafficGeneratorScale(port_handle_vtep3,vlan_start,ip_sa2,'200.200.200.200',rate,str(vlan_vni_scale))


        log.info(banner("----Generating mcast flood traffic----"))
        test1= mcastTrafficGeneratorScale(port_handle_sw1,vlan_start,ip_sa1,'239.1.1.1',rate,str(vlan_vni_scale))
        test2= mcastTrafficGeneratorScale(port_handle_vtep3,vlan_start,ip_sa2,'239.1.1.1',rate,str(vlan_vni_scale))
        

        ###################################################################
        # GENERATING BIDIR UC TRAFFIC
        ###################################################################


        log.info(banner("----Generating hosts Unicast Bidir Traffic----")) 
        SpirentBidirStream222(port_hdl1=port_handle_sw1,port_hdl2=port_handle_vtep3,vlan1=vlan_start,vlan2=vlan_start,\
        scale=vlan_vni_scale,ip1=ip_sa11,ip2=ip_sa22,gw1=ip_sa22,gw2=ip_sa11,rate_pps=rate)


        ###################################################################
        # GENERATING BIDIR ROUTED TRAFFIC
        ###################################################################

        log.info(banner("----Generating Routed Bidir Traffic----")) 

        if not SpirentRoutedBidirStream(vtep1,port_handle_sw1,port_handle_vtep3,pps):
            self.failed()

        ###################################################################
        # GENERATING BIDIR V6 UC TRAFFIC
        ###################################################################


        log.info(banner("----Generating IPV6 Unicast Traffic----")) 

        log.info(banner("Finding the IPv6 address"))
        vlan = 'vlan' + str(vlan_start)
        ipv6_sa1=str(ip_address(findIntfIpv6Addr(vtep1,vlan))+10) 
        ipv6_sa2=str(ip_address(ipv6_sa1)+100) 

        SpirentV6BidirStream(port_handle_sw1,port_handle_vtep3,vlan_start,vlan_start,vlan_vni_scale,\
            ipv6_sa1,ipv6_sa2,rate)
 
        for i in range(1,2):
            for uut in vtep_uut_list:
                uut.execute('clear ip arp vrf all')
                uut.execute('clear mac add dynamic')  


        # log.info(banner("ARP for all streams")) 
        # for i in range(1,4):
        #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
        

        log.info(banner("Starting Traffic and counting 120 seconds")) 
        #sth.traffic_control(port_handle = 'all', action = 'run')
        _result_ = ixiahlt.traffic_control(action='run',traffic_generator='ixnetwork_540',type='l23')
    

        countdown(120)
 
    @aetest.test
    def vxlan_traffic_test_all(self):        
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            # for i in range(1,4):
            #     log.info(banner("Traffic Failed once , Starting ARP Again")) 
            #     sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
            #     countdown(20)
 
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup']) 



    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 



    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """
 
 

class TC001_vxlan_esi_IR_To_Mcast_Change(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):

        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            #log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            #if not VxlanStReset(vtep_uut_list):
            #    self.failed(goto=['common_cleanup'])            
            self.failed(goto=['cleanup']) 
        #pass
    
    @aetest.test
    def ChangeIRtoMcastUUT(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut "))     
   
 
        if not ChangeIRtoMcast(vtep_uut_list,ir_mode,128,8,'225.5.0.1'):
            #mode,scale,mcast_group_scale,group_start
            log.info("Failed NveMcastGroupChange @ 2")

        countdown(120)
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

class TC001_vxlan_esi_Mcast_To_IR_Change(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):

        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            #log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            #if not VxlanStReset(vtep_uut_list):
            #    self.failed(goto=['common_cleanup'])            
            self.failed(goto=['cleanup']) 
        #pass
    
    @aetest.test
    def ChangeMcastToIRUUT(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut "))     
   
 
        if not ChangeMcastToIR(vtep_uut_list,ir_mode,128,8,'225.5.0.1'):
            #mode,scale,mcast_group_scale,group_start
            log.info("Failed NveMcastGroupChange @ 2")

        countdown(120)

        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass 
 
class TC22_vxlan_esi_nve_Bounce(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
    
    @aetest.test
    def Trigger12NveShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut "))     

        for uut in esi_vtep_uut_list:
            cmd1 = \
                """
                interface nve 1
                shut
                """
            uut.configure(cmd1)
        countdown(5)                  
        for uut in esi_vtep_uut_list:
            cmd2 = \
                """
                interface nve 1
                no shut
                """
            uut.configure(cmd2)

        countdown(180)

 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

 
class TC35_vxlan_esi_Mcast_Group_Change(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        #pass
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
        #    log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
        #    if not VxlanStReset(vtep_uut_list):
        #        self.failed(goto=['common_cleanup'])            
            self.failed(goto=['cleanup']) 
    
    
    @aetest.test
    def NveMcastGroupChange(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut "))     
   
        result_list = []
        orphan_handle_list = []
        if not NveMcastGroupChange(vtep_uut_list):
            log.info("Failed NveMcastGroupChange @ 2")
         
                       
        countdown(200)
    
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()       
 
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

 
    
    @aetest.cleanup
    def cleanup(self):
        pass 
 

class TC08_vxlan_esi_vpc_member_flap(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
    
    
    @aetest.test
    def TriggerVpcmemflap(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut "))     

        if not vPCMemberFlap(esi_uut_list,['101']):                
            self.failed()

        countdown(200)
       
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()



    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()   
    
    @aetest.cleanup
    def cleanup(self):
        pass



 
class TC09_vxlan_esi_Vn_Segment_remove_Add(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
    
    
    @aetest.test
    def VnSegmentRemoveAdd(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut "))     
   
        #result_list = []
        #orphan_handle_list = []
        if not VnSegmentRemoveAdd(vtep_uut_list,vlan_start):
            log.info("Failed NveL3VniRemoveAdd @ 2")
         
                       
        countdown(300)
       
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
 

   

    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     ##doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    
    @aetest.cleanup
    def cleanup(self):
        pass 
 
 
class TC10_vxlan_esi_Config_Replace(aetest.Testcase):
    ###    This is description for my testcase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
    

    @aetest.test
    def ConfigReplace(self):
        log.info(banner("Starting TC05_vxlan_esi_Traffic_Config_Replace"))     
             
        for uut in esi_uut_list:
            tm = uut.execute("show clock | excl Time")
            log.info("time is ----- %r",tm)
            tm1 =  tm.replace(":","").replace(".","").replace(" ","")
            uut.configure('copy run bootflash:{name}'.format(name=tm1))
            countdown(2)
            uut.configure("no feature nv overlay")
            countdown(2)                 
            op = uut.configure('configure replace bootflash:{name}'.format(name=tm1),timeout=280)
            if not "successfully" in op:
                self.failed()


        countdown(300)
 
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()


    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     #doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                # for uut in vtep_uut_list:
                #     uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
  
class TC05_vxlan_esi_Trigger_1_bgp_restart(aetest.Testcase):
    ###    This is description for my testcase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()

    @aetest.test
    def Trigger1BgpProcRestart(self):
        log.info(banner("Starting TriggerBgpProcRestart for Broadcast Encap Traffic"))     
             
        for uut in vtep_uut_list:
            for i in range(1,2):
                ProcessRestart2(uut,'bgp')

        countdown(100)
 
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()

    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
 
 
class TC06_vxlan_esi_Trigger_1_nve_restart_vpc(aetest.Testcase):
    ###    This is description for my testcase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()

    @aetest.test
    def Trigger2NveProcRestart(self, testscript, testbed):
        log.info(banner("Starting TriggerNveProcRestart for Broadcast Encap Traffic"))     

        for uut in vtep_uut_list:
            for i in range(1,2):
                ProcessRestart2(uut,'nve')

        countdown(30)

        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
 
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

  
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
 
class TC07_vxlan_esi_Trigger_1_VlanAddRemovePort_Vpc(aetest.Testcase):
    ###    This is description for my testcase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            #if not VxlanStReset(vtep_uut_list):
            #    self.failed(goto=['common_cleanup'])            
            self.failed()

     
    
    @aetest.test
    def Trigger3VlanAddRemovePort(self, testscript, testbed):
        log.info(banner("Starting Trigger1VlanAddRemove @ 5")) 
        for uut in esi_vtep_uut_list:
            if not TriggerVlanRemoveAddFromPort(uut,'Po101',vlan_range,3):
                log.info("TriggerPortVlanRemoveAdd failed @ 2")
                self.failed()

        countdown(240)

        test1=SpirentRateTest22(port_handle_sw1,port_handle_vtep3,int(rate)*4,int(pps))
        

        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            #if not VxlanStReset(esi_vtep_uut_list):
            #    self.failed(goto=['common_cleanup'])            
            self.failed() 

    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
    
 

class TC08_vxlan_esi_flap(aetest.Testcase):
    ###    This is description for my testcase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()

    
    @aetest.test
    def Trigger4AccessPortFlap(self, testscript, testbed):
        log.info(banner("Starting Trigger2PortFlap @ 8"))          

        for uut in [vtep1,vtep2]:
            if not TriggerPortFlap(uut,'po101',3):
                log.info("TriggerPortFlap failed @ 4")
                self.failed()
        countdown(160)
 
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()

    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
  


class TC09_vxlan_esi_Esi_Core_flap(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
         
 
    @aetest.test
    def Trigger5CoreIfFlap(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))          
        result =  pcall(L3InterfaceFlap,uut=tuple(esi_vtep_uut_list),igp=(igp,igp)) 

        if not result: 
            log.info("TriggerCoreIfFlap222 failed @ 4")
            self.failed()
    
        countdown(180)

 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()

    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 
  
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
    
 
  
class TC10_vxlan_esi_ClearIpRoute(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
 
    @aetest.test
    def Trigger6ClearIpRoute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))         

        for uut in esi_vtep_uut_list:
            for i in range(1,3):
                uut.execute("clear ip route *")
 
        countdown(160)
        
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()

    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 
  
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


 
 

class TC11_vxlan_esi_ClearIpMoute(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
         
 
    @aetest.test
    def Trigger7ClearIpMroute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))     


        for uut in esi_vtep_uut_list:
            for i in range(1,3):
                uut.execute("clear ip mroute *")
    
        countdown(160)

        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

  
 

class TC12_vxlan_esi_Clear_IGP(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
 
    @aetest.test
    def Trigger8ClearOspfNeigh(self, testscript, testbed):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))     

        for uut in esi_vtep_uut_list:
            for i in range(1,3):
                if 'ospf' in igp:
                    uut.execute("clear ip ospf neighbor *")
                elif 'isis' in igp:
                    uut.execute("clear isis adjacency *")
    
        countdown(180)
 
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC13_vxlan_esi_Clear_IP_Bgp(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()

    @aetest.test
    def Trigger9ClearIpBgp(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))     


        for uut in esi_vtep_uut_list:
            for i in range(1,3):
                uut.execute("clear ip bgp *")
     
        countdown(180)
 
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC14_vxlan_esi_Clear_Bgp_l2vpn(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
    

 
    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting TriggerClearBgpL2vpnEvpn @ "))     

        for uut in esi_vtep_uut_list:
            for i in range(1,3):
                uut.execute("clear bgp l2vpn evpn *")

        countdown(180)

 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


 

class TC15_vxlan_esi_Spine_ClearIpRoute(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()

    @aetest.test
    def Trigger6ClearIpRoute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))         

        for uut in spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip route *")
 
        countdown(160)
        
 
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

      
class TC16_vxlan_esi_Spine_ClearIpMoute(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
         

    @aetest.test
    def Trigger7ClearIpMroute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))     

        for uut in spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip mroute *")

        countdown(160)

 
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC17_vxlan_esi_Spine_Clear_IGP(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
   
    @aetest.test
    def Trigger8ClearOspfNeigh(self, testscript, testbed):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))     

        for uut in spine_uut_list:
            for i in range(1,3):
                if 'ospf' in igp:
                    uut.execute("clear ip ospf neighbor *")
                elif 'isis' in igp:
                    uut.execute("clear isis adjacency *")
    
        countdown(320)
 
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
     
class TC18_vxlan_esi_Spine_Clear_IP_Bgp(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()

    @aetest.test
    def Trigger9ClearIpBgp(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))     


        for uut in spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip bgp *")
     
        countdown(320)
 
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
      
class TC19_vxlan_esi_Spine_Clear_Bgp_l2vpn(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
 
    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting Trigger10ClearBgpL2vpnEvpn @ spine"))     
        for uut in spine_uut_list:
            for i in range(1,3):
                uut.execute("clear bgp l2vpn evpn *")
                #uut.execute(' clear bgp all *')
        countdown(320)
 
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()

    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
        
 
class TC20_vxlan_esi_Clear_ARP_MAC(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
 
    @aetest.test
    def Trigger11ClearArpMac(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac @ "))     

        for uut in esi_vtep_uut_list:
            for i in range(1,5):
                uut.execute("clear ip arp vrf all")
                uut.execute("clear mac add dy")                              

        countdown(180)
 
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
        


class TC21_vxlan_esi_Clear_ARP_MAC(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()

 
    @aetest.test
    def Trigger11ClearArpMac(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac esi"))     
        for uut in esi_vtep_uut_list:
            for i in range(1,5):
                uut.execute("clear ip arp vrf all")
                uut.execute("clear mac add dy")                              

        countdown(180)
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed() 
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC22_vxlan_esi_nve_Bounce(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
    
    @aetest.test
    def Trigger12NveShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut "))     

        for uut in esi_vtep_uut_list:
            cmd1 = \
                """
                interface nve 1
                shut
                """
            uut.configure(cmd1)
        countdown(5)                  
        for uut in esi_vtep_uut_list:
            cmd2 = \
                """
                interface nve 1
                no shut
                """
            uut.configure(cmd2)

        countdown(180)

 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

class TC23_vxlan_esi_vlan_bounce(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
    @aetest.test
    def Trigger15VlanShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger15VlanShutNoshut "))     
        for uut in esi_vtep_uut_list:
            vlanshut = \
            """
            vlan 1001-1005
            shut
            exit
            """
            uut.configure(vlanshut,timeout=380)
        countdown(5)
        for uut in esi_vtep_uut_list:
            vlannoshut = \
            """
            vlan 1001-1005
            no shut
            exit
            """
            uut.configure(vlannoshut,timeout=380)                   

        countdown(160)

 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
class TC25_vxlan_esi_1Leg_Down(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
     
 
    @aetest.test
    def Trigger13Zflow1(self, testscript, testbed):
        log.info(banner("Starting Trigger13Zflow1"))     

        poshut = \
            """
            interface po{po}
            shut
            """
        ponoshut = \
            """
            interface po{po}
            no shut
            """

        for intf in vtep1.interfaces.keys():
            if 'esi_po' in vtep1.interfaces[intf].type:
                esi_po = vtep1.interfaces[intf].intf
                vtep1.configure(poshut.format(po=esi_po)) 

        for intf in vtep1.interfaces.keys():
            if 'l3_po' in vtep1.interfaces[intf].type:
                l3po6 = vtep1.interfaces[intf].intf
                vtep1.configure(poshut.format(po=l3po6)) 
 
        countdown(160)
 
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),[port_handle_vtep2]):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            self.failed() 

        for intf in vtep1.interfaces.keys():
            if 'esi_po' in vtep1.interfaces[intf].type:
                esi_po = vtep1.interfaces[intf].intf
                vtep1.configure(ponoshut.format(po=esi_po)) 

        for intf in vtep1.interfaces.keys():
            if 'l3_po' in vtep1.interfaces[intf].type:
                l3po6 = vtep1.interfaces[intf].intf
                vtep1.configure(ponoshut.format(po=l3po6)) 

        countdown(160)
 
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            self.failed() 
 
    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

 
class TC26_vxlan_esi_1Leg_Down2(aetest.Testcase):
    ###    This is description for my tecase two

  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
    
    @aetest.test
    def Trigger14Zflow2(self, testscript, testbed):
        log.info(banner("Starting Trigger14Zflow2 "))     

        poshut = \
            """
            interface po{po}
            shut
            """
        ponoshut = \
            """
            interface po{po}
            no shut
            """

        for intf in vtep2.interfaces.keys():
            if 'esi_po' in vtep2.interfaces[intf].type:
                esi_po = vtep2.interfaces[intf].intf
                vtep2.configure(poshut.format(po=esi_po)) 

        for intf in vtep2.interfaces.keys():
            if 'l3_po' in vtep2.interfaces[intf].type:
                l3po5 = vtep2.interfaces[intf].intf
                vtep2.configure(poshut.format(po=l3po5))



        countdown(150)
      
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),[port_handle_vtep1]):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            self.failed() 


        for intf in vtep2.interfaces.keys():
            if 'esi_po' in vtep2.interfaces[intf].type:
                esi_po = vtep2.interfaces[intf].intf
                vtep2.configure(ponoshut.format(po=esi_po)) 

        for intf in vtep2.interfaces.keys():
            if 'l3_po' in vtep2.interfaces[intf].type:
                l3po5 = vtep2.interfaces[intf].intf
                vtep2.configure(ponoshut.format(po=l3po5))



        countdown(150)

 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            self.failed() 


    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

        
    
    @aetest.cleanup
    def cleanup(self):
        pass

   
 
class TC27_VXLAN_esi_trigger_nve_loop_shutnoshut(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
    
    @aetest.test
    def TriggerNveloopShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut "))     

        for uut in esi_uut_list:
            cmd1 = \
                """
                interface loopb 0
                shut
                sleep 5
                interface loopb 0
                no shut
                """
            uut.configure(cmd1)

        countdown(180)
      
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            self.failed() 

    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()         
    
    @aetest.cleanup
    def cleanup(self):
        pass
       

class TC26_vxlan_esi_ethpm_restart(aetest.Testcase):
    ###    This is description for my testcase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):           
            self.failed()

    @aetest.test
    def Trigger1BgpProcRestart(self):
        log.info(banner("Starting TriggerBgpProcRestart for Broadcast Encap Traffic"))     
             
        for uut in esi_uut_list:
            for i in range(1,1):
                ProcessRestart2(uut,'ethpm')

        countdown(100)
 
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()


    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()  

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC26_vxlan_esi_vlan_mgr_restart(aetest.Testcase):
    ###    This is description for my testcase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):           
            self.failed()

    @aetest.test
    def Trigger1BgpProcRestart(self):
        log.info(banner("Starting TriggerBgpProcRestart for Broadcast Encap Traffic"))     
             
        for uut in esi_uut_list:
            for i in range(1,1):
                ProcessRestart2(uut,'vlan_mgr')

        countdown(100)
 
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()


    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()  

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass       
 
 


class TC06_vxlan_esi_nve_loop_Ip_change(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
    

    
    @aetest.test
    def TrigNveSourceIpChange(self, testscript, testbed):
        log.info(banner("Starting TrigNveSourceIpChange "))     

        if not NveSourceIpChange(vtep_uut_list,'65001','Loopback0'):
            self.failed() 
    
        countdown(300)

        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()


    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 


class TC24_VXLAN_esi_trigger_vlan_remove_add(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
    
    @aetest.test
    def TriggerVlan_remove_add(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut "))     

        for uut in esi_uut_list:
            vlan_conf_string = uut.execute("show run vlan | beg 'vlan 1001'")

            remove_vlan = \
            """
            no vlan {range}
            """
            uut.configure(remove_vlan.format(range=vlan_range),timeout=200)
            countdown(5)
            uut.configure(vlan_conf_string,timeout=200) 
            
        countdown(200)
       
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()         
    
    @aetest.cleanup
    def cleanup(self):
        pass

class TC05_vxlan_esi_Core_Ip_Change(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
    
    @aetest.test
    def CoreIPAddressChange(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut "))     
   
        #result_list = []
        #orphan_handle_list = []
        if not CoreIPAddressChangeNew(l3_uut_list,igp):
            log.info("Failed CoreIPAddressChange @ 2")
         
                       
        countdown(300)
       
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()
 

   

    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    
    @aetest.cleanup
    def cleanup(self):
        pass 

 

class TC07_vxlan_esi_nve_source_interface_change(aetest.Testcase):
    ###    This is description for my tecase two
  
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            self.failed()
    
    
    @aetest.test
    def TrigNveSourceInterfaceChange(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut "))     

        #if not NveSourceInterfaceChange(vtep_uut_list,'65001'):
        #    self.failed() 
    
        countdown(300)
 
        if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(vtep_uut_list):
                self.failed(goto=['common_cleanup'])            
            if not AllTrafficTestMsite(port_handle_sw1,port_handle_vtep3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])            
            self.failed()


    @aetest.test
    def ConsistencyCheckerL2(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHMac(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh mac-addresses')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                # for i in range(1,3):
                #     doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.test
    def ConsistencyCheckerMHPath(self, testscript, testbed):                
        for uut in esi_uut_list:
            check = uut.execute('show consistency-checker vxlan mh pathlist')
            if not 'eck: PASSED' in check:
                for uut in vtep_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed() 

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


 
class TC40_vxlan_esi_arp_suppression_test(aetest.Testcase):
    ###    This is description for my testcase two
  
    @aetest.setup
    def setup(self):
        log.info(banner("-----STOP ALL STREAMS---"))
        pcall (arp_supp_add_final,uut=(vtep1,vtep2,vtep3))
      
        countdown(10)

        for uut in vtep_uut_list:
            count = uut.execute('show nve vni | incl SA | count')
            if int(count)<int(vlan_vni_scale):
                log.info(banner("SA not enabled in all VNI's"))
                self.failed()
        '''
        for port_hdl in  port_handle_list:
            traffic_ctrl_ret = sth.traffic_control(port_handle = port_hdl, action = 'stop', db_file=0 ) 
            traffic_ctrl_ret = sth.traffic_control(port_handle = port_hdl, action = 'reset') 

        log.info(banner("-----CLEAR MAC ARP TABLES---"))

        for uut in vtep_uut_list+sw_uut_list:
            uut.configure('system no hap-reset ')
            for i in range(1,2):
                uut.execute('clear mac address-table dynamic')
                uut.execute('clear ip arp vrf all')


        log.info(banner("----VERIFY PEER--"))

        VxlanStArpGen(port_handle_list,'1001','5.1.255.230','5.1.255.240','00a7.0001.0001',1,1)
        #test1 = NvePeerLearning2(port_handle_list,vlan_start,vtep_uut_list,3+int(vtep_scale),'111.0.')
        #if not test1:
        #    log.info(banner("NvePeerLearning F A I L E D"))
        #    self.failed()

        test1 = NvePeerLearning2(port_handle_list,vlan_start,vtep_uut_list,1,'111.0.')
        if not test1:
            log.info(banner("NvePeerLearning F A I L E D"))
            #self.failed(goto=['common_cleanup'])



        log.info(banner("----POPULATE ARP CACHE--"))          
        ip1=str(ip_address(find_svi_ip222(vtep1,vlan_start))+10) 
        ip2=str(ip_address(ip1)+100) 
        mac1='0011.9400.0002'
        mac2='0033.9400.0002'        
        ip11=str(ip_address(ip1)+10) 
        ip22=str(ip_address(ip2)+10) 
        mac11='0011.9411.0002'
        mac22='0033.9433.0002'     



        #for count in (0,int(vlan_vni_scale)):

        FloodTrafficGeneratorScaleArp(port_handle_sw1,vlan_start,ip1,ip2,1,vlan_vni_scale,mac1)
        FloodTrafficGeneratorScaleArp(port_handle_vtep3,vlan_start,ip2,ip1,1,vlan_vni_scale,mac2)
 
        ArpSuppressTrafficGenerator(port_handle_sw1,vlan_start,ip11,ip2,mac11,1000*int(vlan_vni_scale),int(vlan_vni_scale))
        ArpSuppressTrafficGenerator(port_handle_vtep3,vlan_start,ip22,ip1,mac22,1000*int(vlan_vni_scale),int(vlan_vni_scale))

        for i in range(1,5):
            doarp = sth.arp_control(arp_target='all',arpnd_report_retrieve='1')
        countdown(30)
        log.info(banner("----VERIFY ARP CACHE TABLES--"))   

        for uut in esi_uut_list:
            count=uut.execute("show ip arp vrf all | incl '0011.9400' | count")
            if int(count) < int(vlan_vni_scale):
                self.failed()

        for uut in sa_vtep_uut_list:
            count=uut.execute("show ip arp vrf all | incl '0033.9400' | count")
            if int(count) < int(vlan_vni_scale):
                self.failed()

        for uut in vtep_uut_list:
            op1=uut.execute('show ip arp suppression-cache summary | json-pretty')
            op2=json.loads(op1)
            remote_arp_count = op2["TABLE_arp-suppression"]['ROW_arp-suppression']\
            ['TABLE_summary']['ROW_summary']['remote-count']
            if int(remote_arp_count) < int(vlan_vni_scale):
                self.failed()
   
    @aetest.test
    def ArpTrafficTest(self, testscript, testbed):
 
        log.info(banner("----GENERATE ARP TRAFFIC--"))   

        log.info(banner("----Starting ARP TRAFFIC--"))   
        sth.traffic_control(port_handle = [port_handle_sw1,port_handle_vtep3], action = 'stop')
        countdown(5)
        sth.traffic_control(port_handle = [port_handle_sw1,port_handle_vtep3], action = 'run')
        countdown(30)
        log.info(banner("----Starting ARP TRAFFIC rate test--"))   

        if not SpirentArpRateTest([port_handle_sw1,port_handle_vtep3],orphan_handle_list,1000*int(vlan_vni_scale),1000,'on'):
            log.info(banner("Rate test fail for ARP Traffic"))         
            self.failed() 

        if not CheckUplinkRate(vtep_uut_list,igp,600):
            log.info(banner("Rate test should fail for ARP Traffic"))            
            self.failed()
 
    @aetest.test
    def ArpTrafficTestSAremoved(self, testscript, testbed): 
        log.info(banner("----Remove Suppress--")) 
        for uut in vtep_uut_list: 
            #arp_supp_remove(uut,201001,int(vlan_vni_scale),ir_mode)
            arp_supp_remove_final(uut)
            #    self.failed()


        for uut in vtep_uut_list:
            count = uut.execute('show nve vni | incl SA | count')
            if int(count) > 2:
                log.info(banner("SA not disabled in all VNI's"))
                self.failed()

        countdown(10)
        if not SpirentArpRateTest([port_handle_sw1,port_handle_vtep3],orphan_handle_list,1000*int(vlan_vni_scale),1000,'off'):
            log.info(banner("Rate test fail for ARP Traffic"))         
            self.failed() 

    @aetest.test
    def ArpTrafficTestSAAdded(self, testscript, testbed): 
        log.info(banner("----Start ArpTrafficTestSAAdded --")) 

        for uut in vtep_uut_list: 
            #arp_supp_add(uut,201001,int(vlan_vni_scale),ir_mode)
            arp_supp_add_final(uut)
        for uut in vtep_uut_list:
            count = uut.execute('sh nve vni | incl SA | count')
            if int(count)<int(vlan_vni_scale):
                log.info(banner("SA not enabled in all VNI's"))
                self.failed()
 
        for i in range(1,5):
            log.info("ARP All streams")
            doarp = sth.arp_control(arp_target='all',arpnd_report_retrieve='1')
        countdown(20)
        log.info(banner("----VERIFY ARP CACHE TABLES--"))   
        for uut in esi_uut_list:
            count=uut.execute("show ip arp vrf all | incl '0011.9400' | count")
            if int(count) < int(vlan_vni_scale):
                log.info("ARP Entries are not full in %r, Expected : %r, Availables : %r",uut,vlan_vni_scale,count)
                self.failed()
        for uut in sa_vtep_uut_list:
            count=uut.execute("show ip arp vrf all | incl '0033.9400' | count")
            if int(count) < int(vlan_vni_scale):
                log.info("ARP Entries are not full in %r, Expected : %r, Availables : %r",uut,vlan_vni_scale,count)
                self.failed()
        for uut in vtep_uut_list:
            op1=uut.execute('show ip arp suppression-cache summary | json-pretty')
            op2=json.loads(op1)
            remote_arp_count = op2["TABLE_arp-suppression"]['ROW_arp-suppression']\
            ['TABLE_summary']['ROW_summary']['remote-count']
            if int(remote_arp_count) < int(vlan_vni_scale):
                log.info("ARP SA table is not full in %r, Expected : %r, Availables : %r",uut,vlan_vni_scale,remote_arp_count)
                for uut in vtep_uut_list:
                    uut.execute("show ip arp suppression-cache detail")
                    uut.execute("show ip arp vrf all")
                self.failed()
 
        log.info(banner("----Starting ARP TRAFFIC rate test--"))   

   
        if not SpirentArpRateTest([port_handle_sw1,port_handle_vtep3],orphan_handle_list,1000*int(vlan_vni_scale),1000,'on'):
            log.info(banner("Rate test fail for ARP Traffic"))         
            self.failed() 

        if not CheckUplinkRate(vtep_uut_list,igp,600):
            log.info(banner("Rate test should fail for ARP Traffic"))            
            self.failed()
        
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
    '''
 
 
class common_cleanup(aetest.CommonCleanup):

    @aetest.subsection
    def stop_tgn_streams(self):
        pass
    
    @aetest.subsection
    def stop_tgn_streams(self):
        pass
        #for port_hdl in  port_handle_list:
        #    traffic_ctrl_ret = sth.traffic_control(port_handle = port_hdl, action = 'stop', db_file=0 ) 
        #    traffic_ctrl_ret = sth.traffic_control(port_handle = port_hdl, action = 'reset') 
 


    #@aetest.subsection
    #def disconnect_from_tgn(self):
        #general_lib.cleanup_tgn_config(cln_lab_srvr_sess = 1)
        #pass

if __name__ == '__main__':  # pragma: no cover
    aetest.main()
 

 
  
      


