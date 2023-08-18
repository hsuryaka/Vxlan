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
#* ------------- V X L A N  TEST  T O P O L O G Y------------
#*
#*
#*
#*                      Evpn-Vtep-Simulator
#*                           ( Spirent )
#*                               |
#*                               |
#*                               |
#*                               |
#*                           +---+---+
#*                           | spine1|
#*      examp                     |
#*                           +---+---+
#*                               |               |
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
import genie
#from ats.log.utils import banner
#from ats import tcl
#import sth
#from sth import StcPython

from pyats.async_ import pcall

from ats import topology

from ats import aetest
from ats.topology import loader
#from vxlan_macmove_lib import *
#from vxlan_xconnect_lib import *
from vxlan_all_lib import *
#from vxlan_ir_lib import *

from ipaddress import *
from random import *
from string import *
import requests
import pexpect

from unicon.eal.dialogs import Dialog
from unicon.eal.dialogs import Statement

#import re
from re import *
import logging
import general_lib
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

#tcl.q.package('require', 'router_show')

from unicon.utils import Utils
#from rest_util import RestAction
#from routing_util import compare_string
from genie.conf import Genie
from genie.conf.tests import TestCase
from genie.conf.base import Testbed, Device
from genie.conf.base import Interface,Link
from genie.libs.conf.interface.nxos import Interface
from genie.libs.conf.ospf.nxos.ospf import Ospf
from genie import testbed

#countdown(25000)




parameters = {
    'vlan_start' : 1001,
    'vni' : 101001,
    'vlan_vni_scale' : 128,
    'routed_vlan' : 101,
    'routed_vni' : 90101,
    'routing_vlan_scale': 16,
    'ipv4_add' : '5.0.0.1',
    'ipv6_add' : '5::1',
    'mcast_group': '225.5.0.1',
    'mcast_group_scale' : 16,
    'vpc_po' : '101',
    'bgp_as_number' : '65001',
    'pim_rp_address' : '1.1.1.100',
    'vtep1_mg0_ip1' : '10.127.62.235',
    'vtep2_mg0_ip1' : '10.127.62.232',
    'anycastgw' : '0000.2222.3333',
    'stp_mode' : 'mst',
    'test_mac1' : '00a7.0001.0001',
    'rate' : '200000',
    'tolerence' : 3000,
    'igp' : 'isis',
    'ipv6enable' : 'yes',
    'spine_interface' : 'normal',
    'spine_interface_ip' : 'unnumbered',
    'dci_interface' : 'normal',
    'dci_interface_ip' : 'normal',
    'site1_group1' : '239.11.11.11',
    'site2_group1' : '239.21.21.21',
    'site3_group1' : '239.31.31.31',
    'group_scale_per_port' : '4', 
    'ir_mode' : 'mcast'

    #'dci_interface' : ''port-channel',
    #'dci_interface_ip' : 'unnumbered',
    #'spine_interface' : 'svi',
    #'spine_interface' : 'port-channel',
    #'spine_interface_ip' : 'normal',
    #'igp' : 'isis'    
    }
 

site1_group1 = '239.11.11.11'
site2_group1 = '239.21.21.21'
site3_group1 = '239.31.31.31'
group_list = [site1_group1]+[site2_group1]+[site3_group1]
group_scale_per_port = 1

igp = 'isis'
vtep_emulation_spirent = 'no'
vtep_emulation_msite_spirent = 'yes'
vtep_scale = 12
test_l3_vlan_scale = 2
test_rate = int(test_l3_vlan_scale)*16000*int(group_scale_per_port)

traffic_profile = 'trm' # 'full'




###################################################################
####                 COMMON SETUP SECTION                       ###
###################################################################

# Configure and setup all devices and test equipment in this section.
# This should represent the BASE CONFIGURATION that is applicable
# for the bunch of test cases that would follow.

 
class common_setup(aetest.CommonSetup):
    """ Common Setup """
    @aetest.subsection
    def testbed_init(self, testscript, testbed):
        global traffic_profile,vtep_emulation_msite_spirent,rateFull,rateOrphan,site1_group1,site2_group1,site3_group1,ir_mode,vtep_emulation_spirent,vtep_scale,\
        igp,uut_list,leaf_uut_list,spine_uut_list,bgw_uut_list,sw_uut_list,l3_uut_list,l3_site_uut_list,\
        site1_uut_list,site1_leaf_uut_list,site1_spine_uut_list,site1_bgw_uut_list,site1_sw_uut_list,trm_port_handle_list,group_scale_per_port,\
        site2_uut_list,site2_leaf_uut_list,site2_spine_uut_list,site2_bgw_uut_list,site2_sw_uut_list,test_l3_vlan_scale,\
        site3_uut_list,site3_leaf_uut_list,site3_spine_uut_list,site3_bgw_uut_list,site3_sw_uut_list,dci_uut_list,\
        tgn1_sw1site2_intf1,tgn1_sw1site3_intf1,tgn1_bgw1site2_intf1,tgn1_bgw2site2_intf1,tgn1_sw1site1_intf1,rate_list_trm,\
        orphan_handle_list,orphan_handle_list_sa,port_handle_list,labserver_ip,tgn1_dci1_intf1,tgn_ip,test_rate,group_list,\
        vlan_start,vlan_vni_scale,rate,tolerence,vni,routed_vlan,routed_vni,routing_vlan_scale,tgn1_spine2site1_intf1,port_handle_spine2site1,\
        ipv4_add,ipv6_add,mcast_group,mcast_group_scale,bgp_as_number,pps,vlan_range,tgn1_bgw1site1_intf1,tgn1_bgw1site3_intf1,tgn1_bgw2site3_intf1


        uut_list = [];leaf_uut_list = [];spine_uut_list =[] ;bgw_uut_list =[];sw_uut_list=[] ; dci_uut_list = [];\
        site1_uut_list = []; site1_leaf_uut_list =[]; site1_spine_uut_list = [];site1_bgw_uut_list =[] ;site1_sw_uut_list =[];\
        site2_uut_list = []; site2_leaf_uut_list =[]; site2_spine_uut_list = [];site2_bgw_uut_list =[] ;site2_sw_uut_list =[];\
        site3_uut_list = []; site3_leaf_uut_list =[]; site3_spine_uut_list = [];site3_bgw_uut_list =[] ;site3_sw_uut_list =[]


        tgn1_dci1_intf1 = testbed.devices['tgn1'].interfaces['tgn1_dci1_intf1'].intf
        tgn1_sw1site2_intf1 = testbed.devices['tgn1'].interfaces['tgn1_sw1site2_intf1'].intf
        tgn1_sw1site3_intf1 = testbed.devices['tgn1'].interfaces['tgn1_sw1site3_intf1'].intf
        tgn1_sw1site1_intf1 = testbed.devices['tgn1'].interfaces['tgn1_sw1site1_intf1'].intf
        tgn1_bgw1site1_intf1 = testbed.devices['tgn1'].interfaces['tgn1_bgw1site1_intf1'].intf
        tgn1_bgw1site2_intf1 = testbed.devices['tgn1'].interfaces['tgn1_bgw1site2_intf1'].intf
        tgn1_spine2site1_intf1 = testbed.devices['tgn1'].interfaces['tgn1_spine2site1_intf1'].intf
        #tgn1_bgw2site2_intf1 = testbed.devices['tgn1'].interfaces['tgn1_bgw2site2_intf1'].intf
        #tgn1_bgw1site3_intf1 = testbed.devices['tgn1'].interfaces['tgn1_bgw1site3_intf1'].intf
        #tgn1_bgw2site3_intf1 = testbed.devices['tgn1'].interfaces['tgn1_bgw2site3_intf1'].intf

        labserver_ip = str(testbed.devices['tgn1'].connections['labsvr'].ip)
        tgn_ip = str(testbed.devices['tgn1'].connections['a'].ip)

 
        for device in testbed.devices:
            if not 'image' in device:
                if not 'tgn' in device:
                    uut_list.append(testbed.devices[device])

        for device in testbed.devices:
            if 'dci' in (testbed.devices[device].alias):
                dci_uut_list.append(testbed.devices[device])

            elif 'site1' in (testbed.devices[device].alias):
                site1_uut_list.append(testbed.devices[device])
                if 'leaf' in (testbed.devices[device].alias):
                    site1_leaf_uut_list.append(testbed.devices[device])
                    leaf_uut_list.append(testbed.devices[device])
                elif 'spine' in (testbed.devices[device].alias):
                    site1_spine_uut_list.append(testbed.devices[device])
                    spine_uut_list.append(testbed.devices[device])
                elif 'bgw' in (testbed.devices[device].alias):
                    site1_bgw_uut_list.append(testbed.devices[device])
                    bgw_uut_list.append(testbed.devices[device])
                elif 'sw' in (testbed.devices[device].alias):
                    site1_sw_uut_list.append(testbed.devices[device])
                    sw_uut_list.append(testbed.devices[device])

            elif 'site2' in (testbed.devices[device].alias):
                site2_uut_list.append(testbed.devices[device])
                if 'leaf' in (testbed.devices[device].alias):
                    site2_leaf_uut_list.append(testbed.devices[device])
                    leaf_uut_list.append(testbed.devices[device])
                elif 'spine' in (testbed.devices[device].alias):
                    site2_spine_uut_list.append(testbed.devices[device])
                    spine_uut_list.append(testbed.devices[device])
                elif 'bgw' in (testbed.devices[device].alias):
                    site2_bgw_uut_list.append(testbed.devices[device])
                    bgw_uut_list.append(testbed.devices[device])
                elif 'sw' in (testbed.devices[device].alias):
                    site2_sw_uut_list.append(testbed.devices[device])
                    sw_uut_list.append(testbed.devices[device])

            elif 'site3' in (testbed.devices[device].alias):
                site3_uut_list.append(testbed.devices[device])
                if 'leaf' in (testbed.devices[device].alias):
                    site3_leaf_uut_list.append(testbed.devices[device])
                    leaf_uut_list.append(testbed.devices[device])
                    log.info('site3_leaf_uut_list ----%r',site3_leaf_uut_list)
                elif 'spine' in (testbed.devices[device].alias):
                    site3_spine_uut_list.append(testbed.devices[device])
                    spine_uut_list.append(testbed.devices[device])
                elif 'bgw' in (testbed.devices[device].alias):
                    site3_bgw_uut_list.append(testbed.devices[device])
                    bgw_uut_list.append(testbed.devices[device])
                    log.info('site3_bgw_uut_list ----%r',site3_bgw_uut_list)
                elif 'sw' in (testbed.devices[device].alias):
                    site3_sw_uut_list.append(testbed.devices[device])
                    sw_uut_list.append(testbed.devices[device])

        l3_uut_list = leaf_uut_list + spine_uut_list + bgw_uut_list + dci_uut_list
        l3_site_uut_list = leaf_uut_list + spine_uut_list + bgw_uut_list

        vlan_start=parameters['vlan_start']
        vlan_vni_scale=parameters['vlan_vni_scale']
        rate = parameters['rate']
        tolerence = parameters['tolerence']
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
        log.info('test_rate is %r',test_rate)

        if 'full' in traffic_profile:
            rateFull = int(rate)*4+int(test_rate)    
            rateOrphan = int(rate)*2+int(test_rate)

        elif 'trm' in traffic_profile:
            rateFull =  test_rate  
            rateOrphan = test_rate
        
        rate_list_trm = [rateFull,rateFull,rateOrphan]

    @aetest.subsection
    def connect(self, testscript, testbed):
        for uut in uut_list: 
        #for uut in uut_list: 
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
                    uut.connect(connection_timeout=700)
                except:
                    self.failed(goto=['common_cleanup'])
            if not hasattr(uut, 'execute'):
                self.failed(goto=['common_cleanup'])
            if uut.execute != uut.connectionmgr.default.execute:
                self.failed(goto=['common_cleanup'])

        log.info('site1_group1 is %r',site1_group1)

    '''
    @aetest.subsection
    def precleanup(self, testscript, testbed):
        log.info(banner("Base cleanup"))

        try: 
            pcall(DeviceVxlanPreCleanupAll,uut=tuple(l3_uut_list))
            pcall(SwVxlanPreCleanup,uut=tuple(sw_uut_list))
        except:
            log.info('precleanup Failed ')
            self.failed(goto=['common_cleanup'])   
 
    @aetest.subsection
    def base_configs(self, testscript, testbed):
        log.info(banner("Base configurations"))

        try:       
            pcall(vxlanL3NodeCommonConfig,uut=tuple(l3_uut_list))
        except:
            log.info('base_configs Failed ')
            self.failed(goto=['common_cleanup']) 
 
    @aetest.subsection
    def gwandLoopconfigs(self, testscript, testbed):
        log.info(banner("Base gwandLoopconfigs"))
        try:     
            pcall(anycastgatewayConfig10,uut=tuple(leaf_uut_list+bgw_uut_list))   
            pcall(ConfigureLoopback,uut=tuple(l3_uut_list))
        except:
            log.info('gwandLoopconfigs Failed ')
            self.failed(goto=['common_cleanup']) 
 
    @aetest.subsection
    def l3_port_configs(self, testscript, testbed):
        log.info(banner("Base l3_port_configure"))  
        try:
            pcall(ConfigureL3PortvxlanMultisite,uut=tuple(l3_uut_list))
        except:
            log.info('l3_port_configs Failed ')
            self.failed(goto=['common_cleanup']) 
 
    @aetest.subsection
    def igp_configure(self):     
        log.info(banner("igp_configure ConfigureIgpvxlanMultisite"))  
        try:
            pcall(ConfigureIgpvxlanMultisite,uut=tuple(l3_site_uut_list),\
            igp=(igp,igp,igp,igp,igp,igp,igp,igp,igp,igp,igp))
        except:
            log.info('igp_configure Failed ')
            self.failed(goto=['common_cleanup']) 
            
        countdown(60)  
        log.info(banner("Starting igp verify Section"))
        for uut in leaf_uut_list+bgw_uut_list+spine_uut_list:
            test1 = protocolStateCheck(uut,[igp])
            if not test1:
                log.info('Feature %r neigborship on device %r Failed ',igp,str(uut))
                self.failed(goto=['common_cleanup'])
   
    @aetest.subsection  
    def pim_configure(self):
        log.info(banner("pim_configure"))  
        for spine_list,leaf_list,bgw_list in zip([site1_spine_uut_list,site2_spine_uut_list],\
            [site1_leaf_uut_list ,site2_leaf_uut_list],\
            [site1_bgw_uut_list,site2_bgw_uut_list]):

            for uut in spine_list:
                if 'spine1' in uut.alias:
                    loopback1 = uut.interfaces['loopback1'].intf
                    loopback1_ip = uut.interfaces['loopback1'].ipv4  
                    pim_rp =str(loopback1_ip)[:-3]


            for uut in leaf_list + spine_list  + bgw_list:
                pim_intf_list = []
                for intf in [*uut.interfaces.keys()]:
                    if 'loopback' in intf:
                        intf=uut.interfaces[intf].intf
                        pim_intf_list.append(intf)
                    elif 'leaf_spine' in uut.interfaces[intf].alias:
                        intf=uut.interfaces[intf].intf
                        pim_intf_list.append(intf)
                try:
                    PimConfig(uut,pim_intf_list,pim_rp)
                except:
                    log.error('PimConfig config failed for node %r',uut) 
                    self.failed(goto=['common_cleanup'])                  

        for uut in site3_bgw_uut_list:
            loopback1 = uut.interfaces['loopback1'].intf
            loopback1_ip = uut.interfaces['loopback1'].ipv4  
            pim_rp1 =str(loopback1_ip)[:-3]

        for uut in site3_leaf_uut_list + site3_bgw_uut_list:
            pim_intf_list = []
            for intf in [*uut.interfaces.keys()]:
                if 'loopback' in intf:
                    intf=uut.interfaces[intf].intf
                    pim_intf_list.append(intf)
                elif 'leaf_spine' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    pim_intf_list.append(intf)
                try:
                    PimConfig(uut,pim_intf_list,pim_rp1)
                except:
                    log.error('PimConfig config failed for node %r',uut) 
                    self.failed(goto=['common_cleanup'])  


        countdown(30)
        log.info(banner("Starting pim verify Section"))
        for uut in leaf_uut_list:
            test1 = protocolStateCheck(uut,['pim'])
            if not test1:
                log.info('Feature PIM neigborship on device %r Failed ',str(uut))
                self.failed(goto=['common_cleanup'])
 
    @aetest.subsection
    def site1_2_internal_bgp_configure(self):
        log.info(banner("BGP site_internal_bgp_configure configurations"))
        for spine_list,leaf_list,bgw_list,as_num in zip([site1_spine_uut_list,site2_spine_uut_list],\
            [site1_leaf_uut_list ,site2_leaf_uut_list],\
            [site1_bgw_uut_list,site2_bgw_uut_list],\
            ['65001','65002']):

            spine_loop_list = []
            vtep_loop1_list = []
            for uut in spine_list:                
                loopback1 = uut.interfaces['loopback1'].intf
                loopback1_ip = uut.interfaces['loopback1'].ipv4  
                spine_rid =str(loopback1_ip)[:-3]
                spine_loop_list.append(spine_rid)

            for uut in leaf_list + bgw_list:
                loopback1 = uut.interfaces['loopback1'].intf
                loopback1_ip = uut.interfaces['loopback1'].ipv4  
                rid =str(loopback1_ip)[:-3]
                        
                log.info("spine_loop_list is --------=%r",spine_loop_list)
                leaf_bgp_obj1=IbgpLeafNode(uut,rid,as_num,['Nil'],spine_loop_list,'Loopback1','ibgp-vxlan')
                #(self,node,rid,as_number,adv_nwk_list,neigh_list,update_src,template_name):   
                try:
                    leaf_bgp_obj1.bgp_conf()
                except:
                    log.error('leaf_bgp_obj1.bgp_conf() failed for node %r',uut) 
                    self.failed(goto=['common_cleanup'])

 
            for uut in leaf_list + bgw_list:                
                loopback1 = uut.interfaces['loopback1'].intf
                loopback1_ip = uut.interfaces['loopback1'].ipv4  
                rid_vtep =str(loopback1_ip)[:-3]
                vtep_loop1_list.append(rid_vtep)
            
            
            for uut in spine_list:
                loopback1 = uut.interfaces['loopback1'].intf
                loopback1_ip = uut.interfaces['loopback1'].ipv4  
                rid =str(loopback1_ip)[:-3]
                log.info("vtep_loop1_list is --------=%r",vtep_loop1_list)        
                spine_bgp_obj=IbgpSpineNode(uut,rid,as_num,['Nil'],vtep_loop1_list,'loopback1','ibgp-vxlan')
            
                try:
                    spine_bgp_obj.bgp_conf()
                except:
                    log.error('spine_bgp_obj.bgp_conf() failed for node %r',uut) 
                    self.failed(goto=['common_cleanup'])
  
    @aetest.subsection
    def site3_internal_bgp_configure(self):        

        for uut in site3_bgw_uut_list:  
            log.info('uut %r in site3_bgw_uut_list ***** ',uut)              
            loopback1 = uut.interfaces['loopback1'].intf
            loopback1_ip = uut.interfaces['loopback1'].ipv4  
            bgw_rid =str(loopback1_ip)[:-3]
 

        for uut in site3_leaf_uut_list:
            log.info('uut %r in site3_leaf_uut_list ***** ',uut)    
            loopback1 = uut.interfaces['loopback1'].intf
            loopback1_ip = uut.interfaces['loopback1'].ipv4  
            rid =str(loopback1_ip)[:-3]                        
            leaf_bgp_obj1=IbgpLeafNode(uut,rid,'65003',['Nil'],[bgw_rid],'Loopback1','ibgp-vxlan')
            leaf_bgp_obj1.bgp_conf()

        for uut in site3_leaf_uut_list:                
            log.info('uut %r in site3_leaf_uut_list ***** ',uut)  
            loopback1 = uut.interfaces['loopback1'].intf
            loopback1_ip = uut.interfaces['loopback1'].ipv4  
            leaf_rid =str(loopback1_ip)[:-3]
 

        for uut in site3_bgw_uut_list:
            log.info('uut %r in site3_bgw_uut_list ***** ',uut)      
            loopback1 = uut.interfaces['loopback1'].intf
            loopback1_ip = uut.interfaces['loopback1'].ipv4  
            rid =str(loopback1_ip)[:-3]                        
            bgw_bgp_obj1=IbgpLeafNode(uut,rid,'65003',['Nil'],[leaf_rid],'Loopback1','ibgp-vxlan')
            bgw_bgp_obj1.bgp_conf()


        countdown(60)

        log.info(banner("Starting bgp verify Section"))
        for uut in leaf_uut_list:
            test1 = protocolStateCheck(uut,['bgp'])
            if not test1:
                log.info('Feature %r neigborship on device %r Failed ','bgp',str(uut))
                self.failed(goto=['common_cleanup'])
 
 
    @aetest.subsection
    def loop1filter_bgw_peering(self):     
        #filterloop1ibgp(uut):
        pcall(filterloop1ibgp,uut=tuple(bgw_uut_list))      
        bgw_peering(site1_bgw_uut_list[0],site1_bgw_uut_list[1])
        bgw_peering(site2_bgw_uut_list[0],site2_bgw_uut_list[1])
    
 
    @aetest.subsection
    def access_port_configure(self):
        log.info(banner("access_port_configure"))

        try:
            pcall(accessPortConfigure,uut=tuple(sw_uut_list+leaf_uut_list+bgw_uut_list),\
            vlan_range=(vlan_range,vlan_range,vlan_range,\
            vlan_range,vlan_range,vlan_range,vlan_range,vlan_range,vlan_range,vlan_range,vlan_range))
        except:
            log.info('accessPortConfigure Failed ')
            self.failed(goto=['common_cleanup']) 

        try:
            pcall(swPoConfigure,uut=tuple(sw_uut_list+leaf_uut_list),\
            vlan_range=(vlan_range,vlan_range,vlan_range,vlan_range,vlan_range,vlan_range))
        except:
            log.info('swPoConfigure Failed ')
    


    @aetest.subsection
    def vxlan_bringup(self):
        log.info(banner("VXLAN configurations"))
        try:
 
            pcall(vxlanConfigureAuto,uut=(site1_bgw_uut_list[0],site1_bgw_uut_list[1],site1_leaf_uut_list[0],\
            site2_bgw_uut_list[0],site2_bgw_uut_list[1],site2_leaf_uut_list[0],\
            site3_bgw_uut_list[0],site3_leaf_uut_list[0]),\
            l2_scale =(vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale),\
            mcast_group_scale =(mcast_group_scale,mcast_group_scale,mcast_group_scale,mcast_group_scale,mcast_group_scale,mcast_group_scale,mcast_group_scale,mcast_group_scale),\
            l3_scale =(routing_vlan_scale,routing_vlan_scale,routing_vlan_scale,routing_vlan_scale,routing_vlan_scale,routing_vlan_scale,routing_vlan_scale,routing_vlan_scale),\
            mode=(ir_mode,ir_mode,ir_mode,ir_mode,ir_mode,ir_mode,ir_mode,ir_mode),\
            as_num=('65001','65001','65001','65002','65002','65002','65003','65003'))
 
            #vxlanConfigureAuto(site1_leaf_uut_list[0],vlan_vni_scale,routing_vlan_scale,mcast_group_scale,ir_mode,'65001')
            #vxlanConfigureAuto(uut,l2_scale,l3_scale,mcast_group_scale,mode,as_num):
 
        except:
            log.info('vxlanConfigure Failed ')
            self.failed(goto=['common_cleanup']) 

        countdown(20)

    '''

    @aetest.subsection
    def configureTgn(self, testscript, testbed):
        """ common setup subsection: connecting devices """
        global tgen,port_handle_sw1site1,port_handle_sw1site2,port_handle_sw1site3,port_handle_dci1,orphan_handle_list_sa,\
        port_handle_bgw1site2,orphan_handle_list,port_handle_list,orphan_handle_list_sa,\
        orphan_handle_list_anycast_bgw,tgn1_spine2site1_intf1,port_handle_spine2site1,trm_port_handle_list,\
        site1_group1,site2_group1,site3_group1,test_rate,test_l3_vlan_scale,rate_list_trm


        try:
            port_handle = ConnectSpirent(labserver_ip,tgn_ip,[tgn1_dci1_intf1,tgn1_sw1site2_intf1,tgn1_sw1site3_intf1,\
            tgn1_bgw1site1_intf1,tgn1_bgw1site2_intf1,tgn1_sw1site1_intf1,tgn1_spine2site1_intf1])

            #port_handle = ConnectSpirent(labserver_ip,tgn_ip,[tgn1_sw1site2_intf1])
        except:
            log.info('ConnectSpirent Failed ')
            self.failed(goto=['common_cleanup']) 

        port_handle_sw1site1 = port_handle[tgn1_sw1site1_intf1]
        port_handle_sw1site2 = port_handle[tgn1_sw1site2_intf1]
        port_handle_sw1site3 = port_handle[tgn1_sw1site3_intf1]
        port_handle_bgw1site1 = port_handle[tgn1_bgw1site1_intf1]
        port_handle_bgw1site2 = port_handle[tgn1_bgw1site2_intf1]
        port_handle_spine2site1 = port_handle[tgn1_spine2site1_intf1]        
        #port_handle_bgw1site3 = port_handle[tgn1_dci1_intf1]
        #port_handle_bgw2site3 = port_handle[tgn1_bgw2site3_intf1]  
        port_handle_dci1 = port_handle[tgn1_dci1_intf1] 

        port_handle_list = [port_handle_sw1site2,port_handle_bgw1site1,port_handle_sw1site3,\
        port_handle_bgw1site2,port_handle_sw1site1,port_handle_spine2site1]

        orphan_handle_list_sa = [port_handle_sw1site1,port_handle_bgw1site1,port_handle_bgw1site2]
        orphan_handle_list = [port_handle_sw1site3]
        orphan_handle_list_anycast_bgw = [port_handle_sw1site2]
        trm_port_handle_list =[port_handle_sw1site1,port_handle_sw1site2,port_handle_sw1site3]
        
 
  
#######################################################################
###                          TESTCASE BLOCK                         ###
#######################################################################
#
# Place your code that implements the test steps for the test case.
# Each test may or may not contains sections:
###        setup   - test preparation
###        test    - test action
###           cleanup - test wrap-up

'''
 
class TC00002_Nve_Peer_State_Verify(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        
        log.info("Pass testcase setup")

    @aetest.test
    def check_nve_peer_state(self):        
        if not 'mcast' in ir_mode:
            test1 = NvePeerCheck(leaf_uut_list,1)
            if not test1:
                log.info(banner("NvePeerCheck F A I L E D"))
                #self.failed(goto=['common_cleanup']) 

    @aetest.cleanup
    def cleanup(self):
        pass

class TC00003_Nve_Vni_State_Verify(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.test
    def check_nve_vni_state(self):
        for uut in leaf_uut_list:
            uut.execute('terminal length 0')

            test1 = protocolStateCheck(uut,['nve-vni'])
            if not test1:
                self.failed(goto=['common_cleanup']) 

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """
 
class TC00004_Vxlan_Consistency_check(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def vxlan_consistency_check_l2module(self):
        for uut in leaf_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

class TC00005_vxlan_dci_bgp_configs(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
   
    @aetest.test
    def dcibfdEnable(self):

        log.info("+++ Starting bfdEnable +++")      
        try:
            pcall(bfdEnable,uut=tuple(l3_uut_list))
        except:
            log.error('bfdEnable failed ##')
            self.failed()
        
    
    @aetest.test
    def dciEbgpv4Bringup(self):

        log.info("+++ Starting dciEbgpv4Bringup +++")

        try: 
            pcall(dcibgwebgpv4,uut=tuple(dci_uut_list))
            pcall(bgwdciebgpv4,uut=tuple(bgw_uut_list))
        except:
            log.error('multiSiteEnable ##')
            #self.failed(goto=['common_cleanup']) 
 
    @aetest.test
    def dciEbgpevpn4Bringup(self):

        try:
            pcall(multisiteDcibgpEvpntrmall,uut=tuple(dci_uut_list))
            pcall(multisitebgwbgpEvpn,uut=tuple(bgw_uut_list),\
                as_num=('65001','65001','65002','65002','65003'))

        except:
            log.error('multiSiteEnable ##')
            #self.failed(goto=['common_cleanup']) 
      
        countdown(120)
 

    @aetest.test
    def dciBgpCheck(self):
        for uut in bgw_uut_list+dci_uut_list:
            if not protocolStatusCheck(uut,['v4bgp']):
                log.info('DCI bgp Failed')
                self.failed(goto=['common_cleanup'])
            
            test1 = protocolStateCheck(uut,['bgp'])
            if not test1:
                log.info('failed')
                self.failed(goto=['common_cleanup'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


 
class TC00006_vxlan_ms_configs(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
  
    @aetest.test
    def multiSiteEnable(self):

        try:
            pcall(multiSiteEnabletrm,uut=tuple(bgw_uut_list),\
            vni=(vni,vni,vni,vni,vni),scale=(vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale))
            pcall(anycastBgwBgpConfgure,site_bgw_uut_list=tuple(site1_bgw_uut_list,site2_bgw_uut_list))

        except:
            log.error('multiSiteEnable ##')
            #self.failed(goto=['common_cleanup']) 
 
    @aetest.test
    def dciBgpCheck(self):
        for uut in bgw_uut_list+dci_uut_list:
            if not protocolStatusCheck(uut,['v4bgp']):
                log.info('DCI bgp Failed')
                #self.failed(goto=['common_cleanup'])
            
            test1 = protocolStateCheck(uut,['bgp'])
            if not test1:
                log.info('failed')
                #self.failed()

    @aetest.cleanup
    def cleanup(self):
        pass
 

 
 
class TC00008_vxlan_ms_trm_configs(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def trmenable(self):
        try:
            pcall(mstrmBgwConfigure,uut=tuple(bgw_uut_list)) 
            pcall(mstrmLeafConfigure,uut=tuple(leaf_uut_list))
            pcall(mstrmDciConfigure,uut=tuple(dci_uut_list)) 
            pcall(mstrmSpineConfigure,uut=tuple(spine_uut_list)) 

        except:
            log.error('TC007_vxlan_ms_trm_configs Failed')
            #self.failed(goto=['common_cleanup']) 

        log.info(banner("Starting bgw_peer_check"))        
        test1 = bgw_peer_check(site1_bgw_uut_list+[site2_bgw_uut_list[0]]+site3_bgw_uut_list)
        if not test1:
            log.info(banner('bgw_peer_check failed'))


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC00001_vtepEmulationMsite(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")


    @aetest.test
    def vtepEmulationMsite(self):
        """ testcase clean up """
        if 'yes' in vtep_emulation_msite_spirent:        
            log.info("in  vtepEmulation")
            vtepEmulationmSite(dci_uut_list[0],vtep_scale,port_handle_dci1)
            time.sleep(60)
            for uut in [dci_uut_list[0]]:
                log.info("Checking bgp state @ %r",uut)
                test1 = protocolStateCheck(uut,['bgp'])
                if not test1:
                    self.failed()


    @aetest.cleanup
    def cleanup(self):
        pass

'''   
class TC00009_vxlan_ms_trm_cli_check(aetest.Testcase):
    """Result For: Verify the presence and co-existence of Multisite configurations with
    TRM Configurations"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")


    @aetest.test
    def multiSiteCliCheck(self):
        try:
            pcall(multiSitetrmClicheck,uut=tuple(bgw_uut_list))
        except:
            log.error('vxlan_multisite_trm_cli_check failed ##')
            #self.failed(goto=['common_cleanup']) 

        log.info(banner("Starting bgw_peer_check"))        
        test1 = bgw_peer_check(site1_bgw_uut_list+[site2_bgw_uut_list[0]]+site3_bgw_uut_list)
        if not test1:
            log.info(banner('bgw_peer_check failed'))


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


 
class TC00011_vxlan_trm_mcast_traffic_enable(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        log.info(banner("----Generating mcast traffic @ Site1 SW1----"))
        global site1_group1,site2_group1,site3_group1,group_list

        for uut in leaf_uut_list+bgw_uut_list+sw_uut_list:
            uut.configure('system no hap-reset ')
            for i in range(1,2):
                uut.execute('clear mac address-table dynamic')
                uut.execute('clear ip arp vrf all')

        log.info(banner("Resetting the streams"))
        for port_hdl in port_handle_list:
            sth.traffic_control (port_handle = port_hdl, action = 'reset', db_file=0 )


        log.info(banner("Vxlan Msite trmTrafficTestConnfigure"))  
 
        for i in range(0,group_scale_per_port):
            trmTrafficTestConnfigure(site2_bgw_uut_list[0],port_handle_sw1site1,[port_handle_sw1site2,port_handle_sw1site3],'1000',\
                site1_group1,test_l3_vlan_scale)
            trmTrafficTestConnfigure(site2_bgw_uut_list[0],port_handle_sw1site2,[port_handle_sw1site1,port_handle_sw1site3],'1000',\
                site2_group1,test_l3_vlan_scale)
            trmTrafficTestConnfigure(site2_bgw_uut_list[0],port_handle_sw1site3,[port_handle_sw1site1,port_handle_sw1site2],'1000',\
                site3_group1,test_l3_vlan_scale)
            site1_group1 = str(ip_address(site1_group1)+1)
            site2_group1 = str(ip_address(site2_group1)+1)
            site3_group1 = str(ip_address(site3_group1)+1)

        spirentIgmpHostsControll(trm_port_handle_list,'join')

        log.info(banner("Starting Traffic after ARP"))


        traffic_start =   sth.traffic_control(port_handle = 'all', action = 'run') 
        if not traffic_start['status']:
            log.info(banner("traffic_start failed"))          
       
        for i in range(1,3):
            doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')

        if 'full' in traffic_profile:    
            log.info(banner("Vxlan Msite L2/L3/UC/BUM/V6/ traffic"))
            vxlantrafficSetupfull(site1_bgw_uut_list[0],port_handle_sw1site1,port_handle_sw1site2,vlan_start,vlan_vni_scale,rate)

            for i in range(1,3):
                doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')

        traffic_stop =   sth.traffic_control(port_handle = 'all', action = 'stop') 
        if not traffic_stop['status']:
            log.info(banner("traffic_stop failed"))   

        traffic_start =   sth.traffic_control(port_handle = 'all', action = 'run') 
        if not traffic_start['status']:
            log.info(banner("traffic_start failed")) 


        sth.save_xml (filename ="mstrm1.xml")  #page number 1307

        countdown(25)
        
        

    @aetest.test
    def traffic_test(self, testscript, testbed):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site1_bgw_uut_list:
            check = csvxlanall(uut)
            if not check:
                self.failed()
    

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
 
class TC000712_vxlan_ms_trm_Clear_ARP_force_delete_leaf(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def Trigger11ClearArpforcedelSite1(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac @ bgw"))

        for uut in site1_leaf_uut_list:
            for i in range(1,5):
                uut.execute("clear ip arp vrf all force-delete")

        countdown(20)

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def Trigger11ClearArpforcedelSite2(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac @ bgw"))

        for uut in site2_leaf_uut_list:
            for i in range(1,5):
                uut.execute("clear ip arp vrf all force-delete")

        countdown(20)

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC00074_vxlan_ms_trm_vlan_remove_add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def vlanVniRemove(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))
        vlan_count_to_remove_add=int(vlan_vni_scale*.8)
        vlan_2 =  vlan_start + vlan_count_to_remove_add
        for uut in site1_bgw_uut_list:
            try:
                #vlan_vni_remove(uut,vlan_start,vni,vlan_count_to_remove_add)
                vlan_remove(uut,vlan_start,vlan_count_to_remove_add)
            except:
                log.info("vlan Remove failed")

        log.info(" %r vlans Removed",vlan_count_to_remove_add )
        countdown(10)
        for uut in site1_bgw_uut_list:
            try:
                vlan_vni_configure(uut,vlan_start,vni,vlan_count_to_remove_add+1)
            except:
                log.info("vlan Remove failed")
        log.info(" %r vlan/vni's Added",vlan_count_to_remove_add )
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC00081_vxlan_ms_trm_bg1_isolation_nve_shut(aetest.Testcase): 
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def TriggerNveShutBgw1(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in [site2_bgw_uut_list[0]]:
            cmd1 = \
                """
                interface nve 1
                shut
                """
            uut.configure(cmd1)


        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def TriggerNvenNoShutBgw1(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in [site2_bgw_uut_list[0]]:
            cmd1 = \
                """
                interface nve 1
                no shut
                """
            uut.configure(cmd1)


        countdown(20)


        if not pcall(rateTest,port_hdl=tuple(trm_port_handle_list),exp_rate=tuple(rate_list_trm)):
            log.info('msTrmTrafficTest failed')
            self.failed()           

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for uut in [site2_bgw_uut_list[0]]:
            cmd1 = \
                """
                interface nve 1
                no shut
                """
            uut.configure(cmd1)

 

class TC00082_vxlan_ms_trm_bg2_isolation_nve_shut(aetest.Testcase): 
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def TriggerNveShutBgw1(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in [site2_bgw_uut_list[1]]:
            cmd1 = \
                """
                interface nve 1
                shut
                """
            uut.configure(cmd1)


        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def TriggerNvenNoShutBgw1(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in [site2_bgw_uut_list[1]]:
            cmd1 = \
                """
                interface nve 1
                no shut
                """
            uut.configure(cmd1)


        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for uut in site2_bgw_uut_list:
            cmd1 = \
                """
                interface nve 1
                no shut
                """
            uut.configure(cmd1)


class TC00083_vxlan_ms_trm_Clear_ip_route_vrf_all(aetest.Testcase): 
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def Trigger11Clear_ip_route_vrf_all(self, testscript, testbed):
        log.info(banner("Starting clear ip route vrf all "))
        for uut in site1_bgw_uut_list:
            for i in range(1,5):
                uut.execute("clear ip route vrf all *")
 
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
  


class TC00019_vxlan_ms_trm_ip_remove_add(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def ipRemoveBglAllAdddci(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw_dci' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    ipAddRemoveAdd(uut,intf) 
 
        countdown(30)
 

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ipRemoveBglAllAddleaf(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'leaf_spine' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    ipAddRemoveAdd(uut,intf) 
 
        countdown(30)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ipRemoveBglAllAddloop(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'loopback100' in str(intf):
                    intf=uut.interfaces[intf].intf
                    ipAddRemoveAdd(uut,intf) 
 
        countdown(30)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 


class TC00020_vxlan_ms_trm_ipAddRemoveClearIpBgpIpAdd(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):

    
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

 
    @aetest.test
    def ipRemoveBglAllAdddci(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        for uut in bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw_dci' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    ipAddRemoveClearIpBgpIpAdd(uut,intf) 
 
        countdown(30)
  

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 
 
 
    @aetest.test
    def ipRemoveBglAllAdddcileaf(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        for uut in bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'leaf_spine' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    ipAddRemoveClearIpBgpIpAdd(uut,intf) 

 
        countdown(30)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

 
    @aetest.test
    def ipRemoveBglAllAdddciloop100(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        for uut in bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'loopback100' in str(intf):
                    intf=uut.interfaces[intf].intf
                    ipAddRemoveClearIpBgpIpAdd(uut,intf) 
 
        countdown(30)
 
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

 
    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC00018_vxlan_ms_trm_ipAddRemoveClearIprouteIpAdd(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def ipRemoveBglAllAdddci(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw_dci' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    ipAddRemoveClearIprouteIpAdd(uut,intf) 
 
        countdown(30)
 

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ipRemoveBglAllAddleaf(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'leaf_spine' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    ipAddRemoveClearIprouteIpAdd(uut,intf) 
 
        countdown(30)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ipRemoveBglAllAddloop100(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'loopback100' in str(intf):
                    intf=uut.interfaces[intf].intf
                    ipAddRemoveClearIprouteIpAdd(uut,intf) 
 
        countdown(30)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

class TC0001112_vxlan_ms_trm_bgw2_ascii_reload_parellal(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def bgwReloadTraffic(self, testscript, testbed):
       
        uut1 = site1_bgw_uut_list[0]
        port_hdl_list = [port_handle_sw1site1,port_handle_sw1site2,port_handle_sw1site3]
        rate_list = [rateFull,rateFull,rateOrphan]
        list1 = [port_hdl_list,rate_list]
        result = pcall(execute_parallel_reload_traffic_test1,obj1=[uut1,list1],device_flag= [1,2])
        #result = pcall(execute_parallel, device = [sw1, sw2], _ device_flag  = [1,2]

        if not result:
           self.failed()  

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC00018_vxlan_ms_trm_ipAddRemoveClearBgpallIpAdd(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def ipRemoveBglAllAdddci(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw_dci' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    ipAddRemoveClearBgpallIpAdd(uut,intf) 
 
        countdown(10)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ipRemoveBglAllAddleaf(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'leaf_spine' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    ipAddRemoveClearBgpallIpAdd(uut,intf) 
 
        countdown(10)
 


        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ipRemoveBglAllAddloop100(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'loopback100' in str(intf):
                    intf=uut.interfaces[intf].intf
                    ipAddRemoveClearBgpallIpAdd(uut,intf) 
 
        countdown(10)
 

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


 

class TC00019_vxlan_ms_trm_RP_Loop_Remove_Add_shutnoshut(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def trm_RP_Loop_Remove_Add(self, testscript, testbed):
        log.info(banner("Starting Trigger15VlanShutNoshut bgw"))
        for uut in site1_bgw_uut_list:
            last_loop = str(111+routing_vlan_scale-1)
            loop_conf = uut.execute('show run interface loop 111-{last_loop}'.format(last_loop=last_loop),timeout=40)
            loop_remove = uut.configure('no interface loop 111-{last_loop}'.format(last_loop=last_loop),timeout=40)
            countdown(5)
            uut.configure(loop_conf)
 
        countdown(10)


        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC00017_vxlan_ms_trm_acc_port_flap_source(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def TriggeraccessPortFlap(self, testscript, testbed):
        log.info(banner("Starting Trigger4AccessPortFlap SRC"))

        op1= site1_leaf_uut_list[0].execute("show spanning-tree | incl FWD")
        for line in op1.splitlines():
            if line:
                if 'FWD' in line:
                    intf = line.split()[0]

        for uut in site1_leaf_uut_list:
            if not TriggerPortFlap(uut,intf,3):
                log.info("TriggerPortFlap failed @ 4")
                self.failed()

        countdown(10)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 
    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC00018_vxlan_ms_trm_acc_port_flap_receiver(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def TriggeraccessPortFlap(self, testscript, testbed):
        log.info(banner("Starting Trigger4AccessPortFlap rcvr"))

        op1= site2_bgw_uut_list[0].execute("show spanning-tree | incl FWD")
        for line in op1.splitlines():
            if line:
                if 'FWD' in line:
                    intf = line.split()[0]

        for uut in site1_bgw_uut_list:
            if not TriggerPortFlap(uut,intf,3):
                log.info("TriggerPortFlap failed @ 4")
                self.failed()


        countdown(30)


 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



 

class TC00019_vxlan_ms_trm_l3_vlan_shutnoshut(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def Trigger15VlanShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger15VlanShutNoshut bgw"))
        for uut in site1_bgw_uut_list:
            vlanshut = \
            """
            vlan 101-105
            shut
            exit
            """
            uut.configure(vlanshut)

        countdown(15)

        for uut in site1_bgw_uut_list:
            vlannoshut = \
            """
            vlan 101-105
            no shut
            exit
            """
            uut.configure(vlannoshut)

        countdown(20)

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC00020_vxlan_ms_trm_L2_vlan_shutnoshut(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def Trigger15VlanShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger15VlanShutNoshut bgw"))
        for uut in site1_bgw_uut_list:
            vlanshut = \
            """
            vlan 1001-1005
            shut
            exit
            """
            uut.configure(vlanshut)

        countdown(15)

        for uut in site1_bgw_uut_list:
            vlannoshut = \
            """
            vlan 1001-1005
            no shut
            exit
            """
            uut.configure(vlannoshut)

        countdown(20)

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass 


class TC00021_vxlan_ms_trm_BGW_loop_shutnoshut(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def TriggerNveloopShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in site1_bgw_uut_list:
            op = uut.execute("show run interface nve1 | incl border-gateway")
            log.info("++++++++++++++++++++++++++++++++++++++++++++")
            log.info("OP is %r",op)
            log.info("++++++++++++++++++++++++++++++++++++++++++++")
            if 'loop' in str(op):
                intf_num = (findall(r'\d+',str(op)))[0]

            cmd1 = \
                """
                interface loopback{intf_num}
                shut
                sleep 5
                interface loopback{intf_num}
                no shut
                """
            uut.configure(cmd1.format(intf_num=intf_num))

        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

class TC00022_vxlan_ms_trm_Nve_loop_shutnoshut(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def TriggerNveloopShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in site1_bgw_uut_list:
            op = uut.execute("show run interface nve1 | incl 'source-interface loopback'")
            log.info("++++++++++++++++++++++++++++++++++++++++++++")
            log.info("OP is %r",op)
            log.info("++++++++++++++++++++++++++++++++++++++++++++")
            if 'loop' in str(op):
                intf_num = (findall(r'\d+',str(op)))[0]


            cmd1 = \
                """
                interface loopback{intf_num}
                shut
                sleep 5
                interface loopback{intf_num}
                no shut
                """
            uut.configure(cmd1.format(intf_num=intf_num))

        countdown(20)


        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 


class TC00023_vxlan_ms_trm_one_l2_vlan_remove_add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def TriggerVlan_remove_add(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in site1_bgw_uut_list:
            vlan_conf_string = uut.execute("show run vlan 1002")

            remove_vlan = \
            """
            no vlan 1002
            """
            uut.configure(remove_vlan,timeout = 240)
            countdown(5)
            uut.configure(vlan_conf_string,timeout = 240)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        pass


class TC00024_vxlan_ms_trm_one_l3_vlan_remove_add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def TriggerVlan_remove_add(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in site1_bgw_uut_list:
            vlan_conf_string = uut.execute("show run vlan 101")

            remove_vlan = \
            """
            no vlan 101
            """
            uut.configure(remove_vlan,timeout = 240)
            countdown(5)
            uut.configure(vlan_conf_string,timeout = 240)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()



    @aetest.cleanup
    def cleanup(self):
        pass

 
class TC000191_vxlan_ms_dci_tracking_remove_test_add(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def dcI_track_remove(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        dci_remove = \
        """
        interface {intf}
        no evpn multisite dci-tracking
        """
        for uut in [site1_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw_dci' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    uut.configure(dci_remove.format(intf=intf),timeout = 120)


        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def dcI_track_add(self, testscript, testbed):
        dci_add = \
        """
        interface {intf}
        evpn multisite dci-tracking
        """

        for uut in [site1_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw_dci' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    uut.configure(dci_add.format(intf=intf),timeout = 120)

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 
 

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC0001192_vxlan_ms_fabric_tracking_remove_test_add(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def dcI_track_remove(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        fab_remove = \
        """
        interface {intf}
        no evpn multisite fabric-tracking
        """

        for uut in [site1_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'leaf_spine' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    uut.configure(fab_remove.format(intf=intf),timeout = 120)

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

 
    @aetest.test
    def dcI_track_add(self, testscript, testbed):

        fab_add = \
        """
        interface {intf}
        evpn multisite fabric-tracking
        """

        for uut in [site1_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'leaf_spine' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    uut.configure(fab_add.format(intf=intf),timeout = 120)


        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


 
class TC00019_vxlan_ms_dci_tracking_remove_add(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def dcI_track_remove_add(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        dci_remove = \
        """
        interface {intf}
        no evpn multisite dci-tracking
        """

        dci_add = \
        """
        interface {intf}
        evpn multisite dci-tracking
        """

        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw_dci' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    uut.configure(dci_remove.format(intf=intf),timeout = 120)
                    #ipAddRemoveAdd(uut,intf) 

        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw_dci' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    uut.configure(dci_add.format(intf=intf),timeout = 120)
                    #ipAddRemoveAdd(uut,intf)  

        countdown(230)
 


        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

 

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC000119_vxlan_ms_fabric_tracking_remove_add(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def dcI_track_remove_add(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        fab_remove = \
        """
        interface {intf}
        no evpn multisite fabric-tracking
        """

        fab_add = \
        """
        interface {intf}
        evpn multisite fabric-tracking
        """

        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'leaf_spine' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    uut.configure(fab_remove.format(intf=intf),timeout = 120)
                    #ipAddRemoveAdd(uut,intf) 

        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'leaf_spine' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    uut.configure(fab_add.format(intf=intf),timeout = 120)
                    #ipAddRemoveAdd(uut,intf)  

        countdown(260)
  


        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 


 


class TC000192_vxlan_ms_trm_Configure_replace_nv_overlay(aetest.Testcase):
    ###    This is description for my tecase two
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 



    @aetest.test
    def mstrmConfigReplace(self, testscript, testbed):
        
        result_list = []

        for uut in [site1_bgw_uut_list[0]]:
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

        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   


    
    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


'''
class TC000194_vxlan_ms_trm_ngmvpn_remove_Configure_replace(aetest.Testcase):
    ###    This is description for my tecase two
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

   

    @aetest.test
    def mstrmConfigReplacengmvpn(self, testscript, testbed):
        
        result_list = []
        
        for uut in [site2_bgw_uut_list[0]]:
            tm = uut.execute("show clock | excl Time")
            log.info("time is ----- %r",tm)
            tm1 =  tm.replace(":","").replace(".","").replace(" ","")
            uut.configure('copy run bootflash:{name}'.format(name=tm1))
            countdown(2)
            uut.configure("no feature ngmvpn")
            countdown(2)                 
            op = uut.configure('configure replace bootflash:{name}'.format(name=tm1),timeout=120)
            if not "successfully" in op:
                self.failed(goto=['common_cleanup'])

        countdown(20)
 
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   


    
    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

'''

class TC000192_vxlan_ms_trm_Configure_replace_rem_pim(aetest.Testcase):
    ###    This is description for my tecase two
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def mstrmConfigReplace(self, testscript, testbed):
        result_list = []

        for uut in [site1_bgw_uut_list[0]]:
            tm = uut.execute("show clock | excl Time")
            log.info("time is ----- %r",tm)
            tm1 =  tm.replace(":","").replace(".","").replace(" ","")
            uut.configure('copy run bootflash:{name}'.format(name=tm1))
            countdown(2)
            uut.configure("no feature pim")
            countdown(2)                 
            op = uut.configure('configure replace bootflash:{name}'.format(name=tm1),timeout=120)
            if not "successfully" in op:
                self.failed(goto=['common_cleanup'])

        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   


    
    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


''' 

class TC000522_vxlan_ms_trm_restart_ngmvpn(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def ngmvpnrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site1_bgw_uut_list:
            uut.execute('restart ngmvpn')
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()     

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

'''
class TC00051_vxlan_ms_trm_restart_ospf(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site1_bgw_uut_list:
            uut.execute('restart ospf UNDERLAY')
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()     

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC00052_vxlan_ms_trm_restart_bgp(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def bgprestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site1_bgw_uut_list:
            uut.execute('restart bgp 65001')
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()     

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC00053_vxlan_ms_trm_restart_pim(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def pimrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site1_bgw_uut_list:
            uut.execute('restart pim')
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()     

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
class TC00054_vxlan_ms_trm_restart_igmp(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def igmprestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site1_bgw_uut_list:
            uut.execute('restart igmp')
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()     

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC00055_vxlan_ms_trm_restart_mld(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def mldrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site1_bgw_uut_list:
            uut.execute('restart mld')
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()     

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass





class TC00013_vxlan_trm_restart_mfdm(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def mfdmrestart(self, testscript, testbed):
        log.info(banner("Starting MFDM restart 1"))
        for uut in site1_bgw_uut_list:
            ProcessRestart(uut,'mfdm')

        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

 
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC00014_vxlan_trm_restart_l2rib(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def l2ribrestart(self, testscript, testbed):
        log.info(banner("Starting l2rib restart 1"))
        for uut in site1_bgw_uut_list:
            ProcessRestart(uut,'l2rib')

        countdown(20)


 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC00015_vxlan_trm_restart_l2fm(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def l2fmrestart(self, testscript, testbed):
        log.info(banner("Starting l2fm restart 1"))
        for uut in site1_bgw_uut_list:
            ProcessRestart(uut,'l2fm')

        countdown(20)


 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 
    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC00016_vxlan_trm_restart_nve(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
 
    @aetest.test
    def nverestart(self, testscript, testbed):
        log.info(banner("Starting nve restart 1"))
        for uut in site1_bgw_uut_list:
            ProcessRestart(uut,'nve')

        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

class TC00078_vxlan_ms_trm_vlan_mgr_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def Vlan_mgr_restart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site1_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'vlan_mgr')


        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()     

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC00079_vxlan_ms_trm_ethpm_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def ethpmrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site1_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'ethpm')


        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()     

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC00080_vxlan_ms_trm_ospf_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site1_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'ospf')


        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()     

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
  

class TC00025_vxlan_ms_trm_L3_Vni_remove_Add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def L3VniRemoveAdd(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

 
        if not NveL3VniRemoveAddTrm(site1_bgw_uut_list):
            log.info("Failed NveL3VniRemoveAddTrm @ 2")


        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()



    @aetest.cleanup
    def cleanup(self):
        pass


class TC00026_vxlan_ms_trm_Vn_Segment_remove_Add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def VnSegmentRemoveAdd(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))
        if not VnSegmentRemoveAdd(site1_bgw_uut_list,vlan_start):
            log.info("Failed NveL3VniRemoveAdd @ 2")


        countdown(30)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        pass




class TC00027_vxlan_ms_trm_L3_Vn_Segment_remove_Add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def l3VnSegment_Remove_Add(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))
        if not l3VnSegmentRemoveAdd(site1_bgw_uut_list,'101'):
            log.info("Failed l3VnSegmentRemoveAdd @ 2")

        countdown(30)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        pass



class TC00028_vxlan_ms_trm_nve_bounce(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def Trigger12NveShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in site1_bgw_uut_list:
            cmd1 = \
                """
                interface nve 1
                shut
                """
            uut.configure(cmd1)

        countdown(5)
        for uut in site1_bgw_uut_list:
            cmd2 = \
                """
                interface nve 1
                no shut
                """
            uut.configure(cmd2)

        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

class TC00029_vxlan_ms_trm_fabric_link_failover1(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def bgwfabriclinkfailover1(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        for uut in [site1_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_spine1site1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
         
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   

    @aetest.test
    def bgwfabriclinkrecover1(self, testscript, testbed):      
        for uut in [site1_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_spine1site1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()



class TC00030_vxlan_ms_trm_fabric_link_failover2(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def bgwfabriclinkfailover1(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        for uut in [site1_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_spine2site1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
         
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   

    @aetest.test
    def bgwfabriclinkrecover1(self, testscript, testbed):      
        for uut in [site1_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_spine2site1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()



class TC00031_vxlan_ms_trm_spine_isolate_1(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def bgwfabriclinkfailover1(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_spine1site1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
         
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   

    @aetest.test
    def bgwfabriclinkrecover1(self, testscript, testbed):      
        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_spine1site1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()



class TC00032_vxlan_ms_trm_spine_isolate_2(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def bgwfabriclinkfailover1(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_spine2site1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
         
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   

    @aetest.test
    def bgwfabriclinkrecover1(self, testscript, testbed):      
        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_spine2site1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()





class TC00033_vxlan_ms_trm_fabric_link_failover11(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def bgwfabriclinkfailover1(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        for uut in [site1_bgw_uut_list[1]]:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_spine1site1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
         
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   

    @aetest.test
    def bgwfabriclinkrecover1(self, testscript, testbed):      
        for uut in [site1_bgw_uut_list[1]]:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_spine1site1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()



class TC00034_vxlan_ms_trm_fabric_link_failover222(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def bgwfabriclinkfailover1(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        for uut in [site1_bgw_uut_list[1]]:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_spine2site1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
         
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   

    @aetest.test
    def bgwfabriclinkrecover1(self, testscript, testbed):      
        for uut in [site1_bgw_uut_list[1]]:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_spine2site1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()



 
class TC00035_vxlan_ms_trm_spine1_isolation(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def spine1isolation(self, testscript, testbed):
        log.info(banner("Starting spine1isolation @ 8"))

        if not nodeIsolate(site1_spine_uut_list[0]):
            self.failed()

        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def spine1Noisolation(self, testscript, testbed):
        log.info(banner("Starting spine1Noisolation @ 8"))
        if not nodeNoIsolate(site1_spine_uut_list[0]):
            self.failed()

        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

         
class TC00036_vxlan_ms_trm_spine2_isolation(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def spine2isolation(self, testscript, testbed):
        log.info(banner("Starting spine2isolation @ 8"))

        if not nodeIsolate(site1_spine_uut_list[1]):
            self.failed()

        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def spine2Noisolation(self, testscript, testbed):
        log.info(banner("Starting spine2Noisolation @ 8"))
        if not nodeNoIsolate(site1_spine_uut_list[1]):
            self.failed()


        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC00037_vxlan_ms_trm_dci1_router_failover(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def dci1isolation(self, testscript, testbed):
        log.info(banner("Starting dci1isolation @ 8"))

        if not nodeIsolate(dci_uut_list[0]):
            self.failed()

        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def dci1Noisolation(self, testscript, testbed):
        log.info(banner("Starting dci1Noisolation @ 8"))
        if not nodeNoIsolate(dci_uut_list[0]):
            self.failed()


        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC00038_vxlan_ms_trm_dci2_router_failover(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def dci2isolation(self, testscript, testbed):
        log.info(banner("Starting dci2isolation @ 8"))

        if not nodeIsolate(dci_uut_list[1]):
            self.failed()

        countdown(20)

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def dci2Noisolation(self, testscript, testbed):
        log.info(banner("Starting dci2Noisolation @ 8"))
        if not nodeNoIsolate(dci_uut_list[1]):
            self.failed()


        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC00039_vxlan_ms_trm_dci_link_failover1(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def dci1linkfailover1(self, testscript, testbed):       
        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_dci1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
 
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def dci1linkrecover1(self, testscript, testbed):       
        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_dci1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()

        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC00040_vxlan_ms_trm_dci_link_failover2(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def dci1linkfailover1(self, testscript, testbed):       
        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_dci2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
 
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def dci1linkrecover1(self, testscript, testbed):       
        for uut in site1_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_dci2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()

        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass





class TC000193_vxlan_ms_trm_pim_remove_add_vni_vrf(aetest.Testcase):
    ###    This is description for my tecase two
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def mstrmpimRemAddvrf(self, testscript, testbed):
        
        result_list = []
        for uut in site1_bgw_uut_list:
            if not pimRemoveAddvrf(uut):
                result_list.append('fail')

        if 'fail' in  result_list:
             self.failed()

        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   


    
    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC000191_vxlan_ms_trm_Continuos_stop_start_traffic(aetest.Testcase):
    ###    This is description for my tecase two
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def mcastStreamStopStart(self, testscript, testbed):
        log.info(banner("Starting ipRemoveAdd "))

        for i in range(1,5): 
            sth.traffic_control(port_handle = 'all', action = 'stop')
            countdown(20) 
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull-int(test_rate),\
                port002=port_handle_sw1site2,rx_rate002=rateFull-int(test_rate) ,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan-int(test_rate)):
                log.info('msTrmTrafficTest failed after TRM traffic stopped')
                sth.traffic_control(port_handle = 'all', action = 'run')
                self.failed()   
            sth.traffic_control(port_handle = 'all', action = 'run')
            countdown(20) 

            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                log.info('msTrmTrafficTest failed')
                self.failed()   

        sth.traffic_control(port_handle = 'all', action = 'run')

    
    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 


class TC000195_vxlan_ms_trm_pim_vrf_shut_no_shut(aetest.Testcase):
    ###    This is description for my tecase two
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 



    @aetest.test
    def vrfShutNoShutTRM(self, testscript, testbed):
        
        result_list = []

        cfg = \
        """
        vrf context {vrf}
        shut
        """


        cfg_noshut = \
        """
        vrf context {vrf}
        no shut
        """
        for uut in site1_bgw_uut_list:          
            vrf_list = findvrfList(uut)
            for vrf in vrf_list:
                uut.configure(cfg.format(vrf=vrf),timeout=60)
           
        countdown(100)

        for uut in site1_bgw_uut_list:          
            vrf_list = findvrfList(uut)      
            for vrf in vrf_list:
                uut.configure(cfg_noshut.format(vrf=vrf),timeout=60)

        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   


    
    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC000196_vxlan_ms_trm_l3_svi_shut_no_shut(aetest.Testcase):
    ###    This is description for my tecase two
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 



    @aetest.test
    def l3sviShutNoShutTRM(self, testscript, testbed):
        
        result_list = []

        cfg = \
        """
        interface vlan {vlan}
        shut
        sleep 1
        no shut
        """

        for uut in site1_bgw_uut_list:          
            vlan_list = findl3VlanList(uut)
            for vlan in vlan_list:
                uut.configure(cfg.format(vlan=vlan),timeout=60)

        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   


    
    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC000196_vxlan_ms_trm_NVE_shut_noshut_Internal_Leaf(aetest.Testcase):
    ###    This is description for my tecase two
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 



    @aetest.test
    def vrfShutNoShutTRM(self, testscript, testbed):
        
        result_list = []

        cfg = \
        """
        interface nve 1
        shut
        sleep 1
        no shut
        """

        for uut in site1_leaf_uut_list:
            uut.configure(cfg)

        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   


    
    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass





class TC000193_vxlan_ms_trm_remove_add_vni_from_vrf(aetest.Testcase):
    ###    This is description for my tecase two
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def mstrmpimRemAddvrf(self, testscript, testbed):
        
        result_list = []
        for uut in site1_bgw_uut_list:
            if not vniRemoveAddfromvrf(uut): 
                result_list.append('fail')

        if 'fail' in  result_list:
             self.failed()

        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   

     
    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

class TC000193_vxlan_ms_trm_NVE_Uplink_flap_Internal_VTEP(aetest.Testcase):
    ###    This is description for my tecase two
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 



    @aetest.test
    def mstrmpimRemAddvrf(self, testscript, testbed):        
        result_list = []
        log.info(banner("Starting TriggerCoreIfFlap222 @ site1_leaf_uut_list"))
        for uut in site1_leaf_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'leaf_spine' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        result_list.append('fail')

                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        result_list.append('fail')

        if 'fail' in  result_list:
             self.failed()

        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   

    
    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC00041_vxlan_ms_trm_dci_link_failover3(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def dci1linkfailover1(self, testscript, testbed):       
        for uut in [site1_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_dci1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
 
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def dci1linkrecover1(self, testscript, testbed):       
        for uut in [site1_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_dci1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()

        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC00042_vxlan_ms_trm_dci_link_failover4(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def dci1linkfailover1(self, testscript, testbed):       
        for uut in [site1_bgw_uut_list[1]]:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_dci2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
 
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def dci1linkrecover1(self, testscript, testbed):       
        for uut in [site1_bgw_uut_list[1]]:
            for intf in [*uut.interfaces.keys()]:
                if 'site1_dci2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()

        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC00043_vxlan_ms_trm_ospf_shut_noshut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
 

        cfg_shut =\
        """
        router ospf UNDERLAY
        shut
        """
        cfg_noshut =\
        """
        router ospf UNDERLAY
        no shut
        """

        site1_bgw_uut_list[0].configure(cfg_shut)
        site1_bgw_uut_list[1].configure(cfg_shut)
        countdown(15)
        site1_bgw_uut_list[0].configure(cfg_noshut)
        site1_bgw_uut_list[1].configure(cfg_noshut)
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC00044_vxlan_ms_trm_bgp_shut_noshut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def bgwbgpshutNoShut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        cfg_shut =\
        """
        router bgp 65001
        shut
        """
        cfg_noshut =\
        """
        router bgp 65001
        no shut
        """
        site1_bgw_uut_list[0].configure(cfg_shut)
        site1_bgw_uut_list[1].configure(cfg_shut)
        countdown(15)
        site1_bgw_uut_list[0].configure(cfg_noshut)
        site1_bgw_uut_list[1].configure(cfg_noshut)
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


  
 
class TC00045_vxlan_ms_trm_spine1_ospf_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_spine1_ospf_shut @ 8"))
        cfg_shut =\
        """
        router ospf UNDERLAY
        shut
        """

        site1_spine_uut_list[0].configure(cfg_shut)
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def remotebgwospfnoshut(self, testscript, testbed):

        cfg_noshut =\
        """
        router ospf UNDERLAY
        no shut
        """

        site1_spine_uut_list[0].configure(cfg_noshut)
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        cfg_noshut =\
        """
        router ospf UNDERLAY
        no shut
        """

        site1_spine_uut_list[0].configure(cfg_noshut)
        countdown(20)


 
class TC00046_vxlan_ms_trm_spine2_ospf_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_spine2_ospf_shut @ 8"))
        cfg_shut =\
        """
        router ospf UNDERLAY
        shut
        """

        site1_spine_uut_list[1].configure(cfg_shut)
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def remotebgwospfNoshut(self, testscript, testbed):

        cfg_noshut =\
        """
        router ospf UNDERLAY
        no shut
        """
        site1_spine_uut_list[1].configure(cfg_noshut)
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 




    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        cfg_noshut =\
        """
        router ospf UNDERLAY
        no shut
        """
        site1_spine_uut_list[1].configure(cfg_noshut)


class TC00047_vxlan_ms_trm_spine1_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def spine1bgpshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_spine1_bgp_shut @ 8"))
        cfg_shut =\
        """
        router bgp 65001
        shut
        """
 
        site1_spine_uut_list[0].configure(cfg_shut)
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 



    @aetest.test
    def spine1bgpNoshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_spine1_bgp_shut @ 8"))
 
        cfg_noshut =\
        """
        router bgp 65001
        no shut
        """
        site1_spine_uut_list[0].configure(cfg_noshut)
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        cfg_noshut =\
        """
        router bgp 65001
        no shut
        """
        site1_spine_uut_list[0].configure(cfg_noshut)
        countdown(20)


 

class TC00048_vxlan_ms_trm_spine2_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def spine2bgpshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_spine1_bgp_shut @ 8"))
        cfg_shut =\
        """
        router bgp 65001
        shut
        """
 
        site1_spine_uut_list[1].configure(cfg_shut)
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 



    @aetest.test
    def spine2bgpNoshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_spine1_bgp_shut @ 8"))
 
        cfg_noshut =\
        """
        router bgp 65001
        no shut
        """
        site1_spine_uut_list[1].configure(cfg_noshut)
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        cfg_noshut =\
        """
        router bgp 65001
        no shut
        """
        site1_spine_uut_list[1].configure(cfg_noshut)
        countdown(20)


class TC00049_vxlan_ms_trm_dci1_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def dci1_bgp_shut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_dci1_bgp_shut @ 8"))
        cfg_shut =\
        """
        router bgp 99
        shut
        """
 
        dci_uut_list[0].configure(cfg_shut)
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 



 
    @aetest.test
    def dci1_bgp_No_shut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_dci1_bgp_shut @ 8"))
 
        cfg_noshut =\
        """
        router bgp 99
        no shut
        """
        dci_uut_list[0].configure(cfg_noshut)
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 




    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        cfg_noshut =\
        """
        router bgp 99
        no shut
        """
        dci_uut_list[0].configure(cfg_noshut)

 

class TC00050_vxlan_ms_trm_dci2_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def dci2_bgp_shut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_dci1_bgp_shut @ 8"))
        cfg_shut =\
        """
        router bgp 99
        shut
        """
 
        dci_uut_list[1].configure(cfg_shut)
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 



 
    @aetest.test
    def dci2_bgp_No_shut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_dci1_bgp_shut @ 8"))
 
        cfg_noshut =\
        """
        router bgp 99
        no shut
        """
        dci_uut_list[1].configure(cfg_noshut)
        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        cfg_noshut =\
        """
        router bgp 99
        no shut
        """
        dci_uut_list[1].configure(cfg_noshut)
 

class TC00056_vxlan_ms_trm_anycast_bgw_remote_bgw_nve_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def remotebgw1Nveshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        cfg_shut =\
        """
        interface nve 1
        shut
        """
        site2_bgw_uut_list[0].configure(cfg_shut)
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def remotebgw1NvesNohut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))

        cfg_noshut =\
        """
        interface nve 1
        no shut
        """

        site2_bgw_uut_list[0].configure(cfg_noshut)

        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 
                      

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC00057_vxlan_ms_trm_remote_bgw_bgp_shut(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def remotebgwbgpshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        cfg_shut =\
        """
        router bgp 65002
        shut
        """

        site2_bgw_uut_list[0].configure(cfg_shut)
        countdown(10)        

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def remotebgwbgpNoshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))

        cfg_noshut =\
        """
        router bgp 65002
        no shut
        """

        site2_bgw_uut_list[0].configure(cfg_noshut)
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

 
    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC000571_vxlan_ms_trm_local_bgw_bgp_shut(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def bgwbgpshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        cfg_shut =\
        """
        router bgp 65001
        shut
        """

        site1_bgw_uut_list[0].configure(cfg_shut)
        countdown(10)        

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def bgwbgpNoshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))

        cfg_noshut =\
        """
        router bgp 65001
        no shut
        """

        site1_bgw_uut_list[0].configure(cfg_noshut)
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

 
    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass





class TC00058_vxlan_ms_trm_Core_flap(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def Trigger5CoreIfFlap(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))

        if not TriggerCoreIfFlap222(site1_bgw_uut_list):
            log.info("TriggerCoreIfFlap222 failed @ 4")
            #self.failed()

        countdown(28)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC00059_vxlan_ms_trm_ClearIpRoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 



    @aetest.test
    def Trigger6ClearIpRoute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site1_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear ip route *")

        countdown(30)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()





    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC00060_vxlan_ms_trm_clearIpMoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def Trigger7ClearIpMroute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site1_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear ip mroute *")

        countdown(30)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC00061_vxlan_ms_trm_clear_ospf_Neigh(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def Trigger8ClearOspfNeigh(self, testscript, testbed):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))

        for uut in site1_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear ip ospf neighbor *")

        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC00062_vxlan_ms_trm_Clear_IP_Bgp(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def Trigger9ClearIpBgp(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))


        for uut in site1_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear ip bgp *")

        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()





    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC00063_vxlan_ms_trm_Clear_Bgp_l2vpn(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 



    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting TriggerClearBgpL2vpnEvpn @ bgw"))

        for uut in site1_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear bgp l2vpn evpn *")

        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass





class TC00064_vxlan_ms_trm_Clear_Bgp_mvpn(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 



    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting TriggerClearBgpL2vpnEvpn @ bgw"))

        for uut in [site1_bgw_uut_list[0]]:
            for i in range(1,2):
                uut.execute("clear bgp ipv4 mvpn *")

        countdown(20)
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting TriggerClearBgpL2vpnEvpn @ bgw"))

        for uut in [site1_bgw_uut_list[1]]:
            for i in range(1,2):
                uut.execute("clear bgp ipv4 mvpn *")

        countdown(20)

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC00065_vxlan_ms_trm_Spine_ClearIpRoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def Trigger6ClearIpRoute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site1_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip route *")

        countdown(20)

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()





    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC00066_vxlan_ms_trm_Spine_ClearIpMoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def Trigger7ClearIpMroute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site1_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip mroute *")

        countdown(20)

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()





    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC00067_vxlan_ms_trm_Spine_Clear_OSPF(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def Trigger8ClearOspfNeigh(self, testscript, testbed):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))

        for uut in site1_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip ospf neighbor *")

        countdown(20)

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC00068_vxlan_ms_trm_Spine_Clear_IP_Bgp(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 



    @aetest.test
    def Trigger9ClearIpBgp(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))


        for uut in site1_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip bgp *")

        countdown(20)

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC00069_vxlan_ms_trm_Spine_Clear_Bgp_l2vpn(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting Trigger10ClearBgpL2vpnEvpn @ spine"))
        for uut in site1_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear bgp l2vpn evpn *")
                #uut.execute(' clear bgp all *')
        countdown(20)

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC00070_vxlan_ms_trm_Spine_Clear_Bgp_mvpn(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting Trigger10ClearBgpL2vpnEvpn @ spine"))
        for uut in [site1_spine_uut_list[0]]:
            for i in range(1,3):
                uut.execute("clear bgp ipv4 mvpn *")
                #uut.execute(' clear bgp all *')
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting Trigger10ClearBgpL2vpnEvpn @ spine"))
        for uut in [site1_spine_uut_list[1]]:
            for i in range(1,3):
                uut.execute("clear bgp ipv4 mvpn *")
                #uut.execute(' clear bgp all *')
        countdown(20)

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC00071_vxlan_ms_trm_Clear_ARP_MAC(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

    @aetest.test
    def Trigger11ClearArpMac(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac @ bgw"))

        for uut in site1_bgw_uut_list:
            for i in range(1,5):
                uut.execute("clear ip arp vrf all")
                uut.execute("clear mac add dy")

        countdown(20)

        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed() 

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

 
class TC0001111_vxlan_ms_trm_bgw1_reload(aetest.Testcase):
    ###    This is description for my tecase two
    ###Remove/Add Multisite-config from one L3VNI on all Border Gatweays -
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 

   
    @aetest.test
    def bgwReload(self, testscript, testbed):
        
        log.info(banner("S T A R T I N G     vTEP  Site1   R E L O A D"))       
        start_time1 = time.time()
                    
        try:
            reloaduut(site1_bgw_uut_list[0])       
            countdown(90)

            site1_bgw_uut_list[0].execute('termin len 0')  
            if not nodeStateCheck(site1_bgw_uut_list[0]):
                log.info('nodeStateCheck Failed')

        except:
            log.info('site1_bgw_uut_list[0] reload failed ')
            self.failed()

        elapsed_time1 = time.time() - start_time1
        log.info(banner("C O M P L E A T E D    vTEP  R E L O A D"))
        log.info("Time taken for reloading site 1 vTEP's is %r",elapsed_time1)
 
        log.info("----------------------------------------------")  

        log.info("----------------------------------------------")

        log.info(banner("S T A R T I N G     vTEP Site 2    R E L O A D"))       
        start_time2 = time.time()
                    
        try:
            reloaduut(site2_bgw_uut_list[0])       
            countdown(90)

            site2_bgw_uut_list[0].execute('termin len 0')  
            if not nodeStateCheck(site2_bgw_uut_list[0]):
                log.info('nodeStateCheck Failed')
        except:
            log.info('site1_bgw_uut_list[0] reload failed ')
            self.failed()

        elapsed_time2 = time.time() - start_time2

        log.info(banner("C O M P L E A T E D    vTEP 2  R E L O A D"))

        log.info("--------------------------------------------------------")
        log.info("Time taken for reloading site 2 vTEP's is %r",elapsed_time2)
        log.info("Time taken for reloading site 1 vTEP's is %r",elapsed_time1)
        log.info("--------------------------------------------------------")  
 

 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):

            log.info('msTrmTrafficTest failed')
            if not trmCheck(site1_leaf_uut_list,[site2_bgw_uut_list[0]],site1_bgw_uut_list,routing_vlan_scale,group_list):
                log.info('trmCheck failed')
            test1 = bgw_peer_check(site1_bgw_uut_list+[site2_bgw_uut_list[0]]+site3_bgw_uut_list)
            if not test1:
                log.info(banner('bgw_peer_check failed'))

            countdown(25)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
            self.failed()   


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

class TC0001111_vxlan_ms_trm_spine_reload(aetest.Testcase):
    ###    This is description for my tecase two
    ###Remove/Add Multisite-config from one L3VNI on all Border Gatweays -
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def bgwReload(self, testscript, testbed):
        
        log.info(banner("S T A R T I N G     vTEP     R E L O A D"))       
        start_time = time.time()
                    
        try:
            reloaduut(site1_spine_uut_list[0])       
            countdown(120)
            site1_spine_uut_list[0].execute('termin len 0')  
            if not nodeStateCheck(site1_spine_uut_list[0]):
                log.info('nodeStateCheck Failed') 
        except:
            log.info('site1_spine_uut_list[0] reload failed ')
            self.failed()

        elapsed_time = time.time() - start_time
        log.info(banner("C O M P L E A T E D    vTEP  R E L O A D"))
        log.info("Time taken for reloading vTEP's is %r",elapsed_time)
 
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC0001111_vxlan_ms_trm_all_bgw_reload(aetest.Testcase):
    ###    This is description for my tecase two
    ###Remove/Add Multisite-config from one L3VNI on all Border Gatweays -
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def bgwReload(self, testscript, testbed):
        
        log.info(banner("S T A R T I N G     vTEP     R E L O A D"))       
        start_time = time.time()
                    
        try:     
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))
            countdown(120)
            for uut in site1_bgw_uut_list:
                uut.execute('termin len 0')  
                if not nodeStateCheck(uut):
                    log.info('nodeStateCheck Failed %r'.uut)

        except:
            log.info('site1_bgw_uut_list[0] reload failed ')
            self.failed()

        elapsed_time = time.time() - start_time
        log.info(banner("C O M P L E A T E D    vTEP  R E L O A D"))
        log.info("Time taken for reloading vTEP's is %r",elapsed_time)
 
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

class TC0001111_vxlan_ms_trm_bgw2_ascii_reload(aetest.Testcase):
    ###    This is description for my tecase two
    ###Remove/Add Multisite-config from one L3VNI on all Border Gatweays -
    def setup(self):
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed in Setup')                                                      
            #pcall(MsTrmReset,uut=tuple(bgw_uut_list))
            pcall(reloaduut,uut=tuple(site1_bgw_uut_list))       
            countdown(120)
            if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
                port002=port_handle_sw1site2,rx_rate002=rateFull,\
                port003=port_handle_sw1site3,rx_rate003=rateOrphan):
                self.failed(goto=['common_cleanup'])

    @aetest.test
    def bgwReload(self, testscript, testbed):
        
        log.info(banner("S T A R T I N G     vTEP     R E L O A D"))       
        start_time = time.time()
                    
        try:
            Asciireloaduut(site1_bgw_uut_list[1])       
            countdown(100)

            site1_bgw_uut_list[1].execute('termin len 0')  
            if not nodeStateCheck(site1_bgw_uut_list[1]):
                log.info('nodeStateCheck Failed')

   
        except:
            log.info('site1_bgw_uut_list[0] reload failed ')
            self.failed()

        elapsed_time = time.time() - start_time
        log.info(banner("C O M P L E A T E D    vTEP  R E L O A D"))
        log.info("Time taken for reloading vTEP's is %r",elapsed_time)
 
 
        if not msTrmTrafficTestFullTimed(port001=port_handle_sw1site1,rx_rate001=rateFull,\
            port002=port_handle_sw1site2,rx_rate002=rateFull,\
            port003=port_handle_sw1site3,rx_rate003=rateOrphan):
            log.info('msTrmTrafficTest failed')
            self.failed()   


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        result_list = []
        for uut in site1_bgw_uut_list:
            #check = csvxlanall(uut)
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                log.info('CS failed for uut: %r',uut)
                result_list.append('fail')
        if 'fail' in result_list:
            log.info('CC failed, Starting clearMultisitevxlanCC ')
            pcall(clearMultisitevxlanCC,uut=tuple(site1_bgw_uut_list))
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class common_cleanup(aetest.CommonCleanup):

    @aetest.subsection
    def stop_tgn_streams(self):
        pass

    @aetest.subsection
    def disconnect_from_tgn(self):
        pass

if __name__ == '__main__':  # pragma: no cover
    aetest.main()        
 