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
    'vni' : 201001,
    'vlan_vni_scale' : 32,
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
    'test_mac1' : '00a7.0001.0001',
    'rate' : '200000',
    'tolerence' : 3000
    }
###################################################################
###                  COMMON SETUP SECTION                       ###
###################################################################

# Configure and setup all devices and test equipment in this section.
# This should represent the BASE CONFIGURATION that is applicable
# for the bunch of test cases that would follow.

 
class common_setup(aetest.CommonSetup):
    """ Common Setup """
    @aetest.subsection
    def testbed_init(self, testscript, testbed):

        global uut_list,leaf_uut_list,spine_uut_list ,bgw_uut_list,sw_uut_list , l3_uut_list,l3_site_uut_list,\
        site1_uut_list,site1_leaf_uut_list,site1_spine_uut_list ,site1_bgw_uut_list,site1_sw_uut_list,\
        site2_uut_list,site2_leaf_uut_list,site2_spine_uut_list ,site2_bgw_uut_list,site2_sw_uut_list,\
        site3_uut_list,site3_leaf_uut_list,site3_spine_uut_list ,site3_bgw_uut_list,site3_sw_uut_list,dci_uut_list,\
        tgn1_sw1site2_intf1,tgn1_sw1site3_intf1,tgn1_bgw1site2_intf1,tgn1_bgw2site2_intf1,tgn1_sw1site1_intf1,\
        orphan_handle_list,orphan_handle_list2,port_handle_list,labserver_ip,tgn_ip,\
        vlan_start,vlan_vni_scale,rate,tolerence,vni,routed_vlan,routed_vni,routing_vlan_scale,\
        ipv4_add,ipv6_add,mcast_group,mcast_group_scale,bgp_as_number,pps,vlan_range


        uut_list = [];leaf_uut_list = [];spine_uut_list =[] ;bgw_uut_list =[];sw_uut_list=[] ; dci_uut_list = [];\
        site1_uut_list = []; site1_leaf_uut_list =[]; site1_spine_uut_list = [];site1_bgw_uut_list =[] ;site1_sw_uut_list =[];\
        site2_uut_list = []; site2_leaf_uut_list =[]; site2_spine_uut_list = [];site2_bgw_uut_list =[] ;site2_sw_uut_list =[];\
        site3_uut_list = []; site3_leaf_uut_list =[]; site3_spine_uut_list = [];site3_bgw_uut_list =[] ;site3_sw_uut_list =[]


        tgn1_sw1site2_intf1 = testbed.devices['tgn1'].interfaces['tgn1_sw1site2_intf1'].intf
        tgn1_sw1site3_intf1 = testbed.devices['tgn1'].interfaces['tgn1_sw1site3_intf1'].intf
        tgn1_sw1site1_intf1 = testbed.devices['tgn1'].interfaces['tgn1_sw1site1_intf1'].intf
        tgn1_bgw1site2_intf1 = testbed.devices['tgn1'].interfaces['tgn1_bgw1site2_intf1'].intf
        tgn1_bgw2site2_intf1 = testbed.devices['tgn1'].interfaces['tgn1_bgw2site2_intf1'].intf

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
                elif 'spine' in (testbed.devices[device].alias):
                    site3_spine_uut_list.append(testbed.devices[device])
                    spine_uut_list.append(testbed.devices[device])
                elif 'bgw' in (testbed.devices[device].alias):
                    site3_bgw_uut_list.append(testbed.devices[device])
                    bgw_uut_list.append(testbed.devices[device])
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
        #ir_mode = parameters['ir_mode']
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
            except:
                log.info(banner('connect failed once ; clearing console'))
                if 'port' in uut.connections['a']:
                    ts = str(uut.connections['a']['ip'])
                    port=str(uut.connections['a']['port'])[-2:]
                    u = Utils()
                    u.clear_line(ts, port, 'lab', 'lab')
                    countdown(10)
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
    def precleanup(self, testscript, testbed):
        log.info(banner("Base cleanup"))


        result = pcall(DeviceVxlanPreCleanupAll,uut=(l3_uut_list[0],l3_uut_list[1],l3_uut_list[2],l3_uut_list[3],\
            l3_uut_list[4],l3_uut_list[5],l3_uut_list[6],l3_uut_list[7],l3_uut_list[8],l3_uut_list[9],\
            l3_uut_list[10],l3_uut_list[11],l3_uut_list[12],l3_uut_list[13],l3_uut_list[14],l3_uut_list[15],\
            l3_uut_list[16]))

        if not result:
            log.info('DeviceVxlanPreCleanupAll Failed ')
            self.failed(goto=['common_cleanup'])   

        result = pcall(SwVxlanPreCleanup,uut=(sw_uut_list[0],sw_uut_list[1],sw_uut_list[2]))

        if not result:
            log.info('SwVxlanPreCleanup Failed ')
            self.failed(goto=['common_cleanup'])  

 
    @aetest.subsection
    def base_configs(self, testscript, testbed):
        log.info(banner("Base configurations"))

        log.info(banner("Base vxlanL3NodeCommonConfig"))       
        result = pcall(vxlanL3NodeCommonConfig,uut=(l3_uut_list[0],l3_uut_list[1],l3_uut_list[2],l3_uut_list[3],\
            l3_uut_list[4],l3_uut_list[5],l3_uut_list[6],l3_uut_list[7],l3_uut_list[8],l3_uut_list[9],\
            l3_uut_list[10],l3_uut_list[11],l3_uut_list[12],l3_uut_list[13],l3_uut_list[14],l3_uut_list[15],\
            l3_uut_list[16]))

        if not result:
            log.info('vxlanL3NodeCommonConfig Failed ')
            self.failed(goto=['common_cleanup'])           
 
    @aetest.subsection
    def gwandLoopconfigs(self, testscript, testbed):
        log.info(banner("Base configurations"))

        log.info(banner("Base anycastgatewayConfig"))    
        pcall(anycastgatewayConfig10,uut=(leaf_uut_list[0],leaf_uut_list[1],leaf_uut_list[2],leaf_uut_list[3],\
            leaf_uut_list[4],leaf_uut_list[5],bgw_uut_list[0],bgw_uut_list[1],bgw_uut_list[2],bgw_uut_list[3],\
            bgw_uut_list[4]))
 
        log.info(banner("Base ConfigureLoopback"))    
        pcall(ConfigureLoopback,uut=(l3_uut_list[0],l3_uut_list[1],l3_uut_list[2],l3_uut_list[3],\
            l3_uut_list[4],l3_uut_list[5],l3_uut_list[6],l3_uut_list[7],l3_uut_list[8],l3_uut_list[9],\
            l3_uut_list[10],l3_uut_list[11],l3_uut_list[12],l3_uut_list[13],l3_uut_list[14],l3_uut_list[15],\
            l3_uut_list[16]))
 
    @aetest.subsection
    def l3_port_configs(self, testscript, testbed):
        log.info(banner("Base configurations"))

        log.info(banner("Base l3_port_configure"))  
        #pdb.set_trace()  
        pcall(ConfigureL3PortvxlanMultisite,uut=(l3_uut_list[0],l3_uut_list[1],l3_uut_list[2],l3_uut_list[3],\
            l3_uut_list[4],l3_uut_list[5],l3_uut_list[6],l3_uut_list[7],l3_uut_list[8],l3_uut_list[9],\
            l3_uut_list[10],l3_uut_list[11],l3_uut_list[12],l3_uut_list[13],l3_uut_list[14],l3_uut_list[15],\
            l3_uut_list[16]))
  
    @aetest.subsection
    def igp_configure(self):
        log.info(banner("igp_configure ConfigureIgpvxlanMultisite"))  
        pcall(ConfigureIgpvxlanMultisite,uut=(l3_site_uut_list[0],l3_site_uut_list[1],l3_site_uut_list[2],l3_site_uut_list[3],\
            l3_site_uut_list[4],l3_site_uut_list[5],l3_site_uut_list[6],l3_site_uut_list[7],l3_site_uut_list[8],l3_site_uut_list[9],\
            l3_site_uut_list[10],l3_site_uut_list[11],l3_site_uut_list[12],l3_site_uut_list[13],l3_site_uut_list[14]))
    

        countdown(60)

        log.info(banner("Starting igp verify Section"))
        for uut in leaf_uut_list:
            for feature in ['ospf']:
                test1 = protocolStateCheck(uut,[feature])
                if not test1:
                    log.info('Feature %r neigborship on device %r Failed ',feature,str(uut))
                    self.failed(goto=['common_cleanup'])

   
    @aetest.subsection  
    def pim_configure(self):
        log.info(banner("pim_configure"))  
        for spine_list,leaf_list,bgw_list in zip([site1_spine_uut_list,site2_spine_uut_list,site3_spine_uut_list],\
            [site1_leaf_uut_list ,site2_leaf_uut_list,site3_leaf_uut_list],\
            [site1_bgw_uut_list,site2_bgw_uut_list,site3_bgw_uut_list]):

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

        countdown(60)

        log.info(banner("Starting pim verify Section"))
        for uut in leaf_uut_list:
            for feature in ['pim']:
                test1 = protocolStateCheck(uut,[feature])
                if not test1:
                    log.info('Feature %r neigborship on device %r Failed ',feature,str(uut))
                    self.failed(goto=['common_cleanup'])
  
    @aetest.subsection
    def site_internal_bgp_configure(self):
        log.info(banner("BGP site_internal_bgp_configure configurations"))
        for spine_list,leaf_list,bgw_list,as_num in zip([site1_spine_uut_list,site2_spine_uut_list,site3_spine_uut_list],\
            [site1_leaf_uut_list ,site2_leaf_uut_list,site3_leaf_uut_list],\
            [site1_bgw_uut_list,site2_bgw_uut_list,site3_bgw_uut_list],\
            ['65001','65002','65003']):

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

 
        countdown(60)

        log.info(banner("Starting bgp verify Section"))
        for uut in leaf_uut_list:
            for feature in ['bgp']:
                test1 = protocolStateCheck(uut,[feature])
                if not test1:
                    log.info('Feature %r neigborship on device %r Failed ',feature,str(uut))
                    self.failed(goto=['common_cleanup'])

 
    @aetest.subsection
    def access_port_configure(self):
        #log.info(banner("Configuring Ports to TGN"))

        pcall(accessPortConfigure,uut=(sw_uut_list[0],sw_uut_list[1],sw_uut_list[2],\
            leaf_uut_list[0],leaf_uut_list[1],leaf_uut_list[2],leaf_uut_list[3],\
            leaf_uut_list[4],leaf_uut_list[5],bgw_uut_list[0],bgw_uut_list[1],\
            bgw_uut_list[2],bgw_uut_list[3],bgw_uut_list[4]),vlan_range=(vlan_range,vlan_range,\
            vlan_range,vlan_range,vlan_range,vlan_range,vlan_range,vlan_range,vlan_range,vlan_range,\
            vlan_range,vlan_range,vlan_range,vlan_range))

        log.info(banner("Configuring Ports Channel in Switches"))

        pcall(swPoConfigure,uut=(sw_uut_list[0],sw_uut_list[1],sw_uut_list[2]),\
                     vlan_range=(vlan_range,vlan_range,vlan_range))

        #swPoConfigure(sw_uut_list[1],vlan_range)
   
    @aetest.subsection
    def vpc_configure(self):
        log.info(banner("Configuring Ports Channel/VPC in Leaf devices"))

        log.info(banner("Configuring MCT"))

        for uut in leaf_uut_list:
            mct_port_member_list = []
            for intf in [*uut.interfaces.keys()]:            
                if 'mct_link' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    log.info("adding mct port-channel member %r on leaf device  %r",intf,uut)
                    mct_port_member_list.append(intf)

            for intf in [*uut.interfaces.keys()]:
                if 'mct_po' in uut.interfaces[intf].alias:
                    log.info("mct port-channel is %r on leaf device  %r",intf,uut)
                    mct_po_number = uut.interfaces[intf].intf
                    src_ip = uut.interfaces[intf].src_ip
                    peer_ip = uut.interfaces[intf].peer_ip
            
            try:
                vtep_vpc_global_obj1 = VPCNodeGlobal(uut,mct_po_number,str(peer_ip),\
                mct_port_member_list,str(src_ip))
                vtep_vpc_global_obj1.vpc_global_conf()
            except:
                log.error('vtep_vpc_global_obj1.vpc_global_conf failed for uut %r',uut)
                self.failed(goto=['common_cleanup'])
        
        log.info(banner("Completed MCT Configure, Starting vPC Po"))
     
        for uut in leaf_uut_list:
            vpc_po_list = []
            vpc_access_port_member_list_101 = []
            vpc_access_port_member_list_122 = []
            vpc_access_port_member_list_133 = []

            for intf in [*uut.interfaces.keys()]:
                if 'vpc_po_122' in uut.interfaces[intf].alias:
                    log.info("vpc port-channel is %r on leaf device  %r",intf,uut)
                    vpc_po_number = uut.interfaces[intf].intf
                    vpc_po_list.append(vpc_po_number)

                elif 'vpc_po_133' in uut.interfaces[intf].alias:
                    log.info("vpc port-channel is %r on leaf device  %r",intf,uut)
                    vpc_po_number = uut.interfaces[intf].intf
                    vpc_po_list.append(vpc_po_number)

                elif 'vpc_po_101' in uut.interfaces[intf].alias:
                    log.info("vpc port-channel is %r on leaf device  %r",intf,uut)
                    vpc_po_number = uut.interfaces[intf].intf
                    vpc_po_list.append(vpc_po_number)


            for intf in [*uut.interfaces.keys()]:            
                if 'vpc_access122' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    log.info("adding vpc port-channel member %r on leaf device  %r",intf,uut)
                    vpc_access_port_member_list_122.append(intf)
         
                elif 'vpc_access133' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    log.info("adding vpc port-channel member %r on leaf device  %r",intf,uut)
                    vpc_access_port_member_list_133.append(intf)
         
                elif 'vpc_access101' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    log.info("adding vpc port-channel member %r on leaf device  %r",intf,uut)
                    vpc_access_port_member_list_101.append(intf)


            log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            log.info('uut is  %r',uut)
            log.info('vpc_po_listis %r',vpc_po_list)
            log.info('vpc_access_port_member_list_101 %r',vpc_access_port_member_list_101)
            log.info('vpc_access_port_member_list_122 %r',vpc_access_port_member_list_122)
            log.info('vpc_access_port_member_list_133 %r',vpc_access_port_member_list_133)
            log.info("+++++++++++++++++++++++++++++++++++++++++++++++++++++++")

            for vpc_po in vpc_po_list:
                if '101' in vpc_po:
                    try:
                        vtep_vpc_obj1 = VPCPoConfig(uut,vpc_po,vpc_access_port_member_list_101,\
                        vlan_range,'trunk')
                        vtep_vpc_obj1.vpc_conf()
                    except:
                        log.error('vtep_vpc_obj1.vpc_conf failed for %r',uut)
                        self.failed(goto=['common_cleanup'])

                elif '122' in vpc_po:
                    try:
                        vtep_vpc_obj1 = VPCPoConfig(uut,vpc_po,vpc_access_port_member_list_122,\
                        'none','trunk')
                        vtep_vpc_obj1.vpc_conf()
                    except:
                        log.error('vtep_vpc_obj1.vpc_conf failed for %r',uut)
                        self.failed(goto=['common_cleanup'])

                elif '133' in vpc_po:
                    try:
                        vtep_vpc_obj1 = VPCPoConfig(uut,vpc_po,vpc_access_port_member_list_133,\
                        'none','trunk')
                        vtep_vpc_obj1.vpc_conf()
                    except:
                        log.error('vtep_vpc_obj1.vpc_conf failed for %r',uut)
                        self.failed(goto=['common_cleanup'])

    @aetest.subsection
    def vpcVerify(self):
        log.info(banner("Starting VPC verify Section"))
        countdown(180)

        for uut in site2_leaf_uut_list+site3_leaf_uut_list:
            op=uut.execute('show port-channel summary | incl Eth')
            op1=op.splitlines()
            for line in op1:
                if line:
                    if not "(P)" in line:
                        log.info('VPC Bringup Failed on device %r',str(uut))
                        uut.execute('show port-channel summary')
                        self.failed(goto=['common_cleanup'])
 
    
 
    @aetest.subsection
    def configureTgn(self, testscript, testbed):
        """ common setup subsection: connecting devices """

        global tgen, port_handle_sw1site2,port_handle_sw1site3,\
        port_handle_bgw1site2,port_handle_bgw2site2,orphan_handle_list,port_handle_list,orphan_handle_list2

        port_handle = ConnectSpirent(labserver_ip,tgn_ip,[tgn1_sw1site2_intf1,tgn1_sw1site3_intf1,\
            tgn1_bgw1site2_intf1,tgn1_bgw2site2_intf1,tgn1_sw1site1_intf1])
 
        port_handle_sw1site1 = port_handle[tgn1_sw1site1_intf1]
        port_handle_sw1site2 = port_handle[tgn1_sw1site2_intf1]
        port_handle_sw1site3 = port_handle[tgn1_sw1site3_intf1]
        port_handle_bgw1site2 = port_handle[tgn1_bgw1site2_intf1]
        port_handle_bgw2site2 = port_handle[tgn1_bgw2site2_intf1]        


        port_handle_list = [port_handle_sw1site2,port_handle_bgw2site2,port_handle_sw1site3,port_handle_bgw1site2,port_handle_sw1site1]
        orphan_handle_list2 = [port_handle_sw1site1]
        orphan_handle_list = [port_handle_sw1site1,port_handle_bgw1site2,port_handle_bgw2site2]
 
#######################################################################
###                          TESTCASE BLOCK                         ###
#######################################################################
#
# Place your code that implements the test steps for the test case.
# Each test may or may not contains sections:
#           setup   - test preparation
#           test    - test action
#           cleanup - test wrap-up

 
 
class TC001_vxlan_configs(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def vxlan_configs_site1(self, testscript, testbed):
        log.info(banner("VXLAN configurations"))

        pcall(vxlanConfigure,uut=(site1_bgw_uut_list[0],site1_leaf_uut_list[0],site1_leaf_uut_list[1],\
            site2_bgw_uut_list[0],site2_bgw_uut_list[1],site2_leaf_uut_list[0],site2_leaf_uut_list[1],\
            site3_bgw_uut_list[0],site3_bgw_uut_list[1],site3_leaf_uut_list[0],site3_leaf_uut_list[1]),\
            l2_scale =(32,32,32,32,32,32,32,32,32,32,32),\
            l3_scale =(4,4,4,4,4,4,4,4,4,4,4),\
            mode=('mix','mix','mix','mix','mix','mix','mix','mix','mix','mix','mix'),\
            as_num=('65001','65001','65001','65002','65002','65002','65002','65003','65003','65003','65003'))

        countdown(120)

    @aetest.cleanup
    def cleanup(self):
        log.info("Pass testcase cleanup")

 
class TC002_Nve_Peer_State_Verify(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def check_nve_peer_state(self):

        test1 = NvePeerCheck(leaf_uut_list,1)
        if not test1:
            log.info(banner("NvePeerCheck F A I L E D"))
            #self.failed()

    @aetest.cleanup
    def cleanup(self):
        pass

class TC003_Nve_Vni_State_Verify(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.test
    def check_nve_vni_state(self):
        for uut in leaf_uut_list:
            uut.execute('terminal length 0')

            test1 = protocolStateCheck(uut,['nve-vni'])
            if not test1:
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

class TC004_Vxlan_Consistency_check(aetest.Testcase):
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


 
class TC005_vxlan_dci_bgp_configs(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
     
    @aetest.test
    def dcibfdEnable(self):

        log.info("+++ Starting bfdEnable +++")      
        try:
            pcall(bfdEnable,uut=(l3_uut_list[0],l3_uut_list[1],l3_uut_list[2],l3_uut_list[3],\
            l3_uut_list[4],l3_uut_list[5],l3_uut_list[6],l3_uut_list[7],l3_uut_list[8],l3_uut_list[9],\
            l3_uut_list[10],l3_uut_list[11],l3_uut_list[12],l3_uut_list[13],l3_uut_list[14],l3_uut_list[15],\
            l3_uut_list[16]))
        except:
            log.error('bfdEnable failed ##')
            self.failed()


        log.info("+++ Starting dciEbgpv4Bringup +++")
    
    @aetest.test
    def dciEbgpv4Bringup(self):

        try:
 
            pcall(dcibgwebgpv4,uut=(dci_uut_list[0],dci_uut_list[1]))
            pcall(bgwdciebgpv4,uut=(bgw_uut_list[0],bgw_uut_list[1],bgw_uut_list[2],bgw_uut_list[3],bgw_uut_list[4]))
        except:
            log.error('multiSiteEnable ##')
            self.failed()
    
    @aetest.test
    def dciEbgpevpn4Bringup(self):

        try:
            pcall(multisiteDcibgpEvpn,uut=(dci_uut_list[0],dci_uut_list[1]))
            pcall(multisitebgwbgpEvpn,uut=(bgw_uut_list[0],bgw_uut_list[1],bgw_uut_list[2],bgw_uut_list[3],bgw_uut_list[4]),\
                as_num=('65001','65002','65002','65003','65003'))

        except:
            log.error('multiSiteEnable ##')
            self.failed()
      
        countdown(120)
 

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
        """ testcase clean up """
        pass

 
class TC006_vxlan_multisite_configs(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
    
    @aetest.test
    def multiSiteEnable(self):

        try:
            pcall(multiSiteEnable,uut=(site1_bgw_uut_list[0],site2_bgw_uut_list[0],\
            site2_bgw_uut_list[1],site3_bgw_uut_list[0],site3_bgw_uut_list[1]),\
            vni=(101001,101001,101001,101001,101001),scale=(32,32,32,32,32))

        except:
            log.error('multiSiteEnable ##')
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC006_vxlan_multisite_traffic_BGW_standalone_mode(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):

        for uut in leaf_uut_list+bgw_uut_list+sw_uut_list:
            uut.configure('system no hap-reset ')
            for i in range(1,2):
                uut.execute('clear mac address-table dynamic')
                uut.execute('clear ip arp vrf all')

        log.info(banner("Resetting the streams"))
        for port_hdl in  [port_handle_list]:
            sth.traffic_control (port_handle = port_hdl, action = 'reset', db_file=0 )

        log.info(banner("Finding the IP address"))
        ip_sa1=str(ip_address(find_svi_ip222(site1_leaf_uut_list[0],vlan_start))+10)
        ip_sa2=str(ip_address(ip_sa1)+10)
        ip_sa11=str(ip_address(ip_sa1)+40)
        ip_sa22=str(ip_address(ip_sa2)+40)
        
        log.info(banner("----Generating hosts and flood traffic----"))
        test1= FloodTrafficGeneratorScale(port_handle_sw1site2,vlan_start,ip_sa1,'100.100.100.100',rate,str(vlan_vni_scale))
        test2= FloodTrafficGeneratorScale(port_handle_sw1site3,vlan_start,ip_sa2,'200.200.200.200',rate,str(vlan_vni_scale))
        

        log.info(banner("----Generating hosts Unicast Bidir Traffic----"))

        SpirentBidirStream222(port_hdl1=port_handle_sw1site2,port_hdl2=port_handle_sw1site3,vlan1=vlan_start,vlan2=vlan_start,\
        scale=1,ip1=ip_sa11,ip2=ip_sa22,gw1=ip_sa22,gw2=ip_sa11,rate_pps=rate)

        
        log.info(banner("----Generating Routed Bidir Traffic----"))

        if not SpirentRoutedBidirStream(site1_leaf_uut_list[0],port_handle_sw1site2,port_handle_sw1site3,pps):
            self.failed()


        log.info(banner("----Generating IPV6 Unicast Traffic----"))

        log.info(banner("Finding the IPv6 address"))
        vlan = 'vlan' + str(vlan_start)
        ipv6_sa1=str(ip_address(findIntfIpv6Addr(site1_leaf_uut_list[0],vlan))+10)
        ipv6_sa2=str(ip_address(ipv6_sa1)+100)

        SpirentV6BidirStream(port_handle_sw1site2,port_handle_sw1site3,vlan_start,vlan_start,vlan_vni_scale,\
            ipv6_sa1,ipv6_sa2,rate)

        
        log.info(banner("Starting Traffic and counting 120 seconds"))


        log.info(banner("ARP for all streams"))
        for i in range(1,7):
            doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')

        sth.traffic_control(port_handle = 'all', action = 'run')

        countdown(180)
      

        log.info(banner("ARP for all streams"))
        for i in range(1,7):
            doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')

        countdown(30)
       
    @aetest.test
    def vxlan_traffic_test_all(self):

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            self.failed(goto=['common_cleanup'])


    @aetest.cleanup
    def cleanup(self):
        pass


class TC007_vxlan_multisite_BGW_standalone_mode_bringup(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
    
    @aetest.test
    def BGWstandalonemode(self):
        if not nodeIsolate(site2_bgw_uut_list[1]):
            self.failed()

        countdown(200)
    
    @aetest.test
    def vxlan_traffic_test_all(self):

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            self.failed(goto=['common_cleanup'])


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

 
class TC008_vxlan_multisite_bgw_sa_l2fm_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,2):
                ProcessRestart(uut,'l2fm')


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC009_vxlan_multisite_bgw_sa_l2rib_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,2):
                ProcessRestart(uut,'l2rib')


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC010_vxlan_multisite_bgw_sa_nve_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,2):
                ProcessRestart(uut,'nve')


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC011_vxlan_multisite_bgw_sa_vlan_mgr_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,2):
                ProcessRestart(uut,'vlan_mgr')


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC012_vxlan_multisite_bgw_sa_ethpm_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,2):
                ProcessRestart(uut,'ethpm')


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC013_vxlan_multisite_bgw_sa_ospf_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,2):
                ProcessRestart(uut,'ospf')


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

class TC014_vxlan_multisite_bgw_sa_fabric_link_failover1(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def bgwfabriclinkfailover1(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw1site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
         
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()       

    @aetest.test
    def bgwfabriclinkrecover1(self, testscript, testbed):      
        for uut in [site2_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw1site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()       

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for uut in [site2_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw1site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


class TC015_vxlan_multisite_bgw_sa_fabric_link_failover2(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def bgwfabriclinkfailover2(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw1site2_spine2site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
         
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()

    @aetest.test
    def bgwfabriclinkrecover2(self, testscript, testbed):       
        for uut in [site2_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw1site2_spine2site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for uut in [site2_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw1site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


class TC016_vxlan_multisite_bgw_sa_spine1_isolation(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def spine1isolation(self, testscript, testbed):
        log.info(banner("Starting spine1isolation @ 8"))

        if not nodeIsolate(site2_spine_uut_list[0]):
            self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            nodeNoIsolate(site2_spine_uut_list[0])
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def spine1Noisolation(self, testscript, testbed):
        log.info(banner("Starting spine1Noisolation @ 8"))
        if not nodeNoIsolate(site2_spine_uut_list[0]):
            self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

         
class TC017_vxlan_multisite_bgw_sa_spine2_isolation(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def spine2isolation(self, testscript, testbed):
        log.info(banner("Starting spine2isolation @ 8"))

        if not nodeIsolate(site2_spine_uut_list[1]):
            self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            nodeNoIsolate(site2_spine_uut_list[1])
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def spine2Noisolation(self, testscript, testbed):
        log.info(banner("Starting spine2Noisolation @ 8"))
        if not nodeNoIsolate(site2_spine_uut_list[1]):
            self.failed()


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC018_vxlan_multisite_bgw_sa_dci1_router_failover(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def dci1isolation(self, testscript, testbed):
        log.info(banner("Starting dci1isolation @ 8"))

        if not nodeIsolate(dci_uut_list[0]):
            self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            nodeNoIsolate(dci_uut_list[0])
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def dci1Noisolation(self, testscript, testbed):
        log.info(banner("Starting dci1Noisolation @ 8"))
        if not nodeNoIsolate(dci_uut_list[0]):
            self.failed()


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC019_vxlan_multisite_bgw_sa_dci2_router_failover(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def dci2isolation(self, testscript, testbed):
        log.info(banner("Starting dci2isolation @ 8"))

        if not nodeIsolate(dci_uut_list[1]):
            self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            nodeNoIsolate(dci_uut_list[1])
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def dci2Noisolation(self, testscript, testbed):
        log.info(banner("Starting dci2Noisolation @ 8"))
        if not nodeNoIsolate(dci_uut_list[1]):
            self.failed()


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC020_vxlan_multisite_bgw_sa_dci_link_failover1(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def dci1linkfailover1(self, testscript, testbed):       
        for uut in [site2_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw1site2_dci1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
 
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def dci1linkrecover1(self, testscript, testbed):       
        for uut in [site2_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw1site2_dci1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC021_vxlan_multisite_bgw_sa_dci_link_failover2(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def dci1linkfailover1(self, testscript, testbed):       
        for uut in [site2_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw1site2_dci2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
 
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def dci1linkrecover1(self, testscript, testbed):       
        for uut in [site2_bgw_uut_list[0]]:
            for intf in [*uut.interfaces.keys()]:
                if 'bgw1site2_dci2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC022_vxlan_multisite_bgw_sa_ospf_shut_noshut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        cfg_shut =\
        """
        router bgp 65002
        shut
        """
        cfg_noshut =\
        """
        router bgp 65002
        no shut
        """
        site2_bgw_uut_list[0].configure(cfg_shut)
        countdown(15)
        site2_bgw_uut_list[0].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC023_vxlan_multisite_bgw_sa_bgp_shut_noshut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
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
        site2_bgw_uut_list[0].configure(cfg_shut)
        countdown(15)
        site2_bgw_uut_list[0].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


  
 
class TC024_vxlan_multisite_bgw_sa_spine1_ospf_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting bgw_sa_spine1_ospf_shut @ 8"))
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
        site2_spine_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site2_spine_uut_list[0].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
 
class TC025_vxlan_multisite_bgw_sa_spine2_ospf_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting bgw_sa_spine2_ospf_shut @ 8"))
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
        site2_spine_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site2_spine_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()




    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC025_vxlan_multisite_bgw_sa_spine1_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting bgw_sa_spine1_bgp_shut @ 8"))
        cfg_shut =\
        """
        router bgp 65002
        shut
        """
        cfg_noshut =\
        """
        router bgp 65002
        no shut
        """
        site2_spine_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site2_spine_uut_list[0].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()




    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

class TC026_vxlan_multisite_bgw_sa_spine2_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting bgw_sa_spine2_bgp_shut @ 8"))
        cfg_shut =\
        """
        router bgp 65002
        shut
        """
        cfg_noshut =\
        """
        router bgp 65002
        no sh
        """
        site2_spine_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site2_spine_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()




    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC027_vxlan_multisite_bgw_sa_dci1_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting bgw_sa_dci1_bgp_shut @ 8"))
        cfg_shut =\
        """
        router bgp 99
        shut
        """
        cfg_noshut =\
        """
        router bgp 99
        no shut
        """
        dci_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            dci_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


        dci_uut_list[0].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC027_vxlan_multisite_bgw_sa_dci2_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting bgw_sa_dci1_bgp_shut @ 8"))
        cfg_shut =\
        """
        router bgp 99
        shut
        """
        cfg_noshut =\
        """
        router bgp 99
        no shut
        """
        dci_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            dci_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


        dci_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC028_vxlan_multisite_bgw_sa_restart_ospf(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            uut.execute('restart ospf UNDERLAY')
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC029_vxlan_multisite_bgw_sa_restart_bgp(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            uut.execute('restart bgp 65002')
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC030_vxlan_multisite_bgw_sa_restart_pim(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            uut.execute('restart pim')
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
class TC031_vxlan_multisite_bgw_sa_restart_igmp(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            uut.execute('restart igmp')
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC032_vxlan_multisite_bgw_sa_restart_mld(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            uut.execute('restart mld')
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


 
class TC033_vxlan_multisite_bgw_sa_bgw_sa_remote_bgw_nve_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgw1ospfshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        cfg_shut =\
        """
        interface nve 1
        shut
        """
        cfg_noshut =\
        """
        interface nve 1
        no shut
        """
        site3_bgw_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            countdown(100)
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                if not VxlanStReset([site2_bgw_uut_list[0]]):
                    self.failed(goto=['common_cleanup'])
                if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                    self.failed(goto=['common_cleanup'])
            self.failed()

        site3_bgw_uut_list[0].configure(cfg_noshut)

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            countdown(100)
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                if not VxlanStReset([site2_bgw_uut_list[0]]):
                    self.failed(goto=['common_cleanup'])
                if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                    self.failed(goto=['common_cleanup'])
            self.failed()

    @aetest.test
    def remotebgw2ospfshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))

        cfg_shut =\
        """
        interface nve 1
        shut
        """
        cfg_noshut =\
        """
        interface nve 1
        no shut
        """

        site3_bgw_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()

        site3_bgw_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()            

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC034_vxlan_multisite_bgw_sa_remote_bgw_ospf_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
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
        site3_bgw_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site3_bgw_uut_list[0].configure(cfg_noshut)
        site3_bgw_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()

        site3_bgw_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()            

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC035_vxlan_multisite_bgw_sa_remote_bgw_bgp_shut(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwbgpshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        cfg_shut =\
        """
        router bgp 65003
        shut
        """
        cfg_noshut =\
        """
        router bgp 65003
        no shut
        """
        site3_bgw_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site3_bgw_uut_list[0].configure(cfg_noshut)
        site3_bgw_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()

        site3_bgw_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()            

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
 
class TC036_vxlan_multisite_bgw_sa_Core_flap(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def Trigger5CoreIfFlap(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))

        if not TriggerCoreIfFlap222([site2_bgw_uut_list[0]]):
            log.info("TriggerCoreIfFlap222 failed @ 4")
            #self.failed()

        countdown(280)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC037_vxlan_multisite_bgw_sa_ClearIpRoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger6ClearIpRoute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,3):
                uut.execute("clear ip route *")

        countdown(160)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC038_vxlan_multisite_bgw_sa_clearIpMoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger7ClearIpMroute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,3):
                uut.execute("clear ip mroute *")

        countdown(160)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC039_vxlan_multisite_bgw_sa_clear_ospf_Neigh(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger8ClearOspfNeigh(self, testscript, testbed):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))

        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,3):
                uut.execute("clear ip ospf neighbor *")

        countdown(180)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC040_vxlan_multisite_bgw_sa_Clear_IP_Bgp(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger9ClearIpBgp(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))


        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,3):
                uut.execute("clear ip bgp *")

        countdown(180)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC041_vxlan_multisite_bgw_sa_Clear_Bgp_l2vpn(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting TriggerClearBgpL2vpnEvpn @ bgw"))

        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,3):
                uut.execute("clear bgp l2vpn evpn *")

        countdown(180)



        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC042_vxlan_multisite_bgw_sa_Spine_ClearIpRoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger6ClearIpRoute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip route *")

        countdown(160)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC043_vxlan_multisite_bgw_sa_Spine_ClearIpMoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger7ClearIpMroute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip mroute *")

        countdown(160)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC044_vxlan_multisite_bgw_sa_Spine_Clear_OSPF(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger8ClearOspfNeigh(self, testscript, testbed):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))

        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip ospf neighbor *")

        countdown(320)



        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC045_vxlan_multisite_bgw_sa_Spine_Clear_IP_Bgp(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger9ClearIpBgp(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))


        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip bgp *")

        countdown(320)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC046_vxlan_multisite_bgw_sa_Spine_Clear_Bgp_l2vpn(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting Trigger10ClearBgpL2vpnEvpn @ spine"))
        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear bgp l2vpn evpn *")
                #uut.execute(' clear bgp all *')
        countdown(320)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC047_vxlan_multisite_bgw_sa_Clear_ARP_MAC(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def Trigger11ClearArpMac(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac @ bgw"))

        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,5):
                uut.execute("clear ip arp vrf all")
                uut.execute("clear mac add dy")

        countdown(180)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC048_vxlan_multisite_bgw_sa_Clear_ARP_MAC(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger11ClearArpMac(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac "))
        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,5):
                uut.execute("clear ip arp vrf all")
                uut.execute("clear mac add dy")

        countdown(180)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
class TC049_vxlan_multisite_bgw_sa_bgw_reload(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def vtep2Reload(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))


        for uut in [site2_bgw_uut_list[0]]:
            uut.execute("copy run start")
            countdown(5)
            #uut.reload()

        #countdown(500)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC050_vxlan_multisite_bgw_sa_vlan_remove_add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def vlanVniRemove(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))
        vlan_count_to_remove_add=int(vlan_vni_scale*.8)
        vlan_2 =  vlan_start + vlan_count_to_remove_add
        for uut in [site2_bgw_uut_list[0]]:
            try:
                #vlan_vni_remove(uut,vlan_start,vni,vlan_count_to_remove_add)
                vlan_remove(uut,vlan_start,vlan_count_to_remove_add)
            except:
                log.info("vlan Remove failed")

        log.info(" %r vlans Removed",vlan_count_to_remove_add )
        countdown(10)
        for uut in [site2_bgw_uut_list[0]]:
            try:
                vlan_vni_configure(uut,vlan_start,vni,vlan_count_to_remove_add+1)
            except:
                log.info("vlan Remove failed")
        log.info(" %r vlan/vni's Added",vlan_count_to_remove_add )
        countdown(200)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


 

class TC051_vxlan_multisite_bgw_sa_nve_Bounce_bgw_Tahoe(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            #if not VxlanStReset([site2_bgw_uut_list[0]]):
            self.failed(goto=['common_cleanup'])
            #self.failed(goto=['cleanup'])


    @aetest.test
    def Trigger12NveShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in site3_bgw_uut_list:
            cmd1 = \
                """
                interface nve 1
                shut
                """
            uut.configure(cmd1)
        countdown(5)
        for uut in site3_bgw_uut_list:
            cmd2 = \
                """
                interface nve 1
                no shut
                """
            uut.configure(cmd2)

        countdown(175)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner(" faile for tahoe - Additional Countdown(100)"))
            countdown(100)
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
                if not VxlanStReset(site3_bgw_uut_list):
                    self.failed(goto=['common_cleanup'])
                if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                    self.failed(goto=['common_cleanup'])
                self.failed()
        else:
            log.info(banner(" PASS for tahoe - 75 sec")) 



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site3_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site3_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC052_vxlan_multisite_bgw_sa_nve_Bounce_bgw_sundown(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            #if not VxlanStReset([site2_bgw_uut_list[0]]):
            self.failed(goto=['common_cleanup'])
            #self.failed(goto=['cleanup'])


    @aetest.test
    def Trigger12NveShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in [site2_bgw_uut_list[0]]:
            cmd1 = \
                """
                interface nve 1
                shut
                """
            uut.configure(cmd1)
        countdown(5)
        for uut in [site2_bgw_uut_list[0]]:
            cmd2 = \
                """
                interface nve 1
                no shut
                """
            uut.configure(cmd2)

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner(" failed for SD @ 1 - Additional Countdown(100) total 175"))
            countdown(50)
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                log.info(banner(" failed for SD - Additional Countdown(100) total 200"))
                countdown(50)
                if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                    log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
                    if not VxlanStReset([site2_bgw_uut_list[0]]):
                        self.failed(goto=['common_cleanup'])
                    if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                        self.failed(goto=['common_cleanup'])
                    self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

class TC053_vxlan_multisite_bgw_sa_VLAN_Bounce(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            #if not VxlanStReset([site2_bgw_uut_list[0]]):
            self.failed(goto=['common_cleanup'])
            #self.failed(goto=['cleanup'])

    @aetest.test
    def Trigger15VlanShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger15VlanShutNoshut bgw"))
        for uut in [site2_bgw_uut_list[0]]:
            vlanshut = \
            """
            vlan 1001-1005
            shut
            exit
            """
            uut.configure(vlanshut)

        countdown(15)

        for uut in [site2_bgw_uut_list[0]]:
            vlannoshut = \
            """
            vlan 1001-1005
            no shut
            exit
            """
            uut.configure(vlannoshut)

        countdown(160)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC054_vxlan_multisite_bgw_sa_nve_loop100_shutnoshut(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def TriggerNveloopShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in [site2_bgw_uut_list[0]]:
            op = uut.execute("show run interface nve1 | incl loopback100")
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

        countdown(180)



        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

class TC055_vxlan_multisite_bgw_sa_nve_loop0_shutnoshut(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def TriggerNveloopShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in [site2_bgw_uut_list[0]]:
            op = uut.execute("show run interface nve1 | incl loopback0")
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

        countdown(180)



        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
 


class TC056_vxlan_multisite_bgw_sa_one_vlan_remove_add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def TriggerVlan_remove_add(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in [site2_bgw_uut_list[0]]:
            vlan_conf_string = uut.execute("show run vlan 1002")
            #log.info('Removing adding VLAN,vlan conf string is %r',vlan_range)

            remove_vlan = \
            """
            no vlan 1002
            """
            uut.configure(remove_vlan,timeout = 240)
            countdown(5)
            uut.configure(vlan_conf_string,timeout = 240)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        pass


class TC057_vxlan_multisite_bgw_sa_L3_Vni_remove_Add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def L3VniRemoveAdd(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))


        if not NveL3VniRemoveAdd([site2_bgw_uut_list[0]]):
            log.info("Failed NveL3VniRemoveAdd @ 2")


        countdown(200)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        pass


class TC058_vxlan_multisite_bgw_sa_Vn_Segment_remove_Add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def VnSegmentRemoveAdd(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))
        if not VnSegmentRemoveAdd([[site2_bgw_uut_list[0]][0]],vlan_start):
            log.info("Failed NveL3VniRemoveAdd @ 2")


        countdown(300)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in [site2_bgw_uut_list[0]]:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in [site2_bgw_uut_list[0]]:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        pass


 
class TC059_vxlan_multisite_anycast_bgw_mode_bringup(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
    
    @aetest.test
    def BGWstandalonemode(self):
        if not nodeNoIsolate(site2_bgw_uut_list[1]):
            self.failed()
      
    @aetest.test
    def vxlan_traffic_test_all(self):

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            self.failed(goto=['common_cleanup'])


    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """
 
class TC060_vxlan_multisite_anycast_bgw_l2fm_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'l2fm')


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC061_vxlan_multisite_anycast_bgw_l2rib_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'l2rib')


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC062_vxlan_multisite_anycast_bgw_nve_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'nve')


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC063_vxlan_multisite_anycast_bgw_vlan_mgr_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'vlan_mgr')


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC064_vxlan_multisite_anycast_bgw_ethpm_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'ethpm')


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC065_vxlan_multisite_anycast_bgw_ospf_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'ospf')


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

class TC066_vxlan_multisite_anycast_bgw_fabric_link_failover1(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def bgwfabriclinkfailover1(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
         
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()       

    @aetest.test
    def bgwfabriclinkrecover1(self, testscript, testbed):      
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()       

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


class TC067_vxlan_multisite_anycast_bgw_fabric_link_failover2(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def bgwfabriclinkfailover2(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine2site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
         
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()

    @aetest.test
    def bgwfabriclinkrecover2(self, testscript, testbed):       
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine2site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


class TC068_vxlan_multisite_anycast_bgw_spine1_isolation(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def spine1isolation(self, testscript, testbed):
        log.info(banner("Starting spine1isolation @ 8"))

        if not nodeIsolate(site2_spine_uut_list[0]):
            self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            nodeNoIsolate(site2_spine_uut_list[0])
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def spine1Noisolation(self, testscript, testbed):
        log.info(banner("Starting spine1Noisolation @ 8"))
        if not nodeNoIsolate(site2_spine_uut_list[0]):
            self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

         
class TC068_vxlan_multisite_anycast_bgw_spine2_isolation(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def spine2isolation(self, testscript, testbed):
        log.info(banner("Starting spine2isolation @ 8"))

        if not nodeIsolate(site2_spine_uut_list[1]):
            self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            nodeNoIsolate(site2_spine_uut_list[1])
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def spine2Noisolation(self, testscript, testbed):
        log.info(banner("Starting spine2Noisolation @ 8"))
        if not nodeNoIsolate(site2_spine_uut_list[1]):
            self.failed()


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC070_vxlan_multisite_anycast_bgw_dci1_router_failover(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def dci1isolation(self, testscript, testbed):
        log.info(banner("Starting dci1isolation @ 8"))

        if not nodeIsolate(dci_uut_list[0]):
            self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            nodeNoIsolate(dci_uut_list[0])
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def dci1Noisolation(self, testscript, testbed):
        log.info(banner("Starting dci1Noisolation @ 8"))
        if not nodeNoIsolate(dci_uut_list[0]):
            self.failed()


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC071_vxlan_multisite_anycast_bgw_dci2_router_failover(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def dci2isolation(self, testscript, testbed):
        log.info(banner("Starting dci2isolation @ 8"))

        if not nodeIsolate(dci_uut_list[1]):
            self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            nodeNoIsolate(dci_uut_list[1])
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def dci2Noisolation(self, testscript, testbed):
        log.info(banner("Starting dci2Noisolation @ 8"))
        if not nodeNoIsolate(dci_uut_list[1]):
            self.failed()


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC072_vxlan_multisite_anycast_bgw_dci_link_failover1(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def dci1linkfailover1(self, testscript, testbed):       
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_dci1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
 
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def dci1linkrecover1(self, testscript, testbed):       
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_dci1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC073_vxlan_multisite_anycast_bgw_dci_link_failover2(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def dci1linkfailover1(self, testscript, testbed):       
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_dci2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
 
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def dci1linkrecover1(self, testscript, testbed):       
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_dci2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC074_vxlan_multisite_anycast_bgw_ospf_shut_noshut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
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

        site2_bgw_uut_list[0].configure(cfg_shut)
        site2_bgw_uut_list[1].configure(cfg_shut)
        countdown(15)
        site2_bgw_uut_list[0].configure(cfg_noshut)
        site2_bgw_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC075_vxlan_multisite_anycast_bgw_bgp_shut_noshut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        cfg_shut =\
        """
        router bgp 65002
        shut
        """
        cfg_noshut =\
        """
        router bgp 65002
        no shut
        """
        site2_bgw_uut_list[0].configure(cfg_shut)
        site2_bgw_uut_list[1].configure(cfg_shut)
        countdown(15)
        site2_bgw_uut_list[0].configure(cfg_noshut)
        site2_bgw_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


  
 
class TC076_vxlan_multisite_anycast_bgw_spine1_ospf_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_spine1_ospf_shut @ 8"))
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
        site2_spine_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site2_spine_uut_list[0].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
 
class TC077_vxlan_multisite_anycast_bgw_spine2_ospf_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_spine2_ospf_shut @ 8"))
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
        site2_spine_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site2_spine_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()




    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC078_vxlan_multisite_anycast_bgw_spine1_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_spine1_bgp_shut @ 8"))
        cfg_shut =\
        """
        router bgp 65002
        shut
        """
        cfg_noshut =\
        """
        router bgp 65002
        no shut
        """
        site2_spine_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site2_spine_uut_list[0].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()




    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

class TC079_vxlan_multisite_anycast_bgw_spine2_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_spine2_bgp_shut @ 8"))
        cfg_shut =\
        """
        router bgp 65002
        shut
        """
        cfg_noshut =\
        """
        router bgp 65002
        no sh
        """
        site2_spine_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site2_spine_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()




    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC080_vxlan_multisite_anycast_bgw_dci1_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_dci1_bgp_shut @ 8"))
        cfg_shut =\
        """
        router bgp 99
        shut
        """
        cfg_noshut =\
        """
        router bgp 99
        no shut
        """
        dci_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            dci_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


        dci_uut_list[0].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC081_vxlan_multisite_anycast_bgw_dci2_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_dci1_bgp_shut @ 8"))
        cfg_shut =\
        """
        router bgp 99
        shut
        """
        cfg_noshut =\
        """
        router bgp 99
        no shut
        """
        dci_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            dci_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


        dci_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC082_vxlan_multisite_anycast_bgw_restart_ospf(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            uut.execute('restart ospf UNDERLAY')
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC083_vxlan_multisite_anycast_bgw_restart_bgp(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            uut.execute('restart bgp 65002')
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC084_vxlan_multisite_anycast_bgw_restart_pim(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            uut.execute('restart pim')
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
class TC085_vxlan_multisite_anycast_bgw_restart_igmp(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            uut.execute('restart igmp')
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC086_vxlan_multisite_anycast_bgw_restart_mld(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            uut.execute('restart mld')
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC087_vxlan_multisite_anycast_bgw_anycast_bgw_remote_bgw_nve_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgw1ospfshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        cfg_shut =\
        """
        interface nve 1
        shut
        """
        cfg_noshut =\
        """
        interface nve 1
        no shut
        """
        site3_bgw_uut_list[0].configure(cfg_shut)
        countdown(250)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()

        site3_bgw_uut_list[0].configure(cfg_noshut)

        countdown(250)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()
            
    @aetest.test
    def remotebgw2ospfshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))

        cfg_shut =\
        """
        interface nve 1
        shut
        """
        cfg_noshut =\
        """
        interface nve 1
        no shut
        """

        site3_bgw_uut_list[1].configure(cfg_shut)
        countdown(250)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()

        site3_bgw_uut_list[1].configure(cfg_noshut)
        countdown(250)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()            

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC088_vxlan_multisite_anycast_bgw_remote_bgw_ospf_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
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
        site3_bgw_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site3_bgw_uut_list[0].configure(cfg_noshut)
        site3_bgw_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()

        site3_bgw_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()            

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC089_vxlan_multisite_anycast_bgw_remote_bgw_bgp_shut(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwbgpshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        cfg_shut =\
        """
        router bgp 65003
        shut
        """
        cfg_noshut =\
        """
        router bgp 65003
        no shut
        """
        site3_bgw_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site3_bgw_uut_list[0].configure(cfg_noshut)
        site3_bgw_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()

        site3_bgw_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()            

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC090_vxlan_multisite_anycast_bgw_Core_flap(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def Trigger5CoreIfFlap(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))

        if not TriggerCoreIfFlap222(site2_bgw_uut_list):
            log.info("TriggerCoreIfFlap222 failed @ 4")
            #self.failed()

        countdown(280)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC091_vxlan_multisite_anycast_bgw_ClearIpRoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger6ClearIpRoute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site2_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear ip route *")

        countdown(160)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC092_vxlan_multisite_anycast_bgw_clearIpMoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger7ClearIpMroute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site2_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear ip mroute *")

        countdown(160)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC093_vxlan_multisite_anycast_bgw_clear_ospf_Neigh(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger8ClearOspfNeigh(self, testscript, testbed):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))

        for uut in site2_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear ip ospf neighbor *")

        countdown(180)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC094_vxlan_multisite_anycast_bgw_Clear_IP_Bgp(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger9ClearIpBgp(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))


        for uut in site2_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear ip bgp *")

        countdown(180)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC095_vxlan_multisite_anycast_bgw_Clear_Bgp_l2vpn(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting TriggerClearBgpL2vpnEvpn @ bgw"))

        for uut in site2_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear bgp l2vpn evpn *")

        countdown(180)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC096_vxlan_multisite_anycast_bgw_Spine_ClearIpRoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger6ClearIpRoute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip route *")

        countdown(160)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC097_vxlan_multisite_anycast_bgw_Spine_ClearIpMoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger7ClearIpMroute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip mroute *")

        countdown(160)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC098_vxlan_multisite_anycast_bgw_Spine_Clear_OSPF(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger8ClearOspfNeigh(self, testscript, testbed):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))

        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip ospf neighbor *")

        countdown(320)



        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC099_vxlan_multisite_anycast_bgw_Spine_Clear_IP_Bgp(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger9ClearIpBgp(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))


        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip bgp *")

        countdown(320)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC100_vxlan_multisite_anycast_bgw_Spine_Clear_Bgp_l2vpn(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting Trigger10ClearBgpL2vpnEvpn @ spine"))
        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear bgp l2vpn evpn *")
                #uut.execute(' clear bgp all *')
        countdown(320)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC101_vxlan_multisite_anycast_bgw_Clear_MAC(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def Trigger11ClearArpMac(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac @ bgw"))

        for uut in site2_bgw_uut_list:
            for i in range(1,5):
                #uut.execute("clear ip arp vrf all")
                uut.execute("clear mac add dy")

        countdown(180)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC102_vxlan_multisite_anycast_bgw_Clear_ARP(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger11ClearArpMac(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac "))
        for uut in site2_bgw_uut_list:
            for i in range(1,5):
                uut.execute("clear ip arp vrf all")
                #uut.execute("clear mac add dy")

        countdown(180)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

class TC102_vxlan_multisite_anycast_bgw_Clear_ip_route_vrf_all(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger11ClearArpMac(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac "))
        for uut in site2_bgw_uut_list:
            for i in range(1,5):
                uut.execute("clear ip route vrf all")
                #uut.execute("clear mac add dy")

        countdown(180)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 


class TC103_vxlan_multisite_anycast_bgw_bgw_reload(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def vtep2Reload(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))


        for uut in site2_bgw_uut_list:
            uut.execute("copy run start")
            countdown(5)
            #uut.reload()

        #countdown(500)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC104_vxlan_multisite_anycast_bgw_vlan_remove_add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def vlanVniRemove(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))
        vlan_count_to_remove_add=int(vlan_vni_scale*.8)
        vlan_2 =  vlan_start + vlan_count_to_remove_add
        for uut in site2_bgw_uut_list:
            try:
                #vlan_vni_remove(uut,vlan_start,vni,vlan_count_to_remove_add)
                vlan_remove(uut,vlan_start,vlan_count_to_remove_add)
            except:
                log.info("vlan Remove failed")

        log.info(" %r vlans Removed",vlan_count_to_remove_add )
        countdown(10)
        for uut in site2_bgw_uut_list:
            try:
                vlan_vni_configure(uut,vlan_start,vni,vlan_count_to_remove_add+1)
            except:
                log.info("vlan Remove failed")
        log.info(" %r vlan/vni's Added",vlan_count_to_remove_add )
        countdown(200)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


 

class TC105_vxlan_multisite_anycast_bgw_nve_Bounce_bgw_Tahoe(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            #if not VxlanStReset(site2_bgw_uut_list):
            self.failed(goto=['common_cleanup'])
            #self.failed(goto=['cleanup'])


    @aetest.test
    def Trigger12NveShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in site3_bgw_uut_list:
            cmd1 = \
                """
                interface nve 1
                shut
                """
            uut.configure(cmd1)
        countdown(5)
        for uut in site3_bgw_uut_list:
            cmd2 = \
                """
                interface nve 1
                no shut
                """
            uut.configure(cmd2)

        countdown(175)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner(" faile for tahoe - Additional Countdown(100)"))
            countdown(100)
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
                if not VxlanStReset(site3_bgw_uut_list):
                    self.failed(goto=['common_cleanup'])
                if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                    self.failed(goto=['common_cleanup'])
                self.failed()
        else:
            log.info(banner(" PASS for tahoe - 75 sec")) 



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site3_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site3_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC106_vxlan_multisite_anycast_bgw_nve_Bounce_bgw_sundown(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            #if not VxlanStReset(site2_bgw_uut_list):
            self.failed(goto=['common_cleanup'])
            #self.failed(goto=['cleanup'])


    @aetest.test
    def Trigger12NveShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in site2_bgw_uut_list:
            cmd1 = \
                """
                interface nve 1
                shut
                """
            uut.configure(cmd1)
        countdown(5)
        for uut in site2_bgw_uut_list:
            cmd2 = \
                """
                interface nve 1
                no shut
                """
            uut.configure(cmd2)

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner(" failed for SD @ 1 - Additional Countdown(100) total 175"))
            countdown(50)
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                log.info(banner(" failed for SD - Additional Countdown(100) total 200"))
                countdown(50)
                if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                    log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
                    if not VxlanStReset(site2_bgw_uut_list):
                        self.failed(goto=['common_cleanup'])
                    if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                        self.failed(goto=['common_cleanup'])
                    self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

class TC107_vxlan_multisite_anycast_bgw_VLAN_Bounce(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            #if not VxlanStReset(site2_bgw_uut_list):
            self.failed(goto=['common_cleanup'])
            #self.failed(goto=['cleanup'])

    @aetest.test
    def Trigger15VlanShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger15VlanShutNoshut bgw"))
        for uut in site2_bgw_uut_list:
            vlanshut = \
            """
            vlan 1001-1005
            shut
            exit
            """
            uut.configure(vlanshut)

        countdown(15)

        for uut in site2_bgw_uut_list:
            vlannoshut = \
            """
            vlan 1001-1005
            no shut
            exit
            """
            uut.configure(vlannoshut)

        countdown(160)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()




    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC108_vxlan_multisite_anycast_bgw_nve_loop100_shutnoshut(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def TriggerNveloopShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in site2_bgw_uut_list:
            op = uut.execute("show run interface nve1 | incl loopback100")
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

        countdown(180)



        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

class TC109_vxlan_multisite_anycast_bgw_nve_loop0_shutnoshut(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])
 


    @aetest.test
    def TriggerNveloopShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in site2_bgw_uut_list:
            op = uut.execute("show run interface nve1 | incl loopback0")
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

        countdown(180)



        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 



class TC110_vxlan_multisite_anycast_bgw_one_vlan_remove_add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def TriggerVlan_remove_add(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in site2_bgw_uut_list:
            vlan_conf_string = uut.execute("show run vlan 1002")
            #log.info('Removing adding VLAN,vlan conf string is %r',vlan_range)

            remove_vlan = \
            """
            no vlan 1002
            """
            uut.configure(remove_vlan,timeout = 240)
            countdown(5)
            uut.configure(vlan_conf_string,timeout = 240)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        pass


class TC111_vxlan_multisite_anycast_bgw_L3_Vni_remove_Add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def L3VniRemoveAdd(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))


        if not NveL3VniRemoveAdd(site2_bgw_uut_list):
            log.info("Failed NveL3VniRemoveAdd @ 2")


        countdown(200)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        pass


class TC112_vxlan_multisite_anycast_bgw_Vn_Segment_remove_Add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def VnSegmentRemoveAdd(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))
        if not VnSegmentRemoveAdd([site2_bgw_uut_list[0]],vlan_start):
            log.info("Failed NveL3VniRemoveAdd @ 2")


        countdown(300)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        pass

 

class TC113_vxlan_multisite_vPC_bgw_bringup(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self): 
        

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - go- common_cleanup"))
            self.failed(goto=['common_cleanup'])


     
    @aetest.test
    def vpc_configure(self):
        log.info(banner("Configuring Ports Channel/VPC in BGW devices"))

        if not nodeNoIsolate(site2_bgw_uut_list[1]):
            self.failed(goto=['common_cleanup'])
        if not nodeNoIsolate(site2_bgw_uut_list[0]):
            self.failed(goto=['common_cleanup'])

        countdown(10)

        for uut in site2_bgw_uut_list:
            vpc_access_port_member_list = []
            mct_port_member_list = []
            for intf in [*uut.interfaces.keys()]:
                if 'mct_po' in uut.interfaces[intf].alias:
                    log.info("mct port-channel is %r on leaf device  %r",intf,uut)
                    mct_po_number = uut.interfaces[intf].intf
                    src_ip = uut.interfaces[intf].src_ip
                    peer_ip = uut.interfaces[intf].peer_ip

                elif 'vpc_po' in uut.interfaces[intf].alias:
                    log.info("vpc port-channel is %r on leaf device  %r",intf,uut)
                    vpc_po_number = uut.interfaces[intf].intf

            for intf in [*uut.interfaces.keys()]:            
                if 'bgw_vpc' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    log.info("adding vpc port-channel member %r on leaf device  %r",intf,uut)
                    vpc_access_port_member_list.append(intf)

                elif 'mct_link' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    log.info("adding mct port-channel member %r on leaf device  %r",intf,uut)
                    mct_port_member_list.append(intf)

            for intf in [*uut.interfaces.keys()]:
                if 'vpc_po' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    log.info("Configureing VPC port-channel  %r on leaf device  %r",intf,uut)
                    try:
                        vtep_vpc_global_obj1 = VPCNodeGlobal(uut,mct_po_number,str(peer_ip),\
                        mct_port_member_list,str(src_ip))
                        vtep_vpc_global_obj1.vpc_global_conf()
                    except:
                        log.error('vtep_vpc_global_obj1.vpc_global_conf failed for uut %r',uut)
                        self.failed(goto=['common_cleanup'])
                    try:
                        vtep_vpc_obj1 = VPCPoConfig(uut,'102',vpc_access_port_member_list,\
                        vlan_range,'trunk')
                        vtep_vpc_obj1.vpc_conf()
                    except:
                        log.error('vtep_vpc_obj1.vpc_conf failed for %r',uut)
                        self.failed(goto=['common_cleanup'])


        log.info(banner("Configuring Ports Channel/VPC in BGW devices"))
     
    @aetest.test
    def vpc_sw_gw(self):
        log.info(banner("Configuring BGWvpc_sw_gw"))
        swBgwPoConfigure(site2_sw_uut_list[0],'102',vlan_range)


    @aetest.test
    def vpc_fwd_none_configure(self):
        log.info(banner("Configuring BGW vPC to forward None"))
        pcall(vlanRemoveAddPo,uut=(site2_sw_uut_list[0],site2_bgw_uut_list[0],site2_bgw_uut_list[1]),\
                     po_number=('102','102','102'),\
                     vlan_range=('none','none','none'))
 
    @aetest.test
    def vpc_bgw_loop_configure(self):
        log.info(banner("Starting vpc_bgw_loop_configure"))
        ConfigureLoopbackbgwVPC(site2_bgw_uut_list[0],site2_bgw_uut_list[1])

    @aetest.test
    def vpc_bgw_infra_vlan_configure(self):
        log.info(banner("Starting vpc_bgw_loop_configure"))
        SviConfigsallbgw(site2_bgw_uut_list[0],site2_bgw_uut_list[1],'22.22.22')
        #def SviConfigsallbgw(uut1,uut2,prefix):

    @aetest.test
    def vpc_bgw_check(self):
        log.info(banner("Starting VPC verify Section"))
        countdown(180)

        for uut in site2_bgw_uut_list:
            for feature in ['vpc']:
                test1 = protocolStateCheck(uut,[feature])
                if not test1:
                    log.info('Feature %r  on device %r Failed ',feature,str(uut))
                    #self.failed(goto=['common_cleanup'])


    @aetest.test
    def vxlan_traffic_test_all(self):

        log.info(banner("ARP for all streams"))
        for i in range(1,7):
            doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')

        countdown(100)
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            self.failed(goto=['common_cleanup'])


    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """


class TC114_vxlan_multisite_vPC_bgw_traffic_to_vpc(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - go- common_cleanup"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def trafficSwitchover(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        
        none_101 = \
        """
        int po 101
        switchport trunk allowed vlan none
        """

        add_102 = \
        """
        int po 102
        switchport trunk allowed vlan 1001-1032
        """
        site2_sw_uut_list[0].configure(none_101)
        site2_sw_uut_list[0].configure(add_102)
        for uut in site2_bgw_uut_list:
            uut.configure(add_102)
        for uut in site2_leaf_uut_list:
            uut.configure(none_101)

        countdown(200)

    @aetest.test
    def vxlan_traffic_test_all(self):

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            self.failed(goto=['common_cleanup'])


    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """


class TC115_vxlan_multisite_vPC_bgw_mct_flap(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - go- common_cleanup"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def TriggerVpcMctflap(self, testscript, testbed):
        log.info(banner("Starting TriggerVpcMctflap vpc"))

        op1= site2_bgw_uut_list[0].execute("show vpc brief | json-pretty")
        op=json.loads(op1)
        Po=op["TABLE_peerlink"]["ROW_peerlink"]["peerlink-ifindex"]


        for uut in site2_bgw_uut_list:
            if not TriggerPortFlap(uut,Po,3):
                log.info("TriggerPortFlap failed @ 4")
                self.failed()


        countdown(160)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner(" failed for SD @ 1 - Additional Countdown(100) total 175"))
            countdown(50)
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                log.info(banner(" failed for SD - Additional Countdown(100) total 200"))
                countdown(50)
                if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                    log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
                    if not VxlanStReset(site2_bgw_uut_list):
                        self.failed(goto=['common_cleanup'])
                    if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                        self.failed(goto=['common_cleanup'])
                    self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

class TC116_vxlan_multisite_vPC_bgw_acc_port_flap(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - go- common_cleanup"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def TriggeraccessPortFlap(self, testscript, testbed):
        log.info(banner("Starting Trigger4AccessPortFlap bgw"))

        log.info(banner("Starting Trigger2PortFlap @ 8"))

        op1= site2_bgw_uut_list[0].execute("show vpc brief | json-pretty")
        op=json.loads(op1)
        Po=op["TABLE_vpc"]["ROW_vpc"]["vpc-ifindex"]

        for uut in site2_bgw_uut_list:
            if not TriggerPortFlap(uut,Po,3):
                log.info("TriggerPortFlap failed @ 4")
                self.failed()

        countdown(160)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner(" failed for SD @ 1 - Additional Countdown(100) total 175"))
            countdown(50)
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                log.info(banner(" failed for SD - Additional Countdown(100) total 200"))
                countdown(50)
                if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                    log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
                    if not VxlanStReset(site2_bgw_uut_list):
                        self.failed(goto=['common_cleanup'])
                    if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                        self.failed(goto=['common_cleanup'])
                    self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC117_vxlan_multisite_vPC_bgw_vpcmember_flap(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - go- common_cleanup"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def TriggerVpcmemflap(self, testscript, testbed):
        log.info(banner("Starting Trigger4AccessPortFlap bgw"))

 
        log.info(banner("Starting Trigger2PortFlap @ 8"))
        op1= site2_bgw_uut_list[0].execute("show vpc brief | json-pretty")
        op=json.loads(op1)
        Po=op["TABLE_vpc"]["ROW_vpc"]["vpc-ifindex"][2:]

        if not vPCMemberFlap(site2_bgw_uut_list,[str(Po)]):
            self.failed()

        countdown(200)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner(" failed for SD @ 1 - Additional Countdown(100) total 175"))
            countdown(50)
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                log.info(banner(" failed for SD - Additional Countdown(100) total 200"))
                countdown(50)
                if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                    log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
                    if not VxlanStReset(site2_bgw_uut_list):
                        self.failed(goto=['common_cleanup'])
                    if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                        self.failed(goto=['common_cleanup'])
                    self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC118_vxlan_multisite_vPC_bgw_vlan_shutnoshut(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - go- common_cleanup"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger15VlanShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger15VlanShutNoshut bgw"))
        for uut in site2_bgw_uut_list:
            vlanshut = \
            """
            vlan 1001-1005
            shut
            exit
            """
            uut.configure(vlanshut)

        countdown(15)

        for uut in site2_bgw_uut_list:
            vlannoshut = \
            """
            vlan 1001-1005
            no shut
            exit
            """
            uut.configure(vlannoshut)

        countdown(160)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC119_vxlan_multisite_vPC_bgw_loop100_shutnoshut(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - go- common_cleanup"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def TriggerNveloopShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in site2_bgw_uut_list:
            op = uut.execute("show run interface nve1 | incl loopback100")
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

        countdown(180)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

class TC120_vxlan_multisite_vPC_bgw_loop0_shutnoshut(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - go- common_cleanup"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def TriggerNveloopShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in site2_bgw_uut_list:
            op = uut.execute("show run interface nve1 | incl loopback0")
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

        countdown(180)



        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 



class TC121_vxlan_multisite_vPC_bgw_one_vlan_remove_add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - go- common_cleanup"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def TriggerVlan_remove_add(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in site2_bgw_uut_list:
            vlan_conf_string = uut.execute("show run vlan 1002")

            remove_vlan = \
            """
            no vlan 1002
            """
            uut.configure(remove_vlan,timeout = 240)
            countdown(5)
            uut.configure(vlan_conf_string,timeout = 240)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        pass


class TC122_vxlan_multisite_vPC_bgw_L3_Vni_remove_Add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - go- common_cleanup"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def L3VniRemoveAdd(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

 
        if not NveL3VniRemoveAdd(site2_bgw_uut_list):
            log.info("Failed NveL3VniRemoveAdd @ 2")


        countdown(200)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        pass


class TC123_vxlan_multisite_vPC_bgw_Vn_Segment_remove_Add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - go- common_cleanup"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def VnSegmentRemoveAdd(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))
        if not VnSegmentRemoveAdd(site2_bgw_uut_list,vlan_start):
            log.info("Failed NveL3VniRemoveAdd @ 2")


        countdown(300)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        pass




class TC124_vxlan_multisite_vPC_bgw_nve_bounce(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - go- common_cleanup"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger12NveShutNoshut(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

        for uut in site2_bgw_uut_list:
            cmd1 = \
                """
                interface nve 1
                shut
                """
            uut.configure(cmd1)

        countdown(5)
        for uut in site2_bgw_uut_list:
            cmd2 = \
                """
                interface nve 1
                no shut
                """
            uut.configure(cmd2)

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner(" failed for SD @ 1 - Additional Countdown(100) total 175"))
            countdown(50)
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                log.info(banner(" failed for SD - Additional Countdown(100) total 200"))
                countdown(50)
                if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                    log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
                    if not VxlanStReset(site2_bgw_uut_list):
                        self.failed(goto=['common_cleanup'])
                    if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                        self.failed(goto=['common_cleanup'])
                    self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 


class TC125_vxlan_multisite_vPC_bgw_vpc_shut_at_bgw1(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - go- common_cleanup"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def TriggeraccessPortFlap(self, testscript, testbed):
        log.info(banner("Starting Trigger4AccessPortFlap bgw"))

        op1= site2_bgw_uut_list[0].execute("show vpc brief | json-pretty")
        op=json.loads(op1)
        Po=op["TABLE_vpc"]["ROW_vpc"]["vpc-ifindex"]

        portShutNoshut(site2_bgw_uut_list[0],Po,'down')
 
        countdown(160)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            portShutNoshut(site2_bgw_uut_list[0],Po,'up')
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


        portShutNoshut(site2_bgw_uut_list[0],Po,'up')

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()

 
        countdown(160)

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC126_vxlan_multisite_vPC_bgw_vpc_shut_at_bgw2(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - go- common_cleanup"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def TriggeraccessPortFlap(self, testscript, testbed):
        log.info(banner("Starting Trigger4AccessPortFlap bgw"))

        op1= site2_bgw_uut_list[1].execute("show vpc brief | json-pretty")
        op=json.loads(op1)
        Po=op["TABLE_vpc"]["ROW_vpc"]["vpc-ifindex"]

        portShutNoshut(site2_bgw_uut_list[1],Po,'down')
 
        countdown(160)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            portShutNoshut(site2_bgw_uut_list[1],Po,'up')
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


        portShutNoshut(site2_bgw_uut_list[1],Po,'up')

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()

 
        countdown(160)

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



 

class TC127_vxlan_multisite_vPC_bgw_fabric_link_failover1(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def bgwfabriclinkfailover1(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
         
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()       

    @aetest.test
    def bgwfabriclinkrecover1(self, testscript, testbed):      
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()       

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


class TC128_vxlan_multisite_vPC_bgw_fabric_link_failover2(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def bgwfabriclinkfailover2(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine2site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
         
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()

    @aetest.test
    def bgwfabriclinkrecover2(self, testscript, testbed):       
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine2site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_spine1site2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()


class TC129_vxlan_multisite_vPC_bgw_spine1_isolation(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def spine1isolation(self, testscript, testbed):
        log.info(banner("Starting spine1isolation @ 8"))

        if not nodeIsolate(site2_spine_uut_list[0]):
            self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            nodeNoIsolate(site2_spine_uut_list[0])
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def spine1Noisolation(self, testscript, testbed):
        log.info(banner("Starting spine1Noisolation @ 8"))
        if not nodeNoIsolate(site2_spine_uut_list[0]):
            self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

         
class TC130_vxlan_multisite_vPC_bgw_spine2_isolation(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def spine2isolation(self, testscript, testbed):
        log.info(banner("Starting spine2isolation @ 8"))

        if not nodeIsolate(site2_spine_uut_list[1]):
            self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            nodeNoIsolate(site2_spine_uut_list[1])
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def spine2Noisolation(self, testscript, testbed):
        log.info(banner("Starting spine2Noisolation @ 8"))
        if not nodeNoIsolate(site2_spine_uut_list[1]):
            self.failed()


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC131_vxlan_multisite_vPC_bgw_dci1_router_failover(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def dci1isolation(self, testscript, testbed):
        log.info(banner("Starting dci1isolation @ 8"))

        if not nodeIsolate(dci_uut_list[0]):
            self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            nodeNoIsolate(dci_uut_list[0])
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def dci1Noisolation(self, testscript, testbed):
        log.info(banner("Starting dci1Noisolation @ 8"))
        if not nodeNoIsolate(dci_uut_list[0]):
            self.failed()


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC132_vxlan_multisite_vPC_bgw_dci2_router_failover(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def dci2isolation(self, testscript, testbed):
        log.info(banner("Starting dci2isolation @ 8"))

        if not nodeIsolate(dci_uut_list[1]):
            self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            nodeNoIsolate(dci_uut_list[1])
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def dci2Noisolation(self, testscript, testbed):
        log.info(banner("Starting dci2Noisolation @ 8"))
        if not nodeNoIsolate(dci_uut_list[1]):
            self.failed()


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC133_vxlan_multisite_vPC_bgw_dci_link_failover1(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def dci1linkfailover1(self, testscript, testbed):       
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_dci1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
 
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def dci1linkrecover1(self, testscript, testbed):       
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_dci1' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC134_vxlan_multisite_vPC_bgw_dci_link_failover2(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def dci1linkfailover1(self, testscript, testbed):       
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_dci2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'down')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()
 
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def dci1linkrecover1(self, testscript, testbed):       
        for uut in site2_bgw_uut_list:
            for intf in [*uut.interfaces.keys()]:
                if 'site2_dci2' in intf:
                    intf = uut.interfaces[intf].intf
                    try:
                        portShutNoshut(uut,intf,'up')
                    except:
                        log.info('port shut failed @ uut %r',uut)
                        self.failed()

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC135_vxlan_multisite_vPC_bgw_ospf_shut_noshut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
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

        site2_bgw_uut_list[0].configure(cfg_shut)
        site2_bgw_uut_list[1].configure(cfg_shut)
        countdown(15)
        site2_bgw_uut_list[0].configure(cfg_noshut)
        site2_bgw_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC136_vxlan_multisite_vPC_bgw_bgp_shut_noshut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        cfg_shut =\
        """
        router bgp 65002
        shut
        """
        cfg_noshut =\
        """
        router bgp 65002
        no shut
        """
        site2_bgw_uut_list[0].configure(cfg_shut)
        site2_bgw_uut_list[1].configure(cfg_shut)
        countdown(15)
        site2_bgw_uut_list[0].configure(cfg_noshut)
        site2_bgw_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


  
 
class TC137_vxlan_multisite_vPC_bgw_spine1_ospf_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_spine1_ospf_shut @ 8"))
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
        site2_spine_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site2_spine_uut_list[0].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
 
class TC138_vxlan_multisite_vPC_bgw_spine2_ospf_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_spine2_ospf_shut @ 8"))
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
        site2_spine_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site2_spine_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()




    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC139_vxlan_multisite_vPC_bgw_spine1_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_spine1_bgp_shut @ 8"))
        cfg_shut =\
        """
        router bgp 65002
        shut
        """
        cfg_noshut =\
        """
        router bgp 65002
        no shut
        """
        site2_spine_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site2_spine_uut_list[0].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()




    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

class TC140_vxlan_multisite_vPC_bgw_spine2_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_spine2_bgp_shut @ 8"))
        cfg_shut =\
        """
        router bgp 65002
        shut
        """
        cfg_noshut =\
        """
        router bgp 65002
        no sh
        """
        site2_spine_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site2_spine_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()




    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC141_vxlan_multisite_vPC_bgw_dci1_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_dci1_bgp_shut @ 8"))
        cfg_shut =\
        """
        router bgp 99
        shut
        """
        cfg_noshut =\
        """
        router bgp 99
        no shut
        """
        dci_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            dci_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


        dci_uut_list[0].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC142_vxlan_multisite_vPC_bgw_dci2_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwospfshut(self, testscript, testbed):
        log.info(banner("Starting anycast_bgw_dci1_bgp_shut @ 8"))
        cfg_shut =\
        """
        router bgp 99
        shut
        """
        cfg_noshut =\
        """
        router bgp 99
        no shut
        """
        dci_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            dci_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


        dci_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC143_vxlan_multisite_vPC_bgw_restart_ospf(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            uut.execute('restart ospf UNDERLAY')
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC144_vxlan_multisite_vPC_bgw_restart_bgp(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            uut.execute('restart bgp 65002')
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC145_vxlan_multisite_vPC_bgw_restart_pim(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            uut.execute('restart pim')
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
class TC146_vxlan_multisite_vPC_bgw_restart_igmp(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            uut.execute('restart igmp')
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC147_vxlan_multisite_vPC_bgw_restart_mld(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            uut.execute('restart mld')
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC148_vxlan_multisite_vPC_bgw_anycast_bgw_remote_bgw_nve_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def remotebgw1ospfshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        cfg_shut =\
        """
        interface nve 1
        shut
        """
        cfg_noshut =\
        """
        interface nve 1
        no shut
        """
        site3_bgw_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()

        site3_bgw_uut_list[0].configure(cfg_noshut)

        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()
            
    @aetest.test
    def remotebgw2ospfshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))

        cfg_shut =\
        """
        interface nve 1
        shut
        """
        cfg_noshut =\
        """
        interface nve 1
        no shut
        """

        site3_bgw_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()

        site3_bgw_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()            

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC149_vxlan_multisite_vPC_bgw_remote_bgw_ospf_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
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
        site3_bgw_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site3_bgw_uut_list[0].configure(cfg_noshut)
        site3_bgw_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()

        site3_bgw_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()            

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC150_vxlan_multisite_vPC_bgw_remote_bgw_bgp_shut(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def remotebgwbgpshut(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        cfg_shut =\
        """
        router bgp 65003
        shut
        """
        cfg_noshut =\
        """
        router bgp 65003
        no shut
        """
        site3_bgw_uut_list[0].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site3_bgw_uut_list[0].configure(cfg_noshut)
        site3_bgw_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()

        site3_bgw_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()            

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC151_vxlan_multisite_vPC_bgw_Core_flap(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def Trigger5CoreIfFlap(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))

        if not TriggerCoreIfFlap222(site2_bgw_uut_list):
            log.info("TriggerCoreIfFlap222 failed @ 4")
            #self.failed()

        countdown(280)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC152_vxlan_multisite_vPC_bgw_ClearIpRoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger6ClearIpRoute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site2_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear ip route *")

        countdown(160)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC153_vxlan_multisite_vPC_bgw_clearIpMoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger7ClearIpMroute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site2_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear ip mroute *")

        countdown(160)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC154_vxlan_multisite_vPC_bgw_clear_ospf_Neigh(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger8ClearOspfNeigh(self, testscript, testbed):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))

        for uut in site2_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear ip ospf neighbor *")

        countdown(180)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC156_vxlan_multisite_vPC_bgw_Clear_IP_Bgp(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger9ClearIpBgp(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))


        for uut in site2_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear ip bgp *")

        countdown(180)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC157_vxlan_multisite_vPC_bgw_Clear_Bgp_l2vpn(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting TriggerClearBgpL2vpnEvpn @ bgw"))

        for uut in site2_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear bgp l2vpn evpn *")

        countdown(180)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC158_vxlan_multisite_vPC_bgw_Spine_ClearIpRoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger6ClearIpRoute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip route *")

        countdown(160)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC159_vxlan_multisite_vPC_bgw_Spine_ClearIpMoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger7ClearIpMroute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip mroute *")

        countdown(160)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC160_vxlan_multisite_vPC_bgw_Spine_Clear_OSPF(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger8ClearOspfNeigh(self, testscript, testbed):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))

        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip ospf neighbor *")

        countdown(320)



        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC161_vxlan_multisite_vPC_bgw_Spine_Clear_IP_Bgp(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger9ClearIpBgp(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))


        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip bgp *")

        countdown(320)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC162_vxlan_multisite_vPC_bgw_Spine_Clear_Bgp_l2vpn(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting Trigger10ClearBgpL2vpnEvpn @ spine"))
        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear bgp l2vpn evpn *")
                #uut.execute(' clear bgp all *')
        countdown(320)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC163_vxlan_multisite_vPC_bgw_Clear_ARP_MAC(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def Trigger11ClearArpMac(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac @ bgw"))

        for uut in site2_bgw_uut_list:
            for i in range(1,5):
                uut.execute("clear ip arp vrf all")
                uut.execute("clear mac add dy")

        countdown(180)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC164_vxlan_multisite_vPC_bgw_Clear_ARP_MAC(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger11ClearArpMac(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac "))
        for uut in site2_bgw_uut_list:
            for i in range(1,5):
                uut.execute("clear ip arp vrf all")
                uut.execute("clear mac add dy")

        countdown(180)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
class TC165_vxlan_multisite_vPC_bgw_bgw_reload(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def vtep2Reload(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))


        for uut in site2_bgw_uut_list:
            uut.execute("copy run start")
            countdown(5)
            #uut.reload()

        #countdown(500)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC166_vxlan_multisite_vPC_bgw_vlan_remove_add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def vlanVniRemove(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))
        vlan_count_to_remove_add=int(vlan_vni_scale*.8)
        vlan_2 =  vlan_start + vlan_count_to_remove_add
        for uut in site2_bgw_uut_list:
            try:
                #vlan_vni_remove(uut,vlan_start,vni,vlan_count_to_remove_add)
                vlan_remove(uut,vlan_start,vlan_count_to_remove_add)
            except:
                log.info("vlan Remove failed")

        log.info(" %r vlans Removed",vlan_count_to_remove_add )
        countdown(10)
        for uut in site2_bgw_uut_list:
            try:
                vlan_vni_configure(uut,vlan_start,vni,vlan_count_to_remove_add+1)
            except:
                log.info("vlan Remove failed")
        log.info(" %r vlan/vni's Added",vlan_count_to_remove_add )
        countdown(200)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC167_vxlan_multisite_vPC_bgw_l2fm_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'l2fm')


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC168_vxlan_multisite_vPC_bgw_l2rib_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'l2rib')


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC169_vxlan_multisite_vPC_bgw_nve_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'nve')


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC170_vxlan_multisite_vPC_bgw_vlan_mgr_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'vlan_mgr')


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC171_vxlan_multisite_vPC_bgw_ethpm_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'ethpm')


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC172_vxlan_multisite_vPC_bgw_ospf_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'ospf')


        countdown(150)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
 
class TC173_vxlan_multisite_vPC_bgw_bg1_isolation_nve_shut(aetest.Testcase): 
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - go- common_cleanup"))
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


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),[port_handle_sw1site1,port_handle_bgw2site2]):
            log.info(banner(" failed for SD @ 1 - Additional Countdown(100) total 175"))
            countdown(50)
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),[port_handle_sw1site1,port_handle_bgw2site2]):
                log.info(banner(" failed for SD - Additional Countdown(100) total 200"))
                countdown(50)
                if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),[port_handle_sw1site1,port_handle_bgw2site2]):
                    log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
                    if not VxlanStReset(site2_bgw_uut_list):
                        self.failed(goto=['common_cleanup'])
                    if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),[port_handle_sw1site1,port_handle_bgw2site2]):
                        self.failed(goto=['common_cleanup'])
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


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),[port_handle_sw1site1,port_handle_bgw2site2]):
            log.info(banner(" failed for SD @ 1 - Additional Countdown(100) total 175"))
            countdown(50)
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),[port_handle_sw1site1,port_handle_bgw2site2]):
                log.info(banner(" failed for SD - Additional Countdown(100) total 200"))
                countdown(50)
                if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),[port_handle_sw1site1,port_handle_bgw2site2]):
                    log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
                    if not VxlanStReset(site2_bgw_uut_list):
                        self.failed(goto=['common_cleanup'])
                    if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),[port_handle_sw1site1,port_handle_bgw2site2]):
                        self.failed(goto=['common_cleanup'])
                    self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
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

 

class TC174_vxlan_multisite_vPC_bgw_bg2_isolation_nve_shut(aetest.Testcase): 
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - go- common_cleanup"))
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


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),[port_handle_sw1site1,port_handle_bgw1site2]):
            log.info(banner(" failed for SD @ 1 - Additional Countdown(100) total 175"))
            countdown(50)
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),[port_handle_sw1site1,port_handle_bgw1site2]):
                log.info(banner(" failed for SD - Additional Countdown(100) total 200"))
                countdown(50)
                if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),[port_handle_sw1site1,port_handle_bgw1site2]):
                    log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
                    if not VxlanStReset(site2_bgw_uut_list):
                        self.failed(goto=['common_cleanup'])
                    if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),[port_handle_sw1site1,port_handle_bgw1site2]):
                        self.failed(goto=['common_cleanup'])
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


        countdown(150)

        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),[port_handle_sw1site1,port_handle_bgw1site2]):
            log.info(banner(" failed for SD @ 1 - Additional Countdown(100) total 175"))
            countdown(50)
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),[port_handle_sw1site1,port_handle_bgw1site2]):
                log.info(banner(" failed for SD - Additional Countdown(100) total 200"))
                countdown(50)
                if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),[port_handle_sw1site1,port_handle_bgw1site2]):
                    log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
                    if not VxlanStReset(site2_bgw_uut_list):
                        self.failed(goto=['common_cleanup'])
                    if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),[port_handle_sw1site1,port_handle_bgw1site2]):
                        self.failed(goto=['common_cleanup'])
                    self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for uut in [site2_bgw_uut_list[1]]:
            cmd1 = \
                """
                interface nve 1
                no shut
                """
            uut.configure(cmd1)


class TC175_vxlan_multisite_vPC_bgw_Clear_ip_route_vrf_all(aetest.Testcase): 
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger11ClearArpMac(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac "))
        for uut in site2_bgw_uut_list:
            for i in range(1,5):
                uut.execute("clear ip route vrf all")
                #uut.execute("clear mac add dy")

        countdown(180)


        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset(site2_bgw_uut_list):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        for uut in site2_bgw_uut_list:
            check = uut.execute('show consistency-checker l2 module 1')
            if not 'PASSED' in check:
                for uut in site2_bgw_uut_list:
                    uut.execute("clear mac address-table dynamic")
                for i in range(1,3):
                    doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')
                self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
'''
class TC200_vxlan_multisite_vPC_bgw_to_anycast_GW_convert(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self): 
        
        #pass
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            log.info(banner("TEST FAILED - go- common_cleanup"))
            self.failed(goto=['common_cleanup'])

     
    @aetest.test
    def vpcRemove(self):
        log.info(banner("Configuring Ports Channel/VPC in BGW devices"))

        if not nodeNoIsolate(site2_bgw_uut_list[1]):
            self.failed(goto=['common_cleanup'])
        if not nodeNoIsolate(site2_bgw_uut_list[0]):
            self.failed(goto=['common_cleanup'])

        
        cfg = \
        """
        int po 1
        no switchport
        no int po 1
        shut
        int po 102
        no switchport
        shut
        no int po 102
        no interface vlan10
        no feature vpc
        """

        for uut in site2_bgw_uut_list:
            uut.configure(cfg)

        cfg = \
        """
        int po 102
        no switchport
        shut
        no int po 102
        """
        
        site2_sw_uut_list[0].configure(cfg)
     
        removeLoopbackbgwVPC(site2_bgw_uut_list[0],site2_bgw_uut_list[1])


        add_101 = \
        """
        int po 101
        switchport trunk allowed vlan 1001-1032
        """
 
        for uut in site2_leaf_uut_list+[site2_sw_uut_list[0]]:
            uut.configure(add_101)
      
        countdown(200)

  
    def vxlan_traffic_test_all(self):

        log.info(banner("ARP for all streams"))
        for i in range(1,7):
            doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')

        countdown(100)
        if not AllTrafficTest(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list2):
            self.failed(goto=['common_cleanup'])


    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

 

class common_cleanup(aetest.CommonCleanup):

    @aetest.subsection
    def stop_tgn_streams(self):
        pass

    @aetest.subsection
    def disconnect_from_tgn(self):
        pass

if __name__ == '__main__':  # pragma: no cover
    aetest.main()        
 

 



