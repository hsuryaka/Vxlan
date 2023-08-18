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
    'tolerence' : 3000,
    'igp' : 'isis',
    'ipv6enable' : 'yes',
    'spine_interface' : 'normal',
    'spine_interface_ip' : 'unnumbered',
    'dci_interface' : 'normal',
    'dci_interface_ip' : 'normal'
    #'dci_interface' : ''port-channel',
    #'dci_interface_ip' : 'unnumbered',
    #'spine_interface' : 'svi',
    #'spine_interface' : 'port-channel',
    #'spine_interface_ip' : 'normal',
    #'igp' : 'isis'    

    }

igp = 'isis'
vtep_emulation_spirent = 'yes'
vtep_scale = 32
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

        global orphan_handle_list_sa,vtep_emulation_spirent,vtep_scale,igp,uut_list,leaf_uut_list,spine_uut_list ,bgw_uut_list,sw_uut_list , l3_uut_list,l3_site_uut_list,\
        site1_uut_list,site1_leaf_uut_list,site1_spine_uut_list ,site1_bgw_uut_list,site1_sw_uut_list,\
        site2_uut_list,site2_leaf_uut_list,site2_spine_uut_list ,site2_bgw_uut_list,site2_sw_uut_list,\
        site3_uut_list,site3_leaf_uut_list,site3_spine_uut_list ,site3_bgw_uut_list,site3_sw_uut_list,dci_uut_list,\
        tgn1_sw1site2_intf1,tgn1_sw1site3_intf1,tgn1_bgw1site2_intf1,tgn1_bgw2site2_intf1,tgn1_sw1site1_intf1,\
        orphan_handle_list,orphan_handle_list_sa,port_handle_list,labserver_ip,tgn1_dci1_intf1,tgn_ip,\
        vlan_start,vlan_vni_scale,rate,tolerence,vni,routed_vlan,routed_vni,routing_vlan_scale,\
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
        tgn1_bgw2site2_intf1 = testbed.devices['tgn1'].interfaces['tgn1_bgw2site2_intf1'].intf
        tgn1_bgw1site3_intf1 = testbed.devices['tgn1'].interfaces['tgn1_bgw1site3_intf1'].intf
        tgn1_bgw2site3_intf1 = testbed.devices['tgn1'].interfaces['tgn1_bgw2site3_intf1'].intf


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
        #for uut in dci_uut_list + bgw_uut_list:
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
 
    @aetest.subsection
    def precleanup(self, testscript, testbed):
        log.info(banner("Base cleanup"))


        #result = pcall(DeviceVxlanPreCleanupAll,uut=(l3_uut_list[0],l3_uut_list[1],l3_uut_list[2],l3_uut_list[3],\
        #    l3_uut_list[4],l3_uut_list[5],l3_uut_list[6],l3_uut_list[7],l3_uut_list[8],l3_uut_list[9],\
        #    l3_uut_list[10],l3_uut_list[11],l3_uut_list[12],l3_uut_list[13],l3_uut_list[14],l3_uut_list[15],\
        #    l3_uut_list[16]))

        result = pcall(unShutall,uut=(l3_uut_list[0],l3_uut_list[1],l3_uut_list[2],l3_uut_list[3],\
            l3_uut_list[4],l3_uut_list[5],l3_uut_list[6],l3_uut_list[7],l3_uut_list[8],l3_uut_list[9],\
            l3_uut_list[10],l3_uut_list[11],l3_uut_list[12],l3_uut_list[13],l3_uut_list[14],l3_uut_list[15],\
            l3_uut_list[16]))



        #if not result:
        #    log.info('DeviceVxlanPreCleanupAll Failed ')
        #    self.failed(goto=['common_cleanup'])   

        result = pcall(unShutall,uut=(sw_uut_list[0],sw_uut_list[1],sw_uut_list[2]))
        #result = pcall(SwVxlanPreCleanup,uut=(sw_uut_list[0],sw_uut_list[1],sw_uut_list[2]))


        #if not result:
        #    log.info('SwVxlanPreCleanup Failed ')
        #    self.failed(goto=['common_cleanup'])  

    '''
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
            l3_site_uut_list[10],l3_site_uut_list[11],l3_site_uut_list[12],l3_site_uut_list[13],l3_site_uut_list[14]),\
            igp=(igp,igp,igp,igp,igp,igp,igp,igp,igp,igp,igp,igp,igp,igp,igp))
            
        countdown(60)
  
        log.info(banner("Starting igp verify Section"))
        for uut in leaf_uut_list+bgw_uut_list+spine_uut_list:
            for feature in [igp]:
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
            vpc_access_port_member_list_111 = []

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


                elif 'vpc_po_111' in uut.interfaces[intf].alias:
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

                elif 'vpc_access111' in uut.interfaces[intf].alias:
                    intf=uut.interfaces[intf].intf
                    log.info("adding vpc port-channel member %r on leaf device  %r",intf,uut)
                    vpc_access_port_member_list_111.append(intf)


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

                elif '111' in vpc_po:
                    try:
                        vtep_vpc_obj1 = VPCPoConfig(uut,vpc_po,vpc_access_port_member_list_111,\
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

        for uut in leaf_uut_list:
            op=uut.execute('show port-channel summary | incl Eth')
            op1=op.splitlines()
            for line in op1:
                if line:
                    if not "(P)" in line:
                        log.info('VPC Bringup Failed on device %r',str(uut))
                        uut.execute('show port-channel summary')
                        self.failed(goto=['common_cleanup'])
     
    @aetest.subsection
    def mctsviconfigure(self):
        log.info(banner("Configuring mctsviconfigure"))
        
        #pdb.set_trace()
        pcall(mctsviConfigure,uut=(leaf_uut_list[0],leaf_uut_list[1],leaf_uut_list[2],leaf_uut_list[3],\
            leaf_uut_list[4],leaf_uut_list[5]),igp=(igp,igp,igp,igp,igp,igp))
 
        countdown(30)
  
        log.info(banner("Starting igp verify Section"))
        for uut in leaf_uut_list:
            for feature in [igp]:
                test1 = protocolStateCheck(uut,[feature])
                if not test1:
                    log.info('Feature %r neigborship on device %r Failed ',feature,str(uut))
                    self.failed(goto=['common_cleanup'])
 
    @aetest.subsection
    def configureTgn(self, testscript, testbed):
        """ common setup subsection: connecting devices """

        global tgen, port_handle_sw1site2,port_handle_sw1site3,port_handle_dci1,orphan_handle_list_sa,\
        port_handle_bgw1site2,port_handle_bgw2site2,orphan_handle_list,port_handle_list,orphan_handle_list_sa

        port_handle = ConnectSpirent(labserver_ip,tgn_ip,[tgn1_dci1_intf1,tgn1_sw1site2_intf1,tgn1_sw1site3_intf1,\
            tgn1_bgw1site1_intf1,tgn1_bgw1site2_intf1,tgn1_bgw2site2_intf1,tgn1_sw1site1_intf1,tgn1_bgw1site3_intf1,tgn1_bgw2site3_intf1])
 
        port_handle_sw1site1 = port_handle[tgn1_sw1site1_intf1]
        port_handle_sw1site2 = port_handle[tgn1_sw1site2_intf1]
        port_handle_sw1site3 = port_handle[tgn1_sw1site3_intf1]
        port_handle_bgw1site1 = port_handle[tgn1_bgw1site1_intf1]
        port_handle_bgw1site2 = port_handle[tgn1_bgw1site2_intf1]
        port_handle_bgw2site2 = port_handle[tgn1_bgw2site2_intf1]        
        port_handle_bgw1site3 = port_handle[tgn1_bgw1site3_intf1]
        port_handle_bgw2site3 = port_handle[tgn1_bgw2site3_intf1]  
        port_handle_dci1 = port_handle[tgn1_dci1_intf1] 

        port_handle_list = [port_handle_sw1site2,port_handle_bgw1site1,port_handle_bgw2site2,port_handle_sw1site3,\
        port_handle_bgw1site2,port_handle_bgw1site3,port_handle_bgw1site3,port_handle_sw1site1]
        orphan_handle_list_sa = [port_handle_sw1site1,port_handle_bgw1site1,port_handle_bgw1site2,port_handle_bgw1site3]
        orphan_handle_list = [port_handle_sw1site1,port_handle_bgw1site1,port_handle_bgw1site2,port_handle_bgw1site3]
 
#######################################################################
###                          TESTCASE BLOCK                         ###
#######################################################################
#
# Place your code that implements the test steps for the test case.
# Each test may or may not contains sections:
#           setup   - test preparation
#           test    - test action
#           cleanup - test wrap-up

 
 
class TC0001_vxlan_configs(aetest.Testcase):
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
            l2_scale =(vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale),\
            l3_scale =(routing_vlan_scale,routing_vlan_scale,routing_vlan_scale,routing_vlan_scale,routing_vlan_scale,routing_vlan_scale,routing_vlan_scale,routing_vlan_scale,routing_vlan_scale,routing_vlan_scale,routing_vlan_scale),\
            mode=('mix','mix','mix','mix','mix','mix','mix','mix','mix','mix','mix'),\
            as_num=('65001','65001','65001','65002','65002','65002','65002','65003','65003','65003','65003'))

        countdown(120)

        for uut in uut_list:
            uut.configure('copy run start',timeout=100)

    @aetest.cleanup
    def cleanup(self):
        log.info("Pass testcase cleanup")
 
class TC01_Nve_Simulation_To_Scale(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        #log.info("Pass testcase setup")
             #dci1_tgn1_intf1: 
             #   intf: "Eth1/1/1"
             #   link: link-1
             #   type: fiber
             #   ipv4: "99.0.0.1/8"
             #   pim: 'yes'

        threads = []
        for uut in [dci_uut_list[0]]:
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

            if 'yes' in vtep_emulation_spirent:
                spine_bgp_obj2=IbgpSpineNode(uut,bgp_rid,'99',adv_nwk_list_tgn,neight_list_spine_tgn,intf_tgn,'ibgp-vxlan-tgn')
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

        bgp1 = sth.emulation_bgp_config (
                mode='enable',
                port_handle=port_handle_dci1,
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
        ip_list = []
        for i in range(0,scale):
            ip_list.append(ip)
            ip = ip + i


        mac = 'aa:bb:cc:dd:ee:01' 

 
        for router,ip in zip(bgp_dev_list,ip_list):
            type3 = sth.emulation_bgp_route_config (
                mode = 'add',
                handle = router,
                evpn_type3_agg_ip = str(ip),
                route_type = 'evpn_type3',
                evpn_type3_community='99:1',
                evpn_type3_data_plane_encap='vxlan',
                evpn_type3_encap_label='201001',
                evpn_type3_origin='igp',
                evpn_type3_route_target='99:201001',
                )
            type2 = sth.emulation_bgp_route_config (
                mode = 'add',
                handle = router,
                evpn_type2_mac_addr_start =mac,
                route_type = 'evpn_type2',
                evpn_type2_community='99:1',
                evpn_type2_data_plane_encap ='vxlan',
                evpn_type2_encap_label='201001',
                evpn_type2_origin='igp',
                evpn_type2_route_target ='99:201001',
                )


        bgp1_start1 = sth.emulation_bgp_control (
                handle = bgp_dev_list,
                mode = 'start')

        elapsed_time = time.time() - start_time
 
        log.info(banner("C O M P L E A T E D    vTEP   E M U L A T I O N  "))

        log.info("Thank you for the patience :-) , Time taken for Simulating %r vTEP's is %r",vtep_scale,elapsed_time)


        countdown(60)
        for uut in [dci_uut_list[0]]:
            log.info("Checking bgp state @ %r",uut)
            test1 = protocolStateCheck(uut,['bgp'])
            if not test1:
                self.failed()

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

    @aetest.test
    def check_nve_peer_state(self):

        test1 = NvePeerCheck(leaf_uut_list,1)
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
        for uut in leaf_uut_list:
            uut.execute('terminal length 0')

            test1 = protocolStateCheck(uut,['nve-vni'])
            if not test1:
                self.failed()

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

class TC0004_Vxlan_Consistency_check(aetest.Testcase):
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

class TC004_Vxlan_ngoam_enable(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def enablengoam(self, testscript, testbed):
        op = pcall(enableFeaturengoam,uut=(site1_bgw_uut_list[0],site1_leaf_uut_list[0],site1_leaf_uut_list[1],\
            site2_bgw_uut_list[0],site2_bgw_uut_list[1],site2_leaf_uut_list[0],site2_leaf_uut_list[1],\
            site3_bgw_uut_list[0],site3_bgw_uut_list[1],site3_leaf_uut_list[0],site3_leaf_uut_list[1]))
        #op = pcall(enableFeaturengoam,uut=(vtep_uut_list[0],vtep_uut_list[1],vtep_uut_list[1]))
        if not op:
            log.info('TC004_Vxlan_ngoam_enable FAILED')
            self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

 
class TC0005_vxlan_dci_bgp_configs(aetest.Testcase):
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
        
    
    @aetest.test
    def dciEbgpv4Bringup(self):

        log.info("+++ Starting dciEbgpv4Bringup +++")

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

  
class TC0006_vxlan_multisite_configs(aetest.Testcase):
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
 
 
 


class TC007_vxlan_multisite_BGW_standalone_mode_bringup(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
    
    @aetest.test
    def BGWstandalonemode(self):
        if not nodeIsolate(site2_bgw_uut_list[1]):
            self.failed()
        if not nodeIsolate(site3_bgw_uut_list[1]):
            self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

class TC0007_vxlan_ms_anycbgw_traffic(aetest.Testcase):
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
        
        log.info(banner("----Generating mcast flood traffic----"))
        test1= mcastTrafficGeneratorScale(port_handle_sw1site2,vlan_start,ip_sa1,'239.1.1.1',rate,str(vlan_vni_scale))
        test2= mcastTrafficGeneratorScale(port_handle_sw1site3,vlan_start,ip_sa2,'239.1.1.1',rate,str(vlan_vni_scale))
        

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
    def nxosvxlancontrolplaneleaf(self, testscript, testbed):
        for uut in leaf_uut_list:        
            if not nxosVxlanEvpnCheck(uut,mac='0012.6060.0002'):
                log.info('nxosVxlanEvpnCheck FAILED for %r',uut)
                self.failed()

    @aetest.test
    def nxosvxlancontrolplanebgw(self, testscript, testbed):
        for uut in bgw_uut_list:        
            if not nxosVxlanEvpnCheck(uut,mac='0012.6060.0002'):
                log.info('nxosVxlanEvpnCheck FAILED for %r',uut)
                self.failed()       
    @aetest.test
    def vxlan_traffic_test_all(self):

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            self.failed(goto=['common_cleanup'])


    @aetest.cleanup
    def cleanup(self):
        pass
 
 

class TC007_vxlan_multisite_BGW_sa_trm_bgw(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
    
    @aetest.test
    def trmenable(self):
        pcall(trmEnablebgw,uut=(bgw_uut_list[0],bgw_uut_list[1],bgw_uut_list[2],bgw_uut_list[3],bgw_uut_list[4]))
            #,\
            #vlan_vni_scale=(vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale))

        pcall(trmEnabledci,uut=(dci_uut_list[0],dci_uut_list[1])) 

        for uut in bgw_uut_list+dci_uut_list:
            uut.configure('copy run start',timeout=100)

        countdown(45) 
 

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

 



class TC004_Vxlan_nxos_checks(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def nxosvxlancontrolplaneleaf(self, testscript, testbed):
        for uut in leaf_uut_list:        
            if not nxosVxlanEvpnCheck(uut,mac='0012.6060.0002'):
                log.info('nxosVxlanEvpnCheck FAILED for %r',uut)
                #self.failed()

    @aetest.test
    def nxosvxlancontrolplanebgw(self, testscript, testbed):
        for uut in bgw_uut_list:        
            if not nxosVxlanEvpnCheck(uut,mac='0012.6060.0002'):
                log.info('nxosVxlanEvpnCheck FAILED for %r',uut)
                #self.failed()


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
        
 
class TC0006a_vxlan_ms_anycbgw_type5_route_add(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

        
    @aetest.test
    def evpntype5routeadd(self):
        fail_list = []
        if not evpnType5routeAdd(site2_bgw_uut_list[0],'22.1.1.0/24','65002','5.1.0.100'):
            fail_list.append('fail')
        if not evpnType5routeAdd(site2_leaf_uut_list[0],'22.2.2.0/24','65002','5.1.0.3'):
            fail_list.append('fail')
        if not evpnType5routeAdd(site3_bgw_uut_list[0],'33.1.1.0/24','65003','5.1.0.122'):
            fail_list.append('fail')
        if not evpnType5routeAdd(site3_leaf_uut_list[0],'33.3.3.0/24','65003','5.1.0.22'):
            fail_list.append('fail')
        
        countdown(30)

    @aetest.test
    def evpntype5routecheck(self):
        fail_list = []
        for uut in leaf_uut_list + bgw_uut_list:
            uut.execute('sh bgp l2 evpn route-type 5')
            uut.execute(' sh ip route 22.1.1.0 vrf vxlan-90101')
            uut.execute(' sh ip route 22.2.2.0 vrf vxlan-90101')
            uut.execute(' sh ip route 33.1.1.0 vrf vxlan-90101')
            uut.execute(' sh ip route 33.3.3.0 vrf vxlan-90101')


    @aetest.cleanup
    def cleanup(self):
        pass
 

 
class TC008_vxlan_multisite_bgw_sa_l2fm_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,2):
                ProcessRestart(uut,'l2fm')


        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,2):
                ProcessRestart(uut,'l2rib')


        countdown(150)


        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,2):
                ProcessRestart(uut,'nve')


        countdown(150)


        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,2):
                ProcessRestart(uut,'vlan_mgr')


        countdown(150)


        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,2):
                ProcessRestart(uut,'ethpm')


        countdown(150)


        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,2):
                ProcessRestart(uut,'ospf')


        countdown(150)


        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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


        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def spine1isolation(self, testscript, testbed):
        log.info(banner("Starting spine1isolation @ 8"))

        if not nodeIsolate(site2_spine_uut_list[0]):
            self.failed()

        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            nodeNoIsolate(site2_spine_uut_list[0])
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def spine1Noisolation(self, testscript, testbed):
        log.info(banner("Starting spine1Noisolation @ 8"))
        if not nodeNoIsolate(site2_spine_uut_list[0]):
            self.failed()

        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def spine2isolation(self, testscript, testbed):
        log.info(banner("Starting spine2isolation @ 8"))

        if not nodeIsolate(site2_spine_uut_list[1]):
            self.failed()

        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            nodeNoIsolate(site2_spine_uut_list[1])
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def spine2Noisolation(self, testscript, testbed):
        log.info(banner("Starting spine2Noisolation @ 8"))
        if not nodeNoIsolate(site2_spine_uut_list[1]):
            self.failed()


        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def dci1isolation(self, testscript, testbed):
        log.info(banner("Starting dci1isolation @ 8"))

        if not nodeIsolate(dci_uut_list[0]):
            self.failed()

        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            nodeNoIsolate(dci_uut_list[0])
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def dci1Noisolation(self, testscript, testbed):
        log.info(banner("Starting dci1Noisolation @ 8"))
        if not nodeNoIsolate(dci_uut_list[0]):
            self.failed()


        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def dci2isolation(self, testscript, testbed):
        log.info(banner("Starting dci2isolation @ 8"))

        if not nodeIsolate(dci_uut_list[1]):
            self.failed()

        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            nodeNoIsolate(dci_uut_list[1])
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                self.failed(goto=['common_cleanup'])
            self.failed()


    @aetest.test
    def dci2Noisolation(self, testscript, testbed):
        log.info(banner("Starting dci2Noisolation @ 8"))
        if not nodeNoIsolate(dci_uut_list[1]):
            self.failed()


        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site2_spine_uut_list[0].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site2_spine_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site2_spine_uut_list[0].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site2_spine_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            dci_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                self.failed(goto=['common_cleanup'])
            self.failed()


        dci_uut_list[0].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            dci_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                self.failed(goto=['common_cleanup'])
            self.failed()


        dci_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site2_spine_uut_list[0].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            uut.execute('restart ospf UNDERLAY')
        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            uut.execute('restart bgp 65002')
        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            uut.execute('restart pim')
        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            uut.execute('restart igmp')
        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in [site2_bgw_uut_list[0]]:
            uut.execute('restart mld')
        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            countdown(100)
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                if not VxlanStReset([site2_bgw_uut_list[0]]):
                    self.failed(goto=['common_cleanup'])
                if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                    self.failed(goto=['common_cleanup'])
            self.failed()

        site3_bgw_uut_list[0].configure(cfg_noshut)

        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            countdown(100)
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                if not VxlanStReset([site2_bgw_uut_list[0]]):
                    self.failed(goto=['common_cleanup'])
                if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                self.failed(goto=['common_cleanup'])
            self.failed()

        site3_bgw_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site3_bgw_uut_list[0].configure(cfg_noshut)
        site3_bgw_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                self.failed(goto=['common_cleanup'])
            self.failed()

        site3_bgw_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                self.failed(goto=['common_cleanup'])
            self.failed()


        site3_bgw_uut_list[0].configure(cfg_noshut)
        site3_bgw_uut_list[1].configure(cfg_shut)
        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            site3_bgw_uut_list[0].configure(cfg_noshut)
            site3_bgw_uut_list[1].configure(cfg_noshut)
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                self.failed(goto=['common_cleanup'])
            self.failed()

        site3_bgw_uut_list[1].configure(cfg_noshut)
        countdown(150)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def Trigger5CoreIfFlap(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))

        if not TriggerCoreIfFlap222([site2_bgw_uut_list[0]]):
            log.info("TriggerCoreIfFlap222 failed @ 4")
            #self.failed()

        countdown(280)


        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger6ClearIpRoute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,3):
                uut.execute("clear ip route *")

        countdown(160)


        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger7ClearIpMroute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,3):
                uut.execute("clear ip mroute *")

        countdown(160)


        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger8ClearOspfNeigh(self, testscript, testbed):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))

        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,3):
                uut.execute("clear ip ospf neighbor *")

        countdown(180)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger9ClearIpBgp(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))


        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,3):
                uut.execute("clear ip bgp *")

        countdown(180)


        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting TriggerClearBgpL2vpnEvpn @ bgw"))

        for uut in [site2_bgw_uut_list[0]]:
            for i in range(1,3):
                uut.execute("clear bgp l2vpn evpn *")

        countdown(180)



        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger6ClearIpRoute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip route *")

        countdown(160)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger7ClearIpMroute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip mroute *")

        countdown(160)


        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger8ClearOspfNeigh(self, testscript, testbed):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))

        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip ospf neighbor *")

        countdown(320)



        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger9ClearIpBgp(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))


        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip bgp *")

        countdown(320)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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


        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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


        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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


        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner(" faile for tahoe - Additional Countdown(100)"))
            countdown(100)
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
                if not VxlanStReset(site3_bgw_uut_list):
                    self.failed(goto=['common_cleanup'])
                if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner(" failed for SD @ 1 - Additional Countdown(100) total 175"))
            countdown(50)
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                log.info(banner(" failed for SD - Additional Countdown(100) total 200"))
                countdown(50)
                if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
                    log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
                    if not VxlanStReset([site2_bgw_uut_list[0]]):
                        self.failed(goto=['common_cleanup'])
                    if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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


        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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



        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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



        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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


        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def L3VniRemoveAdd(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))


        if not NveL3VniRemoveAdd([site2_bgw_uut_list[0]]):
            log.info("Failed NveL3VniRemoveAdd @ 2")


        countdown(200)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def VnSegmentRemoveAdd(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))
        if not VnSegmentRemoveAdd([[site2_bgw_uut_list[0]][0]],vlan_start):
            log.info("Failed NveL3VniRemoveAdd @ 2")


        countdown(300)

        if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
            log.info(banner("TEST FAILED - Starting VXLAN Recovery"))
            if not VxlanStReset([site2_bgw_uut_list[0]]):
                self.failed(goto=['common_cleanup'])
            if not AllTrafficTestMsite(port_handle_sw1site2,port_handle_sw1site3,rate,int(pps),orphan_handle_list_sa):
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
'''

class common_cleanup(aetest.CommonCleanup):

    @aetest.subsection
    def stop_tgn_streams(self):
        pass

    @aetest.subsection
    def disconnect_from_tgn(self):
        pass

if __name__ == '__main__':  # pragma: no cover
    aetest.main()        
 

 

