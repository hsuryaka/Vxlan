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

import upgrade_lib
from upgrade_lib import *

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
from genie.conf import *
#from genie.conf.tests import TestCase
from genie.conf.base import Testbed, Device
from genie.conf.base import Interface,Link
from genie.libs.conf.interface.nxos import Interface
from genie.libs.conf.ospf.nxos.ospf import Ospf
from genie import testbed



parameters = {
    'vlan_start' : 1001,
    'vni' : 201001,
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
    'ir_mode' : 'mix',
    'dci_interface_ip' : 'normal'
    #'dci_interface' : ''port-channel',
    #'dci_interface_ip' : 'unnumbered',
    #'spine_interface' : 'svi',
    #'spine_interface' : 'port-channel',
    #'spine_interface_ip' : 'normal',
    #'igp' : 'isis'    

    }

igp = 'isis'
vtep_emulation_spirent = 'no'
vtep_emulation_msite_spirent = 'yes'
vtep_scale = 256


rate_orph = 800000
rate_type5 = 200000
rate_sw = 1200000
test_l3_vni_scale = 2

 
issu_image = 'nxos.9.3.4.IIL9.0.708.bin.upg'
test_issu = 'no'
load_from_bootflash = 'no'



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

        global load_from_bootflash,test_port_list21,rate_list21,test_issu,issu_image,test_port_list_anycast,rate_list_anycast,vtep_emulation_msite_spirent,l2_scale_list,mcast_group_scale_list,l3_scale_list,mode_list,test_l3_vni_scale,filename_list,filename,port_handle_bgw2site3,test_port_list,rate_list,rate_orph,rate_type5,rate_sw,vtep_emulation_spirent,vtep_scale,igp,uut_list,leaf_uut_list,spine_uut_list ,bgw_uut_list,sw_uut_list , l3_uut_list,l3_site_uut_list,\
        site1_uut_list,site1_leaf_uut_list,site1_spine_uut_list ,site1_bgw_uut_list,site1_sw_uut_list,\
        site2_uut_list,site2_leaf_uut_list,site2_spine_uut_list ,site2_bgw_uut_list,site2_sw_uut_list,\
        site3_uut_list,site3_leaf_uut_list,site3_spine_uut_list ,site3_bgw_uut_list,site3_sw_uut_list,dci_uut_list,\
        tgn1_sw1site2_intf1,tgn1_sw1site3_intf1,tgn1_bgw1site2_intf1,tgn1_bgw2site2_intf1,tgn1_sw1site1_intf1,\
        orphan_handle_list,orphan_handle_list2,port_handle_list,labserver_ip,tgn1_dci1_intf1,tgn_ip,\
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
        ir_mode = parameters['ir_mode']
        mcast_group_scale = parameters['mcast_group_scale']
        bgp_as_number=parameters['bgp_as_number']
        pps = int(int(rate)/vlan_vni_scale)
        vlan_range= str(vlan_start)+"-"+str(vlan_start+vlan_vni_scale-1)
        log.info('vlan_range iss-----%r',vlan_range)

        filename='ib_msvpc_l2_'+str(vlan_vni_scale)+'_l3_'+str(routing_vlan_scale)+'_mc_'+str(mcast_group_scale)
        
        filename_list = []
        l3_scale_list = []
        l2_scale_list = []
        mode_list = []
        mcast_group_scale_list = []

        for i in uut_list:
            filename_list.append(filename)

        for i in leaf_uut_list + bgw_uut_list:
            l2_scale_list.append(vlan_vni_scale)
            mcast_group_scale_list.append(mcast_group_scale)
            l3_scale_list.append(routing_vlan_scale)
            mode_list.append(ir_mode)

 

    @aetest.subsection
    def connect(self, testscript, testbed):
        #for uut in site1_bgw_uut_list: 
        if not ConnectAll(uut_list):
            self.failed(goto=['common_cleanup'])

 
 
    
    @aetest.subsection
    def checkbringup(self, testscript, testbed):
        #for uut in uut_list:
        #    checkcdpall(uut)


        result = pcall(checkcdpall,uut=tuple(uut_list))


        if 'yes' in load_from_bootflash:
            log.info('+++++load_from_bootflash+++++')
            pcall(loadmsvpc,uut=tuple(uut_list),filename=tuple(filename_list)) 
            log.info('countdown 300 in checkbringup ')
            countdown(300)
            goto=['TC00001_configureTgn']
        
        else:
            log.info('+++++NO load_from_bootflash+++++') 
            pass  

 
 
    @aetest.subsection
    def precleanup(self, testscript, testbed):
        log.info(banner("Base cleanup"))

        result = pcall(DeviceVxlanPreCleanupAll,uut=tuple(l3_uut_list))

        if not result:
            log.info('DeviceVxlanPreCleanupAll Failed ')
            self.failed(goto=['common_cleanup'])   

        result = pcall(SwVxlanPreCleanup,uut=tuple(sw_uut_list))

        if not result:
            log.info('SwVxlanPreCleanup Failed ')
            self.failed(goto=['common_cleanup'])  

 
    @aetest.subsection
    def base_configs(self, testscript, testbed):
        log.info(banner("Base configurations"))

        log.info(banner("Base vxlanL3NodeCommonConfig"))       
        result = pcall(vxlanL3NodeCommonConfig,uut=tuple(l3_uut_list))

        if not result:
            log.info('vxlanL3NodeCommonConfig Failed ')
            self.failed(goto=['common_cleanup'])           
 
    @aetest.subsection
    def gwandLoopconfigs(self, testscript, testbed):
        log.info(banner("Base configurations"))

        log.info(banner("Base anycastgatewayConfig"))    
        pcall(anycastgatewayConfig10,uut=tuple(leaf_uut_list+bgw_uut_list))


        log.info(banner("Base ConfigureLoopback"))    
        pcall(ConfigureLoopback,uut=tuple(l3_uut_list))
 
    @aetest.subsection
    def l3_port_configs(self, testscript, testbed):
        log.info(banner("Base configurations"))

        log.info(banner("Base l3_port_configure"))  
        #pdb.set_trace()  
        pcall(ConfigureL3PortvxlanMultisite,uut=tuple(l3_uut_list))

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
        countdown(60)

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
        pcall(mctsviConfigure,uut=tuple(leaf_uut_list),igp=(igp,igp,igp,igp,igp,igp))
 
        countdown(60)
  
        log.info(banner("Starting igp verify Section"))
        for uut in leaf_uut_list:
            for feature in [igp]:
                test1 = protocolStateCheck(uut,[feature])
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
 


 
 
class TC0001_vxlan_configs(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def vxlan_configs_site1(self, testscript, testbed):
        log.info(banner("VXLAN configurations"))
        pcall(vxlanConfigureAuto222,\
            uut  = tuple(bgw_uut_list+leaf_uut_list),\
            l2_scale = tuple(l2_scale_list),\
            mcast_group_scale = tuple(mcast_group_scale_list),\
            l3_scale = tuple(l3_scale_list),\
            mode = tuple(mode_list))

        countdown(20)

    @aetest.cleanup
    def cleanup(self):
        log.info("Pass testcase cleanup")



class TC00001_vtepEmulationBgp(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")


    @aetest.test
    def vtepEmulationBgp(self):
        """ testcase clean up """
        if 'yes' in vtep_emulation_msite_spirent:        
            log.info("in  vtepEmulation BGP")
            try:
                vtepEmulationBgpConf(dci_uut_list[0],vtep_scale)
            except:
                log.info('vtepEmulationBgpConf Failed')    
                self.failed()  

    @aetest.cleanup
    def cleanup(self):
        pass
 

class TC00001_vtepEmulationSpirent(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")


    @aetest.test
    def vtepEmulationMsite(self):
        """ testcase clean up """
        if 'yes' in vtep_emulation_msite_spirent:        
            log.info("in  vtepEmulation")
            try:
                SpirentVtepEmulation(port_handle_dci1)
            except:
                log.info('SpirentVtepEmulation Failed')  
                self.failed()  


            countdown(60)
            for uut in [dci_uut_list[0]]:
                log.info("Checking bgp state @ %r",uut)
                test1 = protocolStateCheck(uut,['bgp'])
                if not test1:
                    self.failed()

    @aetest.cleanup
    def cleanup(self):
        pass


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



class TC004_Vxlan_ngoam_enable(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def enablengoam(self, testscript, testbed):
        op = pcall(enableFeaturengoam,uut=tuple(bgw_uut_list+leaf_uut_list))
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
            pcall(bfdEnable,uut=tuple(l3_uut_list))
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

 
class TC0006_vxlan_ms_configs(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
    
    @aetest.test
    def multiSiteEnable(self):

        try:
            pcall(multiSiteEnable,uut=(site1_bgw_uut_list[0],site2_bgw_uut_list[0],\
            site2_bgw_uut_list[1],site3_bgw_uut_list[0],site3_bgw_uut_list[1]),\
            vni=(101001,101001,101001,101001,101001),\
            scale=(vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale,vlan_vni_scale))

            #pcall(anycastBgwBgpConfgure,site_bgw_uut_list=tuple(site2_bgw_uut_list,site3_bgw_uut_list))

        except:
            log.error('multiSiteEnable ##')
            self.failed()

    @aetest.test
    def multiSiteAnycastEnable(self):
        try:
            anycastBgwBgpConfgure(site2_bgw_uut_list)
            anycastBgwBgpConfgure(site3_bgw_uut_list)            
        except ValueError:
            log.error('multiSiteAnycastEnable ##')
            self.failed(goto=['common_cleanup']) 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

class TC0006_vxlan_ms_type5_bring_up(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
    
    @aetest.test
    def add_type5_routes(self):
        uut1 = site1_leaf_uut_list[0]
        uut2 = site2_leaf_uut_list[0]
        uut3 = site2_bgw_uut_list[1]
        uut4 = site3_leaf_uut_list[0]
        uut5 = site3_bgw_uut_list[1]

        cfg = \
        """
        interface {intf}
        no switchp
        vrf member vxlan-90101
        ip address {ip_add}/24
        no shutdown
        router bgp {as_num}
        vrf vxlan-90101
        address-family ipv4 unicast
        network {nwk}/24
        """

        for intf in [*uut3.interfaces.keys()]:
            if 'tgn' in uut3.interfaces[intf].alias:
                intf1=uut3.interfaces[intf].intf

        uut3.configure(cfg.format(intf=intf1,ip_add="22.22.22.1",nwk="22.22.22.0",as_num="65002"))     

        for intf in [*uut5.interfaces.keys()]:
            if 'tgn' in uut5.interfaces[intf].alias:
                intf2=uut5.interfaces[intf].intf

        uut5.configure(cfg.format(intf=intf2,ip_add="33.33.33.1",nwk="33.33.33.0",as_num="65003")) 

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

class TC0008_vxlan_ms_dhcp_relay(aetest.Testcase):
    ###    This is de  scription for my testcase two

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
    
    @aetest.test
    def add_type5_routes(self):

        cfg = \
        """
        feature dhcp
        service dhcp
        ip dhcp relay
        ip dhcp relay information option
        ip dhcp relay information option vpn
        ipv6 dhcp relay

        interface Vlan1001
        ip dhcp relay address 5.1.200.1 
        ip dhcp relay source-interface loopback111

        no interface loopback111 
        interface loopback111
        vrf member vxlan-90101
        ip address {ip_add}
        no shut

        router bgp 65002
        vrf vxlan-90101
        address-fam ipv4 uni
        network {ip_add}
        """

        site2_bgw_uut_list[0].configure(cfg.format(ip_add="111.111.111.1/32"))
        site2_bgw_uut_list[1].configure(cfg.format(ip_add="111.111.111.2/32"))


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

 
class TC00001_configureTgn(aetest.Testcase):
    @aetest.setup
    def configureTgn(self, testscript, testbed):
        """ common setup subsection: connecting devices """

        global test_port_list21,rate_list21,test_port_list_anycast,rate_list_anycast,port_handle_bgw2site3,test_port_list,rate_list,tgen, port_handle_sw1site2,port_handle_sw1site3,port_handle_dci1,\
        port_handle_bgw1site1,port_handle_bgw1site2,port_handle_bgw2site2,orphan_handle_list,port_handle_list,orphan_handle_list2

        port_handle = ConnectSpirent(labserver_ip,tgn_ip,[tgn1_dci1_intf1,tgn1_sw1site2_intf1,tgn1_sw1site3_intf1,\
            tgn1_bgw1site1_intf1,tgn1_bgw1site2_intf1,tgn1_bgw2site2_intf1,tgn1_sw1site1_intf1,tgn1_bgw1site3_intf1,tgn1_bgw2site3_intf1])
 
        port_handle_sw1site1 = port_handle[tgn1_sw1site1_intf1]
        port_handle_sw1site2 = port_handle[tgn1_sw1site2_intf1]
        port_handle_sw1site3 = port_handle[tgn1_sw1site3_intf1]
        #port_handle_bgw1site1 = port_handle[tgn1_bgw1site1_intf1]
        port_handle_bgw1site2 = port_handle[tgn1_bgw1site2_intf1]
        port_handle_bgw2site2 = port_handle[tgn1_bgw2site2_intf1]        
        port_handle_bgw1site3 = port_handle[tgn1_bgw1site3_intf1]
        port_handle_bgw2site3 = port_handle[tgn1_bgw2site3_intf1]  
        port_handle_dci1 = port_handle[tgn1_dci1_intf1] 
 

        port_handle_list = [port_handle_sw1site2,port_handle_bgw2site2,port_handle_sw1site3,\
        port_handle_bgw1site2,port_handle_bgw1site3,port_handle_bgw1site3,port_handle_sw1site1]
        orphan_handle_list2 = [port_handle_sw1site1]
        orphan_handle_list = [port_handle_sw1site1,port_handle_bgw1site2,port_handle_bgw2site2]

        test_port_list = [port_handle_sw1site2,port_handle_sw1site3,port_handle_sw1site1,port_handle_bgw1site2,port_handle_bgw2site2,port_handle_bgw2site3]
        rate_list = [rate_sw,rate_sw,rate_orph,rate_orph,rate_type5,rate_type5]


        test_port_list21 = [port_handle_sw1site2,port_handle_sw1site3,port_handle_bgw1site2,port_handle_bgw2site2,port_handle_bgw2site3]
        rate_list21 = [rate_sw,rate_sw,rate_orph,rate_type5,rate_type5]


        test_port_list_anycast = [port_handle_sw1site2,port_handle_sw1site3,port_handle_sw1site1,port_handle_bgw2site2,port_handle_bgw2site3]
        rate_list_anycast = [rate_sw,rate_sw,rate_orph,rate_type5,rate_type5]  
        
class TC0007_vxlan_ms_traffic(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):

        log.info(banner("----Generating Type5 Unicast Traffic--2 to 3  --"))
        SpirentHostBidirStreamType5(port_hdl1=port_handle_bgw2site2,port_hdl2=port_handle_sw1site3,\
            vlan1='Nil',vlan2='1002',ip1='22.22.22.99',ip2='5.2.0.99',gw1='22.22.22.1',gw2='5.2.0.2',rate_pps=200000)
        SpirentHostBidirStreamType5(port_hdl1=port_handle_bgw2site3,port_hdl2=port_handle_sw1site2,\
            vlan1='Nil',vlan2='1003',ip1='33.33.33.99',ip2='5.3.0.99',gw1='33.33.33.1',gw2='5.3.0.2',rate_pps=200000)

        log.info(banner("Starting ALL Traffic"))

        vxlantrafficSetupfullScaledMS(site1_leaf_uut_list[0],port_handle_sw1site2,port_handle_sw1site3,vlan_start,vlan_vni_scale,rate,test_l3_vni_scale)
      
        log.info(banner("Starting Traffic and counting 120 seconds"))

        log.info(banner("ARP for all streams"))
        for i in range(1,7):
            doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')

        sth.traffic_control(port_handle = 'all', action = 'run')

        countdown(30)
      
    
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
    
    @aetest.test
    def vxlan_traffic_test_all(self):
        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed(goto=['common_cleanup'])



    @aetest.cleanup
    def cleanup(self):
        pass
 
 
class TC11114_vxlan_ms_vPC_bgw_issu_bgw1(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def issu_1(self, testscript, testbed):
        log.info(banner("Starting Trigger issu_1 @ 1"))

        device = site2_bgw_uut_list[0]

        if 'yes' in test_issu:
            res = start_nd_issu(device, issu_image)
  
            if not res:
                self.failed()
 
            countdown(60)
 
    @aetest.test
    def vxlan_traffic_test_all(self):
        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

class TC11111114_vxlan_ms_vPC_bgw_issu_bgw2(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def issu_1(self, testscript, testbed):
        log.info(banner("Starting Trigger issu_1 @ 1"))

        device = site2_bgw_uut_list[1]

        if 'yes' in test_issu:
            res = start_nd_issu(device, issu_image)
  
            if not res:
                self.failed()
 
            countdown(60)
 
    @aetest.test
    def vxlan_traffic_test_all(self):
        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

 
class TC1141_vxlan_ms_same_Loopback_addresses_on_Leafs(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def loopChange(self, testscript, testbed):

        fail_list = []

        loAd01 = site3_leaf_uut_list[0].execute('show running-config interface loopback0 | be loopback0')
        loAd02 = site3_leaf_uut_list[1].execute('show running-config interface loopback0 | be loopback0')

        loAd11 = site2_leaf_uut_list[0].execute('show running-config interface loopback0 | be loopback0')
        loAd12 = site2_leaf_uut_list[1].execute('show running-config interface loopback0 | be loopback0')

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

        for uut in site2_leaf_uut_list:
            uut.configure(shut_nve)
            uut.configure('no interface loopb0')

        site2_leaf_uut_list[0].configure(loAd01)
        site2_leaf_uut_list[1].configure(loAd02)

        for uut in site2_leaf_uut_list:
            uut.configure(no_shut_nve)

        countdown(60)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            fail_list.append('fail')

        log.info('Reverting Loop ipaddresss')

        for uut in site2_leaf_uut_list:
            uut.configure(shut_nve)
            uut.configure('no interface loopb0')

        site2_leaf_uut_list[0].configure(loAd11)
        site2_leaf_uut_list[1].configure(loAd12)

        for uut in site2_leaf_uut_list:
            uut.configure(no_shut_nve)

        countdown(60)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            fail_list.append('fail')
        
        if 'fail' in  fail_list:
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """



class TC1141_vxlan_ms_Change_Multisite_loopback(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def loop100IpChange(self, testscript, testbed):
        fail_list = []

        for uut in site2_bgw_uut_list:
            LoopIpAddChange(uut,'Loopback100','incr') 

        countdown(60)
 
        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            fail_list.append('fail')

        for uut in site2_bgw_uut_list:
            LoopIpAddChange(uut,'Loopback100','decr') 

        countdown(60)
 
        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            fail_list.append('fail')

        if 'fail' in  fail_list:
            self.failed()


    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """



class TC116_vxlan_ms_vPC_bgw_acc_port_flap(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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

        countdown(60)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC117_vxlan_ms_vPC_bgw_vpcmember_flap(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.testtest_port_list_anycast
    def TriggerVpcmemflap(self, testscript, testbed):
        log.info(banner("Starting Trigger4AccessPortFlap bgw"))

 
        log.info(banner("Starting Trigger2PortFlap @ 8"))
        op1= site2_bgw_uut_list[0].execute("show vpc brief | json-pretty")
        op=json.loads(op1)
        Po=op["TABLE_vpc"]["ROW_vpc"]["vpc-ifindex"][2:]

        if not vPCMemberFlap(site2_bgw_uut_list,[str(Po)]):
            self.failed()

        countdown(60)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC118_vxlan_ms_vPC_bgw_vlan_shutnoshut(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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

        countdown(60)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC119_vxlan_ms_vPC_bgw_loop100_shutnoshut(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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

        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 

class TC120_vxlan_ms_vPC_bgw_loop0_shutnoshut(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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

        countdown(40)



        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 



class TC121_vxlan_ms_vPC_bgw_one_vlan_remove_add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        pass


class TC122_vxlan_ms_vPC_bgw_L3_Vni_remove_Add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def L3VniRemoveAdd(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))

 
        if not NveL3VniRemoveAdd(site2_bgw_uut_list):
            log.info("Failed NveL3VniRemoveAdd @ 2")


        countdown(60)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 

    @aetest.cleanup
    def cleanup(self):
        pass


class TC123_vxlan_ms_vPC_bgw_Vn_Segment_remove_Add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def VnSegmentRemoveAdd(self, testscript, testbed):
        log.info(banner("Starting Trigger12NveShutNoshut bgw"))
        if not VnSegmentRemoveAdd(site2_bgw_uut_list,vlan_start):
            log.info("Failed NveL3VniRemoveAdd @ 2")


        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        pass




class TC124_vxlan_ms_vPC_bgw_nve_bounce(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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

        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 


class TC125_vxlan_ms_vPC_bgw_vpc_shut_at_bgw1(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def TriggeraccessPortFlap(self, testscript, testbed):
        log.info(banner("Starting Trigger4AccessPortFlap bgw"))

        op1= site2_bgw_uut_list[0].execute("show vpc brief | json-pretty")
        op=json.loads(op1)
        Po=op["TABLE_vpc"]["ROW_vpc"]["vpc-ifindex"]

        portShutNoshut(site2_bgw_uut_list[0],Po,'down')
 
        countdown(40)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


        portShutNoshut(site2_bgw_uut_list[0],Po,'up')

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()

 
        countdown(40)

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC126_vxlan_ms_vPC_bgw_vpc_shut_at_bgw2(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def TriggeraccessPortFlap(self, testscript, testbed):
        log.info(banner("Starting Trigger4AccessPortFlap bgw"))

        op1= site2_bgw_uut_list[1].execute("show vpc brief | json-pretty")
        op=json.loads(op1)
        Po=op["TABLE_vpc"]["ROW_vpc"]["vpc-ifindex"]

        portShutNoshut(site2_bgw_uut_list[1],Po,'down')
 
        countdown(40)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


        portShutNoshut(site2_bgw_uut_list[1],Po,'up')

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()

 
        countdown(40)

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



 

class TC127_vxlan_ms_vPC_bgw_fabric_link_failover1(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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
         
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
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


        countdown(40)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()       

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 

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


class TC128_vxlan_ms_vPC_bgw_fabric_link_failover2(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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
         
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
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


        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 

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


class TC129_vxlan_ms_vPC_bgw_spine1_isolation(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def spine1isolation(self, testscript, testbed):
        log.info(banner("Starting spine1isolation @ 8"))

        if not nodeIsolate(site2_spine_uut_list[0]):
            self.failed()

        countdown(40)
        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         



    @aetest.test
    def spine1Noisolation(self, testscript, testbed):
        log.info(banner("Starting spine1Noisolation @ 8"))
        if not nodeNoIsolate(site2_spine_uut_list[0]):
            self.failed()

        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

         
class TC130_vxlan_ms_vPC_bgw_spine2_isolation(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def spine2isolation(self, testscript, testbed):
        log.info(banner("Starting spine2isolation @ 8"))

        if not nodeIsolate(site2_spine_uut_list[1]):
            self.failed()

        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         



    @aetest.test
    def spine2Noisolation(self, testscript, testbed):
        log.info(banner("Starting spine2Noisolation @ 8"))
        if not nodeNoIsolate(site2_spine_uut_list[1]):
            self.failed()


        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC131_vxlan_ms_vPC_bgw_dci1_router_failover(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def dci1isolation(self, testscript, testbed):
        log.info(banner("Starting dci1isolation @ 8"))

        if not nodeIsolate(dci_uut_list[0]):
            self.failed()

        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         



    @aetest.test
    def dci1Noisolation(self, testscript, testbed):
        log.info(banner("Starting dci1Noisolation @ 8"))
        if not nodeNoIsolate(dci_uut_list[0]):
            self.failed()


        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC132_vxlan_ms_vPC_bgw_dci2_router_failover(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def dci2isolation(self, testscript, testbed):
        log.info(banner("Starting dci2isolation @ 8"))

        if not nodeIsolate(dci_uut_list[1]):
            self.failed()

        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         



    @aetest.test
    def dci2Noisolation(self, testscript, testbed):
        log.info(banner("Starting dci2Noisolation @ 8"))
        if not nodeNoIsolate(dci_uut_list[1]):
            self.failed()


        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC133_vxlan_ms_vPC_bgw_dci_link_failover1(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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
 
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
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

        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC134_vxlan_ms_vPC_bgw_dci_link_failover2(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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
 
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
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

        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC135_vxlan_ms_vPC_bgw_ospf_shut_noshut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC136_vxlan_ms_vPC_bgw_bgp_shut_noshut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


  
 
class TC137_vxlan_ms_vPC_bgw_spine1_ospf_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         


        site2_spine_uut_list[0].configure(cfg_noshut)
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
 
class TC138_vxlan_ms_vPC_bgw_spine2_ospf_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         



        site2_spine_uut_list[1].configure(cfg_noshut)
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         




    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC139_vxlan_ms_vPC_bgw_spine1_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         


        site2_spine_uut_list[0].configure(cfg_noshut)
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         




    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 

class TC140_vxlan_ms_vPC_bgw_spine2_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         



        site2_spine_uut_list[1].configure(cfg_noshut)
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         




    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC141_vxlan_ms_vPC_bgw_dci1_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         



        dci_uut_list[0].configure(cfg_noshut)
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC142_vxlan_ms_vPC_bgw_dci2_bgp_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         



        dci_uut_list[1].configure(cfg_noshut)
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC143_vxlan_ms_vPC_bgw_restart_ospf(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            uut.execute('restart ospf UNDERLAY')
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC144_vxlan_ms_vPC_bgw_restart_bgp(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            uut.execute('restart bgp 65002')
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC145_vxlan_ms_vPC_bgw_restart_pim(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            uut.execute('restart pim')
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
class TC146_vxlan_ms_vPC_bgw_restart_igmp(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            uut.execute('restart igmp')
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC147_vxlan_ms_vPC_bgw_restart_mld(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            uut.execute('restart mld')
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC148_vxlan_ms_vPC_bgw_anycast_bgw_remote_bgw_nve_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def bgw1shut(self, testscript, testbed):
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
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         


        site3_bgw_uut_list[0].configure(cfg_noshut)

        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         

            
    @aetest.test
    def bgw2shut(self, testscript, testbed):
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
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()

        site3_bgw_uut_list[1].configure(cfg_noshut)
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()            

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        cfg_noshut =\
        """
        interface nve 1
        no shut
        """
        site3_bgw_uut_list[0].configure(cfg_noshut)
        site3_bgw_uut_list[1].configure(cfg_noshut)




class TC149_vxlan_ms_vPC_bgw_remote_bgw_ospf_shut(aetest.Testcase):
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         



        site3_bgw_uut_list[0].configure(cfg_noshut)
        site3_bgw_uut_list[1].configure(cfg_shut)
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         


        site3_bgw_uut_list[1].configure(cfg_noshut)
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()            

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC150_vxlan_ms_vPC_bgw_remote_bgw_bgp_shut(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         



        site3_bgw_uut_list[0].configure(cfg_noshut)
        site3_bgw_uut_list[1].configure(cfg_shut)
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         


        site3_bgw_uut_list[1].configure(cfg_noshut)
        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()            

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

 
class TC151_vxlan_ms_vPC_bgw_Core_flap(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def Trigger5CoreIfFlap(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))

        for uut in site2_bgw_uut_list:
            if not L3InterfaceFlap(uut,igp):
                log.info("L3InterfaceFlap failed @ 4")
                self.failed()


        countdown(80)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC152_vxlan_ms_vPC_bgw_ClearIpRoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger6ClearIpRoute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site2_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear ip route *")

        countdown(60)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC153_vxlan_ms_vPC_bgw_clearIpMoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger7ClearIpMroute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site2_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear ip mroute *")

        countdown(60)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC154_vxlan_ms_vPC_bgw_clear_igp_Neigh(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger8ClearOspfNeigh(self, testscript, testbed):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))

        for uut in site2_bgw_uut_list:
            for i in range(1,3):
                if 'ospf' in igp:
                    uut.execute("clear ip ospf neighbor *")
                elif 'isis' in igp:
                    uut.execute("clear isis adjacency *")



        countdown(60)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC156_vxlan_ms_vPC_bgw_Clear_IP_Bgp(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger9ClearIpBgp(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))


        for uut in site2_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear ip bgp *")

        countdown(60)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC157_vxlan_ms_vPC_bgw_Clear_Bgp_l2vpn(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting TriggerClearBgpL2vpnEvpn @ bgw"))

        for uut in site2_bgw_uut_list:
            for i in range(1,3):
                uut.execute("clear bgp l2vpn evpn *")

        countdown(60)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC158_vxlan_ms_vPC_bgw_Spine_ClearIpRoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger6ClearIpRoute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip route *")

        countdown(60)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC159_vxlan_ms_vPC_bgw_Spine_ClearIpMoute(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger7ClearIpMroute(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpRoute @ 11"))

        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip mroute *")

        countdown(60)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC160_vxlan_ms_vPC_bgw_Spine_Clear_igp(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger8ClearOspfNeigh(self, testscript, testbed):
        log.info(banner("Starting TriggerClearOspfNeigh @ 11"))


        for uut in site2_spine_uut_list:
            for i in range(1,3):
                if 'ospf' in igp:
                    uut.execute("clear ip ospf neighbor *")
                elif 'isis' in igp:
                    uut.execute("clear isis adjacency *")



        countdown(60)



        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC161_vxlan_ms_vPC_bgw_Spine_Clear_IP_Bgp(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger9ClearIpBgp(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))


        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear ip bgp *")

        countdown(60)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC162_vxlan_ms_vPC_bgw_Spine_Clear_Bgp_l2vpn(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def Trigger10ClearBgpL2vpnEvpn(self, testscript, testbed):
        log.info(banner("Starting Trigger10ClearBgpL2vpnEvpn @ spine"))
        for uut in site2_spine_uut_list:
            for i in range(1,3):
                uut.execute("clear bgp l2vpn evpn *")
                #uut.execute(' clear bgp all *')
        countdown(60)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC163_vxlan_ms_vPC_bgw_Clear_ARP_MAC(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])
 
    @aetest.test
    def Trigger11ClearArpMac(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac @ bgw"))

        for uut in site2_bgw_uut_list:
            for i in range(1,5):
                uut.execute("clear ip arp vrf all")
                uut.execute("clear mac add dy")

        countdown(60)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


 
class TC164_vxlan_ms_vPC_bgw_Clear_ARP_MAC(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])



    @aetest.test
    def Trigger11ClearArpMac(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac "))
        for uut in site2_bgw_uut_list:
            for i in range(1,5):
                uut.execute("clear ip arp vrf all")
                uut.execute("clear mac add dy")

        countdown(60)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
class TC165_vxlan_ms_vPC_bgw_bgw_reload(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def vtep2Reload(self, testscript, testbed):
        log.info(banner("Starting TriggerClearIpBgp @ 11"))


        for uut in site2_bgw_uut_list:
            uut.execute("copy run start")
            countdown(5)
            #uut.reload()

        #countdown(500)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 



    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass

class TC166_vxlan_ms_vPC_bgw_vlan_remove_add(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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
        countdown(60)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC167_vxlan_ms_vPC_bgw_l2fm_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'l2fm')


        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC168_vxlan_ms_vPC_bgw_l2rib_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'l2rib')


        countdown(40)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass




class TC169_vxlan_ms_vPC_bgw_nve_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'nve')


        countdown(40)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC170_vxlan_ms_vPC_bgw_vlan_mgr_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'vlan_mgr')


        countdown(40)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC171_vxlan_ms_vPC_bgw_ethpm_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart ospf UNDERLAY @ 8"))
        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,'ethpm')


        countdown(40)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC172_vxlan_ms_vPC_bgw_ospf_restart(aetest.Testcase): 
   ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def ospfrestart(self, testscript, testbed):
        log.info(banner("Starting restart IGP UNDERLAY @ 8"))

        for uut in site2_bgw_uut_list:
            for i in range(1,2):
                ProcessRestart(uut,igp)


        countdown(40)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()         

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 
 
class TC173_vxlan_ms_vPC_bgw_bg1_isolation_nve_shut(aetest.Testcase): 
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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


        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
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


        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()      



    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


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

 

class TC174_vxlan_ms_vPC_bgw_bg2_isolation_nve_shut(aetest.Testcase): 
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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


        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
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


        countdown(40)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()      


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


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


class TC175_vxlan_ms_vPC_bgw_Clear_ip_route_vrf_all(aetest.Testcase): 
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def Trigger11ClearArpMac(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac "))
        for uut in site2_bgw_uut_list:
            for i in range(1,5):
                uut.execute("clear ip route vrf all")
                #uut.execute("clear mac add dy")

        countdown(60)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass
 


class TC000001_vxlan_ms_Peer_type_fabric_externa(aetest.Testcase):
    ###    This is description for my tecase two

 
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

                

    @aetest.test
    def removAdd_Peer_type_fabric_external(self, testscript, testbed):
        log.info(banner("Starting Trigger11ClearArpMac @ bgw"))

        cfg1 = \
        """
        router bgp 65002
        template peer dcioverlay
        no peer-type fabric-external
        """
        cfg2 = \
        """
        router bgp 65002
        template peer dcioverlay
        peer-type fabric-external
        """

        for uut in site2_bgw_uut_list:
            for i in range(1,5):
                uut.configure(cfg1)
                countdown(2)
                uut.configure(cfg2)

        countdown(20)

        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()      

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(site2_bgw_uut_list):
            self.failed()

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass


class TC115_vxlan_ms_vPC_bgw_mct_flap(aetest.Testcase):
    ###    This is description for my tecase two
    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
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


        countdown(60)


        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        pass



class TC114a_vxlan_ms_vPC_mac_move_3_1(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def mac_move_1(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        

        cfg = \
        """
        int {Po}
        switchport trunk allowed vlan {vlan_range}
        """

        cfg2 = \
        """
        int po 101
        switchport trunk allowed vlan 1001-1032

        int po 133
        switchport trunk allowed vlan none

        int po 111
        switchport trunk allowed vlan 1001-1032
        """


        log.info('Current   :  sw1s3-101-leafs3---bgws3---dci---bgws2---leafs2---sw1s2')
        log.info('Change to :  sw1s3-111-leafs1---bgws1---dci---bgws2---leafs2---sw1s2')

        for uut in site3_leaf_uut_list+site1_leaf_uut_list+site1_sw_uut_list+site3_sw_uut_list:
            uut.configure(cfg.format(Po='Po101',vlan_range='none'))

        for uut in site3_leaf_uut_list+site1_sw_uut_list:
            uut.configure(cfg.format(Po='Po133',vlan_range=vlan_range))

        for uut in site1_leaf_uut_list+site3_sw_uut_list:
            uut.configure(cfg.format(Po='Po111',vlan_range=vlan_range))

        countdown(24)
 
        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 


    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """


class TC114aa_vxlan_ms_vPC_mac_move_1_3_revert(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])

    @aetest.test
    def mac_move_1(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        

        cfg = \
        """
        int {Po}
        switchport trunk allowed vlan {vlan_range}
        """

        log.info('Current   :  sw1s3-101-leafs3---bgws3---dci---bgws2---leafs2---sw1s2')
        log.info('Change to :  sw1s3-111-leafs1---bgws1---dci---bgws2---leafs2---sw1s2')

        for uut in site3_leaf_uut_list+site1_leaf_uut_list+site1_sw_uut_list+site3_sw_uut_list:
            uut.configure(cfg.format(Po='Po101',vlan_range=vlan_range))

        for uut in site3_leaf_uut_list+site1_sw_uut_list:
            uut.configure(cfg.format(Po='Po133',vlan_range='none'))

        for uut in site1_leaf_uut_list+site3_sw_uut_list:
            uut.configure(cfg.format(Po='Po111',vlan_range='none'))

        countdown(24)

 
        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()


    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """



class TC114a_vxlan_ms_vPC_mac_move_2_1(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list_anycast,rate_list_anycast,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def mac_move_1(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        

        cfg = \
        """
        int {Po}
        switchport trunk allowed vlan {vlan_range}
        """

        log.info('Current   :  sw1s3-101-leafs3---bgws3---dci---bgws2---leafs2---sw1s2')
        log.info('Change to :  sw1s3-111-leafs1---bgws1---dci---bgws1---leafs1---sw1s1')

        for uut in site2_leaf_uut_list+site1_leaf_uut_list+site1_sw_uut_list+site2_sw_uut_list:
            uut.configure(cfg.format(Po='Po101',vlan_range='none'))

        for uut in site2_sw_uut_list:
            uut.configure(cfg.format(Po='Po102',vlan_range='none'))

        for uut in site1_leaf_uut_list+site2_sw_uut_list:
            uut.configure(cfg.format(Po='Po122',vlan_range=vlan_range))

        countdown(24)

 
        if not traffictest1(test_port_list21,rate_list21):
            self.failed()

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
            self.failed(goto=['common_cleanup'])
 

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """
 
class TC114a_vxlan_ms_vPC_mac_move_2_1_revert(aetest.Testcase):
    ###    This is description for my tecase two

    @aetest.setup
    def setup(self):
        if not setupTrafficTest(test_port_list21,rate_list21,bgw_uut_list,filename):
            self.failed(goto=['common_cleanup'])


    @aetest.test
    def mac_move_1(self, testscript, testbed):
        log.info(banner("Starting TriggerCoreIfFlap222 @ 8"))
        

        cfg = \
        """
        int {Po}
        switchport trunk allowed vlan {vlan_range}
        """

        log.info('Current   :  sw1s3-101-leafs3---bgws3---dci---bgws2---leafs2---sw1s2')
        log.info('Change to :  sw1s3-111-leafs1---bgws1---dci---bgws2---leafs2---sw1s2')

        for uut in site2_leaf_uut_list+site1_leaf_uut_list+site1_sw_uut_list+site2_sw_uut_list:
            uut.configure(cfg.format(Po='Po101',vlan_range=vlan_range))

        for uut in site2_sw_uut_list:
            uut.configure(cfg.format(Po='Po102',vlan_range='none'))

        for uut in site1_leaf_uut_list+site2_sw_uut_list:
            uut.configure(cfg.format(Po='Po122',vlan_range='none'))


        countdown(24)

 
        if not traffictest1(test_port_list_anycast,rate_list_anycast):
            self.failed()

    @aetest.test
    def ConsistencyChecker(self, testscript, testbed):
        if not vxlanMsiteCCheckerAll(bgw_uut_list):
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
 

 



