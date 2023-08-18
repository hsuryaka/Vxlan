import logging
from pyats.async_ import pcall
from pyats import aetest
from genie.testbed import load
 
import time
import os
from IxNetwork import IxNet
from ats import aetest, log
from pexpect import pxssh
import getpass
import pdb
from ipaddress import *
import sys
import random
import genie
import yaml
from genie.libs.conf.ospf import Ospf
 
import unittest
from unittest.mock import Mock
from Project_Conf import *

from genie.conf import Genie
from genie.conf.base import Testbed, Device, Link, Interface

# Genie Conf
from genie.libs.conf.vrf import Vrf
from genie.libs.conf.interface import Interface
from genie.libs.conf.ospf import Ospf
from genie.libs.conf.ospf.gracefulrestart import GracefulRestart
from genie.libs.conf.ospf.stubrouter import StubRouter
from genie.libs.conf.ospf.areanetwork import AreaNetwork
from genie.libs.conf.ospf.arearange import AreaRange
from genie.libs.conf.ospf.interfacestaticneighbor import InterfaceStaticNeighbor
from unicon.utils import Utils
logger = logging.getLogger(__name__)

from unicon.eal.dialogs import Statement, Dialog
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

import os
import socket
import warnings,time

# import Python packages
import time
import os
from IxNetwork import IxNet
 
import ixiaPyats_lib
from Project_Lib import *

ixiangpf = IxiaNgpf(ixiahlt)

scale = 1

class CommonSetup(aetest.CommonSetup):
    # Common Setup section always runs first within the script

    @aetest.subsection
    def connect_to_tb_devices(self, testbed,build=""):
        self.parent.parameters['testbed'] = testbed = load(testbed)

        global scale,ixiangpf,ixLib,vtep_uut_list,uut_list,vtep_1,vtep_2,vtep_3,spine,fanout,sw3,conf_dict,l3_device_list,l3_conf_dict,\
            l2_conf_dict,l2_device_list,leaf_conf_dict,tgn1,client_mac_list,dhcp_client1,client_mac_list1,topo_handle1,dhcp_client2,client_mac_list2,topo_handle2,\
            client_port_hdl1,client_port_hdl2,mac_start1,mac_start2,mac_start3,mac_start4,snoop_list_local_1,snoop_list_local_2,snoop_list_local_3,fanout_svi_mac_svi_mac,sw3_svi_mac,\
            snoop_mac_list,dhcp_client3,topo_handle1,topo_handle2,topo_handle3,dhcp_client1,client_mac_list1,topo_handle1,dhcp_client2,client_mac_list2,topo_handle2,client_port_hdl1,client_port_hdl2,\
            dhcp_client3,dhcp_client4,topo_handle3,port_hdl3,port_hdl4,port_hdl5,topo_handle4,port_hdl1,port_hdl2,port_list

        port1 = '2/7'
        port2 = '2/2'
        port3 = '2/6'
        port4 = '2/5'
        port5 = '2/3'

        port_list = [port1,port2,port3,port4,port5]
        
        client_mac_list = []

        skip_setup =  False
        image_upgrade = True

        chassisIP = '10.104.102.68'
        serverIP = '10.104.102.238'

        vtep_1 = testbed.devices['VTEP-1']
        vtep_2 = testbed.devices['VTEP-2']   
        vtep_3 = testbed.devices['VTEP-3']               
        spine = testbed.devices['SPINE']
        fanout = testbed.devices['FANOUT']     
     
        vtep_uut_list = [vtep_1,vtep_2,vtep_3]
        uut_list = [vtep_1,vtep_2,vtep_3,spine,fanout]
        conf_dict = yaml.safe_load(open('/ws/rudshah-bgl/automation/repo_develop/Summer Internship Project/Project_Topology.yaml'))

        l3_device_list = [vtep_1,vtep_2,vtep_3,spine] 
        l3_conf_dict = (conf_dict,conf_dict,conf_dict,conf_dict)
        leaf_conf_dict = (conf_dict,conf_dict,conf_dict)
        l2_conf_dict = (conf_dict,conf_dict,conf_dict,conf_dict)
        l2_device_list = [vtep_1,vtep_2,vtep_3,fanout] 

        mac_start1 = macGenerator()
        mac_start2 = macGenerator() 
        mac_start3 = macGenerator() 
        mac_start4 = macGenerator()                     
    

    @aetest.subsection
    def connect(self, testscript, testbed):
        for uut in uut_list:   
            # log.info('connect to %s' % uut.alias)
            try:
                uut.connect()
   
            except:
                # log.info('connect failed once ; clearing console'))
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
    def cleanup(self, testbed):                 
        pcall(preSetupVxlan, uut=tuple(uut_list))

 
    @aetest.subsection
    def vpcGlobalConf(self, testbed):             
        pcall(addVpcConfig, uut=tuple([vtep_1,vtep_2]),conf_dict=[conf_dict,conf_dict])

 
    @aetest.subsection
    def l2Conf(self, testbed):   
        pcall(configureL2Interface, uut=tuple(l2_device_list),conf_dict=l2_conf_dict)

        cfg = \
            """
            interface {po}
            switchport trunk allowed vlan {vlan}
            """
 

    @aetest.subsection
    def LoopIntfBringup(self, testbed):    
        pcall(configureLoopInterface, uut=tuple(l3_device_list),conf_dict=l3_conf_dict)


    @aetest.subsection
    def l3IntfBringup(self, testbed): 
        pcall(configureL3Interface, uut=tuple(l3_device_list),conf_dict=l3_conf_dict)
 

    @aetest.subsection
    def igpConf(self, testbed):  
        pcall(addOspfConfig, uut=tuple(l3_device_list),conf_dict=l3_conf_dict)


    @aetest.subsection
    def PimConf(self, testbed):  
        pcall(pimConfig, uut=tuple(l3_device_list),conf_dict=l3_conf_dict) 
 

    @aetest.subsection
    def bgpConf(self, testbed):   
        pcall(ibgpConfigure, uut=tuple(l3_device_list),conf_dict=l3_conf_dict) 
 

    @aetest.subsection
    def vxlanConf(self, testbed):   
        pcall(configVxlanLeaf, uut=tuple(vtep_uut_list),conf_dict=(leaf_conf_dict)) 
        pcall(vxlanRouteAdd, uut=tuple(vtep_uut_list),conf_dict=(leaf_conf_dict))   


    @aetest.subsection
    def checkl2l3vxlan(self, testbed): 
        pcall(vxlanRouteAdd, uut=tuple(vtep_uut_list),conf_dict=(leaf_conf_dict))  


#######################################################################
###                  testCASE BLOCK                                 ###
#######################################################################
# Test 1 : Check Tables , Configs
# test 2 : Traffic
# Test 3 : Test SNMP polling 
# Test 4 : Test failover
# Test 5 : Test Reload
# Test 6 : Test Link Flap
# Test 7 : Test Remove add config
# Test 8 : Test config replace
# Verify stats/ Counters in each case


class TC01(aetest.Testcase): 
   # DHCP Server Behind non-vpc vtep and DHCP client behind diff non-vpc vtep (diff vrf)
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(vtep_2,"vtep2")
        relayConf(vtep_3,"vtep3")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetup(port_hdl2,vtep_1)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl3,mac_start3)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl4,mac_start4)

        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):
        cleanupConf(vtep_2,"vtep2")
        cleanupConf(vtep_3,"vtep3")   
        IxiaReset()

 
class TC02(aetest.Testcase): 
   # DHCP Server Behind non-vpc vtep and DHCP client behind diff non-vpc vtep (same vrf)
   
    @aetest.setup
    def setup(self):

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpServerSetup(port_hdl2)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl3,mac_start3)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl4,mac_start4)

        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):   
        IxiaReset()
 

class TC03(aetest.Testcase): 
   # DHCP Server Behind non-vpc vtep and DHCP client behind diff vpc vtep (diff vrf)
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(fanout,"fanout")
        relayConf(vtep_1,"vtep1")
        relayConf(vtep_2,"vtep2")
        confPort(vtep_1,"vtep1")
        confPort(vtep_2,"vtep2")
        confPort(fanout,"fanout")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetup(port_hdl4,vtep_3)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl1,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl2,mac_start2)
        c2_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl3,mac_start3)

        countdown(40)

        dhcpClientTrafficl(topo_handle3,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle3)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl1,port_hdl2,port_hdl3]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self): 
        cleanupConf(fanout,"fanout")
        cleanupConf(vtep_1,"vtep1")
        cleanupConf(vtep_2,"vtep2")  
        IxiaReset()


class TC04(aetest.Testcase): 
   # DHCP Server Behind non-vpc vtep and DHCP client behind diff vpc vtep (same vrf)
   
    @aetest.setup
    def setup(self):

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpServerSetup(port_hdl4)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl1,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl2,mac_start2)
        c2_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl3,mac_start3)

        countdown(40)

        dhcpClientTrafficl(topo_handle3,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle3)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl1,port_hdl2,port_hdl3]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):   
        IxiaReset()


class TC05(aetest.Testcase): 
   # DHCP Server Behind non-vpc vtep and DHCP client behind same vtep (diff Vrf)
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(vtep_1,"vtep1")
        relayConf(vtep_2,"vtep2")
        relayConf(vtep_3,"vtep32")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetup(port_hdl4,vtep_3)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl5,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl2,mac_start2)
        c2_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl3,mac_start3)

        countdown(40)

        dhcpClientTrafficl(topo_handle3,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle3)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl2,port_hdl3,port_hdl5]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(vtep_1,"vtep1")
        cleanupConf(vtep_2,"vtep2")
        cleanupConf(vtep_3,"vtep32")  
        IxiaReset()


class TC06(aetest.Testcase): 
   # DHCP Server Behind non-vpc vtep and DHCP client behind same vtep (same Vrf)
   
    @aetest.setup
    def setup(self):

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpServerSetup(port_hdl4)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl5,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl2,mac_start2)
        c2_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl3,mac_start3)

        countdown(40)

        dhcpClientTrafficl(topo_handle3,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle3)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl2,port_hdl3,port_hdl5]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):   
        IxiaReset()


class TC07_Symmetric(aetest.Testcase): 
   # DHCP Server Behind non-vpc vtepA and DHCP client behind diff non-vpc vtep (diff vrf) 
   # IPv4 for Symmetric and Asymmetric VNIs
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(vtep_2,"vtep2")
        relayConf(vtep_3,"vtep3")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetup(port_hdl2,vtep_1)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl3,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl4,mac_start2)

        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(vtep_2,"vtep2")
        cleanupConf(vtep_3,"vtep3")
        IxiaReset()


class TC07_Asymmetric(aetest.Testcase): 
   # DHCP Server Behind non-vpc vtepA and DHCP client behind diff non-vpc vtep (diff vrf) 
   # IPv4 for Symmetric and Asymmetric VNIs
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConfSymm(vtep_2,"vtep2")
        relayConfSymm(vtep_3,"vtep3")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetupAsymmDiff(port_hdl2,vtep_1)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl3,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl4,mac_start2)

        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(vtep_2,"vtep2")
        cleanupConf(vtep_3,"vtep3")
        IxiaReset()


class TC08_Symmetric(aetest.Testcase): 
   # DHCP Server Behind non-vpc vtepA and DHCP client behind diff vpc vtep (diff vrf) 
   # IPv4 for Symmetric and Asymmetric VNIs
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(fanout,"fanout")
        relayConf(vtep_1,"vtep1")
        relayConf(vtep_2,"vtep2")
        confPort(vtep_1,"vtep1")
        confPort(vtep_2,"vtep2")
        confPort(fanout,"fanout")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetup(port_hdl4,vtep_3)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl1,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl2,mac_start2)
        c2_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl3,mac_start3)

        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl1,port_hdl2,port_hdl3]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(fanout,"fanout")
        cleanupConf(vtep_1,"vtep1")
        cleanupConf(vtep_2,"vtep2")  
        IxiaReset()


class TC08_Asymmetric(aetest.Testcase): 
   # DHCP Server Behind non-vpc vtepA and DHCP client behind diff vpc vtep (diff vrf) 
   # IPv4 for Symmetric and Asymmetric VNIs
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(fanout,"fanout")
        relayConf(vtep_1,"vtep1")
        relayConf(vtep_2,"vtep2")
        confPort(vtep_1,"vtep1")
        confPort(vtep_2,"vtep2")
        confPort(fanout,"fanout")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetupAsymmDiff(port_hdl4,vtep_3)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl1,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl2,mac_start2)
        c2_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl3,mac_start3)

        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl1,port_hdl2,port_hdl3]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(fanout,"fanout")
        cleanupConf(vtep_1,"vtep1")
        cleanupConf(vtep_2,"vtep2") 
        IxiaReset()


class TC10_Symmetric(aetest.Testcase): 
   # DHCP Server Behind non-vpc vtepA  -- DHCP client behind diff vpc vtep (same Vrf) 
   # IPv4 for Symmetric and Asymmetric VNIs 
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(fanout,"fanout")
        relayConf(vtep_1,"vtep1")
        relayConf(vtep_2,"vtep2")
        confPort(vtep_1,"vtep1")
        confPort(vtep_2,"vtep2")
        confPort(fanout,"fanout")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetupSymm(port_hdl4,vtep_3)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl1,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl2,mac_start2)
        c2_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl3,mac_start3)

        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl1,port_hdl2,port_hdl3]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(fanout,"fanout")
        cleanupConf(vtep_1,"vtep1")
        cleanupConf(vtep_2,"vtep2") 
        IxiaReset()


class TC10_Asymmetric(aetest.Testcase): 
   # DHCP Server Behind non-vpc vtepA  -- DHCP client behind diff vpc vtep (same Vrf) 
   # IPv4 for Symmetric and Asymmetric VNIs 
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(fanout,"fanout")
        relayConf(vtep_1,"vtep1")
        relayConf(vtep_2,"vtep2")
        confPort(vtep_1,"vtep1")
        confPort(vtep_2,"vtep2")
        confPort(fanout,"fanout")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetupAsymm(port_hdl4,vtep_3)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl1,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl2,mac_start2)
        c2_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl3,mac_start3)

        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl1,port_hdl2,port_hdl3]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(fanout,"fanout")
        cleanupConf(vtep_1,"vtep1")
        cleanupConf(vtep_2,"vtep2") 
        IxiaReset()


class TC11_Symmetric(aetest.Testcase): 
   # DHCP Server Behind vpc vtep orphan port A  -- DHCP client behind diff non-vpc vtep 
   # IPv4 for Symmetric and Asymmetric VNIs
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConfSymm(vtep_2,"vtep2")
        relayConfSymm(vtep_3,"vtep3")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetupSymm(port_hdl2,vtep_1)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl3,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl4,mac_start2)

        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(vtep_2,"vtep2")
        cleanupConf(vtep_3,"vtep3")
        IxiaReset()


class TC11_Asymmetric(aetest.Testcase): 
   # DHCP Server Behind vpc vtep orphan port A  -- DHCP client behind diff non-vpc vtep 
   # IPv4 for Symmetric and Asymmetric VNIs
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConfSymm(vtep_2,"vtep2")
        relayConfSymm(vtep_3,"vtep3")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetupAsymm(port_hdl2,vtep_1)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl3,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl4,mac_start2)

        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(vtep_2,"vtep2")
        cleanupConf(vtep_3,"vtep3")
        IxiaReset()


class TC12_Symmetric(aetest.Testcase): 
   # DHCP Server Behind vpc vtep orphan port A  -- DHCP client behind diff vpc vtep 
   # IPv4 for Symmetric and Asymmetric VNIs
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(fanout,"fanout")
        relayConf(vtep_2,"vtep2")
        confPort(vtep_1,"vtep1")
        confPort(vtep_2,"vtep2")
        confPort(fanout,"fanout")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetupSymm(port_hdl2,vtep_1)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl1,mac_start1)
        c2_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl3,mac_start3)

        countdown(40)

        dhcpClientTrafficl(topo_handle3,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle3)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl1,port_hdl3]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(fanout,"fanout")
        cleanupConf(vtep_1,"vtep1")
        cleanupConf(vtep_2,"vtep2") 
        IxiaReset()


class TC12_Asymmetric(aetest.Testcase): 
   # DHCP Server Behind vpc vtep orphan port A  -- DHCP client behind diff vpc vtep 
   # IPv4 for Symmetric and Asymmetric VNIs
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(fanout,"fanout")
        relayConf(vtep_2,"vtep2")
        confPort(vtep_1,"vtep1")
        confPort(vtep_2,"vtep2")
        confPort(fanout,"fanout")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetupAsymm(port_hdl2,vtep_1)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl1,mac_start1)
        c2_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl3,mac_start3)

        countdown(40)

        dhcpClientTrafficl(topo_handle3,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle3)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl1,port_hdl3]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(fanout,"fanout")
        cleanupConf(vtep_1,"vtep1")
        cleanupConf(vtep_2,"vtep2") 
        IxiaReset()


class TC13_Symmetric(aetest.Testcase): 
   # DHCP Server Behind vpc vtep orphan port A  -- DHCP client behind same vtep 
   # IPv4 for Symmetric and Asymmetric VNIs
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConfSymm(vtep_1,"vtep1")
        relayConfSymm(vtep_3,"vtep32")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetupSymm(port_hdl3,vtep_3)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl5,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl2,mac_start2)

        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl2,port_hdl5]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(vtep_1,"vtep1")
        cleanupConf(vtep_3,"vtep32")
        IxiaReset()


class TC14(aetest.Testcase): 
    # DHCP Server Behind vpc vtep -- DHCP client behind diff non-vpc vtep (diff vrf)
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(vtep_1,"vtep1")
        relayConf(vtep_2,"vtep2")
        relayConf(vtep_3,"vtep3")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   
        
        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetup(port_hdl1,fanout)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl4,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl2,mac_start2)
        c2_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl3,mac_start3)
 
        countdown(40)

        dhcpClientTrafficl(topo_handle3,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle3)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl2,port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()


    @aetest.test   
    def test3_core(self, testbed): 
        for uut in vtep_uut_list:
            if not checkCore(uut):
                self.failed()


    @aetest.test   
    def test3_traffic(self, testbed): 
        trafficControll('run')
        countdown(30)
       
        trafficStats = getTrafficStats()
        tx = trafficStats['aggregate']['tx']['total_pkt_rate']['sum']
        rx = trafficStats['aggregate']['rx']['total_pkt_rate']['sum']
        if abs(int(tx)-int(rx)) > 200:
            self.failed()
                                            

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(vtep_1,"vtep1")
        cleanupConf(vtep_2,"vtep2")
        cleanupConf(vtep_3,"vtep3")
        IxiaReset()

 
class TC15(aetest.Testcase): 
    # DHCP Server Behind vpc vtep -- DHCP client behind diff non-vpc vtep (same vrf)
   
    @aetest.setup
    def setup(self):

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        
        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpServerSetup(port_hdl1)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl4,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl2,mac_start2)
        c2_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl3,mac_start3)
 
        countdown(40)

        dhcpClientTrafficl(topo_handle3,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle3)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl2,port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()


    @aetest.test   
    def test3_core(self, testbed): 
        for uut in vtep_uut_list:
            if not checkCore(uut):
                self.failed()


    @aetest.test   
    def test3_traffic(self, testbed): 
        trafficControll('run')
        countdown(30)
       
        trafficStats = getTrafficStats()
        tx = trafficStats['aggregate']['tx']['total_pkt_rate']['sum']
        rx = trafficStats['aggregate']['rx']['total_pkt_rate']['sum']
        if abs(int(tx)-int(rx)) > 200:
            self.failed()
                                            

    @aetest.cleanup
    def cleanup(self):   
        IxiaReset()


class TC16(aetest.Testcase): 
    # DHCP Server Behind vpc vtep -- DHCP client behind diff vpc vtep (diff vrf)
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(vtep_1,"vtep1")
        relayConf(vtep_2,"vtep2")
        relayConf(vtep_3,"vtep3")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        
        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetup(port_hdl1,fanout)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl2,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl3,mac_start2)
        c2_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl4,mac_start3)
 
        countdown(40)

        dhcpClientTrafficl(topo_handle3,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle3)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl2,port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()


    @aetest.test   
    def test3_core(self, testbed): 
        for uut in vtep_uut_list:
            if not checkCore(uut):
                self.failed()


    @aetest.test   
    def test3_traffic(self, testbed): 
        trafficControll('run')
        countdown(30)
       
        trafficStats = getTrafficStats()
        tx = trafficStats['aggregate']['tx']['total_pkt_rate']['sum']
        rx = trafficStats['aggregate']['rx']['total_pkt_rate']['sum']
        if abs(int(tx)-int(rx)) > 200:
            self.failed()
                                            

    @aetest.cleanup
    def cleanup(self):
        cleanupConf(vtep_1,"vtep1")
        cleanupConf(vtep_2,"vtep2")
        cleanupConf(vtep_3,"vtep3")   
        IxiaReset()


class TC17(aetest.Testcase): 
    # DHCP Server Behind vpc vtep -- DHCP client behind diff vpc vtep (same vrf)
   
    @aetest.setup
    def setup(self):

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        
        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpServerSetup(port_hdl1)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl2,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl3,mac_start2)
        c2_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl4,mac_start3)
 
        countdown(40)

        dhcpClientTrafficl(topo_handle3,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle3)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl2,port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()


    @aetest.test   
    def test3_core(self, testbed): 
        for uut in vtep_uut_list:
            if not checkCore(uut):
                self.failed()


    @aetest.test   
    def test3_traffic(self, testbed): 
        trafficControll('run')
        countdown(30)
       
        trafficStats = getTrafficStats()
        tx = trafficStats['aggregate']['tx']['total_pkt_rate']['sum']
        rx = trafficStats['aggregate']['rx']['total_pkt_rate']['sum']
        if abs(int(tx)-int(rx)) > 200:
            self.failed()
                                            

    @aetest.cleanup
    def cleanup(self):   
        IxiaReset()


class TC18(aetest.Testcase): 
    # DHCP Server Behind vpc vtep -- DHCP client behind same vtep (diff vrf)
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(vtep_1,"vtep1")
        relayConf(vtep_2,"vtep2")
        relayConf(vtep_3,"vtep3")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        
        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetup(port_hdl1,fanout)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl3,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl2,mac_start2)
        c2_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl4,mac_start3)
 
        countdown(40)

        dhcpClientTrafficl(topo_handle3,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle3)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl2,port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()


    @aetest.test   
    def test3_core(self, testbed): 
        for uut in vtep_uut_list:
            if not checkCore(uut):
                self.failed()


    @aetest.test   
    def test3_traffic(self, testbed): 
        trafficControll('run')
        countdown(30)
       
        trafficStats = getTrafficStats()
        tx = trafficStats['aggregate']['tx']['total_pkt_rate']['sum']
        rx = trafficStats['aggregate']['rx']['total_pkt_rate']['sum']
        if abs(int(tx)-int(rx)) > 200:
            self.failed()
                                            

    @aetest.cleanup
    def cleanup(self):  
        cleanupConf(vtep_1,"vtep1")
        cleanupConf(vtep_2,"vtep2")
        cleanupConf(vtep_3,"vtep3") 
        IxiaReset()


class TC19(aetest.Testcase): 
    # DHCP Server Behind vpc vtep -- DHCP client behind same vtep (same vrf)
   
    @aetest.setup
    def setup(self):

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        
        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpServerSetup(port_hdl1)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl3,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl2,mac_start2)
        c2_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl4,mac_start3)
 
        countdown(40)

        dhcpClientTrafficl(topo_handle3,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle3)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl2,port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()


    @aetest.test   
    def test3_core(self, testbed): 
        for uut in vtep_uut_list:
            if not checkCore(uut):
                self.failed()


    @aetest.test   
    def test3_traffic(self, testbed): 
        trafficControll('run')
        countdown(30)
       
        trafficStats = getTrafficStats()
        tx = trafficStats['aggregate']['tx']['total_pkt_rate']['sum']
        rx = trafficStats['aggregate']['rx']['total_pkt_rate']['sum']
        if abs(int(tx)-int(rx)) > 200:
            self.failed()
                                            

    @aetest.cleanup
    def cleanup(self):   
        IxiaReset()


class TC20_Symmetric(aetest.Testcase): 
    # DHCP Server Behind vpc vtepA -- DHCP client behind diff vpc vtep (diff VRF)
    # IPv4 for Symmetric and Asymmetric VNIs
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(vtep_1,"vtep1")
        relayConf(vtep_2,"vtep2")
        relayConf(vtep_3,"vtep3")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        
        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetup(port_hdl1,fanout)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl2,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl3,mac_start2)
        c3_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl4,mac_start2)
 
        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl2,port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()


    @aetest.test   
    def test3_core(self, testbed): 
        for uut in vtep_uut_list:
            if not checkCore(uut):
                self.failed()


    @aetest.test   
    def test3_traffic(self, testbed): 
        trafficControll('run')
        countdown(30)
       
        trafficStats = getTrafficStats()
        tx = trafficStats['aggregate']['tx']['total_pkt_rate']['sum']
        rx = trafficStats['aggregate']['rx']['total_pkt_rate']['sum']
        if abs(int(tx)-int(rx)) > 200:
            self.failed()
                                            

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(vtep_1,"vtep1")
        cleanupConf(vtep_2,"vtep2")
        cleanupConf(vtep_3,"vtep3")
        IxiaReset()


class TC20_Asymmetric(aetest.Testcase): 
    # DHCP Server Behind vpc vtepA -- DHCP client behind diff vpc vtep (diff VRF)
    # IPv4 for Symmetric and Asymmetric VNIs
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(vtep_1,"vtep1")
        relayConf(vtep_2,"vtep2")
        relayConf(vtep_3,"vtep3")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        
        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetupAsymmDiff(port_hdl1,fanout)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl2,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl3,mac_start2)
        c3_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl4,mac_start2)
 
        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl2,port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()


    @aetest.test   
    def test3_core(self, testbed): 
        for uut in vtep_uut_list:
            if not checkCore(uut):
                self.failed()


    @aetest.test   
    def test3_traffic(self, testbed): 
        trafficControll('run')
        countdown(30)
       
        trafficStats = getTrafficStats()
        tx = trafficStats['aggregate']['tx']['total_pkt_rate']['sum']
        rx = trafficStats['aggregate']['rx']['total_pkt_rate']['sum']
        if abs(int(tx)-int(rx)) > 200:
            self.failed()
                                            

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(vtep_2,"vtep2")
        cleanupConf(vtep_3,"vtep3")
        IxiaReset()


class TC21_Symmetric(aetest.Testcase): 
    # DHCP Server Behind vpc vtepA  -- DHCP client behind diff non-vpc vtep
    # IPv4 for Symmetric and Asymmetric VNIs
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(vtep_1,"vtep1")
        relayConf(vtep_2,"vtep2")
        relayConf(vtep_3,"vtep3")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        
        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetupSymm(port_hdl1,fanout)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl2,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl3,mac_start2)
        c3_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl4,mac_start2)
 
        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl2,port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()


    @aetest.test   
    def test3_core(self, testbed): 
        for uut in vtep_uut_list:
            if not checkCore(uut):
                self.failed()


    @aetest.test   
    def test3_traffic(self, testbed): 
        trafficControll('run')
        countdown(30)
       
        trafficStats = getTrafficStats()
        tx = trafficStats['aggregate']['tx']['total_pkt_rate']['sum']
        rx = trafficStats['aggregate']['rx']['total_pkt_rate']['sum']
        if abs(int(tx)-int(rx)) > 200:
            self.failed()
                                            

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(vtep_1,"vtep1")
        cleanupConf(vtep_2,"vtep2")
        cleanupConf(vtep_3,"vtep3")
        IxiaReset()


class TC21_Asymmetric(aetest.Testcase): 
    # DHCP Server Behind vpc vtepA  -- DHCP client behind diff non-vpc vtep
    # IPv4 for Symmetric and Asymmetric VNIs
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(vtep_1,"vtep1")
        relayConf(vtep_2,"vtep2")
        relayConf(vtep_3,"vtep3")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        
        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetupAsymm(port_hdl1,fanout)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl2,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl3,mac_start2)
        c3_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl4,mac_start2)
 
        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl2,port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()


    @aetest.test   
    def test3_core(self, testbed): 
        for uut in vtep_uut_list:
            if not checkCore(uut):
                self.failed()


    @aetest.test   
    def test3_traffic(self, testbed): 
        trafficControll('run')
        countdown(30)
       
        trafficStats = getTrafficStats()
        tx = trafficStats['aggregate']['tx']['total_pkt_rate']['sum']
        rx = trafficStats['aggregate']['rx']['total_pkt_rate']['sum']
        if abs(int(tx)-int(rx)) > 200:
            self.failed()
                                            

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(vtep_2,"vtep2")
        cleanupConf(vtep_3,"vtep3")
        IxiaReset()


class TC22_Symmetric(aetest.Testcase): 
    # DHCP Server Behind vpc vtepA  -- DHCP client behind diff vpc vtep (same vrf) 
    # IPv4 for Symmetric and Asymmetric VNIs
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(vtep_1,"vtep1")
        relayConf(vtep_2,"vtep2")
        relayConf(vtep_3,"vtep3")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        
        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetupSymm(port_hdl1,fanout)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl2,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl3,mac_start2)
        c3_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl4,mac_start2)
 
        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl2,port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()


    @aetest.test   
    def test3_core(self, testbed): 
        for uut in vtep_uut_list:
            if not checkCore(uut):
                self.failed()


    @aetest.test   
    def test3_traffic(self, testbed): 
        trafficControll('run')
        countdown(30)
       
        trafficStats = getTrafficStats()
        tx = trafficStats['aggregate']['tx']['total_pkt_rate']['sum']
        rx = trafficStats['aggregate']['rx']['total_pkt_rate']['sum']
        if abs(int(tx)-int(rx)) > 200:
            self.failed()
                                            

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(vtep_1,"vtep1")
        cleanupConf(vtep_2,"vtep2")
        cleanupConf(vtep_3,"vtep3")
        IxiaReset()


class TC22_Asymmetric(aetest.Testcase): 
    # DHCP Server Behind vpc vtepA  -- DHCP client behind diff vpc vtep (same vrf)
    # IPv4 for Symmetric and Asymmetric VNIs
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConf(vtep_1,"vtep1")
        relayConf(vtep_2,"vtep2")
        relayConf(vtep_3,"vtep3")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        
        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetupAsymm(port_hdl1,fanout)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl2,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl3,mac_start2)
        c3_top_stat,dhcp_client3,topo_handle3 = dhcpClientSetup(port_hdl4,mac_start2)
 
        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl2,port_hdl3,port_hdl4]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()


    @aetest.test   
    def test3_core(self, testbed): 
        for uut in vtep_uut_list:
            if not checkCore(uut):
                self.failed()


    @aetest.test   
    def test3_traffic(self, testbed): 
        trafficControll('run')
        countdown(30)
       
        trafficStats = getTrafficStats()
        tx = trafficStats['aggregate']['tx']['total_pkt_rate']['sum']
        rx = trafficStats['aggregate']['rx']['total_pkt_rate']['sum']
        if abs(int(tx)-int(rx)) > 200:
            self.failed()
                                            

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(vtep_2,"vtep2")
        cleanupConf(vtep_3,"vtep3")
        IxiaReset()


class TC24_Symmetric(aetest.Testcase): 
   # DHCP Server Behind vpc vtepB  -- DHCP client behind same vtep 
   # IPv4 for Symmetric and Asymmetric VNIs 
   
    @aetest.setup
    def setup(self):

        vpcVtep(vtep_1)
        vpcVtep(vtep_2)
        relayConfSymm(vtep_1,"vtep1")
        relayConfSymm(vtep_3,"vtep32")

        global  port_hdl1,port_hdl2,port_hdl3,port_hdl4,port_hdl5

        port_handle = IxiaConnect(port_list)
        port_hdl1 = port_handle.split(' ')[0]
        port_hdl2 = port_handle.split(' ')[1]
        port_hdl3 = port_handle.split(' ')[2]
        port_hdl4 = port_handle.split(' ')[3]
        port_hdl5 = port_handle.split(' ')[4]   

        dhcp_server,srv_deviceGroup_handle,topo_handle = dhcpRelayServerSetupSymm(port_hdl3,vtep_3)

        c1_top_stat,dhcp_client1,topo_handle1 = dhcpClientSetup(port_hdl5,mac_start1)
        c2_top_stat,dhcp_client2,topo_handle2 = dhcpClientSetup(port_hdl2,mac_start2)

        countdown(40)

        dhcpClientTrafficl(topo_handle2,topo_handle1)
        dhcpClientTrafficl(topo_handle1,topo_handle2)

        countdown(10)  


    @aetest.test   
    def test_binding(self, testbed): 
        for port_handle in [port_hdl2,port_hdl5]:        
            if not checkClientBindingStatsIxia(port_handle):
                self.failed()
               

    @aetest.cleanup
    def cleanup(self):   
        cleanupConf(vtep_1,"vtep1")
        cleanupConf(vtep_3,"vtep32")
        IxiaReset()


class common_cleanup(aetest.CommonCleanup):

    @aetest.subsection
    def stop_tgn_streams(self):
        pass

 
if __name__ == '__main__': # pragma: no cover
    import argparse 
    import json