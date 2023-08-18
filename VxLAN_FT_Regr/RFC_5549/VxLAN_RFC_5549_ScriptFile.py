#!/usr/bin/env python

###################################################################
###                  Importing Libraries                        ###
###################################################################
import logging
import time
import yaml
import json
import re
import os
from time import sleep
from yaml import Loader
from pyats import aetest
from pyats.log.utils import banner

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

#################################################################################
from pyats import tcl
from pyats import aetest
from pyats.log.utils import banner
# from pyats.async import pcall
from pyats.async_ import pcall

from pyats.aereport.exceptions.utils_errors import \
MissingArgError, TypeMismatchError,\
DictInvalidKeyError, DictMissingMandatoryKeyError,\
StrInvalidOptionError, InvalidArgumentError

from ats.topology import loader
from pyats.aereport.utils.argsvalidator import ArgsValidator
ArgVal = ArgsValidator()
import pdb
import os
import re
import logging
import time

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

#################################################################################

import pdb
import sys
import copy

class ForkedPdb(pdb.Pdb):
    """A Pdb subclass that may be used
    from a forked multiprocessing child
    """
    def interaction(self, *args, **kwargs):
        _stdin = sys.stdin
        try:
            sys.stdin = open('/dev/stdin')
            pdb.Pdb.interaction(self, *args, **kwargs)
        finally:
            sys.stdin = _stdin

# Import the RestPy module
from ixnetwork_restpy import *

###################################################################
###                  User Library Methods                       ###
###################################################################

def increment_prefix_network(pref, count):
    size = 1 << (pref.network.max_prefixlen - pref.network.prefixlen)
    pref_lst = []
    for i in range(count):
        pref_lst.append(str((pref.ip+size*i)) + "/" + str(pref.network.prefixlen))
    return pref_lst

def getNvePeerList(allLeaves_data):
    nve_peer_lst = []
    for item in allLeaves_data:
        if 'VPC_VTEP_IP' in item['NVE_data'].keys():
            if item['NVE_data']['VPC_VTEP_IP'] not in nve_peer_lst:
                nve_peer_lst.append(item['NVE_data']['VPC_VTEP_IP'])
        else:
            nve_peer_lst.append(item['NVE_data']['VTEP_IP'])
    return nve_peer_lst

def Peer_State(json_input, peer_ip):
  for i in json_input['TABLE_nve_peers']['ROW_nve_peers']:
    if i['peer-ip'] == peer_ip:
        return i['peer-state']
        break
  return 0

def Mac_Table(json_input, peer_ip):
  for i in json_input['TABLE_mac_address']['ROW_mac_address']:
    if i['disp_port'] == 'nve1('+str(peer_ip)+')':
        return i['disp_mac_addr']
        break
  return 0

def Fib_Table(json_input, loopbck):
  for i in json_input['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']:
    if i['ipprefix'] == loopbck:
        return i['TABLE_path']['ROW_path']['ipnexthop']
        break
  return 0

def Rtr_Mac(json_input, peer_ip):
  for i in json_input['TABLE_l2route_mac_all']['ROW_l2route_mac_all']:
    if i['next-hop1'] == peer_ip:
        return i['mac-addr']
        break
  return 0

def BGP_Route_Type(json_input, loopbck):
  for i in json_input['TABLE_vrf']['ROW_vrf']['TABLE_afi']['ROW_afi']['TABLE_safi']['ROW_safi']['TABLE_rd']['ROW_rd']['TABLE_prefix']['ROW_prefix']:
    if i['nonipprefix'] == loopbck:
        return i['TABLE_path']['ROW_path']['ipnexthop']
        break
  return 0

def strtolist(inputstr,retainint=False):
     inputstr=str(inputstr)
     inputstr=inputstr.strip("[]")
     splitbycomma=inputstr.split(",")
     splitbyspace=inputstr.split()
     if len(splitbycomma) >= 2:
         returnlist=[]
         for elem in splitbycomma:
             elem=elem.strip(" '")
             elem=elem.strip('"')
             if elem.isdigit() and retainint:
                 returnlist.append(int(elem))
             else:
                 returnlist.append(elem)
         return returnlist
     returnlist=[]
     for elem in splitbyspace:
         elem=elem.strip(" '")
         elem=elem.strip('"')
         if elem.isdigit() and retainint:
             returnlist.append(int(elem))
         else:
             returnlist.append(elem)
     return returnlist

###################################################################
###                  GLOBAL VARIABLES                           ###
###################################################################

device_list     = []

###################################################################
###                  COMMON SETUP SECTION                       ###
###################################################################

# Configure and setup all devices and test equipment in this section.
# This should represent the BASE CONFIGURATION that is applicable
# for the bunch of test cases that would follow.


class COMMON_SETUP(aetest.CommonSetup):
    """ Common Setup """

    log.info(banner("Common Setup"))

    @aetest.subsection
    def connecting_to_devices(self, testscript, testbed, uut_list, ixia_cfg):
        """ common setup subsection: Connecting to devices """

        log.info(banner("Connecting to Devices"))

        # =============================================================================================================================#
        # Grab the device object of the uut device with that name
        SPINE = testscript.parameters['SPINE'] = testbed.devices[uut_list['Spine-01']]

        LEAF_1 = testscript.parameters['LEAF-1'] = testbed.devices[uut_list['Sundown-01']]
        LEAF_2 = testscript.parameters['LEAF-2'] = testbed.devices[uut_list['Sundown-02']]
        LEAF_3 = testscript.parameters['LEAF-3'] = testbed.devices[uut_list['Sumpin-01']]

        FAN = testscript.parameters['FAN'] = testbed.devices[uut_list['NepCR-01']]

        IXIA = testscript.parameters['IXIA'] = testbed.devices[uut_list['ixia']]

        testscript.parameters['ixia_chassis_ip'] = str(IXIA.connections.a.ip)
        testscript.parameters['ixia_tcl_server'] = str(IXIA.connections.alt.ip)
        testscript.parameters['ixia_tcl_port'] = str(IXIA.connections.alt.port)
        testscript.parameters['ixia_cfg_file'] = ixia_cfg

        # =============================================================================================================================#
        # Connect to the device
        SPINE.connect()
        LEAF_1.connect()
        LEAF_2.connect()
        LEAF_3.connect()
        FAN.connect()

        device_list.append(SPINE)
        device_list.append(LEAF_1)
        device_list.append(LEAF_2)
        device_list.append(LEAF_3)
        device_list.append(FAN)

        # =============================================================================================================================#
        # Make sure that the connection went fine

        for dut in device_list:
            if not hasattr(dut, 'execute'):
                self.failed()

            if dut.execute != dut.connectionmgr.default.execute:
                self.failed()

    # *****************************************************************************************************************************#

    @aetest.subsection
    def get_interfaces(self, testscript):
        """ common setup subsection: Getting required Connections for Test """

        log.info(banner("Retrieve the interfaces from Yaml file"))

        SPINE = testscript.parameters['SPINE']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN = testscript.parameters['FAN']
        IXIA = testscript.parameters['IXIA']

        # =============================================================================================================================#

        log.info("================================================")
        log.info("All Available Interfaces from the YAML file are:")
        for dut in device_list:
            log.info("\n\n--->" + str(dut) + " Interface list")
            for interface in dut.interfaces.keys():
                log.info(str(dut.interfaces[interface].alias) + " --> " + str(interface))

        # =============================================================================================================================#
        # Fetching the specific interfaces NEW Logic

        for intf in SPINE.interfaces.keys():
            if SPINE.interfaces[intf].alias == 'SPINE_to_LEAF-1':
                testscript.parameters['intf_SPINE_to_LEAF_1'] = intf
            if SPINE.interfaces[intf].alias == 'SPINE_to_LEAF-2':
                testscript.parameters['intf_SPINE_to_LEAF_2'] = intf
            if SPINE.interfaces[intf].alias == 'SPINE_to_LEAF-3':
                testscript.parameters['intf_SPINE_to_LEAF_3'] = intf

        for intf in LEAF_1.interfaces.keys():
            if LEAF_1.interfaces[intf].alias == 'LEAF-1_to_LEAF-2_1':
                testscript.parameters['intf_LEAF_1_to_LEAF_2_1'] = intf
            if LEAF_1.interfaces[intf].alias == 'LEAF-1_to_LEAF-2_2':
                testscript.parameters['intf_LEAF_1_to_LEAF_2_2'] = intf
            if LEAF_1.interfaces[intf].alias == 'LEAF-1_to_SPINE':
                testscript.parameters['intf_LEAF_1_to_SPINE'] = intf
            if LEAF_1.interfaces[intf].alias == 'LEAF-1_to_FAN':
                testscript.parameters['intf_LEAF_1_to_FAN'] = intf

        for intf in LEAF_2.interfaces.keys():
            if LEAF_2.interfaces[intf].alias == 'LEAF-2_to_LEAF-1_1':
                testscript.parameters['intf_LEAF_2_to_LEAF_1_1'] = intf
            if LEAF_2.interfaces[intf].alias == 'LEAF-2_to_LEAF-1_2':
                testscript.parameters['intf_LEAF_2_to_LEAF_1_2'] = intf
            if LEAF_2.interfaces[intf].alias == 'LEAF-2_to_SPINE':
                testscript.parameters['intf_LEAF_2_to_SPINE'] = intf
            if LEAF_2.interfaces[intf].alias == 'LEAF-2_to_FAN':
                testscript.parameters['intf_LEAF_2_to_FAN'] = intf

        for intf in LEAF_3.interfaces.keys():
            if LEAF_3.interfaces[intf].alias == 'LEAF-3_to_SPINE':
                testscript.parameters['intf_LEAF_3_to_SPINE'] = intf
            if LEAF_3.interfaces[intf].alias == 'LEAF-3_to_IXIA':
                testscript.parameters['intf_LEAF_3_to_IXIA'] = intf

        for intf in FAN.interfaces.keys():
            if FAN.interfaces[intf].alias == 'FAN_to_LEAF-1':
                testscript.parameters['intf_FAN_to_LEAF_1'] = intf
            if FAN.interfaces[intf].alias == 'FAN_to_LEAF-2':
                testscript.parameters['intf_FAN_to_LEAF_2'] = intf
            if FAN.interfaces[intf].alias == 'FAN_to_IXIA':
                testscript.parameters['intf_FAN_to_IXIA'] = intf

        for intf in IXIA.interfaces.keys():
            if IXIA.interfaces[intf].alias == 'IXIA_to_FAN':
                testscript.parameters['intf_IXIA_to_FAN'] = intf
            if IXIA.interfaces[intf].alias == 'IXIA_to_LEAF-3':
                testscript.parameters['intf_IXIA_to_LEAF_3'] = intf

        testscript.parameters['ixia_int_list'] = str(testscript.parameters['intf_IXIA_to_FAN']) + " " + str(testscript.parameters['intf_IXIA_to_LEAF_3'])

        # =============================================================================================================================#

        log.info("\n\n================================================")
        log.info("Topology Specific Interfaces \n\n")
        for key in testscript.parameters.keys():
            if "intf_" in key:
                log.info("%-25s   ---> %-15s" % (key, testscript.parameters[key]))
        log.info("\n\n")

    # *****************************************************************************************************************************#

    @aetest.subsection
    def topology_used_for_suite(self):
        """ common setup subsection: Represent Topology """

        log.info(banner("Topology to be used"))

        # Set topology to be used
        topology = """
        
                                            +-------------+
                                            |    SPINE    |
                                            +-------------+
                                           /       |       \\
                                          /        |        \\
                                         /         |         \\
                                        /          |          \\
                                       /           |           \\
                                      /            |            \\
                              +-----------+    +-----------+    +-----------+
                              |   LEAF-1  |====|   LEAF-2  |    |   LEAF-3  |
                              +-----------+    +-----------+    +-----------+
                                   \\             /                 |
                                    \\           /                  |
                                     \\         /                   |
                                      \\       /                    |
                                    +-----------+             +-----------+
                                    |   FAN     |             |   IXIA    |
                                    +-----------+             +-----------+     
                                         |
                                         |
                                    +-----------+
                                    |   IXIA    |
                                    +-----------+

        """

        log.info("Topology to be used is")
        log.info(topology)

# *****************************************************************************************************************************#

class DEVICE_BRINGUP(aetest.Testcase):
    """Device Bring-up Test-Case"""

    log.info(banner("Device Bring UP"))

    @aetest.test
    def configure_SPINE(self, testscript):
        """ Device Bring-up subsection: Configuring SPINE """

        try:
            testscript.parameters['SPINE'].configure('''

                nv overlay evpn
                feature bgp
                feature pim

                ip pim rp-address 100.1.1.1

                route-map ALL permit 10
                route-map NH-UNCHANGED permit 10
                  set ip next-hop unchanged

                interface {0}
                  ip forward
                  ipv6 address use-link-local-only
                  ipv6 nd ra-interval 4 min 3
                  ipv6 nd ra-lifetime 10
                  ip pim sparse-mode
                  no shutdown

                interface {1}
                  ip forward
                  ipv6 address use-link-local-only
                  ipv6 nd ra-interval 4 min 3
                  ipv6 nd ra-lifetime 10
                  ip pim sparse-mode
                  no shutdown

                interface {2}
                  ip forward
                  ipv6 address use-link-local-only
                  ipv6 nd ra-interval 4 min 3
                  ipv6 nd ra-lifetime 10
                  ip pim sparse-mode
                  no shutdown

                interface loopback0
                  ip address 192.168.10.4/32
                  ip pim sparse-mode

                interface loopback1
                  ip address 100.1.1.1/32
                  ip pim sparse-mode

                router bgp 65001
                  address-family ipv4 unicast
                    redistribute direct route-map ALL
                  address-family ipv6 unicast
                    redistribute direct route-map ALL
                  address-family l2vpn evpn
                    nexthop route-map NH-UNCHANGED
                    retain route-target all
                  template peer OVERLAY-SPINE
                    remote-as external
                    update-source loopback0
                    ebgp-multihop 5
                    address-family l2vpn evpn
                    allowas-in 3
                    disable-peer-as-check
                    send-community
                    send-community extended
                    route-map NH-UNCHANGED out
                  template peer UNDERLAY-SPINE
                    remote-as external
                    address-family ipv4 unicast
                    allowas-in 1
                    disable-peer-as-check
                    address-family ipv6 unicast
                    allowas-in 1
                    disable-peer-as-check
                  neighbor 192.168.10.1
                    inherit peer OVERLAY-SPINE
                  neighbor 192.168.10.2
                    inherit peer OVERLAY-SPINE
                  neighbor 192.168.10.3
                    inherit peer OVERLAY-SPINE
                  neighbor {0}
                    inherit peer UNDERLAY-SPINE
                  neighbor {1}
                    inherit peer UNDERLAY-SPINE
                  neighbor {2}
                    inherit peer UNDERLAY-SPINE

            '''.format(testscript.parameters['intf_SPINE_to_LEAF_1'],
                        testscript.parameters['intf_SPINE_to_LEAF_2'],
                        testscript.parameters['intf_SPINE_to_LEAF_3']))
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.failed('Exception occurred while configuring on SPINE', goto=['common_cleanup'])

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_LEAF_1_2(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        try:
            testscript.parameters['LEAF-1'].configure('''

                nv overlay evpn
                feature bgp
                feature pim
                feature fabric forwarding
                feature interface-vlan
                feature vn-segment-vlan-based
                feature vpc
                feature nv overlay

                fabric forwarding anycast-gateway-mac 0001.0001.0001
                ip pim rp-address 100.1.1.1

                vlan 10,20,30
                vlan 10
                  vn-segment 10010
                vlan 20
                  vn-segment 10020
                vlan 30
                  vn-segment 10030

                route-map ALL permit 10
                route-map NH-UNCHANGED permit 10
                  set ip next-hop unchanged

                vrf context peer-keep-alive

                vrf context EVPN-VRF-1
                  vni 10030
                  ip pim ssm range 232.0.0.0/8
                  rd auto
                  address-family ipv4 unicast
                    route-target both auto
                    route-target both auto evpn
                  address-family ipv6 unicast
                    route-target both auto
                    route-target both auto evpn

                vpc domain 10
                  peer-switch
                  peer-keepalive destination 5.5.5.2 source 5.5.5.1 vrf peer-keep-alive

                interface Vlan10
                  no shutdown
                  vrf member EVPN-VRF-1
                  no ip redirects
                  ip address 10.1.1.1/24
                  ipv6 address 2001:10:1:1::1/64
                  no ipv6 redirects
                  fabric forwarding mode anycast-gateway

                interface Vlan20
                  no shutdown
                  vrf member EVPN-VRF-1
                  no ip redirects
                  ip address 20.1.1.1/24
                  ipv6 address 2001:20:1:1::1/64
                  no ipv6 redirects
                  fabric forwarding mode anycast-gateway

                interface Vlan30
                  no shutdown
                  vrf member EVPN-VRF-1
                  no ip redirects
                  ip forward
                  ipv6 forward
                  no ipv6 redirects
                  ip pim sparse-mode

                interface nve1
                  no shutdown
                  host-reachability protocol bgp
                  advertise virtual-rmac
                  source-interface loopback1
                  member vni 10010
                    suppress-arp
                    ingress-replication protocol bgp
                  member vni 10020
                    suppress-arp
                    ingress-replication protocol bgp
                  member vni 10030 associate-vrf

                interface {0}
                  ip forward
                  ipv6 address use-link-local-only
                  ipv6 nd ra-interval 4 min 3
                  ipv6 nd ra-lifetime 10
                  ip pim sparse-mode
                  no shutdown

                interface {1}
                  channel-group 10 force
                  no shutdown

                interface {2}
                  vrf member peer-keep-alive
                  ip address 5.5.5.1/24
                  no shutdown

                interface {3}
                  channel-group 20 force
                  no shutdown

                interface port-channel10
                  switchport
                  switchport mode trunk
                  spanning-tree port type network
                  vpc peer-link

                interface port-channel20
                  switchport
                  switchport mode trunk
                  vpc 20

                interface loopback0
                  ip address 192.168.10.1/32
                  ip pim sparse-mode

                interface loopback1
                  ip address 1.1.1.1/32
                  ip address 12.12.12.12/32 secondary
                  ip pim sparse-mode

                router bgp 65000
                  address-family ipv4 unicast
                    redistribute direct route-map ALL
                  address-family ipv6 unicast
                    redistribute direct route-map ALL
                  address-family l2vpn evpn
                    nexthop route-map NH-UNCHANGED
                    retain route-target all
                    advertise-pip
                  template peer OVERLAY-SPINE
                    remote-as external
                    update-source loopback0
                    ebgp-multihop 5
                    address-family l2vpn evpn
                      allowas-in 3
                      disable-peer-as-check
                      send-community
                      send-community extended
                      route-map NH-UNCHANGED out
                  template peer UNDERLAY-SPINE
                    remote-as external
                    address-family ipv4 unicast
                      allowas-in 1
                      disable-peer-as-check
                    address-family ipv6 unicast
                      allowas-in 1
                      disable-peer-as-check
                  neighbor 192.168.10.4
                    inherit peer OVERLAY-SPINE
                  neighbor {0}
                    inherit peer UNDERLAY-SPINE
                  vrf EVPN-VRF-1
                    address-family ipv4 unicast
                      advertise l2vpn evpn
                      redistribute direct route-map ALL
                    address-family ipv6 unicast
                      advertise l2vpn evpn
                      redistribute direct route-map ALL
                  evpn
                  vni 10010 l2
                    rd auto
                    route-target import auto
                    route-target export auto
                  vni 10020 l2
                    rd auto
                    route-target import auto
                    route-target export auto

          '''.format(testscript.parameters['intf_LEAF_1_to_SPINE'],
                    testscript.parameters['intf_LEAF_1_to_LEAF_2_1'],
                    testscript.parameters['intf_LEAF_1_to_LEAF_2_2'],
                    testscript.parameters['intf_LEAF_1_to_FAN']))
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-1', goto=['common_cleanup'])

        try:
            testscript.parameters['LEAF-2'].configure('''

                nv overlay evpn
                feature bgp
                feature pim
                feature fabric forwarding
                feature interface-vlan
                feature vn-segment-vlan-based
                feature vpc
                feature nv overlay

                fabric forwarding anycast-gateway-mac 0001.0001.0001
                ip pim rp-address 100.1.1.1

                vlan 10,20,30
                vlan 10
                  vn-segment 10010
                vlan 20
                  vn-segment 10020
                vlan 30
                  vn-segment 10030

                route-map ALL permit 10
                route-map NH-UNCHANGED permit 10
                  set ip next-hop unchanged

                vrf context peer-keep-alive

                vrf context EVPN-VRF-1
                  vni 10030
                  ip pim ssm range 232.0.0.0/8
                  rd auto
                  address-family ipv4 unicast
                    route-target both auto
                    route-target both auto evpn
                  address-family ipv6 unicast
                    route-target both auto
                    route-target both auto evpn

                vpc domain 10
                  peer-switch
                  peer-keepalive destination 5.5.5.1 source 5.5.5.2 vrf peer-keep-alive

                interface Vlan10
                  no shutdown
                  vrf member EVPN-VRF-1
                  no ip redirects
                  ip address 10.1.1.1/24
                  ipv6 address 2001:10:1:1::1/64
                  no ipv6 redirects
                  fabric forwarding mode anycast-gateway

                interface Vlan20
                  no shutdown
                  vrf member EVPN-VRF-1
                  no ip redirects
                  ip address 20.1.1.1/24
                  ipv6 address 2001:20:1:1::1/64
                  no ipv6 redirects
                  fabric forwarding mode anycast-gateway

                interface Vlan30
                  no shutdown
                  vrf member EVPN-VRF-1
                  no ip redirects
                  ip forward
                  ipv6 forward
                  no ipv6 redirects
                  ip pim sparse-mode

                interface nve1
                  no shutdown
                  host-reachability protocol bgp
                  advertise virtual-rmac
                  source-interface loopback1
                  member vni 10010
                    suppress-arp
                    ingress-replication protocol bgp
                  member vni 10020
                    suppress-arp
                    ingress-replication protocol bgp
                  member vni 10030 associate-vrf

                interface {0}
                  ip forward
                  ipv6 address use-link-local-only
                  ipv6 nd ra-interval 4 min 3
                  ipv6 nd ra-lifetime 10
                  ip pim sparse-mode
                  no shutdown

                interface {1}
                  channel-group 10 force
                  no shutdown

                interface {2}
                  vrf member peer-keep-alive
                  ip address 5.5.5.2/24
                  no shutdown

                interface {3}
                  channel-group 20 force
                  no shutdown

                interface port-channel10
                  switchport
                  switchport mode trunk
                  spanning-tree port type network
                  vpc peer-link

                interface port-channel20
                  switchport
                  switchport mode trunk
                  vpc 20

                interface loopback0
                  ip address 192.168.10.2/32
                  ip pim sparse-mode

                interface loopback1
                  ip address 2.2.2.2/32
                  ip address 12.12.12.12/32 secondary
                  ip pim sparse-mode

                router bgp 65000
                  address-family ipv4 unicast
                    redistribute direct route-map ALL
                 address-family ipv6 unicast
                    redistribute direct route-map ALL
                  address-family l2vpn evpn
                    nexthop route-map NH-UNCHANGED
                    retain route-target all
                    advertise-pip
                  template peer OVERLAY-SPINE
                    remote-as external
                    update-source loopback0
                    ebgp-multihop 5
                    address-family l2vpn evpn
                      allowas-in 3
                      disable-peer-as-check
                      send-community
                      send-community extended
                      route-map NH-UNCHANGED out
                  template peer UNDERLAY-SPINE
                    remote-as external
                    address-family ipv4 unicast
                      allowas-in 1
                      disable-peer-as-check
                    address-family ipv6 unicast
                      allowas-in 1
                      disable-peer-as-check
                  neighbor 192.168.10.4
                    inherit peer OVERLAY-SPINE
                  neighbor {0}
                    inherit peer UNDERLAY-SPINE
                  vrf EVPN-VRF-1
                    address-family ipv4 unicast
                      advertise l2vpn evpn
                      redistribute direct route-map ALL
                    address-family ipv6 unicast
                      advertise l2vpn evpn
                      redistribute direct route-map ALL
                  evpn
                  vni 10010 l2
                    rd auto
                    route-target import auto
                    route-target export auto
                  vni 10020 l2
                    rd auto
                    route-target import auto
                    route-target export auto

          '''.format(testscript.parameters['intf_LEAF_2_to_SPINE'],
                    testscript.parameters['intf_LEAF_2_to_LEAF_1_1'],
                    testscript.parameters['intf_LEAF_2_to_LEAF_1_2'],
                    testscript.parameters['intf_LEAF_2_to_FAN']))
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-2', goto=['common_cleanup'])

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_LEAF_3(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-3 """

        try:
            testscript.parameters['LEAF-3'].configure('''
              
                nv overlay evpn
                feature bgp
                feature pim
                feature fabric forwarding
                feature interface-vlan
                feature vn-segment-vlan-based
                feature nv overlay

                fabric forwarding anycast-gateway-mac 0001.0001.0001
                ip pim rp-address 100.1.1.1

                vlan 10,20,30
                vlan 10
                  vn-segment 10010
                vlan 20
                  vn-segment 10020
                vlan 30
                  vn-segment 10030

                route-map ALL permit 10
                route-map NH-UNCHANGED permit 10
                  set ip next-hop unchanged

                vrf context EVPN-VRF-1
                  vni 10030
                  ip pim ssm range 232.0.0.0/8
                  rd auto
                  address-family ipv4 unicast
                    route-target both auto
                    route-target both auto evpn
                  address-family ipv6 unicast
                    route-target both auto
                    route-target both auto evpn

                interface Vlan10
                  no shutdown
                  vrf member EVPN-VRF-1
                  no ip redirects
                  ip address 10.1.1.1/24
                  ipv6 address 2001:10:1:1::1/64
                  no ipv6 redirects
                  fabric forwarding mode anycast-gateway

                interface Vlan20
                  no shutdown
                  vrf member EVPN-VRF-1
                  no ip redirects
                  ip address 20.1.1.1/24
                  ipv6 address 2001:20:1:1::1/64
                  no ipv6 redirects
                  fabric forwarding mode anycast-gateway

                interface Vlan30
                  no shutdown
                  vrf member EVPN-VRF-1
                  no ip redirects
                  ip forward
                  ipv6 forward
                  no ipv6 redirects
                  ip pim sparse-mode

                interface nve1
                  no shutdown
                  host-reachability protocol bgp
                  source-interface loopback1
                  member vni 10010
                    suppress-arp
                    ingress-replication protocol bgp
                  member vni 10020
                    suppress-arp
                    ingress-replication protocol bgp
                  member vni 10030 associate-vrf

                interface {0}
                  ip forward
                  ipv6 address use-link-local-only
                  ipv6 nd ra-interval 4 min 3
                  ipv6 nd ra-lifetime 10
                  ip pim sparse-mode
                  no shutdown

                interface {1}
                  switchport
                  switchport mode trunk
                  spanning-tree port type edge trunk
                  no shutdown

                interface loopback0
                  ip address 192.168.10.3/32
                  ip pim sparse-mode

                interface loopback1
                  ip address 3.3.3.3/32
                  ip pim sparse-mode

                router bgp 65000
                  address-family ipv4 unicast
                    redistribute direct route-map ALL
                  address-family ipv6 unicast
                    redistribute direct route-map ALL
                  address-family l2vpn evpn
                    nexthop route-map NH-UNCHANGED
                    retain route-target all
                  template peer OVERLAY-SPINE
                    remote-as external
                    update-source loopback0
                    ebgp-multihop 5
                    address-family l2vpn evpn
                      allowas-in 3
                      disable-peer-as-check
                      send-community
                      send-community extended
                      route-map NH-UNCHANGED out
                  template peer UNDERLAY-SPINE
                    remote-as external
                    address-family ipv4 unicast
                      allowas-in 1
                      disable-peer-as-check
                    address-family ipv6 unicast
                      allowas-in 1
                      disable-peer-as-check
                  neighbor 192.168.10.4
                    inherit peer OVERLAY-SPINE
                  neighbor {0}
                    inherit peer UNDERLAY-SPINE
                  vrf EVPN-VRF-1
                    address-family ipv4 unicast
                      advertise l2vpn evpn
                      redistribute direct route-map ALL
                    address-family ipv6 unicast
                      advertise l2vpn evpn
                      redistribute direct route-map ALL
                  evpn
                  vni 10010 l2
                    rd auto
                    route-target import auto
                    route-target export auto
                  vni 10020 l2
                    rd auto
                    route-target import auto
                    route-target export auto

          '''.format(testscript.parameters['intf_LEAF_3_to_SPINE'],
                    testscript.parameters['intf_LEAF_3_to_IXIA']))

        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-3', goto=['common_cleanup'])

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_FAN(self, testscript):
        """ Device Bring-up subsection: Configuring FAN """

        try:
            testscript.parameters['FAN'].configure('''

                vlan 10,20,30

                interface {0}
                  channel-group 1 force

                interface {1}
                  channel-group 1 force

                interface {2}
                  switchport mode trunk

                interface port-channel1
                  switchport mode trunk

                            '''.format(testscript.parameters['intf_FAN_to_LEAF_1'],
                                       testscript.parameters['intf_FAN_to_LEAF_2'],
                                       testscript.parameters['intf_FAN_to_IXIA']))
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on FAN', goto=['common_cleanup'])

    # *****************************************************************************************************************************#

    @aetest.test
    def perform_copy_r_s(self, testscript):
        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Save all configurations (copy r s) """

        log.info(banner("Performing Copy R S"))

        testscript.parameters['LEAF-1'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-3'].configure("copy r s", timeout=300)

        time.sleep(100)

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    # =============================================================================================================================#
    @aetest.test
    def CONNECT_IXIA_CHASSIS(self, testscript):
        """ IXIA_CONFIGURATION subsection: Connect to IXIA """
        
        # Get IXIA paraameters, Connect and confiure TG
        ixChassisIpList = strtolist(testscript.parameters['ixia_chassis_ip'])
        apiServerIp = testscript.parameters['ixia_tcl_server']
        ixia_lc_port_0 = testscript.parameters['intf_IXIA_to_FAN'].split('/')
        ixia_lc_port_1 = testscript.parameters['intf_IXIA_to_LEAF_3'].split('/')
        portList = [[ixChassisIpList[0], ixia_lc_port_0[0], ixia_lc_port_0[1]], [ixChassisIpList[0], ixia_lc_port_1[0], ixia_lc_port_1[1]]]
        configFile = testscript.parameters['ixia_cfg_file']

        # Forcefully take port ownership if the portList are owned by other users.
        forceTakePortOwnership = True

        # LogLevel: none, info, warning, request, request_response, all
        testscript.parameters['session'] = session = SessionAssistant(IpAddress=apiServerIp, RestPort=None, UserName='admin', Password='admin', 
                            SessionName=None, SessionId=None, ApiKey=None,
                            ClearConfig=True, LogLevel='all', LogFilename='restpy.log')

        testscript.parameters['ixNetwork'] = ixNetwork = session.Ixnetwork

        #######Load a saved config file
        ixNetwork.info('Loading config file: {0}'.format(configFile))
        ixNetwork.LoadConfig(Files(configFile, local_file=True))

        # Assign ports. Map physical ports to the configured vports.
        portMap = session.PortMapAssistant()
        vport = dict()
        for index,port in enumerate(portList):
            # For the port name, get the loaded configuration's port name
            portName = ixNetwork.Vport.find()[index].Name
            portMap.Map(IpAddress=port[0], CardId=port[1], PortId=port[2], Name=portName)

        portMap.Connect(forceTakePortOwnership)

# *****************************************************************************************************************************#

class TC000_Verify_Steady_State(aetest.Testcase):
    """ TC000_Verify_Steady_State """

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        # Show Version on ALL NODES
        testscript.parameters['SPINE'].execute('''show version''')
        testscript.parameters['LEAF-1'].execute('''show version''')
        testscript.parameters['LEAF-2'].execute('''show version''')
        testscript.parameters['LEAF-3'].execute('''show version''')

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC001_SA_UP_Link_Flap(aetest.Testcase):
    """ TC001_SA_UP_Link_Flap """

    @aetest.test
    def SA_UP_Link_Flap(self, testscript):
        """ SA_UP_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''
    
                  interface {0}
                  shutdown
    
              '''.format(testscript.parameters['intf_LEAF_3_to_SPINE']))

        time.sleep(30)

        testscript.parameters['LEAF-3'].configure('''
    
                  interface {0}
                  no shutdown
    
              '''.format(testscript.parameters['intf_LEAF_3_to_SPINE']))

        time.sleep(90)

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC002_vPC_UP_Link_Flap(aetest.Testcase):
    """ TC002_vPC_UP_Link_Flap """

    @aetest.test
    def vPC_UP_Link_Flap(self, testscript):
        """ vPC_UP_Link_Flap """

        testscript.parameters['LEAF-1'].configure('''
    
                  interface {0}
                  shutdown
    
              '''.format(testscript.parameters['intf_LEAF_1_to_SPINE']))

        testscript.parameters['LEAF-2'].configure('''
    
                  interface {0}
                  shutdown
    
              '''.format(testscript.parameters['intf_LEAF_2_to_SPINE']))

        time.sleep(30)

        testscript.parameters['LEAF-1'].configure('''
    
                  interface {0}
                  no shutdown
    
              '''.format(testscript.parameters['intf_LEAF_1_to_SPINE']))

        testscript.parameters['LEAF-2'].configure('''
    
                  interface {0}
                  no shutdown
    
              '''.format(testscript.parameters['intf_LEAF_2_to_SPINE']))

        time.sleep(90)

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC003_SA_Access_Link_Flap(aetest.Testcase):
    """ TC003_SA_Access_Link_Flap """

    @aetest.test
    def SA_Access_Link_Flap(self, testscript):
        """ SA_Access_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''
    
                  interface {0}
                  shutdown
    
              '''.format(testscript.parameters['intf_LEAF_3_to_IXIA']))

        time.sleep(30)

        testscript.parameters['LEAF-3'].configure('''
    
                  interface {0}
                  no shutdown
    
              '''.format(testscript.parameters['intf_LEAF_3_to_IXIA']))

        time.sleep(30)

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC004_vPC_Access_Link_Flap(aetest.Testcase):
    """ TC004_vPC_Access_Link_Flap """

    @aetest.test
    def vPC_Access_Link_Flap(self, testscript):
        """ vPC_Access_Link_Flap """

        testscript.parameters['LEAF-1'].configure('''
    
                  interface {0}
                  shutdown
    
              '''.format(testscript.parameters['intf_LEAF_1_to_FAN']))

        testscript.parameters['LEAF-2'].configure('''
    
                  interface {0}
                  shutdown
    
              '''.format(testscript.parameters['intf_LEAF_2_to_FAN']))

        time.sleep(30)

        testscript.parameters['LEAF-1'].configure('''
    
                  interface {0}
                  no shutdown
    
              '''.format(testscript.parameters['intf_LEAF_1_to_FAN']))

        testscript.parameters['LEAF-2'].configure('''
    
                  interface {0}
                  no shutdown
    
              '''.format(testscript.parameters['intf_LEAF_2_to_FAN']))

        time.sleep(30)

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC005_SA_NVE_Flap(aetest.Testcase):
    """ TC005_SA_NVE_Flap """

    @aetest.test
    def SA_NVE_Flap(self, testscript):
        """ SA_NVE_Flap """

        testscript.parameters['LEAF-3'].configure('''
    
                  interface nve 1
                  shutdown
    
              ''')

        time.sleep(30)

        testscript.parameters['LEAF-3'].configure('''
    
                  interface nve 1
                  no shutdown
    
              ''')

        time.sleep(30)

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC006_vPC_NVE_Flap(aetest.Testcase):
    """ TC006_vPC_NVE_Flap """

    @aetest.test
    def vPC_NVE_Flap(self, testscript):
        """ vPC_NVE_Flap """

        testscript.parameters['LEAF-1'].configure('''
    
                  interface nve 1
                  shutdown
    
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
                  interface nve 1
                  shutdown
    
              ''')

        time.sleep(30)

        testscript.parameters['LEAF-1'].configure('''
    
                  interface nve 1
                  no shutdown
    
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
                  interface nve 1
                  no shutdown
    
              ''')

        time.sleep(30)

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC007_SA_Remove_Add_VN_Segment(aetest.Testcase):
    """ TC007_SA_Remove_Add_VN_Segment """

    @aetest.test
    def SA_Remove_Add_VN_Segment(self, testscript):
        """ SA_Remove_Add_VN_Segment """

        testscript.parameters['LEAF-3'].configure('''
    
                  vlan 10
                    no vn-segment 10010
                  vlan 20
                    no vn-segment 10020
    
              ''')

        time.sleep(30)

        testscript.parameters['LEAF-3'].configure('''
    
                  vlan 10
                    vn-segment 10010
                  vlan 20
                    vn-segment 10020
    
              ''')

        time.sleep(30)

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC008_vPC_Remove_Add_VN_Segment(aetest.Testcase):
    """ TC008_vPC_Remove_Add_VN_Segment """

    @aetest.test
    def vPC_Remove_Add_VN_Segment(self, testscript):
        """ vPC_Remove_Add_VN_Segment """

        testscript.parameters['LEAF-1'].configure('''
    
                  vlan 10
                    no vn-segment 10010
                  vlan 20
                    no vn-segment 10020
    
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
                  vlan 10
                    no vn-segment 10010
                  vlan 20
                    no vn-segment 10020
    
              ''')

        time.sleep(30)

        testscript.parameters['LEAF-1'].configure('''
    
                  vlan 10
                    vn-segment 10010
                  vlan 20
                    vn-segment 10020
    
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
                  vlan 10
                    vn-segment 10010
                  vlan 20
                    vn-segment 10020
    
              ''')

        time.sleep(30)

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC009_SA_Loopback_Flap(aetest.Testcase):
    """ TC009_SA_Loopback_Flap """

    @aetest.test
    def SA_Loopback_Flap(self, testscript):
        """ SA_Loopback_Flap """

        testscript.parameters['LEAF-3'].configure('''
    
                  interface loopback0
                    shutdown

                  interface loopback1
                    shutdown
    
              ''')

        time.sleep(30)

        testscript.parameters['LEAF-3'].configure('''
    
                  interface loopback0
                    no shutdown

                  interface loopback1
                    no shutdown
    
              ''')

        time.sleep(30)

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC010_vPC_Loopback_Flap(aetest.Testcase):
    """ TC010_vPC_Loopback_Flap """

    @aetest.test
    def vPC_Loopback_Flap(self, testscript):
        """ vPC_Loopback_Flap """

        testscript.parameters['LEAF-1'].configure('''
    
                  interface loopback0
                    shutdown

                  interface loopback1
                    shutdown
    
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
                  interface loopback0
                    shutdown

                  interface loopback1
                    shutdown
    
              ''')

        time.sleep(30)

        testscript.parameters['LEAF-1'].configure('''
    
                  interface loopback0
                    no shutdown

                  interface loopback1
                    no shutdown
    
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
                  interface loopback0
                    no shutdown

                  interface loopback1
                    no shutdown
    
              ''')

        time.sleep(30)

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC011_SA_Remove_Add_VLAN(aetest.Testcase):
    """ TC011_SA_Remove_Add_VLAN """

    @aetest.test
    def SA_Remove_Add_VLAN(self, testscript):
        """ SA_Remove_Add_VLAN """

        testscript.parameters['LEAF-3'].configure('''
    
                no vlan 10
                no vlan 20
                no vlan 30
    
              ''')

        time.sleep(30)

        testscript.parameters['LEAF-3'].configure('''
    
                vlan 10
                  vn-segment 10010
                vlan 20
                  vn-segment 10020
                vlan 30
                  vn-segment 10030

              ''')

        time.sleep(30)

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC012_vPC_Remove_Add_VLAN(aetest.Testcase):
    """ TC012_vPC_Remove_Add_VLAN """

    @aetest.test
    def vPC_Remove_Add_VLAN(self, testscript):
        """ vPC_Remove_Add_VLAN """

        testscript.parameters['LEAF-1'].configure('''
    
              no vlan 10
              no vlan 20
              no vlan 30

    
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
              no vlan 10
              no vlan 20
              no vlan 30

              ''')

        time.sleep(30)

        testscript.parameters['LEAF-1'].configure('''
    
                vlan 10
                  vn-segment 10010
                vlan 20
                  vn-segment 10020
                vlan 30
                  vn-segment 10030
    
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
                vlan 10
                  vn-segment 10010
                vlan 20
                  vn-segment 10020
                vlan 30
                  vn-segment 10030
    
              ''')

        time.sleep(30)

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC013_Remove_Add_NVE_Configs(aetest.Testcase):
    """ TC013_Remove_Add_NVE_Configs """

    @aetest.test
    def Remove_Add_NVE_Configs(self, testscript):
        """ Remove_Add_NVE_Configs """

        testscript.parameters['LEAF-1'].configure('''
    
                  delete bootflash:temp_nve_configs.txt no-prompt
                  
                  show running-config interface nve 1 > bootflash:temp_nve_configs.txt
                  
                  no interface nve 1
                      
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
                  delete bootflash:temp_nve_configs.txt no-prompt
                  
                  show running-config interface nve 1 > bootflash:temp_nve_configs.txt
                  
                  no interface nve 1

              ''')

        testscript.parameters['LEAF-3'].configure('''
    
                  delete bootflash:temp_nve_configs.txt no-prompt
                  
                  show running-config interface nve 1 > bootflash:temp_nve_configs.txt
                  
                  no interface nve 1

              ''')

        time.sleep(30)

        testscript.parameters['LEAF-1'].configure('''
            
          copy bootflash:temp_nve_configs.txt running-config echo-commands
    
              ''', timeout=300)

        testscript.parameters['LEAF-2'].configure('''
            
          copy bootflash:temp_nve_configs.txt running-config echo-commands
    
              ''', timeout=300)
        
        testscript.parameters['LEAF-3'].configure('''
            
          copy bootflash:temp_nve_configs.txt running-config echo-commands
    
              ''', timeout=300)

        time.sleep(60)

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC014_Remove_Add_BGP_Configs(aetest.Testcase):
    """ TC014_Remove_Add_BGP_Configs """

    @aetest.test
    def Remove_Add_BGP_Configs(self, testscript):
        """ Remove_Add_BGP_Configs """

        testscript.parameters['LEAF-1'].configure('''
    
                  delete bootflash:temp_bgp_configs.txt no-prompt
                  
                  show running-config bgp > bootflash:temp_bgp_configs.txt
                  
                  no feature bgp
    
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
                  delete bootflash:temp_bgp_configs.txt no-prompt
                  
                  show running-config bgp > bootflash:temp_bgp_configs.txt
                  
                  no feature bgp
    
              ''')

        testscript.parameters['LEAF-3'].configure('''
    
                  delete bootflash:temp_bgp_configs.txt no-prompt
                  
                  show running-config bgp > bootflash:temp_bgp_configs.txt
                  
                  no feature bgp
    
              ''')

        time.sleep(30)

        testscript.parameters['LEAF-1'].configure('''
            
          copy bootflash:temp_bgp_configs.txt running-config echo-commands
    
              ''', timeout=300)

        testscript.parameters['LEAF-2'].configure('''
            
          copy bootflash:temp_bgp_configs.txt running-config echo-commands
    
              ''', timeout=300)

        testscript.parameters['LEAF-3'].configure('''
            
          copy bootflash:temp_bgp_configs.txt running-config echo-commands
    
              ''', timeout=300)

        time.sleep(60)

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC015_VxLAN_CC(aetest.Testcase):
    """ TC015_VxLAN_CC """

    @aetest.test
    def VxLAN_CC(self, testscript):
        """ VxLAN_CC """

        VxLANCC = json.loads(testscript.parameters['LEAF-1'].execute('show consistency-checker vxlan config-check brief | no'))

        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("FAIL : VxLAN Config-Check BRIEF CC Failed\n\n")
        else:
            log.info("PASS : VxLAN Config-Check BRIEF CC Passed\n\n")

        VxLANCC = json.loads(testscript.parameters['LEAF-1'].execute('show consistency-checker vxlan infra brief | no', timeout=300))
        
        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("FAIL : VxLAN Infro BRIEF CC Failed\n\n")
        else:
            log.info("PASS : VxLAN Infro BRIEF CC Passed\n\n")


        VxLANCC = json.loads(testscript.parameters['LEAF-1'].execute('show consistency-checker vxlan vlan all brief | no', timeout=300))

        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("FAIL : VxLAN VLAN ALL BRIEF CC Failed")
        else:
            log.info("PASS : VxLAN VLAN ALL BRIEF CC Passed")

        VxLANCC = json.loads(testscript.parameters['LEAF-2'].execute('show consistency-checker vxlan config-check brief | no', timeout=300))

        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("FAIL : VxLAN Config-Check BRIEF CC Failed\n\n")
        else:
            log.info("PASS : VxLAN Config-Check BRIEF CC Passed\n\n")

        VxLANCC = json.loads(testscript.parameters['LEAF-2'].execute('show consistency-checker vxlan infra brief | no', timeout=300))
        
        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("FAIL : VxLAN Infro BRIEF CC Failed\n\n")
        else:
            log.info("PASS : VxLAN Infro BRIEF CC Passed\n\n")


        VxLANCC = json.loads(testscript.parameters['LEAF-2'].execute('show consistency-checker vxlan vlan all brief | no', timeout=300))

        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("FAIL : VxLAN VLAN ALL BRIEF CC Failed")
        else:
            log.info("PASS : VxLAN VLAN ALL BRIEF CC Passed")

        VxLANCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan config-check brief | no', timeout=300))

        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("FAIL : VxLAN Config-Check BRIEF CC Failed\n\n")
        else:
            log.info("PASS : VxLAN Config-Check BRIEF CC Passed\n\n")

        VxLANCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan infra brief | no', timeout=300))
        
        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("FAIL : VxLAN Infro BRIEF CC Failed\n\n")
        else:
            log.info("PASS : VxLAN Infro BRIEF CC Passed\n\n")


        VxLANCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan vlan all brief | no', timeout=300))

        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            self.failed(reason="VxLAN VLAN ALL BRIEF CC Failed")
        else:
            self.passed(reason="VxLAN VLAN ALL BRIEF CC Passed")

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC016_iCAM_Check(aetest.Testcase):
    """ TC016_iCAM_Check """

    @aetest.test
    def iCAM_Check(self, testscript):
        """ iCAM_Check """

        testscript.parameters['LEAF-1'].configure('''
        
          icam monitor scale
          
          show icam system | no-more
          
          show icam scale | no-more
          
          show icam scale vxlan | no-more
          
          show icam health | no-more
          
          show icam prediction scale vxlan 2030 Jan 01 01:01:01    
        
              ''', timeout=300)

        testscript.parameters['LEAF-2'].configure('''
    
          icam monitor scale
    
          show icam system | no-more
    
          show icam scale | no-more
    
          show icam scale vxlan | no-more
    
          show icam health | no-more
    
          show icam prediction scale vxlan 2030 Jan 01 01:01:01    
    
              ''', timeout=300)

        testscript.parameters['LEAF-3'].configure('''
    
          icam monitor scale
    
          show icam system | no-more
    
          show icam scale | no-more
    
          show icam scale vxlan | no-more
    
          show icam health | no-more
    
          show icam prediction scale vxlan 2030 Jan 01 01:01:01    
    
              ''', timeout=300)

    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#

class TC017_Config_Replace(aetest.Testcase):
    """ TC017_Config_Replace """

    @aetest.test
    def Config_Replace(self, testscript):
        """ Config_Replace """

        testscript.parameters['SPINE'].configure('''
    
          delete bootflash:config_replace.cfg no-prompt
    
          copy running-config bootflash:config_replace.cfg

          no router bgp 65001

              ''', timeout=300)

        testscript.parameters['LEAF-1'].configure('''
    
          delete bootflash:config_replace.cfg no-prompt
    
          copy running-config bootflash:config_replace.cfg
    
          no router bgp 65000
    
              ''', timeout=300)

        testscript.parameters['LEAF-2'].configure('''
    
          delete bootflash:config_replace.cfg no-prompt
    
          copy running-config bootflash:config_replace.cfg

          no router bgp 65000

              ''', timeout=300)

        testscript.parameters['LEAF-3'].configure('''
    
          delete bootflash:config_replace.cfg no-prompt
    
          copy running-config bootflash:config_replace.cfg

          no router bgp 65000

              ''', timeout=300)

        time.sleep(60)

        testscript.parameters['SPINE'].configure('''

          configure replace bootflash:config_replace.cfg verbose
    
              ''', timeout=300)

        testscript.parameters['LEAF-1'].configure('''
       
          configure replace bootflash:config_replace.cfg verbose
    
              ''', timeout=300)

        testscript.parameters['LEAF-2'].configure('''
            
          configure replace bootflash:config_replace.cfg verbose
    
              ''', timeout=300)

        testscript.parameters['LEAF-3'].configure('''
            
          configure replace bootflash:config_replace.cfg verbose
    
              ''', timeout=300)

        ConfigReplace1 = testscript.parameters['SPINE'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace4 = testscript.parameters['LEAF-3'].execute('show config-replace log exec | i "Rollback Status"')
        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)
        match4 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace4)

        time.sleep(60)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success' and match4[1] == 'Success':
            self.passed(reason="Rollback Passed")
        else:
            self.failed(reason="Rollback Failed")


    @aetest.test
    def Verify_Steady_State(self,testscript):
        """ Verify_Steady_State """

        ixNetwork = testscript.parameters['ixNetwork']
        session = testscript.parameters['session']

        ixNetwork.StartAllProtocols(Arg1='sync')

        ixNetwork.Traffic.Apply()
        ixNetwork.Traffic.Start()

        time.sleep(20)

        ixNetwork.ClearStats()

        time.sleep(20)

        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        Loss_per = trafficItemStatistics.Rows['Loss %']
        txFrames = trafficItemStatistics.Rows['Tx Frames']
        rxFrames = trafficItemStatistics.Rows['Rx Frames']

        log.info("Loss Percentage: "+ Loss_per)
        log.info("Tx Frames: "+ txFrames)
        log.info("Rx Frames: "+ rxFrames)

        time.sleep(20)

        ixNetwork.Traffic.Stop()
        ixNetwork.StopAllProtocols()

        if Loss_per == '':
            if (int(txFrames)-int(rxFrames)) in range(-100,101):
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")
        else:
            if int(float(Loss_per)) < 5:
                self.passed(reason="Steady State Traffic Verification Passed")
            else:
                self.failed(reason="Steady State Traffic Verification Failed")

# *****************************************************************************************************************************#


# # ########################################################################
# # ####                       COMMON CLEANUP SECTION                    ###
# # ########################################################################
# # #
# # ## Remove the BASE CONFIGURATION that was applied earlier in the 
# # ## common cleanup section, clean the left over


class common_cleanup(aetest.CommonCleanup):
    """ Common Cleanup for Sample Test """
    pass

if __name__ == '__main__':  # pragma: no cover
    aetest.main()
