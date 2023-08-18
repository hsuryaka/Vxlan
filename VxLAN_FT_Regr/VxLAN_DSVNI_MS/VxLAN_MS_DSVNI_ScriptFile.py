#!/usr/bin/env python

###################################################################
###                  Importing Libraries                        ###
###################################################################
import logging
import yaml
import json
from time import sleep
from yaml import Loader
import pdb
import sys
import os

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

#################################################################################
from pyats import aetest
from pyats.log.utils import banner

from pyats.aereport.utils.argsvalidator import ArgsValidator

ArgVal = ArgsValidator()
import re
import logging
import time

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

#################################################################################


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


# ------------------------------------------------------
# Import and initialize EVPN specific libraries
# ------------------------------------------------------
import vxlanEVPN_FNL_lib

evpnLib = vxlanEVPN_FNL_lib.configure39KVxlanEvpn()
verifyEvpn = vxlanEVPN_FNL_lib.verifyEVPNconfiguration()

# ------------------------------------------------------
# Import and initialize IXIA specific libraries
# ------------------------------------------------------
import ixiaPyats_lib

ixLib = ixiaPyats_lib.ixiaPyats_lib()

# ------------------------------------------------------
# Import and initialize INFRA specific libraries
# ------------------------------------------------------
import infra_lib

infraTrig = infra_lib.infraTrigger()
infraConfig = infra_lib.infraConfigure()
infraVerify = infra_lib.infraVerify()

# ------------------------------------------------------
# Import and initialize NIA specific libraries
# ------------------------------------------------------
import vxlanNIA_lib

niaLib = vxlanNIA_lib.verifyVxlanNIA()


###################################################################
###                  User Library Methods                       ###
###################################################################

def increment_prefix_network(pref, count):
    size = 1 << (pref.network.max_prefixlen - pref.network.prefixlen)
    pref_lst = []
    for i in range(count):
        pref_lst.append(str((pref.ip + size * i)) + "/" + str(pref.network.prefixlen))
    return pref_lst


# *****************************************************************************************************************************#

def getNvePeerList(allLeaves_data):
    nve_peer_lst = []
    for item in allLeaves_data:
        if 'VPC_VTEP_IP' in item['NVE_data'].keys():
            if item['NVE_data']['VPC_VTEP_IP'] not in nve_peer_lst:
                nve_peer_lst.append(item['NVE_data']['VPC_VTEP_IP'])
        else:
            nve_peer_lst.append(item['NVE_data']['VTEP_IP'])
    return nve_peer_lst


# *****************************************************************************************************************************#

def Peer_State(json_input, peer_ip):
    for i in json_input['TABLE_nve_peers']['ROW_nve_peers']:
        if i['peer-ip'] == peer_ip:
            return i['peer-state']
    return 0


# *****************************************************************************************************************************#

def Mac_Table(json_input, peer_ip):
    for i in json_input['TABLE_mac_address']['ROW_mac_address']:
        if i['disp_port'] == 'nve1(' + str(peer_ip) + ')':
            return i['disp_mac_addr']
    return 0


# *****************************************************************************************************************************#

def Fib_Table(json_input, loopbck):
    for i in json_input['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']:
        if i['ipprefix'] == loopbck:
            return i['TABLE_path']['ROW_path']['ipnexthop']
    return 0


# *****************************************************************************************************************************#

def Rtr_Mac(json_input, peer_ip):
    for i in json_input['TABLE_l2route_mac_all']['ROW_l2route_mac_all']:
        if i['next-hop1'] == peer_ip:
            return i['mac-addr']
    return 0


# *****************************************************************************************************************************#

def BGP_Route_Type(json_input, loopbck):
    for i in json_input['TABLE_vrf']['ROW_vrf']['TABLE_afi']['ROW_afi']['TABLE_safi']['ROW_safi']['TABLE_rd']['ROW_rd']['TABLE_prefix']['ROW_prefix']:
        if i['nonipprefix'] == loopbck:
            return i['TABLE_path']['ROW_path']['ipnexthop']
    return 0

# *****************************************************************************************************************************#

def evnis(evn, peerip):
  for i in evn['TABLE_nve_peers']['ROW_nve_peers']:
    if i['peer-ip'] == peerip:
        return i['vni'], i['egress-vni']



###################################################################
###                  GLOBAL VARIABLES                           ###
###################################################################

device_list = []


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
    def connecting_to_devices(self, testscript, testbed, uut_list, configurationFile, job_file_params):
        """ common setup subsection: Connecting to devices """

        log.info(banner("Connecting to Devices"))
        global post_test_process_dict

        # =============================================================================================================================#
        # Grab the device object of the uut device with that name

        LEAF_1 = testscript.parameters['LEAF-1'] = testbed.devices[uut_list['LEAF-1']]
        LEAF_2 = testscript.parameters['LEAF-2'] = testbed.devices[uut_list['LEAF-2']]
        BGW_1 = testscript.parameters['BGW-1'] = testbed.devices[uut_list['BGW-1']]
        BGW_2 = testscript.parameters['BGW-2'] = testbed.devices[uut_list['BGW-2']]

        IXIA = testscript.parameters['IXIA'] = testbed.devices[uut_list['ixia']]

        testscript.parameters['ixia_chassis_ip'] = str(IXIA.connections.a.ip)
        testscript.parameters['ixia_tcl_server'] = str(IXIA.connections.alt.ip)
        testscript.parameters['ixia_tcl_port'] = str(IXIA.connections.alt.port)

        # =============================================================================================================================#
        # Connect to the device

        LEAF_1.connect()
        LEAF_2.connect()
        BGW_1.connect()
        BGW_2.connect()

        device_list.append(LEAF_1)
        device_list.append(LEAF_2)
        device_list.append(BGW_1)
        device_list.append(BGW_2)

        # =============================================================================================================================#
        # Make sure that the connection went fine

        for dut in device_list:
            if not hasattr(dut, 'execute'):
                self.failed()

            if dut.execute != dut.connectionmgr.default.execute:
                self.failed()

        # =============================================================================================================================#
        # Import script_flags into testscript.parameters
        # Setting up the Post Test Check Parameters
        log.info(job_file_params)
        if 'script_flags' not in job_file_params.keys():
            script_flags = {}
            testscript.parameters['script_flags'] = {}
        else:
            script_flags = job_file_params['script_flags']
            script_flags = job_file_params['script_flags']
            testscript.parameters['script_flags'] = job_file_params['script_flags']

        if script_flags is not None:
            if 'skip_device_config' in script_flags.keys():
                testscript.parameters['script_flags']['skip_device_config'] = script_flags['skip_device_config']
            else:
                testscript.parameters['script_flags']['skip_device_config'] = 0

            if 'skip_tgen_config' in script_flags.keys():
                testscript.parameters['script_flags']['skip_tgen_config'] = script_flags['skip_tgen_config']
            else:
                testscript.parameters['script_flags']['skip_tgen_config'] = 0

            if 'skip_device_cleanup' in script_flags.keys():
                testscript.parameters['script_flags']['skip_device_cleanup'] = script_flags['skip_device_cleanup']
            else:
                testscript.parameters['script_flags']['skip_device_cleanup'] = 0
            if 'eor_cc_flag' in script_flags.keys():
                testscript.parameters['script_flags']['eor_cc_flag'] = script_flags['skip_device_cleanup']
            else:
                testscript.parameters['script_flags']['eor_cc_flag'] = 0
            if 'skip_eor_triggers' in script_flags.keys():
                testscript.parameters['script_flags']['skip_eor_triggers'] = script_flags['skip_eor_triggers']
            else:
                testscript.parameters['script_flags']['skip_eor_triggers'] = 1
        else:
            testscript.parameters['script_flags']['skip_device_config'] = 0
            testscript.parameters['script_flags']['skip_tgen_config'] = 0
            testscript.parameters['script_flags']['skip_device_cleanup'] = 0
            testscript.parameters['script_flags']['eor_cc_flag'] = 0

        # =============================================================================================================================#
        # Import Configuration File and create required Structures

        with open(configurationFile) as cfgFile:
            configuration = yaml.load(cfgFile, Loader=Loader)

        testscript.parameters['LEAF_1_dict'] = configuration['LEAF_1_dict']
        testscript.parameters['LEAF_2_dict'] = configuration['LEAF_2_dict']
        testscript.parameters['BGW_1_dict'] = configuration['BGW_1_dict']
        testscript.parameters['BGW_2_dict'] = configuration['BGW_2_dict']

        testscript.parameters['LEAF_1_TGEN_dict'] = configuration['LEAF_1_TGEN_data']
        testscript.parameters['LEAF_2_TGEN_dict'] = configuration['LEAF_2_TGEN_data']

        testscript.parameters['forwardingSysDict1'] = configuration['FWD_SYS_dict1']
        testscript.parameters['forwardingSysDict2'] = configuration['FWD_SYS_dict2']

        testscript.parameters['leavesDictList'] = [configuration['LEAF_1_dict'], configuration['LEAF_2_dict'],
                                                   configuration['BGW_1_dict'], configuration['BGW_2_dict']]

        testscript.parameters['leavesDict'] = {LEAF_1: configuration['LEAF_1_dict'],
                                               LEAF_2: configuration['LEAF_2_dict'],
                                               BGW_1: configuration['BGW_1_dict'],
                                               BGW_2: configuration['BGW_2_dict']}

        testscript.parameters['VTEP_List'] = [testscript.parameters['LEAF_1_dict'],
                                              testscript.parameters['LEAF_2_dict'],
                                              testscript.parameters['BGW_1_dict'],
                                              testscript.parameters['BGW_2_dict']]

        post_test_process_dict = {}
        post_test_process_dict = job_file_params['postTestArgs']
        post_test_process_dict['dut_list'] = [LEAF_1, LEAF_2, BGW_1, BGW_2]
        log.info("===> Post Test Check Process Parameters")
        log.info(post_test_process_dict)

    # *****************************************************************************************************************************#

    @aetest.subsection
    def get_interfaces(self, testscript):
        """ common setup subsection: Getting required Connections for Test """

        log.info(banner("Retrieve the interfaces from Yaml file"))

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        BGW_1 = testscript.parameters['BGW-1']
        BGW_2 = testscript.parameters['BGW-2']
        IXIA = testscript.parameters['IXIA']

        # =============================================================================================================================#

        log.info("================================================")
        log.info("All Available Interfaces from the YAML file are:")
        for dut in device_list:
            log.info("\n\n--->" + str(dut) + " Interface list")
            for interface in dut.interfaces.keys():
                log.info(str(interface) + " --> " + str(dut.interfaces[interface].intf))

        # =============================================================================================================================#
        # Fetching the specific interfaces

        testscript.parameters['intf_LEAF_1_to_BGW_1'] = LEAF_1.interfaces['LEAF-1_to_BGW-1'].intf
        testscript.parameters['intf_LEAF_1_to_IXIA'] = LEAF_1.interfaces['LEAF-1_to_IXIA'].intf

        testscript.parameters['intf_LEAF_2_to_BGW_2'] = LEAF_2.interfaces['LEAF-2_to_BGW-2'].intf
        testscript.parameters['intf_LEAF_2_to_IXIA'] = LEAF_2.interfaces['LEAF-2_to_IXIA'].intf

        testscript.parameters['intf_BGW_1_to_LEAF_1'] = BGW_1.interfaces['BGW-1_to_LEAF-1'].intf
        testscript.parameters['intf_BGW_1_to_BGW_2'] = BGW_1.interfaces['BGW-1_to_BGW-2'].intf

        testscript.parameters['intf_BGW_2_to_LEAF_2'] = BGW_2.interfaces['BGW-2_to_LEAF-2'].intf
        testscript.parameters['intf_BGW_2_to_BGW_1'] = BGW_2.interfaces['BGW-2_to_BGW-1'].intf

        testscript.parameters['intf_IXIA_to_LEAF_1'] = IXIA.interfaces['IXIA_to_LEAF-1'].intf
        testscript.parameters['intf_IXIA_to_LEAF_2'] = IXIA.interfaces['IXIA_to_LEAF-2'].intf

        testscript.parameters['ixia_int_list'] = str(testscript.parameters['intf_IXIA_to_LEAF_1']) + " " + str(testscript.parameters['intf_IXIA_to_LEAF_2'])

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
                                DC-1                                                               DC-2
                                ----                                                               ----

                            +-------------+                                                   +-------------+
                            |    BGW-1    |---------------------------------------------------|    BGW-2    |
                            +-------------+                                                   +-------------+
                                   |                                                                 |
                                   |                                                                 |
                                   |                                                                 |
                            +-------------+                                                   +-------------+
                            |    LEAF-1   |                                                   |    LEAF-2   |
                            +-------------+                                                   +-------------+
                                   |                                                                 |                 
                                   |                                                                 |             
                                   |                                                                 |             
                                   |                                                                 |             
                            +-------------+                                                   +-------------+
                            |     IXIA    |                                                   |    IXIA     |
                            +-------------+                                                   +-------------+
                
        """

        log.info("Topology to be used is")
        log.info(topology)

# *****************************************************************************************************************************#

class DEVICE_BRINGUP_enable_feature_set(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def enable_feature_set(self, testscript):
        """ Device Bring-up subsection: Configuring Features and Feature-sets """

        log.info(banner("Enabling Feature Set"))

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            testscript.parameters['leafLst'] = leafLst = [testscript.parameters['LEAF-1'],
                                                          testscript.parameters['LEAF-2'],
                                                          testscript.parameters['BGW-1'],
                                                          testscript.parameters['BGW-2']]

            testscript.parameters['LeafFeatureList'] = LeafFeatureList = ['ospf', 'bgp', 'pim', 'interface-vlan',
                                                                          'vn-segment-vlan-based', 'lacp', 'nv overlay',
                                                                          'fabric forwarding', 'bash-shell']

            configFeatureSet_status = []
            configFeatureSet_msgs = ""

            # --------------------------------
            # Configure Feature-set on LEAF-1
            featureConfigureLeaf1_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-1'],
                                                                              LeafFeatureList)
            if featureConfigureLeaf1_status['result']:
                log.info("Passed Configuring features on LEAF-1")
            else:
                log.debug("Failed configuring features on LEAF-1")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-2
            featureConfigureLeaf2_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-2'],
                                                                              LeafFeatureList)
            if featureConfigureLeaf2_status['result']:
                log.info("Passed Configuring features on LEAF-2")
            else:
                log.debug("Failed configuring features on LEAF-2")
                configFeatureSet_msgs += featureConfigureLeaf2_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on BGW-1
            featureConfigureBGW1_status = infraConfig.configureVerifyFeature(testscript.parameters['BGW-1'],
                                                                              LeafFeatureList)
            if featureConfigureBGW1_status['result']:
                log.info("Passed Configuring features on BGW-1")
            else:
                log.debug("Failed configuring features on BGW-1")
                configFeatureSet_msgs += featureConfigureBGW1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on BGW-2
            featureConfigureBGW2_status = infraConfig.configureVerifyFeature(testscript.parameters['BGW-2'],
                                                                              LeafFeatureList)
            if featureConfigureBGW2_status['result']:
                log.info("Passed Configuring features on BGW-2")
            else:
                log.debug("Failed configuring features on BGW-2")
                configFeatureSet_msgs += featureConfigureBGW2_status['log']
                configFeatureSet_status.append(0)

            featureConfigureLeafs_status = infraConfig.configureVerifyFeature(leafLst, LeafFeatureList)
            if featureConfigureLeafs_status['result']:
                log.info("Passed Configuring features on LEAFs/BGWs")
            else:
                log.debug("Failed configuring features on LEAFs/BGWs")
                configFeatureSet_msgs += featureConfigureLeafs_status['log']
                configFeatureSet_status.append(0)

            if 0 in configFeatureSet_status:
                self.failed(reason=configFeatureSet_msgs, goto=['common_cleanup'])

        else:
            self.passed(reason="Skipped Device Configuration as per request")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class DEVICE_BRINGUP_configure_LEAF_1(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_LEAF_1(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        log.info(banner("Device BringUP LEAF-1"))

        evpnLib.configureEVPNLeaf(testscript.parameters['LEAF-1'], testscript.parameters['forwardingSysDict1'],
                                  testscript.parameters['LEAF_1_dict'])

        try:
            testscript.parameters['LEAF-1'].configure('''

              interface ''' + str(testscript.parameters['intf_LEAF_1_to_BGW_1']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                no shutdown

              interface ''' + str(testscript.parameters['intf_LEAF_1_to_IXIA']) + '''
                switchport
                switchport mode trunk
                spanning-tree port type edge trunk
                no shutdown

              vlan 18
                no vn-segment 10018
                vn-segment 40018
              vlan 20
                no vn-segment 10020
                vn-segment 40020
              vlan 38
                no vn-segment 20038
                vn-segment 40038

              vrf context EVPN-VRF-37
                address-family ipv4 unicast
                  no export map ANY
                address-family ipv6 unicast
                  no export map ANY

              vrf context EVPN-VRF-38
                no vni 20038
                vni 40038
                address-family ipv4 unicast
                  no route-target both auto
                  no route-target both auto evpn
                  no export map ANY
                  route-target import 803:3868
                  route-target import 803:3868 evpn
                  route-target export 803:3868
                  route-target export 803:3868 evpn
                address-family ipv6 unicast
                  no route-target both auto
                  no route-target both auto evpn
                  no export map ANY
                  route-target import 803:3868
                  route-target import 803:3868 evpn
                  route-target export 803:3868
                  route-target export 803:3868 evpn

              interface nve1
                member vni 10017
                  no mcast-group 224.1.1.101
                  no suppress-arp
                  ingress-replication protocol bgp
                member vni 10019
                  no mcast-group 224.1.2.101
                  no suppress-arp
                  ingress-replication protocol bgp
                no member vni 10018
                no member vni 10020
                no member vni 20038 associate-vrf
                member vni 40018
                  ingress-replication protocol bgp
                member vni 40020
                  ingress-replication protocol bgp
                member vni 40038 associate-vrf

              evpn
                no vni 10018 l2
                no vni 10020 l2
                vni 40018 l2
                  rd auto
                  route-target import 703:18
                  route-target export 703:18
                vni 40020 l2
                  rd auto
                  route-target import 803:20
                  route-target export 803:20

          ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-1', goto=['common_cleanup'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class DEVICE_BRINGUP_configure_LEAF_2(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_LEAF_2(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-2 """

        log.info(banner("Device BringUP LEAF-2"))

        evpnLib.configureEVPNLeaf(testscript.parameters['LEAF-2'], testscript.parameters['forwardingSysDict2'],
                                  testscript.parameters['LEAF_2_dict'])

        try:
            testscript.parameters['LEAF-2'].configure('''

                interface ''' + str(testscript.parameters['intf_LEAF_2_to_BGW_2']) + '''
                  channel-group ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                  no shutdown

                interface ''' + str(testscript.parameters['intf_LEAF_2_to_IXIA']) + '''
                  switchport
                  switchport mode trunk
                  spanning-tree port type edge trunk
                  no shutdown

                vrf context EVPN-VRF-37
                  address-family ipv4 unicast
                    no export map ANY
                  address-family ipv6 unicast
                    no export map ANY

                vrf context EVPN-VRF-38
                  address-family ipv4 unicast
                    no route-target both auto
                    no route-target both auto evpn
                    no export map ANY
                    route-target import 803:3868
                    route-target import 803:3868 evpn
                    route-target export 803:3868
                    route-target export 803:3868 evpn
                  address-family ipv6 unicast
                    no route-target both auto
                    no route-target both auto evpn
                    no export map ANY
                    route-target import 803:3868
                    route-target import 803:3868 evpn
                    route-target export 803:3868
                    route-target export 803:3868 evpn

                  interface nve1
                    member vni 10017
                      no mcast-group 224.1.1.101
                      no suppress-arp
                      ingress-replication protocol bgp
                    member vni 10018
                      no mcast-group 224.1.1.101
                      no suppress-arp
                      ingress-replication protocol bgp
                    member vni 10019
                      no mcast-group 224.1.2.101
                      no suppress-arp
                      ingress-replication protocol bgp
                    member vni 10020
                      no mcast-group 224.1.2.101
                      no suppress-arp
                      ingress-replication protocol bgp

                  evpn
                    vni 10018 l2
                      rd auto
                      no route-target import auto
                      no route-target export auto
                      route-target import 703:18
                      route-target export 703:18
                    vni 10020 l2
                      rd auto
                      no route-target import auto
                      no route-target export auto
                      route-target import 803:20
                      route-target export 803:20

            ''')

        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-2', goto=['common_cleanup'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class DEVICE_BRINGUP_configure_BGW_1(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_BGW_1(self, testscript):
        """ Device Bring-up subsection: Configuring BGW-1 """

        log.info(banner("Device BringUP BGW-1"))

        evpnLib.configureEVPNLeaf(testscript.parameters['BGW-1'], testscript.parameters['forwardingSysDict1'],
                                  testscript.parameters['BGW_1_dict'])

        try:
            testscript.parameters['BGW-1'].configure('''

              interface ''' + str(testscript.parameters['intf_BGW_1_to_LEAF_1']) + '''
                channel-group ''' + str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                no shutdown

                evpn multisite border-gateway 100
                  delay-restore time 300

              vrf context EVPN-VRF-37
                address-family ipv4 unicast
                  no export map ANY
                address-family ipv6 unicast
                  no export map ANY

              vrf context EVPN-VRF-38
                address-family ipv4 unicast
                  no route-target both auto
                  no route-target both auto evpn
                  no export map ANY
                  route-target import 803:3868
                  route-target import 803:3868 evpn
                  route-target export 803:3868
                  route-target export 803:3868 evpn
                address-family ipv6 unicast
                  no route-target both auto
                  no route-target both auto evpn
                  no export map ANY
                  route-target import 803:3868
                  route-target import 803:3868 evpn
                  route-target export 803:3868
                  route-target export 803:3868 evpn

                interface nve1
                  member vni 10017
                    no mcast-group 224.1.1.101
                    no suppress-arp
                    ingress-replication protocol bgp
                    multisite ingress-replication
                  member vni 10018
                    no mcast-group 224.1.1.101
                    no suppress-arp
                    ingress-replication protocol bgp
                    multisite ingress-replication
                  member vni 10019
                    no mcast-group 224.1.2.101
                    no suppress-arp
                    ingress-replication protocol bgp
                    multisite ingress-replication
                  member vni 10020
                    no mcast-group 224.1.2.101
                    no suppress-arp
                    ingress-replication protocol bgp
                    multisite ingress-replication

                evpn
                  vni 10018 l2
                    rd auto
                    no route-target import auto
                    no route-target export auto
                    route-target import 703:18
                    route-target export 703:18
                  vni 10020 l2
                    rd auto
                    no route-target import auto
                    no route-target export auto
                    route-target import 803:20
                    route-target export 803:20
                
                route-map RMAP_REDIST_DIRECT permit 10
                  match tag 54321 
                
                interface nve1
                  multisite border-gateway interface loopback100
                  
                interface port-channel ''' + str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                  evpn multisite fabric-tracking

                interface ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2']) + '''
                  ip address 10.51.21.1/30 tag 54321
                  evpn multisite dci-tracking
                  no shutdown

                interface loopback0
                  ip address ''' + str(testscript.parameters['BGW_1_dict']['loop0_ip']) + '''/32 tag 54321

                interface ''' + str(testscript.parameters['BGW_1_dict']['NVE_data']['src_loop']) + '''
                  ip address ''' + str(testscript.parameters['BGW_1_dict']['NVE_data']['VTEP_IP']) + '''/32 tag 54321

                interface loopback100
                  ip address 10.101.101.101/32 tag 54321
                  ip router ospf ''' + str(testscript.parameters['forwardingSysDict1']['OSPF_AS']) + ''' area 0.0.0.0
                
                router bgp ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''
                  address-family ipv4 unicast
                    redistribute direct route-map RMAP_REDIST_DIRECT
                  neighbor ''' + str(testscript.parameters['BGW_2_dict']['loop0_ip']) + '''
                    remote-as ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''
                    update-source loopback0
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family l2vpn evpn
                      send-community
                      send-community extended
                      rewrite-evpn-rt-asn
                  neighbor 10.51.21.2
                    remote-as ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''
                    update-source ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2']) + '''
                    address-family ipv4 unicast

          ''')

        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on BGW-1', goto=['common_cleanup'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class DEVICE_BRINGUP_configure_BGW_2(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_BGW_2(self, testscript):
        """ Device Bring-up subsection: Configuring BGW-2 """

        log.info(banner("Device BringUP BGW-2"))

        evpnLib.configureEVPNLeaf(testscript.parameters['BGW-2'], testscript.parameters['forwardingSysDict2'],
                                  testscript.parameters['BGW_2_dict'])

        try:
            testscript.parameters['BGW-2'].configure('''

              interface ''' + str(testscript.parameters['intf_BGW_2_to_LEAF_2']) + '''
                channel-group ''' + str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                no shutdown

              evpn multisite border-gateway 200
                delay-restore time 300

              vlan 18
                no vn-segment 10018
                vn-segment 40018
              vlan 20
                no vn-segment 10020
                vn-segment 40020
              vlan 38
                no vn-segment 20038
                vn-segment 40038

              vrf context EVPN-VRF-37
                address-family ipv4 unicast
                  no export map ANY
                address-family ipv6 unicast
                  no export map ANY

              vrf context EVPN-VRF-38
                no vni 20038
                vni 40038
                address-family ipv4 unicast
                  no route-target both auto
                  no route-target both auto evpn
                  no export map ANY
                  route-target import 803:3868
                  route-target import 803:3868 evpn
                  route-target export 803:3868
                  route-target export 803:3868 evpn
                address-family ipv6 unicast
                  no route-target both auto
                  no route-target both auto evpn
                  no export map ANY
                  route-target import 803:3868
                  route-target import 803:3868 evpn
                  route-target export 803:3868
                  route-target export 803:3868 evpn

              interface nve1
                member vni 10017
                  no mcast-group 224.1.1.101
                  no suppress-arp
                  ingress-replication protocol bgp
                  multisite ingress-replication
                member vni 10019
                  no mcast-group 224.1.2.101
                  no suppress-arp
                  ingress-replication protocol bgp
                  multisite ingress-replication
                no member vni 10018
                no member vni 10020
                no member vni 20038 associate-vrf
                member vni 40018
                  ingress-replication protocol bgp
                  multisite ingress-replication
                member vni 40020
                  ingress-replication protocol bgp
                  multisite ingress-replication
                member vni 40038 associate-vrf

              evpn
                no vni 10018 l2
                no vni 10020 l2
                vni 40018 l2
                  rd auto
                  route-target import 703:18
                  route-target export 703:18
                vni 40020 l2
                  rd auto
                  route-target import 803:20
                  route-target export 803:20

                route-map RMAP_REDIST_DIRECT permit 10
                  match tag 54321 
                
                interface nve1
                  multisite border-gateway interface loopback100
                  
                interface port-channel ''' + str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                  evpn multisite fabric-tracking

                interface ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1']) + '''
                  ip address 10.51.21.2/30 tag 54321
                  evpn multisite dci-tracking
                  no shutdown

                interface loopback0
                  ip address ''' + str(testscript.parameters['BGW_2_dict']['loop0_ip']) + '''/32 tag 54321

                interface ''' + str(testscript.parameters['BGW_2_dict']['NVE_data']['src_loop']) + '''
                  ip address ''' + str(testscript.parameters['BGW_2_dict']['NVE_data']['VTEP_IP']) + '''/32 tag 54321

                interface loopback100
                  ip address 10.201.201.201/32 tag 54321
                  ip router ospf ''' + str(testscript.parameters['forwardingSysDict2']['OSPF_AS']) + ''' area 0.0.0.0
                
                router bgp ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''
                  address-family ipv4 unicast
                    redistribute direct route-map RMAP_REDIST_DIRECT
                  neighbor ''' + str(testscript.parameters['BGW_1_dict']['loop0_ip']) + '''
                    remote-as ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''
                    update-source loopback0
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family l2vpn evpn
                      send-community
                      send-community extended
                      rewrite-evpn-rt-asn
                  neighbor 10.51.21.1
                    remote-as ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''
                    update-source ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1']) + '''
                    address-family ipv4 unicast

          ''')

        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on BGW-2', goto=['common_cleanup'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class DEVICE_BRINGUP_perform_copy_r_s(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def perform_copy_r_s(self, testscript):
        """ MS_DSVNI_CONFIGURATION test subsection: Save all configurations (copy r s) """

        log.info(banner("Performing Copy R S"))

        testscript.parameters['LEAF-1'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=300)
        testscript.parameters['BGW-1'].configure("copy r s", timeout=300)
        testscript.parameters['BGW-2'].configure("copy r s", timeout=300)

        time.sleep(30)

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class VERIFY_NETWORK(aetest.Testcase):
    """VERIFY_NETWORK"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict1'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict1'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        if 0 in status['status']:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_ENABLE_IGMP_Snooping(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def ENABLE_IGMP_Snooping(self, testscript):
        """ENABLE_IGMP_Snooping """

        testscript.parameters['LEAF-1'].configure('''
            ip igmp snooping
            ip igmp snooping vxlan
        ''')
        testscript.parameters['LEAF-2'].configure('''
            ip igmp snooping
            ip igmp snooping vxlan
        ''')
        testscript.parameters['BGW-1'].configure('''
            ip igmp snooping
            ip igmp snooping vxlan
        ''')
        testscript.parameters['BGW-2'].configure('''
            ip igmp snooping
            ip igmp snooping vxlan
        ''')

        forwardingSysDict = testscript.parameters['forwardingSysDict1']

        vlan_id_start = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        total_vlans = int(forwardingSysDict['VRF_count']) * int(forwardingSysDict['VLAN_PER_VRF_count'])
        vlan_id_stop = int(vlan_id_start) + total_vlans

        testscript.parameters['LEAF-1'].configure('''
            vlan configuration ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
              ip igmp snooping querier 1.1.1.1
        ''')

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_CONNECT_IXIA_CHASSIS(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONNECT_IXIA_CHASSIS(self, testscript):
        """ IXIA_CONFIGURATION subsection: Connect to IXIA """

        log.info(banner("IXIA Configuration Block"))

        # Get IXIA paraameters
        ixia_chassis_ip = testscript.parameters['ixia_chassis_ip']
        ixia_tcl_server = testscript.parameters['ixia_tcl_server']
        ixia_tcl_port = testscript.parameters['ixia_tcl_port']
        ixia_int_list = testscript.parameters['ixia_int_list']

        ix_int_1 = testscript.parameters['intf_IXIA_to_LEAF_1']
        ix_int_2 = testscript.parameters['intf_IXIA_to_LEAF_2']

        ixiaArgDict = {
            'chassis_ip': ixia_chassis_ip,
            'port_list': ixia_int_list,
            'tcl_server': ixia_tcl_server,
            'tcl_port': ixia_tcl_port,
        }

        log.info("Ixia Args Dict is:")
        log.info(ixiaArgDict)

        result = ixLib.connect_to_ixia(ixiaArgDict)
        if result == 0:
            log.debug("Connecting to ixia failed")
            self.errored("Connecting to ixia failed", goto=['next_tc'])

        testscript.parameters['ixia_connect_result'] = result

        log.info(result)
        log.info(testscript.parameters['ixia_connect_result'])

        ch_key = result['port_handle']
        for ch_p in ixia_chassis_ip.split('.'):
            ch_key = ch_key[ch_p]

        log.info("Port Handles are:")
        log.info(ch_key)

        testscript.parameters['port_handle_1'] = ch_key[ix_int_1]
        testscript.parameters['port_handle_2'] = ch_key[ix_int_2]

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_CREATE_IXIA_TOPOLOGIES(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CREATE_IXIA_TOPOLOGIES(self, testscript):
        """ IXIA_CONFIGURATION subsection: Create IXIA Topologies """

        TOPO_1_dict = {'topology_name': 'LEAF-1-TG',
                       'device_grp_name': 'LEAF-1-TG',
                       'port_handle': testscript.parameters['port_handle_1']}

        TOPO_2_dict = {'topology_name': 'LEAF-2-TG',
                       'device_grp_name': 'LEAF-2-TG',
                       'port_handle': testscript.parameters['port_handle_2']}

        testscript.parameters['IX_TP1'] = ixLib.create_topo_device_grp(TOPO_1_dict)
        if testscript.parameters['IX_TP1'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created L1-TG Topology Successfully")

        testscript.parameters['IX_TP2'] = ixLib.create_topo_device_grp(TOPO_2_dict)
        if testscript.parameters['IX_TP2'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created L2-TG Topology Successfully")

        testscript.parameters['IX_TP1']['port_handle'] = testscript.parameters['port_handle_1']
        testscript.parameters['IX_TP2']['port_handle'] = testscript.parameters['port_handle_2']

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_CONFIGURE_IXIA_INTERFACES(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONFIGURE_IXIA_INTERFACES(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure IXIA Interfaces """

        P1 = testscript.parameters['port_handle_1']
        P2 = testscript.parameters['port_handle_2']

        P1_dict = testscript.parameters['LEAF_1_TGEN_dict']
        P2_dict = testscript.parameters['LEAF_2_TGEN_dict']

        P1_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP1']['dev_grp_hndl'],
                         'port_hndl': P1,
                         'no_of_ints': P1_dict['no_of_ints'],
                         'phy_mode': P1_dict['phy_mode'],
                         'mac': P1_dict['mac'],
                         'mac_step': P1_dict['mac_step'],
                         'protocol': P1_dict['protocol'],
                         'v4_addr': P1_dict['v4_addr'],
                         'v4_addr_step': P1_dict['v4_addr_step'],
                         'v4_gateway': P1_dict['v4_gateway'],
                         'v4_gateway_step': P1_dict['v4_gateway_step'],
                         'v4_netmask': P1_dict['v4_netmask'],
                         'v6_addr': P1_dict['v6_addr'],
                         'v6_addr_step': P1_dict['v6_addr_step'],
                         'v6_gateway': P1_dict['v6_gateway'],
                         'v6_gateway_step': P1_dict['v6_gateway_step'],
                         'v6_netmask': P1_dict['v6_netmask'],
                         'vlan_id': P1_dict['vlan_id'],
                         'vlan_id_step': P1_dict['vlan_id_step']}

        P2_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP2']['dev_grp_hndl'],
                         'port_hndl': P2,
                         'no_of_ints': P2_dict['no_of_ints'],
                         'phy_mode': P2_dict['phy_mode'],
                         'mac': P2_dict['mac'],
                         'mac_step': P2_dict['mac_step'],
                         'protocol': P2_dict['protocol'],
                         'v4_addr': P2_dict['v4_addr'],
                         'v4_addr_step': P2_dict['v4_addr_step'],
                         'v4_gateway': P2_dict['v4_gateway'],
                         'v4_gateway_step': P2_dict['v4_gateway_step'],
                         'v4_netmask': P2_dict['v4_netmask'],
                         'v6_addr': P2_dict['v6_addr'],
                         'v6_addr_step': P2_dict['v6_addr_step'],
                         'v6_gateway': P2_dict['v6_gateway'],
                         'v6_gateway_step': P2_dict['v6_gateway_step'],
                         'v6_netmask': P2_dict['v6_netmask'],
                         'vlan_id': P2_dict['vlan_id'],
                         'vlan_id_step': P2_dict['vlan_id_step']}

        P1_IX_int_data = ixLib.configure_multi_ixia_interface(P1_int_dict_1)
        P2_IX_int_data = ixLib.configure_multi_ixia_interface(P2_int_dict_1)

        log.info(P1_IX_int_data)
        log.info(P2_IX_int_data)

        if P1_IX_int_data == 0 or P2_IX_int_data == 0:
            log.debug("Configuring IXIA Interface failed")
            self.errored("Configuring IXIA Interface failed", goto=['next_tc'])
        else:
            log.info("Configured IXIA Interface Successfully")

        testscript.parameters['IX_TP1']['eth_handle'] = P1_IX_int_data['eth_handle']
        testscript.parameters['IX_TP1']['ipv4_handle'] = P1_IX_int_data['ipv4_handle']
        testscript.parameters['IX_TP1']['ipv6_handle'] = P1_IX_int_data['ipv6_handle']
        testscript.parameters['IX_TP1']['topo_int_handle'] = P1_IX_int_data['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP2']['eth_handle'] = P2_IX_int_data['eth_handle']
        testscript.parameters['IX_TP2']['ipv4_handle'] = P2_IX_int_data['ipv4_handle']
        testscript.parameters['IX_TP2']['ipv6_handle'] = P2_IX_int_data['ipv6_handle']
        testscript.parameters['IX_TP2']['topo_int_handle'] = P2_IX_int_data['topo_int_handle'].split(" ")

        log.info("IXIA Port 1 Handles")
        log.info(testscript.parameters['IX_TP1'])
        log.info("IXIA Port 2 Handles")
        log.info(testscript.parameters['IX_TP2'])

        time.sleep(100)

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_CONFIGURE_IXIA_IGMP_GROUPS(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONFIGURE_IXIA_IGMP_GROUPS(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

        IX_TP1 = testscript.parameters['IX_TP1']

        P1_TGEN_dict = testscript.parameters['LEAF_1_TGEN_dict']
        P2_TGEN_dict = testscript.parameters['LEAF_2_TGEN_dict']

        IGMP_dict_1 = {'ipv4_hndl'                      : IX_TP1['ipv4_handle'],
                       'igmp_ver'                       : P1_TGEN_dict['igmp_ver'],
                       'mcast_grp_ip'                   : P1_TGEN_dict['mcast_grp_ip'],
                       'mcast_grp_ip_step'              : P1_TGEN_dict['mcast_grp_ip_step'],
                       'no_of_grps'                     : P1_TGEN_dict['no_of_grps'],
                       'mcast_src_ip'                   : P2_TGEN_dict['v4_addr'],
                       'mcast_src_ip_step'              : P1_TGEN_dict['v4_addr_step'],
                       'mcast_src_ip_step_per_port'     : P1_TGEN_dict['v4_addr_step'],
                       'mcast_grp_ip_step_per_port'     : P1_TGEN_dict['v4_addr_step'],
                       'mcast_no_of_srcs'               : P1_TGEN_dict['no_of_mcast_sources'],
                       'topology_handle'                : IX_TP1['topo_hndl']
                       }

        IGMP_EML_1 = ixLib.emulate_igmp_groupHost(IGMP_dict_1)

        # ForkedPdb().set_trace()

        if IGMP_EML_1 == 0:
            log.debug("Configuring IGMP failed")
            self.errored("Configuring IGMP failed", goto=['next_tc'])
        else:
            log.info("Configured IGMP Successfully")

        testscript.parameters['IX_TP1']['igmpHost_handle'] = []
        testscript.parameters['IX_TP1']['igmp_group_handle'] = []
        testscript.parameters['IX_TP1']['igmp_source_handle'] = []
        testscript.parameters['IX_TP1']['igmpMcastGrpList'] = []

        testscript.parameters['IX_TP1']['igmpHost_handle'].append(IGMP_EML_1['igmpHost_handle'])
        testscript.parameters['IX_TP1']['igmp_group_handle'].append(IGMP_EML_1['igmp_group_handle'])
        testscript.parameters['IX_TP1']['igmp_source_handle'].append(IGMP_EML_1['igmp_source_handle'])
        testscript.parameters['IX_TP1']['igmpMcastGrpList'].append(IGMP_EML_1['igmpMcastGrpList'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_START_IXIA_PROTOCOLS(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def START_IXIA_PROTOCOLS(self):
        """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

        # _result_ = ixiahlt.test_control(action='configure_all')
        # print(_result_)
        proto_result = ixLib.start_protocols()
        if proto_result == 0:
            log.debug("Starting Protocols failed")
            self.errored("Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Started Protocols Successfully")

        time.sleep(60)

        proto_result = ixLib.stop_protocols()
        if proto_result == 0:
            log.debug("Stopped Protocols failed")
            self.errored("Stopped Protocols failed", goto=['next_tc'])
        else:
            log.info("Stopped Protocols Successfully")

        time.sleep(30)

        proto_result = ixLib.start_protocols()
        if proto_result == 0:
            log.debug("Starting Protocols failed")
            self.errored("Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Started Protocols Successfully")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_CONFIGURE_BCAST_IXIA_TRAFFIC(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']

        P2_dict = testscript.parameters['LEAF_2_TGEN_dict']

        BCAST_L2_to_L1_dict = {
                            'src_hndl'      : IX_TP2['port_handle'],
                            'dst_hndl'      : IX_TP1['port_handle'],
                            'TI_name'       : "BCAST_SA_2_vPC",
                            'frame_size'    : "70",
                            'rate_pps'      : "1000",
                            'src_mac'       : "00:00:30:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "100",
                            'vlan_id'       : P2_dict['vlan_id'],
                            'vlanid_step'   : "1",
                            'vlanid_count'  : P2_dict['no_of_ints'],
                            'ip_src_addrs'  : "30.1.1.10",
                            'ip_step'       : "0.0.1.0",
                      }

        BCAST_L2_to_L1_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_L2_to_L1_dict)

        if BCAST_L2_to_L1_TI == 0:
            log.debug("Configuring BCast from SA to vPC failed")
            self.errored("Configuring BCast from SA to vPC failed", goto=['next_tc'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_CONFIGURE_UNKNOWN_UCAST_IXIA_TRAFFIC(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def CONFIGURE_UNKNOWN_UCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']

        P2_dict = testscript.parameters['LEAF_2_TGEN_dict']

        UKNOWN_UCAST_L2_to_L1_dict = {
                            'src_hndl'      : IX_TP2['port_handle'],
                            'dst_hndl'      : IX_TP1['port_handle'],
                            'TI_name'       : "UKNOWN_UCAST_SA_2_VPC",
                            'frame_size'    : "64",
                            'rate_pps'      : "1000",
                            'dst_mac'       : "00:00:45:00:00:01",
                            'dstmac_step'   : "00:00:00:00:00:01",
                            'dstmac_count'  : "100",
                            'src_mac'       : "00:00:41:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "100",
                            'vlan_id'       : P2_dict['vlan_id'],
                            'vlanid_step'   : "1",
                            'vlanid_count'  : P2_dict['no_of_ints'],
                      }

        UKNOWN_UCAST_L2_to_L1_TI = ixLib.configure_ixia_UNKNOWN_UCAST_traffic_item(UKNOWN_UCAST_L2_to_L1_dict)

        if UKNOWN_UCAST_L2_to_L1_TI == 0:
            log.debug("Configuring UNKNOWN_UCAST TI failed")
            self.errored("Configuring UNKNOWN_UCAST TI failed", goto=['next_tc'])

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_CONFIGURE_MCAST_IXIA_TRAFFIC(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONFIGURE_MCAST_IXIA_TRAFFIC(self, testscript):

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']

        forwardingSysDict = testscript.parameters['forwardingSysDict1']
        total_vlans = int(forwardingSysDict['VRF_count']) * int(forwardingSysDict['VLAN_PER_VRF_count'])

        # Creating TAGs for SRC IP Handles
        TAG_dict = {'subject_handle': IX_TP2['ipv4_handle'],
                    'topo_handle': IX_TP2['topo_hndl'],
                    'TAG_count_per_item': str(total_vlans)
                    }

        SRC_IP_TAG = ixLib.configure_tag_config_multiplier(TAG_dict)
        if SRC_IP_TAG == 0:
            log.debug("Configuring TAGS for SRC IP failed")

        # Creating TAGs for DST IP Handles
        TAG_dict = {'subject_handle': IX_TP1['ipv4_handle'],
                    'topo_handle': IX_TP1['topo_hndl'],
                    'TAG_count_per_item': str(total_vlans)
                    }

        DST_IP_TAG = ixLib.configure_tag_config_multiplier(TAG_dict)
        if DST_IP_TAG == 0:
            log.debug("Configuring TAGS for DST IP failed")

        # Creating TAGs for IGMP Host Handles
        TAG_dict = {'subject_handle': IX_TP1['igmp_group_handle'],
                    'topo_handle': IX_TP1['topo_hndl'],
                    'TAG_count_per_item': str(total_vlans)
                    }

        IGMP_Host_TAG = ixLib.configure_tag_config_multiplier(TAG_dict)
        if IGMP_Host_TAG == 0:
            log.debug("Configuring TAGS for IGMP Hosts failed")

        MCAST_dict = {'src_ipv4_topo_handle': IX_TP2['topo_hndl'],
                      'total_tags': str(int(total_vlans)),
                      'TI_name': "MCAST_STD_END_NODE_ORPH",
                      'rate_pps': "1000",
                      'frame_size': "70",
                      }

        MCAST_TI = ixLib.configure_v4_mcast_traffic_item_per_tag(MCAST_dict)

        if MCAST_TI == 0:
            log.debug("Configuring MCast TI failed")
            self.errored("Configuring MCast TI failed", goto=['next_tc'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_CONFIGURE_L2KUC_IXIA_TRAFFIC(aetest.Testcase):
    """IXIA_CONFIGURATION_CONFIGURE_L2KUC_IXIA_TRAFFIC"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONFIGURE_L2KUC_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure L2 KUC Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']

            L2KUC_v4_dict = {'src_hndl'   : IX_TP1['ipv4_handle'],
                                'dst_hndl'  : IX_TP2['ipv4_handle'],
                                'circuit'   : 'ipv4',
                                'TI_name'   : "L2KUC_TP1_TP2_V4",
                                'rate_pps'  : "1000",
                                'bi_dir'    : 1
                                }

            L2KUC_v6_dict = {'src_hndl'   : IX_TP1['ipv6_handle'],
                                'dst_hndl'  : IX_TP2['ipv6_handle'],
                                'circuit'   : 'ipv6',
                                'TI_name'   : "L2KUC_TP1_TP2_V6",
                                'rate_pps'  : "1000",
                                'bi_dir'    : 1
                                }

            L2KUC_v4_TI = ixLib.configure_ixia_traffic_item(L2KUC_v4_dict)
            L2KUC_v6_TI = ixLib.configure_ixia_traffic_item(L2KUC_v6_dict)

            if L2KUC_v4_TI == 0 or L2KUC_v6_TI == 0:
                log.debug("Configuring L2 KUC failed")
                self.errored("Configuring L2 KUC failed", goto=['next_tc'])

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

        time.sleep(100)

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_CONFIGURE_L3KUC_IXIA_TRAFFIC(aetest.Testcase):
    """IXIA_CONFIGURATION_CONFIGURE_L3KUC_IXIA_TRAFFIC"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONFIGURE_L3KUC_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure L3 KUC Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']

            vrf_count = int(testscript.parameters['forwardingSysDict1']['VRF_count'])
            vlan_per_vrf = int(testscript.parameters['forwardingSysDict1']['VLAN_PER_VRF_count'])

            L3KUC_v4_dict = {'src_hndl'                 : IX_TP1['ipv4_handle'],
                                'dst_hndl'              : IX_TP2['ipv4_handle'],
                                'circuit'               : 'ipv4',
                                'TI_name'               : "L3KUC_TP4_TP2_V4",
                                'rate_pps'              : "1000",
                                'bi_dir'                : 1,
                                'no_of_end_points'      : vrf_count,
                                'src_port_start'        : '1',
                                'src_port_start_step'   : '0',
                                'src_intf_count'        : str(vlan_per_vrf),
                                'dst_port_start'        : '1',
                                'dst_port_start_step'   : '0',
                                'dst_intf_count'        : str(vlan_per_vrf),
                                'route_mesh'            : 'fully'
                                }

            L3KUC_v6_dict = {'src_hndl'                 : IX_TP1['ipv6_handle'],
                                'dst_hndl'              : IX_TP2['ipv6_handle'],
                                'circuit'               : 'ipv6',
                                'TI_name'               : "L3KUC_TP2_TP4_V6",
                                'rate_pps'              : "1000",
                                'bi_dir'                : 1,
                                'no_of_end_points'      : vrf_count,
                                'src_port_start'        : '1',
                                'src_port_start_step'   : '0',
                                'src_intf_count'        : str(vlan_per_vrf),
                                'dst_port_start'        : '1',
                                'dst_port_start_step'   : '0',
                                'dst_intf_count'        : str(vlan_per_vrf),
                                'route_mesh'            : 'fully'
                                }

            L3KUC_v4_TI = ixLib.configure_ixia_traffic_item(L3KUC_v4_dict)
            L3KUC_v6_TI = ixLib.configure_ixia_traffic_item(L3KUC_v6_dict)

            if L3KUC_v4_TI == 0 or L3KUC_v6_TI == 0:
                log.debug("Configuring L3 KUC failed")
                self.errored("Configuring L3 KUC failed", goto=['next_tc'])

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

        time.sleep(100)

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_STOP_START_IXIA_PROTOCOLS(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def START_IXIA_PROTOCOLS(self):
        """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

        proto_result = ixLib.stop_protocols()
        if proto_result == 0:
            log.debug("Stopped Protocols failed")
            self.errored("Stopped Protocols failed", goto=['next_tc'])
        else:
            log.info("Stopped Protocols Successfully")

        time.sleep(30)

        proto_result = ixLib.start_protocols()
        if proto_result == 0:
            log.debug("Starting Protocols failed")
            self.errored("Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Started Protocols Successfully")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_APPLY_TRAFFIC(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['next_tc'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_VERIFY_IXIA_TRAFFIC(aetest.Testcase):
    """IXIA_TRAFFIC_VERIFICATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class Start_Ixia_Traffic(aetest.Testcase):
    """ Start_Ixia_Traffic """

    @aetest.test
    def Start_Ixia_Traffic(self, testscript):
        """ Start_Ixia_Traffic """

        if ixLib.start_traffic() == 0:
            log.debug("Starting Traffic failed")
            self.failed("Starting Traffic failed", goto=['cleanup'])

# *****************************************************************************************************************************#

class VERIFY_NETWORK_POST_TRAFFIC(aetest.Testcase):
    """VERIFY_NETWORK_POST_TRAFFIC"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict1'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict1'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class VERIFY_VNI_TO_EGR_VNI_MAP_LEAF1(aetest.Testcase):
    """VERIFY_VNI_TO_EGR_VNI_MAP_LEAF1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def verify_vni_to_egr_vni_map(self, testscript):
        """ VERIFY_VNI_EGR_VNI_MAP subsection: Verify VNI to Egress VNI Mapping """

        log.info(banner("MultiSite DSVNI Functional Testing Block LEAF"))

        fail_flag = []
        status_msgs = '\n'
        
        LEAF_1 = testscript.parameters['LEAF-1']

        l2vni_1 = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']
        l2vni_3 = str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 2)
        l3vni_1 = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vni_start']

        l2_vni_1 = json.loads(testscript.parameters['LEAF-1'].execute('''sh nve peers control-plane-vni vni ''' + str(l2vni_1) + ''' | json'''))

        l2_vni_2 = json.loads(testscript.parameters['LEAF-1'].execute("sh nve peers control-plane-vni vni 40018 | json"))

        l2_vni_3 = json.loads(testscript.parameters['LEAF-1'].execute('''sh nve peers control-plane-vni vni ''' + str(l2vni_3) + ''' | json'''))

        l2_vni_4 = json.loads(testscript.parameters['LEAF-1'].execute('''sh nve peers control-plane-vni vni 40020 | json'''))

        l3_vni_1 = json.loads(testscript.parameters['LEAF-1'].execute('''sh nve peers control-plane-vni vni ''' + str(l3vni_1) + ''' | json'''))

        l3_vni_2 = json.loads(testscript.parameters['LEAF-1'].execute('''sh nve peers control-plane-vni vni 40038 | json'''))

        peerip_1 = testscript.parameters['BGW_1_dict']['NVE_data']['VTEP_IP']
        peerip_2 = '10.101.101.101'

        dsvni_counter = []
        for item in l2_vni_1['TABLE_nve_peers']['ROW_nve_peers']:
            if "peer-ip" in item.keys():
                if item['peer-ip'] == peerip_1:
                    local_l2vni_11 = item['vni']
                    egress_l2vni_11 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l2vni_11 == egress_l2vni_11:
                        log.info("PASS : L2VNI '" + str(local_l2vni_11) + "' and '" + str(egress_l2vni_11) + "' is Mapping Correctly\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_l2vni_11) + "' and '" + str(egress_l2vni_11) + "' is Mapping Correctly\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_l2vni_11) + "' and '" + str(egress_l2vni_11) + "' is NOT Mapping\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_l2vni_11) + "' and '" + str(egress_l2vni_11) + "' is NOT Mapping\n\n"
                        fail_flag.append(0)
                elif item['peer-ip'] == peerip_2:
                    local_l2vni_12 = item['vni']
                    egress_l2vni_12 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l2vni_12 == egress_l2vni_12:
                        log.info("PASS : L2VNI '" + str(local_l2vni_12) + "' and '" + str(egress_l2vni_12) + "' is Mapping to Correct DSVNI\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_l2vni_12) + "' and '" + str(egress_l2vni_12) + "' is Mapping to Correct DSVNI\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_l2vni_12) + "' and '" + str(egress_l2vni_12) + "' is NOT Mapping to Correct DSVNI\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_l2vni_12) + "' and '" + str(egress_l2vni_12) + "' is NOT Mapping to Correct DSVNI\n\n"
                        fail_flag.append(0)
        if dsvni_counter == []:
            log.debug("FAIL : Did not find any DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find any DSVNI Mapping\n\n"
            fail_flag.append(0)
        elif len(dsvni_counter) != 2:
            log.debug("FAIL : Did not find all needed DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find all needed Mapping\n\n"
            fail_flag.append(0)

        dsvni_counter = []
        for item in l2_vni_2['TABLE_nve_peers']['ROW_nve_peers']:
            if "peer-ip" in item.keys():
                if item['peer-ip'] == peerip_1:
                    local_l2vni_21 = item['vni']
                    egress_l2vni_21 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l2vni_21 != egress_l2vni_21:
                        log.info("PASS : L2VNI '" + str(local_l2vni_21) + "' and '" + str(egress_l2vni_21) + "' is Mapping Correctly\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_l2vni_21) + "' and '" + str(egress_l2vni_21) + "' is Mapping Correctly\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_l2vni_21) + "' and '" + str(egress_l2vni_21) + "' is NOT Mapping\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_l2vni_21) + "' and '" + str(egress_l2vni_21) + "' is NOT Mapping\n\n"
                        fail_flag.append(0)
                elif item['peer-ip'] == peerip_2:
                    local_l2vni_22 = item['vni']
                    egress_l2vni_22 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l2vni_22 != egress_l2vni_22:
                        log.info("PASS : L2VNI '" + str(local_l2vni_22) + "' and '" + str(egress_l2vni_22) + "' is Mapping to Correct DSVNI\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_l2vni_22) + "' and '" + str(egress_l2vni_22) + "' is Mapping to Correct DSVNI\n\n"

                    else:
                        log.debug("FAIL : L2VNI '" + str(local_l2vni_22) + "' and '" + str(egress_l2vni_22) + "' is NOT Mapping to Correct DSVNI\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_l2vni_22) + "' and '" + str(egress_l2vni_22) + "' is NOT Mapping to Correct DSVNI\n\n"
                        fail_flag.append(0)
        if dsvni_counter == []:
            log.debug("FAIL : Did not find any DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find any DSVNI Mapping\n\n"
            fail_flag.append(0)
        elif len(dsvni_counter) != 2:
            log.debug("FAIL : Did not find all needed DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find all needed Mapping\n\n"
            fail_flag.append(0)

        dsvni_counter = []
        for item in l2_vni_3['TABLE_nve_peers']['ROW_nve_peers']:
            if "peer-ip" in item.keys():
                if item['peer-ip'] == peerip_1:
                    local_l2vni_31 = item['vni']
                    egress_l2vni_31 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l2vni_31 == egress_l2vni_31:
                        log.info("PASS : L2VNI '" + str(local_l2vni_31) + "' and '" + str(egress_l2vni_31) + "' is Mapping Correctly\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_l2vni_31) + "' and '" + str(egress_l2vni_31) + "' is Mapping Correctly\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_l2vni_31) + "' and '" + str(egress_l2vni_31) + "' is NOT Mapping\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_l2vni_31) + "' and '" + str(egress_l2vni_31) + "' is NOT Mapping\n\n"
                        fail_flag.append(0)
                elif item['peer-ip'] == peerip_2:
                    local_l2vni_32 = item['vni']
                    egress_l2vni_32 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l2vni_32 == egress_l2vni_32:
                        log.info("PASS : L2VNI '" + str(local_l2vni_32) + "' and '" + str(egress_l2vni_32) + "' is Mapping to Correct DSVNI\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_l2vni_32) + "' and '" + str(egress_l2vni_32) + "' is Mapping to Correct DSVNI\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_l2vni_32) + "' and '" + str(egress_l2vni_32) + "' is NOT Mapping to Correct DSVNI\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_l2vni_32) + "' and '" + str(egress_l2vni_32) + "' is NOT Mapping to Correct DSVNI\n\n"
                        fail_flag.append(0)
        if dsvni_counter == []:
            log.debug("FAIL : Did not find any DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find any DSVNI Mapping\n\n"
            fail_flag.append(0)
        elif len(dsvni_counter) != 2:
            log.debug("FAIL : Did not find all needed DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find all needed Mapping\n\n"
            fail_flag.append(0)

        dsvni_counter = []
        for item in l2_vni_4['TABLE_nve_peers']['ROW_nve_peers']:
            if "peer-ip" in item.keys():
                if item['peer-ip'] == peerip_1:
                    local_l2vni_41 = item['vni']
                    egress_l2vni_41 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l2vni_41 != egress_l2vni_41:
                        log.info("PASS : L2VNI '" + str(local_l2vni_41) + "' and '" + str(egress_l2vni_41) + "' is Mapping Correctly\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_l2vni_41) + "' and '" + str(egress_l2vni_41) + "' is Mapping Correctly\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_l2vni_41) + "' and '" + str(egress_l2vni_41) + "' is NOT Mapping\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_l2vni_41) + "' and '" + str(egress_l2vni_41) + "' is NOT Mapping\n\n"
                        fail_flag.append(0)
                elif item['peer-ip'] == peerip_2:
                    local_l2vni_42 = item['vni']
                    egress_l2vni_42 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l2vni_42 != egress_l2vni_32:
                        log.info("PASS : L2VNI '" + str(local_l2vni_42) + "' and '" + str(egress_l2vni_42) + "' is Mapping to Correct DSVNI\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_l2vni_42) + "' and '" + str(egress_l2vni_42) + "' is Mapping to Correct DSVNI\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_l2vni_42) + "' and '" + str(egress_l2vni_42) + "' is NOT Mapping to Correct DSVNI\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_l2vni_42) + "' and '" + str(egress_l2vni_42) + "' is NOT Mapping to Correct DSVNI\n\n"
                        fail_flag.append(0)
        if dsvni_counter == []:
            log.debug("FAIL : Did not find any DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find any DSVNI Mapping\n\n"
            fail_flag.append(0)
        elif len(dsvni_counter) != 2:
            log.debug("FAIL : Did not find all needed DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find all needed Mapping\n\n"
            fail_flag.append(0)

        dsvni_counter = []
        for item in l3_vni_1['TABLE_nve_peers']['ROW_nve_peers']:
            if "peer-ip" in item.keys():
                if item['peer-ip'] == peerip_1:
                    local_l3vni_11 = item['vni']
                    egress_l3vni_11 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l3vni_11 == egress_l3vni_11:
                        log.info("PASS : L3VNI '" + str(local_l3vni_11) + "' and '" + str(egress_l3vni_11) + "' is Mapping Correctly\n\n")
                        status_msgs+="PASS : L3VNI '" + str(local_l3vni_11) + "' and '" + str(egress_l3vni_11) + "' is Mapping Correctly\n\n"
                    else:
                        log.debug("FAIL : L3VNI '" + str(local_l3vni_11) + "' and '" + str(egress_l3vni_11) + "' is NOT Mapping\n\n")
                        status_msgs+="FAIL : L3VNI '" + str(local_l3vni_11) + "' and '" + str(egress_l3vni_11) + "' is NOT Mapping\n\n"
                        fail_flag.append(0)
                elif item['peer-ip'] == peerip_2:
                    local_l3vni_12 = item['vni']
                    egress_l3vni_12 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l3vni_12 == egress_l3vni_12:
                        log.info("PASS : L3VNI '" + str(local_l3vni_12) + "' and '" + str(egress_l3vni_12) + "' is Mapping Correctly\n\n")
                        status_msgs+="PASS : L3VNI '" + str(local_l3vni_12) + "' and '" + str(egress_l3vni_12) + "' is Mapping Correctly\n\n"
                    else:
                        log.debug("FAIL : L3VNI '" + str(local_l3vni_12) + "' and '" + str(egress_l3vni_12) + "' is NOT Mapping\n\n")
                        status_msgs+="FAIL : L3VNI '" + str(local_l3vni_12) + "' and '" + str(egress_l3vni_12) + "' is NOT Mapping\n\n"
                        fail_flag.append(0)
        if dsvni_counter == []:
            log.debug("FAIL : Did not find any DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find any DSVNI Mapping\n\n"
            fail_flag.append(0)
        elif len(dsvni_counter) != 2:
            log.debug("FAIL : Did not find all needed DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find all needed Mapping\n\n"
            fail_flag.append(0)

        dsvni_counter = []
        for item in l3_vni_2['TABLE_nve_peers']['ROW_nve_peers']:
            if "peer-ip" in item.keys():
                if item['peer-ip'] == peerip_1:
                    local_l3vni_21 = item['vni']
                    egress_l3vni_21 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l3vni_21 != egress_l3vni_21:
                        log.info("PASS : L3VNI '" + str(local_l3vni_21) + "' and '" + str(egress_l3vni_21) + "' is Mapping to Correct DSVNI\n\n")
                        status_msgs+="PASS : L3VNI '" + str(local_l3vni_21) + "' and '" + str(egress_l3vni_21) + "' is Mapping to Correct DSVNI\n\n"
                    else:
                        log.debug("FAIL : L3VNI '" + str(local_l3vni_21) + "' and '" + str(egress_l3vni_21) + "' is NOT Mapping to Correct DSVNI\n\n")
                        status_msgs+="FAIL : L3VNI '" + str(local_l3vni_21) + "' and '" + str(egress_l3vni_21) + "' is NOT Mapping to Correct DSVNI\n\n"
                        fail_flag.append(0)
                elif item['peer-ip'] == peerip_2:
                    local_l3vni_22 = item['vni']
                    egress_l3vni_22 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l3vni_22 != egress_l3vni_22:
                        log.info("PASS : L3VNI '" + str(local_l3vni_22) + "' and '" + str(egress_l3vni_22) + "' is Mapping to Correct DSVNI\n\n")
                        status_msgs+="PASS : L3VNI '" + str(local_l3vni_22) + "' and '" + str(egress_l3vni_22) + "' is Mapping to Correct DSVNI\n\n"
                    else:
                        log.debug("FAIL : L3VNI '" + str(local_l3vni_22) + "' and '" + str(egress_l3vni_22) + "' is NOT Mapping to Correct DSVNI\n\n")
                        status_msgs+="FAIL : L3VNI '" + str(local_l3vni_22) + "' and '" + str(egress_l3vni_22) + "' is NOT Mapping to Correct DSVNI\n\n"
                        fail_flag.append(0)
        if dsvni_counter == []:
            log.debug("FAIL : Did not find any DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find any DSVNI Mapping\n\n"
            fail_flag.append(0)
        elif len(dsvni_counter) != 2:
            log.debug("FAIL : Did not find all needed DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find all needed Mapping\n\n"
            fail_flag.append(0)

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if 0 in status['status']:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class VERIFY_VLAN_DSVNI_LEAF1(aetest.Testcase):
    """VERIFY_VLAN_DSVNI_LEAF1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def verify_vlan_dsvni(self, testscript):
        """ VERIFY_VLAN_DSVNI subsection: Verify VLAN Flood-List is DSVNI or NOT """

        fail_flag = []
        status_msgs = '\n'
        
        LEAF_1 = testscript.parameters['LEAF-1']

        vlan_1 = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        vlan_2 = str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start'] + 1))
        vlan_3 = str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start'] + 2))
        vlan_4 = str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start'] + 3))

        vlan_dsvni_1 = testscript.parameters['LEAF-1'].execute('''show forwarding internal nve vlan-floodlist ''' + str(vlan_1) + ''' | grep DSVNI''')

        vlan_dsvni_2 = testscript.parameters['LEAF-1'].execute('''show forwarding internal nve vlan-floodlist ''' + str(vlan_2) + ''' | grep DSVNI''')

        vlan_dsvni_3 = testscript.parameters['LEAF-1'].execute('''show forwarding internal nve vlan-floodlist ''' + str(vlan_3) + ''' | grep DSVNI''')

        vlan_dsvni_4 = testscript.parameters['LEAF-1'].execute('''show forwarding internal nve vlan-floodlist ''' + str(vlan_4) + ''' | grep DSVNI''')

        if "DSVNI: FALSE" in vlan_dsvni_1:
            log.info("PASS : peer in the flood list '" + str(vlan_1) + "' is NOT DSVNI/Asymmetric\n\n")
            status_msgs+="PASS : peer in the flood list '" + str(vlan_1) + "' is NOT DSVNI/Asymmetric\n\n"
        else:
            log.debug("FAIL : peer in the flood list '" + str(vlan_1) + "' is DSVNI/Asymmetric\n\n")
            status_msgs+="FAIL : peer in the flood list '" + str(vlan_1) + "' is DSVNI/Asymmetric\n\n"
            fail_flag.append(0)

        if "DSVNI: TRUE" in vlan_dsvni_2:
            log.info("PASS : peer in the flood list '" + str(vlan_2) + "' is DSVNI/Asymmetric\n\n")
            status_msgs+="PASS : peer in the flood list '" + str(vlan_2) + "' is DSVNI/Asymmetric\n\n"
        else:
            log.debug("FAIL : peer in the flood list '" + str(vlan_2) + "' is NOT DSVNI/Asymmetric\n\n")
            status_msgs+="FAIL : peer in the flood list '" + str(vlan_2) + "' is NOT DSVNI/Asymmetric\n\n"
            fail_flag.append(0)

        if "DSVNI: FALSE" in vlan_dsvni_3:
            log.info("PASS : peer in the flood list '" + str(vlan_3) + "' is NOT DSVNI/Asymmetric\n\n")
            status_msgs+="PASS : peer in the flood list '" + str(vlan_3) + "' is NOT DSVNI/Asymmetric\n\n"
        else:
            log.debug("FAIL : peer in the flood list '" + str(vlan_3) + "' is DSVNI/Asymmetric\n\n")
            status_msgs+="FAIL : peer in the flood list '" + str(vlan_3) + "' is DSVNI/Asymmetric\n\n"
            fail_flag.append(0)

        if "DSVNI: TRUE" in vlan_dsvni_4:
            log.info("PASS : peer in the flood list '" + str(vlan_4) + "' is DSVNI/Asymmetric\n\n")
            status_msgs+="PASS : peer in the flood list '" + str(vlan_4) + "' is DSVNI/Asymmetric\n\n"
        else:
            log.debug("FAIL : peer in the flood list '" + str(vlan_4) + "' is NOT DSVNI/Asymmetric\n\n")
            status_msgs+="FAIL : peer in the flood list '" + str(vlan_4) + "' is NOT DSVNI/Asymmetric\n\n"
            fail_flag.append(0)

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if 0 in status['status']:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class VERIFY_NextHop_DSVNI_LEAF1(aetest.Testcase):
    """VERIFY_NextHop_DSVNI_LEAF1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def VERIFY_NextHop_DSVNI(self, testscript):
        """ VERIFY_NextHop_DSVNI subsection: Verify Next Hop DSVNI or VNI """

        fail_flag = []
        status_msgs = '\n'

        LEAF_1 = testscript.parameters['LEAF-1']

        ip_addr_11 = '2.1.3.20/32'

        dsvni_11 = json.loads(testscript.parameters['LEAF-1'].execute('''sh forwarding route ''' + ip_addr_11 + ''' vrf EVPN-VRF-38 | json'''))

        dsvni_true_11 = dsvni_11['TABLE_module']['ROW_module']['DownStream']

        if "dsvni" in dsvni_true_11:
            log.info("PASS : Host Route Next Hop is DSVNI : '" + dsvni_11['TABLE_module']['ROW_module']['VNI'] + "'\n\n")
            status_msgs+="PASS : Host Route Next Hop is DSVNI : '" + dsvni_11['TABLE_module']['ROW_module']['VNI'] + "'\n\n"
        else:
            log.debug("FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_11['TABLE_module']['ROW_module']['VNI'] + "'\n\n")
            status_msgs+="FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_11['TABLE_module']['ROW_module']['VNI'] + "'\n\n"
            fail_flag.append(0)

        ip_addr_21 = '2.1.4.20/32'

        dsvni_21 = json.loads(testscript.parameters['LEAF-1'].execute('''sh forwarding route ''' + ip_addr_21 + ''' vrf EVPN-VRF-38 | json'''))

        dsvni_true_21 = dsvni_21['TABLE_module']['ROW_module']['DownStream']

        if "dsvni" in dsvni_true_21:
            log.info("PASS : Host Route Next Hop is DSVNI : '" + dsvni_21['TABLE_module']['ROW_module']['VNI'] + "'\n\n")
            status_msgs+="PASS : Host Route Next Hop is DSVNI : '" + dsvni_21['TABLE_module']['ROW_module']['VNI'] + "'\n\n"
        else:
            log.debug("FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_21['TABLE_module']['ROW_module']['VNI'] + "'\n\n")
            status_msgs+="FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_21['TABLE_module']['ROW_module']['VNI'] + "'\n\n"
            fail_flag.append(0)

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if 0 in status['status']:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class VERIFY_Symmetric_Route_LEAF1(aetest.Testcase):
    """VERIFY_Symmetric_Route_LEAF1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def VERIFY_Symmetric_Route(self, testscript):
        """ VERIFY_Symmetric_Route subsection: Verify Symmetric Route """

        fail_flag = []
        status_msgs = '\n'

        LEAF_1 = testscript.parameters['LEAF-1']

        ip_addr_11 = '2.1.1.20/32'

        sym_rt_11 = testscript.parameters['LEAF-1'].execute('''show ip route ''' + ip_addr_11 + ''' vrf EVPN-VRF-37''')

        if "Asymmetric" not in sym_rt_11:
            log.info("PASS : Host Route '" + ip_addr_11 + "' is Symmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_11 + "' is Symmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_11 + "' is NOT Symmetric\n\n")
            fail_flag.append(0)
            status_msgs +="FAIL : Host Route '" + ip_addr_11 + "' is NOT Symmetric\n\n"

        ip_addr_21 = '2.1.2.20/32'

        sym_rt_21 = testscript.parameters['LEAF-1'].execute('''show ip route ''' + ip_addr_21 + ''' vrf EVPN-VRF-37''')

        if "Asymmetric" not in sym_rt_21:
            log.info("PASS : Host Route '" + ip_addr_21 + "' is Symmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_21 + "' is Symmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_21 + "' is NOT Symmetric\n\n")
            fail_flag.append(0)
            status_msgs+="FAIL : Host Route '" + ip_addr_21 + "' is NOT Symmetric\n\n"

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if 0 in status['status']:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class VERIFY_Asymmetric_Route_LEAF1(aetest.Testcase):
    """VERIFY_Asymmetric_Route_LEAF1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def VERIFY_Asymmetric_Route(self, testscript):
        """ VERIFY_Asymmetric_Route subsection: Verify Asymmetric Route """

        fail_flag = []
        status_msgs = '\n'
        
        LEAF_1 = testscript.parameters['LEAF-1']

        ip_addr_11 = '2.1.3.20/32'

        sym_rt_11 = testscript.parameters['LEAF-1'].execute('''show ip route ''' + ip_addr_11 + ''' vrf EVPN-VRF-38''')

        if "Asymmetric" in sym_rt_11:
            log.info("PASS : Host Route '" + ip_addr_11 + "' is Asymmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_11 + "' is Asymmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_11 + "' is NOT Asymmetric\n\n")
            fail_flag.append(0)
            status_msgs+="FAIL : Host Route '" + ip_addr_11 + "' is NOT Asymmetric\n\n"

        ip_addr_21 = '2.1.4.20/32'

        sym_rt_21 = testscript.parameters['LEAF-1'].execute('''show ip route ''' + ip_addr_21 + ''' vrf EVPN-VRF-38''')

        if "Asymmetric" in sym_rt_21:
            log.info("PASS : Host Route '" + ip_addr_21 + "' is Asymmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_21 + "' is Asymmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_21 + "' is NOT Asymmetric\n\n")
            fail_flag.append(0)
            status_msgs+="FAIL : Host Route '" + ip_addr_21 + "' is NOT Asymmetric\n\n"

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if 0 in status['status']:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class VERIFY_VNI_TO_EGR_VNI_MAP_BGW2(aetest.Testcase):
    """VERIFY_VNI_TO_EGR_VNI_MAP_BGW2"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def verify_vni_to_egr_vni_map(self, testscript):
        """ VERIFY_VNI_EGR_VNI_MAP subsection: Verify VNI to Egress VNI Mapping """

        log.info(banner("MultiSite DSVNI Functional Testing Block on BGW"))

        fail_flag = []
        status_msgs = '\n'
        
        BGW_2 = testscript.parameters['BGW-2']

        l2vni_1 = testscript.parameters['BGW_2_dict']['VNI_data']['l2_vni_start']
        l2vni_3 = str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vni_start']) + 2)
        l3vni_1 = testscript.parameters['BGW_2_dict']['VNI_data']['l3_vni_start']

        l2_vni_1 = json.loads(testscript.parameters['BGW-2'].execute('''sh nve peers control-plane-vni vni ''' + str(l2vni_1) + ''' | json'''))

        l2_vni_2 = json.loads(testscript.parameters['BGW-2'].execute("sh nve peers control-plane-vni vni 40018 | json"))

        l2_vni_3 = json.loads(testscript.parameters['BGW-2'].execute('''sh nve peers control-plane-vni vni ''' + str(l2vni_3) + ''' | json'''))

        l2_vni_4 = json.loads(testscript.parameters['BGW-2'].execute('''sh nve peers control-plane-vni vni 40020 | json'''))

        l3_vni_1 = json.loads(testscript.parameters['BGW-2'].execute('''sh nve peers control-plane-vni vni ''' + str(l3vni_1) + ''' | json'''))

        l3_vni_2 = json.loads(testscript.parameters['BGW-2'].execute('''sh nve peers control-plane-vni vni 40038 | json'''))

        peerip_1 = testscript.parameters['BGW_1_dict']['NVE_data']['VTEP_IP']
        peerip_2 = testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP']

        dsvni_counter = []
        for item in l2_vni_1['TABLE_nve_peers']['ROW_nve_peers']:
            if "peer-ip" in item.keys():
                if item['peer-ip'] == peerip_1:
                    local_l2vni_11 = item['vni']
                    egress_l2vni_11 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l2vni_11 == egress_l2vni_11:
                        log.info("PASS : L2VNI '" + str(local_l2vni_11) + "' and '" + str(egress_l2vni_11) + "' is Mapping Correctly\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_l2vni_11) + "' and '" + str(egress_l2vni_11) + "' is Mapping Correctly\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_l2vni_11) + "' and '" + str(egress_l2vni_11) + "' is NOT Mapping\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_l2vni_11) + "' and '" + str(egress_l2vni_11) + "' is NOT Mapping\n\n"
                        fail_flag.append(0)
                elif item['peer-ip'] == peerip_2:
                    local_l2vni_12 = item['vni']
                    egress_l2vni_12 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l2vni_12 == egress_l2vni_12:
                        log.info("PASS : L2VNI '" + str(local_l2vni_12) + "' and '" + str(egress_l2vni_12) + "' is Mapping to Correct DSVNI\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_l2vni_12) + "' and '" + str(egress_l2vni_12) + "' is Mapping to Correct DSVNI\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_l2vni_12) + "' and '" + str(egress_l2vni_12) + "' is NOT Mapping to Correct DSVNI\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_l2vni_12) + "' and '" + str(egress_l2vni_12) + "' is NOT Mapping to Correct DSVNI\n\n"
                        fail_flag.append(0)
        if dsvni_counter == []:
            log.debug("FAIL : Did not find any DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find any DSVNI Mapping\n\n"
            fail_flag.append(0)
        elif len(dsvni_counter) != 2:
            log.debug("FAIL : Did not find all needed DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find all needed Mapping\n\n"
            fail_flag.append(0)

        dsvni_counter = []
        for item in l2_vni_2['TABLE_nve_peers']['ROW_nve_peers']:
            if "peer-ip" in item.keys():
                if item['peer-ip'] == peerip_1:
                    local_l2vni_21 = item['vni']
                    egress_l2vni_21 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l2vni_21 != egress_l2vni_21:
                        log.info("PASS : L2VNI '" + str(local_l2vni_21) + "' and '" + str(egress_l2vni_21) + "' is Mapping Correctly\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_l2vni_21) + "' and '" + str(egress_l2vni_21) + "' is Mapping Correctly\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_l2vni_21) + "' and '" + str(egress_l2vni_21) + "' is NOT Mapping\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_l2vni_21) + "' and '" + str(egress_l2vni_21) + "' is NOT Mapping\n\n"
                        fail_flag.append(0)
                elif item['peer-ip'] == peerip_2:
                    local_l2vni_22 = item['vni']
                    egress_l2vni_22 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l2vni_22 != egress_l2vni_22:
                        log.info("PASS : L2VNI '" + str(local_l2vni_22) + "' and '" + str(egress_l2vni_22) + "' is Mapping to Correct DSVNI\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_l2vni_22) + "' and '" + str(egress_l2vni_22) + "' is Mapping to Correct DSVNI\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_l2vni_22) + "' and '" + str(egress_l2vni_22) + "' is NOT Mapping to Correct DSVNI\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_l2vni_22) + "' and '" + str(egress_l2vni_22) + "' is NOT Mapping to Correct DSVNI\n\n"
                        fail_flag.append(0)
        if dsvni_counter == []:
            log.debug("FAIL : Did not find any DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find any DSVNI Mapping\n\n"
            fail_flag.append(0)
        elif len(dsvni_counter) != 2:
            log.debug("FAIL : Did not find all needed DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find all needed Mapping\n\n"
            fail_flag.append(0)

        l2vni_31 = evnis(l2_vni_3, peerip_1)
        l2vni_32 = evnis(l2_vni_3, peerip_2)

        dsvni_counter = []
        for item in l2_vni_3['TABLE_nve_peers']['ROW_nve_peers']:
            if "peer-ip" in item.keys():
                if item['peer-ip'] == peerip_1:
                    local_l2vni_31 = item['vni']
                    egress_l2vni_31 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l2vni_31 == egress_l2vni_31:
                        log.info("PASS : L2VNI '" + str(local_l2vni_31) + "' and '" + str(egress_l2vni_31) + "' is Mapping Correctly\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_l2vni_31) + "' and '" + str(egress_l2vni_31) + "' is Mapping Correctly\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_l2vni_31) + "' and '" + str(egress_l2vni_31) + "' is NOT Mapping\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_l2vni_31) + "' and '" + str(egress_l2vni_31) + "' is NOT Mapping\n\n"
                        fail_flag.append(0)
                elif item['peer-ip'] == peerip_2:
                    local_l2vni_32 = item['vni']
                    egress_l2vni_32 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l2vni_32 == egress_l2vni_32:
                        log.info("PASS : L2VNI '" + str(local_l2vni_32) + "' and '" + str(egress_l2vni_32) + "' is Mapping to Correct DSVNI\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_l2vni_32) + "' and '" + str(egress_l2vni_32) + "' is Mapping to Correct DSVNI\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_l2vni_32) + "' and '" + str(egress_l2vni_32) + "' is NOT Mapping to Correct DSVNI\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_l2vni_32) + "' and '" + str(egress_l2vni_32) + "' is NOT Mapping to Correct DSVNI\n\n"
                        fail_flag.append(0)
        if dsvni_counter == []:
            log.debug("FAIL : Did not find any DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find any DSVNI Mapping\n\n"
            fail_flag.append(0)
        elif len(dsvni_counter) != 2:
            log.debug("FAIL : Did not find all needed DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find all needed Mapping\n\n"
            fail_flag.append(0)

        l2vni_41 = evnis(l2_vni_4, peerip_1)
        l2vni_42 = evnis(l2_vni_4, peerip_2)

        dsvni_counter = []
        for item in l2_vni_4['TABLE_nve_peers']['ROW_nve_peers']:
            if "peer-ip" in item.keys():
                if item['peer-ip'] == peerip_1:
                    local_l2vni_41 = item['vni']
                    egress_l2vni_41 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l2vni_41 != egress_l2vni_41:
                        log.info("PASS : L2VNI '" + str(local_l2vni_41) + "' and '" + str(egress_l2vni_41) + "' is Mapping Correctly\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_l2vni_41) + "' and '" + str(egress_l2vni_41) + "' is Mapping Correctly\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_l2vni_41) + "' and '" + str(egress_l2vni_41) + "' is NOT Mapping\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_l2vni_41) + "' and '" + str(egress_l2vni_41) + "' is NOT Mapping\n\n"
                        fail_flag.append(0)
                elif item['peer-ip'] == peerip_2:
                    local_l2vni_42 = item['vni']
                    egress_l2vni_42 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l2vni_42 != egress_l2vni_32:
                        log.info("PASS : L2VNI '" + str(local_l2vni_42) + "' and '" + str(egress_l2vni_42) + "' is Mapping to Correct DSVNI\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_l2vni_42) + "' and '" + str(egress_l2vni_42) + "' is Mapping to Correct DSVNI\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_l2vni_42) + "' and '" + str(egress_l2vni_42) + "' is NOT Mapping to Correct DSVNI\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_l2vni_42) + "' and '" + str(egress_l2vni_42) + "' is NOT Mapping to Correct DSVNI\n\n"
                        fail_flag.append(0)
        if dsvni_counter == []:
            log.debug("FAIL : Did not find any DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find any DSVNI Mapping\n\n"
            fail_flag.append(0)
        elif len(dsvni_counter) != 2:
            log.debug("FAIL : Did not find all needed DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find all needed Mapping\n\n"
            fail_flag.append(0)

        l3vni_11 = evnis(l3_vni_1, peerip_1)
        l3vni_12 = evnis(l3_vni_1, peerip_2)

        dsvni_counter = []
        for item in l3_vni_1['TABLE_nve_peers']['ROW_nve_peers']:
            if "peer-ip" in item.keys():
                if item['peer-ip'] == peerip_1:
                    local_l3vni_11 = item['vni']
                    egress_l3vni_11 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l3vni_11 == egress_l3vni_11:
                        log.info("PASS : L3VNI '" + str(local_l3vni_11) + "' and '" + str(egress_l3vni_11) + "' is Mapping Correctly\n\n")
                        status_msgs+="PASS : L3VNI '" + str(local_l3vni_11) + "' and '" + str(egress_l3vni_11) + "' is Mapping Correctly\n\n"
                    else:
                        log.debug("FAIL : L3VNI '" + str(local_l3vni_11) + "' and '" + str(egress_l3vni_11) + "' is NOT Mapping\n\n")
                        status_msgs+="FAIL : L3VNI '" + str(local_l3vni_11) + "' and '" + str(egress_l3vni_11) + "' is NOT Mapping\n\n"
                        fail_flag.append(0)
                elif item['peer-ip'] == peerip_2:
                    local_l3vni_12 = item['vni']
                    egress_l3vni_12 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l3vni_12 == egress_l3vni_12:
                        log.info("PASS : L3VNI '" + str(local_l3vni_12) + "' and '" + str(egress_l3vni_12) + "' is Mapping Correctly\n\n")
                        status_msgs+="PASS : L3VNI '" + str(local_l3vni_12) + "' and '" + str(egress_l3vni_12) + "' is Mapping Correctly\n\n"
                    else:
                        log.debug("FAIL : L3VNI '" + str(local_l3vni_12) + "' and '" + str(egress_l3vni_12) + "' is NOT Mapping\n\n")
                        status_msgs+="FAIL : L3VNI '" + str(local_l3vni_12) + "' and '" + str(egress_l3vni_12) + "' is NOT Mapping\n\n"
                        fail_flag.append(0)
        if dsvni_counter == []:
            log.debug("FAIL : Did not find any DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find any DSVNI Mapping\n\n"
            fail_flag.append(0)
        elif len(dsvni_counter) != 2:
            log.debug("FAIL : Did not find all needed DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find all needed Mapping\n\n"
            fail_flag.append(0)

        l3vni_21 = evnis(l3_vni_2, peerip_1)
        l3vni_22 = evnis(l3_vni_2, peerip_2)

        dsvni_counter = []
        for item in l3_vni_2['TABLE_nve_peers']['ROW_nve_peers']:
            if "peer-ip" in item.keys():
                if item['peer-ip'] == peerip_1:
                    local_l3vni_21 = item['vni']
                    egress_l3vni_21 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l3vni_21 != egress_l3vni_21:
                        log.info("PASS : L3VNI '" + str(local_l3vni_21) + "' and '" + str(egress_l3vni_21) + "' is Mapping to Correct DSVNI\n\n")
                        status_msgs+="PASS : L3VNI '" + str(local_l3vni_21) + "' and '" + str(egress_l3vni_21) + "' is Mapping to Correct DSVNI\n\n"
                    else:
                        log.debug("FAIL : L3VNI '" + str(local_l3vni_21) + "' and '" + str(egress_l3vni_21) + "' is NOT Mapping to Correct DSVNI\n\n")
                        status_msgs+="FAIL : L3VNI '" + str(local_l3vni_21) + "' and '" + str(egress_l3vni_21) + "' is NOT Mapping to Correct DSVNI\n\n"
                        fail_flag.append(0)
                elif item['peer-ip'] == peerip_2:
                    local_l3vni_22 = item['vni']
                    egress_l3vni_22 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l3vni_22 != egress_l3vni_22:
                        log.info("PASS : L3VNI '" + str(local_l3vni_22) + "' and '" + str(egress_l3vni_22) + "' is Mapping to Correct DSVNI\n\n")
                        status_msgs+="PASS : L3VNI '" + str(local_l3vni_22) + "' and '" + str(egress_l3vni_22) + "' is Mapping to Correct DSVNI\n\n"
                    else:
                        log.debug("FAIL : L3VNI '" + str(local_l3vni_22) + "' and '" + str(egress_l3vni_22) + "' is NOT Mapping to Correct DSVNI\n\n")
                        status_msgs+="FAIL : L3VNI '" + str(local_l3vni_22) + "' and '" + str(egress_l3vni_22) + "' is NOT Mapping to Correct DSVNI\n\n"
                        fail_flag.append(0)
        if dsvni_counter == []:
            log.debug("FAIL : Did not find any DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find any DSVNI Mapping\n\n"
            fail_flag.append(0)
        elif len(dsvni_counter) != 2:
            log.debug("FAIL : Did not find all needed DSVNI Mapping\n\n")
            status_msgs+="FAIL : Did not find all needed Mapping\n\n"
            fail_flag.append(0)

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if 0 in status['status']:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class VERIFY_VLAN_DSVNI_BGW2(aetest.Testcase):
    """VERIFY_VLAN_DSVNI_BGW2"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def verify_vlan_dsvni(self, testscript):
        """ VERIFY_VLAN_DSVNI subsection: Verify VLAN Flood-List is DSVNI or NOT """

        fail_flag = []
        status_msgs = '\n'
        
        BGW_2 = testscript.parameters['BGW-2']

        vlan_1 = testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']
        vlan_2 = str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start'] + 1))
        vlan_3 = str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start'] + 2))
        vlan_4 = str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start'] + 3))

        vlan_dsvni_1 = testscript.parameters['BGW-2'].execute('''show forwarding internal nve vlan-floodlist ''' + str(vlan_1) + ''' | grep DSVNI''')

        vlan_dsvni_2 = testscript.parameters['BGW-2'].execute('''show forwarding internal nve vlan-floodlist ''' + str(vlan_2) + ''' | grep DSVNI''')

        vlan_dsvni_3 = testscript.parameters['BGW-2'].execute('''show forwarding internal nve vlan-floodlist ''' + str(vlan_3) + ''' | grep DSVNI''')

        vlan_dsvni_4 = testscript.parameters['BGW-2'].execute('''show forwarding internal nve vlan-floodlist ''' + str(vlan_4) + ''' | grep DSVNI''')

        if "DSVNI: FALSE" in vlan_dsvni_1:
            log.info("PASS : peer in the flood list '" + str(vlan_1) + "' is NOT DSVNI/Asymmetric\n\n")
            status_msgs+="PASS : peer in the flood list '" + str(vlan_1) + "' is NOT DSVNI/Asymmetric\n\n"
        else:
            log.debug("FAIL : peer in the flood list '" + str(vlan_1) + "' is DSVNI/Asymmetric\n\n")
            status_msgs+="FAIL : peer in the flood list '" + str(vlan_1) + "' is DSVNI/Asymmetric\n\n"
            fail_flag.append(0)

        if "DSVNI: TRUE" in vlan_dsvni_2:
            log.info("PASS : peer in the flood list '" + str(vlan_2) + "' is DSVNI/Asymmetric\n\n")
            status_msgs+="PASS : peer in the flood list '" + str(vlan_2) + "' is DSVNI/Asymmetric\n\n"
        else:
            log.debug("FAIL : peer in the flood list '" + str(vlan_2) + "' is NOT DSVNI/Asymmetric\n\n")
            status_msgs+="FAIL : peer in the flood list '" + str(vlan_2) + "' is NOT DSVNI/Asymmetric\n\n"
            fail_flag.append(0)

        if "DSVNI: FALSE" in vlan_dsvni_3:
            log.info("PASS : peer in the flood list '" + str(vlan_3) + "' is NOT DSVNI/Asymmetric\n\n")
            status_msgs+="PASS : peer in the flood list '" + str(vlan_3) + "' is NOT DSVNI/Asymmetric\n\n"
        else:
            log.debug("FAIL : peer in the flood list '" + str(vlan_3) + "' is DSVNI/Asymmetric\n\n")
            status_msgs+="FAIL : peer in the flood list '" + str(vlan_3) + "' is DSVNI/Asymmetric\n\n"
            fail_flag.append(0)

        if "DSVNI: TRUE" in vlan_dsvni_4:
            log.info("PASS : peer in the flood list '" + str(vlan_4) + "' is DSVNI/Asymmetric\n\n")
            status_msgs+="PASS : peer in the flood list '" + str(vlan_4) + "' is DSVNI/Asymmetric\n\n"
        else:
            log.debug("FAIL : peer in the flood list '" + str(vlan_4) + "' is NOT DSVNI/Asymmetric\n\n")
            status_msgs+="FAIL : peer in the flood list '" + str(vlan_4) + "' is NOT DSVNI/Asymmetric\n\n"
            fail_flag.append(0)

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if 0 in status['status']:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class VERIFY_NextHop_DSVNI_BGW2(aetest.Testcase):
    """VERIFY_NextHop_DSVNI_BGW2"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def VERIFY_NextHop_DSVNI(self, testscript):
        """ VERIFY_NextHop_DSVNI subsection: Verify Next Hop DSVNI or VNI """

        fail_flag = []
        status_msgs = '\n'
        
        BGW_2 = testscript.parameters['BGW-2']

        ip_addr_11 = '2.1.3.20/32'

        dsvni_11 = json.loads(testscript.parameters['BGW-2'].execute('''sh forwarding route ''' + ip_addr_11 + ''' vrf EVPN-VRF-38 | json'''))

        dsvni_true_11 = dsvni_11['TABLE_module']['ROW_module']['DownStream']

        if "dsvni" in dsvni_true_11:
            log.info("PASS : Host Route Next Hop is DSVNI : '" + dsvni_11['TABLE_module']['ROW_module']['VNI'] + "'\n\n")
            status_msgs+="PASS : Host Route Next Hop is DSVNI : '" + dsvni_11['TABLE_module']['ROW_module']['VNI'] + "'\n\n"
        else:
            log.debug("FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_11['TABLE_module']['ROW_module']['VNI'] + "'\n\n")
            status_msgs+="FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_11['TABLE_module']['ROW_module']['VNI'] + "'\n\n"
            fail_flag.append(0)

        ip_addr_21 = '2.1.4.20/32'

        dsvni_21 = json.loads(testscript.parameters['BGW-2'].execute('''sh forwarding route ''' + ip_addr_21 + ''' vrf EVPN-VRF-38 | json'''))

        dsvni_true_21 = dsvni_21['TABLE_module']['ROW_module']['DownStream']

        if "dsvni" in dsvni_true_21:
            log.info("PASS : Host Route Next Hop is DSVNI : '" + dsvni_21['TABLE_module']['ROW_module']['VNI'] + "'\n\n")
            status_msgs+="PASS : Host Route Next Hop is DSVNI : '" + dsvni_21['TABLE_module']['ROW_module']['VNI'] + "'\n\n"
        else:
            log.debug("FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_21['TABLE_module']['ROW_module']['VNI'] + "'\n\n")
            status_msgs+="FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_21['TABLE_module']['ROW_module']['VNI'] + "'\n\n"
            fail_flag.append(0)

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if 0 in status['status']:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class VERIFY_Symmetric_Route_BGW2(aetest.Testcase):
    """VERIFY_Symmetric_Route_BGW2"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def VERIFY_Symmetric_Route(self, testscript):
        """ VERIFY_Symmetric_Route subsection: Verify Symmetric Route """

        fail_flag = []
        status_msgs = '\n'
        
        BGW_2 = testscript.parameters['BGW-2']

        ip_addr_11 = '2.1.1.20/32'

        sym_rt_11 = testscript.parameters['BGW-2'].execute('''show ip route ''' + ip_addr_11 + ''' vrf EVPN-VRF-37''')

        if "Asymmetric" not in sym_rt_11:
            log.info("PASS : Host Route '" + ip_addr_11 + "' is Symmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_11 + "' is Symmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_11 + "' is NOT Symmetric\n\n")
            status_msgs+="FAIL : Host Route '" + ip_addr_11 + "' is NOT Symmetric\n\n"
            fail_flag.append(0)

        ip_addr_21 = '2.1.2.20/32'

        sym_rt_21 = testscript.parameters['BGW-2'].execute('''show ip route ''' + ip_addr_21 + ''' vrf EVPN-VRF-37''')

        if "Asymmetric" not in sym_rt_21:
            log.info("PASS : Host Route '" + ip_addr_21 + "' is Symmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_21 + "' is Symmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_21 + "' is NOT Symmetric\n\n")
            status_msgs+="FAIL : Host Route '" + ip_addr_21 + "' is NOT Symmetric\n\n"
            fail_flag.append(0)

        sleep(10)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if 0 in status['status']:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class VERIFY_Asymmetric_Route_BGW2(aetest.Testcase):
    """VERIFY_Asymmetric_Route_BGW2"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def VERIFY_Asymmetric_Route(self, testscript):
        """ VERIFY_Asymmetric_Route subsection: Verify Asymmetric Route """

        fail_flag = []
        status_msgs = '\n'
        
        BGW_2 = testscript.parameters['BGW-2']

        ip_addr_11 = '2.1.3.20/32'

        sym_rt_11 = testscript.parameters['BGW-2'].execute('''show ip route ''' + ip_addr_11 + ''' vrf EVPN-VRF-38''')

        if "Asymmetric" in sym_rt_11:
            log.info("PASS : Host Route '" + ip_addr_11 + "' is Asymmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_11 + "' is Asymmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_11 + "' is NOT Asymmetric\n\n")
            status_msgs+="FAIL : Host Route '" + ip_addr_11 + "' is NOT Asymmetric\n\n"
            fail_flag.append(0)

        ip_addr_21 = '2.1.4.20/32'

        sym_rt_21 = testscript.parameters['BGW-2'].execute('''show ip route ''' + ip_addr_21 + ''' vrf EVPN-VRF-38''')

        if "Asymmetric" in sym_rt_21:
            log.info("PASS : Host Route '" + ip_addr_21 + "' is Asymmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_21 + "' is Asymmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_21 + "' is NOT Asymmetric\n\n")
            status_msgs+="FAIL : Host Route '" + ip_addr_21 + "' is NOT Asymmetric\n\n"
            fail_flag.append(0)

        sleep(10)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if 0 in status['status']:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class Switch_from_Asym_L2VNI_with_SymL2L3VNI(aetest.Testcase):
    """ Switch_from_Asym_L2VNI_with_SymL2L3VNI """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Switch_from_Asym_L2VNI_on_BGW_2(self, testscript):
        """ Switch from Asym L2VNI subsection: Switching from Asym L2VNI to Sym L2VNI on BGW-2 """

        log.info(banner("MultiSite DSVNI Testing Triggers Block"))

        testscript.parameters['BGW-2'].configure('''

          vlan 18
            no vn-segment 40018
            vn-segment 10018

          interface nve1
            no member vni 40018
            member vni 10018
              ingress-replication protocol bgp
              multisite ingress-replication

          evpn
            no vni 40018 l2
            vni 10018 l2
              rd auto
              route-target import auto
              route-target export auto

      ''')

    sleep(10)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def SwitchBack_to_Asym_L2VNI_on_BGW_2(self, testscript):
        """ SwitchBack to Asym L2VNI subsection: Switching Back to Asym L2VNI from Sym L2VNI on BGW-2 """

        testscript.parameters['BGW-2'].configure('''

          vlan 18
            no vn-segment 10018
            vn-segment 40018

          interface nve1
            no member vni 10018
            member vni 40018
              ingress-replication protocol bgp
              multisite ingress-replication

          evpn
            no vni 10018 l2
            vni 40018 l2
              rd auto
              route-target import 703:18
              route-target export 703:18

      ''')

    sleep(10)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Switch_from_Asym_L2VNI_with_AsymL2L3VNI(aetest.Testcase):
    """ Switch_from_Asym_L2VNI_with_AsymL2L3VNI """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Switch_from_Asym_L2VNI_on_BGW_2(self, testscript):
        """ Switch from Asym L2VNI subsection: Switching from Asym L2VNI to Sym L2VNI on BGW-2 """

        testscript.parameters['BGW-2'].configure('''

          vlan 20
            no vn-segment 40020
            vn-segment 10020

          interface nve1
            no member vni 40020
            member vni 10020
              ingress-replication protocol bgp
              multisite ingress-replication

          evpn
            no vni 40020 l2
            vni 10020 l2
              rd auto
              route-target import auto
              route-target export auto

      ''')

    sleep(10)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def SwitchBack_to_Asym_L2VNI_on_BGW_2(self, testscript):
        """ SwitchBack to Asym L2VNI subsection: Switching Back to Asym L2VNI from Sym L2VNI on BGW-2 """

        testscript.parameters['BGW-2'].configure('''

          vlan 20
            no vn-segment 10020
            vn-segment 40020

          interface nve1
            no member vni 10020
            member vni 40020
              ingress-replication protocol bgp
              multisite ingress-replication

          evpn
            no vni 10020 l2
            vni 40020 l2
              rd auto
              route-target import 803:20
              route-target export 803:20

      ''')

    sleep(10)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Switch_from_Asym_L3VNI_with_SymL2VNI(aetest.Testcase):
    """ Switch_from_Asym_L3VNI_with_SymL2VNI """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Switch_from_Asym_L3VNI_on_BGW_2(self, testscript):
        """ Switch from Asym L3VNI subsection: Switching from Asym L3VNI to Sym L3VNI on BGW-2 """

        testscript.parameters['BGW-2'].configure('''

              vlan 20
                no vn-segment 40020
                vn-segment 10020
              vlan 38
                no vn-segment 40038
                vn-segment 20038

              vrf context EVPN-VRF-38
                no vni 40038
                vni 20038
                address-family ipv4 unicast
                  no route-target import 803:3868
                  no route-target import 803:3868 evpn
                  no route-target export 803:3868
                  no route-target export 803:3868 evpn
                  route-target both auto
                  route-target both auto evpn
                address-family ipv6 unicast
                  no route-target import 803:3868
                  no route-target import 803:3868 evpn
                  no route-target export 803:3868
                  no route-target export 803:3868 evpn
                  route-target both auto
                  route-target both auto evpn

              interface nve1
                no member vni 40020
                member vni 10020
                  ingress-replication protocol bgp
                  multisite ingress-replication
                no member vni 40038 associate-vrf
                member vni 20038 associate-vrf

              evpn
                no vni 40020 l2
                vni 10020 l2
                  rd auto
                  route-target import auto
                  route-target export auto

      ''')

    sleep(10)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def SwitchBack_Asym_L3VNI_on_BGW_2(self, testscript):
        """ SwitchBack to Asym L3VNI subsection: Switching Back to Asym L3VNI from Sym L3VNI on BGW-2 """

        testscript.parameters['BGW-2'].configure('''

              vlan 20
                no vn-segment 10020
                vn-segment 40020
              vlan 38
                no vn-segment 20038
                vn-segment 40038

              vrf context EVPN-VRF-38
                no vni 20038
                vni 40038
                address-family ipv4 unicast
                  no route-target both auto
                  no route-target both auto evpn
                  route-target import 803:3868
                  route-target import 803:3868 evpn
                  route-target export 803:3868
                  route-target export 803:3868 evpn
                address-family ipv6 unicast
                  no route-target both auto
                  no route-target both auto evpn
                  route-target import 803:3868
                  route-target import 803:3868 evpn
                  route-target export 803:3868
                  route-target export 803:3868 evpn

              interface nve1
                no member vni 10020
                no member vni 20038 associate-vrf
                member vni 40020
                  ingress-replication protocol bgp
                  multisite ingress-replication
                member vni 40038 associate-vrf

              evpn
                no vni 10020 l2
                vni 40020 l2
                  rd auto
                  route-target import 803:20
                  route-target export 803:20

      ''')

    sleep(10)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Switch_from_Asym_L3VNI_with_AsymL2VNI(aetest.Testcase):
    """ Switch_from_Asym_L3VNI_with_AsymL2VNI """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Switch_from_Asym_L3VNI_on_BGW_2(self, testscript):
        """ Switch from Asym L3VNI subsection: Switching from Asym L3VNI to Sym L3VNI on BGW-2 """

        testscript.parameters['BGW-2'].configure('''

              vlan 38
                no vn-segment 40038
                vn-segment 20038

              vrf context EVPN-VRF-38
                no vni 40038
                vni 20038
                address-family ipv4 unicast
                  no route-target import 803:3868
                  no route-target import 803:3868 evpn
                  no route-target export 803:3868
                  no route-target export 803:3868 evpn
                  route-target both auto
                  route-target both auto evpn
                address-family ipv6 unicast
                  no route-target import 803:3868
                  no route-target import 803:3868 evpn
                  no route-target export 803:3868
                  no route-target export 803:3868 evpn
                  route-target both auto
                  route-target both auto evpn

              interface nve1
                no member vni 40038 associate-vrf
                member vni 20038 associate-vrf

      ''')

    sleep(10)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def SwitchBack_Asym_L3VNI_on_BGW_2(self, testscript):
        """ SwitchBack to Asym L3VNI subsection: Switching Back to Asym L3VNI from Sym L3VNI on BGW-2 """

        testscript.parameters['BGW-2'].configure('''

              vlan 38
                no vn-segment 20038
                vn-segment 40038

              vrf context EVPN-VRF-38
                no vni 20038
                vni 40038
                address-family ipv4 unicast
                  no route-target both auto
                  no route-target both auto evpn
                  route-target import 803:3868
                  route-target import 803:3868 evpn
                  route-target export 803:3868
                  route-target export 803:3868 evpn
                address-family ipv6 unicast
                  no route-target both auto
                  no route-target both auto evpn
                  route-target import 803:3868
                  route-target import 803:3868 evpn
                  route-target export 803:3868
                  route-target export 803:3868 evpn

              interface nve1
                no member vni 20038 associate-vrf
                member vni 40038 associate-vrf

      ''')

    sleep(10)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Switch_RD_Auto_to_Manual(aetest.Testcase):
    """ Switch_RD_Auto_to_Manual """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Switch_RD_Auto_to_Manual_on_all(self, testscript):
        """ Switch RD Auto to Manual subsection: Switching RD Auto to Manual on ALL """

        testscript.parameters['LEAF-1'].configure('''

              vrf context EVPN-VRF-38
                rd 1:1

      ''')

        testscript.parameters['LEAF-2'].configure('''

              vrf context EVPN-VRF-38
                rd 2:2

      ''')

        testscript.parameters['BGW-1'].configure('''

              vrf context EVPN-VRF-38
                rd 11:11

      ''')

        testscript.parameters['BGW-2'].configure('''

                vrf context EVPN-VRF-38
                  rd 22:22

        ''')

        testscript.parameters['LEAF-1'].configure('''

                restart bgp ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''

      ''')

        testscript.parameters['LEAF-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['BGW-1'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['BGW-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''

        ''')

    sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def SwitchBack_RD_Manual_to_Auto_on_all(self, testscript):
        """ Switch Back RD Manual to Auto subsection: Switching Back RD Manual to Auto on ALL """

        testscript.parameters['LEAF-1'].configure('''

              vrf context EVPN-VRF-38
                no rd 1:1
                rd auto

      ''')

        testscript.parameters['LEAF-2'].configure('''

              vrf context EVPN-VRF-38
                no rd 2:2
                rd auto

      ''')

        testscript.parameters['BGW-1'].configure('''

              vrf context EVPN-VRF-38
                no rd 11:11
                rd auto

      ''')

        testscript.parameters['BGW-2'].configure('''

                vrf context EVPN-VRF-38
                  no rd 22:22
                  rd auto

        ''')

        testscript.parameters['LEAF-1'].configure('''

                restart bgp ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''

      ''')

        testscript.parameters['LEAF-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['BGW-1'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['BGW-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''

        ''')

    sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Switch_RT_Auto_to_Manual(aetest.Testcase):
    """ Switch_RT_Auto_to_Manual """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Switch_RT_Auto_to_Manual_on_all(self, testscript):
        """ Switch RT Auto to Manual subsection: Switching RT Auto to Manual on ALL """

        testscript.parameters['LEAF-1'].configure('''

              vrf context EVPN-VRF-37
                address-family ipv4 unicast
                  no route-target both auto
                  no route-target both auto evpn
                  route-target import 703:3867
                  route-target import 703:3867 evpn
                  route-target export 703:3867
                  route-target export 703:3867 evpn
                address-family ipv6 unicast
                  no route-target both auto
                  no route-target both auto evpn
                  route-target import 703:3867
                  route-target import 703:3867 evpn
                  route-target export 703:3867
                  route-target export 703:3867 evpn

      ''')

        testscript.parameters['LEAF-2'].configure('''

              vrf context EVPN-VRF-37
                address-family ipv4 unicast
                  no route-target both auto
                  no route-target both auto evpn
                  route-target import 703:3867
                  route-target import 703:3867 evpn
                  route-target export 703:3867
                  route-target export 703:3867 evpn
                address-family ipv6 unicast
                  no route-target both auto
                  no route-target both auto evpn
                  route-target import 703:3867
                  route-target import 703:3867 evpn
                  route-target export 703:3867
                  route-target export 703:3867 evpn

      ''')

        testscript.parameters['BGW-1'].configure('''

              vrf context EVPN-VRF-37
                address-family ipv4 unicast
                  no route-target both auto
                  no route-target both auto evpn
                  route-target import 703:3867
                  route-target import 703:3867 evpn
                  route-target export 703:3867
                  route-target export 703:3867 evpn
                address-family ipv6 unicast
                  no route-target both auto
                  no route-target both auto evpn
                  route-target import 703:3867
                  route-target import 703:3867 evpn
                  route-target export 703:3867
                  route-target export 703:3867 evpn

      ''')

        testscript.parameters['BGW-2'].configure('''

                vrf context EVPN-VRF-37
                  address-family ipv4 unicast
                    no route-target both auto
                    no route-target both auto evpn
                    route-target import 703:3867
                    route-target import 703:3867 evpn
                    route-target export 703:3867
                    route-target export 703:3867 evpn
                  address-family ipv6 unicast
                    no route-target both auto
                    no route-target both auto evpn
                    route-target import 703:3867
                    route-target import 703:3867 evpn
                    route-target export 703:3867
                    route-target export 703:3867 evpn

        ''')

        testscript.parameters['LEAF-1'].configure('''

                restart bgp ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''

      ''')

        testscript.parameters['LEAF-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['BGW-1'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['BGW-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''

        ''')

    sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def SwitchBack_RT_Manual_to_Auto_on_all(self, testscript):
        """ Switch Back RT Manual to Auto subsection: Switching Back RT Manual to Auto on ALL """

        testscript.parameters['LEAF-1'].configure('''

              vrf context EVPN-VRF-37
                address-family ipv4 unicast
                  no route-target import 703:3867
                  no route-target import 703:3867 evpn
                  no route-target export 703:3867
                  no route-target export 703:3867 evpn
                  route-target both auto
                  route-target both auto evpn
                address-family ipv6 unicast
                  no route-target import 703:3867
                  no route-target import 703:3867 evpn
                  no route-target export 703:3867
                  no route-target export 703:3867 evpn
                  route-target both auto
                  route-target both auto evpn

      ''')

        testscript.parameters['LEAF-2'].configure('''

              vrf context EVPN-VRF-37
                address-family ipv4 unicast
                  no route-target import 703:3867
                  no route-target import 703:3867 evpn
                  no route-target export 703:3867
                  no route-target export 703:3867 evpn
                  route-target both auto
                  route-target both auto evpn
                address-family ipv6 unicast
                  no route-target import 703:3867
                  no route-target import 703:3867 evpn
                  no route-target export 703:3867
                  no route-target export 703:3867 evpn
                  route-target both auto
                  route-target both auto evpn

      ''')

        testscript.parameters['BGW-1'].configure('''

              vrf context EVPN-VRF-37
                address-family ipv4 unicast
                  no route-target import 703:3867
                  no route-target import 703:3867 evpn
                  no route-target export 703:3867
                  no route-target export 703:3867 evpn
                  route-target both auto
                  route-target both auto evpn
                address-family ipv6 unicast
                  no route-target import 703:3867
                  no route-target import 703:3867 evpn
                  no route-target export 703:3867
                  no route-target export 703:3867 evpn
                  route-target both auto
                  route-target both auto evpn

      ''')

        testscript.parameters['BGW-2'].configure('''

                vrf context EVPN-VRF-37
                  address-family ipv4 unicast
                    no route-target import 703:3867
                    no route-target import 703:3867 evpn
                    no route-target export 703:3867
                    no route-target export 703:3867 evpn
                    route-target both auto
                    route-target both auto evpn
                  address-family ipv6 unicast
                    no route-target import 703:3867
                    no route-target import 703:3867 evpn
                    no route-target export 703:3867
                    no route-target export 703:3867 evpn
                    route-target both auto
                    route-target both auto evpn

        ''')

        testscript.parameters['LEAF-1'].configure('''

                restart bgp ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''

      ''')

        testscript.parameters['LEAF-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['BGW-1'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['BGW-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''

        ''')

    sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Switch_RT_Auto_to_Manual_Under_EVPN(aetest.Testcase):
    """ Switch_RT_Auto_to_Manual_Under_EVPN """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Switch_RT_Auto_to_Manual_Under_EVPN(self, testscript):
        """ Switch RT Auto to Manual subsection: Switching RT Auto to Manual Under EVPN """

        testscript.parameters['LEAF-1'].configure('''

            evpn
              vni 10017 l2
                no route-target import auto
                no route-target export auto
                route-target import 703:17
                route-target export 703:17
              vni 10019 l2
                no route-target import auto
                no route-target export auto
                route-target import 803:19
                route-target export 803:19

      ''')

        testscript.parameters['LEAF-2'].configure('''

            evpn
              vni 10017 l2
                no route-target import auto
                no route-target export auto
                route-target import 703:17
                route-target export 703:17
              vni 10019 l2
                no route-target import auto
                no route-target export auto
                route-target import 803:19
                route-target export 803:19

      ''')

        testscript.parameters['BGW-1'].configure('''

            evpn
              vni 10017 l2
                no route-target import auto
                no route-target export auto
                route-target import 703:17
                route-target export 703:17
              vni 10019 l2
                no route-target import auto
                no route-target export auto
                route-target import 803:19
                route-target export 803:19

      ''')

        testscript.parameters['BGW-2'].configure('''

              evpn
                vni 10017 l2
                  no route-target import auto
                  no route-target export auto
                  route-target import 703:17
                  route-target export 703:17
                vni 10019 l2
                  no route-target import auto
                  no route-target export auto
                  route-target import 803:19
                  route-target export 803:19

        ''')

        testscript.parameters['LEAF-1'].configure('''

                restart bgp ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''

      ''')

        testscript.parameters['LEAF-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['BGW-1'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['BGW-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''

        ''')

    sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def SwitchBack_RT_Manual_to_Auto_Under_EVPN(self, testscript):
        """ Switch Back RT Manual to Auto subsection: Switching Back RT Manual to Auto Under EVPN """

        testscript.parameters['LEAF-1'].configure('''

              evpn
                vni 10017 l2
                  no route-target import 703:17
                  no route-target export 703:17
                  route-target import auto
                  route-target export auto
                vni 10019 l2
                  no route-target import 803:19
                  no route-target export 803:19
                  route-target import auto
                  route-target export auto


        ''')

        testscript.parameters['LEAF-2'].configure('''

              evpn
                vni 10017 l2
                  no route-target import 703:17
                  no route-target export 703:17
                  route-target import auto
                  route-target export auto
                vni 10019 l2
                  no route-target import 803:19
                  no route-target export 803:19
                  route-target import auto
                  route-target export auto

        ''')

        testscript.parameters['BGW-1'].configure('''

              evpn
                vni 10017 l2
                  no route-target import 703:17
                  no route-target export 703:17
                  route-target import auto
                  route-target export auto
                vni 10019 l2
                  no route-target import 803:19
                  no route-target export 803:19
                  route-target import auto
                  route-target export auto

        ''')

        testscript.parameters['BGW-2'].configure('''

              evpn
                vni 10017 l2
                  no route-target import 703:17
                  no route-target export 703:17
                  route-target import auto
                  route-target export auto
                vni 10019 l2
                  no route-target import 803:19
                  no route-target export 803:19
                  route-target import auto
                  route-target export auto

        ''')

        testscript.parameters['LEAF-1'].configure('''

                restart bgp ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''

      ''')

        testscript.parameters['LEAF-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['BGW-1'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['BGW-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''

        ''')

    sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Remove_Add_L2VNI_VLAN(aetest.Testcase):
    """ Remove_Add_L2VNI_VLAN """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_L2VNI_VLAN_on_All(self, testscript):
        """ Remove L2VNI VLAN subsection: Removing L2VNI VLAN on All """

        testscript.parameters['LEAF-1'].configure('''

                no vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + '''
                no vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                no vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                no vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''

      ''')

        testscript.parameters['LEAF-2'].configure('''

                no vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + '''
                no vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                no vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                no vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 3) + '''

      ''')

        testscript.parameters['BGW-1'].configure('''

                no vlan ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + '''
                no vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                no vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                no vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''

      ''')

        testscript.parameters['BGW-2'].configure('''

                no vlan ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + '''
                no vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                no vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                no vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 3) + '''

      ''')

    sleep(10)

    @aetest.test
    def ReAdd_L2VNI_VLAN_on_All(self, testscript):
        """ Re-Add L2VNI VLAN subsection: Re-Adding Back L2VNI VLAN on All """

        testscript.parameters['LEAF-1'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                    vn-segment 40018
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                    vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                    vn-segment 40020
                    exit

        ''')

        testscript.parameters['BGW-1'].configure('''

                  vlan ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                    vn-segment ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + 1) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                    vn-segment ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                    vn-segment ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + 3) + '''
                    exit

        ''')

        testscript.parameters['BGW-2'].configure('''

                  vlan ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                    vn-segment 40018
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                    vn-segment ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                    vn-segment 40020
                    exit

        ''')

        testscript.parameters['LEAF-2'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                    vn-segment ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                    vn-segment ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                    vn-segment ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 3) + '''
                    exit


        ''')

    sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Remove_Add_L3VNI_VLAN(aetest.Testcase):
    """ Remove_Add_L3VNI_VLAN """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_L3VNI_VLAN_on_All(self, testscript):
        """ Remove L3VNI VLAN subsection: Removing L3VNI VLAN on All """

        testscript.parameters['LEAF-1'].configure('''

                no vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']) + '''
                no vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']) + 1) + '''

      ''')

        testscript.parameters['LEAF-2'].configure('''

                no vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vlan_start']) + '''
                no vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vlan_start']) + 1) + '''

      ''')

        testscript.parameters['BGW-1'].configure('''

                no vlan ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vlan_start']) + '''
                no vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vlan_start']) + 1) + '''

      ''')

        testscript.parameters['BGW-2'].configure('''

                no vlan ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vlan_start']) + '''
                no vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vlan_start']) + 1) + '''

      ''')

    sleep(10)

    @aetest.test
    def ReAdd_L3VNI_VLAN_on_All(self, testscript):
        """ Re-Add L3VNI VLAN subsection: Re-Adding Back L3VNI VLAN on All """

        testscript.parameters['LEAF-1'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
                    vn-segment 40038
                    exit

        ''')

        testscript.parameters['BGW-1'].configure('''

                  vlan ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
                    vn-segment ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vni_start']) + 1) + '''
                    exit

        ''')

        testscript.parameters['BGW-2'].configure('''

                  vlan ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
                    vn-segment 40038
                    exit

        ''')

        testscript.parameters['LEAF-2'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
                    vn-segment ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vni_start']) + 1) + '''
                    exit

        ''')

    sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Remove_Add_L2VNI_VN_Segment(aetest.Testcase):
    """ Remove_Add_L2VNI_VN_Segment """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_L2VNI_VN_Segment_on_All(self, testscript):
        """ Remove L2VNI VN Segment subsection: Removing L2VNI VN Segment on All """

        testscript.parameters['LEAF-1'].configure('''

                    vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + '''
                      no vn-segment ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + '''
                      exit
                    vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                      no vn-segment 40018
                      exit
                    vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                      no vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                      exit
                    vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                      no vn-segment 40020
                      exit

        ''')

        testscript.parameters['BGW-1'].configure('''

                  vlan ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + '''
                    no vn-segment ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                    no vn-segment ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + 1) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                    no vn-segment ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                    no vn-segment ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + 3) + '''
                    exit

      ''')

        testscript.parameters['BGW-2'].configure('''

                    vlan ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + '''
                      no vn-segment ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vni_start']) + '''
                      exit
                    vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                      no vn-segment 40018
                      exit
                    vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                      no vn-segment ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                      exit
                    vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                      no vn-segment 40020
                      exit

        ''')

        testscript.parameters['LEAF-2'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + '''
                    no vn-segment ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                    no vn-segment ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                    no vn-segment ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                    no vn-segment ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 3) + '''
                    exit

      ''')

    sleep(10)

    @aetest.test
    def ReAdd_L2VNI_VN_Segment_on_All(self, testscript):
        """ Re-Add L2VNI VN Segment subsection: Re-Adding Back L2VNI VN Segment on All """

        testscript.parameters['LEAF-1'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                    vn-segment 40018
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                    vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                    vn-segment 40020
                    exit

        ''')

        testscript.parameters['BGW-1'].configure('''

                  vlan ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                    vn-segment ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + 1) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                    vn-segment ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                    vn-segment ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + 3) + '''
                    exit

        ''')

        testscript.parameters['BGW-2'].configure('''

                  vlan ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                    vn-segment 40018
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                    vn-segment ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                    vn-segment 40020
                    exit

        ''')

        testscript.parameters['LEAF-2'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                    vn-segment ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                    vn-segment ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                    vn-segment ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 3) + '''
                    exit


        ''')

    sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Remove_Add_L3VNI_VN_Segment(aetest.Testcase):
    """ Remove_Add_L3VNI_VN_Segment """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_L3VNI_VN_Segment_on_All(self, testscript):
        """ Remove L3VNI VN Segment subsection: Removing L3VNI VN Segment on All """

        testscript.parameters['LEAF-1'].configure('''

                    vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']) + '''
                      no vn-segment ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vni_start']) + '''
                      exit
                    vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
                      no vn-segment 40038
                      exit

        ''')

        testscript.parameters['BGW-1'].configure('''

                  vlan ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vlan_start']) + '''
                    no vn-segment ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
                    no vn-segment ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vni_start']) + 1) + '''
                    exit

      ''')

        testscript.parameters['BGW-2'].configure('''

                    vlan ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vlan_start']) + '''
                      no vn-segment ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vni_start']) + '''
                      exit
                    vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
                      no vn-segment 40038
                      exit

        ''')

        testscript.parameters['LEAF-2'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vlan_start']) + '''
                    no vn-segment ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
                    no vn-segment ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vni_start']) + 1) + '''
                    exit

      ''')

    sleep(10)

    @aetest.test
    def ReAdd_L3VNI_VN_Segment_on_All(self, testscript):
        """ Re-Add L3VNI VN Segment subsection: Re-Adding Back L3VNI VN Segment on All """

        testscript.parameters['LEAF-1'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
                    vn-segment 40038
                    exit

        ''')

        testscript.parameters['BGW-1'].configure('''

                  vlan ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
                    vn-segment ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vni_start']) + 1) + '''
                    exit

        ''')

        testscript.parameters['BGW-2'].configure('''

                  vlan ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
                    vn-segment 40038
                    exit

        ''')

        testscript.parameters['LEAF-2'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
                    vn-segment ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vni_start']) + 1) + '''
                    exit

        ''')

    sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Remove_Add_L2VNI_SVI(aetest.Testcase):
    """ Remove_Add_L2VNI_SVI """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_Add_L2VNI_SVI_on_All(self, testscript):
        """ Remove_Add_L2VNI_SVI_on_All """

        testscript.parameters['LEAF-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          no interface vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + '''
          no interface vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
          no interface vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
          no interface vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''

              ''')

        testscript.parameters['LEAF-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          no interface vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + '''
          no interface vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
          no interface vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
          no interface vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 3) + '''

              ''')

        testscript.parameters['BGW-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          no interface vlan ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + '''
          no interface vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
          no interface vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
          no interface vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''

              ''')

        testscript.parameters['BGW-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          no interface vlan ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + '''
          no interface vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
          no interface vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
          no interface vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 3) + '''

              ''')

        sleep(30)

        testscript.parameters['LEAF-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['BGW-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace4 = testscript.parameters['BGW-2'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)
        match4 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace4)

        sleep(10)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success' and  match4[1] == 'Success':
            log.info("Rollback Passed")
        else:
            log.debug("Rollback Failed")
            self.failed(reason="Rollback Failed", goto=['next_tc'])

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Remove_Add_L3VNI_SVI(aetest.Testcase):
    """ Remove_Add_L3VNI_SVI """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_Add_L3VNI_SVI_on_All(self, testscript):
        """ Remove_Add_L2VNI_SVI_on_All """

        testscript.parameters['LEAF-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          no interface vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']) + '''
          no interface vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']) + 1) + '''

              ''')

        testscript.parameters['LEAF-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          no interface vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vlan_start']) + '''
          no interface vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vlan_start']) + 1) + '''

              ''')

        testscript.parameters['BGW-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          no interface vlan ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vlan_start']) + '''
          no interface vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vlan_start']) + 1) + '''

              ''')

        testscript.parameters['BGW-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          no interface vlan ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vlan_start']) + '''
          no interface vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vlan_start']) + 1) + '''

              ''')

        sleep(30)

        testscript.parameters['LEAF-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['BGW-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace4 = testscript.parameters['BGW-2'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)
        match4 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace4)

        sleep(10)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success' and match4[1] == 'Success':
            log.info("Rollback Passed")
        else:
            log.debug("Rollback Failed")
            self.failed(reason="Rollback Failed", goto=['next_tc'])

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Remove_Add_L2VNI_Under_NVE(aetest.Testcase):
    """ Remove_Add_L2VNI_Under_NVE """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_Add_L2VNI_Under_NVE_on_All(self, testscript):
        """ Remove_Add_L2VNI_Under_NVE_on_All """

        testscript.parameters['BGW-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no member vni ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + '''
            no member vni ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + 1) + '''
            no member vni ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
            no member vni ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + 3) + '''

              ''')

        testscript.parameters['LEAF-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no member vni ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + '''
            no member vni ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + '''
            no member vni ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 2) + '''
            no member vni ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 3) + '''

              ''')

        testscript.parameters['LEAF-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no member vni ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + '''
            no member vni 40018
            no member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
            no member vni 40020

              ''')

        testscript.parameters['BGW-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no member vni ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vni_start']) + '''
            no member vni 40018
            no member vni ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vni_start']) + 2) + '''
            no member vni 40020

              ''')

        sleep(30)

        testscript.parameters['LEAF-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['BGW-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace4 = testscript.parameters['BGW-2'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)
        match4 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace4)

        sleep(10)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success' and match4[1] == 'Success':
            log.info("Rollback Passed")
        else:
            log.debug("Rollback Failed")
            self.failed(reason="Rollback Failed", goto=['next_tc'])

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Remove_Add_L3VNI_Under_NVE(aetest.Testcase):
    """ Remove_Add_L3VNI_Under_NVE """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_Add_L3VNI_Under_NVE_on_All(self, testscript):
        """ Remove_Add_L3VNI_Under_NVE_on_All """

        testscript.parameters['BGW-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no member vni ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vni_start']) + '''
            no member vni ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vni_start']) + 1) + '''

              ''')

        testscript.parameters['LEAF-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no member vni ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vni_start']) + '''
            no member vni ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vni_start']) + 1) + '''

              ''')

        testscript.parameters['LEAF-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no member vni ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vni_start']) + '''
            no member vni 40038

              ''')

        testscript.parameters['BGW-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no member vni ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vni_start']) + '''
            no member vni 40038

              ''')

        sleep(30)

        testscript.parameters['LEAF-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['BGW-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace4 = testscript.parameters['BGW-2'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)
        match4 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace4)

        sleep(10)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success' and match4[1] == 'Success':
            log.info("Rollback Passed")
        else:
            log.debug("Rollback Failed")
            self.failed(reason="Rollback Failed", goto=['next_tc'])

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Remove_Add_NVE_Interface(aetest.Testcase):
    """ Remove_Add_NVE_Interface """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_Add_NVE_Interface_on_All(self, testscript):
        """ Remove_Add_NVE_Interface_on_All """

        testscript.parameters['LEAF-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          no interface nve1

              ''')

        testscript.parameters['LEAF-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          no interface nve1

              ''')

        testscript.parameters['BGW-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          no interface nve1

              ''')

        testscript.parameters['BGW-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          no interface nve1

              ''')

        sleep(30)

        testscript.parameters['LEAF-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['BGW-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace4 = testscript.parameters['BGW-2'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)
        match4 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace4)

        sleep(10)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success' and match4[1] == 'Success':
            log.info("Rollback Passed")
        else:
            log.debug("Rollback Failed")
            self.failed(reason="Rollback Failed", goto=['next_tc'])

        sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Remove_Add_NVE_Host_Reach_Proto(aetest.Testcase):
    """ Remove_Add_NVE_Host_Reach_Proto """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_Add_NVE_Host_Reach_Proto_on_All(self, testscript):
        """ Remove_Add_NVE_Host_Reach_Proto_on_All """

        testscript.parameters['LEAF-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no host-reachability protocol bgp

              ''')

        testscript.parameters['LEAF-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no host-reachability protocol bgp

              ''')

        testscript.parameters['BGW-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no host-reachability protocol bgp

              ''')

        testscript.parameters['BGW-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no host-reachability protocol bgp

              ''')

        sleep(30)

        testscript.parameters['LEAF-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['BGW-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace4 = testscript.parameters['BGW-2'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)
        match4 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace4)

        sleep(10)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success' and match4[1] == 'Success':
            log.info("Rollback Passed")
        else:
            log.debug("Rollback Failed")
            self.failed(reason="Rollback Failed", goto=['next_tc'])

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Remove_Add_NVE_Src_Interface(aetest.Testcase):
    """ Remove_Add_NVE_Src_Interface """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_Add_NVE_Src_Interface_on_All(self, testscript):
        """ Remove_Add_NVE_Src_Interface_on_All """

        testscript.parameters['LEAF-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no source-interface loopback1

              ''')

        testscript.parameters['LEAF-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no source-interface loopback1

              ''')

        testscript.parameters['BGW-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no source-interface loopback1

              ''')

        testscript.parameters['BGW-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no source-interface loopback1

              ''')

        sleep(30)

        testscript.parameters['LEAF-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['BGW-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace4 = testscript.parameters['BGW-2'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)
        match4 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace4)

        sleep(10)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success' and match4[1] == 'Success':
            log.info("Rollback Passed")
        else:
            log.debug("Rollback Failed")
            self.failed(reason="Rollback Failed", goto=['next_tc'])

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Remove_Add_NVE_IR_Under_L2VNI_Members(aetest.Testcase):
    """ Remove_Add_NVE_IR_Under_L2VNI_Members """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_Add_NVE_IR_Under_L2VNI_Members_on_All(self, testscript):
        """ Remove_Add_NVE_IR_Under_L2VNI_Members_on_All """

        testscript.parameters['LEAF-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            member vni ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + '''
              no ingress-replication protocol bgp
            member vni 40018
              no ingress-replication protocol bgp
            member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
              no ingress-replication protocol bgp
            member vni 40020
              no ingress-replication protocol bgp

              ''')

        testscript.parameters['BGW-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            member vni ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + '''
              no ingress-replication protocol bgp
            member vni ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + 1) + '''
              no ingress-replication protocol bgp
            member vni ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
              no ingress-replication protocol bgp
            member vni ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vni_start']) + 3) + '''
              no ingress-replication protocol bgp

              ''')

        testscript.parameters['BGW-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            member vni ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vni_start']) + '''
              no ingress-replication protocol bgp
            member vni 40018
              no ingress-replication protocol bgp
            member vni ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vni_start']) + 2) + '''
              no ingress-replication protocol bgp
            member vni 40020
              no ingress-replication protocol bgp

              ''')

        testscript.parameters['LEAF-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            member vni ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + '''
              no ingress-replication protocol bgp
            member vni ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + '''
              no ingress-replication protocol bgp
            member vni ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 2) + '''
              no ingress-replication protocol bgp
            member vni ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 3) + '''
              no ingress-replication protocol bgp

              ''')

        sleep(30)

        testscript.parameters['LEAF-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['BGW-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace4 = testscript.parameters['BGW-2'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)
        match4 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace4)

        sleep(10)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success' and match4[1] == 'Success':
            log.info("Rollback Passed")
        else:
            log.debug("Rollback Failed")
            self.failed(reason="Rollback Failed", goto=['next_tc'])

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class L2VNI_SVI_Link_Flap(aetest.Testcase):
    """ L2VNI_SVI_Link_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def L2VNI_SVI_Link_Flap(self, testscript):
        """ L2VNI_SVI_Link_Flap """

        testscript.parameters['LEAF-1'].configure('''

          interface vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
            shutdown

              ''')

        testscript.parameters['LEAF-2'].configure('''

          interface vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
            shutdown

              ''')

        testscript.parameters['BGW-1'].configure('''

          interface vlan ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
            shutdown

              ''')

        testscript.parameters['BGW-2'].configure('''

          interface vlan ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
            shutdown

              ''')

        sleep(10)

        testscript.parameters['LEAF-1'].configure('''

          interface vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
            no shutdown

              ''')

        testscript.parameters['LEAF-2'].configure('''

          interface vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
            no shutdown

              ''')

        testscript.parameters['BGW-1'].configure('''

          interface vlan ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
            no shutdown

              ''')

        testscript.parameters['BGW-2'].configure('''

          interface vlan ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
            no shutdown

              ''')

        sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class L3VNI_SVI_Link_Flap(aetest.Testcase):
    """ L3VNI_SVI_Link_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def L3VNI_SVI_Link_Flap(self, testscript):
        """ L3VNI_SVI_Link_Flap """

        testscript.parameters['LEAF-1'].configure('''

          interface vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
            shutdown

              ''')

        testscript.parameters['LEAF-2'].configure('''

          interface vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vlan_start']) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
            shutdown

              ''')

        testscript.parameters['BGW-1'].configure('''

          interface vlan ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vlan_start']) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
            shutdown

              ''')

        testscript.parameters['BGW-2'].configure('''

          interface vlan ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vlan_start']) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
            shutdown

              ''')

        sleep(10)

        testscript.parameters['LEAF-1'].configure('''

          interface vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
            no shutdown

              ''')

        testscript.parameters['LEAF-2'].configure('''

          interface vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vlan_start']) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
            no shutdown

              ''')

        testscript.parameters['BGW-1'].configure('''

          interface vlan ''' + str(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vlan_start']) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['BGW_1_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
            no shutdown

              ''')

        testscript.parameters['BGW-2'].configure('''

          interface vlan ''' + str(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vlan_start']) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['BGW_2_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
            no shutdown

              ''')

        sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class BGW_NVE_Flap(aetest.Testcase):
    """ BGW_NVE_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def BGW_NVE_Flap(self, testscript):
        """ BGW_NVE_Flap """

        testscript.parameters['BGW-1'].configure('''

                  interface nve 1
                  shutdown
                  no shutdown

              ''')

        testscript.parameters['BGW-2'].configure('''

                  interface nve 1
                  shutdown
                  no shutdown

              ''')

        sleep(30)

    sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class LEAF_NVE_Flap(aetest.Testcase):
    """ LEAF_NVE_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def LEAF_NVE_Flap(self, testscript):
        """ LEAF_NVE_Flap """

        testscript.parameters['LEAF-1'].configure('''

                  interface nve 1
                  shutdown
                  no shutdown

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  interface nve 1
                  shutdown
                  no shutdown

              ''')

        sleep(30)

    sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class BGW_Fabric_Link_Flap(aetest.Testcase):
    """ BGW_Fabric_Link_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def BGW_Fabric_Link_Flap(self, testscript):
        """ BGW_Fabric_Link_Flap """

        testscript.parameters['BGW-1'].configure('''

                  interface port-channel ''' + str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                  shutdown
                  no shutdown

              ''')

        testscript.parameters['BGW-2'].configure('''

                  interface port-channel ''' + str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                  shutdown
                  no shutdown

              ''')

        sleep(30)

    sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class LEAF_UP_Link_Flap(aetest.Testcase):
    """ LEAF_UP_Link_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def LEAF_UP_Link_Flap(self, testscript):
        """ LEAF_UP_Link_Flap """

        testscript.parameters['LEAF-1'].configure('''

                  interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                  shutdown
                  no shutdown

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                  shutdown
                  no shutdown

              ''')

        sleep(30)

    sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class BGW_DCI_Link_Flap(aetest.Testcase):
    """ BGW_DCI_Link_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def BGW_DCI_Link_Flap(self, testscript):
        """ BGW_DCI_Link_Flap """

        testscript.parameters['BGW-1'].configure('''

                  interface ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2']) + '''
                  shutdown
                  no shutdown

              ''')

        testscript.parameters['BGW-2'].configure('''

                  interface ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1']) + '''
                  shutdown
                  no shutdown

              ''')

        sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Verify_NVE_PEERS(aetest.Testcase):
    """ Verify_NVE_PEERS """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_NVE_PEERS(self, testscript):
        """ Verify_NVE_PEERS """

        XML_Peer_IP_11 = testscript.parameters['LEAF-1'].execute('''show nve peers | grep peer-ip | xml''')

        NVE_PEERS_11 = json.loads(testscript.parameters['LEAF-1'].execute('''show nve peers | json'''))

        peer_ip_address_11 = str(testscript.parameters['BGW_1_dict']['NVE_data']['VTEP_IP'])
        peer_ip_address_12 = '10.101.101.101'

        if peer_ip_address_11 in XML_Peer_IP_11:
            Peer_State_11 = Peer_State(NVE_PEERS_11, peer_ip_address_11)
            if Peer_State_11 == "Up":
                log.info("PASS : BGW PIP is Present & UP\n\n")
        else:
            log.debug("FAIL : BGW PIP is NOT Present\n\n")

        if peer_ip_address_12 in XML_Peer_IP_11:
            Peer_State_12 = Peer_State(NVE_PEERS_11, peer_ip_address_12)
            if Peer_State_12 == "Up":
                log.info("PASS : BGW VIP is Present & UP\n\n")
                self.passed(reason="BGW VIP is Present & UP")
        else:
            log.debug("FAIL : BGW VIP is NOT Present\n\n")
            self.failed(reason="BGW VIP is NOT Present")

        sleep(10)

        XML_Peer_IP = testscript.parameters['BGW-2'].execute('''show nve peers | grep peer-ip | xml''')

        NVE_PEERS = json.loads(testscript.parameters['BGW-2'].execute('''show nve peers | json'''))

        peer_ip_address_1 = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])
        peer_ip_address_2 = str(testscript.parameters['BGW_1_dict']['NVE_data']['VTEP_IP'])
        peer_ip_address_3 = '10.101.101.101'

        if peer_ip_address_1 in XML_Peer_IP:
            Peer_State_1 = Peer_State(NVE_PEERS, peer_ip_address_1)
            if Peer_State_1 == "Up":
                log.info("PASS : LEAF PEER-IP is Present & UP\n\n")
        else:
            log.debug("FAIL : LEAF PEER-IP is NOT Present\n\n")

        if peer_ip_address_2 in XML_Peer_IP:
            Peer_State_2 = Peer_State(NVE_PEERS, peer_ip_address_2)
            if Peer_State_2 == "Up":
                log.info("PASS : BGW PIP is Present & UP\n\n")
        else:
            log.debug("FAIL : BGW PIP is NOT Present\n\n")

        if peer_ip_address_3 in XML_Peer_IP:
            Peer_State_3 = Peer_State(NVE_PEERS, peer_ip_address_3)
            if Peer_State_3 == "Up":
                log.info("PASS : BGW VIP is Present & UP\n\n")
                self.passed(reason="BGW VIP is Present & UP")
        else:
            log.debug("FAIL : BGW VIP is NOT Present\n\n")
            self.failed(reason="BGW VIP is NOT Present")

        sleep(10)

    @aetest.cleanup
    def cleanup(self):
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class BGW_Loopback_Flap(aetest.Testcase):
    """ BGW_Loopback_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def BGW_Loopback_Flap(self, testscript):
        """ BGW_Loopback_Flap """

        testscript.parameters['BGW-1'].configure('''

                interface ''' + str(testscript.parameters['BGW_1_dict']['NVE_data']['src_loop']) + '''
                  shutdown
                  no shutdown
                  
                interface loopback100
                  shutdown
                  no shutdown

              ''')

        testscript.parameters['BGW-2'].configure('''

                interface ''' + str(testscript.parameters['BGW_2_dict']['NVE_data']['src_loop']) + '''
                  shutdown
                  no shutdown

                interface loopback100
                  shutdown
                  no shutdown

              ''')

        sleep(60)

    sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class LEAF_Loopback_Flap(aetest.Testcase):
    """ LEAF_Loopback_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def LEAF_Loopback_Flap(self, testscript):
        """ LEAF_Loopback_Flap """

        testscript.parameters['LEAF-1'].configure('''

                  interface ''' + str(testscript.parameters['LEAF_1_dict']['NVE_data']['src_loop']) + '''
                  shutdown
                  no shutdown

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  interface ''' + str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']) + '''
                  shutdown
                  no shutdown

              ''')

        sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Remove_Add_BGP_Configs(aetest.Testcase):
    """ Remove_Add_BGP_Configs """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_Add_BGP_Configs(self, testscript):
        """ Remove_Add_BGP_Configs """

        testscript.parameters['LEAF-1'].configure('''

                  delete bootflash:temp_bgp_configs.txt no-prompt

                  show running-config bgp > bootflash:temp_bgp_configs.txt

                  no feature bgp

                  copy bootflash:temp_bgp_configs.txt running-config echo-commands

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  delete bootflash:temp_bgp_configs.txt no-prompt

                  show running-config bgp > bootflash:temp_bgp_configs.txt

                  no feature bgp

                  copy bootflash:temp_bgp_configs.txt running-config echo-commands

              ''')

        sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class iCAM_Check(aetest.Testcase):
    """ iCAM_Check """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

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

              ''')

        testscript.parameters['LEAF-2'].configure('''

          icam monitor scale

          show icam system | no-more

          show icam scale | no-more

          show icam scale vxlan | no-more

          show icam health | no-more

          show icam prediction scale vxlan 2030 Jan 01 01:01:01

              ''')

        testscript.parameters['BGW-1'].configure('''

          icam monitor scale

          show icam system | no-more

          show icam scale | no-more

          show icam scale vxlan | no-more

          show icam health | no-more

          show icam prediction scale vxlan 2030 Jan 01 01:01:01

              ''')

        testscript.parameters['BGW-2'].configure('''

          icam monitor scale

          show icam system | no-more

          show icam scale | no-more

          show icam scale vxlan | no-more

          show icam health | no-more

          show icam prediction scale vxlan 2030 Jan 01 01:01:01

              ''')

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class Config_Replace(aetest.Testcase):
    """ Config_Replace """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Config_Replace(self, testscript):
        """ Config_Replace """

        testscript.parameters['LEAF-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

              vrf context EVPN-VRF-38
                address-family ipv4 unicast
                  no route-target import 803:3868
                  no route-target import 803:3868 evpn
                  no route-target export 803:3868
                  no route-target export 803:3868 evpn
                address-family ipv6 unicast
                  no route-target import 803:3868
                  no route-target import 803:3868 evpn
                  no route-target export 803:3868
                  no route-target export 803:3868 evpn

              evpn
                vni 40018 l2
                  no route-target import 703:18
                  no route-target export 703:18
                vni 40020 l2
                  no route-target import 803:20
                  no route-target export 803:20

          configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

              vrf context EVPN-VRF-38
                address-family ipv4 unicast
                  no route-target import 803:3868
                  no route-target import 803:3868 evpn
                  no route-target export 803:3868
                  no route-target export 803:3868 evpn
                address-family ipv6 unicast
                  no route-target import 803:3868
                  no route-target import 803:3868 evpn
                  no route-target export 803:3868
                  no route-target export 803:3868 evpn

              evpn
                vni 10018 l2
                  no route-target import 703:18
                  no route-target export 703:18
                vni 10020 l2
                  no route-target import 803:20
                  no route-target export 803:20

          configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

              vrf context EVPN-VRF-38
                address-family ipv4 unicast
                  no route-target import 803:3868
                  no route-target import 803:3868 evpn
                  no route-target export 803:3868
                  no route-target export 803:3868 evpn
                address-family ipv6 unicast
                  no route-target import 803:3868
                  no route-target import 803:3868 evpn
                  no route-target export 803:3868
                  no route-target export 803:3868 evpn

              evpn
                vni 10018 l2
                  no route-target import 703:18
                  no route-target export 703:18
                vni 10020 l2
                  no route-target import 803:20
                  no route-target export 803:20

          configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['BGW-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

              vrf context EVPN-VRF-38
                address-family ipv4 unicast
                  no route-target import 803:3868
                  no route-target import 803:3868 evpn
                  no route-target export 803:3868
                  no route-target export 803:3868 evpn
                address-family ipv6 unicast
                  no route-target import 803:3868
                  no route-target import 803:3868 evpn
                  no route-target export 803:3868
                  no route-target export 803:3868 evpn

              evpn
                vni 40018 l2
                  no route-target import 703:18
                  no route-target export 703:18
                vni 40020 l2
                  no route-target import 803:20
                  no route-target export 803:20

          configure replace bootflash:config_replace.cfg verbose

              ''')

        sleep(10)

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['BGW-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace4 = testscript.parameters['BGW-2'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)
        match4 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace4)

        sleep(60)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success' and match4[1] == 'Success':
            self.passed(reason="Rollback Passed")
        else:
            self.failed(reason="Rollback Failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(30)

        proto_result = ixLib.restart_protocols()
        if proto_result == 0:
            log.debug("Re-Starting Protocols failed")
            self.errored("Re-Starting Protocols failed", goto=['next_tc'])
        else:
            log.info("Re-Started Protocols Successfully")

        time.sleep(30)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class FINAL_CC_CHECK(aetest.Testcase):
    """ FINAL_CC_CHECK """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONSISTENCY_CHECK(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        fail_flag = []
        status_msgs = ''

        for dut in post_test_process_dict['dut_list']:
            status = infraVerify.verifyBasicVxLANCC(dut)
            fail_flag.append(status['status'])
            status_msgs += status['logs']

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

# # ########################################################################
# # ####                       COMMON CLEANUP SECTION                    ###
# # ########################################################################
# # #
# # ## Remove the BASE CONFIGURATION that was applied earlier in the 
# # ## common cleanup section, clean the left over


class common_cleanup(aetest.CommonCleanup):
    """ Common Cleanup for Sample Test """

    # @aetest.subsection
    # def cleanUP_LEAF1(self, testscript):
    #     """ Common Cleanup subsection """
    #     log.info(banner("LEAF1 common cleanup starts here"))

    #     if not testscript.parameters['script_flags']['skip_device_cleanup']:

    #         vrfConfigurations = ''
    #         l3_vrf_count_iter = 1
    #         while l3_vrf_count_iter <= testscript.parameters['forwardingSysDict']['VRF_count']:
    #             vrfConfigurations += 'no vrf context ' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(l3_vrf_count_iter) + '\n'
    #             l3_vrf_count_iter += 1

    #         featureConfigurations = ''
    #         for feature in testscript.parameters['LeafFeatureList']:
    #             featureConfigurations += 'no feature ' + str(feature) + '\n'

    #         testscript.parameters['LEAF-1'].configure('''                        

    #                     default interface ''' + str(testscript.parameters['intf_LEAF_1_to_SPINE']) + '''
    #                     default interface ''' + str(testscript.parameters['intf_LEAF_1_to_FAN']) + '''

    #                     no vlan 10-11,301-304
    #                     no interface loop0
    #                     no interface loop1

    #                     no interface port-channel200
    #                     no interface port-channel211

    #                     no feature nv overlay
    #                     no nv overlay evpn

    #                 ''' + str(vrfConfigurations) + '''
    #                 ''' + str(featureConfigurations) + '''

    #                     no feature-set mpls

    #                 ''', timeout=900)
    #         testscript.parameters['LEAF-1'].execute("show run | no", timeout=900)

    #     else:
    #         self.passed(reason="Skipped device cleanup as requested")

    # @aetest.subsection
    # def cleanUP_LEAF2(self, testscript):
    #     """ Common Cleanup subsection """
    #     log.info(banner("LEAF2 common cleanup starts here"))

    #     if not testscript.parameters['script_flags']['skip_device_cleanup']:

    #         vrfConfigurations = ''
    #         l3_vrf_count_iter = 1
    #         while l3_vrf_count_iter <= testscript.parameters['forwardingSysDict']['VRF_count']:
    #             vrfConfigurations += 'no vrf context ' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(l3_vrf_count_iter) + '\n'
    #             l3_vrf_count_iter += 1

    #         featureConfigurations = ''
    #         for feature in testscript.parameters['LeafFeatureList']:
    #             featureConfigurations += 'no feature ' + str(feature) + '\n'

    #         testscript.parameters['LEAF-2'].configure('''                        

    #                     default interface ''' + str(testscript.parameters['intf_LEAF_2_to_SPINE']) + '''
    #                     default interface ''' + str(testscript.parameters['intf_LEAF_2_to_FAN']) + '''

    #                     no vlan 10-11,301-304
    #                     no interface loop0
    #                     no interface loop1

    #                     no interface port-channel200
    #                     no interface port-channel212

    #                     no feature nv overlay
    #                     no nv overlay evpn

    #                 ''' + str(vrfConfigurations) + '''
    #                 ''' + str(featureConfigurations) + '''

    #                     no feature-set mpls

    #                 ''', timeout=900)
    #         testscript.parameters['LEAF-2'].execute("show run | no", timeout=900)

    #     else:
    #         self.passed(reason="Skipped device cleanup as requested")

    # @aetest.subsection
    # def cleanUP_LEAF3(self, testscript):
    #     """ Common Cleanup subsection """
    #     log.info(banner("LEAF3 common cleanup starts here"))

    #     if not testscript.parameters['script_flags']['skip_device_cleanup']:

    #         vrfConfigurations = ''
    #         l3_vrf_count_iter = 1
    #         while l3_vrf_count_iter <= testscript.parameters['forwardingSysDict']['VRF_count']:
    #             vrfConfigurations += 'no vrf context ' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(l3_vrf_count_iter) + '\n'
    #             l3_vrf_count_iter += 1

    #         featureConfigurations = ''
    #         for feature in testscript.parameters['LeafFeatureList']:
    #             featureConfigurations += 'no feature ' + str(feature) + '\n'

    #         testscript.parameters['LEAF-3'].configure('''                        

    #                     default interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''
    #                     default interface ''' + str(testscript.parameters['intf_LEAF_3_to_IXIA']) + '''

    #                     no vlan 10-11,301-304
    #                     no interface loop0
    #                     no interface loop1

    #                     no interface port-channel200
    #                     no interface port-channel213

    #                     no feature nv overlay
    #                     no nv overlay evpn

    #                 ''' + str(vrfConfigurations) + '''
    #                 ''' + str(featureConfigurations) + '''

    #                     no feature-set mpls

    #                 ''', timeout=900)
    #         testscript.parameters['LEAF-3'].execute("show run | no", timeout=900)

    #     else:
    #         self.passed(reason="Skipped device cleanup as requested")

    # @aetest.subsection
    # def cleanUP_SPINE(self, testscript):
    #     """ Common Cleanup subsection """
    #     log.info(banner("SPINE common cleanup starts here"))

    #     if not testscript.parameters['script_flags']['skip_device_cleanup']:

    #         featureConfigurations = ''
    #         for feature in testscript.parameters['spineFeatureList']:
    #             featureConfigurations += 'no feature ' + str(feature) + '\n'

    #         testscript.parameters['SPINE'].configure('''                        

    #                     default interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_1']) + '''
    #                     default interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_2']) + '''
    #                     default interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_3']) + '''

    #                     no vlan 10-11,301-304
    #                     no interface loop0

    #                     no interface port-channel211
    #                     no interface port-channel212
    #                     no interface port-channel213

    #                     ''' + str(featureConfigurations) + '''
    #                 ''', timeout=900)
    #         testscript.parameters['SPINE'].execute("show run | no", timeout=900)

    #     else:
    #         self.passed(reason="Skipped device cleanup as requested")

    # @aetest.subsection
    # def cleanUP_FAN(self, testscript):
    #     """ Common Cleanup subsection """
    #     log.info(banner("FAN common cleanup starts here"))

    #     if not testscript.parameters['script_flags']['skip_device_cleanup']:

    #         featureConfigurations = ''
    #         for feature in testscript.parameters['fanOutFeatureList']:
    #             featureConfigurations += 'no feature ' + str(feature) + '\n'

    #         testscript.parameters['FAN'].configure('''                        

    #                     default interface ''' + str(testscript.parameters['intf_FAN_to_LEAF_1']) + '''
    #                     default interface ''' + str(testscript.parameters['intf_FAN_to_LEAF_2']) + '''

    #                     no vlan 10-11,301-304

    #                     no interface port-channel200

    #                     ''' + str(featureConfigurations) + '''

    #                 ''', timeout=900)
    #         testscript.parameters['FAN'].execute("show run | no", timeout=900)

    #     else:
    #         self.passed(reason="Skipped device cleanup as requested")


if __name__ == '__main__':  # pragma: no cover
    aetest.main()
