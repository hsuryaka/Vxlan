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

# *****************************************************************************************************************************#

def BUM_State(json_input, BUM):
  for i in json_input['TABLE_storm_control_level']['ROW_storm_control_level']:
    if i['type'] == BUM:
        return i['status'], i['level']

# *****************************************************************************************************************************#

def Total_BW(json_input, Int_Type):
  for i in json_input['TABLE_total_bandwidth']['ROW_total_bandwidth']:
    if i['type'] == Int_Type:
        return i['bandwidth']

# *****************************************************************************************************************************#

def Interface_Table(json_input, Interface):
  for i in json_input['TABLE_counters']['ROW_counters']:
    if i['interface'] == Interface:
        return i['eth_outrate_mbps'],i['eth_outrate_pcnt']

# *****************************************************************************************************************************#

def PO_Mem(json_input, Interface):
    for i in json_input['TABLE_channel']['ROW_channel']['TABLE_member']['ROW_member']:
        if i['port'] == Interface:
            return i['port-status']

# *****************************************************************************************************************************#

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
        if 'script_flags' not in job_file_params.keys():
            script_flags = {}
            testscript.parameters['script_flags'] = {}
        else:
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
        else:
            testscript.parameters['script_flags']['skip_device_config'] = 0
            testscript.parameters['script_flags']['skip_tgen_config'] = 0
            testscript.parameters['script_flags']['skip_device_cleanup'] = 0

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

        testscript.parameters['intf_LEAF_1_to_BGW_1_1'] = LEAF_1.interfaces['LEAF-1_to_BGW-1_1'].intf
        testscript.parameters['intf_LEAF_1_to_BGW_1_2'] = LEAF_1.interfaces['LEAF-1_to_BGW-1_2'].intf
        testscript.parameters['intf_LEAF_1_to_IXIA'] = LEAF_1.interfaces['LEAF-1_to_IXIA'].intf

        testscript.parameters['intf_LEAF_2_to_BGW_2_1'] = LEAF_2.interfaces['LEAF-2_to_BGW-2_1'].intf
        testscript.parameters['intf_LEAF_2_to_BGW_2_2'] = LEAF_2.interfaces['LEAF-2_to_BGW-2_2'].intf
        testscript.parameters['intf_LEAF_2_to_IXIA'] = LEAF_2.interfaces['LEAF-2_to_IXIA'].intf

        testscript.parameters['intf_BGW_1_to_LEAF_1_1'] = BGW_1.interfaces['BGW-1_to_LEAF-1_1'].intf
        testscript.parameters['intf_BGW_1_to_LEAF_1_2'] = BGW_1.interfaces['BGW-1_to_LEAF-1_2'].intf
        testscript.parameters['intf_BGW_1_to_BGW_2_1'] = BGW_1.interfaces['BGW-1_to_BGW-2_1'].intf
        testscript.parameters['intf_BGW_1_to_BGW_2_2'] = BGW_1.interfaces['BGW-1_to_BGW-2_2'].intf

        testscript.parameters['intf_BGW_2_to_LEAF_2_1'] = BGW_2.interfaces['BGW-2_to_LEAF-2_1'].intf
        testscript.parameters['intf_BGW_2_to_LEAF_2_2'] = BGW_2.interfaces['BGW-2_to_LEAF-2_2'].intf
        testscript.parameters['intf_BGW_2_to_BGW_1_1'] = BGW_2.interfaces['BGW-2_to_BGW-1_1'].intf
        testscript.parameters['intf_BGW_2_to_BGW_1_2'] = BGW_2.interfaces['BGW-2_to_BGW-1_2'].intf

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

              interface ''' + str(testscript.parameters['intf_LEAF_1_to_BGW_1_1']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                no shutdown

              interface ''' + str(testscript.parameters['intf_LEAF_1_to_BGW_1_2']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                no shutdown

              interface ''' + str(testscript.parameters['intf_LEAF_1_to_IXIA']) + '''
                switchport
                switchport mode trunk
                spanning-tree port type edge trunk
                no shutdown

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

                interface ''' + str(testscript.parameters['intf_LEAF_2_to_BGW_2_1']) + '''
                  channel-group ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                  no shutdown

                interface ''' + str(testscript.parameters['intf_LEAF_2_to_BGW_2_2']) + '''
                  channel-group ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                  no shutdown

                interface ''' + str(testscript.parameters['intf_LEAF_2_to_IXIA']) + '''
                  switchport
                  switchport mode trunk
                  spanning-tree port type edge trunk
                  no shutdown

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

              interface ''' + str(testscript.parameters['intf_BGW_1_to_LEAF_1_1']) + '''
                channel-group ''' + str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                no shutdown

              interface ''' + str(testscript.parameters['intf_BGW_1_to_LEAF_1_2']) + '''
                channel-group ''' + str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                no shutdown

                evpn multisite border-gateway 100

                interface nve1
                  member vni 10017
                    multisite ingress-replication
                  member vni 10018
                    multisite ingress-replication
                  member vni 10019
                    multisite ingress-replication
                  member vni 10020
                    multisite ingress-replication
                
                route-map RMAP_REDIST_DIRECT permit 10
                  match tag 54321 
                
                interface nve1
                  multisite border-gateway interface loopback100
                  
                interface port-channel ''' + str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                  evpn multisite fabric-tracking

                interface port-channel ''' + str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id']) + '''
                  ip address 10.51.21.1/30 tag 54321
                  evpn multisite dci-tracking
                  no shutdown                

                interface ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2_1']) + '''
                  channel-group ''' + str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id']) + ''' force mode active
                  no shutdown

                interface ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2_2']) + '''
                  channel-group ''' + str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id']) + ''' force mode active
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
                    update-source port-channel ''' + str(testscript.parameters['BGW_2_dict']['DCI_Link_PO']['po_id']) + '''
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

              interface ''' + str(testscript.parameters['intf_BGW_2_to_LEAF_2_1']) + '''
                channel-group ''' + str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                no shutdown

              interface ''' + str(testscript.parameters['intf_BGW_2_to_LEAF_2_2']) + '''
                channel-group ''' + str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                no shutdown

              evpn multisite border-gateway 200

              interface nve1
                member vni 10017
                  multisite ingress-replication
                member vni 10018
                  multisite ingress-replication
                member vni 10019
                  multisite ingress-replication
                member vni 10020
                  multisite ingress-replication

                route-map RMAP_REDIST_DIRECT permit 10
                  match tag 54321 
                
                interface nve1
                  multisite border-gateway interface loopback100
                  
                interface port-channel ''' + str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                  evpn multisite fabric-tracking

                interface port-channel ''' + str(testscript.parameters['BGW_2_dict']['DCI_Link_PO']['po_id']) + '''
                  ip address 10.51.21.2/30 tag 54321
                  evpn multisite dci-tracking
                  no shutdown

                interface ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1_1']) + '''
                  channel-group ''' + str(testscript.parameters['BGW_2_dict']['DCI_Link_PO']['po_id']) + ''' force mode active
                  no shutdown

                interface ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1_2']) + '''
                  channel-group ''' + str(testscript.parameters['BGW_2_dict']['DCI_Link_PO']['po_id']) + ''' force mode active
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
                    update-source port-channel ''' + str(testscript.parameters['BGW_2_dict']['DCI_Link_PO']['po_id']) + '''
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

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

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

        P1_dict = testscript.parameters['LEAF_1_TGEN_dict']

        BCAST_L1_to_L2_dict = {
                            'src_hndl'      : IX_TP1['port_handle'],
                            'dst_hndl'      : IX_TP2['port_handle'],
                            'TI_name'       : "BCAST_L1_to_L2",
                            'frame_size'    : "1500",
                            'rate_pps'      : "1000",
                            'src_mac'       : "00:00:30:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "4",
                            'vlan_id'       : "17",
                            'vlanid_step'   : "1",
                            'vlanid_count'  : "4",
                            'ip_src_addrs'  : "2.1.1.100",
                            'ip_step'       : "0.0.1.0",
                      }

        BCAST_L1_to_L2_TI = testscript.parameters['BCAST_L1_to_L2_TI'] = ixLib.configure_ixia_BCAST_traffic_item(BCAST_L1_to_L2_dict)

        if BCAST_L1_to_L2_TI == 0:
            log.debug("Configuring BCast from L1 to L2 failed")
            self.errored("Configuring BCast from L1 to L2 failed", goto=['next_tc'])

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

        P1_dict = testscript.parameters['LEAF_1_TGEN_dict']

        UKNOWN_UCAST_L1_to_L2_dict = {
                            'src_hndl'      : IX_TP1['port_handle'],
                            'dst_hndl'      : IX_TP2['port_handle'],
                            'TI_name'       : "UKNOWN_UCAST_L1_to_L2",
                            'frame_size'    : "1500",
                            'rate_pps'      : "1000",
                            'dst_mac'       : "00:00:45:00:00:01",
                            'dstmac_step'   : "00:00:00:00:00:01",
                            'dstmac_count'  : "4",
                            'src_mac'       : "00:00:41:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "4",
                            'vlan_id'       : "17",
                            'vlanid_step'   : "1",
                            'vlanid_count'  : "4",
                      }

        UKNOWN_UCAST_L1_to_L2_TI = testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI'] = ixLib.configure_ixia_UNKNOWN_UCAST_traffic_item(UKNOWN_UCAST_L1_to_L2_dict)

        if UKNOWN_UCAST_L1_to_L2_TI == 0:
            log.debug("Configuring UNKNOWN_UCAST TI failed")
            self.errored("Configuring UNKNOWN_UCAST TI failed", goto=['next_tc'])

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_CONFIGURE_BUM_MCAST_IXIA_TRAFFIC(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def CONFIGURE_BUM_MCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']

        P2_dict = testscript.parameters['LEAF_2_TGEN_dict']

        BUM_MCAST_L2_to_L1_dict = {
                            'src_hndl'      : IX_TP2['port_handle'],
                            'dst_hndl'      : IX_TP1['port_handle'],
                            'TI_name'       : "BUM_MCAST_L2_to_L1",
                            'frame_size'    : "1500",
                            'rate_pps'      : "1000",
                            'dst_mac'       : "01:00:5E:00:00:C8",
                            'dstmac_step'   : "00:00:00:00:00:00",
                            'dstmac_count'  : "4",
                            'src_mac'       : "00:00:55:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "4",
                            'vlan_id'       : "17",
                            'vlanid_step'   : "1",
                            'vlanid_count'  : "4",
                            'ip_src_addrs'  : "2.1.1.200",
                            'ip_src_step'   : "0.0.1.0",
                            'ip_dst_addrs'  : '226.1.1.10',
                            'ip_dst_step'   : '0.0.1.0',
                      }

        BUM_MCAST_L2_to_L1_TI = testscript.parameters['BUM_MCAST_L2_to_L1_TI'] = ixLib.configure_ixia_raw_vlan_traffic(BUM_MCAST_L2_to_L1_dict)

        if BUM_MCAST_L2_to_L1_TI == 0:
            log.debug("Configuring BUM_MCAST TI failed")
            self.errored("Configuring BUM_MCAST TI failed", goto=['cleanup'])

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

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
                                'rate_pps'  : "10000",
                                'bi_dir'    : 1
                                }

            L2KUC_v6_dict = {'src_hndl'   : IX_TP1['ipv6_handle'],
                                'dst_hndl'  : IX_TP2['ipv6_handle'],
                                'circuit'   : 'ipv6',
                                'TI_name'   : "L2KUC_TP1_TP2_V6",
                                'rate_pps'  : "10000",
                                'bi_dir'    : 1
                                }

            L2KUC_v4_TI = testscript.parameters['L2KUC_v4_TI'] = ixLib.configure_ixia_traffic_item(L2KUC_v4_dict)
            L2KUC_v6_TI = testscript.parameters['L2KUC_v6_TI'] = ixLib.configure_ixia_traffic_item(L2KUC_v6_dict)

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
                                'TI_name'               : "L3KUC_TP1_TP2_V4",
                                'rate_pps'              : "10000",
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
                                'TI_name'               : "L3KUC_TP1_TP2_V6",
                                'rate_pps'              : "10000",
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

            L3KUC_v4_TI = testscript.parameters['L3KUC_v4_TI'] = ixLib.configure_multi_endpoint_ixia_traffic_item(L3KUC_v4_dict)
            L3KUC_v6_TI = testscript.parameters['L3KUC_v6_TI'] = ixLib.configure_multi_endpoint_ixia_traffic_item(L3KUC_v6_dict)

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
            self.passed("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

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

class TC001_Configure_MultiSite_Storm_Control_Unicast_on_BGW1(aetest.Testcase):
    """TC001_Configure_MultiSite_Storm_Control_Unicast_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

        sleep(60)

    @aetest.test
    def Configure_MultiSite_Storm_Control_Unicast_on_BGW1(self, testscript):
        """ Configure_MultiSite_Storm_Control_Unicast_on_BGW1 subsection: Configuring MultiSite Storm Control Unicast on BGW-1 """

        log.info(banner("MultiSite Storm-Control Functional Testing Block on BGW-1"))

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC002_Configure_MultiSite_Storm_Control_Broadcast_on_BGW1(aetest.Testcase):
    """TC002_Configure_MultiSite_Storm_Control_Broadcast_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Configure_MultiSite_Storm_Control_Broadcast_on_BGW1(self, testscript):
        """ Configure_MultiSite_Storm_Control_Broadcast_on_BGW1 subsection: Configuring MultiSite Storm Control Broadcast on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC003_Configure_MultiSite_Storm_Control_Multicast_on_BGW1(aetest.Testcase):
    """TC003_Configure_MultiSite_Storm_Control_Multicast_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Configure_MultiSite_Storm_Control_Multicast_on_BGW1(self, testscript):
        """ Configure_MultiSite_Storm_Control_Multicast_on_BGW1 subsection: Configuring MultiSite Storm Control Multicast on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC004_Verify_MultiSite_Storm_Control_Unicast_FIB_Programming_on_BGW1(aetest.Testcase):
    """TC004_Verify_MultiSite_Storm_Control_Unicast_FIB_Programming_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_MultiSite_Storm_Control_Unicast_FIB_Programming_on_BGW1(self, testscript):
        """ Verify_MultiSite_Storm_Control_Unicast_FIB_Programming_on_BGW1 subsection: Verify Storm Control Unicast FIB Programming on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        mssc_fib = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(mssc_fib, 'Unicast')

        mssc_fib_ucast_status = mssc_fib_ucast[0]
        mssc_fib_ucast_level  = float(mssc_fib_ucast[1])

        if mssc_fib_ucast_status == 'Enabled':
            log.info("PASS : MultiSite Storm-Control is "+str(mssc_fib_ucast_status)+" for Ucast\n\n")
            self.passed("PASS : MultiSite Storm-Control is "+str(mssc_fib_ucast_status)+" for Ucast\n\n")
        else:
            log.debug("FAIL : MultiSite Storm-Control is "+str(mssc_fib_ucast_status)+" for Ucast\n\n")
            self.failed("FAIL : MultiSite Storm-Control is "+str(mssc_fib_ucast_status)+" for Ucast\n\n")

        if mssc_fib_ucast_level == float(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast']):
            log.info("PASS : MultiSite Storm-Control Level is Configured "+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+" is reflecting "+str(mssc_fib_ucast_level)+" for Ucast\n\n")
            self.passed("PASS : MultiSite Storm-Control Level is Configured "+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+" is reflecting "+str(mssc_fib_ucast_level)+" for Ucast\n\n")
        else:
            log.debug("FAIL : MultiSite Storm-Control Level is Configured "+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+" but NOT reflecting "+str(mssc_fib_ucast_level)+" for Ucast\n\n")
            self.failed("FAIL : MultiSite Storm-Control Level is Configured "+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+" but NOT reflecting "+str(mssc_fib_ucast_level)+" for Ucast\n\n")

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC005_Verify_MultiSite_Storm_Control_Broadcast_FIB_Programming_on_BGW1(aetest.Testcase):
    """TC005_Verify_MultiSite_Storm_Control_Broadcast_FIB_Programming_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_MultiSite_Storm_Control_Broadcast_FIB_Programming_on_BGW1(self, testscript):
        """ Verify_MultiSite_Storm_Control_Broadcast_FIB_Programming_on_BGW1 subsection: Verify Storm Control Broadcast FIB Programming on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        mssc_fib = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(mssc_fib, 'Broadcast')

        mssc_fib_bcast_status = mssc_fib_bcast[0]
        mssc_fib_bcast_level  = float(mssc_fib_bcast[1])

        if mssc_fib_bcast_status == 'Enabled':
          log.info("PASS : MultiSite Storm-Control is "+str(mssc_fib_bcast_status)+" for Bcast\n\n")
        else:
          log.debug("FAIL : MultiSite Storm-Control is "+str(mssc_fib_bcast_status)+" for Bcast\n\n")

        if mssc_fib_bcast_level == float(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast']):
          log.info("PASS : MultiSite Storm-Control Level is Configured "+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+" is reflecting "+str(mssc_fib_bcast_level)+" for Bcast\n\n")
          self.passed("PASS : MultiSite Storm-Control Level is Configured "+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+" is reflecting "+str(mssc_fib_bcast_level)+" for Bcast\n\n")
        else:
          log.debug("FAIL : MultiSite Storm-Control Level is Configured "+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+" but NOT reflecting "+str(mssc_fib_bcast_level)+" for Bcast\n\n")
          self.failed("FAIL : MultiSite Storm-Control Level is Configured "+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+" but NOT reflecting "+str(mssc_fib_bcast_level)+" for Bcast\n\n")

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC006_Verify_MultiSite_Storm_Control_Multicast_FIB_Programming_on_BGW1(aetest.Testcase):
    """TC006_Verify_MultiSite_Storm_Control_Multicast_FIB_Programming_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_MultiSite_Storm_Control_Multicast_FIB_Programming_on_BGW1(self, testscript):
        """ Verify_MultiSite_Storm_Control_Multicast_FIB_Programming_on_BGW1 subsection: Verify Storm Control Multicast FIB Programming on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        mssc_fib = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(mssc_fib, 'Multicast')

        mssc_fib_mcast_status = mssc_fib_mcast[0]
        mssc_fib_mcast_level  = float(mssc_fib_mcast[1])

        if mssc_fib_mcast_status == 'Enabled':
          log.info("PASS : MultiSite Storm-Control is "+str(mssc_fib_mcast_status)+" for Mcast\n\n")
        else:
          log.debug("FAIL : MultiSite Storm-Control is "+str(mssc_fib_mcast_status)+" for Mcast\n\n")

        if mssc_fib_mcast_level == float(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast']):
          log.info("PASS : MultiSite Storm-Control Level is Configured "+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+" is reflecting "+str(mssc_fib_mcast_level)+" for Mcast\n\n")
          self.passed("PASS : MultiSite Storm-Control Level is Configured "+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+" is reflecting "+str(mssc_fib_mcast_level)+" for Mcast\n\n")
        else:
          log.debug("FAIL : MultiSite Storm-Control Level is Configured "+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+" but NOT reflecting "+str(mssc_fib_mcast_level)+" for Mcast\n\n")
          self.failed("FAIL : MultiSite Storm-Control Level is Configured "+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+" but NOT reflecting "+str(mssc_fib_mcast_level)+" for Mcast\n\n")

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC007_Verify_MultiSite_DCI_Links_on_BGW1(aetest.Testcase):
    """TC007_Verify_MultiSite_DCI_Links_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_MultiSite_DCI_Links_on_BGW1(self, testscript):
        """ Verify_MultiSite_DCI_Links_on_BGW1 subsection: Verify MultiSite DCI Links on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level 100
              evpn storm-control broadcast level 100
              evpn storm-control multicast level 100

          ''')

        dci_link_bgw1_to_bgw2 = 'port-channel'+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        dci_link_on_bgw1 = json.loads(testscript.parameters['BGW-1'].execute('''show nve multisite dci-links | json'''))

        dci_link_on_bgw1_if_name  = dci_link_on_bgw1['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-name']
        dci_link_on_bgw1_if_state = dci_link_on_bgw1['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-state']

        if dci_link_bgw1_to_bgw2 in dci_link_on_bgw1_if_name:
            log.info("PASS : DCI Link Config - "+str(dci_link_bgw1_to_bgw2)+" is Correctly reflecting on BGW-1 - "+str(dci_link_on_bgw1_if_name)+" \n\n")
        else:
            log.debug("FAIL : DCI Link Config - "+str(dci_link_bgw1_to_bgw2)+" is NOT Correctly reflecting on BGW-1 - "+str(dci_link_on_bgw1_if_name)+" \n\n")

        if 'Up' in dci_link_on_bgw1_if_state:
            log.info("PASS : DCI Link is 'UP' on BGW-1 - "+str(dci_link_on_bgw1_if_state)+" \n\n")
            self.passed("PASS : DCI Link is 'UP' on BGW-1 - "+str(dci_link_on_bgw1_if_state)+" \n\n")
        else:
            log.debug("FAIL : DCI Link is 'NOT UP' on BGW-1 - "+str(dci_link_on_bgw1_if_state)+" \n\n")
            self.failed("FAIL : DCI Link is 'NOT UP' on BGW-1 - "+str(dci_link_on_bgw1_if_state)+" \n\n")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC008_Verify_MultiSite_DCI_Links_on_BGW2(aetest.Testcase):
    """TC008_Verify_MultiSite_DCI_Links_on_BGW2"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_MultiSite_DCI_Links_on_BGW2(self, testscript):
        """ Verify_MultiSite_DCI_Links_on_BGW2 subsection: Verify MultiSite DCI Links on BGW-2 """

        dci_link_bgw2_to_bgw1 = 'port-channel'+str(testscript.parameters['BGW_2_dict']['DCI_Link_PO']['po_id'])

        dci_link_on_bgw2 = json.loads(testscript.parameters['BGW-2'].execute('''show nve multisite dci-links | json'''))

        dci_link_on_bgw2_if_name  = dci_link_on_bgw2['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-name']
        dci_link_on_bgw2_if_state = dci_link_on_bgw2['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-state']

        if dci_link_bgw2_to_bgw1 in dci_link_on_bgw2_if_name:
            log.info("PASS : DCI Link Config - "+str(dci_link_bgw2_to_bgw1)+" is Correctly reflecting on BGW-2 - "+str(dci_link_on_bgw2_if_name)+"  \n\n")
        else:
            log.debug("FAIL : DCI Link Config - "+str(dci_link_bgw2_to_bgw1)+" is NOT Correctly reflecting on BGW-2 - "+str(dci_link_on_bgw2_if_name)+" \n\n")

        if 'Up' in dci_link_on_bgw2_if_state:
            log.info("PASS : DCI Link is 'UP' on BGW-2 - "+str(dci_link_on_bgw2_if_state)+" \n\n")
            self.passed("PASS : DCI Link is 'UP' on BGW-2 - "+str(dci_link_on_bgw2_if_state)+" \n\n")
        else:
            log.debug("FAIL : DCI Link is 'NOT UP' on BGW-2 - "+str(dci_link_on_bgw2_if_state)+" \n\n")
            self.failed("FAIL : DCI Link is 'NOT UP' on BGW-2 - "+str(dci_link_on_bgw2_if_state)+" \n\n")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class TC009_Verify_MultiSite_Fabric_Links_on_BGW1(aetest.Testcase):
    """TC009_Verify_MultiSite_Fabric_Links_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_MultiSite_Fabric_Links_on_BGW1(self, testscript):
        """ Verify_MultiSite_Fabric_Links_on_BGW1 subsection: Verify MultiSite Fabric Links on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level 100
              evpn storm-control broadcast level 100
              evpn storm-control multicast level 100

          ''')

        fab_link_bgw1_to_bgw2 = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        fab_link_on_bgw1 = json.loads(testscript.parameters['BGW-1'].execute('''show nve multisite fabric-links | json'''))

        fab_link_on_bgw1_if_name  = fab_link_on_bgw1['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-name']
        fab_link_on_bgw1_if_state = fab_link_on_bgw1['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-state']

        if fab_link_bgw1_to_bgw2 in fab_link_on_bgw1_if_name:
            log.info("PASS : Fabric Link Config - "+str(fab_link_bgw1_to_bgw2)+" is Correctly reflecting on BGW-1 - "+str(fab_link_on_bgw1_if_name)+" \n\n")
        else:
            log.debug("FAIL : Fabric Link Config - "+str(fab_link_bgw1_to_bgw2)+" is NOT Correctly reflecting on BGW-1 - "+str(fab_link_on_bgw1_if_name)+" \n\n")

        if 'Up' in fab_link_on_bgw1_if_state:
            log.info("PASS : Fabric Link is 'UP' on BGW-1 - "+str(fab_link_on_bgw1_if_state)+" \n\n")
            self.passed("PASS : Fabric Link is 'UP' on BGW-1 - "+str(fab_link_on_bgw1_if_state)+" \n\n")
        else:
            log.debug("FAIL : Fabric Link is 'NOT UP' on BGW-1 - "+str(fab_link_on_bgw1_if_state)+" \n\n")
            self.failed("FAIL : Fabric Link is 'NOT UP' on BGW-1 - "+str(fab_link_on_bgw1_if_state)+" \n\n")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC010_Verify_MultiSite_Fabric_Links_on_BGW2(aetest.Testcase):
    """TC010_Verify_MultiSite_Fabric_Links_on_BGW2"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_MultiSite_Fabric_Links_on_BGW2(self, testscript):
        """ Verify_MultiSite_Fabric_Links_on_BGW2 subsection: Verify MultiSite Fabric Links on BGW-2 """

        fab_link_bgw2_to_bgw1 = 'port-channel'+str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id'])

        fab_link_on_bgw2 = json.loads(testscript.parameters['BGW-2'].execute('''show nve multisite fabric-links | json'''))

        fab_link_on_bgw2_if_name  = fab_link_on_bgw2['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-name']
        fab_link_on_bgw2_if_state = fab_link_on_bgw2['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-state']

        if fab_link_bgw2_to_bgw1 in fab_link_on_bgw2_if_name:
            log.info("PASS : Fabric Link Config - "+str(fab_link_bgw2_to_bgw1)+" is Correctly reflecting on BGW-2 - "+str(fab_link_on_bgw2_if_name)+" \n\n")
        else:
            log.debug("FAIL : Fabric Link Config - "+str(fab_link_bgw2_to_bgw1)+" is NOT Correctly reflecting on BGW-2 - "+str(fab_link_on_bgw2_if_name)+" \n\n")

        if 'Up' in fab_link_on_bgw2_if_state:
            log.info("PASS : Fabric Link is 'UP' on BGW-2 - "+str(fab_link_on_bgw2_if_state)+" \n\n")
            self.passed("PASS : Fabric Link is 'UP' on BGW-2 - "+str(fab_link_on_bgw2_if_state)+" \n\n")
        else:
            log.debug("FAIL : Fabric Link is 'NOT UP' on BGW-2 - "+str(fab_link_on_bgw2_if_state)+" \n\n")
            self.failed("FAIL : Fabric Link is 'NOT UP' on BGW-2 - "+str(fab_link_on_bgw2_if_state)+" \n\n")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class TC011_Verify_Unicast_DCI_Policing_Info_on_BGW1(aetest.Testcase):
    """TC011_Verify_Unicast_DCI_Policing_Info_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_Unicast_DCI_Policing_Info_on_BGW1(self, testscript):
        """ Verify_Unicast_DCI_Policing_Info_on_BGW1 subsection: Verify Unicast DCI Policing Info on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')

        mssc_fib_ucast_level  = mssc_fib_ucast[1]
        dci_bw = Total_BW(sh_fw_dist_evpn_sc, 'DCI')

        dci_ucast_rate = int((float(mssc_fib_ucast_level) * int(dci_bw))/100)

        ucast_prog = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_prog_list = ucast_prog.replace(" ","").split("|")

        if dci_ucast_rate == int(ucast_prog_list[2]):
            log.info("PASS : DCI Rate - "+str(dci_ucast_rate)+" is Programmed Correctly for Ucast on BGW-1 - "+str(int(ucast_prog_list[2]))+" \n\n")
            self.passed("PASS : DCI Rate - "+str(dci_ucast_rate)+" is Programmed Correctly for Ucast on BGW-1 - "+str(int(ucast_prog_list[2]))+" \n\n")
        else:
            log.debug("FAIL : DCI Rate - "+str(dci_ucast_rate)+" is NOT Programmed Correctly for Ucast on BGW-1 - "+str(int(ucast_prog_list[2]))+" \n\n")
            self.failed("FAIL : DCI Rate - "+str(dci_ucast_rate)+" is NOT Programmed Correctly for Ucast on BGW-1 - "+str(int(ucast_prog_list[2]))+" \n\n")

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC012_Verify_Broadcast_DCI_Policing_Info_on_BGW1(aetest.Testcase):
    """TC012_Verify_Broadcast_DCI_Policing_Info_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_Broadcast_DCI_Policing_Info_on_BGW1(self, testscript):
        """ Verify_Broadcast_DCI_Policing_Info_on_BGW1 subsection: Verify Broadcast DCI Policing Info on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')

        mssc_fib_bcast_level  = mssc_fib_bcast[1]
        dci_bw = Total_BW(sh_fw_dist_evpn_sc, 'DCI')
        
        dci_bcast_rate = int((float(mssc_fib_bcast_level) * int(dci_bw))/100)

        bcast_prog = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_prog_list = bcast_prog.replace(" ","").split("|")

        if dci_bcast_rate == int(bcast_prog_list[2]):
            log.info("PASS : DCI Rate - "+str(dci_bcast_rate)+" is Programmed Correctly for Bcast on BGW-1 - "+str(int(bcast_prog_list[2]))+" \n\n")
            self.passed("PASS : DCI Rate - "+str(dci_bcast_rate)+" is Programmed Correctly for Bcast on BGW-1 - "+str(int(bcast_prog_list[2]))+" \n\n")
        else:
            log.debug("FAIL : DCI Rate - "+str(dci_bcast_rate)+" is NOT Programmed Correctly for Bcast on BGW-1 - "+str(int(bcast_prog_list[2]))+" \n\n")
            self.failed("FAIL : DCI Rate - "+str(dci_bcast_rate)+" is NOT Programmed Correctly for Bcast on BGW-1 - "+str(int(bcast_prog_list[2]))+" \n\n")

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC013_Verify_Multicast_DCI_Policing_Info_on_BGW1(aetest.Testcase):
    """TC013_Verify_Multicast_DCI_Policing_Info_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_Multicast_DCI_Policing_Info_on_BGW1(self, testscript):
        """ Verify_Multicast_DCI_Policing_Info_on_BGW1 subsection: Verify Multicast DCI Policing Info on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        
        mssc_fib_mcast_level  = mssc_fib_mcast[1]
        dci_bw = Total_BW(sh_fw_dist_evpn_sc, 'DCI')

        dci_mcast_rate = int((float(mssc_fib_mcast_level) * int(dci_bw))/100)

        mcast_prog = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_prog_list = mcast_prog.replace(" ","").split("|")

        if dci_mcast_rate == int(mcast_prog_list[2]):
            log.info("PASS : DCI Rate - "+str(dci_mcast_rate)+" is Programmed Correctly for Mcast on BGW-1 - "+str(int(mcast_prog_list[2]))+" \n\n")
            self.passed("PASS : DCI Rate - "+str(dci_mcast_rate)+" is Programmed Correctly for Mcast on BGW-1 - "+str(int(mcast_prog_list[2]))+" \n\n")
        else:
            log.debug("FAIL : DCI Rate - "+str(dci_mcast_rate)+" is NOT Programmed Correctly for Mcast on BGW-1 - "+str(int(mcast_prog_list[2]))+" \n\n")
            self.failed("FAIL : DCI Rate - "+str(dci_mcast_rate)+" is NOT Programmed Correctly for Mcast on BGW-1 - "+str(int(mcast_prog_list[2]))+" \n\n")

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC014_Verify_Unicast_Fabric_Policing_Info_on_BGW1(aetest.Testcase):
    """TC014_Verify_Unicast_Fabric_Policing_Info_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_Unicast_Fabric_Policing_Info_on_BGW1(self, testscript):
        """ Verify_Unicast_Fabric_Policing_Info_on_BGW1 subsection: Verify Unicast Fabric Policing Info on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        
        mssc_fib_ucast_level  = mssc_fib_ucast[1]
        fab_bw = Total_BW(sh_fw_dist_evpn_sc, 'FABRIC')

        fab_ucast_rate = int((float(mssc_fib_ucast_level) * int(fab_bw))/100)

        ucast_prog = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_prog_list = ucast_prog.replace(" ","").split("|")

        if fab_ucast_rate == int(ucast_prog_list[4]):
            log.info("PASS : Fabric Rate - "+str(fab_ucast_rate)+" is Programmed Correctly for Ucast on BGW-1 - "+str(int(ucast_prog_list[4]))+" \n\n")
            self.passed("PASS : Fabric Rate - "+str(fab_ucast_rate)+" is Programmed Correctly for Ucast on BGW-1 - "+str(int(ucast_prog_list[4]))+" \n\n")
        else:
            log.debug("FAIL : Fabric Rate - "+str(fab_ucast_rate)+" is NOT Programmed Correctly for Ucast on BGW-1 - "+str(int(ucast_prog_list[4]))+" \n\n")
            self.failed("FAIL : Fabric Rate - "+str(fab_ucast_rate)+" is NOT Programmed Correctly for Ucast on BGW-1 - "+str(int(ucast_prog_list[4]))+" \n\n")

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC015_Verify_Broadcast_Fabric_Policing_Info_on_BGW1(aetest.Testcase):
    """TC015_Verify_Broadcast_Fabric_Policing_Info_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_Broadcast_Fabric_Policing_Info_on_BGW1(self, testscript):
        """ Verify_Broadcast_Fabric_Policing_Info_on_BGW1 subsection: Verify Broadcast Fabric Policing Info on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        
        mssc_fib_bcast_level  = mssc_fib_bcast[1]
        fab_bw = Total_BW(sh_fw_dist_evpn_sc, 'FABRIC')

        fab_bcast_rate = int((float(mssc_fib_bcast_level) * int(fab_bw))/100)

        bcast_prog = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_prog_list = bcast_prog.replace(" ","").split("|")

        if fab_bcast_rate == int(bcast_prog_list[4]):
            log.info("PASS : Fabric Rate - "+str(fab_bcast_rate)+" is Programmed Correctly for Bcast on BGW-1 - "+str(int(bcast_prog_list[4]))+" \n\n")
            self.passed("PASS : Fabric Rate - "+str(fab_bcast_rate)+" is Programmed Correctly for Bcast on BGW-1 - "+str(int(bcast_prog_list[4]))+" \n\n")
        else:
            log.debug("FAIL : Fabric Rate - "+str(fab_bcast_rate)+" is NOT Programmed Correctly for Bcast on BGW-1 - "+str(int(bcast_prog_list[4]))+" \n\n")
            self.failed("FAIL : Fabric Rate - "+str(fab_bcast_rate)+" is NOT Programmed Correctly for Bcast on BGW-1 - "+str(int(bcast_prog_list[4]))+" \n\n")

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC016_Verify_Multicast_Fabric_Policing_Info_on_BGW1(aetest.Testcase):
    """TC016_Verify_Multicast_Fabric_Policing_Info_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_Multicast_Fabric_Policing_Info_on_BGW1(self, testscript):
        """ Verify_Multicast_Fabric_Policing_Info_on_BGW1 subsection: Verify Multicast Fabric Policing Info on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        fab_mcast_rate = 0

        mcast_prog = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_prog_list = mcast_prog.replace(" ","").split("|")

        if fab_mcast_rate == int(mcast_prog_list[4]):
            log.info("PASS : Fabric Rate - "+str(fab_mcast_rate)+" is Programmed Correctly for Mcast on BGW-1 - "+str(int(mcast_prog_list[4]))+" \n\n")
            self.passed("PASS : Fabric Rate - "+str(fab_mcast_rate)+" is Programmed Correctly for Mcast on BGW-1 - "+str(int(mcast_prog_list[4]))+" \n\n")
        else:
            log.debug("FAIL : Fabric Rate - "+str(fab_mcast_rate)+" is NOT Programmed Correctly for Mcast on BGW-1 - "+str(int(mcast_prog_list[4]))+" \n\n")
            self.failed("FAIL : Fabric Rate - "+str(fab_mcast_rate)+" is NOT Programmed Correctly for Mcast on BGW-1 - "+str(int(mcast_prog_list[4]))+" \n\n")

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC017_Verify_Unicast_Fabric_Policer_Stats_on_BGW1(aetest.Testcase):
    """TC017_Verify_Unicast_Fabric_Policer_Stats_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_Unicast_Fabric_Policer_Stats_on_BGW1(self, testscript):
        """ Verify_Unicast_Fabric_Policer_Stats_on_BGW1 subsection: Verify Unicast Fabric Policer Stats on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")

        sleep(30)

        ucast_index = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_index_list = ucast_index.replace(" ","").split("|")

        testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | diff")
        sleep(2)
        testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | diff")
        sleep(2)
        testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | diff")

        ucast_pass_drop_bytes = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | diff | grep " + str(ucast_index_list[3]) + "")
        ucast_pass_drop_count = ucast_pass_drop_bytes.count(ucast_index_list[3])

        if ucast_pass_drop_count == 2:
            log.info("PASS : Ingress Fabric Index - "+str(ucast_index_list[3])+" is Polcing the Ucast Traffic on BGW-1 \n\n")
        else:
            log.debug("FAIL : Ingress Fabric Index - "+str(ucast_index_list[3])+" is NOT Polcing the Ucast Traffic on BGW-1 \n\n")

        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC018_Verify_Broadcast_Fabric_Policer_Stats_on_BGW1(aetest.Testcase):
    """TC018_Verify_Broadcast_Fabric_Policer_Stats_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_Broadcast_Fabric_Policer_Stats_on_BGW1(self, testscript):
        """ Verify_Broadcast_Fabric_Policer_Stats_on_BGW1 subsection: Verify Broadcast Fabric Policer Stats on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")

        sleep(30)

        bcast_index = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_index_list = bcast_index.replace(" ","").split("|")

        testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | diff")
        sleep(2)
        testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | diff")
        sleep(2)
        testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | diff")
        sleep(2)

        bcast_pass_drop_bytes = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | diff | grep " + str(bcast_index_list[3]) + "")
        bcast_pass_drop_count = bcast_pass_drop_bytes.count(bcast_index_list[3])

        if bcast_pass_drop_count == 2:
            log.info("PASS : Ingress Fabric Index - "+str(bcast_index_list[3])+" is Polcing the Bcast Traffic on BGW-1 \n\n")
        else:
            log.debug("FAIL : Ingress Fabric Index - "+str(bcast_index_list[3])+" is NOT Polcing the Bcast Traffic on BGW-1 \n\n")

        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC019_Verify_Multicast_DCI_Policer_Stats_on_BGW1(aetest.Testcase):
    """TC019_Verify_Multicast_DCI_Policer_Stats_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_Multicast_DCI_Policer_Stats_on_BGW1(self, testscript):
        """ Verify_Multicast_DCI_Policer_Stats_on_BGW1 subsection: Verify Multicast DCI Policer Stats on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")

        sleep(30)

        mcast_index = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_index_list = mcast_index.replace(" ","").split("|")

        testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | diff")
        sleep(2)
        testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | diff")
        sleep(2)
        testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | diff")

        mcast_pass_drop_bytes = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | diff | grep " + str(mcast_index_list[1]) + "")
        mcast_pass_drop_count = mcast_pass_drop_bytes.count(mcast_index_list[1])
 
        if mcast_pass_drop_count == 2:
            log.info("PASS : Ingress DCI Index - "+str(mcast_index_list[1])+" is Polcing the Mcast Traffic on BGW-1 \n\n")
        else:
            log.debug("FAIL : Ingress DCI Index - "+str(mcast_index_list[1])+" is NOT Polcing the Mcast Traffic on BGW-1 \n\n")

        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC020_Verify_BUM_Unicast_Traffic_Rate_on_BGW1(aetest.Testcase):
    """TC020_Verify_BUM_Unicast_Traffic_Rate_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_BUM_Unicast_Traffic_Rate_on_BGW1(self, testscript):
        """ Verify_BUM_Unicast_Traffic_Rate_on_BGW1 subsection: Verify BUM Unicast Traffic Rate on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")

        sleep(30)

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")

        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC021_Verify_BUM_Broadcast_Traffic_Rate_on_BGW1(aetest.Testcase):
    """TC021_Verify_BUM_Broadcast_Traffic_Rate_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_BUM_Broadcast_Traffic_Rate_on_BGW1(self, testscript):
        """ Verify_BUM_Broadcast_Traffic_Rate_on_BGW1 subsection: Verify BUM Broadcast Traffic Rate on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")

        sleep(30)

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC022_Verify_BUM_Multicast_Traffic_Rate_on_BGW1(aetest.Testcase):
    """TC022_Verify_BUM_Multicast_Traffic_Rate_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_BUM_Multicast_Traffic_Rate_on_BGW1(self, testscript):
        """ Verify_BUM_Multicast_Traffic_Rate_on_BGW1 subsection: Verify BUM Multicast Traffic Rate on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")

        sleep(30)

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC023_Single_DCI_And_Fabric_Links(aetest.Testcase):
    """TC023_Single_DCI_And_Fabric_Links"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Single_DCI_And_Fabric_Links(self, testscript):
        """ Single_DCI_And_Fabric_Links subsection: Verify Single DCI & Fabric Links """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

              default interface ''' + str(testscript.parameters['intf_BGW_1_to_LEAF_1_2']) + '''
              default interface ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2_1']) + '''
              default interface ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2_2']) + '''

              no interface port-channel ''' + str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id']) + '''
              
              interface ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2_1']) + '''
                ip address 10.51.21.1/30 tag 54321
                evpn multisite dci-tracking
                no shutdown

              router bgp ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''
                neighbor 10.51.21.2
                  update-source ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2_1']) + '''

          ''')

        testscript.parameters['BGW-2'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              default interface ''' + str(testscript.parameters['intf_BGW_2_to_LEAF_2_2']) + '''
              default interface ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1_1']) + '''
              default interface ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1_2']) + '''

              no interface port-channel ''' + str(testscript.parameters['BGW_2_dict']['DCI_Link_PO']['po_id']) + '''

              interface ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1_1']) + '''
                ip address 10.51.21.2/30 tag 54321
                evpn multisite dci-tracking
                no shutdown
                
              router bgp ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''
                neighbor 10.51.21.1
                  update-source ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1_1']) + '''

          ''')

        sleep(180)

        #Check for DCI Links on BGW-1
        dci_link_bgw1_to_bgw2 = testscript.parameters['intf_BGW_1_to_BGW_2_1']

        dci_link_on_bgw1 = json.loads(testscript.parameters['BGW-1'].execute('''show nve multisite dci-links | json'''))

        dci_link_on_bgw1_if_name  = dci_link_on_bgw1['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-name']
        dci_link_on_bgw1_if_state = dci_link_on_bgw1['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-state']

        if dci_link_bgw1_to_bgw2 in dci_link_on_bgw1_if_name:
            log.info("PASS : Single DCI Link Config - "+str(dci_link_bgw1_to_bgw2)+" is Correctly reflecting on BGW-1 - "+str(dci_link_on_bgw1_if_name)+" \n\n")
        else:
            log.debug("FAIL : Single DCI Link Config - "+str(dci_link_bgw1_to_bgw2)+" is NOT Correctly reflecting on BGW-1 - "+str(dci_link_on_bgw1_if_name)+" \n\n")

        if 'Up' in dci_link_on_bgw1_if_state:
            log.info("PASS : Single DCI Link is 'UP' on BGW-1 - "+str(dci_link_on_bgw1_if_state)+" \n\n")
        else:
            log.debug("FAIL : Single DCI Link is 'NOT UP' on BGW-1 - "+str(dci_link_on_bgw1_if_state)+" \n\n")

        #Check for DCI Links on BGW-2
        dci_link_bgw2_to_bgw1 = testscript.parameters['intf_BGW_2_to_BGW_1_1']

        dci_link_on_bgw2 = json.loads(testscript.parameters['BGW-2'].execute('''show nve multisite dci-links | json'''))

        dci_link_on_bgw2_if_name  = dci_link_on_bgw2['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-name']
        dci_link_on_bgw2_if_state = dci_link_on_bgw2['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-state']

        if dci_link_bgw2_to_bgw1 in dci_link_on_bgw2_if_name:
            log.info("PASS : Single DCI Link Config - "+str(dci_link_bgw2_to_bgw1)+" is Correctly reflecting on BGW-2 - "+str(dci_link_on_bgw2_if_name)+"  \n\n")
        else:
            log.debug("FAIL : Single DCI Link Config - "+str(dci_link_bgw2_to_bgw1)+" is NOT Correctly reflecting on BGW-2 - "+str(dci_link_on_bgw2_if_name)+" \n\n")

        if 'Up' in dci_link_on_bgw2_if_state:
            log.info("PASS : Single DCI Link is 'UP' on BGW-2 - "+str(dci_link_on_bgw2_if_state)+" \n\n")
        else:
            log.debug("FAIL : Single DCI Link is 'NOT UP' on BGW-2 - "+str(dci_link_on_bgw2_if_state)+" \n\n")

        #Check for Fabric Links on BGW-1
        PO_Json_OP_1 = json.loads(testscript.parameters['BGW-1'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' | json'''))        
        fab_link_bgw1_to_leaf1_int = PO_Json_OP_1['TABLE_channel']['ROW_channel']['TABLE_member']['ROW_member']['port']
        fab_link_bgw1_to_leaf1_state = PO_Json_OP_1['TABLE_channel']['ROW_channel']['TABLE_member']['ROW_member']['port-status']

        if fab_link_bgw1_to_leaf1_int == testscript.parameters['intf_BGW_1_to_LEAF_1_1'] and fab_link_bgw1_to_leaf1_state == 'P':
            log.info("PASS : Single Fabric Link Config - "+str(fab_link_bgw1_to_leaf1_int)+" is Correctly reflecting on BGW-1, also "+str(fab_link_bgw1_to_leaf1_state)+"  \n\n")
        else:
            log.debug("FAIL : Single Fabric Link Config - "+str(fab_link_bgw1_to_leaf1_int)+" is NOT Correctly reflecting on BGW-1 - coz, "+str(fab_link_bgw1_to_leaf1_state)+" \n\n")

        fab_link_bgw1_to_bgw2 = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        fab_link_on_bgw1 = json.loads(testscript.parameters['BGW-1'].execute('''show nve multisite fabric-links | json'''))

        fab_link_on_bgw1_if_name  = fab_link_on_bgw1['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-name']
        fab_link_on_bgw1_if_state = fab_link_on_bgw1['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-state']

        if fab_link_bgw1_to_bgw2 in fab_link_on_bgw1_if_name:
            log.info("PASS : Single Fabric Link Config - "+str(fab_link_bgw1_to_bgw2)+" is Correctly reflecting on BGW-1 - "+str(fab_link_on_bgw1_if_name)+" \n\n")
        else:
            log.debug("FAIL : Single Fabric Link Config - "+str(fab_link_bgw1_to_bgw2)+" is NOT Correctly reflecting on BGW-1 - "+str(fab_link_on_bgw1_if_name)+" \n\n")

        if 'Up' in fab_link_on_bgw1_if_state:
            log.info("PASS : Single Fabric Link is 'UP' on BGW-1 - "+str(fab_link_on_bgw1_if_state)+" \n\n")
        else:
            log.debug("FAIL : Single Fabric Link is 'NOT UP' on BGW-1 - "+str(fab_link_on_bgw1_if_state)+" \n\n")

        #Check for Fabric Links on BGW-2
        PO_Json_OP_2 = json.loads(testscript.parameters['BGW-2'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' | json'''))        
        fab_link_bgw2_to_leaf2_int = PO_Json_OP_2['TABLE_channel']['ROW_channel']['TABLE_member']['ROW_member']['port']
        fab_link_bgw2_to_leaf2_state = PO_Json_OP_2['TABLE_channel']['ROW_channel']['TABLE_member']['ROW_member']['port-status']

        if fab_link_bgw2_to_leaf2_int == testscript.parameters['intf_BGW_2_to_LEAF_2_1'] and fab_link_bgw2_to_leaf2_state == 'P':
            log.info("PASS : Single Fabric Link Config - "+str(fab_link_bgw2_to_leaf2_int)+" is Correctly reflecting on BGW-1, also "+str(fab_link_bgw2_to_leaf2_state)+"  \n\n")
        else:
            log.debug("FAIL : Single Fabric Link Config - "+str(fab_link_bgw2_to_leaf2_int)+" is NOT Correctly reflecting on BGW-1 - coz, "+str(fab_link_bgw2_to_leaf2_state)+" \n\n")

        fab_link_bgw2_to_bgw1 = 'port-channel'+str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id'])

        fab_link_on_bgw2 = json.loads(testscript.parameters['BGW-2'].execute('''show nve multisite fabric-links | json'''))

        fab_link_on_bgw2_if_name  = fab_link_on_bgw2['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-name']
        fab_link_on_bgw2_if_state = fab_link_on_bgw2['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-state']

        if fab_link_bgw2_to_bgw1 in fab_link_on_bgw2_if_name:
            log.info("PASS : Single Fabric Link Config - "+str(fab_link_bgw2_to_bgw1)+" is Correctly reflecting on BGW-2 - "+str(fab_link_on_bgw2_if_name)+" \n\n")
        else:
            log.debug("FAIL : Single Fabric Link Config - "+str(fab_link_bgw2_to_bgw1)+" is NOT Correctly reflecting on BGW-2 - "+str(fab_link_on_bgw2_if_name)+" \n\n")

        if 'Up' in fab_link_on_bgw2_if_state:
            log.info("PASS : Single Fabric Link is 'UP' on BGW-2 - "+str(fab_link_on_bgw2_if_state)+" \n\n")
        else:
            log.debug("FAIL : Single Fabric Link is 'NOT UP' on BGW-2 - "+str(fab_link_on_bgw2_if_state)+" \n\n")

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = testscript.parameters['intf_BGW_1_to_BGW_2_1']

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = testscript.parameters['intf_BGW_1_to_BGW_2_1']

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')
        testscript.parameters['BGW-2'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(120)

# *****************************************************************************************************************************#

class TC024_Single_DCI_And_Multi_Fabric_Links(aetest.Testcase):
    """TC024_Single_DCI_And_Multi_Fabric_Links"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Single_DCI_And_Multi_Fabric_Links(self, testscript):
        """ Single_DCI_And_Multi_Fabric_Links subsection: Verify Single DCI & Multi Fabric Links """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

              default interface ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2_1']) + '''
              default interface ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2_2']) + '''

              no interface port-channel ''' + str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id']) + '''
              
              interface ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2_1']) + '''
                ip address 10.51.21.1/30 tag 54321
                evpn multisite dci-tracking
                no shutdown

              router bgp ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''
                neighbor 10.51.21.2
                  update-source ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2_1']) + '''

          ''')

        testscript.parameters['BGW-2'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              default interface ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1_1']) + '''
              default interface ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1_2']) + '''

              no interface port-channel ''' + str(testscript.parameters['BGW_2_dict']['DCI_Link_PO']['po_id']) + '''

              interface ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1_1']) + '''
                ip address 10.51.21.2/30 tag 54321
                evpn multisite dci-tracking
                no shutdown
                
              router bgp ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''
                neighbor 10.51.21.1
                  update-source ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1_1']) + '''

          ''')

        sleep(180)

        #Check for DCI Links on BGW-1
        dci_link_bgw1_to_bgw2 = testscript.parameters['intf_BGW_1_to_BGW_2_1']

        dci_link_on_bgw1 = json.loads(testscript.parameters['BGW-1'].execute('''show nve multisite dci-links | json'''))

        dci_link_on_bgw1_if_name  = dci_link_on_bgw1['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-name']
        dci_link_on_bgw1_if_state = dci_link_on_bgw1['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-state']

        if dci_link_bgw1_to_bgw2 in dci_link_on_bgw1_if_name:
            log.info("PASS : Single DCI Link Config - "+str(dci_link_bgw1_to_bgw2)+" is Correctly reflecting on BGW-1 - "+str(dci_link_on_bgw1_if_name)+" \n\n")
        else:
            log.debug("FAIL : Single DCI Link Config - "+str(dci_link_bgw1_to_bgw2)+" is NOT Correctly reflecting on BGW-1 - "+str(dci_link_on_bgw1_if_name)+" \n\n")

        if 'Up' in dci_link_on_bgw1_if_state:
            log.info("PASS : Single DCI Link is 'UP' on BGW-1 - "+str(dci_link_on_bgw1_if_state)+" \n\n")
        else:
            log.debug("FAIL : Single DCI Link is 'NOT UP' on BGW-1 - "+str(dci_link_on_bgw1_if_state)+" \n\n")

        #Check for DCI Links on BGW-2
        dci_link_bgw2_to_bgw1 = testscript.parameters['intf_BGW_2_to_BGW_1_1']

        dci_link_on_bgw2 = json.loads(testscript.parameters['BGW-2'].execute('''show nve multisite dci-links | json'''))

        dci_link_on_bgw2_if_name  = dci_link_on_bgw2['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-name']
        dci_link_on_bgw2_if_state = dci_link_on_bgw2['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-state']

        if dci_link_bgw2_to_bgw1 in dci_link_on_bgw2_if_name:
            log.info("PASS : Single DCI Link Config - "+str(dci_link_bgw2_to_bgw1)+" is Correctly reflecting on BGW-2 - "+str(dci_link_on_bgw2_if_name)+"  \n\n")
        else:
            log.debug("FAIL : Single DCI Link Config - "+str(dci_link_bgw2_to_bgw1)+" is NOT Correctly reflecting on BGW-2 - "+str(dci_link_on_bgw2_if_name)+" \n\n")

        if 'Up' in dci_link_on_bgw2_if_state:
            log.info("PASS : Single DCI Link is 'UP' on BGW-2 - "+str(dci_link_on_bgw2_if_state)+" \n\n")
        else:
            log.debug("FAIL : Single DCI Link is 'NOT UP' on BGW-2 - "+str(dci_link_on_bgw2_if_state)+" \n\n")

        #Check for Fabric Links on BGW-1
        PO_Json_OP_1 = json.loads(testscript.parameters['BGW-1'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' | json'''))        
        fab_link_bgw1_to_leaf1_1 = PO_Mem(PO_Json_OP_1, testscript.parameters['intf_BGW_1_to_LEAF_1_1'])
        fab_link_bgw1_to_leaf1_2 = PO_Mem(PO_Json_OP_1, testscript.parameters['intf_BGW_1_to_LEAF_1_2'])

        if fab_link_bgw1_to_leaf1_1 == 'P' and  fab_link_bgw1_to_leaf1_2 == 'P':
            log.info("PASS : Multi Fabric Link Config - "+str(fab_link_bgw1_to_leaf1_1)+" & "+str(fab_link_bgw1_to_leaf1_2)+" is Correctly reflecting on BGW-1 \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link Config - "+str(fab_link_bgw1_to_leaf1_1)+" & "+str(fab_link_bgw1_to_leaf1_2)+" is NOT Correctly reflecting on BGW-1 \n\n")

        fab_link_bgw1_to_bgw2 = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        fab_link_on_bgw1 = json.loads(testscript.parameters['BGW-1'].execute('''show nve multisite fabric-links | json'''))

        fab_link_on_bgw1_if_name  = fab_link_on_bgw1['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-name']
        fab_link_on_bgw1_if_state = fab_link_on_bgw1['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-state']

        if fab_link_bgw1_to_bgw2 in fab_link_on_bgw1_if_name:
            log.info("PASS : Multi Fabric Link Config - "+str(fab_link_bgw1_to_bgw2)+" is Correctly reflecting on BGW-1 - "+str(fab_link_on_bgw1_if_name)+" \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link Config - "+str(fab_link_bgw1_to_bgw2)+" is NOT Correctly reflecting on BGW-1 - "+str(fab_link_on_bgw1_if_name)+" \n\n")

        if 'Up' in fab_link_on_bgw1_if_state:
            log.info("PASS : Multi Fabric Link is 'UP' on BGW-1 - "+str(fab_link_on_bgw1_if_state)+" \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link is 'NOT UP' on BGW-1 - "+str(fab_link_on_bgw1_if_state)+" \n\n")

        #Check for Fabric Links on BGW-2
        PO_Json_OP_2 = json.loads(testscript.parameters['BGW-2'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' | json'''))        
        fab_link_bgw2_to_leaf2_1 = PO_Mem(PO_Json_OP_2, testscript.parameters['intf_BGW_2_to_LEAF_2_1'])
        fab_link_bgw2_to_leaf2_2 = PO_Mem(PO_Json_OP_2, testscript.parameters['intf_BGW_2_to_LEAF_2_2'])

        if fab_link_bgw2_to_leaf2_1 == 'P' and  fab_link_bgw2_to_leaf2_2 == 'P':
            log.info("PASS : Multi Fabric Link Config - "+str(fab_link_bgw2_to_leaf2_1)+" & "+str(fab_link_bgw2_to_leaf2_2)+" is Correctly reflecting on BGW-2 \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link Config - "+str(fab_link_bgw2_to_leaf2_1)+" & "+str(fab_link_bgw2_to_leaf2_2)+" is NOT Correctly reflecting on BGW-2 \n\n")

        fab_link_bgw2_to_bgw1 = 'port-channel'+str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id'])

        fab_link_on_bgw2 = json.loads(testscript.parameters['BGW-2'].execute('''show nve multisite fabric-links | json'''))

        fab_link_on_bgw2_if_name  = fab_link_on_bgw2['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-name']
        fab_link_on_bgw2_if_state = fab_link_on_bgw2['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-state']

        if fab_link_bgw2_to_bgw1 in fab_link_on_bgw2_if_name:
            log.info("PASS : Multi Fabric Link Config - "+str(fab_link_bgw2_to_bgw1)+" is Correctly reflecting on BGW-2 - "+str(fab_link_on_bgw2_if_name)+" \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link Config - "+str(fab_link_bgw2_to_bgw1)+" is NOT Correctly reflecting on BGW-2 - "+str(fab_link_on_bgw2_if_name)+" \n\n")

        if 'Up' in fab_link_on_bgw2_if_state:
            log.info("PASS : Multi Fabric Link is 'UP' on BGW-2 - "+str(fab_link_on_bgw2_if_state)+" \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link is 'NOT UP' on BGW-2 - "+str(fab_link_on_bgw2_if_state)+" \n\n")

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(40)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = testscript.parameters['intf_BGW_1_to_BGW_2_1']

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = testscript.parameters['intf_BGW_1_to_BGW_2_1']

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')
        testscript.parameters['BGW-2'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(120)

# *****************************************************************************************************************************#

class TC025_Multi_DCI_And_Single_Fabric_Links(aetest.Testcase):
    """TC025_Multi_DCI_And_Single_Fabric_Links"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Multi_DCI_And_Single_Fabric_Links(self, testscript):
        """ Multi_DCI_And_Single_Fabric_Links subsection: Verify Multi DCI & Single Fabric Links """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

              default interface ''' + str(testscript.parameters['intf_BGW_1_to_LEAF_1_2']) + '''

          ''')

        testscript.parameters['BGW-2'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              default interface ''' + str(testscript.parameters['intf_BGW_2_to_LEAF_2_2']) + '''

          ''')

        sleep(180)

        #Check for DCI Links on BGW-1
        PO_Json_OP_1 = json.loads(testscript.parameters['BGW-1'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id']) + ''' | json'''))        
        dci_link_bgw1_to_bgw2_1 = PO_Mem(PO_Json_OP_1, testscript.parameters['intf_BGW_1_to_BGW_2_1'])
        dci_link_bgw1_to_bgw2_2 = PO_Mem(PO_Json_OP_1, testscript.parameters['intf_BGW_1_to_BGW_2_2'])

        if dci_link_bgw1_to_bgw2_1 == 'P' and  dci_link_bgw1_to_bgw2_2 == 'P':
            log.info("PASS : Multi DCI Link Config - "+str(dci_link_bgw1_to_bgw2_1)+" & "+str(dci_link_bgw1_to_bgw2_2)+" is Correctly reflecting on BGW-1 \n\n")
        else:
            log.debug("FAIL : Multi DCI Link Config - "+str(dci_link_bgw1_to_bgw2_1)+" & "+str(dci_link_bgw1_to_bgw2_2)+" is NOT Correctly reflecting on BGW-1 \n\n")


        dci_link_bgw1_to_bgw2 = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        dci_link_on_bgw1 = json.loads(testscript.parameters['BGW-1'].execute('''show nve multisite dci-links | json'''))

        dci_link_on_bgw1_if_name  = dci_link_on_bgw1['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-name']
        dci_link_on_bgw1_if_state = dci_link_on_bgw1['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-state']

        if dci_link_bgw1_to_bgw2 in dci_link_on_bgw1_if_name:
            log.info("PASS : Multi DCI Link Config - "+str(dci_link_bgw1_to_bgw2)+" is Correctly reflecting on BGW-1 - "+str(dci_link_on_bgw1_if_name)+" \n\n")
        else:
            log.debug("FAIL : Multi DCI Link Config - "+str(dci_link_bgw1_to_bgw2)+" is NOT Correctly reflecting on BGW-1 - "+str(dci_link_on_bgw1_if_name)+" \n\n")

        if 'Up' in dci_link_on_bgw1_if_state:
            log.info("PASS : Multi DCI Link is 'UP' on BGW-1 - "+str(dci_link_on_bgw1_if_state)+" \n\n")
        else:
            log.debug("FAIL : Multi DCI Link is 'NOT UP' on BGW-1 - "+str(dci_link_on_bgw1_if_state)+" \n\n")

        #Check for DCI Links on BGW-2
        PO_Json_OP_2 = json.loads(testscript.parameters['BGW-1'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_2_dict']['DCI_Link_PO']['po_id']) + ''' | json'''))        
        dci_link_bgw2_to_bgw1_1 = PO_Mem(PO_Json_OP_2, testscript.parameters['intf_BGW_2_to_BGW_1_1'])
        dci_link_bgw2_to_bgw1_2 = PO_Mem(PO_Json_OP_2, testscript.parameters['intf_BGW_2_to_BGW_1_2'])

        if dci_link_bgw2_to_bgw1_1 == 'P' and  dci_link_bgw2_to_bgw1_2 == 'P':
            log.info("PASS : Multi DCI Link Config - "+str(dci_link_bgw2_to_bgw1_1)+" & "+str(dci_link_bgw2_to_bgw1_2)+" is Correctly reflecting on BGW-1 \n\n")
        else:
            log.debug("FAIL : Multi DCI Link Config - "+str(dci_link_bgw2_to_bgw1_1)+" & "+str(dci_link_bgw2_to_bgw1_2)+" is NOT Correctly reflecting on BGW-1 \n\n")

        dci_link_bgw2_to_bgw1 = "port-channel"+str(testscript.parameters['BGW_2_dict']['DCI_Link_PO']['po_id'])

        dci_link_on_bgw2 = json.loads(testscript.parameters['BGW-2'].execute('''show nve multisite dci-links | json'''))

        dci_link_on_bgw2_if_name  = dci_link_on_bgw2['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-name']
        dci_link_on_bgw2_if_state = dci_link_on_bgw2['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-state']

        if dci_link_bgw2_to_bgw1 in dci_link_on_bgw2_if_name:
            log.info("PASS : Multi DCI Link Config - "+str(dci_link_bgw2_to_bgw1)+" is Correctly reflecting on BGW-2 - "+str(dci_link_on_bgw2_if_name)+"  \n\n")
        else:
            log.debug("FAIL : Multi DCI Link Config - "+str(dci_link_bgw2_to_bgw1)+" is NOT Correctly reflecting on BGW-2 - "+str(dci_link_on_bgw2_if_name)+" \n\n")

        if 'Up' in dci_link_on_bgw2_if_state:
            log.info("PASS : Multi DCI Link is 'UP' on BGW-2 - "+str(dci_link_on_bgw2_if_state)+" \n\n")
        else:
            log.debug("FAIL : Multi DCI Link is 'NOT UP' on BGW-2 - "+str(dci_link_on_bgw2_if_state)+" \n\n")

        #Check for Fabric Links on BGW-1
        PO_Json_OP_3 = json.loads(testscript.parameters['BGW-1'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' | json'''))        
        fab_link_bgw1_to_leaf1_int = PO_Json_OP_3['TABLE_channel']['ROW_channel']['TABLE_member']['ROW_member']['port']
        fab_link_bgw1_to_leaf1_state = PO_Json_OP_3['TABLE_channel']['ROW_channel']['TABLE_member']['ROW_member']['port-status']

        if fab_link_bgw1_to_leaf1_int == testscript.parameters['intf_BGW_1_to_LEAF_1_1'] and fab_link_bgw1_to_leaf1_state == 'P':
            log.info("PASS : Single Fabric Link Config - "+str(fab_link_bgw1_to_leaf1_int)+" is Correctly reflecting on BGW-1, also "+str(fab_link_bgw1_to_leaf1_state)+"  \n\n")
        else:
            log.debug("FAIL : Single Fabric Link Config - "+str(fab_link_bgw1_to_leaf1_int)+" is NOT Correctly reflecting on BGW-1 - coz, "+str(fab_link_bgw1_to_leaf1_state)+" \n\n")

        fab_link_bgw1_to_bgw2 = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        fab_link_on_bgw1 = json.loads(testscript.parameters['BGW-1'].execute('''show nve multisite fabric-links | json'''))

        fab_link_on_bgw1_if_name  = fab_link_on_bgw1['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-name']
        fab_link_on_bgw1_if_state = fab_link_on_bgw1['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-state']

        if fab_link_bgw1_to_bgw2 in fab_link_on_bgw1_if_name:
            log.info("PASS : Single Fabric Link Config - "+str(fab_link_bgw1_to_bgw2)+" is Correctly reflecting on BGW-1 - "+str(fab_link_on_bgw1_if_name)+" \n\n")
        else:
            log.debug("FAIL : Single Fabric Link Config - "+str(fab_link_bgw1_to_bgw2)+" is NOT Correctly reflecting on BGW-1 - "+str(fab_link_on_bgw1_if_name)+" \n\n")

        if 'Up' in fab_link_on_bgw1_if_state:
            log.info("PASS : Single Fabric Link is 'UP' on BGW-1 - "+str(fab_link_on_bgw1_if_state)+" \n\n")
        else:
            log.debug("FAIL : Single Fabric Link is 'NOT UP' on BGW-1 - "+str(fab_link_on_bgw1_if_state)+" \n\n")

        #Check for Fabric Links on BGW-2
        PO_Json_OP_4 = json.loads(testscript.parameters['BGW-2'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' | json'''))        
        fab_link_bgw2_to_leaf2_int = PO_Json_OP_4['TABLE_channel']['ROW_channel']['TABLE_member']['ROW_member']['port']
        fab_link_bgw2_to_leaf2_state = PO_Json_OP_4['TABLE_channel']['ROW_channel']['TABLE_member']['ROW_member']['port-status']

        if fab_link_bgw2_to_leaf2_int == testscript.parameters['intf_BGW_1_to_LEAF_1_1'] and fab_link_bgw2_to_leaf2_state == 'P':
            log.info("PASS : Single Fabric Link Config - "+str(fab_link_bgw2_to_leaf2_int)+" is Correctly reflecting on BGW-1, also "+str(fab_link_bgw2_to_leaf2_state)+"  \n\n")
        else:
            log.debug("FAIL : Single Fabric Link Config - "+str(fab_link_bgw2_to_leaf2_int)+" is NOT Correctly reflecting on BGW-1 - coz, "+str(fab_link_bgw2_to_leaf2_state)+" \n\n")

        fab_link_bgw2_to_bgw1 = 'port-channel'+str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id'])

        fab_link_on_bgw2 = json.loads(testscript.parameters['BGW-2'].execute('''show nve multisite fabric-links | json'''))

        fab_link_on_bgw2_if_name  = fab_link_on_bgw2['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-name']
        fab_link_on_bgw2_if_state = fab_link_on_bgw2['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-state']

        if fab_link_bgw2_to_bgw1 in fab_link_on_bgw2_if_name:
            log.info("PASS : Single Fabric Link Config - "+str(fab_link_bgw2_to_bgw1)+" is Correctly reflecting on BGW-2 - "+str(fab_link_on_bgw2_if_name)+" \n\n")
        else:
            log.debug("FAIL : Single Fabric Link Config - "+str(fab_link_bgw2_to_bgw1)+" is NOT Correctly reflecting on BGW-2 - "+str(fab_link_on_bgw2_if_name)+" \n\n")

        if 'Up' in fab_link_on_bgw2_if_state:
            log.info("PASS : Single Fabric Link is 'UP' on BGW-2 - "+str(fab_link_on_bgw2_if_state)+" \n\n")
        else:
            log.debug("FAIL : Single Fabric Link is 'NOT UP' on BGW-2 - "+str(fab_link_on_bgw2_if_state)+" \n\n")

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')
        testscript.parameters['BGW-2'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(120)

# *****************************************************************************************************************************#

class TC026_Multi_DCI_And_Fabric_Links(aetest.Testcase):
    """TC026_Multi_DCI_And_Fabric_Links"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Multi_DCI_And_Fabric_Links(self, testscript):
        """ Multi_DCI_And_Fabric_Links subsection: Verify Multi DCI & Fabric Links """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        sleep(120)

        #Check for DCI Links on BGW-1
        PO_Json_OP_1 = json.loads(testscript.parameters['BGW-1'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id']) + ''' | json'''))        
        dci_link_bgw1_to_bgw2_1 = PO_Mem(PO_Json_OP_1, testscript.parameters['intf_BGW_1_to_BGW_2_1'])
        dci_link_bgw1_to_bgw2_2 = PO_Mem(PO_Json_OP_1, testscript.parameters['intf_BGW_1_to_BGW_2_2'])

        if dci_link_bgw1_to_bgw2_1 == 'P' and  dci_link_bgw1_to_bgw2_2 == 'P':
            log.info("PASS : Multi DCI Link Config - "+str(dci_link_bgw1_to_bgw2_1)+" & "+str(dci_link_bgw1_to_bgw2_2)+" is Correctly reflecting on BGW-1 \n\n")
        else:
            log.debug("FAIL : Multi DCI Link Config - "+str(dci_link_bgw1_to_bgw2_1)+" & "+str(dci_link_bgw1_to_bgw2_2)+" is NOT Correctly reflecting on BGW-1 \n\n")

        dci_link_bgw1_to_bgw2 = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        dci_link_on_bgw1 = json.loads(testscript.parameters['BGW-1'].execute('''show nve multisite dci-links | json'''))

        dci_link_on_bgw1_if_name  = dci_link_on_bgw1['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-name']
        dci_link_on_bgw1_if_state = dci_link_on_bgw1['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-state']

        if dci_link_bgw1_to_bgw2 in dci_link_on_bgw1_if_name:
            log.info("PASS : Multi DCI Link Config - "+str(dci_link_bgw1_to_bgw2)+" is Correctly reflecting on BGW-1 - "+str(dci_link_on_bgw1_if_name)+" \n\n")
        else:
            log.debug("FAIL : Multi DCI Link Config - "+str(dci_link_bgw1_to_bgw2)+" is NOT Correctly reflecting on BGW-1 - "+str(dci_link_on_bgw1_if_name)+" \n\n")

        if 'Up' in dci_link_on_bgw1_if_state:
            log.info("PASS : Multi DCI Link is 'UP' on BGW-1 - "+str(dci_link_on_bgw1_if_state)+" \n\n")
        else:
            log.debug("FAIL : Multi DCI Link is 'NOT UP' on BGW-1 - "+str(dci_link_on_bgw1_if_state)+" \n\n")

        #Check for DCI Links on BGW-2
        PO_Json_OP_2 = json.loads(testscript.parameters['BGW-1'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_2_dict']['DCI_Link_PO']['po_id']) + ''' | json'''))        
        dci_link_bgw2_to_bgw1_1 = PO_Mem(PO_Json_OP_2, testscript.parameters['intf_BGW_2_to_BGW_1_1'])
        dci_link_bgw2_to_bgw1_2 = PO_Mem(PO_Json_OP_2, testscript.parameters['intf_BGW_2_to_BGW_1_2'])

        if dci_link_bgw2_to_bgw1_1 == 'P' and  dci_link_bgw2_to_bgw1_2 == 'P':
            log.info("PASS : Multi DCI Link Config - "+str(dci_link_bgw2_to_bgw1_1)+" & "+str(dci_link_bgw2_to_bgw1_2)+" is Correctly reflecting on BGW-1 \n\n")
        else:
            log.debug("FAIL : Multi DCI Link Config - "+str(dci_link_bgw2_to_bgw1_1)+" & "+str(dci_link_bgw2_to_bgw1_2)+" is NOT Correctly reflecting on BGW-1 \n\n")

        dci_link_bgw2_to_bgw1 = "port-channel"+str(testscript.parameters['BGW_2_dict']['DCI_Link_PO']['po_id'])

        dci_link_on_bgw2 = json.loads(testscript.parameters['BGW-2'].execute('''show nve multisite dci-links | json'''))

        dci_link_on_bgw2_if_name  = dci_link_on_bgw2['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-name']
        dci_link_on_bgw2_if_state = dci_link_on_bgw2['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-state']

        if dci_link_bgw2_to_bgw1 in dci_link_on_bgw2_if_name:
            log.info("PASS : Multi DCI Link Config - "+str(dci_link_bgw2_to_bgw1)+" is Correctly reflecting on BGW-2 - "+str(dci_link_on_bgw2_if_name)+"  \n\n")
        else:
            log.debug("FAIL : Multi DCI Link Config - "+str(dci_link_bgw2_to_bgw1)+" is NOT Correctly reflecting on BGW-2 - "+str(dci_link_on_bgw2_if_name)+" \n\n")

        if 'Up' in dci_link_on_bgw2_if_state:
            log.info("PASS : Multi DCI Link is 'UP' on BGW-2 - "+str(dci_link_on_bgw2_if_state)+" \n\n")
        else:
            log.debug("FAIL : Multi DCI Link is 'NOT UP' on BGW-2 - "+str(dci_link_on_bgw2_if_state)+" \n\n")

        #Check for Fabric Links on BGW-1
        PO_Json_OP_3 = json.loads(testscript.parameters['BGW-1'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' | json'''))        
        fab_link_bgw1_to_leaf1_1 = PO_Mem(PO_Json_OP_3, testscript.parameters['intf_BGW_1_to_LEAF_1_1'])
        fab_link_bgw1_to_leaf1_2 = PO_Mem(PO_Json_OP_3, testscript.parameters['intf_BGW_1_to_LEAF_1_2'])

        if fab_link_bgw1_to_leaf1_1 == 'P' and  fab_link_bgw1_to_leaf1_2 == 'P':
            log.info("PASS : Multi Fabric Link Config - "+str(fab_link_bgw1_to_leaf1_1)+" & "+str(fab_link_bgw1_to_leaf1_2)+" is Correctly reflecting on BGW-1 \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link Config - "+str(fab_link_bgw1_to_leaf1_1)+" & "+str(fab_link_bgw1_to_leaf1_2)+" is NOT Correctly reflecting on BGW-1 \n\n")

        fab_link_bgw1_to_bgw2 = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        fab_link_on_bgw1 = json.loads(testscript.parameters['BGW-1'].execute('''show nve multisite fabric-links | json'''))

        fab_link_on_bgw1_if_name  = fab_link_on_bgw1['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-name']
        fab_link_on_bgw1_if_state = fab_link_on_bgw1['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-state']

        if fab_link_bgw1_to_bgw2 in fab_link_on_bgw1_if_name:
            log.info("PASS : Multi Fabric Link Config - "+str(fab_link_bgw1_to_bgw2)+" is Correctly reflecting on BGW-1 - "+str(fab_link_on_bgw1_if_name)+" \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link Config - "+str(fab_link_bgw1_to_bgw2)+" is NOT Correctly reflecting on BGW-1 - "+str(fab_link_on_bgw1_if_name)+" \n\n")

        if 'Up' in fab_link_on_bgw1_if_state:
            log.info("PASS : Multi Fabric Link is 'UP' on BGW-1 - "+str(fab_link_on_bgw1_if_state)+" \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link is 'NOT UP' on BGW-1 - "+str(fab_link_on_bgw1_if_state)+" \n\n")

        #Check for Fabric Links on BGW-2
        PO_Json_OP_4 = json.loads(testscript.parameters['BGW-2'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' | json'''))        
        fab_link_bgw2_to_leaf2_1 = PO_Mem(PO_Json_OP_4, testscript.parameters['intf_BGW_2_to_LEAF_2_1'])
        fab_link_bgw2_to_leaf2_2 = PO_Mem(PO_Json_OP_4, testscript.parameters['intf_BGW_2_to_LEAF_2_2'])

        if fab_link_bgw2_to_leaf2_1 == 'P' and  fab_link_bgw2_to_leaf2_2 == 'P':
            log.info("PASS : Multi Fabric Link Config - "+str(fab_link_bgw2_to_leaf2_1)+" & "+str(fab_link_bgw2_to_leaf2_2)+" is Correctly reflecting on BGW-2 \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link Config - "+str(fab_link_bgw2_to_leaf2_1)+" & "+str(fab_link_bgw2_to_leaf2_2)+" is NOT Correctly reflecting on BGW-2 \n\n")

        fab_link_bgw2_to_bgw1 = 'port-channel'+str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id'])

        fab_link_on_bgw2 = json.loads(testscript.parameters['BGW-2'].execute('''show nve multisite fabric-links | json'''))

        fab_link_on_bgw2_if_name  = fab_link_on_bgw2['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-name']
        fab_link_on_bgw2_if_state = fab_link_on_bgw2['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-state']

        if fab_link_bgw2_to_bgw1 in fab_link_on_bgw2_if_name:
            log.info("PASS : Multi Fabric Link Config - "+str(fab_link_bgw2_to_bgw1)+" is Correctly reflecting on BGW-2 - "+str(fab_link_on_bgw2_if_name)+" \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link Config - "+str(fab_link_bgw2_to_bgw1)+" is NOT Correctly reflecting on BGW-2 - "+str(fab_link_on_bgw2_if_name)+" \n\n")

        if 'Up' in fab_link_on_bgw2_if_state:
            log.info("PASS : Multi Fabric Link is 'UP' on BGW-2 - "+str(fab_link_on_bgw2_if_state)+" \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link is 'NOT UP' on BGW-2 - "+str(fab_link_on_bgw2_if_state)+" \n\n")

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(20)

# *****************************************************************************************************************************#

class TC027_Verify_MultiSite_StormControl_with_Ingress_Replication(aetest.Testcase):
    """TC027_Verify_MultiSite_StormControl_with_Ingress_Replication"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_MultiSite_StormControl_with_Ingress_Replication(self, testscript):
        """ Verify_MultiSite_StormControl_with_Ingress_Replication subsection: Verify MultiSite Storm-Control with Ingress-Replication """

        testscript.parameters['LEAF-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

                interface nve1
                  member vni 10017
                    no mcast-group
                    ingress-replication protocol bgp
                  member vni 10018
                    no mcast-group
                    ingress-replication protocol bgp
                  member vni 10019
                    no mcast-group
                    ingress-replication protocol bgp
                  member vni 10020
                    no mcast-group
                    ingress-replication protocol bgp

          ''')

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

                interface nve1
                  member vni 10017
                    no mcast-group
                    ingress-replication protocol bgp
                  member vni 10018
                    no mcast-group
                    ingress-replication protocol bgp
                  member vni 10019
                    no mcast-group
                    ingress-replication protocol bgp
                  member vni 10020
                    no mcast-group
                    ingress-replication protocol bgp

          ''')

        testscript.parameters['BGW-2'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

                interface nve1
                  member vni 10017
                    no mcast-group
                    ingress-replication protocol bgp
                  member vni 10018
                    no mcast-group
                    ingress-replication protocol bgp
                  member vni 10019
                    no mcast-group
                    ingress-replication protocol bgp
                  member vni 10020
                    no mcast-group
                    ingress-replication protocol bgp

          ''')

        testscript.parameters['LEAF-2'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

                interface nve1
                  member vni 10017
                    no mcast-group
                    ingress-replication protocol bgp
                  member vni 10018
                    no mcast-group
                    ingress-replication protocol bgp
                  member vni 10019
                    no mcast-group
                    ingress-replication protocol bgp
                  member vni 10020
                    no mcast-group
                    ingress-replication protocol bgp

          ''')

        sleep(60)

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['LEAF-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')
        testscript.parameters['BGW-2'].configure('''configure replace bootflash:config_replace.cfg verbose''')
        testscript.parameters['LEAF-2'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(30)

# *****************************************************************************************************************************#

class TC028_Verify_MultiSite_StormControl_with_Mcast_Group(aetest.Testcase):
    """TC028_Verify_MultiSite_StormControl_with_Mcast_Group"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_MultiSite_StormControl_with_Mcast_Group(self, testscript):
        """ Verify_MultiSite_StormControl_with_Mcast_Group subsection: Verify MultiSite Storm-Control with Mcast-Group """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC029_Verify_MultiSite_StormControl_Show_CLIs(aetest.Testcase):
    """TC029_Verify_MultiSite_StormControl_Show_CLIs"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_MultiSite_StormControl_Show_CLIs(self, testscript):
        """ Verify_MultiSite_StormControl_Show_CLIs subsection: Verify MultiSite Storm-Control Show CLIs """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

              show version
            
              show module

              show nve multisite dci-links

              show nve multisite fabric-links

              show forwarding distribution evpn storm-control

              slot 1 quoted "show hardware vxlan storm-control"


          ''')

        testscript.parameters['BGW-2'].execute('''

              show version
            
              show module

              show nve multisite dci-links

              show nve multisite fabric-links

              show forwarding distribution evpn storm-control

              slot 1 quoted "show hardware vxlan storm-control"


          ''')

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC030_Configure_MultiSite_Storm_Control_Float_Value_for_Unicast_on_BGW1(aetest.Testcase):
    """TC030_Configure_MultiSite_Storm_Control_Float_Value_for_Unicast_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Configure_MultiSite_Storm_Control_Float_Value_for_Unicast_on_BGW1(self, testscript):
        """ Configure_MultiSite_Storm_Control_Float_Value_for_Unicast_on_BGW1 subsection: Configuring MultiSite Storm Control Float Value forUnicast on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC031_Configure_MultiSite_Storm_Control_Float_Value_for_Broadcast_on_BGW1(aetest.Testcase):
    """TC031_Configure_MultiSite_Storm_Control_Float_Value_for_Broadcast_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Configure_MultiSite_Storm_Control_Float_Value_for_Broadcast_on_BGW1(self, testscript):
        """ Configure_MultiSite_Storm_Control_Float_Value_for_Broadcast_on_BGW1 subsection: Configuring MultiSite Storm Control Float Value for Broadcast on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC032_Configure_MultiSite_Storm_Control_Float_Value_for_Multicast_on_BGW1(aetest.Testcase):
    """TC032_Configure_MultiSite_Storm_Control_Float_Value_for_Multicast_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Configure_MultiSite_Storm_Control_Float_Value_for_Multicast_on_BGW1(self, testscript):
        """ Configure_MultiSite_Storm_Control_Float_Value_for_Multicast_on_BGW1 subsection: Configuring MultiSite Storm Control Float Value for Multicast on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC033_Configure_MultiSite_Storm_Control_Decimal_Value_for_Unicast_on_BGW1(aetest.Testcase):
    """TC033_Configure_MultiSite_Storm_Control_Decimal_Value_for_Unicast_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Configure_MultiSite_Storm_Control_Decimal_Value_for_Unicast_on_BGW1(self, testscript):
        """ Configure_MultiSite_Storm_Control_Decimal_Value_for_Unicast_on_BGW1 subsection: Configuring MultiSite Storm Control Decimal Value forUnicast on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(int(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast']))+'''
              evpn storm-control broadcast level '''+str(int(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast']))+'''
              evpn storm-control multicast level '''+str(int(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast']))+'''

          ''')

        sleep(30)

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC034_Configure_MultiSite_Storm_Control_Decimal_Value_for_Broadcast_on_BGW1(aetest.Testcase):
    """TC034_Configure_MultiSite_Storm_Control_Decimal_Value_for_Broadcast_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Configure_MultiSite_Storm_Control_Decimal_Value_for_Broadcast_on_BGW1(self, testscript):
        """ Configure_MultiSite_Storm_Control_Decimal_Value_for_Broadcast_on_BGW1 subsection: Configuring MultiSite Storm Control Decimal Value for Broadcast on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(int(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast']))+'''
              evpn storm-control broadcast level '''+str(int(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast']))+'''
              evpn storm-control multicast level '''+str(int(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast']))+'''

          ''')

        sleep(30)

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC035_Configure_MultiSite_Storm_Control_Decimal_Value_for_Multicast_on_BGW1(aetest.Testcase):
    """TC035_Configure_MultiSite_Storm_Control_Decimal_Value_for_Multicast_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Configure_MultiSite_Storm_Control_Decimal_Value_for_Multicast_on_BGW1(self, testscript):
        """ Configure_MultiSite_Storm_Control_Decimal_Value_for_Multicast_on_BGW1 subsection: Configuring MultiSite Storm Control Decimal Value for Multicast on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(int(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast']))+'''
              evpn storm-control broadcast level '''+str(int(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast']))+'''
              evpn storm-control multicast level '''+str(int(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast']))+'''

          ''')

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC036_Configure_MultiSite_Storm_Control_Zero_Percent_for_Unicast_on_BGW1(aetest.Testcase):
    """TC033_Configure_MultiSite_Storm_Control_Zero_Percent_for_Unicast_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Configure_MultiSite_Storm_Control_Zero_Percent_for_Unicast_on_BGW1(self, testscript):
        """ Configure_MultiSite_Storm_Control_Zero_Percent_for_Unicast_on_BGW1 subsection: Configuring MultiSite Storm Control Zero Percent forUnicast on BGW-1 """

        log.info(banner("MultiSite Storm-Control Functional Testing Block on BGW-1"))

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level 0.00
              evpn storm-control broadcast level 0.00
              evpn storm-control multicast level 0.00

          ''')

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        traffic_result = ixLib.verify_traffic({'traffic_item_list':[testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']]})

        if traffic_result['status'] == 0:
            if int(float(traffic_result['individual_TI'][testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']]['loss_percentage'])) == 100:
                log.info("Traffic Verification for Unknown Ucast Passed : "+str(traffic_result)+"")
                self.passed("Traffic Verification for Unknown Ucast Passed : "+str(traffic_result)+"")
        else:
            log.debug("Traffic Verification for Unknown Ucast Failed : "+str(traffic_result)+"")
            self.failed("Traffic Verification for Unknown Ucast Failed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')
        
        sleep(5)

# *****************************************************************************************************************************#

class TC037_Configure_MultiSite_Storm_Control_Zero_Percent_for_Broadcast_on_BGW1(aetest.Testcase):
    """TC037_Configure_MultiSite_Storm_Control_Zero_Percent_for_Broadcast_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Configure_MultiSite_Storm_Control_Zero_Percent_for_Broadcast_on_BGW1(self, testscript):
        """ Configure_MultiSite_Storm_Control_Zero_Percent_for_Broadcast_on_BGW1 subsection: Configuring MultiSite Storm Control Zero Percent for Broadcast on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level 0.00
              evpn storm-control broadcast level 0.00
              evpn storm-control multicast level 0.00

          ''')

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        traffic_result = ixLib.verify_traffic({'traffic_item_list':[testscript.parameters['BCAST_L1_to_L2_TI']]})

        if traffic_result['status'] == 0:
            if int(float(traffic_result['individual_TI'][testscript.parameters['BCAST_L1_to_L2_TI']]['loss_percentage'])) == 100:
                log.info("Traffic Verification for Bcast Passed : "+str(traffic_result)+"")
                self.passed("Traffic Verification for Bcast Passed : "+str(traffic_result)+"")
        else:
            log.debug("Traffic Verification for Bcast Failed : "+str(traffic_result)+"")
            self.failed("Traffic Verification for Bcast Failed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC038_Configure_MultiSite_Storm_Control_Zero_Percent_for_Multicast_on_BGW1(aetest.Testcase):
    """TC038_Configure_MultiSite_Storm_Control_Zero_Percent_for_Multicast_on_BGW1"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Configure_MultiSite_Storm_Control_Zero_Percent_for_Multicast_on_BGW1(self, testscript):
        """ Configure_MultiSite_Storm_Control_Zero_Percent_for_Multicast_on_BGW1 subsection: Configuring MultiSite Storm Control Zero Percent for Multicast on BGW-1 """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level 0.00
              evpn storm-control broadcast level 0.00
              evpn storm-control multicast level 0.00

          ''')

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        traffic_result = ixLib.verify_traffic({'traffic_item_list':[testscript.parameters['BUM_MCAST_L2_to_L1_TI']]})

        if traffic_result['status'] == 0:
            if int(float(traffic_result['individual_TI'][testscript.parameters['BUM_MCAST_L2_to_L1_TI']]['loss_percentage'])) == 100:
                log.info("Traffic Verification for Mcast Passed : "+str(traffic_result)+"")
                self.passed("Traffic Verification for Mcast Passed : "+str(traffic_result)+"")
        else:
            log.debug("Traffic Verification for Mcast Failed : "+str(traffic_result)+"")
            self.failed("Traffic Verification for Mcast Failed")

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC039_Remove_DCI_Links_from_PO_And_Verify_MultiSite_StormControl(aetest.Testcase):
    """TC039_Remove_DCI_Links_from_PO_And_Verify_MultiSite_StormControl"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_DCI_Links_from_PO_And_Verify_MultiSite_StormControl(self, testscript):
        """ Remove_DCI_Links_from_PO_And_Verify_MultiSite_StormControl subsection: Remove DCI Links from PO And Verify MultiSite StormControl """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

              default interface ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2_1']) + '''
              default interface ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2_2']) + '''

              no interface port-channel ''' + str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id']) + '''
              
              interface ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2_1']) + '''
                ip address 10.51.21.1/30 tag 54321
                evpn multisite dci-tracking
                no shutdown

              router bgp ''' + str(testscript.parameters['forwardingSysDict1']['BGP_AS_num']) + '''
                neighbor 10.51.21.2
                  update-source ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2_1']) + '''

          ''')

        testscript.parameters['BGW-2'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              default interface ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1_1']) + '''
              default interface ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1_2']) + '''

              no interface port-channel ''' + str(testscript.parameters['BGW_2_dict']['DCI_Link_PO']['po_id']) + '''

              interface ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1_1']) + '''
                ip address 10.51.21.2/30 tag 54321
                evpn multisite dci-tracking
                no shutdown
                
              router bgp ''' + str(testscript.parameters['forwardingSysDict2']['BGP_AS_num']) + '''
                neighbor 10.51.21.1
                  update-source ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1_2']) + '''

          ''')

        sleep(200)

        #Check for DCI Links on BGW-1
        dci_link_bgw1_to_bgw2 = testscript.parameters['intf_BGW_1_to_BGW_2_1']

        dci_link_on_bgw1 = json.loads(testscript.parameters['BGW-1'].execute('''show nve multisite dci-links | json'''))

        dci_link_on_bgw1_if_name  = dci_link_on_bgw1['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-name']
        dci_link_on_bgw1_if_state = dci_link_on_bgw1['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-state']

        if dci_link_bgw1_to_bgw2 in dci_link_on_bgw1_if_name:
            log.info("PASS : Single DCI Link Config - "+str(dci_link_bgw1_to_bgw2)+" is Correctly reflecting on BGW-1 - "+str(dci_link_on_bgw1_if_name)+" \n\n")
        else:
            log.debug("FAIL : Single DCI Link Config - "+str(dci_link_bgw1_to_bgw2)+" is NOT Correctly reflecting on BGW-1 - "+str(dci_link_on_bgw1_if_name)+" \n\n")

        if 'Up' in dci_link_on_bgw1_if_state:
            log.info("PASS : Single DCI Link is 'UP' on BGW-1 - "+str(dci_link_on_bgw1_if_state)+" \n\n")
        else:
            log.debug("FAIL : Single DCI Link is 'NOT UP' on BGW-1 - "+str(dci_link_on_bgw1_if_state)+" \n\n")

        #Check for DCI Links on BGW-2
        dci_link_bgw2_to_bgw1 = testscript.parameters['intf_BGW_2_to_BGW_1_1']

        dci_link_on_bgw2 = json.loads(testscript.parameters['BGW-2'].execute('''show nve multisite dci-links | json'''))

        dci_link_on_bgw2_if_name  = dci_link_on_bgw2['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-name']
        dci_link_on_bgw2_if_state = dci_link_on_bgw2['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-state']

        if dci_link_bgw2_to_bgw1 in dci_link_on_bgw2_if_name:
            log.info("PASS : Single DCI Link Config - "+str(dci_link_bgw2_to_bgw1)+" is Correctly reflecting on BGW-2 - "+str(dci_link_on_bgw2_if_name)+"  \n\n")
        else:
            log.debug("FAIL : Single DCI Link Config - "+str(dci_link_bgw2_to_bgw1)+" is NOT Correctly reflecting on BGW-2 - "+str(dci_link_on_bgw2_if_name)+" \n\n")

        if 'Up' in dci_link_on_bgw2_if_state:
            log.info("PASS : Single DCI Link is 'UP' on BGW-2 - "+str(dci_link_on_bgw2_if_state)+" \n\n")
        else:
            log.debug("FAIL : Single DCI Link is 'NOT UP' on BGW-2 - "+str(dci_link_on_bgw2_if_state)+" \n\n")

        sleep(10)

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(40)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = testscript.parameters['intf_BGW_1_to_BGW_2_1']

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(40)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = testscript.parameters['intf_BGW_1_to_BGW_2_1']

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(40)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class TC040_ReAdd_DCI_Links_to_PO_And_Verify_MultiSite_StormControl(aetest.Testcase):
    """TC040_ReAdd_DCI_Links_to_PO_And_Verify_MultiSite_StormControl"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def ReAdd_DCI_Links_to_PO_And_Verify_MultiSite_StormControl(self, testscript):
        """ ReAdd_DCI_Links_to_PO_And_Verify_MultiSite_StormControl subsection: ReAdd DCI Links to PO And Verify MultiSite StormControl """

        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')
        testscript.parameters['BGW-2'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        sleep(200)

        #Check for DCI Links on BGW-1
        PO_Json_OP_1 = json.loads(testscript.parameters['BGW-1'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id']) + ''' | json'''))        
        dci_link_bgw1_to_bgw2_1 = PO_Mem(PO_Json_OP_1, testscript.parameters['intf_BGW_1_to_BGW_2_1'])
        dci_link_bgw1_to_bgw2_2 = PO_Mem(PO_Json_OP_1, testscript.parameters['intf_BGW_1_to_BGW_2_2'])

        if dci_link_bgw1_to_bgw2_1 == 'P' and  dci_link_bgw1_to_bgw2_2 == 'P':
            log.info("PASS : Multi DCI Link Config - "+str(dci_link_bgw1_to_bgw2_1)+" & "+str(dci_link_bgw1_to_bgw2_2)+" is Correctly reflecting on BGW-1 \n\n")
        else:
            log.debug("FAIL : Multi DCI Link Config - "+str(dci_link_bgw1_to_bgw2_1)+" & "+str(dci_link_bgw1_to_bgw2_2)+" is NOT Correctly reflecting on BGW-1 \n\n")

        dci_link_bgw1_to_bgw2 = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        dci_link_on_bgw1 = json.loads(testscript.parameters['BGW-1'].execute('''show nve multisite dci-links | json'''))

        dci_link_on_bgw1_if_name  = dci_link_on_bgw1['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-name']
        dci_link_on_bgw1_if_state = dci_link_on_bgw1['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-state']

        if dci_link_bgw1_to_bgw2 in dci_link_on_bgw1_if_name:
            log.info("PASS : Multi DCI Link Config - "+str(dci_link_bgw1_to_bgw2)+" is Correctly reflecting on BGW-1 - "+str(dci_link_on_bgw1_if_name)+" \n\n")
        else:
            log.debug("FAIL : Multi DCI Link Config - "+str(dci_link_bgw1_to_bgw2)+" is NOT Correctly reflecting on BGW-1 - "+str(dci_link_on_bgw1_if_name)+" \n\n")

        if 'Up' in dci_link_on_bgw1_if_state:
            log.info("PASS : Multi DCI Link is 'UP' on BGW-1 - "+str(dci_link_on_bgw1_if_state)+" \n\n")
        else:
            log.debug("FAIL : Multi DCI Link is 'NOT UP' on BGW-1 - "+str(dci_link_on_bgw1_if_state)+" \n\n")

        #Check for DCI Links on BGW-2
        PO_Json_OP_2 = json.loads(testscript.parameters['BGW-1'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_2_dict']['DCI_Link_PO']['po_id']) + ''' | json'''))        
        dci_link_bgw2_to_bgw1_1 = PO_Mem(PO_Json_OP_2, testscript.parameters['intf_BGW_2_to_BGW_1_1'])
        dci_link_bgw2_to_bgw1_2 = PO_Mem(PO_Json_OP_2, testscript.parameters['intf_BGW_2_to_BGW_1_2'])

        if dci_link_bgw2_to_bgw1_1 == 'P' and  dci_link_bgw2_to_bgw1_2 == 'P':
            log.info("PASS : Multi DCI Link Config - "+str(dci_link_bgw2_to_bgw1_1)+" & "+str(dci_link_bgw2_to_bgw1_2)+" is Correctly reflecting on BGW-1 \n\n")
        else:
            log.debug("FAIL : Multi DCI Link Config - "+str(dci_link_bgw2_to_bgw1_1)+" & "+str(dci_link_bgw2_to_bgw1_2)+" is NOT Correctly reflecting on BGW-1 \n\n")

        dci_link_bgw2_to_bgw1 = "port-channel"+str(testscript.parameters['BGW_2_dict']['DCI_Link_PO']['po_id'])

        dci_link_on_bgw2 = json.loads(testscript.parameters['BGW-2'].execute('''show nve multisite dci-links | json'''))

        dci_link_on_bgw2_if_name  = dci_link_on_bgw2['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-name']
        dci_link_on_bgw2_if_state = dci_link_on_bgw2['TABLE_multisite_dci_link']['ROW_multisite_dci_link']['if-state']

        if dci_link_bgw2_to_bgw1 in dci_link_on_bgw2_if_name:
            log.info("PASS : Multi DCI Link Config - "+str(dci_link_bgw2_to_bgw1)+" is Correctly reflecting on BGW-2 - "+str(dci_link_on_bgw2_if_name)+"  \n\n")
        else:
            log.debug("FAIL : Multi DCI Link Config - "+str(dci_link_bgw2_to_bgw1)+" is NOT Correctly reflecting on BGW-2 - "+str(dci_link_on_bgw2_if_name)+" \n\n")

        if 'Up' in dci_link_on_bgw2_if_state:
            log.info("PASS : Multi DCI Link is 'UP' on BGW-2 - "+str(dci_link_on_bgw2_if_state)+" \n\n")
        else:
            log.debug("FAIL : Multi DCI Link is 'NOT UP' on BGW-2 - "+str(dci_link_on_bgw2_if_state)+" \n\n")

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(40)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(40)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(40)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC041_Remove_Fabric_Links_from_PO_And_Verify_MultiSite_StormControl(aetest.Testcase):
    """TC041_Remove_Fabric_Links_from_PO_And_Verify_MultiSite_StormControl"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_Fabric_Links_from_PO_And_Verify_MultiSite_StormControl(self, testscript):
        """ Remove_Fabric_Links_from_PO_And_Verify_MultiSite_StormControl subsection: Remove Fabric Links from PO And Verify MultiSite StormControl """

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

              default interface ''' + str(testscript.parameters['intf_BGW_1_to_LEAF_1_2']) + '''

          ''')

        testscript.parameters['BGW-2'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              default interface ''' + str(testscript.parameters['intf_BGW_2_to_LEAF_2_2']) + '''

          ''')

        sleep(180)

        #Check for Fabric Links on BGW-1
        PO_Json_OP_3 = json.loads(testscript.parameters['BGW-1'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' | json'''))        
        fab_link_bgw1_to_leaf1_int = PO_Json_OP_3['TABLE_channel']['ROW_channel']['TABLE_member']['ROW_member']['port']
        fab_link_bgw1_to_leaf1_state = PO_Json_OP_3['TABLE_channel']['ROW_channel']['TABLE_member']['ROW_member']['port-status']

        if fab_link_bgw1_to_leaf1_int == testscript.parameters['intf_BGW_1_to_LEAF_1_1'] and fab_link_bgw1_to_leaf1_state == 'P':
            log.info("PASS : Single Fabric Link Config - "+str(fab_link_bgw1_to_leaf1_int)+" is Correctly reflecting on BGW-1, also "+str(fab_link_bgw1_to_leaf1_state)+"  \n\n")
        else:
            log.debug("FAIL : Single Fabric Link Config - "+str(fab_link_bgw1_to_leaf1_int)+" is NOT Correctly reflecting on BGW-1 - coz, "+str(fab_link_bgw1_to_leaf1_state)+" \n\n")

        fab_link_bgw1_to_bgw2 = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        fab_link_on_bgw1 = json.loads(testscript.parameters['BGW-1'].execute('''show nve multisite fabric-links | json'''))

        fab_link_on_bgw1_if_name  = fab_link_on_bgw1['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-name']
        fab_link_on_bgw1_if_state = fab_link_on_bgw1['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-state']

        if fab_link_bgw1_to_bgw2 in fab_link_on_bgw1_if_name:
            log.info("PASS : Single Fabric Link Config - "+str(fab_link_bgw1_to_bgw2)+" is Correctly reflecting on BGW-1 - "+str(fab_link_on_bgw1_if_name)+" \n\n")
        else:
            log.debug("FAIL : Single Fabric Link Config - "+str(fab_link_bgw1_to_bgw2)+" is NOT Correctly reflecting on BGW-1 - "+str(fab_link_on_bgw1_if_name)+" \n\n")

        if 'Up' in fab_link_on_bgw1_if_state:
            log.info("PASS : Single Fabric Link is 'UP' on BGW-1 - "+str(fab_link_on_bgw1_if_state)+" \n\n")
        else:
            log.debug("FAIL : Single Fabric Link is 'NOT UP' on BGW-1 - "+str(fab_link_on_bgw1_if_state)+" \n\n")

        #Check for Fabric Links on BGW-2
        PO_Json_OP_4 = json.loads(testscript.parameters['BGW-2'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' | json'''))        
        fab_link_bgw2_to_leaf2_int = PO_Json_OP_4['TABLE_channel']['ROW_channel']['TABLE_member']['ROW_member']['port']
        fab_link_bgw2_to_leaf2_state = PO_Json_OP_4['TABLE_channel']['ROW_channel']['TABLE_member']['ROW_member']['port-status']

        if fab_link_bgw2_to_leaf2_int == testscript.parameters['intf_BGW_2_to_LEAF_2_1'] and fab_link_bgw2_to_leaf2_state == 'P':
            log.info("PASS : Single Fabric Link Config - "+str(fab_link_bgw2_to_leaf2_int)+" is Correctly reflecting on BGW-1, also "+str(fab_link_bgw2_to_leaf2_state)+"  \n\n")
        else:
            log.debug("FAIL : Single Fabric Link Config - "+str(fab_link_bgw2_to_leaf2_int)+" is NOT Correctly reflecting on BGW-1 - coz, "+str(fab_link_bgw2_to_leaf2_state)+" \n\n")

        fab_link_bgw2_to_bgw1 = 'port-channel'+str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id'])

        fab_link_on_bgw2 = json.loads(testscript.parameters['BGW-2'].execute('''show nve multisite fabric-links | json'''))

        fab_link_on_bgw2_if_name  = fab_link_on_bgw2['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-name']
        fab_link_on_bgw2_if_state = fab_link_on_bgw2['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-state']

        if fab_link_bgw2_to_bgw1 in fab_link_on_bgw2_if_name:
            log.info("PASS : Single Fabric Link Config - "+str(fab_link_bgw2_to_bgw1)+" is Correctly reflecting on BGW-2 - "+str(fab_link_on_bgw2_if_name)+" \n\n")
        else:
            log.debug("FAIL : Single Fabric Link Config - "+str(fab_link_bgw2_to_bgw1)+" is NOT Correctly reflecting on BGW-2 - "+str(fab_link_on_bgw2_if_name)+" \n\n")

        if 'Up' in fab_link_on_bgw2_if_state:
            log.info("PASS : Single Fabric Link is 'UP' on BGW-2 - "+str(fab_link_on_bgw2_if_state)+" \n\n")
        else:
            log.debug("FAIL : Single Fabric Link is 'NOT UP' on BGW-2 - "+str(fab_link_on_bgw2_if_state)+" \n\n")

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

            sleep(5)

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class TC042_ReAdd_Fabric_Links_to_PO_And_Verify_MultiSite_StormControl(aetest.Testcase):
    """TC042_ReAdd_Fabric_Links_to_PO_And_Verify_MultiSite_StormControl"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def ReAdd_Fabric_Links_to_PO_And_Verify_MultiSite_StormControl(self, testscript):
        """ ReAdd_Fabric_Links_to_PO_And_Verify_MultiSite_StormControl subsection: ReAdd Fabric Links to PO And Verify MultiSite StormControl """

        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')
        testscript.parameters['BGW-2'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        testscript.parameters['BGW-1'].configure('''

              delete bootflash:config_replace.cfg no-prompt
              copy running-config bootflash:config_replace.cfg

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          ''')

        sleep(180)

        #Check for Fabric Links on BGW-1
        PO_Json_OP_1 = json.loads(testscript.parameters['BGW-1'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' | json'''))        
        fab_link_bgw1_to_leaf1_1 = PO_Mem(PO_Json_OP_1, testscript.parameters['intf_BGW_1_to_LEAF_1_1'])
        fab_link_bgw1_to_leaf1_2 = PO_Mem(PO_Json_OP_1, testscript.parameters['intf_BGW_1_to_LEAF_1_2'])

        if fab_link_bgw1_to_leaf1_1 == 'P' and  fab_link_bgw1_to_leaf1_2 == 'P':
            log.info("PASS : Multi Fabric Link Config - "+str(fab_link_bgw1_to_leaf1_1)+" & "+str(fab_link_bgw1_to_leaf1_2)+" is Correctly reflecting on BGW-1 \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link Config - "+str(fab_link_bgw1_to_leaf1_1)+" & "+str(fab_link_bgw1_to_leaf1_2)+" is NOT Correctly reflecting on BGW-1 \n\n")

        fab_link_bgw1_to_bgw2 = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        fab_link_on_bgw1 = json.loads(testscript.parameters['BGW-1'].execute('''show nve multisite fabric-links | json'''))

        fab_link_on_bgw1_if_name  = fab_link_on_bgw1['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-name']
        fab_link_on_bgw1_if_state = fab_link_on_bgw1['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-state']

        if fab_link_bgw1_to_bgw2 in fab_link_on_bgw1_if_name:
            log.info("PASS : Multi Fabric Link Config - "+str(fab_link_bgw1_to_bgw2)+" is Correctly reflecting on BGW-1 - "+str(fab_link_on_bgw1_if_name)+" \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link Config - "+str(fab_link_bgw1_to_bgw2)+" is NOT Correctly reflecting on BGW-1 - "+str(fab_link_on_bgw1_if_name)+" \n\n")

        if 'Up' in fab_link_on_bgw1_if_state:
            log.info("PASS : Multi Fabric Link is 'UP' on BGW-1 - "+str(fab_link_on_bgw1_if_state)+" \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link is 'NOT UP' on BGW-1 - "+str(fab_link_on_bgw1_if_state)+" \n\n")

        #Check for Fabric Links on BGW-2
        PO_Json_OP_2 = json.loads(testscript.parameters['BGW-2'].execute('''show port-channel summary interface port-channel ''' + str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' | json'''))        
        fab_link_bgw2_to_leaf2_1 = PO_Mem(PO_Json_OP_2, testscript.parameters['intf_BGW_2_to_LEAF_2_1'])
        fab_link_bgw2_to_leaf2_2 = PO_Mem(PO_Json_OP_2, testscript.parameters['intf_BGW_2_to_LEAF_2_2'])

        if fab_link_bgw2_to_leaf2_1 == 'P' and  fab_link_bgw2_to_leaf2_2 == 'P':
            log.info("PASS : Multi Fabric Link Config - "+str(fab_link_bgw2_to_leaf2_1)+" & "+str(fab_link_bgw2_to_leaf2_2)+" is Correctly reflecting on BGW-2 \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link Config - "+str(fab_link_bgw2_to_leaf2_1)+" & "+str(fab_link_bgw2_to_leaf2_2)+" is NOT Correctly reflecting on BGW-2 \n\n")

        fab_link_bgw2_to_bgw1 = 'port-channel'+str(testscript.parameters['BGW_2_dict']['SPINE_1_UPLINK_PO']['po_id'])

        fab_link_on_bgw2 = json.loads(testscript.parameters['BGW-2'].execute('''show nve multisite fabric-links | json'''))

        fab_link_on_bgw2_if_name  = fab_link_on_bgw2['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-name']
        fab_link_on_bgw2_if_state = fab_link_on_bgw2['TABLE_multisite_fabric_link']['ROW_multisite_fabric_link']['if-state']

        if fab_link_bgw2_to_bgw1 in fab_link_on_bgw2_if_name:
            log.info("PASS : Multi Fabric Link Config - "+str(fab_link_bgw2_to_bgw1)+" is Correctly reflecting on BGW-2 - "+str(fab_link_on_bgw2_if_name)+" \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link Config - "+str(fab_link_bgw2_to_bgw1)+" is NOT Correctly reflecting on BGW-2 - "+str(fab_link_on_bgw2_if_name)+" \n\n")

        if 'Up' in fab_link_on_bgw2_if_state:
            log.info("PASS : Multi Fabric Link is 'UP' on BGW-2 - "+str(fab_link_on_bgw2_if_state)+" \n\n")
        else:
            log.debug("FAIL : Multi Fabric Link is 'NOT UP' on BGW-2 - "+str(fab_link_on_bgw2_if_state)+" \n\n")

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''configure replace bootflash:config_replace.cfg verbose''')

        sleep(5)

# *****************************************************************************************************************************#

class TC043_ShutDown_Few_DCI_Links_on_PO_And_Verify_MultiSite_StormControl(aetest.Testcase):
    """TC043_ShutDown_Few_DCI_Links_on_PO_And_Verify_MultiSite_StormControl"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def ShutDown_Few_DCI_Links_on_PO_And_Verify_MultiSite_StormControl(self, testscript):
        """ ShutDown_Few_DCI_Links_on_PO_And_Verify_MultiSite_StormControl subsection: ShutDown Few DCI Links on PO And Verify MultiSite StormControl """

        testscript.parameters['BGW-1'].configure('''

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

              interface ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2_1']) + '''
                shutdown

          ''')

        testscript.parameters['BGW-2'].configure('''

              interface ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1_1']) + '''
                shutdown

          ''')

        sleep(120)

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

        testscript.parameters['BGW-1'].configure('''
              
              no evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              no evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              no evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

              interface ''' + str(testscript.parameters['intf_BGW_1_to_BGW_2_1']) + '''
                no shutdown

          ''')

        testscript.parameters['BGW-2'].configure('''

              interface ''' + str(testscript.parameters['intf_BGW_2_to_BGW_1_1']) + '''
                no shutdown

          ''')

        sleep(30)

# *****************************************************************************************************************************#

class TC044_ShutDown_Few_Fabric_Links_on_PO_And_Verify_MultiSite_StormControl(aetest.Testcase):
    """TC044_ShutDown_Few_Fabric_Links_on_PO_And_Verify_MultiSite_StormControl"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def ShutDown_Few_Fabric_Links_on_PO_And_Verify_MultiSite_StormControl(self, testscript):
        """ ShutDown_Few_Fabric_Links_on_PO_And_Verify_MultiSite_StormControl subsection: ShutDown Few Fabric Links on PO And Verify MultiSite StormControl """

        testscript.parameters['BGW-1'].configure('''

              evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

              interface ''' + str(testscript.parameters['intf_BGW_1_to_LEAF_1_2']) + '''
                shutdown

          ''')

        testscript.parameters['BGW-2'].configure('''

              interface ''' + str(testscript.parameters['intf_BGW_2_to_LEAF_2_2']) + '''
                shutdown

          ''')

        sleep(120)

    @aetest.test
    def Start_Unknown_UCast_Traffic(self, testscript):
        """ Start_Unknown_UCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['UKNOWN_UCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_Unknown_UCast_Traffic_on_BGW1(self, testscript):
        """ Verification_Unknown_UCast_Traffic_on_BGW1 """

        ucast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Unicast: | end Broadcast: | grep  0/0")
        ucast_list = ucast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Ucast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Ucast_DCI_Rate = Ucast_DCI_Rate_Pcnt[0]
        Ucast_DCI_Pcnt = Ucast_DCI_Rate_Pcnt[1]

        if int(float(Ucast_DCI_Rate)) in range(int(ucast_list[4])-10,int(ucast_list[4])):
            log.info("PASS : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Rate - "+str(Ucast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(ucast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_ucast = BUM_State(sh_fw_dist_evpn_sc, 'Unicast')
        mssc_fib_ucast_level  = mssc_fib_ucast[1]

        if round(float(mssc_fib_ucast_level),1) == float(Ucast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Ucast Pcnt - "+str(Ucast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_ucast_level)+" \n\n")

    @aetest.test
    def Stop_Unknown_UCast_Traffic(self):
        """ Stop_Unknown_UCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BCast_Traffic(self, testscript):
        """ Start_BCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BCAST_L1_to_L2_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BCast_Traffic_on_BGW1 """

        bcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Broadcast: | end Multicast: | grep  0/0")
        bcast_list = bcast_rate.replace(" ","").split("|")

        dci_int = "port-channel"+str(testscript.parameters['BGW_1_dict']['DCI_Link_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Bcast_DCI_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, dci_int)
        Bcast_DCI_Rate = Bcast_DCI_Rate_Pcnt[0]
        Bcast_DCI_Pcnt = Bcast_DCI_Rate_Pcnt[1]

        if int(float(Bcast_DCI_Rate)) in range(int(bcast_list[4])-10,int(bcast_list[4])):
            log.info("PASS : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Rate - "+str(Bcast_DCI_Rate)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(bcast_list[4])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_bcast = BUM_State(sh_fw_dist_evpn_sc, 'Broadcast')
        mssc_fib_bcast_level  = mssc_fib_bcast[1]

        if round(float(mssc_fib_bcast_level),1) == float(Bcast_DCI_Pcnt):
            log.info("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.passed("PASS : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")
            self.failed("FAIL : Egress DCI Link Bcast Pcnt - "+str(Bcast_DCI_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_bcast_level)+" \n\n")

    @aetest.test
    def Stop_BCast_Traffic(self):
        """ Stop_BCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
            sleep(5)

    @aetest.test
    def Start_BUM_MCast_Traffic(self, testscript):
        """ Start_BUM_MCast_Traffic """
        if ixLib.start_traffic(testscript.parameters['BUM_MCAST_L2_to_L1_TI']) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Verification_BUM_MCast_Traffic_on_BGW1(self, testscript):
        """ Verification_BUM_MCast_Traffic_on_BGW1 """

        mcast_rate = testscript.parameters['BGW-1'].execute("slot 1 quoted \"show hardware vxlan storm-control\" | begin Multicast: | end Policer | grep  0/0")
        mcast_list = mcast_rate.replace(" ","").split("|")

        fab_int = 'port-channel'+str(testscript.parameters['BGW_1_dict']['SPINE_1_UPLINK_PO']['po_id'])

        sh_int_cnt_tab = json.loads(testscript.parameters['BGW-1'].execute("show interface counters table | json"))
        Mcast_FAB_Rate_Pcnt = Interface_Table(sh_int_cnt_tab, fab_int)
        Mcast_FAB_Rate = Mcast_FAB_Rate_Pcnt[0]
        Mcast_FAB_Pcnt = Mcast_FAB_Rate_Pcnt[1]

        if int(float(Mcast_FAB_Rate)) in range(int(mcast_list[2])-10,int(mcast_list[2])):
            log.info("PASS : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link - "+str(Mcast_FAB_Rate)+" Mcast Rate is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mcast_list[2])+" \n\n")
            
        sh_fw_dist_evpn_sc = json.loads(testscript.parameters['BGW-1'].execute("show forwarding distribution evpn storm-control | json"))
        mssc_fib_mcast = BUM_State(sh_fw_dist_evpn_sc, 'Multicast')
        mssc_fib_mcast_level  = mssc_fib_mcast[1]

        if round(float(mssc_fib_mcast_level),1) == float(Mcast_FAB_Pcnt):
            log.info("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.passed("PASS : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
        else:
            log.debug("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")
            self.failed("FAIL : Egress Fabric Link Mcast Pcnt - "+str(Mcast_FAB_Pcnt)+" is NOT as-per the Storm-Control Configured on BGW-1 - "+str(mssc_fib_mcast_level)+" \n\n")

    @aetest.test
    def Stop_MCast_Traffic(self):
        """ Stop_MCast_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")
            
    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self, testscript):
        """ testcase clean up """
        log.info("Pass testcase cleanup")
        
        testscript.parameters['BGW-1'].configure('''

              no evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
              no evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
              no evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

              interface ''' + str(testscript.parameters['intf_BGW_1_to_LEAF_1_2']) + '''
                no shutdown

          ''')

        testscript.parameters['BGW-2'].configure('''

              interface ''' + str(testscript.parameters['intf_BGW_2_to_LEAF_2_2']) + '''
                no shutdown

          ''')

        sleep(30)

# *****************************************************************************************************************************#

class TC045_Verify_MultiSite_StormControl_Show_CLIs_JSONify(aetest.Testcase):
    """TC045_Verify_MultiSite_StormControl_Show_CLIs_JSONify"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_MultiSite_StormControl_Show_CLIs_JSONify(self, testscript):
        """ Verify_MultiSite_StormControl_Show_CLIs_JSONify subsection: Verify MultiSite Storm-Control Show CLIs JSONify """

        testscript.parameters['BGW-1'].execute('''

                show nve multisite dci-links | json-pretty

                show nve multisite fabric-links | json-pretty

                show forwarding distribution evpn storm-control | json-pretty

          ''')

        testscript.parameters['BGW-2'].execute('''

                show nve multisite dci-links | json-pretty

                show nve multisite fabric-links | json-pretty

                show forwarding distribution evpn storm-control | json-pretty

          ''')

    @aetest.test
    def post_configure_system_check(self):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        status = infraVerify.postTestVerification(post_test_process_dict)

        # if status['status'] == 0:
        #     self.failed(reason=status['logs'])
        # else:
        #     self.passed(reason=status['logs'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class TC046_iCAM_Check(aetest.Testcase):
    """ TC046_iCAM_Check """

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

class TC047_Config_Replace(aetest.Testcase):
    """ TC047_Config_Replace """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Config_Replace(self, testscript):
        """ Config_Replace """

        testscript.parameters['BGW-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

            evpn storm-control unicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['ucast'])+'''
            evpn storm-control broadcast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['bcast'])+'''
            evpn storm-control multicast level '''+str(testscript.parameters['BGW_1_dict']['Strom_Control']['mcast'])+'''

          configure replace bootflash:config_replace.cfg verbose

              ''')

        sleep(10)

        ConfigReplace = testscript.parameters['BGW-1'].execute('show config-replace log exec | i "Rollback Status"')

        match = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace)

        sleep(60)

        if match[1] == 'Success':
            self.passed(reason="Rollback Passed")
        else:
            self.failed(reason="Rollback Failed")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        if ixLib.verify_traffic(2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")
            self.passed("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class TC048_FINAL_CC_CHECK(aetest.Testcase):
    """ TC048_FINAL_CC_CHECK """

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
