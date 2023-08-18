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
        SPINE = testscript.parameters['SPINE'] = testbed.devices[uut_list['SPINE']]

        LEAF_1 = testscript.parameters['LEAF-1'] = testbed.devices[uut_list['LEAF-1']]
        LEAF_2 = testscript.parameters['LEAF-2'] = testbed.devices[uut_list['LEAF-2']]
        LEAF_3 = testscript.parameters['LEAF-3'] = testbed.devices[uut_list['LEAF-3']]

        FAN = testscript.parameters['FAN'] = testbed.devices[uut_list['FAN']]

        IXIA = testscript.parameters['IXIA'] = testbed.devices[uut_list['ixia']]

        testscript.parameters['ixia_chassis_ip'] = str(IXIA.connections.a.ip)
        testscript.parameters['ixia_tcl_server'] = str(IXIA.connections.alt.ip)
        testscript.parameters['ixia_tcl_port'] = str(IXIA.connections.alt.port)

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
        testscript.parameters['LEAF_3_dict'] = configuration['LEAF_3_dict']

        testscript.parameters['LEAF_12_TGEN_dict'] = configuration['LEAF_12_TGEN_data']
        testscript.parameters['LEAF_1_TGEN_dict'] = configuration['LEAF_1_TGEN_data']
        testscript.parameters['LEAF_2_TGEN_dict'] = configuration['LEAF_2_TGEN_data']
        testscript.parameters['LEAF_3_TGEN_dict'] = configuration['LEAF_3_TGEN_data']

        testscript.parameters['forwardingSysDict'] = configuration['FWD_SYS_dict']

        testscript.parameters['leafVPCDictData'] = {LEAF_1: configuration['LEAF_1_dict'],
                                                    LEAF_2: configuration['LEAF_2_dict']}
        testscript.parameters['leavesDictList'] = [configuration['LEAF_1_dict'], configuration['LEAF_2_dict'],
                                                   configuration['LEAF_3_dict']]
        testscript.parameters['leavesDict'] = {LEAF_1: configuration['LEAF_1_dict'],
                                               LEAF_2: configuration['LEAF_2_dict'],
                                               LEAF_3: configuration['LEAF_3_dict']}

        testscript.parameters['VTEP_List'] = [testscript.parameters['LEAF_1_dict'],
                                              testscript.parameters['LEAF_2_dict'],
                                              testscript.parameters['LEAF_3_dict']]

        post_test_process_dict = {}
        post_test_process_dict = job_file_params['postTestArgs']
        post_test_process_dict['dut_list'] = [LEAF_1, LEAF_2, LEAF_3]
        log.info("===> Post Test Check Process Parameters")
        log.info(post_test_process_dict)

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
                log.info(str(interface) + " --> " + str(dut.interfaces[interface].intf))

        # =============================================================================================================================#
        # Fetching the specific interfaces
        testscript.parameters['intf_SPINE_to_LEAF_1'] = SPINE.interfaces['SPINE_to_LEAF-1'].intf
        testscript.parameters['intf_SPINE_to_LEAF_2'] = SPINE.interfaces['SPINE_to_LEAF-2'].intf
        testscript.parameters['intf_SPINE_to_LEAF_3'] = SPINE.interfaces['SPINE_to_LEAF-3'].intf

        testscript.parameters['intf_LEAF_1_to_LEAF_2_1'] = LEAF_1.interfaces['LEAF-1_to_LEAF-2_1'].intf
        testscript.parameters['intf_LEAF_1_to_LEAF_2_2'] = LEAF_1.interfaces['LEAF-1_to_LEAF-2_2'].intf
        testscript.parameters['intf_LEAF_1_to_SPINE'] = LEAF_1.interfaces['LEAF-1_to_SPINE'].intf
        testscript.parameters['intf_LEAF_1_to_FAN'] = LEAF_1.interfaces['LEAF-1_to_FAN'].intf
        testscript.parameters['intf_LEAF_1_to_IXIA'] = LEAF_1.interfaces['LEAF-1_to_IXIA'].intf

        testscript.parameters['intf_LEAF_2_to_LEAF_1_1'] = LEAF_2.interfaces['LEAF-2_to_LEAF-1_1'].intf
        testscript.parameters['intf_LEAF_2_to_LEAF_1_2'] = LEAF_2.interfaces['LEAF-2_to_LEAF-1_2'].intf
        testscript.parameters['intf_LEAF_2_to_SPINE'] = LEAF_2.interfaces['LEAF-2_to_SPINE'].intf
        testscript.parameters['intf_LEAF_2_to_FAN'] = LEAF_2.interfaces['LEAF-2_to_FAN'].intf
        testscript.parameters['intf_LEAF_2_to_IXIA'] = LEAF_2.interfaces['LEAF-2_to_IXIA'].intf

        testscript.parameters['intf_LEAF_3_to_SPINE'] = LEAF_3.interfaces['LEAF-3_to_SPINE'].intf
        testscript.parameters['intf_LEAF_3_to_IXIA'] = LEAF_3.interfaces['LEAF-3_to_IXIA'].intf

        testscript.parameters['intf_FAN_to_LEAF_1'] = FAN.interfaces['FAN_to_LEAF-1'].intf
        testscript.parameters['intf_FAN_to_LEAF_2'] = FAN.interfaces['FAN_to_LEAF-2'].intf
        testscript.parameters['intf_FAN_to_IXIA'] = FAN.interfaces['FAN_to_IXIA'].intf

        testscript.parameters['intf_IXIA_to_FAN'] = IXIA.interfaces['IXIA_to_FAN'].intf
        testscript.parameters['intf_IXIA_to_LEAF_1'] = IXIA.interfaces['IXIA_to_LEAF-1'].intf
        testscript.parameters['intf_IXIA_to_LEAF_2'] = IXIA.interfaces['IXIA_to_LEAF-2'].intf
        testscript.parameters['intf_IXIA_to_LEAF_3'] = IXIA.interfaces['IXIA_to_LEAF-3'].intf

        testscript.parameters['ixia_int_list'] = str(testscript.parameters['intf_IXIA_to_FAN']) + " " + \
        str(testscript.parameters['intf_IXIA_to_LEAF_1']) + " " + str(testscript.parameters['intf_IXIA_to_LEAF_2']) + \
        " " + str(testscript.parameters['intf_IXIA_to_LEAF_3'])

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
                                           /       |      \\
                                          /        |        \\
                                         /         |          \\
                                        /          |            \\
                                       /           |              \\
                                      /            |                \\
                                     /             |                  \\
                                    /              |                    \\
            +---------+       +-----------+    +-----------+            +-----------+
            |   IXIA  |-------|   LEAF-1  |====|   LEAF-2  |            |   LEAF-3  |
            +---------+       +-----------+    +-----------+            +-----------+
                                   \\             /     \\                   |
                                    \\           /       \\                  |
                                     \\         /         \\                 |
                                      \\       /           \\                |
                                    +-----------+     +---------+       +-----------+
                                    |   FAN     |     |  IXIA   |       |   IXIA    |
                                    +-----------+     +---------+       +-----------+     
                                         |
                                         |
                                    +-----------+
                                    |   IXIA    |
                                    +-----------+

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
                                                          testscript.parameters['LEAF-3']]
            testscript.parameters['spineFeatureList'] = spineFeatureList = ['ospf', 'bgp', 'pim', 'lacp', 'nv overlay']
            testscript.parameters['vpcLeafFeatureList'] = vpcLeafFeatureList = ['vpc', 'ospf', 'pim', 'bgp',
                                                                                'interface-vlan',
                                                                                'vn-segment-vlan-based', 'lacp',
                                                                                'nv overlay', 'fabric forwarding', 'bash-shell']
            testscript.parameters['LeafFeatureList'] = LeafFeatureList = ['ospf', 'bgp', 'pim', 'interface-vlan',
                                                                          'vn-segment-vlan-based', 'lacp', 'nv overlay',
                                                                          'fabric forwarding', 'bash-shell']
            testscript.parameters['fanOutFeatureList'] = fanOutFeatureList = ['lacp']
            configFeatureSet_status = []
            configFeatureSet_msgs = ""

            # --------------------------------
            # Configure Features on SPINE
            featureConfigureSpine_status = infraConfig.configureVerifyFeature(testscript.parameters['SPINE'],
                                                                              spineFeatureList)
            if featureConfigureSpine_status['result']:
                log.info("Passed Configuring features on SPINE")
            else:
                log.debug("Failed configuring features on SPINE")
                configFeatureSet_msgs += featureConfigureSpine_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-1
            featureConfigureLeaf1_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-1'],
                                                                              vpcLeafFeatureList)
            if featureConfigureLeaf1_status['result']:
                log.info("Passed Configuring features on LEAF-1")
            else:
                log.debug("Failed configuring features on LEAF-1")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-2
            featureConfigureLeaf2_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-2'],
                                                                              vpcLeafFeatureList)
            if featureConfigureLeaf2_status['result']:
                log.info("Passed Configuring features on LEAF-2")
            else:
                log.debug("Failed configuring features on LEAF-2")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-3
            featureConfigureLeaf3_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-3'],
                                                                              LeafFeatureList)
            if featureConfigureLeaf3_status['result']:
                log.info("Passed Configuring features on LEAF-3")
            else:
                log.debug("Failed configuring features on LEAF-3")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature Set on Leafs
            featureConfigureLeafs_status = infraConfig.configureVerifyFeature(leafLst, LeafFeatureList)
            if featureConfigureLeafs_status['result']:
                log.info("Passed Configuring features on LEAFs")
            else:
                log.debug("Failed configuring features on LEAFs")
                configFeatureSet_msgs += featureConfigureLeafs_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on FANOUTs
            featureConfigureFan_status = infraConfig.configureVerifyFeature(testscript.parameters['FAN'],
                                                                            fanOutFeatureList)
            if featureConfigureFan_status['result']:
                log.info("Passed Configuring features on FAN boxes")
            else:
                log.debug("Failed configuring features on FAN boxes")
                configFeatureSet_msgs += featureConfigureFan_status['log']
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

class DEVICE_BRINGUP_configure_SPINE(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_SPINE(self, testscript):
        """ Device Bring-up subsection: Configuring SPINE """

        evpnLib.configureEVPNSpines([testscript.parameters['SPINE']], testscript.parameters['forwardingSysDict'],
                                    testscript.parameters['leavesDictList'])

        try:
            testscript.parameters['SPINE'].configure('''

                interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_1']) + '''
                  channel-group ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                  no shutdown

                interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_2']) + '''
                  channel-group ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                  no shutdown

                interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_3']) + '''
                  channel-group ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                  no shutdown

            ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.failed('Exception occurred while configuring on SPINE', goto=['common_cleanup'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class DEVICE_BRINGUP_configure_LEAF_1_2(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_LEAF_1_2(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        evpnLib.configureEVPNVPCLeafs(testscript.parameters['forwardingSysDict'],
                                      testscript.parameters['leafVPCDictData'])

        try:
            testscript.parameters['LEAF-1'].configure('''

              vlan 2

              vpc domain ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['domain_id']) + '''
                layer3 peer-router

              interface Vlan2
                description special_svi_over_peer-link
                no shutdown
                no ip redirects
                ip address 30.2.1.2/30
                no ipv6 redirects
                ip ospf network point-to-point
                ip router ospf ''' + str(testscript.parameters['forwardingSysDict']['OSPF_AS']) + ''' area 0.0.0.0
                ip pim sparse-mode

              system nve infra-vlans 2 force

              system dot1q-tunnel transit vlan 301-302

              interface nve 1
                advertise virtual-rmac
          
              router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                address-family l2vpn evpn
                  advertise-pip

              interface ''' + str(testscript.parameters['intf_LEAF_1_to_SPINE']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                no shutdown

              interface ''' + str(testscript.parameters['intf_LEAF_1_to_FAN']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + ''' force mode active
                no shutdown

              interface ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_2_2']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po']) + ''' force mode active
                no shutdown

              interface ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_2_1']) + '''
                vrf member peer-keep-alive
                ip address ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['kp_al_ip']) + '''/24
                no shutdown

              interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
                switchport
                switchport mode trunk
                switchport vlan mapping 50 dot1q-tunnel 301
                switchport vlan mapping 60 dot1q-tunnel 302 
                switchport trunk allowed vlan 50,60,301-304
                no shutdown               

              interface ''' + str(testscript.parameters['intf_LEAF_1_to_IXIA']) + '''
                switchport
                switchport mode trunk
                switchport vlan mapping 50 dot1q-tunnel 301
                switchport vlan mapping 60 dot1q-tunnel 302 
                switchport trunk allowed vlan 50,60,301-304
                no shutdown

              interface nve 1
                member vni ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + '''
                no suppress-arp
                member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + '''
                no suppress-arp
                member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                no suppress-arp
                member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 3) + '''
                no suppress-arp

          ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-1', goto=['common_cleanup'])

        try:
            testscript.parameters['LEAF-2'].configure('''

              vlan 2

              vpc domain ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['domain_id']) + '''
                layer3 peer-router

              interface Vlan2
                description special_svi_over_peer-link
                no shutdown
                no ip redirects
                ip address 30.2.1.2/30
                no ipv6 redirects
                ip ospf network point-to-point
                ip router ospf ''' + str(testscript.parameters['forwardingSysDict']['OSPF_AS']) + ''' area 0.0.0.0
                ip pim sparse-mode

              system nve infra-vlans 2 force

              system dot1q-tunnel transit vlan 301-302

              interface nve 1
                advertise virtual-rmac
          
              router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                address-family l2vpn evpn
                  advertise-pip

              interface ''' + str(testscript.parameters['intf_LEAF_2_to_SPINE']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                no shutdown

              interface ''' + str(testscript.parameters['intf_LEAF_2_to_FAN']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + ''' force mode active
                no shutdown

              interface ''' + str(testscript.parameters['intf_LEAF_2_to_LEAF_1_2']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['peer_link_po']) + ''' force mode active
                no shutdown

              interface ''' + str(testscript.parameters['intf_LEAF_2_to_LEAF_1_1']) + '''
                vrf member peer-keep-alive
                ip address ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['kp_al_ip']) + '''/24
                no shutdown

              interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + '''
                switchport
                switchport mode trunk
                switchport vlan mapping 50 dot1q-tunnel 301
                switchport vlan mapping 60 dot1q-tunnel 302 
                switchport trunk allowed vlan 50,60,301-304
                no shutdown               

              interface ''' + str(testscript.parameters['intf_LEAF_2_to_IXIA']) + '''
                switchport
                switchport mode trunk
                switchport vlan mapping 50 dot1q-tunnel 301
                switchport vlan mapping 60 dot1q-tunnel 302 
                switchport trunk allowed vlan 50,60,301-304
                no shutdown

              interface nve 1
                member vni ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + '''
                no suppress-arp
                member vni ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + '''
                no suppress-arp
                member vni ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                no suppress-arp
                member vni ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 3) + '''
                no suppress-arp

          ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-2', goto=['common_cleanup'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class DEVICE_BRINGUP_configure_LEAF_3(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_LEAF_3(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-3 """

        evpnLib.configureEVPNLeaf(testscript.parameters['LEAF-3'], testscript.parameters['forwardingSysDict'],
                                  testscript.parameters['LEAF_3_dict'])

        try:
            testscript.parameters['LEAF-3'].configure('''

              interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                no shutdown

              interface ''' + str(testscript.parameters['intf_LEAF_3_to_IXIA']) + '''
                switchport
                switchport mode trunk
                switchport vlan mapping 50 dot1q-tunnel 301
                switchport vlan mapping 60 dot1q-tunnel 302 
                switchport trunk allowed vlan 50,60,301-304
                no shutdown

              interface nve 1
                member vni ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + '''
                no suppress-arp
                member vni ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + '''
                no suppress-arp
                member vni ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                no suppress-arp
                member vni ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 3) + '''
                no suppress-arp

          ''')

        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-3', goto=['common_cleanup'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class DEVICE_BRINGUP_configure_FAN(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_FAN(self, testscript):
        """ Device Bring-up subsection: Configuring FAN """

        fanOut_vlanConfiguration = ""

        l3_vrf_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            fanOut_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''
                                            state active
                                            no shut\n'''
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                fanOut_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''
                                                state active
                                                no shut\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            testscript.parameters['FAN'].configure(
                str(fanOut_vlanConfiguration) + '''

              vlan 50, 60
              exit

              interface port-channel200
                switchport
                switchport mode trunk
                no shutdown

              interface {0}
                channel-group 200 force mode active
                no shutdown

              interface {1}
                channel-group 200 force mode active
                no shutdown

              interface {2}
                switchport
                switchport mode trunk
                no shut

                            '''.format(testscript.parameters['intf_FAN_to_LEAF_1'],
                                       testscript.parameters['intf_FAN_to_LEAF_2'],
                                       testscript.parameters['intf_FAN_to_IXIA']))
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on FAN', goto=['common_cleanup'])

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
        """ SQinVNI_CONFIGURATION test subsection: Save all configurations (copy r s) """

        log.info(banner("Performing Copy R S"))

        testscript.parameters['LEAF-1'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-3'].configure("copy r s", timeout=300)
        testscript.parameters['FAN'].configure("copy r s", timeout=300)

        time.sleep(180)

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
    def verify_vpc(self, testscript):
        """ VERIFY_NETWORK subsection: Verify VPC """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info(
                "PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            log.info("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")
            self.failed()

    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict'],
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

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict'],
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

        # Get IXIA paraameters
        ixia_chassis_ip = testscript.parameters['ixia_chassis_ip']
        ixia_tcl_server = testscript.parameters['ixia_tcl_server']
        ixia_tcl_port = testscript.parameters['ixia_tcl_port']
        ixia_int_list = testscript.parameters['ixia_int_list']

        ix_int_1 = testscript.parameters['intf_IXIA_to_FAN']
        ix_int_2 = testscript.parameters['intf_IXIA_to_LEAF_1']
        ix_int_3 = testscript.parameters['intf_IXIA_to_LEAF_2']
        ix_int_4 = testscript.parameters['intf_IXIA_to_LEAF_3']

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
        testscript.parameters['port_handle_3'] = ch_key[ix_int_3]
        testscript.parameters['port_handle_4'] = ch_key[ix_int_4]

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

        TOPO_1_dict = {'topology_name': 'FAN-TG',
                       'device_grp_name': 'FAN-TG',
                       'port_handle': testscript.parameters['port_handle_1']}

        TOPO_2_dict = {'topology_name': 'LEAF-1-TG',
                       'device_grp_name': 'LEAF-1-TG',
                       'port_handle': testscript.parameters['port_handle_2']}

        TOPO_3_dict = {'topology_name': 'LEAF-2-TG',
                       'device_grp_name': 'LEAF-2-TG',
                       'port_handle': testscript.parameters['port_handle_3']}

        TOPO_4_dict = {'topology_name': 'LEAF-3-TG',
                       'device_grp_name': 'LEAF-3-TG',
                       'port_handle': testscript.parameters['port_handle_4']}

        testscript.parameters['IX_TP1'] = ixLib.create_topo_device_grp(TOPO_1_dict)
        if testscript.parameters['IX_TP1'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created ACS-TG Topology Successfully")

        testscript.parameters['IX_TP2'] = ixLib.create_topo_device_grp(TOPO_2_dict)
        if testscript.parameters['IX_TP2'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created L1-TG Topology Successfully")

        testscript.parameters['IX_TP3'] = ixLib.create_topo_device_grp(TOPO_3_dict)
        if testscript.parameters['IX_TP3'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created L2-TG Topology Successfully")

        testscript.parameters['IX_TP4'] = ixLib.create_topo_device_grp(TOPO_4_dict)
        if testscript.parameters['IX_TP4'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['next_tc'])
        else:
            log.info("Created L3-TG Topology Successfully")

        testscript.parameters['IX_TP1']['port_handle'] = testscript.parameters['port_handle_1']
        testscript.parameters['IX_TP2']['port_handle'] = testscript.parameters['port_handle_2']
        testscript.parameters['IX_TP3']['port_handle'] = testscript.parameters['port_handle_3']
        testscript.parameters['IX_TP4']['port_handle'] = testscript.parameters['port_handle_4']

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
        P3 = testscript.parameters['port_handle_3']
        P4 = testscript.parameters['port_handle_4']

        P1_dict = testscript.parameters['LEAF_12_TGEN_dict']
        P2_dict = testscript.parameters['LEAF_1_TGEN_dict']
        P3_dict = testscript.parameters['LEAF_2_TGEN_dict']
        P4_dict = testscript.parameters['LEAF_3_TGEN_dict']

        P1_int_dict_11 = {'dev_grp_hndl': testscript.parameters['IX_TP1']['dev_grp_hndl'],
                         'port_hndl': P1,
                         'no_of_ints': P1_dict['no_of_ints'],
                         'phy_mode': P1_dict['phy_mode'],
                         'mac': P1_dict['mac_1'],
                         'mac_step': P1_dict['mac_step'],
                         'protocol': P1_dict['protocol'],
                         'v4_addr': P1_dict['v4_addr_1'],
                         'v4_addr_step': P1_dict['v4_addr_step_1'],
                         'v4_gateway': P1_dict['v4_gateway_1'],
                         'v4_gateway_step': P1_dict['v4_gateway_step'],
                         'v4_netmask': P1_dict['v4_netmask'],
                         'v6_addr': P1_dict['v6_addr_1'],
                         'v6_addr_step': P1_dict['v6_addr_step_1'],
                         'v6_gateway': P1_dict['v6_gateway_1'],
                         'v6_gateway_step': P1_dict['v6_gateway_step'],
                         'v6_netmask': P1_dict['v6_netmask'],
                         'vlan_id': P1_dict['vlan_id_1'],
                         'vlan_id_step': P1_dict['vlan_id_step_1']}

        P2_int_dict_12 = {'dev_grp_hndl': testscript.parameters['IX_TP2']['dev_grp_hndl'],
                         'port_hndl': P2,
                         'no_of_ints': P2_dict['no_of_ints'],
                         'phy_mode': P2_dict['phy_mode'],
                         'mac': P2_dict['mac_1'],
                         'mac_step': P2_dict['mac_step'],
                         'protocol': P2_dict['protocol'],
                         'v4_addr': P2_dict['v4_addr_1'],
                         'v4_addr_step': P2_dict['v4_addr_step_1'],
                         'v4_gateway': P2_dict['v4_gateway_1'],
                         'v4_gateway_step': P2_dict['v4_gateway_step'],
                         'v4_netmask': P2_dict['v4_netmask'],
                         'v6_addr': P2_dict['v6_addr_1'],
                         'v6_addr_step': P2_dict['v6_addr_step_1'],
                         'v6_gateway': P2_dict['v6_gateway_1'],
                         'v6_gateway_step': P2_dict['v6_gateway_step'],
                         'v6_netmask': P2_dict['v6_netmask'],
                         'vlan_id': P1_dict['vlan_id_1'],
                         'vlan_id_step': P1_dict['vlan_id_step_1']}

        P3_int_dict_13 = {'dev_grp_hndl': testscript.parameters['IX_TP3']['dev_grp_hndl'],
                         'port_hndl': P3,
                         'no_of_ints': P3_dict['no_of_ints'],
                         'phy_mode': P3_dict['phy_mode'],
                         'mac': P3_dict['mac_1'],
                         'mac_step': P3_dict['mac_step'],
                         'protocol': P3_dict['protocol'],
                         'v4_addr': P3_dict['v4_addr_1'],
                         'v4_addr_step': P3_dict['v4_addr_step_1'],
                         'v4_gateway': P3_dict['v4_gateway_1'],
                         'v4_gateway_step': P3_dict['v4_gateway_step'],
                         'v4_netmask': P3_dict['v4_netmask'],
                         'v6_addr': P3_dict['v6_addr_1'],
                         'v6_addr_step': P3_dict['v6_addr_step_1'],
                         'v6_gateway': P3_dict['v6_gateway_1'],
                         'v6_gateway_step': P3_dict['v6_gateway_step'],
                         'v6_netmask': P3_dict['v6_netmask'],
                         'vlan_id': P1_dict['vlan_id_1'],
                         'vlan_id_step': P1_dict['vlan_id_step_1']}

        P4_int_dict_14 = {'dev_grp_hndl': testscript.parameters['IX_TP4']['dev_grp_hndl'],
                         'port_hndl': P4,
                         'no_of_ints': P4_dict['no_of_ints'],
                         'phy_mode': P4_dict['phy_mode'],
                         'mac': P4_dict['mac_1'],
                         'mac_step': P4_dict['mac_step'],
                         'protocol': P4_dict['protocol'],
                         'v4_addr': P4_dict['v4_addr_1'],
                         'v4_addr_step': P4_dict['v4_addr_step_1'],
                         'v4_gateway': P4_dict['v4_gateway_1'],
                         'v4_gateway_step': P4_dict['v4_gateway_step'],
                         'v4_netmask': P4_dict['v4_netmask'],
                         'v6_addr': P4_dict['v6_addr_1'],
                         'v6_addr_step': P4_dict['v6_addr_step_1'],
                         'v6_gateway': P4_dict['v6_gateway_1'],
                         'v6_gateway_step': P4_dict['v6_gateway_step'],
                         'v6_netmask': P4_dict['v6_netmask'],
                         'vlan_id': P4_dict['vlan_id_1'],
                         'vlan_id_step': P4_dict['vlan_id_step_1']}

        P1_IX_int_data_11 = ixLib.configure_multi_ixia_interface(P1_int_dict_11)
        P2_IX_int_data_12 = ixLib.configure_multi_ixia_interface(P2_int_dict_12)
        P3_IX_int_data_13 = ixLib.configure_multi_ixia_interface(P3_int_dict_13)
        P4_IX_int_data_14 = ixLib.configure_multi_ixia_interface(P4_int_dict_14)

        log.info(P1_IX_int_data_11)
        log.info(P2_IX_int_data_12)
        log.info(P3_IX_int_data_13)
        log.info(P4_IX_int_data_14)

        if P1_IX_int_data_11 == 0 or P2_IX_int_data_12 == 0 or P3_IX_int_data_13 == 0 or P4_IX_int_data_14 == 0:
            log.debug("Configuring IXIA Interface failed")
            self.errored("Configuring IXIA Interface failed", goto=['next_tc'])
        else:
            log.info("Configured IXIA Interface Successfully")

        testscript.parameters['IX_TP1']['eth_handle_11'] = P1_IX_int_data_11['eth_handle']
        testscript.parameters['IX_TP1']['ipv4_handle_11'] = P1_IX_int_data_11['ipv4_handle']
        testscript.parameters['IX_TP1']['ipv6_handle_11'] = P1_IX_int_data_11['ipv6_handle']
        testscript.parameters['IX_TP1']['topo_int_handle_11'] = P1_IX_int_data_11['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP2']['eth_handle_12'] = P2_IX_int_data_12['eth_handle']
        testscript.parameters['IX_TP2']['ipv4_handle_12'] = P2_IX_int_data_12['ipv4_handle']
        testscript.parameters['IX_TP2']['ipv6_handle_12'] = P2_IX_int_data_12['ipv6_handle']
        testscript.parameters['IX_TP2']['topo_int_handle_12'] = P2_IX_int_data_12['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP3']['eth_handle_13'] = P3_IX_int_data_13['eth_handle']
        testscript.parameters['IX_TP3']['ipv4_handle_13'] = P3_IX_int_data_13['ipv4_handle']
        testscript.parameters['IX_TP3']['ipv6_handle_13'] = P3_IX_int_data_13['ipv6_handle']
        testscript.parameters['IX_TP3']['topo_int_handle_13'] = P3_IX_int_data_13['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP4']['eth_handle_14'] = P4_IX_int_data_14['eth_handle']
        testscript.parameters['IX_TP4']['ipv4_handle_14'] = P4_IX_int_data_14['ipv4_handle']
        testscript.parameters['IX_TP4']['ipv6_handle_14'] = P4_IX_int_data_14['ipv6_handle']
        testscript.parameters['IX_TP4']['topo_int_handle_14'] = P4_IX_int_data_14['topo_int_handle'].split(" ")

        log.info("IXIA Port 1 Handles")
        log.info(testscript.parameters['IX_TP1'])
        log.info("IXIA Port 2 Handles")
        log.info(testscript.parameters['IX_TP2'])
        log.info("IXIA Port 3 Handles")
        log.info(testscript.parameters['IX_TP3'])
        log.info("IXIA Port 4 Handles")
        log.info(testscript.parameters['IX_TP4'])




        P1_int_dict_21 = {'dev_grp_hndl': testscript.parameters['IX_TP1']['dev_grp_hndl'],
                         'port_hndl': P1,
                         'no_of_ints': P1_dict['no_of_ints'],
                         'phy_mode': P1_dict['phy_mode'],
                         'mac': P1_dict['mac_2'],
                         'mac_step': P1_dict['mac_step'],
                         'protocol': P1_dict['protocol'],
                         'v4_addr': P1_dict['v4_addr_2'],
                         'v4_addr_step': P1_dict['v4_addr_step_2'],
                         'v4_gateway': P1_dict['v4_gateway_2'],
                         'v4_gateway_step': P1_dict['v4_gateway_step'],
                         'v4_netmask': P1_dict['v4_netmask'],
                         'v6_addr': P1_dict['v6_addr_2'],
                         'v6_addr_step': P1_dict['v6_addr_step_2'],
                         'v6_gateway': P1_dict['v6_gateway_2'],
                         'v6_gateway_step': P1_dict['v6_gateway_step'],
                         'v6_netmask': P1_dict['v6_netmask'],
                         'vlan_id': P1_dict['vlan_id_2'],
                         'vlan_id_step': P1_dict['vlan_id_step_2']}

        P2_int_dict_22 = {'dev_grp_hndl': testscript.parameters['IX_TP2']['dev_grp_hndl'],
                         'port_hndl': P2,
                         'no_of_ints': P2_dict['no_of_ints'],
                         'phy_mode': P2_dict['phy_mode'],
                         'mac': P2_dict['mac_2'],
                         'mac_step': P2_dict['mac_step'],
                         'protocol': P2_dict['protocol'],
                         'v4_addr': P2_dict['v4_addr_2'],
                         'v4_addr_step': P2_dict['v4_addr_step_2'],
                         'v4_gateway': P2_dict['v4_gateway_2'],
                         'v4_gateway_step': P2_dict['v4_gateway_step'],
                         'v4_netmask': P2_dict['v4_netmask'],
                         'v6_addr': P2_dict['v6_addr_2'],
                         'v6_addr_step': P2_dict['v6_addr_step_2'],
                         'v6_gateway': P2_dict['v6_gateway_2'],
                         'v6_gateway_step': P2_dict['v6_gateway_step'],
                         'v6_netmask': P2_dict['v6_netmask'],
                         'vlan_id': P1_dict['vlan_id_2'],
                         'vlan_id_step': P1_dict['vlan_id_step_2']}

        P3_int_dict_23 = {'dev_grp_hndl': testscript.parameters['IX_TP3']['dev_grp_hndl'],
                         'port_hndl': P3,
                         'no_of_ints': P3_dict['no_of_ints'],
                         'phy_mode': P3_dict['phy_mode'],
                         'mac': P3_dict['mac_2'],
                         'mac_step': P3_dict['mac_step'],
                         'protocol': P3_dict['protocol'],
                         'v4_addr': P3_dict['v4_addr_2'],
                         'v4_addr_step': P3_dict['v4_addr_step_2'],
                         'v4_gateway': P3_dict['v4_gateway_2'],
                         'v4_gateway_step': P3_dict['v4_gateway_step'],
                         'v4_netmask': P3_dict['v4_netmask'],
                         'v6_addr': P3_dict['v6_addr_2'],
                         'v6_addr_step': P3_dict['v6_addr_step_2'],
                         'v6_gateway': P3_dict['v6_gateway_2'],
                         'v6_gateway_step': P3_dict['v6_gateway_step'],
                         'v6_netmask': P3_dict['v6_netmask'],
                         'vlan_id': P1_dict['vlan_id_2'],
                         'vlan_id_step': P1_dict['vlan_id_step_2']}

        P4_int_dict_24 = {'dev_grp_hndl': testscript.parameters['IX_TP4']['dev_grp_hndl'],
                         'port_hndl': P4,
                         'no_of_ints': P4_dict['no_of_ints'],
                         'phy_mode': P4_dict['phy_mode'],
                         'mac': P4_dict['mac_2'],
                         'mac_step': P4_dict['mac_step'],
                         'protocol': P4_dict['protocol'],
                         'v4_addr': P4_dict['v4_addr_2'],
                         'v4_addr_step': P4_dict['v4_addr_step_2'],
                         'v4_gateway': P4_dict['v4_gateway_2'],
                         'v4_gateway_step': P4_dict['v4_gateway_step'],
                         'v4_netmask': P4_dict['v4_netmask'],
                         'v6_addr': P4_dict['v6_addr_2'],
                         'v6_addr_step': P4_dict['v6_addr_step_2'],
                         'v6_gateway': P4_dict['v6_gateway_2'],
                         'v6_gateway_step': P4_dict['v6_gateway_step'],
                         'v6_netmask': P4_dict['v6_netmask'],
                         'vlan_id': P4_dict['vlan_id_2'],
                         'vlan_id_step': P4_dict['vlan_id_step_2']}

        P1_IX_int_data_21 = ixLib.configure_multi_ixia_interface(P1_int_dict_21)
        P2_IX_int_data_22 = ixLib.configure_multi_ixia_interface(P2_int_dict_22)
        P3_IX_int_data_23 = ixLib.configure_multi_ixia_interface(P3_int_dict_23)
        P4_IX_int_data_24 = ixLib.configure_multi_ixia_interface(P4_int_dict_24)

        log.info(P1_IX_int_data_21)
        log.info(P2_IX_int_data_22)
        log.info(P3_IX_int_data_23)
        log.info(P4_IX_int_data_24)

        if P1_IX_int_data_21 == 0 or P2_IX_int_data_22 == 0 or P3_IX_int_data_23 == 0 or P4_IX_int_data_24 == 0:
            log.debug("Configuring IXIA Interface failed")
            self.errored("Configuring IXIA Interface failed", goto=['next_tc'])
        else:
            log.info("Configured IXIA Interface Successfully")

        testscript.parameters['IX_TP1']['eth_handle_21'] = P1_IX_int_data_21['eth_handle']
        testscript.parameters['IX_TP1']['ipv4_handle_21'] = P1_IX_int_data_21['ipv4_handle']
        testscript.parameters['IX_TP1']['ipv6_handle_21'] = P1_IX_int_data_21['ipv6_handle']
        testscript.parameters['IX_TP1']['topo_int_handle_21'] = P1_IX_int_data_21['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP2']['eth_handle_22'] = P2_IX_int_data_22['eth_handle']
        testscript.parameters['IX_TP2']['ipv4_handle_22'] = P2_IX_int_data_22['ipv4_handle']
        testscript.parameters['IX_TP2']['ipv6_handle_22'] = P2_IX_int_data_22['ipv6_handle']
        testscript.parameters['IX_TP2']['topo_int_handle_22'] = P2_IX_int_data_22['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP3']['eth_handle_23'] = P3_IX_int_data_23['eth_handle']
        testscript.parameters['IX_TP3']['ipv4_handle_23'] = P3_IX_int_data_23['ipv4_handle']
        testscript.parameters['IX_TP3']['ipv6_handle_23'] = P3_IX_int_data_23['ipv6_handle']
        testscript.parameters['IX_TP3']['topo_int_handle_23'] = P3_IX_int_data_23['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP4']['eth_handle_24'] = P4_IX_int_data_24['eth_handle']
        testscript.parameters['IX_TP4']['ipv4_handle_24'] = P4_IX_int_data_24['ipv4_handle']
        testscript.parameters['IX_TP4']['ipv6_handle_24'] = P4_IX_int_data_24['ipv6_handle']
        testscript.parameters['IX_TP4']['topo_int_handle_24'] = P4_IX_int_data_24['topo_int_handle'].split(" ")

        log.info("IXIA Port 1 Handles")
        log.info(testscript.parameters['IX_TP1'])
        log.info("IXIA Port 2 Handles")
        log.info(testscript.parameters['IX_TP2'])
        log.info("IXIA Port 3 Handles")
        log.info(testscript.parameters['IX_TP3'])
        log.info("IXIA Port 4 Handles")
        log.info(testscript.parameters['IX_TP4'])

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
        IX_TP4 = testscript.parameters['IX_TP4']

        P1_dict = testscript.parameters['LEAF_3_TGEN_dict']

        BCAST_L3_to_ACS_dict = {
                            'src_hndl'      : IX_TP4['port_handle'],
                            'dst_hndl'      : IX_TP1['port_handle'],
                            'TI_name'       : "BCAST_L1_to_L2",
                            'frame_size'    : "1500",
                            'rate_pps'      : "10000",
                            'src_mac'       : "00:00:30:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "100",
                            'vlan_id'       : P1_dict['vlan_id_2'],
                            'vlanid_step'   : "1",
                            'vlanid_count'  : P1_dict['no_of_ints'],
                            'ip_src_addrs'  : P1_dict['v4_addr_2'],
                            'ip_step'       : "0.0.1.0",
                      }

        BCAST_L3_to_ACS_TI = testscript.parameters['BCAST_L3_to_ACS_TI'] = ixLib.configure_ixia_BCAST_traffic_item(BCAST_L3_to_ACS_dict)

        if BCAST_L3_to_ACS_TI == 0:
            log.debug("Configuring BCast from L3 to ACS failed")
            self.errored("Configuring BCast from L3 to ACS failed", goto=['next_tc'])

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
        IX_TP4 = testscript.parameters['IX_TP4']

        P1_dict = testscript.parameters['LEAF_3_TGEN_dict']

        UKNOWN_UCAST_L3_to_ACS_dict = {
                            'src_hndl'      : IX_TP4['port_handle'],
                            'dst_hndl'      : IX_TP1['port_handle'],
                            'TI_name'       : "UKNOWN_UCAST_L1_to_L2",
                            'frame_size'    : "1500",
                            'rate_pps'      : "10000",
                            'dst_mac'       : "00:00:45:00:00:01",
                            'dstmac_step'   : "00:00:00:00:00:01",
                            'dstmac_count'  : "100",
                            'src_mac'       : "00:00:41:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "100",
                            'vlan_id'       : P1_dict['vlan_id_2'],
                            'vlanid_step'   : "1",
                            'vlanid_count'  : P1_dict['no_of_ints'],
                      }

        UKNOWN_UCAST_L3_to_ACS_TI = testscript.parameters['UKNOWN_UCAST_L3_to_ACS_TI'] = ixLib.configure_ixia_UNKNOWN_UCAST_traffic_item(UKNOWN_UCAST_L3_to_ACS_dict)

        if UKNOWN_UCAST_L3_to_ACS_TI == 0:
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
        IX_TP4 = testscript.parameters['IX_TP4']

        P1_dict = testscript.parameters['LEAF_3_TGEN_dict']

        BUM_MCAST_L3_to_ACS_dict = {
                            'src_hndl'      : IX_TP4['port_handle'],
                            'dst_hndl'      : IX_TP1['port_handle'],
                            'TI_name'       : "BUM_MCAST_L2_to_L1",
                            'frame_size'    : "1500",
                            'rate_pps'      : "250000",
                            'dst_mac'       : "01:00:5E:00:00:C8",
                            'dstmac_step'   : "00:00:00:00:00:00",
                            'dstmac_count'  : P1_dict['no_of_ints'],
                            'src_mac'       : "00:00:AA:00:00:01",
                            'srcmac_step'   : P1_dict['mac_step'],
                            'srcmac_count'  : P1_dict['no_of_ints'],
                            'vlan_id'       : P1_dict['vlan_id_2'],
                            'vlanid_step'   : "1",
                            'vlanid_count'  : P1_dict['no_of_ints'],
                            'ip_src_addrs'  : P1_dict['v4_addr_2'],
                            'ip_src_step'   : P1_dict['v4_addr_step_2'],
                            'ip_dst_addrs'  : '226.1.1.10',
                            'ip_dst_step'   : '0.0.1.0',
                      }

        BUM_MCAST_L3_to_ACS_TI = testscript.parameters['BUM_MCAST_L3_to_ACS_TI'] = ixLib.configure_ixia_raw_vlan_traffic(BUM_MCAST_L3_to_ACS_dict)

        if BUM_MCAST_L3_to_ACS_TI == 0:
            log.debug("Configuring BUM_MCAST TI failed")
            self.errored("Configuring BUM_MCAST TI failed", goto=['cleanup'])

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

# *****************************************************************************************************************************#

class IXIA_CONFIGURATION_CONFIGURE_SQinVNI_IXIA_TRAFFIC(aetest.Testcase):
    """IXIA_CONFIGURATION_CONFIGURE_SQinVNI_IXIA_TRAFFIC"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONFIGURE_SQinVNI_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure SQinVNI Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']
            IX_TP3 = testscript.parameters['IX_TP3']
            IX_TP4 = testscript.parameters['IX_TP4']

            SQinVNI_v4_dict_1   = {'src_hndl'   : IX_TP2['ipv4_handle_12'],
                                    'dst_hndl'  : IX_TP3['ipv4_handle_13'],
                                    'circuit'   : 'ipv4',
                                    'TI_name'   : "SQinVNI_vPC1_vPC2_V4",
                                    'rate_pps'  : "10000",
                                    'bi_dir'    : 1
                                    }

            SQinVNI_v4_dict_2   = {'src_hndl'   : IX_TP2['ipv4_handle_12'],
                                    'dst_hndl'  : IX_TP4['ipv4_handle_14'],
                                    'circuit'   : 'ipv4',
                                    'TI_name'   : "SQinVNI_vPC1_SA_V4",
                                    'rate_pps'  : "10000",
                                    'bi_dir'    : 1
                                    }

            SQinVNI_v4_dict_3   = {'src_hndl'   : IX_TP3['ipv4_handle_13'],
                                    'dst_hndl'  : IX_TP4['ipv4_handle_14'],
                                    'circuit'   : 'ipv4',
                                    'TI_name'   : "SQinVNI_vPC2_SA_V4",
                                    'rate_pps'  : "10000",
                                    'bi_dir'    : 1
                                    }

            SQinVNI_v4_dict_4    = {'src_hndl'  : IX_TP4['ipv4_handle_14'],
                                    'dst_hndl'  : IX_TP1['ipv4_handle_11'],
                                    'circuit'   : 'ipv4',
                                    'TI_name'   : "SQinVNI_ACS_SA_V4",
                                    'rate_pps'  : "10000",
                                    'bi_dir'    : 1
                                    }

            SQinVNI_v6_dict_1   = {'src_hndl'   : IX_TP2['ipv6_handle_12'],
                                    'dst_hndl'  : IX_TP3['ipv6_handle_13'],
                                    'circuit'   : 'ipv6',
                                    'TI_name'   : "SQinVNI_vPC1_vPC2_V6",
                                    'rate_pps'  : "10000",
                                    'bi_dir'    : 1
                                    }

            SQinVNI_v6_dict_2   = {'src_hndl'   : IX_TP2['ipv6_handle_12'],
                                    'dst_hndl'  : IX_TP4['ipv6_handle_14'],
                                    'circuit'   : 'ipv6',
                                    'TI_name'   : "SQinVNI_vPC1_SA_V6",
                                    'rate_pps'  : "10000",
                                    'bi_dir'    : 1
                                    }

            SQinVNI_v6_dict_3   = {'src_hndl'   : IX_TP3['ipv6_handle_13'],
                                    'dst_hndl'  : IX_TP4['ipv6_handle_14'],
                                    'circuit'   : 'ipv6',
                                    'TI_name'   : "SQinVNI_vPC2_SA_V6",
                                    'rate_pps'  : "10000",
                                    'bi_dir'    : 1
                                    }

            SQinVNI_v6_dict_4   = {'src_hndl'   : IX_TP4['ipv6_handle_14'],
                                    'dst_hndl'  : IX_TP1['ipv6_handle_11'],
                                    'circuit'   : 'ipv6',
                                    'TI_name'   : "SQinVNI_ACS_SA_V6",
                                    'rate_pps'  : "10000",
                                    'bi_dir'    : 1
                                    }

            SQinVNI_v4_TI_1 = testscript.parameters['SQinVNI_v4_TI_1'] = ixLib.configure_ixia_traffic_item(SQinVNI_v4_dict_1)
            SQinVNI_v4_TI_2 = testscript.parameters['SQinVNI_v4_TI_2'] = ixLib.configure_ixia_traffic_item(SQinVNI_v4_dict_2)
            SQinVNI_v4_TI_3 = testscript.parameters['SQinVNI_v4_TI_3'] = ixLib.configure_ixia_traffic_item(SQinVNI_v4_dict_3)
            SQinVNI_v4_TI_4 = testscript.parameters['SQinVNI_v4_TI_4'] = ixLib.configure_ixia_traffic_item(SQinVNI_v4_dict_4)
            SQinVNI_v6_TI_1 = testscript.parameters['SQinVNI_v6_TI_1'] = ixLib.configure_ixia_traffic_item(SQinVNI_v6_dict_1)
            SQinVNI_v6_TI_2 = testscript.parameters['SQinVNI_v6_TI_2'] = ixLib.configure_ixia_traffic_item(SQinVNI_v6_dict_2)
            SQinVNI_v6_TI_3 = testscript.parameters['SQinVNI_v6_TI_3'] = ixLib.configure_ixia_traffic_item(SQinVNI_v6_dict_3)
            SQinVNI_v6_TI_4 = testscript.parameters['SQinVNI_v6_TI_4'] = ixLib.configure_ixia_traffic_item(SQinVNI_v6_dict_4)

            if SQinVNI_v4_TI_1 == 0 or SQinVNI_v4_TI_2 == 0 or SQinVNI_v4_TI_3 == 0 or SQinVNI_v4_TI_4 == 0 or SQinVNI_v6_TI_1 == 0 or SQinVNI_v6_TI_2 == 0 or SQinVNI_v6_TI_3 == 0 or SQinVNI_v6_TI_4 == 0:
                log.debug("Configuring SQinVNI failed")
                self.errored("Configuring SQinVNI failed", goto=['next_tc'])

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

        time.sleep(100)

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
        """ IXIA_CONFIGURATION subsection: Configure L2KUC Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']
            IX_TP3 = testscript.parameters['IX_TP3']
            IX_TP4 = testscript.parameters['IX_TP4']

            L2KUC_v4_dict_1 = {'src_hndl'   : IX_TP2['ipv4_handle_22'],
                                'dst_hndl'  : IX_TP3['ipv4_handle_23'],
                                'circuit'   : 'ipv4',
                                'TI_name'   : "L2KUC_vPC1_vPC2_V4",
                                'rate_pps'  : "10000",
                                'bi_dir'    : 1
                                }

            L2KUC_v4_dict_2 = {'src_hndl'   : IX_TP2['ipv4_handle_22'],
                                'dst_hndl'  : IX_TP4['ipv4_handle_24'],
                                'circuit'   : 'ipv4',
                                'TI_name'   : "L2KUC_vPC1_SA_V4",
                                'rate_pps'  : "10000",
                                'bi_dir'    : 1
                                }

            L2KUC_v4_dict_3 = {'src_hndl'   : IX_TP3['ipv4_handle_23'],
                                'dst_hndl'  : IX_TP4['ipv4_handle_24'],
                                'circuit'   : 'ipv4',
                                'TI_name'   : "L2KUC_vPC2_SA_V4",
                                'rate_pps'  : "10000",
                                'bi_dir'    : 1
                                }

            L2KUC_v4_dict_4 = {'src_hndl'   : IX_TP4['ipv4_handle_24'],
                                'dst_hndl'  : IX_TP1['ipv4_handle_21'],
                                'circuit'   : 'ipv4',
                                'TI_name'   : "L2KUC_ACS_SA_V4",
                                'rate_pps'  : "10000",
                                'bi_dir'    : 1
                                }

            L2KUC_v6_dict_1 = {'src_hndl'   : IX_TP2['ipv6_handle_22'],
                                'dst_hndl'  : IX_TP3['ipv6_handle_23'],
                                'circuit'   : 'ipv6',
                                'TI_name'   : "L2KUC_vPC1_vPC2_V6",
                                'rate_pps'  : "10000",
                                'bi_dir'    : 1
                                }

            L2KUC_v6_dict_2 = {'src_hndl'   : IX_TP2['ipv6_handle_22'],
                                'dst_hndl'  : IX_TP4['ipv6_handle_24'],
                                'circuit'   : 'ipv6',
                                'TI_name'   : "L2KUC_vPC1_SA_V6",
                                'rate_pps'  : "10000",
                                'bi_dir'    : 1
                                }

            L2KUC_v6_dict_3 = {'src_hndl'   : IX_TP3['ipv6_handle_23'],
                                'dst_hndl'  : IX_TP4['ipv6_handle_24'],
                                'circuit'   : 'ipv6',
                                'TI_name'   : "L2KUC_vPC2_SA_V6",
                                'rate_pps'  : "10000",
                                'bi_dir'    : 1
                                }

            L2KUC_v6_dict_4 = {'src_hndl'   : IX_TP4['ipv6_handle_24'],
                                'dst_hndl'  : IX_TP1['ipv6_handle_21'],
                                'circuit'   : 'ipv6',
                                'TI_name'   : "L2KUC_ACS_SA_V6",
                                'rate_pps'  : "10000",
                                'bi_dir'    : 1
                                }

            L2KUC_v4_TI_1 = testscript.parameters['L2KUC_v4_TI_1'] = ixLib.configure_ixia_traffic_item(L2KUC_v4_dict_1)
            L2KUC_v4_TI_2 = testscript.parameters['L2KUC_v4_TI_2'] = ixLib.configure_ixia_traffic_item(L2KUC_v4_dict_2)
            L2KUC_v4_TI_3 = testscript.parameters['L2KUC_v4_TI_3'] = ixLib.configure_ixia_traffic_item(L2KUC_v4_dict_3)
            L2KUC_v4_TI_4 = testscript.parameters['L2KUC_v4_TI_4'] = ixLib.configure_ixia_traffic_item(L2KUC_v4_dict_4)
            L2KUC_v6_TI_1 = testscript.parameters['L2KUC_v6_TI_1'] = ixLib.configure_ixia_traffic_item(L2KUC_v6_dict_1)
            L2KUC_v6_TI_2 = testscript.parameters['L2KUC_v6_TI_2'] = ixLib.configure_ixia_traffic_item(L2KUC_v6_dict_2)
            L2KUC_v6_TI_3 = testscript.parameters['L2KUC_v6_TI_3'] = ixLib.configure_ixia_traffic_item(L2KUC_v6_dict_3)
            L2KUC_v6_TI_4 = testscript.parameters['L2KUC_v6_TI_4'] = ixLib.configure_ixia_traffic_item(L2KUC_v6_dict_4)

            if L2KUC_v4_TI_1 == 0 or L2KUC_v4_TI_2 == 0 or L2KUC_v4_TI_3 == 0 or L2KUC_v4_TI_4 == 0 or L2KUC_v6_TI_1 == 0 or L2KUC_v6_TI_2 == 0 or L2KUC_v6_TI_3 == 0 or L2KUC_v6_TI_4 == 0:
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
            IX_TP3 = testscript.parameters['IX_TP3']
            IX_TP4 = testscript.parameters['IX_TP4']

            vrf_count = int(testscript.parameters['forwardingSysDict']['VRF_count'])
            vlan_per_vrf = int(testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']) - 2

            L3KUC_v4_dict_1 = {'src_hndl'               : IX_TP2['ipv4_handle_22'],
                                'dst_hndl'              : IX_TP3['ipv4_handle_23'],
                                'circuit'               : 'ipv4',
                                'TI_name'               : "L3KUC_vPC1_vPC2_V4",
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

            L3KUC_v4_dict_2 = {'src_hndl'               : IX_TP2['ipv4_handle_22'],
                                'dst_hndl'              : IX_TP4['ipv4_handle_24'],
                                'circuit'               : 'ipv4',
                                'TI_name'               : "L3KUC_vPC1_SA_V4",
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

            L3KUC_v4_dict_3 = {'src_hndl'               : IX_TP3['ipv4_handle_23'],
                                'dst_hndl'              : IX_TP4['ipv4_handle_24'],
                                'circuit'               : 'ipv4',
                                'TI_name'               : "L3KUC_vPC2_SA_V4",
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

            L3KUC_v4_dict_4 = {'src_hndl'               : IX_TP4['ipv4_handle_24'],
                                'dst_hndl'              : IX_TP1['ipv4_handle_21'],
                                'circuit'               : 'ipv4',
                                'TI_name'               : "L3KUC_ACS_SA_V4",
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

            L3KUC_v6_dict_1 = {'src_hndl'               : IX_TP2['ipv6_handle_22'],
                                'dst_hndl'              : IX_TP3['ipv6_handle_23'],
                                'circuit'               : 'ipv6',
                                'TI_name'               : "L3KUC_vPC1_vPC2_V6",
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

            L3KUC_v6_dict_2 = {'src_hndl'               : IX_TP2['ipv6_handle_22'],
                                'dst_hndl'              : IX_TP4['ipv6_handle_24'],
                                'circuit'               : 'ipv6',
                                'TI_name'               : "L3KUC_vPC1_SA_V6",
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

            L3KUC_v6_dict_3 = {'src_hndl'               : IX_TP3['ipv6_handle_23'],
                                'dst_hndl'              : IX_TP4['ipv6_handle_24'],
                                'circuit'               : 'ipv6',
                                'TI_name'               : "L3KUC_vPC2_SA_V6",
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

            L3KUC_v6_dict_4 = {'src_hndl'               : IX_TP4['ipv6_handle_24'],
                                'dst_hndl'              : IX_TP1['ipv6_handle_21'],
                                'circuit'               : 'ipv6',
                                'TI_name'               : "L3KUC_ACS_SA_V6",
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


            L3KUC_v4_TI_1 = testscript.parameters['L3KUC_v4_TI_1'] = ixLib.configure_multi_endpoint_ixia_traffic_item(L3KUC_v4_dict_1)
            L3KUC_v4_TI_2 = testscript.parameters['L3KUC_v4_TI_2'] = ixLib.configure_multi_endpoint_ixia_traffic_item(L3KUC_v4_dict_2)
            L3KUC_v4_TI_3 = testscript.parameters['L3KUC_v4_TI_3'] = ixLib.configure_multi_endpoint_ixia_traffic_item(L3KUC_v4_dict_3)
            L3KUC_v4_TI_4 = testscript.parameters['L3KUC_v4_TI_4'] = ixLib.configure_multi_endpoint_ixia_traffic_item(L3KUC_v4_dict_4)
            L3KUC_v6_TI_1 = testscript.parameters['L3KUC_v6_TI_1'] = ixLib.configure_multi_endpoint_ixia_traffic_item(L3KUC_v6_dict_1)
            L3KUC_v6_TI_2 = testscript.parameters['L3KUC_v6_TI_2'] = ixLib.configure_multi_endpoint_ixia_traffic_item(L3KUC_v6_dict_2)
            L3KUC_v6_TI_3 = testscript.parameters['L3KUC_v6_TI_3'] = ixLib.configure_multi_endpoint_ixia_traffic_item(L3KUC_v6_dict_3)
            L3KUC_v6_TI_4 = testscript.parameters['L3KUC_v6_TI_4'] = ixLib.configure_multi_endpoint_ixia_traffic_item(L3KUC_v6_dict_4)

            if L3KUC_v4_TI_1 == 0 or L3KUC_v4_TI_2 == 0 or L3KUC_v4_TI_3 == 0 or L3KUC_v4_TI_4 == 0 or L3KUC_v6_TI_1 == 0 or L3KUC_v6_TI_2 == 0 or L3KUC_v6_TI_3 == 0 or L3KUC_v6_TI_4 == 0:
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

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict'],
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

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict'],
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

class TC001_VxLAN_SQinVNI_Verification(aetest.Testcase):
    """ TC001_VxLAN_SQinVNI_Verification """

    @aetest.test
    def Start_Mirror_on_Leafs(self, testscript):
        """ Start_Mirror_on_Leafs """

        testscript.parameters['LEAF-1'].configure('''

                  monitor session 1
                  source interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' rx
                  destination interface sup-eth0
                  no shut

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  monitor session 1
                  source interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' rx
                  destination interface sup-eth0
                  no shut

              ''')

        testscript.parameters['LEAF-3'].configure('''

                  monitor session 1
                  source interface port-channel ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' rx
                  destination interface sup-eth0
                  no shut

              ''')

    @aetest.test
    def perform_copy_r_s(self, testscript):
        """ SPAN_CONFIGURATION test subsection: Save all configurations (copy r s) """

        log.info(banner("Performing Copy R S"))

        testscript.parameters['LEAF-1'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-3'].configure("copy r s", timeout=300)

        time.sleep(60) 

    @aetest.test
    def Start_SQinVNI_Traffic(self, testscript):
        """ Start_SQinVNI_Traffic """
        if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Ethanalyzer_Mirrored_Leafs(self, testscript):
        """ Ethanalyzer_Mirrored_Leafs """

        fail_flag = 0

        Traffic_Leaf = json.loads(testscript.parameters['LEAF-1'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])))

        if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
            """ LEAF-1 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_1)):
                if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_1)):
                if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
                elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
        else:
            """ LEAF-2 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_2)):
                if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_2)):
                if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
                elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
                    fail_flag = 1

        """ LEAF-3 Verification """
        Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

        match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

        for i in range(len(match_vlan_3)):
            if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
                log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
                log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
                log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
                log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            else:
                log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
                fail_flag = 1


        Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

        match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

        for i in range(len(match_vni_3)):
            if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
                log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
            elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
                log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
            else:
                log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
                fail_flag = 1

        if fail_flag == 1:
            self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
        else:
            self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")
    
    @aetest.test
    def Stop_SQinVNI_Traffic(self):
        """ Stop_SQinVNI_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

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

class TC002_VxLAN_SQinVNI_UpLink_Flap(aetest.Testcase):
    """ TC002_VxLAN_SQinVNI_UpLink_Flap """
    
    @aetest.test
    def SA_UP_Link_Flap(self, testscript):
        """ SA_UP_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface port-channel ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                  shutdown
                  no shutdown

              ''')

        sleep(150)

    @aetest.test
    def Start_SQinVNI_Traffic(self, testscript):
        """ Start_SQinVNI_Traffic """
        if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Ethanalyzer_Mirrored_Leafs(self, testscript):
        """ Ethanalyzer_Mirrored_Leafs """

        fail_flag = 0

        Traffic_Leaf = json.loads(testscript.parameters['LEAF-1'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])))


        if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
            """ LEAF-1 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_1)):
                if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_1)):
                if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
                elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
        else:
            """ LEAF-2 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_2)):
                if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_2)):
                if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
                elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
                    fail_flag = 1


        """ LEAF-3 Verification """
        Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

        match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

        for i in range(len(match_vlan_3)):
            if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
                log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
                log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
                log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
                log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            else:
                log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
                fail_flag = 1


        Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

        match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

        for i in range(len(match_vni_3)):
            if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
                log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
            elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
                log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
            else:
                log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
                fail_flag = 1


        if fail_flag == 1:
            self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
        else:
            self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")

    @aetest.test
    def Stop_SQinVNI_Traffic(self):
        """ Stop_SQinVNI_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

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
     
class TC003_VxLAN_SQinVNI_vPC_UpLink_Flap(aetest.Testcase):
    """ TC003_VxLAN_SQinVNI_vPC_UpLink_Flap """

    @aetest.test
    def vPC_UP_Link_Flap(self, testscript):
        """ vPC_UP_Link_Flap """

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

        sleep(150)

    @aetest.test
    def Start_SQinVNI_Traffic(self, testscript):
        """ Start_SQinVNI_Traffic """
        if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Ethanalyzer_Mirrored_Leafs(self, testscript):
        """ Ethanalyzer_Mirrored_Leafs """

        fail_flag = 0

        Traffic_Leaf = json.loads(testscript.parameters['LEAF-1'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])))


        if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
            """ LEAF-1 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_1)):
                if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_1)):
                if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
                elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
        else:
            """ LEAF-2 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_2)):
                if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_2)):
                if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
                elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
                    fail_flag = 1


        """ LEAF-3 Verification """
        Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

        match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

        for i in range(len(match_vlan_3)):
            if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
                log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
                log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
                log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
                log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            else:
                log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
                fail_flag = 1


        Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

        match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

        for i in range(len(match_vni_3)):
            if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
                log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
            elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
                log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
            else:
                log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
                fail_flag = 1


        if fail_flag == 1:
            self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
        else:
            self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")

    @aetest.test
    def Stop_SQinVNI_Traffic(self):
        """ Stop_SQinVNI_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

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

class TC004_VxLAN_SQinVNI_Access_Link_Flap(aetest.Testcase):
    """ TC004_VxLAN_SQinVNI_Access_Link_Flap """

    @aetest.test
    def SA_Access_Link_Flap(self, testscript):
        """ SA_Access_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_IXIA']) + '''
                  shutdown
                  no shutdown

              ''')

        sleep(200)

    @aetest.test
    def Start_SQinVNI_Traffic(self, testscript):
        """ Start_SQinVNI_Traffic """
        if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Ethanalyzer_Mirrored_Leafs(self, testscript):
        """ Ethanalyzer_Mirrored_Leafs """

        fail_flag = 0

        Traffic_Leaf = json.loads(testscript.parameters['LEAF-3'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id'])))


        if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
            """ LEAF-1 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_1)):
                if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_1)):
                if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
                elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
        else:
            """ LEAF-2 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_2)):
                if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_2)):
                if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
                elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
                    fail_flag = 1


        """ LEAF-3 Verification """
        Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

        match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

        for i in range(len(match_vlan_3)):
            if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
                log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
                log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
                log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
                log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            else:
                log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
                fail_flag = 1


        Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

        match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

        for i in range(len(match_vni_3)):
            if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
                log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
            elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
                log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
            else:
                log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
                fail_flag = 1


        if fail_flag == 1:
            self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
        else:
            self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")

    @aetest.test
    def Stop_SQinVNI_Traffic(self):
        """ Stop_SQinVNI_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(3) == 0:
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
            
class TC005_VxLAN_SQinVNI_vPC_Access_LinkFlap(aetest.Testcase):
    """ TC005_VxLAN_SQinVNI_vPC_Access_LinkFlap """

    @aetest.test
    def vPC_Access_Link_Flap(self, testscript):
        """ vPC_Access_Link_Flap """

        testscript.parameters['LEAF-1'].configure('''

                  interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
                  shutdown
                  no shutdown

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + '''
                  shutdown
                  no shutdown

              ''')

        sleep(200)

    @aetest.test
    def Start_SQinVNI_Traffic(self, testscript):
        """ Start_SQinVNI_Traffic """
        if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Ethanalyzer_Mirrored_Leafs(self, testscript):
        """ Ethanalyzer_Mirrored_Leafs """

        fail_flag = 0

        Traffic_Leaf = json.loads(testscript.parameters['LEAF-1'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])))


        if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
            """ LEAF-1 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_1)):
                if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_1)):
                if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
                elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
        else:
            """ LEAF-2 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_2)):
                if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_2)):
                if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
                elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
                    fail_flag = 1


        """ LEAF-3 Verification """
        Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

        match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

        for i in range(len(match_vlan_3)):
            if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
                log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
                log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
                log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
                log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            else:
                log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
                fail_flag = 1


        Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

        match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

        for i in range(len(match_vni_3)):
            if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
                log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
            elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
                log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
            else:
                log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
                fail_flag = 1

        if fail_flag == 1:
            self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
        else:
            self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")

    @aetest.test
    def Stop_SQinVNI_Traffic(self):
        """ Stop_SQinVNI_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(3) == 0:
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

class TC006_VxLAN_SQinVNI_NVE_Flap(aetest.Testcase):
    """ TC006_VxLAN_SQinVNI_NVE_Flap """

    @aetest.test
    def SA_NVE_Flap(self, testscript):
        """ SA_NVE_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface nve 1
                  shutdown
                  no shutdown

              ''')

        sleep(150)

    @aetest.test
    def Start_SQinVNI_Traffic(self, testscript):
        """ Start_SQinVNI_Traffic """
        if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Ethanalyzer_Mirrored_Leafs(self, testscript):
        """ Ethanalyzer_Mirrored_Leafs """

        fail_flag = 0

        Traffic_Leaf = json.loads(testscript.parameters['LEAF-1'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])))


        if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
            """ LEAF-1 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_1)):
                if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_1)):
                if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
                elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
        else:
            """ LEAF-2 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_2)):
                if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_2)):
                if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
                elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
                    fail_flag = 1


        """ LEAF-3 Verification """
        Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

        match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

        for i in range(len(match_vlan_3)):
            if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
                log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
                log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
                log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
                log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            else:
                log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
                fail_flag = 1


        Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

        match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

        for i in range(len(match_vni_3)):
            if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
                log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
            elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
                log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
            else:
                log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
                fail_flag = 1


        if fail_flag == 1:
            self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
        else:
            self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")

    @aetest.test
    def Stop_SQinVNI_Traffic(self):
        """ Stop_SQinVNI_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

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
            
class TC007_VxLAN_SQinVNI_vPC_NVE_Flap(aetest.Testcase):
    """ TC007_VxLAN_SQinVNI_vPC_NVE_Flap """
    
    @aetest.test
    def vPC_NVE_Flap(self, testscript):
        """ vPC_NVE_Flap """

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

        sleep(150)

    @aetest.test
    def Start_SQinVNI_Traffic(self, testscript):
        """ Start_SQinVNI_Traffic """
        if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Ethanalyzer_Mirrored_Leafs(self, testscript):
        """ Ethanalyzer_Mirrored_Leafs """
        fail_flag = 0

        Traffic_Leaf = json.loads(testscript.parameters['LEAF-1'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])))


        if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
            """ LEAF-1 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_1)):
                if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_1)):
                if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
                elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
        else:
            """ LEAF-2 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_2)):
                if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_2)):
                if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
                elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
                    fail_flag = 1


        """ LEAF-3 Verification """
        Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

        match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

        for i in range(len(match_vlan_3)):
            if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
                log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
                log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
                log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
                log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            else:
                log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
                fail_flag = 1


        Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

        match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

        for i in range(len(match_vni_3)):
            if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
                log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
            elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
                log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
            else:
                log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
                fail_flag = 1


        if fail_flag == 1:
            self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
        else:
            self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")

    @aetest.test
    def Stop_SQinVNI_Traffic(self):
        """ Stop_SQinVNI_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

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

class TC008_VxLAN_SQinVNI_Add_Remove_VN_Segemnt(aetest.Testcase):
    """ TC008_VxLAN_SQinVNI_Add_Remove_VN_Segemnt """
            
    @aetest.test
    def SA_Remove_Add_VN_Segment(self, testscript):
        """ SA_Remove_Add_VN_Segment """


        testscript.parameters['LEAF-3'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + '''
                  no vn-segment ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + '''
                  vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                  no vn-segment ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + '''

              ''')

        testscript.parameters['LEAF-3'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + '''
                  vn-segment ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + '''
                  vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                  vn-segment ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + '''

              ''')

        sleep(150)

    @aetest.test
    def Start_SQinVNI_Traffic(self, testscript):
        """ Start_SQinVNI_Traffic """
        if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Ethanalyzer_Mirrored_Leafs(self, testscript):
        """ Ethanalyzer_Mirrored_Leafs """

        fail_flag = 0

        Traffic_Leaf = json.loads(testscript.parameters['LEAF-1'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])))


        if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
            """ LEAF-1 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_1)):
                if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_1)):
                if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
                elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
        else:
            """ LEAF-2 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_2)):
                if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_2)):
                if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
                elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
                    fail_flag = 1


        """ LEAF-3 Verification """
        Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

        match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

        for i in range(len(match_vlan_3)):
            if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
                log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
                log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
                log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
                log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            else:
                log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
                fail_flag = 1


        Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

        match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

        for i in range(len(match_vni_3)):
            if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
                log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
            elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
                log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
            else:
                log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
                fail_flag = 1


        if fail_flag == 1:
            self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
        else:
            self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")

    @aetest.test
    def Stop_SQinVNI_Traffic(self):
        """ Stop_SQinVNI_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

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

class TC009_VxLAN_SQinVNI_vPC_Remove_Add_VN_Segment(aetest.Testcase):
    """ TC009_VxLAN_SQinVNI_vPC_Remove_Add_VN_Segment """
    
    @aetest.test
    def vPC_Remove_Add_VN_Segment(self, testscript):
        """ vPC_Remove_Add_VN_Segment """

        testscript.parameters['LEAF-1'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + '''
                  no vn-segment ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + '''
                  vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                  no vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + '''

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + '''
                  no vn-segment ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + '''
                  vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                  no vn-segment ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + '''

              ''')

        testscript.parameters['LEAF-1'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + '''
                  vn-segment ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + '''
                  vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                  vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + '''

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + '''
                  vn-segment ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + '''
                  vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                  vn-segment ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + '''

              ''')

        sleep(150)

    @aetest.test
    def Start_SQinVNI_Traffic(self, testscript):
        """ Start_SQinVNI_Traffic """
        if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Ethanalyzer_Mirrored_Leafs(self, testscript):
        """ Ethanalyzer_Mirrored_Leafs """

        fail_flag = 0

        Traffic_Leaf = json.loads(testscript.parameters['LEAF-1'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])))


        if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
            """ LEAF-1 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_1)):
                if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_1)):
                if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
                elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
        else:
            """ LEAF-2 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_2)):
                if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_2)):
                if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
                elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
                    fail_flag = 1


        """ LEAF-3 Verification """
        Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

        match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

        for i in range(len(match_vlan_3)):
            if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
                log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
                log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
                log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
                log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            else:
                log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
                fail_flag = 1


        Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

        match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

        for i in range(len(match_vni_3)):
            if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
                log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
            elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
                log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
            else:
                log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
                fail_flag = 1


        if fail_flag == 1:
            self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
        else:
            self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")

    @aetest.test
    def Stop_SQinVNI_Traffic(self):
        """ Stop_SQinVNI_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

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

class TC010_VxLAN_SQinVNI_SA_Remove_Add_Member_VN(aetest.Testcase):
    """ TC010_VxLAN_SQinVNI_SA_Remove_Add_Member_VN """
    
    @aetest.test
    def SA_Remove_Add_Member_VNI(self, testscript):
        """ SA_Remove_Add_Member_VNI """


        testscript.parameters['LEAF-3'].configure('''

                  interface nve 1
                  no member vni ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + '''
                  no member vni ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + '''

              ''')

        testscript.parameters['LEAF-3'].configure('''

                  interface nve 1
                  member vni ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + '''
                  mcast-group 224.1.1.101
                  member vni ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + '''
                  mcast-group 224.1.1.101

              ''')

        sleep(200)

    @aetest.test
    def Start_SQinVNI_Traffic(self, testscript):
        """ Start_SQinVNI_Traffic """
        if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Ethanalyzer_Mirrored_Leafs(self, testscript):
        """ Ethanalyzer_Mirrored_Leafs """

        fail_flag = 0

        Traffic_Leaf = json.loads(testscript.parameters['LEAF-1'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])))


        if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
            """ LEAF-1 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_1)):
                if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_1)):
                if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
                elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
        else:
            """ LEAF-2 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_2)):
                if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_2)):
                if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
                elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
                    fail_flag = 1


        """ LEAF-3 Verification """
        Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

        match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

        for i in range(len(match_vlan_3)):
            if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
                log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
                log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
                log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
                log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            else:
                log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
                fail_flag = 1


        Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

        match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

        for i in range(len(match_vni_3)):
            if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
                log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
            elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
                log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
            else:
                log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
                fail_flag = 1


        if fail_flag == 1:
            self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
        else:
            self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")
            
    @aetest.test
    def Stop_SQinVNI_Traffic(self):
        """ Stop_SQinVNI_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

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

class TC011_VxLAN_SQinVNI_vPC_Remove_Add_Member_VNI(aetest.Testcase):
    """ TC011_VxLAN_SQinVNI_vPC_Remove_Add_Member_VNI """
    
    @aetest.test
    def vPC_Remove_Add_Member_VNI(self, testscript):
        """ vPC_Remove_Add_Member_VNI """

        testscript.parameters['LEAF-1'].configure('''

                  interface nve 1
                  no member vni ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + '''
                  no member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + '''

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  interface nve 1
                  no member vni ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + '''
                  no member vni ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + '''

              ''')

        testscript.parameters['LEAF-1'].configure('''

                  interface nve 1
                  member vni ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + '''
                  mcast-group 224.1.1.101
                  member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + '''
                  mcast-group 224.1.1.101

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  interface nve 1
                  member vni ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + '''
                  mcast-group 224.1.1.101
                  member vni ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + '''
                  mcast-group 224.1.1.101

              ''')

        sleep(150)

    @aetest.test
    def Start_SQinVNI_Traffic(self, testscript):
        """ Start_SQinVNI_Traffic """
        if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Ethanalyzer_Mirrored_Leafs(self, testscript):
        """ Ethanalyzer_Mirrored_Leafs """

        fail_flag = 0

        Traffic_Leaf = json.loads(testscript.parameters['LEAF-1'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])))


        if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
            """ LEAF-1 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_1)):
                if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_1)):
                if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
                elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
        else:
            """ LEAF-2 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_2)):
                if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_2)):
                if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
                elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
                    fail_flag = 1


        """ LEAF-3 Verification """
        Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

        match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

        for i in range(len(match_vlan_3)):
            if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
                log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
                log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
                log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
                log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            else:
                log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
                fail_flag = 1


        Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

        match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

        for i in range(len(match_vni_3)):
            if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
                log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
            elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
                log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
            else:
                log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
                fail_flag = 1


        if fail_flag == 1:
            self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
        else:
            self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")

    @aetest.test
    def Stop_SQinVNI_Traffic(self):
        """ Stop_SQinVNI_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

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

class TC012_VxLAN_SQinVNI_SA_Loopback_Flap(aetest.Testcase):
    """ TC012_VxLAN_SQinVNI_SA_Loopback_Flap """
    
    @aetest.test
    def SA_Loopback_Flap(self, testscript):
        """ SA_Loopback_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['LEAF_3_dict']['NVE_data']['src_loop']) + '''
                  shutdown
                  no shutdown

              ''')

        sleep(150)

    @aetest.test
    def Start_SQinVNI_Traffic(self, testscript):
        """ Start_SQinVNI_Traffic """
        if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Ethanalyzer_Mirrored_Leafs(self, testscript):
        """ Ethanalyzer_Mirrored_Leafs """

        fail_flag = 0

        Traffic_Leaf = json.loads(testscript.parameters['LEAF-1'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])))


        if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
            """ LEAF-1 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_1)):
                if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_1)):
                if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
                elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
        else:
            """ LEAF-2 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_2)):
                if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_2)):
                if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
                elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
                    fail_flag = 1


        """ LEAF-3 Verification """
        Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

        match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

        for i in range(len(match_vlan_3)):
            if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
                log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
                log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
                log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
                log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            else:
                log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
                fail_flag = 1


        Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

        match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

        for i in range(len(match_vni_3)):
            if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
                log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
            elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
                log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
            else:
                log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
                fail_flag = 1


        if fail_flag == 1:
            self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
        else:
            self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")

    @aetest.test
    def Stop_SQinVNI_Traffic(self):
        """ Stop_SQinVNI_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

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

class TC013_VxLAN_SQinVNI_vPC_Loopback_Flap(aetest.Testcase):
    """ TC013_VxLAN_SQinVNI_vPC_Loopback_Flap """

    @aetest.test
    def vPC_Loopback_Flap(self, testscript):
        """ vPC_Loopback_Flap """

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

        sleep(150)

    @aetest.test
    def Start_SQinVNI_Traffic(self, testscript):
        """ Start_SQinVNI_Traffic """
        if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Ethanalyzer_Mirrored_Leafs(self, testscript):
        """ Ethanalyzer_Mirrored_Leafs """

        fail_flag = 0

        Traffic_Leaf = json.loads(testscript.parameters['LEAF-1'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])))


        if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
            """ LEAF-1 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_1)):
                if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_1)):
                if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
                elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
        else:
            """ LEAF-2 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_2)):
                if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_2)):
                if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
                elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
                    fail_flag = 1


        """ LEAF-3 Verification """
        Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

        match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

        for i in range(len(match_vlan_3)):
            if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
                log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
                log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
                log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
                log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            else:
                log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
                fail_flag = 1


        Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

        match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

        for i in range(len(match_vni_3)):
            if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
                log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
            elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
                log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
            else:
                log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
                fail_flag = 1


        if fail_flag == 1:
            self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
        else:
            self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")
            
    @aetest.test
    def Stop_SQinVNI_Traffic(self):
        """ Stop_SQinVNI_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

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

class TC014_VxLAN_SQinVNI_SA_Remove_Add_VLAN(aetest.Testcase):
    """ TC014_VxLAN_SQinVNI_SA_Remove_Add_VLAN """

    @aetest.test
    def SA_Remove_Add_VLAN(self, testscript):
        """ SA_Remove_Add_VLAN """

        testscript.parameters['LEAF-3'].configure('''

                  no vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + '''
                  vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + '''

              ''')

        sleep(150)

    @aetest.test
    def Start_SQinVNI_Traffic(self, testscript):
        """ Start_SQinVNI_Traffic """
        if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Ethanalyzer_Mirrored_Leafs(self, testscript):
        """ Ethanalyzer_Mirrored_Leafs """

        fail_flag = 0

        Traffic_Leaf = json.loads(testscript.parameters['LEAF-1'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])))


        if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
            """ LEAF-1 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_1)):
                if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_1)):
                if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
                elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
        else:
            """ LEAF-2 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_2)):
                if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_2)):
                if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
                elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
                    fail_flag = 1


        """ LEAF-3 Verification """
        Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

        match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

        for i in range(len(match_vlan_3)):
            if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
                log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
                log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
                log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
                log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            else:
                log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
                fail_flag = 1


        Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

        match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

        for i in range(len(match_vni_3)):
            if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
                log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
            elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
                log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
            else:
                log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
                fail_flag = 1


        if fail_flag == 1:
            self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
        else:
            self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")

    @aetest.test
    def Stop_SQinVNI_Traffic(self):
        """ Stop_SQinVNI_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

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

class TC015_VxLAN_SQinVNI_vPC_Remove_Add_VLAN(aetest.Testcase):
    """ TC015_VxLAN_SQinVNI_vPC_Remove_Add_VLAN """
    
    @aetest.test
    def vPC_Remove_Add_VLAN(self, testscript):
        """ vPC_Remove_Add_VLAN """

        testscript.parameters['LEAF-1'].configure('''

                  no vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + '''
                  vlan ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + '''

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  no vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + '''
                  vlan ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + '''

              ''')

        sleep(150)

    @aetest.test
    def Start_SQinVNI_Traffic(self, testscript):
        """ Start_SQinVNI_Traffic """
        if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Ethanalyzer_Mirrored_Leafs(self, testscript):
        """ Ethanalyzer_Mirrored_Leafs """

        fail_flag = 0

        Traffic_Leaf = json.loads(testscript.parameters['LEAF-1'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])))


        if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
            """ LEAF-1 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_1)):
                if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_1)):
                if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
                elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
        else:
            """ LEAF-2 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_2)):
                if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_2)):
                if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
                elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
                    fail_flag = 1


        """ LEAF-3 Verification """
        Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

        match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

        for i in range(len(match_vlan_3)):
            if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
                log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
                log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
                log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
                log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            else:
                log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
                fail_flag = 1


        Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

        match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

        for i in range(len(match_vni_3)):
            if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
                log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
            elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
                log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
            else:
                log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
                fail_flag = 1


        if fail_flag == 1:
            self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
        else:
            self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")

    @aetest.test
    def Stop_SQinVNI_Traffic(self):
        """ Stop_SQinVNI_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

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

# class TC016_VxLAN_SQinVNI_Change_Access_VLAN_All_Nodes(aetest.Testcase):
#     """ TC016_VxLAN_SQinVNI_Change_Access_VLAN_All_Nodes """

#     @aetest.test
#     def Change_Access_VLAN_All_Nodes(self, testscript):
#         """ Change_Access_VLAN_All_Nodes """

#         testscript.parameters['LEAF-1'].configure('''

#                   interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
#                   switchport access vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''

#                   interface ''' + str(testscript.parameters['intf_LEAF_1_to_IXIA']) + '''
#                   switchport access vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''

#               ''')

#         testscript.parameters['LEAF-2'].configure('''

#                   interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + '''
#                   switchport access vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''

#               ''')

#         testscript.parameters['LEAF-3'].configure('''

#                   interface ''' + str(testscript.parameters['intf_LEAF_3_to_IXIA']) + '''
#                   switchport access vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + '''

#               ''')

#         sleep(150)

#         """ Start_SQinVNI_Traffic """

#         if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
#             log.info("Traffic Started successfully")
            
#         sleep(30)

#         """ Ethanalyzer_Mirrored_Leafs """

#         fail_flag = 0

#         Traffic_Leaf = json.loads(testscript.parameters['LEAF-1'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])))


#         if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
#             """ LEAF-1 Verification """
#             Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

#             match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

#             for i in range(len(match_vlan_1)):
#                 if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
#                     log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
#                 elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
#                     log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
#                 elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
#                     log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
#                     fail_flag = 1
#                 elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
#                     log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
#                     fail_flag = 1
#                 else:
#                     log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
#                     fail_flag = 1


#             Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

#             match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

#             for i in range(len(match_vni_1)):
#                 if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
#                     log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
#                 elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
#                     log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
#                 else:
#                     log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
#                     fail_flag = 1
#         else:
#             """ LEAF-2 Verification """
#             Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

#             match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

#             for i in range(len(match_vlan_2)):
#                 if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
#                     log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
#                 elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
#                     log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
#                 elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
#                     log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
#                     fail_flag = 1
#                 elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
#                     log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
#                     fail_flag = 1
#                 else:
#                     log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
#                     fail_flag = 1


#             Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

#             match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

#             for i in range(len(match_vni_2)):
#                 if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
#                     log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
#                 elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
#                     log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
#                 else:
#                     log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
#                     fail_flag = 1


#         """ LEAF-3 Verification """
#         Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

#         match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

#         for i in range(len(match_vlan_3)):
#             if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
#                 log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
#             elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
#                 log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
#             elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
#                 log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
#                 fail_flag = 1
#             elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
#                 log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
#                 fail_flag = 1
#             else:
#                 log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
#                 fail_flag = 1


#         Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

#         match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

#         for i in range(len(match_vni_3)):
#             if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
#                 log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
#             elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
#                 log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
#             else:
#                 log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
#                 fail_flag = 1


#         if fail_flag == 1:
#             self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
#         else:
#             self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")
    
#     @aetest.test
#     def Stop_SQinVNI_Traffic(self):
#         """ Stop_SQinVNI_Traffic """
#         if ixLib.stop_traffic() == 1:
#             log.info("Traffic Stopped successfully")

#     @aetest.test
#     def VERIFY_IXIA_TRAFFIC(self):
#         """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
#         time.sleep(20)

#         if ixLib.verify_traffic(2) == 0:
#             log.debug("Traffic Verification failed")
#             self.failed("Traffic Verification failed", goto=['next_tc'])
#         else:
#             log.info("Traffic Verification Passed")
#             self.passed("Traffic Verification Passed")

#     @aetest.cleanup
#     def cleanup(self):
#         """ testcase clean up """
#         log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#            
            
class TC017_VxLAN_SQinVNI_ConsistencyCheck(aetest.Testcase):
    """ TC017_VxLAN_SQinVNI_ConsistencyCheck """

    @aetest.test
    def VxLAN_CC(self, testscript):
        """ VxLAN_CC """

        fail_flag = 0

        VxLANCC = json.loads(testscript.parameters['LEAF-1'].execute('show consistency-checker vxlan config-check brief | no'))

        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("VxLAN Config-Check BRIEF CC Failed on LEAF-1")
            fail_flag = 1
        else:
            log.info("VxLAN Config-Check BRIEF CC Passed on LEAF-1")

        VxLANCC = json.loads(testscript.parameters['LEAF-2'].execute('show consistency-checker vxlan config-check brief | no'))

        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("VxLAN Config-Check BRIEF CC Failed on LEAF-2")
            fail_flag = 1
        else:
            log.info("VxLAN Config-Check BRIEF CC Passed on LEAF-2")

        VxLANCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan config-check brief | no'))

        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("VxLAN Config-Check BRIEF CC Failed on LEAF-3")
            fail_flag = 1
        else:
            log.info("VxLAN Config-Check BRIEF CC Passed on LEAF-3")

        VxLANCC = json.loads(testscript.parameters['LEAF-1'].execute('show consistency-checker vxlan infra brief | no'))

        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("VxLAN Infra BRIEF CC Failed on LEAF-1")
            fail_flag = 1
        else:
            log.info("VxLAN Infra BRIEF CC Passed on LEAF-1")

        VxLANCC = json.loads(testscript.parameters['LEAF-2'].execute('show consistency-checker vxlan infra brief | no'))

        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("VxLAN Infra BRIEF CC Failed on LEAF-2")
            fail_flag = 1
        else:
            log.info("VxLAN Infra BRIEF CC Passed on LEAF-2")

        VxLANCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan infra brief | no'))

        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("VxLAN Infra BRIEF CC Failed on LEAF-3")
            fail_flag = 1
        else:
            log.info("VxLAN Infra BRIEF CC Passed on LEAF-3")

        VxLANCC = json.loads(testscript.parameters['LEAF-1'].execute('show consistency-checker vxlan vlan all brief | no'))

        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("VxLAN VLAN ALL BRIEF CC Failed on LEAF-1")
            fail_flag = 1
        else:
            log.info("VxLAN VLAN ALL BRIEF CC Passed on LEAF-1")
    
        VxLANCC = json.loads(testscript.parameters['LEAF-2'].execute('show consistency-checker vxlan vlan all brief | no'))

        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("VxLAN VLAN ALL BRIEF CC Failed on LEAF-2")
            fail_flag = 1
        else:
            log.info("VxLAN VLAN ALL BRIEF CC Passed on LEAF-2")

        VxLANCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan vlan all brief | no'))

        if "CC_STATUS_NOT_OK" in VxLANCC['result']['status']:
            log.debug("VxLAN VLAN ALL BRIEF CC Failed on LEAF-3")
            fail_flag = 1
        else:
            log.info("VxLAN VLAN ALL BRIEF CC Passed on LEAF-3")

        VxLANCC = testscript.parameters['LEAF-1'].execute('show consistency-checker vxlan selective-qinvni | no')

        if "FAIL" in VxLANCC:
            log.debug("VxLAN SQinVNI CC Failed on LEAF-1")
            fail_flag = 1
        else:
            log.info("VxLAN SQinVNI CC Passed on LEAF-1")

        VxLANCC = testscript.parameters['LEAF-2'].execute('show consistency-checker vxlan selective-qinvni | no')

        if "FAIL" in VxLANCC:
            log.debug("VxLAN SQinVNI CC Failed on LEAF-2")
            fail_flag = 1
        else:
            log.info("VxLAN SQinVNI CC Passed on LEAF-2")

        VxLANCC = testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan selective-qinvni | no')

        if "FAIL" in VxLANCC:
            log.debug("VxLAN SQinVNI CC Failed on LEAF-3")
            fail_flag = 1
        else:
            log.info("VxLAN SQinVNI CC Passed on LEAF-3")

        VxLANCC = testscript.parameters['LEAF-1'].execute('show consistency-checker vxlan selective-qinvni interface po'+str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po'])+' | no')

        if "FAIL" in VxLANCC:
            log.debug("VxLAN SQinVNI vPC-PO Interface CC Failed on LEAF-1")
            fail_flag = 1
        else:
            log.info("VxLAN SQinVNI vPC-PO Interface CC Passed on LEAF-1")

        VxLANCC = testscript.parameters['LEAF-1'].execute('show consistency-checker vxlan selective-qinvni interface '+str(testscript.parameters['intf_LEAF_1_to_IXIA'])+' | no')

        if "FAIL" in VxLANCC:
            log.debug("VxLAN SQinVNI vPC-Orp Interface CC Failed on LEAF-1")
            fail_flag = 1
        else:
            log.info("VxLAN SQinVNI vPC-Orp Interface CC Passed on LEAF-1")

        VxLANCC = testscript.parameters['LEAF-2'].execute('show consistency-checker vxlan selective-qinvni interface po'+str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po'])+' | no')

        if "FAIL" in VxLANCC:
            log.debug("VxLAN SQinVNI vPC-PO Interface CC Failed on LEAF-2")
            fail_flag = 1
        else:
            log.info("VxLAN SQinVNI vPC-PO Interface CC Passed on LEAF-2")

        VxLANCC = testscript.parameters['LEAF-2'].execute('show consistency-checker vxlan selective-qinvni interface '+str(testscript.parameters['intf_LEAF_2_to_IXIA'])+' | no')

        if "FAIL" in VxLANCC:
            log.debug("VxLAN SQinVNI vPC-Orp Interface CC Failed on LEAF-2")
            fail_flag = 1
        else:
            log.info("VxLAN SQinVNI vPC-Orp Interface CC Passed on LEAF-2")

        VxLANCC = testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan selective-qinvni interface '+str(testscript.parameters['intf_LEAF_3_to_IXIA'])+' | no')

        if "FAIL" in VxLANCC:
            log.debug("VxLAN SQinVNI ACCESS Interface CC Failed on LEAF-3")
            fail_flag = 1
        else:
            log.info("VxLAN SQinVNI ACCESS Interface CC Passed on LEAF-3")

        if fail_flag == 1:
            self.failed(reason="VxLAN CC Failed on few or all LEAFs")
        else:
            self.passed(reason="VxLAN CC Passed on all LEAFs")

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
            
class TC018_VxLAN_SQinVNI_Toggle_System_dot1q_Tunnel_Transit(aetest.Testcase):
    """ TC018_VxLAN_SQinVNI_Toggle_System_dot1q_Tunnel_Transit """

    @aetest.test
    def Toggle_System_dot1q_Tunnel_Transit(self, testscript):
        """ Toggle_System_dot1q_Tunnel_Transit """

        testscript.parameters['LEAF-1'].configure('''no system dot1q-tunnel transit vlan 301-302''')

        testscript.parameters['LEAF-2'].configure('''no system dot1q-tunnel transit vlan 301-302''')

        sleep(30)

        testscript.parameters['LEAF-1'].configure('''system dot1q-tunnel transit vlan 301-302''')

        testscript.parameters['LEAF-2'].configure('''system dot1q-tunnel transit vlan 301-302''')

        sleep(150)

    @aetest.test
    def Start_SQinVNI_Traffic(self, testscript):
        """ Start_SQinVNI_Traffic """
        if ixLib.start_traffic([testscript.parameters['SQinVNI_v4_TI_1'],testscript.parameters['SQinVNI_v4_TI_2'],testscript.parameters['SQinVNI_v4_TI_3'],testscript.parameters['SQinVNI_v4_TI_4']]) == 1:
            log.info("Traffic Started successfully")
            
            sleep(30)

    @aetest.test
    def Ethanalyzer_Mirrored_Leafs(self, testscript):
        """ Ethanalyzer_Mirrored_Leafs """

        fail_flag = 0

        Traffic_Leaf = json.loads(testscript.parameters['LEAF-1'].execute('''show interface port-channel {} | json'''.format(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])))


        if 99 < int(Traffic_Leaf['TABLE_interface']['ROW_interface']['eth_inrate1_pkts']):
            """ LEAF-1 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_1 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_1)):
                if match_vlan_1[i] == str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_1_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-1''')
                elif match_vlan_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                elif match_vlan_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_1[i] + ''' Tag Found in LEAF-1!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-1'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_1 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_1)):
                if match_vni_1[i] == str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-1''')
                elif match_vni_1[i] == str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-1''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_1[i] + ''' is Found in LEAF-1!!''')
                    fail_flag = 1
        else:
            """ LEAF-2 Verification """
            Ethanalyzer_VLAN = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

            match_vlan_2 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

            for i in range(len(match_vlan_2)):
                if match_vlan_2[i] == str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']):
                    log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i]== str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10):
                    log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_12_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-2''')
                elif match_vlan_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']):
                    log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                elif match_vlan_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1):
                    log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-2!!''')
                    fail_flag = 1
                else:
                    log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_2[i] + ''' Tag Found in LEAF-2!!''')
                    fail_flag = 1


            Ethanalyzer_VNI = testscript.parameters['LEAF-2'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

            match_vni_2 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

            for i in range(len(match_vni_2)):
                if match_vni_2[i] == str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']):
                    log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-2''')
                elif match_vni_2[i] == str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1):
                    log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-2''')
                else:
                    log.debug('''!!Wrong L2VNI : ''' + match_vni_2[i] + ''' is Found in LEAF-2!!''')
                    fail_flag = 1


        """ LEAF-3 Verification """
        Ethanalyzer_VLAN = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "Virtual LAN"')

        match_vlan_3 = re.findall(r'ID:\s+(\d+)', Ethanalyzer_VLAN)

        for i in range(len(match_vlan_3)):
            if match_vlan_3[i] == str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']):
                log.info('''Customer VLAN : ''' + str(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10):
                log.info('''Customer VLAN : ''' + str(int(testscript.parameters['LEAF_3_TGEN_dict']['vlan_id_1']) + 10) + ''' is Found in LEAF-3''')
            elif match_vlan_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']):
                log.debug('''!!L2VNI VLAN : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            elif match_vlan_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1):
                log.debug('''!!L2VNI VLAN : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + ''' is Found in LEAF-3!!''')
                fail_flag = 1
            else:
                log.debug('''!!Wrong/NO Dot1Q : ''' + match_vlan_3[i] + ''' Tag Found in LEAF-3!!''')
                fail_flag = 1


        Ethanalyzer_VNI = testscript.parameters['LEAF-3'].execute('ethanalyzer local interface inband mirror detail | grep "VNI"')

        match_vni_3 = re.findall(r'Identifier\s+\(VNI\):\s+(\d+)', Ethanalyzer_VNI)

        for i in range(len(match_vni_3)):
            if match_vni_3[i] == str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']):
                log.info('''L2VNI : ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + ''' is Found in LEAD-3''')
            elif match_vni_3[i] == str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1):
                log.info('''L2VNI : ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 1) + ''' is Found in LEAD-3''')
            else:
                log.debug('''!!Wrong L2VNI : ''' + match_vni_3[i] + ''' is Found in LEAF-3!!''')
                fail_flag = 1

        if fail_flag == 1:
            self.failed(reason="Only Customer VLAN & L2 VNI is NOT Found on all LEAFs")
        else:
            self.passed(reason="Only Customer VLAN & L2 VNI is Found on all LEAFs")
            
    @aetest.test
    def Stop_SQinVNI_Traffic(self):
        """ Stop_SQinVNI_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

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

# class TC019_VxLAN_SQinVNI_ConfigReplace(aetest.Testcase):
#     """ TC019_VxLAN_SQinVNI_ConfigReplace """

#     @aetest.test
#     def Config_Replace(self, testscript):
#         """ Toggle_System_dot1q_Tunnel_Transit """

#         testscript.parameters['LEAF-1'].configure('''

#           delete bootflash:config_replace.cfg no-prompt

#           copy running-config bootflash:config_replace.cfg

#           no system dot1q-tunnel transit vlan 301-302

#           interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
#             no switchport access vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
#             switchport mode trunk

#           interface ''' + str(testscript.parameters['intf_LEAF_1_to_IXIA']) + '''
#             no switchport access vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
#             switchport mode trunk

#           configure replace bootflash:config_replace.cfg verbose

#               ''')

#         testscript.parameters['LEAF-2'].configure('''

#           delete bootflash:config_replace.cfg no-prompt

#           copy running-config bootflash:config_replace.cfg

#           no system dot1q-tunnel transit vlan 301-302

#           interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + '''
#             no switchport access vlan ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
#             switchport mode trunk

#           configure replace bootflash:config_replace.cfg verbose

#               ''')

#         testscript.parameters['LEAF-3'].configure('''

#           delete bootflash:config_replace.cfg no-prompt

#           copy running-config bootflash:config_replace.cfg

#           interface ''' + str(testscript.parameters['intf_LEAF_3_to_IXIA']) + '''
#             no switchport access vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
#             switchport mode trunk

#           configure replace bootflash:config_replace.cfg verbose

#               ''')

#         sleep(150)

#         brcmConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
#         brcmConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
#         brcmConfigReplace3 = testscript.parameters['LEAF-3'].execute('show config-replace log exec | i "Rollback Status"')
#         match1 = re.search(r'Rollback Status\s+\:\s+(Success)', brcmConfigReplace1)
#         match2 = re.search(r'Rollback Status\s+\:\s+(Success)', brcmConfigReplace2)
#         match3 = re.search(r'Rollback Status\s+\:\s+(Success)', brcmConfigReplace3)

#         sleep(60)

#         if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success':
#             self.passed(reason="Rollback Passed")
#         else:
#             self.failed(reason="Rollback Failed")

#     @aetest.test
#     def VERIFY_IXIA_TRAFFIC(self):
#         """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
#         time.sleep(20)

#         if ixLib.verify_traffic(2) == 0:
#             log.debug("Traffic Verification failed")
#             self.failed("Traffic Verification failed", goto=['next_tc'])
#         else:
#             log.info("Traffic Verification Passed")
#             self.passed("Traffic Verification Passed")

#     @aetest.cleanup
#     def cleanup(self):
#         """ testcase clean up """
#         log.info("Pass testcase cleanup")    

# *****************************************************************************************************************************#

class TC020_VxLAN_L2KUC_traffic_on_SQinVNI_Port(aetest.Testcase):
    """ TC020_VxLAN_L2KUC_traffic_on_SQinVNI_Port """

    @aetest.test
    def VxLAN_L2KUC_traffic_on_SQinVNI_Port(self, testscript):
        """ VxLAN_L2KUC_traffic_on_SQinVNI_Port with "system dot1q-tunnel transit vlan <vlan>" in vPC LEAFs """

        traffic_result = ixLib.verify_traffic({'traffic_item_list':[testscript.parameters['L2KUC_v4_TI_1'],testscript.parameters['L2KUC_v4_TI_2'],testscript.parameters['L2KUC_v4_TI_3'],
        testscript.parameters['L2KUC_v4_TI_4'],testscript.parameters['L2KUC_v6_TI_1'],testscript.parameters['L2KUC_v6_TI_2'],testscript.parameters['L2KUC_v6_TI_3'],testscript.parameters['L2KUC_v6_TI_4']]})

        if traffic_result['status'] == 1:
            log.info("Traffic Verification for L2KUC Passed : "+str(traffic_result)+"")
            self.passed("Traffic Verification for L2KUC Passed : "+str(traffic_result)+"")
        else:
            log.debug("Traffic Verification for L2KUC Failed : "+str(traffic_result)+"")
            self.failed("Traffic Verification for L2KUC Failed")

    @aetest.test
    def Stop_VxLAN_L2KUC_Traffic(self):
        """ Stop_VxLAN_L2KUC_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class TC021_VxLAN_L3KUC_traffic_on_SQinVNI_Port(aetest.Testcase):
    """ TC021_VxLAN_L3KUC_traffic_on_SQinVNI_Port """

    @aetest.test
    def VxLAN_L3KUC_traffic_on_SQinVNI_Port(self, testscript):
        """ VxLAN_L3KUC_traffic_on_SQinVNI_Port with "system dot1q-tunnel transit vlan <vlan>" in vPC LEAFs """

        traffic_result = ixLib.verify_traffic({'traffic_item_list':[testscript.parameters['L3KUC_v4_TI_1'],testscript.parameters['L3KUC_v4_TI_2'],testscript.parameters['L3KUC_v4_TI_3'],
        testscript.parameters['L3KUC_v4_TI_4'],testscript.parameters['L3KUC_v6_TI_1'],testscript.parameters['L3KUC_v6_TI_2'],testscript.parameters['L3KUC_v6_TI_3'],testscript.parameters['L3KUC_v6_TI_4']]})

        if traffic_result['status'] == 1:
            log.info("Traffic Verification for L3KUC Passed : "+str(traffic_result)+"")
            self.passed("Traffic Verification for L3KUC Passed : "+str(traffic_result)+"")
        else:
            log.debug("Traffic Verification for L3KUC Failed : "+str(traffic_result)+"")
            self.failed("Traffic Verification for L3KUC Failed")

    @aetest.test
    def Stop_VxLAN_L3KUC_Traffic(self):
        """ Stop_VxLAN_L3KUC_Traffic """
        if ixLib.stop_traffic() == 1:
            log.info("Traffic Stopped successfully")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class TC022_VxLAN_plus_SQinVNI_traffic_on_SQinVNI_Port(aetest.Testcase):
    """ TC022_VxLAN_plus_SQinVNI_traffic_on_SQinVNI_Port """

    @aetest.test
    def VxLAN_plus_SQinVNI_traffic_on_SQinVNI_Port(self, testscript):
        """ VxLAN_plus_SQinVNI_traffic_on_SQinVNI_Port with "system dot1q-tunnel transit vlan <vlan>" in vPC LEAFs """

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

class TC023_iCAM_Check(aetest.Testcase):
    """ TC023_iCAM_Check """

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

        testscript.parameters['LEAF-3'].configure('''

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

class TC024_FINAL_CC_CHECK(aetest.Testcase):
    """ TC024_FINAL_CC_CHECK """

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
            if status['status'] == 0:
                fail_flag.append(0)
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
