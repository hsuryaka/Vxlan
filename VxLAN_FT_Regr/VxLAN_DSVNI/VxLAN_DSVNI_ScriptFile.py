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
from VxLAN_PYlib import vxlanEVPN_FNL_lib

evpnLib = vxlanEVPN_FNL_lib.configure39KVxlanEvpn()
verifyEvpn = vxlanEVPN_FNL_lib.verifyEVPNconfiguration()

# ------------------------------------------------------
# Import and initialize IXIA specific libraries
# ------------------------------------------------------
from VxLAN_PYlib import ixiaPyats_lib

ixLib = ixiaPyats_lib.ixiaPyats_lib()

# ------------------------------------------------------
# Import and initialize INFRA specific libraries
# ------------------------------------------------------
from VxLAN_PYlib import infra_lib

infraTrig = infra_lib.infraTrigger()
infraEORTrig = infra_lib.infraEORTrigger()
infraConfig = infra_lib.infraConfigure()
infraVerify = infra_lib.infraVerify()


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
    else:
        return 0


###################################################################
###                  GLOBAL VARIABLES                           ###
###################################################################

device_list = []
post_test_process_dict = {}


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
    def connecting_to_devices(self, testscript, testbed, uut_list):
        """ common setup subsection: Connecting to devices """

        log.info(banner("Connecting to Devices"))
        global post_test_process_dict

        # =============================================================================================================================#
        # Grab the device object of the uut device with that name
        SPINE = testscript.parameters['SPINE'] = testbed.devices[uut_list['SPINE']]

        LEAF_1 = testscript.parameters['LEAF-1'] = testbed.devices[uut_list['LEAF-1']]
        LEAF_2 = testscript.parameters['LEAF-2'] = testbed.devices[uut_list['LEAF-2']]
        LEAF_3 = testscript.parameters['LEAF-3'] = testbed.devices[uut_list['LEAF-3']]

        FAN = testscript.parameters['FAN'] = testbed.devices[uut_list['ACCESS']]

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

    # *****************************************************************************************************************************#
    @aetest.subsection
    def set_script_flags(self, testscript, configurationFile, job_file_params):

        # =============================================================================================================================#
        # Import script_flags into testscript.parameters
        # Setting up the Post Test Check Parameters
        global post_test_process_dict
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

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

        # Flags to control pre-clean, config and EOR Trigger test-cases
        resn = "Skipped by the user via job file"
        log.info(resn)
        if testscript.parameters['script_flags']['skip_device_config']:
            aetest.skip.affix(section=DEVICE_BRINGUP_enable_feature_set, reason=resn)
            aetest.skip.affix(section=DEVICE_BRINGUP_configure_SPINE, reason=resn)
            aetest.skip.affix(section=DEVICE_BRINGUP_configure_LEAF_1_2, reason=resn)
            aetest.skip.affix(section=DEVICE_BRINGUP_configure_LEAF_3, reason=resn)
            aetest.skip.affix(section=DEVICE_BRINGUP_configure_FAN, reason=resn)
        if testscript.parameters['script_flags']['eor_cc_flag']:
            aetest.skip.affix(section=TC041_FINAL_CC_CHECK, reason=resn)
        if testscript.parameters['script_flags']['skip_eor_triggers']:
            aetest.skip.affix(section=TC042_vxlan_vpc_leaf1_LC_reload, reason=resn)
            aetest.skip.affix(section=TC043_vxlan_vpc_leaf2_LC_reload, reason=resn)
            aetest.skip.affix(section=TC044_vxlan_leaf3_LC_reload, reason=resn)
            aetest.skip.affix(section=TC045_vxlan_vpc_leaf1_FM_all_reload, reason=resn)
            aetest.skip.affix(section=TC046_vxlan_vpc_leaf2_FM_all_reload, reason=resn)
            aetest.skip.affix(section=TC047_vxlan_leaf3_FM_all_reload, reason=resn)
            aetest.skip.affix(section=TC048_vxlan_vpc_leaf1_SC_all_reload, reason=resn)
            aetest.skip.affix(section=TC049_vxlan_vpc_leaf2_SC_all_reload, reason=resn)
            aetest.skip.affix(section=TC050_vxlan_leaf3_SC_all_reload, reason=resn)
            aetest.skip.affix(section=TC051_vxlan_vpc_leaf1_SSO, reason=resn)
            aetest.skip.affix(section=TC052_vxlan_vpc_leaf2_SSO, reason=resn)
            aetest.skip.affix(section=TC053_vxlan_leaf3_SSO, reason=resn)        

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

        testscript.parameters['intf_LEAF_1_to_IXIA']    = LEAF_1.interfaces['LEAF_to_IXIA'].intf
        testscript.parameters['intf_LEAF_2_to_IXIA']    = LEAF_2.interfaces['LEAF_to_IXIA'].intf
        testscript.parameters['intf_LEAF_3_to_IXIA']    = LEAF_3.interfaces['LEAF_to_IXIA'].intf
        testscript.parameters['intf_FAN_to_IXIA']       = FAN.interfaces['FAN_to_IXIA'].intf

        testscript.parameters['intf_IXIA_to_FAN']       = IXIA.interfaces['IXIA_to_FAN'].intf
        testscript.parameters['intf_IXIA_to_LEAF_1']    = IXIA.interfaces['IXIA_to_LEAF-1'].intf
        testscript.parameters['intf_IXIA_to_LEAF_2']    = IXIA.interfaces['IXIA_to_LEAF-2'].intf
        testscript.parameters['intf_IXIA_to_LEAF_3']    = IXIA.interfaces['IXIA_to_LEAF-3'].intf

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
            featureSetConfigureLeafs_status = infraConfig.configureVerifyFeatureSet(leafLst, ['mpls'])
            if featureSetConfigureLeafs_status['result']:
                log.info("Passed Configuring feature Sets on all Leafs")
            else:
                log.debug("Failed Configuring feature Sets on all Leafs")
                configFeatureSet_msgs += featureSetConfigureLeafs_status['log']
                configFeatureSet_status.append(0)

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

        SPINE = testscript.parameters['SPINE']
        evpnLib.configureEVPNSpines([testscript.parameters['SPINE']], testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDictList'])

        try:
            for interf in SPINE.interfaces.keys():
                if "SPINE_to_LEAF" in interf:
                    log.info("Interface picked up is "+ str(SPINE.interfaces[interf].intf) +" and corresponding PO ID is "+ str(SPINE.interfaces[interf].PO))
                    SPINE.configure('''
                        interface ''' + str(SPINE.interfaces[interf].intf) + '''
                            channel-group ''' + str(SPINE.interfaces[interf].PO) + ''' force mode active
                            no shut
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

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        evpnLib.configureEVPNVPCLeafs(testscript.parameters['forwardingSysDict'],testscript.parameters['leafVPCDictData'])

        try:
            for interf in LEAF_1.interfaces.keys():
                if "LEAF_to_SPINE" in interf:
                    LEAF_1.configure('''
                        interface ''' + str(LEAF_1.interfaces[interf].intf) + '''
                            channel-group ''' + str(LEAF_1.interfaces[interf].PO) + ''' force mode active
                            no shut
                    ''')
                elif "LEAF_to_PEER_KEEP_ALIVE" in interf:
                    LEAF_1.configure('''
                        interface ''' + str(LEAF_1.interfaces[interf].intf) + '''
                            no switchport
                            vrf member ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['kp_al_vrf']) + '''
                            ip address ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['kp_al_ip']) + '''/24
                            no shutdown
                    ''')
                elif "LEAF_to_MCT" in interf:
                    LEAF_1.configure('''
                        interface ''' + str(LEAF_1.interfaces[interf].intf) + '''
                            channel-group ''' + str(LEAF_1.interfaces[interf].PO) + ''' force mode active
                            no shut
                    ''')
                elif "LEAF_to_FAN" in interf:
                    LEAF_1.configure('''
                        interface ''' + str(LEAF_1.interfaces[interf].intf) + '''
                            channel-group ''' + str(LEAF_1.interfaces[interf].PO) + ''' force mode active
                            no shut
                    ''')
                elif "LEAF_to_IXIA" in interf:
                    LEAF_1.configure('''
                        interface ''' + str(LEAF_1.interfaces[interf].intf) + '''
                            switchport
                            switchport mode trunk
                            spanning-tree port type edge trunk
                            no shutdown
                    ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-1', goto=['common_cleanup'])

        try:
            testscript.parameters['LEAF-1'].configure('''

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

                router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                  address-family l2vpn evpn
                    advertise-pip

                interface nve1
                  advertise virtual-rmac
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
            self.errored('Exception occurred while configuring on LEAF-1', goto=['common_cleanup'])

        try:
            for interf in LEAF_2.interfaces.keys():
                if "LEAF_to_SPINE" in interf:
                    LEAF_2.configure('''
                        interface ''' + str(LEAF_2.interfaces[interf].intf) + '''
                            channel-group ''' + str(LEAF_2.interfaces[interf].PO) + ''' force mode active
                            no shut
                    ''')
                elif "LEAF_to_PEER_KEEP_ALIVE" in interf:
                    LEAF_2.configure('''
                        interface ''' + str(LEAF_2.interfaces[interf].intf) + '''
                            no switchport
                            vrf member ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['kp_al_vrf']) + '''
                            ip address ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['kp_al_ip']) + '''/24
                            no shutdown
                    ''')
                elif "LEAF_to_MCT" in interf:
                    LEAF_2.configure('''
                        interface ''' + str(LEAF_2.interfaces[interf].intf) + '''
                            channel-group ''' + str(LEAF_2.interfaces[interf].PO) + ''' force mode active
                            no shut
                    ''')
                elif "LEAF_to_FAN" in interf:
                    LEAF_2.configure('''                 
                        interface ''' + str(LEAF_2.interfaces[interf].intf) + '''
                            channel-group ''' + str(LEAF_2.interfaces[interf].PO) + ''' force mode active
                            no shut
                    ''')
                elif "LEAF_to_IXIA" in interf:
                    LEAF_2.configure('''
                        interface ''' + str(LEAF_2.interfaces[interf].intf) + '''
                            switchport
                            switchport mode trunk
                            spanning-tree port type edge trunk
                            no shutdown
                    ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-2', goto=['common_cleanup'])

        try:
            testscript.parameters['LEAF-2'].configure('''

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

                router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                  address-family l2vpn evpn
                    advertise-pip

                interface nve1
                  advertise virtual-rmac
                  advertise virtual-rmac
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

class DEVICE_BRINGUP_configure_LEAF_3(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_LEAF_3(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-3 """

        LEAF_3 = testscript.parameters['LEAF-3']
        evpnLib.configureEVPNLeaf(testscript.parameters['LEAF-3'], testscript.parameters['forwardingSysDict'],testscript.parameters['LEAF_3_dict'])

        try:
            for interf in LEAF_3.interfaces.keys():
                if "LEAF_to_SPINE" in interf:
                    LEAF_3.configure('''
                        interface ''' + str(LEAF_3.interfaces[interf].intf) + '''
                            channel-group ''' + str(LEAF_3.interfaces[interf].PO) + ''' force mode active
                            no shut
                    ''')
                elif "LEAF_to_IXIA" in interf:
                    LEAF_3.configure('''
                        interface ''' + str(LEAF_3.interfaces[interf].intf) + '''
                            switchport
                            switchport mode trunk
                            spanning-tree port type edge trunk
                            no shutdown
                    ''')

        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-3', goto=['common_cleanup'])
        
        try:
            testscript.parameters['LEAF-3'].configure('''

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
        FAN = testscript.parameters['FAN']

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
            FAN.configure(fanOut_vlanConfiguration)
            FAN.configure('''
              interface port-channel200
                switchport
                switchport mode trunk
                no shutdown
            ''')
            
            for interf in FAN.interfaces.keys():
                if "FAN_to_LEAF" in interf:
                    FAN.configure('''
                        interface ''' + str(FAN.interfaces[interf].intf) + '''
                            channel-group ''' + str(FAN.interfaces[interf].PO) + ''' force mode active
                            no shut
                    ''')
                elif "FAN_to_IXIA" in interf:
                    FAN.configure('''
                        interface ''' + str(FAN.interfaces[interf].intf) + '''
                            switchport
                            switchport mode trunk
                            spanning-tree port type edge trunk
                            no shutdown
                    ''')

        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on FAN-1', goto=['common_cleanup'])

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
        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Save all configurations (copy r s) """

        log.info(banner("Performing Copy R S"))

        testscript.parameters['LEAF-1'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-3'].configure("copy r s", timeout=300)

        if not testscript.parameters['script_flags']['skip_device_config']:
            time.sleep(300)
        else:
            time.sleep(60)

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
            log.info(nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict'],
                                                  testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("WARNING : Failed to verify NVE VNI Data\n\n")
            log.info(nveVniData['log'])

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
        testscript.parameters['LEAF-3'].configure('''
            ip igmp snooping
            ip igmp snooping vxlan
        ''')
        testscript.parameters['FAN'].configure('''
            ip igmp snooping
            ip igmp snooping vxlan
        ''')

        forwardingSysDict = testscript.parameters['forwardingSysDict']

        vlan_id_start = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        total_vlans = int(forwardingSysDict['VRF_count']) * int(forwardingSysDict['VLAN_PER_VRF_count'])
        vlan_id_stop = int(vlan_id_start) + total_vlans

        testscript.parameters['LEAF-3'].configure('''
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
                         'vlan_id': P1_dict['vlan_id'],
                         'vlan_id_step': P1_dict['vlan_id_step']}

        P3_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP3']['dev_grp_hndl'],
                         'port_hndl': P3,
                         'no_of_ints': P3_dict['no_of_ints'],
                         'phy_mode': P3_dict['phy_mode'],
                         'mac': P3_dict['mac'],
                         'mac_step': P3_dict['mac_step'],
                         'protocol': P3_dict['protocol'],
                         'v4_addr': P3_dict['v4_addr'],
                         'v4_addr_step': P3_dict['v4_addr_step'],
                         'v4_gateway': P3_dict['v4_gateway'],
                         'v4_gateway_step': P3_dict['v4_gateway_step'],
                         'v4_netmask': P3_dict['v4_netmask'],
                         'v6_addr': P3_dict['v6_addr'],
                         'v6_addr_step': P3_dict['v6_addr_step'],
                         'v6_gateway': P3_dict['v6_gateway'],
                         'v6_gateway_step': P3_dict['v6_gateway_step'],
                         'v6_netmask': P3_dict['v6_netmask'],
                         'vlan_id': P1_dict['vlan_id'],
                         'vlan_id_step': P1_dict['vlan_id_step']}

        P4_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP4']['dev_grp_hndl'],
                         'port_hndl': P4,
                         'no_of_ints': P4_dict['no_of_ints'],
                         'phy_mode': P4_dict['phy_mode'],
                         'mac': P4_dict['mac'],
                         'mac_step': P4_dict['mac_step'],
                         'protocol': P4_dict['protocol'],
                         'v4_addr': P4_dict['v4_addr'],
                         'v4_addr_step': P4_dict['v4_addr_step'],
                         'v4_gateway': P4_dict['v4_gateway'],
                         'v4_gateway_step': P4_dict['v4_gateway_step'],
                         'v4_netmask': P4_dict['v4_netmask'],
                         'v6_addr': P4_dict['v6_addr'],
                         'v6_addr_step': P4_dict['v6_addr_step'],
                         'v6_gateway': P4_dict['v6_gateway'],
                         'v6_gateway_step': P4_dict['v6_gateway_step'],
                         'v6_netmask': P4_dict['v6_netmask'],
                         'vlan_id': P4_dict['vlan_id'],
                         'vlan_id_step': P4_dict['vlan_id_step']}

        P1_IX_int_data = ixLib.configure_multi_ixia_interface(P1_int_dict_1)
        P2_IX_int_data = ixLib.configure_multi_ixia_interface(P2_int_dict_1)
        P3_IX_int_data = ixLib.configure_multi_ixia_interface(P3_int_dict_1)
        P4_IX_int_data = ixLib.configure_multi_ixia_interface(P4_int_dict_1)

        log.info(P1_IX_int_data)
        log.info(P2_IX_int_data)
        log.info(P3_IX_int_data)
        log.info(P4_IX_int_data)

        if P1_IX_int_data == 0 or P2_IX_int_data == 0 or P3_IX_int_data == 0 or P4_IX_int_data == 0:
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

        testscript.parameters['IX_TP3']['eth_handle'] = P3_IX_int_data['eth_handle']
        testscript.parameters['IX_TP3']['ipv4_handle'] = P3_IX_int_data['ipv4_handle']
        testscript.parameters['IX_TP3']['ipv6_handle'] = P3_IX_int_data['ipv6_handle']
        testscript.parameters['IX_TP3']['topo_int_handle'] = P3_IX_int_data['topo_int_handle'].split(" ")

        testscript.parameters['IX_TP4']['eth_handle'] = P4_IX_int_data['eth_handle']
        testscript.parameters['IX_TP4']['ipv4_handle'] = P4_IX_int_data['ipv4_handle']
        testscript.parameters['IX_TP4']['ipv6_handle'] = P4_IX_int_data['ipv6_handle']
        testscript.parameters['IX_TP4']['topo_int_handle'] = P4_IX_int_data['topo_int_handle'].split(" ")

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

class IXIA_CONFIGURATION_CONFIGURE_IXIA_IGMP_GROUPS(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONFIGURE_IXIA_IGMP_GROUPS(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']

        P1_TGEN_dict = testscript.parameters['LEAF_12_TGEN_dict']
        P2_TGEN_dict = testscript.parameters['LEAF_1_TGEN_dict']
        P3_TGEN_dict = testscript.parameters['LEAF_2_TGEN_dict']
        P4_TGEN_dict = testscript.parameters['LEAF_3_TGEN_dict']

        IGMP_dict_1 = {'ipv4_hndl'                      : IX_TP1['ipv4_handle'],
                       'igmp_ver'                       : P1_TGEN_dict['igmp_ver'],
                       'mcast_grp_ip'                   : P1_TGEN_dict['mcast_grp_ip'],
                       'mcast_grp_ip_step'              : P1_TGEN_dict['mcast_grp_ip_step'],
                       'no_of_grps'                     : P1_TGEN_dict['no_of_grps'],
                       'mcast_src_ip'                   : P4_TGEN_dict['v4_addr'],
                       'mcast_src_ip_step'              : P1_TGEN_dict['v4_addr_step'],
                       'mcast_src_ip_step_per_port'     : P1_TGEN_dict['v4_addr_step'],
                       'mcast_grp_ip_step_per_port'     : P1_TGEN_dict['v4_addr_step'],
                       'mcast_no_of_srcs'               : P1_TGEN_dict['no_of_mcast_sources'],
                       'topology_handle'                : IX_TP1['topo_hndl']
                       }

        IGMP_dict_2 = {'ipv4_hndl'                      : IX_TP2['ipv4_handle'],
                       'igmp_ver'                       : P2_TGEN_dict['igmp_ver'],
                       'mcast_grp_ip'                   : P2_TGEN_dict['mcast_grp_ip'],
                       'mcast_grp_ip_step'              : P2_TGEN_dict['mcast_grp_ip_step'],
                       'no_of_grps'                     : P2_TGEN_dict['no_of_grps'],
                       'mcast_src_ip'                   : P4_TGEN_dict['v4_addr'],
                       'mcast_src_ip_step'              : P2_TGEN_dict['v4_addr_step'],
                       'mcast_src_ip_step_per_port'     : P2_TGEN_dict['v4_addr_step'],
                       'mcast_grp_ip_step_per_port'     : P2_TGEN_dict['v4_addr_step'],
                       'mcast_no_of_srcs'               : P2_TGEN_dict['no_of_mcast_sources'],
                       'topology_handle'                : IX_TP2['topo_hndl']
                       }

        IGMP_dict_3 = {'ipv4_hndl'                      : IX_TP3['ipv4_handle'],
                       'igmp_ver'                       : P3_TGEN_dict['igmp_ver'],
                       'mcast_grp_ip'                   : P3_TGEN_dict['mcast_grp_ip'],
                       'mcast_grp_ip_step'              : P3_TGEN_dict['mcast_grp_ip_step'],
                       'no_of_grps'                     : P3_TGEN_dict['no_of_grps'],
                       'mcast_src_ip'                   : P4_TGEN_dict['v4_addr'],
                       'mcast_src_ip_step'              : P3_TGEN_dict['v4_addr_step'],
                       'mcast_src_ip_step_per_port'     : P3_TGEN_dict['v4_addr_step'],
                       'mcast_grp_ip_step_per_port'     : P3_TGEN_dict['v4_addr_step'],
                       'mcast_no_of_srcs'               : P3_TGEN_dict['no_of_mcast_sources'],
                       'topology_handle'                : IX_TP3['topo_hndl']
                       }

        IGMP_EML_1 = ixLib.emulate_igmp_groupHost(IGMP_dict_1)
        IGMP_EML_2 = ixLib.emulate_igmp_groupHost(IGMP_dict_2)
        IGMP_EML_3 = ixLib.emulate_igmp_groupHost(IGMP_dict_3)
        # ForkedPdb().set_trace()

        if IGMP_EML_1 == 0 and IGMP_EML_2 == 0 and IGMP_EML_3 == 0:
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

        testscript.parameters['IX_TP2']['igmpHost_handle'] = []
        testscript.parameters['IX_TP2']['igmp_group_handle'] = []
        testscript.parameters['IX_TP2']['igmp_source_handle'] = []
        testscript.parameters['IX_TP2']['igmpMcastGrpList'] = []

        testscript.parameters['IX_TP2']['igmpHost_handle'].append(IGMP_EML_2['igmpHost_handle'])
        testscript.parameters['IX_TP2']['igmp_group_handle'].append(IGMP_EML_2['igmp_group_handle'])
        testscript.parameters['IX_TP2']['igmp_source_handle'].append(IGMP_EML_2['igmp_source_handle'])
        testscript.parameters['IX_TP2']['igmpMcastGrpList'].append(IGMP_EML_2['igmpMcastGrpList'])

        testscript.parameters['IX_TP3']['igmpHost_handle'] = []
        testscript.parameters['IX_TP3']['igmp_group_handle'] = []
        testscript.parameters['IX_TP3']['igmp_source_handle'] = []
        testscript.parameters['IX_TP3']['igmpMcastGrpList'] = []

        testscript.parameters['IX_TP3']['igmpHost_handle'].append(IGMP_EML_3['igmpHost_handle'])
        testscript.parameters['IX_TP3']['igmp_group_handle'].append(IGMP_EML_3['igmp_group_handle'])
        testscript.parameters['IX_TP3']['igmp_source_handle'].append(IGMP_EML_3['igmp_source_handle'])
        testscript.parameters['IX_TP3']['igmpMcastGrpList'].append(IGMP_EML_3['igmpMcastGrpList'])

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
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        P4_dict = testscript.parameters['LEAF_3_TGEN_dict']

        BCAST_SA_2_VPC_dict = {
                            'src_hndl'      : IX_TP4['port_handle'],
                            'dst_hndl'      : [IX_TP1['port_handle'],IX_TP2['port_handle'],IX_TP3['port_handle']],
                            'TI_name'       : "BCAST_SA_2_vPC",
                            'frame_size'    : "70",
                            'rate_pps'      : "1000",
                            'src_mac'       : "00:00:30:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "100",
                            'vlan_id'       : P4_dict['vlan_id'],
                            'vlanid_step'   : "1",
                            'vlanid_count'  : P4_dict['no_of_ints'],
                            'ip_src_addrs'  : "30.1.1.10",
                            'ip_step'       : "0.0.1.0",
                      }

        BCAST_SA_2_VPC_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_SA_2_VPC_dict)

        if BCAST_SA_2_VPC_TI == 0:
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
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        P4_dict = testscript.parameters['LEAF_3_TGEN_dict']

        UKNOWN_UCAST_SA_2_VPC_dict = {
                            'src_hndl'      : IX_TP4['port_handle'],
                            'dst_hndl'      : [IX_TP1['port_handle'],IX_TP2['port_handle'],IX_TP3['port_handle']],
                            'TI_name'       : "UKNOWN_UCAST_SA_2_VPC",
                            'frame_size'    : "64",
                            'rate_pps'      : "1000",
                            'dst_mac'       : "00:00:45:00:00:01",
                            'dstmac_step'   : "00:00:00:00:00:01",
                            'dstmac_count'  : "100",
                            'src_mac'       : "00:00:41:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "100",
                            'vlan_id'       : P4_dict['vlan_id'],
                            'vlanid_step'   : "1",
                            'vlanid_count'  : P4_dict['no_of_ints'],
                      }

        UKNOWN_UCAST_SA_2_VPC_TI = ixLib.configure_ixia_UNKNOWN_UCAST_traffic_item(UKNOWN_UCAST_SA_2_VPC_dict)

        if UKNOWN_UCAST_SA_2_VPC_TI == 0:
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
        IX_TP3 = testscript.parameters['IX_TP3']
        IX_TP4 = testscript.parameters['IX_TP4']

        forwardingSysDict = testscript.parameters['forwardingSysDict']
        total_vlans = int(forwardingSysDict['VRF_count']) * int(forwardingSysDict['VLAN_PER_VRF_count'])

        # Creating TAGs for SRC IP Handles
        TAG_dict = {'subject_handle': IX_TP4['ipv4_handle'],
                    'topo_handle': IX_TP4['topo_hndl'],
                    'TAG_count_per_item': str(total_vlans)
                    }

        SRC_IP_TAG = ixLib.configure_tag_config_multiplier(TAG_dict)
        if SRC_IP_TAG == 0:
            log.debug("Configuring TAGS for SRC IP failed")

        # Creating TAGs for DST IP Handles
        TAG_dict = {'subject_handle': IX_TP2['ipv4_handle'],
                    'topo_handle': IX_TP2['topo_hndl'],
                    'TAG_count_per_item': str(total_vlans)
                    }

        DST_IP_TAG_VPC = ixLib.configure_tag_config_multiplier(TAG_dict)
        if DST_IP_TAG_VPC == 0:
            log.debug("Configuring TAGS for DST IP failed")

        # Creating TAGs for IGMP Host Handles
        TAG_dict = {'subject_handle': IX_TP2['igmp_group_handle'],
                    'topo_handle': IX_TP2['topo_hndl'],
                    'TAG_count_per_item': str(total_vlans)
                    }

        IGMP_Host_TAG_VPC = ixLib.configure_tag_config_multiplier(TAG_dict)
        if IGMP_Host_TAG_VPC == 0:
            log.debug("Configuring TAGS for IGMP Hosts failed")

        # Creating TAGs for DST IP Handles
        TAG_dict = {'subject_handle': IX_TP1['ipv4_handle'],
                    'topo_handle': IX_TP1['topo_hndl'],
                    'TAG_count_per_item': str(total_vlans)
                    }

        DST_IP_TAG_ORPH = ixLib.configure_tag_config_multiplier(TAG_dict)
        if DST_IP_TAG_ORPH == 0:
            log.debug("Configuring TAGS for DST IP failed")

        # Creating TAGs for IGMP Host Handles
        TAG_dict = {'subject_handle': IX_TP1['igmp_group_handle'],
                    'topo_handle': IX_TP1['topo_hndl'],
                    'TAG_count_per_item': str(total_vlans)
                    }

        IGMP_Host_TAG_ORPH = ixLib.configure_tag_config_multiplier(TAG_dict)
        if IGMP_Host_TAG_ORPH == 0:
            log.debug("Configuring TAGS for IGMP Hosts failed")

        # Creating TAGs for DST IP Handles
        TAG_dict = {'subject_handle': IX_TP3['ipv4_handle'],
                    'topo_handle': IX_TP3['topo_hndl'],
                    'TAG_count_per_item': str(total_vlans)
                    }

        DST_IP_TAG_ORPH_2 = ixLib.configure_tag_config_multiplier(TAG_dict)
        if DST_IP_TAG_ORPH_2 == 0:
            log.debug("Configuring TAGS for DST IP failed")

        # Creating TAGs for IGMP Host Handles
        TAG_dict = {'subject_handle': IX_TP3['igmp_group_handle'],
                    'topo_handle': IX_TP3['topo_hndl'],
                    'TAG_count_per_item': str(total_vlans)
                    }

        IGMP_Host_TAG_ORPH_2 = ixLib.configure_tag_config_multiplier(TAG_dict)
        if IGMP_Host_TAG_ORPH_2 == 0:
            log.debug("Configuring TAGS for IGMP Hosts failed")

        MCAST_dict = {'src_ipv4_topo_handle': IX_TP4['topo_hndl'],
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
            IX_TP3 = testscript.parameters['IX_TP3']
            IX_TP4 = testscript.parameters['IX_TP4']

            L2KUC_v4_dict_1 = {'src_hndl'   : IX_TP1['ipv4_handle'],
                                'dst_hndl'  : IX_TP4['ipv4_handle'],
                                'circuit'   : 'ipv4',
                                'TI_name'   : "L2KUC_TP1_TP4_V4",
                                'rate_pps'  : "100000",
                                'bi_dir'    : 1
                                }

            L2KUC_v4_dict_2 = {'src_hndl'   : IX_TP2['ipv4_handle'],
                                'dst_hndl'  : IX_TP4['ipv4_handle'],
                                'circuit'   : 'ipv4',
                                'TI_name'   : "L2KUC_TP2_TP4_V4",
                                'rate_pps'  : "100000",
                                'bi_dir'    : 1
                                }

            L2KUC_v4_dict_3 = {'src_hndl'   : IX_TP3['ipv4_handle'],
                                'dst_hndl'  : IX_TP4['ipv4_handle'],
                                'circuit'   : 'ipv4',
                                'TI_name'   : "L2KUC_TP3_TP4_V4",
                                'rate_pps'  : "100000",
                                'bi_dir'    : 1
                                }

            L2KUC_v6_dict_1 = {'src_hndl'   : IX_TP1['ipv6_handle'],
                                'dst_hndl'  : IX_TP4['ipv6_handle'],
                                'circuit'   : 'ipv6',
                                'TI_name'   : "L2KUC_TP1_TP4_V6",
                                'rate_pps'  : "100000",
                                'bi_dir'    : 1
                                }

            L2KUC_v6_dict_2 = {'src_hndl'   : IX_TP2['ipv6_handle'],
                                'dst_hndl'  : IX_TP4['ipv6_handle'],
                                'circuit'   : 'ipv6',
                                'TI_name'   : "L2KUC_TP2_TP4_V6",
                                'rate_pps'  : "100000",
                                'bi_dir'    : 1
                                }

            L2KUC_v6_dict_3 = {'src_hndl'   : IX_TP3['ipv6_handle'],
                                'dst_hndl'  : IX_TP4['ipv6_handle'],
                                'circuit'   : 'ipv6',
                                'TI_name'   : "L2KUC_TP3_TP4_V6",
                                'rate_pps'  : "100000",
                                'bi_dir'    : 1
                                }

            L2KUC_v4_TI_1 = ixLib.configure_ixia_traffic_item(L2KUC_v4_dict_1)
            L2KUC_v4_TI_2 = ixLib.configure_ixia_traffic_item(L2KUC_v4_dict_2)
            L2KUC_v4_TI_3 = ixLib.configure_ixia_traffic_item(L2KUC_v4_dict_3)
            L2KUC_v6_TI_1 = ixLib.configure_ixia_traffic_item(L2KUC_v6_dict_1)
            L2KUC_v6_TI_2 = ixLib.configure_ixia_traffic_item(L2KUC_v6_dict_2)
            L2KUC_v6_TI_3 = ixLib.configure_ixia_traffic_item(L2KUC_v6_dict_3)

            if L2KUC_v4_TI_1 == 0 or L2KUC_v4_TI_2 == 0 or L2KUC_v4_TI_3 == 0 or L2KUC_v6_TI_1 == 0 or L2KUC_v6_TI_2 == 0 or L2KUC_v6_TI_3 == 0:
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
            vlan_per_vrf = int(testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count'])

            L3KUC_v4_dict_1 = {'src_hndl'               : IX_TP4['ipv4_handle'],
                                'dst_hndl'              : IX_TP2['ipv4_handle'],
                                'circuit'               : 'ipv4',
                                'TI_name'               : "L3KUC_TP4_TP2_V4",
                                'rate_pps'              : "100000",
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

            L3KUC_v4_dict_2 = {'src_hndl'               : IX_TP1['ipv4_handle'],
                                'dst_hndl'              : IX_TP4['ipv4_handle'],
                                'circuit'               : 'ipv4',
                                'TI_name'               : "L3KUC_TP1_TP4_V4",
                                'rate_pps'              : "100000",
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

            L3KUC_v4_dict_3 = {'src_hndl'               : IX_TP4['ipv4_handle'],
                                'dst_hndl'              : IX_TP3['ipv4_handle'],
                                'circuit'               : 'ipv4',
                                'TI_name'               : "L3KUC_TP4_TP3_V4",
                                'rate_pps'              : "100000",
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

            L3KUC_v6_dict_1 = {'src_hndl'               : IX_TP2['ipv6_handle'],
                                'dst_hndl'              : IX_TP4['ipv6_handle'],
                                'circuit'               : 'ipv6',
                                'TI_name'               : "L3KUC_TP2_TP4_V6",
                                'rate_pps'              : "100000",
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

            L3KUC_v6_dict_2 = {'src_hndl'               : IX_TP1['ipv6_handle'],
                                'dst_hndl'              : IX_TP4['ipv6_handle'],
                                'circuit'               : 'ipv6',
                                'TI_name'               : "L3KUC_TP1_TP4_V6",
                                'rate_pps'              : "100000",
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

            L3KUC_v6_dict_3 = {'src_hndl'               : IX_TP4['ipv6_handle'],
                                'dst_hndl'              : IX_TP3['ipv6_handle'],
                                'circuit'               : 'ipv6',
                                'TI_name'               : "L3KUC_TP4_TP3_V6",
                                'rate_pps'              : "100000",
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

            L3KUC_v4_TI_1 = ixLib.configure_ixia_traffic_item(L3KUC_v4_dict_1)
            L3KUC_v4_TI_2 = ixLib.configure_ixia_traffic_item(L3KUC_v4_dict_2)
            L3KUC_v4_TI_3 = ixLib.configure_ixia_traffic_item(L3KUC_v4_dict_3)
            L3KUC_v6_TI_1 = ixLib.configure_ixia_traffic_item(L3KUC_v6_dict_1)
            L3KUC_v6_TI_2 = ixLib.configure_ixia_traffic_item(L3KUC_v6_dict_2)
            L3KUC_v6_TI_3 = ixLib.configure_ixia_traffic_item(L3KUC_v6_dict_3)

            if L3KUC_v4_TI_1 == 0 or L3KUC_v4_TI_2 == 0 or L3KUC_v4_TI_3 == 0 or L3KUC_v6_TI_1 == 0 or L3KUC_v6_TI_2 == 0 or L3KUC_v6_TI_3 == 0:
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

class TRAFFIC_VERIFICATION(aetest.Testcase):
    """IXIA_TRAFFIC_VERIFICATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(3) == 0:
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

class TC001_VERIFY_NETWORK_POST_TRAFFIC_PRE_ISSU(aetest.Testcase):
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
            log.info("WARNING : Failed to verify NVE VNI Data\n\n")
            log.info(nveVniData['log'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class TC002_VERIFY_VNI_TO_EGR_VNI_MAP(aetest.Testcase):
    """VERIFY_VNI_EGR_VNI_MAP"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def verify_vni_to_egr_vni_map(self, testscript):
        """ VERIFY_VNI_EGR_VNI_MAP subsection: Verify VNI to Egress VNI Mapping """

        fail_flag = []
        status_msgs = '\n'
        
        LEAF_3 = testscript.parameters['LEAF-3']

        l2vni_1 = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']
        l2vni_3 = str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 2)
        l3vni_1 = testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vni_start']

        l2_vni_1 = json.loads(testscript.parameters['LEAF-3'].execute('''sh nve peers control-plane-vni vni ''' + str(l2vni_1) + ''' | json'''))

        l2_vni_2 = json.loads(testscript.parameters['LEAF-3'].execute("sh nve peers control-plane-vni vni 40018 | json"))

        l2_vni_3 = json.loads(testscript.parameters['LEAF-3'].execute('''sh nve peers control-plane-vni vni ''' + str(l2vni_3) + ''' | json'''))

        l2_vni_4 = json.loads(testscript.parameters['LEAF-3'].execute('''sh nve peers control-plane-vni vni 40020 | json'''))

        l3_vni_1 = json.loads(testscript.parameters['LEAF-3'].execute('''sh nve peers control-plane-vni vni ''' + str(l3vni_1) + ''' | json'''))

        l3_vni_2 = json.loads(testscript.parameters['LEAF-3'].execute('''sh nve peers control-plane-vni vni 40038 | json'''))

        if type(l2_vni_1['TABLE_nve_peers']['ROW_nve_peers']) is list:
            dsvni_counter = 0
            for item in l2_vni_1['TABLE_nve_peers']['ROW_nve_peers']:
                if "egress-vni" in item.keys():
                    local_vni_1 = item['vni']
                    egress_vni_1 = item['egress-vni']
                    dsvni_counter = 1
                    if local_vni_1 == egress_vni_1:
                        log.info("PASS : L2VNI '" + str(local_vni_1) + "' and '" + str(egress_vni_1) + "' is Mapping Correctly\n\n")
                        status_msgs += "PASS : L2VNI '" + str(local_vni_1) + "' and '" + str(egress_vni_1) + "' is Mapping Correctly\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_vni_1) + "' and '" + str(egress_vni_1) + "' is NOT Mapping\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_vni_1) + "' and '" + str(egress_vni_1) + "' is NOT Mapping\n\n"
                        fail_flag.append(0)
            if dsvni_counter == 0:
                log.debug("FAIL : Did not find any DSVNI Mapping\n\n")
                status_msgs+="FAIL : Did not find any DSVNI Mapping\n\n"
                fail_flag.append(0)
        else:
            local_vni_1 = l2_vni_1['TABLE_nve_peers']['ROW_nve_peers']['vni']
            egress_vni_1 = l2_vni_1['TABLE_nve_peers']['ROW_nve_peers']['egress-vni']

            if local_vni_1 == egress_vni_1:
                log.info("PASS : L2VNI '" + str(local_vni_1) + "' and '" + str(egress_vni_1) + "' is Mapping Correctly\n\n")
                status_msgs += "PASS : L2VNI '" + str(local_vni_1) + "' and '" + str(egress_vni_1) + "' is Mapping Correctly\n\n"
            else:
                log.debug("FAIL : L2VNI '" + str(local_vni_1) + "' and '" + str(egress_vni_1) + "' is NOT Mapping\n\n")
                status_msgs+="FAIL : L2VNI '" + str(local_vni_1) + "' and '" + str(egress_vni_1) + "' is NOT Mapping\n\n"
                fail_flag.append(0)

        if type(l2_vni_2['TABLE_nve_peers']['ROW_nve_peers']) is list:
            dsvni_counter = 0
            for item in l2_vni_2['TABLE_nve_peers']['ROW_nve_peers']:
                if "egress-vni" in item.keys():
                    local_vni_2 = item['vni']
                    egress_vni_2 = item['egress-vni']
                    dsvni_counter = 1
                    if local_vni_2 != egress_vni_2:
                        log.info("PASS : L2VNI '" + str(local_vni_2) + "' and '" + str(egress_vni_2) + "' is Mapping to Correct DSVNI\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_vni_2) + "' and '" + str(egress_vni_2) + "' is Mapping to Correct DSVNI\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_vni_2) + "' and '" + str(egress_vni_2) + "' is NOT Mapping to Correct DSVNI\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_vni_2) + "' and '" + str(egress_vni_2) + "' is NOT Mapping to Correct DSVNI\n\n"
                        fail_flag.append(0)
            if dsvni_counter == 0:
                log.debug("FAIL : Did not find any DSVNI Mapping\n\n")
                status_msgs+="FAIL : Did not find any DSVNI Mapping\n\n"
                fail_flag.append(0)
        else:
            local_vni_2 = l2_vni_2['TABLE_nve_peers']['ROW_nve_peers']['vni']
            egress_vni_2 = l2_vni_2['TABLE_nve_peers']['ROW_nve_peers']['egress-vni']

            if local_vni_2 != egress_vni_2:
                log.info("PASS : L2VNI '" + str(local_vni_2) + "' and '" + str(egress_vni_2) + "' is Mapping to Correct DSVNI\n\n")
                status_msgs+="PASS : L2VNI '" + str(local_vni_2) + "' and '" + str(egress_vni_2) + "' is Mapping to Correct DSVNI\n\n"
            else:
                log.debug("FAIL : L2VNI '" + str(local_vni_2) + "' and '" + str(egress_vni_2) + "' is NOT Mapping to Correct DSVNI\n\n")
                status_msgs+="FAIL : L2VNI '" + str(local_vni_2) + "' and '" + str(egress_vni_2) + "' is NOT Mapping to Correct DSVNI\n\n"
                fail_flag.append(0)

        if type(l2_vni_3['TABLE_nve_peers']['ROW_nve_peers']) is list:
            dsvni_counter = 0
            for item in l2_vni_3['TABLE_nve_peers']['ROW_nve_peers']:
                if "egress-vni" in item.keys():
                    local_vni_3 = item['vni']
                    egress_vni_3 = item['egress-vni']
                    dsvni_counter = 1
                    if local_vni_3 == egress_vni_3:
                        log.info("PASS : L2VNI '" + str(local_vni_3) + "' and '" + str(egress_vni_3) + "' is Mapping Correctly\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_vni_3) + "' and '" + str(egress_vni_3) + "' is Mapping Correctly\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_vni_3) + "' and '" + str(egress_vni_3) + "' is NOT Mapping\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_vni_3) + "' and '" + str(egress_vni_3) + "' is NOT Mapping\n\n"
                        fail_flag.append(0)
            if dsvni_counter == 0:
                log.debug("FAIL : Did not find any DSVNI Mapping\n\n")
                status_msgs+="FAIL : Did not find any DSVNI Mapping\n\n"
                fail_flag.append(0)
        else:
            local_vni_3 = l2_vni_3['TABLE_nve_peers']['ROW_nve_peers']['vni']
            egress_vni_3 = l2_vni_3['TABLE_nve_peers']['ROW_nve_peers']['egress-vni']

            if local_vni_3 == egress_vni_3:
                log.info("PASS : L2VNI '" + str(local_vni_3) + "' and '" + str(egress_vni_3) + "' is Mapping Correctly\n\n")
                status_msgs+="PASS : L2VNI '" + str(local_vni_3) + "' and '" + str(egress_vni_3) + "' is Mapping Correctly\n\n"
            else:
                log.debug("FAIL : L2VNI '" + str(local_vni_3) + "' and '" + str(egress_vni_3) + "' is NOT Mapping\n\n")
                status_msgs+="FAIL : L2VNI '" + str(local_vni_3) + "' and '" + str(egress_vni_3) + "' is NOT Mapping\n\n"
                fail_flag.append(0)

        if type(l2_vni_4['TABLE_nve_peers']['ROW_nve_peers']) is list:
            dsvni_counter = 0
            for item in l2_vni_4['TABLE_nve_peers']['ROW_nve_peers']:
                if "egress-vni" in item.keys():
                    local_vni_4 = item['vni']
                    egress_vni_4 = item['egress-vni']
                    dsvni_counter = 1
                    if local_vni_4 != egress_vni_4:
                        log.info("PASS : L2VNI '" + str(local_vni_4) + "' and '" + str(egress_vni_4) + "' is Mapping to Correct DSVNI\n\n")
                        status_msgs+="PASS : L2VNI '" + str(local_vni_4) + "' and '" + str(egress_vni_4) + "' is Mapping to Correct DSVNI\n\n"
                    else:
                        log.debug("FAIL : L2VNI '" + str(local_vni_4) + "' and '" + str(egress_vni_4) + "' is NOT Mapping to Correct DSVNI\n\n")
                        status_msgs+="FAIL : L2VNI '" + str(local_vni_4) + "' and '" + str(egress_vni_4) + "' is NOT Mapping to Correct DSVNI\n\n"
                        fail_flag.append(0)
            if dsvni_counter == 0:
                log.debug("FAIL : Did not find any DSVNI Mapping\n\n")
                status_msgs+="FAIL : Did not find any DSVNI Mapping\n\n"
                fail_flag.append(0)
        else:
            local_vni_4 = l2_vni_4['TABLE_nve_peers']['ROW_nve_peers']['vni']
            egress_vni_4 = l2_vni_4['TABLE_nve_peers']['ROW_nve_peers']['egress-vni']

            if local_vni_4 != egress_vni_4:
                log.info("PASS : L2VNI '" + str(local_vni_4) + "' and '" + str(egress_vni_4) + "' is Mapping to Correct DSVNI\n\n")
                status_msgs+="PASS : L2VNI '" + str(local_vni_4) + "' and '" + str(egress_vni_4) + "' is Mapping to Correct DSVNI\n\n"
            else:
                log.debug("FAIL : L2VNI '" + str(local_vni_4) + "' and '" + str(egress_vni_4) + "' is NOT Mapping to Correct DSVNI\n\n")
                status_msgs+="FAIL : L2VNI '" + str(local_vni_4) + "' and '" + str(egress_vni_4) + "' is NOT Mapping to Correct DSVNI\n\n"
                fail_flag.append(0)

        peerip_1 = testscript.parameters['LEAF_1_dict']['NVE_data']['VTEP_IP']
        peerip_2 = testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP']

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
                    local_l3vni_11 = item['vni']
                    egress_l3vni_11 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l3vni_11 != egress_l3vni_11:
                        log.info("PASS : L3VNI '" + str(local_l3vni_11) + "' and '" + str(egress_l3vni_11) + "' is Mapping to Correct DSVNI\n\n")
                        status_msgs+="PASS : L3VNI '" + str(local_l3vni_11) + "' and '" + str(egress_l3vni_11) + "' is Mapping to Correct DSVNI\n\n"
                    else:
                        log.debug("FAIL : L3VNI '" + str(local_l3vni_11) + "' and '" + str(egress_l3vni_11) + "' is NOT Mapping to Correct DSVNI\n\n")
                        status_msgs+="FAIL : L3VNI '" + str(local_l3vni_11) + "' and '" + str(egress_l3vni_11) + "' is NOT Mapping to Correct DSVNI\n\n"
                        fail_flag.append(0)
                elif item['peer-ip'] == peerip_2:
                    local_l3vni_11 = item['vni']
                    egress_l3vni_11 = item['egress-vni']
                    dsvni_counter.append(1)
                    if local_l3vni_11 != egress_l3vni_11:
                        log.info("PASS : L3VNI '" + str(local_l3vni_11) + "' and '" + str(egress_l3vni_11) + "' is Mapping to Correct DSVNI\n\n")
                        status_msgs+="PASS : L3VNI '" + str(local_l3vni_11) + "' and '" + str(egress_l3vni_11) + "' is Mapping to Correct DSVNI\n\n"
                    else:
                        log.debug("FAIL : L3VNI '" + str(local_l3vni_11) + "' and '" + str(egress_l3vni_11) + "' is NOT Mapping to Correct DSVNI\n\n")
                        status_msgs+="FAIL : L3VNI '" + str(local_l3vni_11) + "' and '" + str(egress_l3vni_11) + "' is NOT Mapping to Correct DSVNI\n\n"
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

        sleep(10)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

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

class TC003_VERIFY_VLAN_DSVNI(aetest.Testcase):
    """VERIFY_VLAN_DSVNI"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def verify_vlan_dsvni(self, testscript):
        """ VERIFY_VLAN_DSVNI subsection: Verify VLAN Flood-List is DSVNI or NOT """

        fail_flag=[]
        status_msgs=''
        
        LEAF_3 = testscript.parameters['LEAF-3']

        vlan_1 = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']
        vlan_2 = str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'] + 1))
        vlan_3 = str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'] + 2))
        vlan_4 = str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'] + 3))

        vlan_dsvni_1 = testscript.parameters['LEAF-3'].execute('''show forwarding internal nve vlan-floodlist ''' + str(vlan_1) + ''' | grep DSVNI''')

        vlan_dsvni_2 = testscript.parameters['LEAF-3'].execute('''show forwarding internal nve vlan-floodlist ''' + str(vlan_2) + ''' | grep DSVNI''')

        vlan_dsvni_3 = testscript.parameters['LEAF-3'].execute('''show forwarding internal nve vlan-floodlist ''' + str(vlan_3) + ''' | grep DSVNI''')

        vlan_dsvni_4 = testscript.parameters['LEAF-3'].execute('''show forwarding internal nve vlan-floodlist ''' + str(vlan_4) + ''' | grep DSVNI''')

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
        
        sleep(10)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

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

class TC004_VERIFY_NextHop_DSVNI(aetest.Testcase):
    """VERIFY_NextHop_DSVNI"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def VERIFY_NextHop_DSVNI(self, testscript):
        """ VERIFY_NextHop_DSVNI subsection: Verify Next Hop DSVNI or VNI """

        fail_flag=[]
        status_msgs=''
        
        LEAF_3 = testscript.parameters['LEAF-3']

        ip_addr_11 = '2.1.3.10/32'
        ip_addr_12 = '2.1.3.20/32'
        ip_addr_13 = '2.1.3.30/32'
        mod_num = '1'

        if testscript.parameters['script_flags']['eor_cc_flag']:
            
            # This is EOR chassis get the active SUP ID
            modules = json.loads(LEAF_3.execute('show mod | json'))['TABLE_modinfo']['ROW_modinfo']
            for mod in modules:
                if 'Supervisor' in mod['modtype'] and 'status' in mod['status']:
                    mod_num = str(mod['modinf'])

        dsvni_11 = json.loads(testscript.parameters['LEAF-3'].execute('''sh forwarding route ''' + ip_addr_11 + ''' vrf EVPN-VRF-38 mod ''' + mod_num + ''' | json'''))

        dsvni_12 = json.loads(testscript.parameters['LEAF-3'].execute('''sh forwarding route ''' + ip_addr_12 + ''' vrf EVPN-VRF-38 mod ''' + mod_num + ''' | json'''))

        dsvni_13 = json.loads(testscript.parameters['LEAF-3'].execute('''sh forwarding route ''' + ip_addr_13 + ''' vrf EVPN-VRF-38 mod ''' + mod_num + ''' | json'''))

        dsvni_true_11 = dsvni_11['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']
        dsvni_true_12 = dsvni_12['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']
        dsvni_true_13 = dsvni_13['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']

        if "dsvni" in dsvni_true_11['DownStream']:
            log.info("PASS : Host Route Next Hop is DSVNI : '" + dsvni_true_11['VNI'] + "'\n\n")
            status_msgs+="PASS : Host Route Next Hop is DSVNI : '" + dsvni_true_11['VNI'] + "'\n\n"
        else:
            log.debug("FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_true_11['VNI'] + "'\n\n")
            status_msgs+="FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_true_11['VNI'] + "'\n\n"
            fail_flag.append(0)

        if "dsvni" in dsvni_true_12['DownStream']:
            log.info("PASS : Host Route Next Hop is DSVNI : '" + dsvni_true_12['VNI'] + "'\n\n")
            status_msgs+="PASS : Host Route Next Hop is DSVNI : '" + dsvni_true_12['VNI'] + "'\n\n"
        else:
            log.debug("FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_true_12['VNI'] + "'\n\n")
            status_msgs+="FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_true_12['VNI'] + "'\n\n"
            fail_flag.append(0)

        if "dsvni" in dsvni_true_13['DownStream']:
            log.info("PASS : Host Route Next Hop is DSVNI : '" + dsvni_true_13['VNI'] + "'\n\n")
            status_msgs+="PASS : Host Route Next Hop is DSVNI : '" + dsvni_true_13['VNI'] + "'\n\n"
        else:
            log.debug("FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_true_13['VNI'] + "'\n\n")
            status_msgs+="FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_true_13['VNI'] + "'\n\n"
            fail_flag.append(0)

        ip_addr_21 = '2.1.4.10/32'
        ip_addr_22 = '2.1.4.20/32'
        ip_addr_23 = '2.1.4.30/32'


        dsvni_21 = json.loads(testscript.parameters['LEAF-3'].execute('''sh forwarding route ''' + ip_addr_21 + ''' vrf EVPN-VRF-38 mod ''' + mod_num + ''' | json'''))

        dsvni_22 = json.loads(testscript.parameters['LEAF-3'].execute('''sh forwarding route ''' + ip_addr_22 + ''' vrf EVPN-VRF-38 mod ''' + mod_num + ''' | json'''))

        dsvni_23 = json.loads(testscript.parameters['LEAF-3'].execute('''sh forwarding route ''' + ip_addr_23 + ''' vrf EVPN-VRF-38 mod ''' + mod_num + ''' | json'''))

        dsvni_true_21 = dsvni_21['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']
        dsvni_true_22 = dsvni_22['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']
        dsvni_true_23 = dsvni_23['TABLE_module']['ROW_module']['TABLE_vrf']['ROW_vrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']

        if "dsvni" in dsvni_true_21['DownStream']:
            log.info("PASS : Host Route Next Hop is DSVNI : '" + dsvni_true_21['VNI'] + "'\n\n")
            status_msgs+="PASS : Host Route Next Hop is DSVNI : '" + dsvni_true_21['VNI'] + "'\n\n"
        else:
            log.debug("FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_true_21['VNI'] + "'\n\n")
            status_msgs+="FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_true_21['VNI'] + "'\n\n"
            fail_flag.append(0)

        if "dsvni" in dsvni_true_22['DownStream']:
            log.info("PASS : Host Route Next Hop is DSVNI : '" + dsvni_true_22['VNI'] + "'\n\n")
            status_msgs+="PASS : Host Route Next Hop is DSVNI : '" + dsvni_true_22['VNI'] + "'\n\n"
        else:
            log.debug("FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_true_22['VNI'] + "'\n\n")
            status_msgs+="FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_true_22['VNI'] + "'\n\n"
            fail_flag.append(0)

        if "dsvni" in dsvni_true_23['DownStream']:
            log.info("PASS : Host Route Next Hop is DSVNI : '" + dsvni_true_23['VNI'] + "'\n\n")
            status_msgs+="PASS : Host Route Next Hop is DSVNI : '" + dsvni_true_23['VNI'] + "'\n\n"
        else:
            log.debug("FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_true_23['VNI'] + "'\n\n")
            status_msgs+="FAIL : Host Route Next Hop is NOT DSVNI : '" + dsvni_true_23['VNI'] + "'\n\n"
            fail_flag.append(0)

        sleep(10)

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

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

class TC005_VERIFY_Symmetric_Route(aetest.Testcase):
    """VERIFY_Symmetric_Route"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def VERIFY_Symmetric_Route(self, testscript):
        """ VERIFY_Symmetric_Route subsection: Verify Symmetric Route """

        fail_flag=[]
        status_msgs=''
        
        LEAF_3 = testscript.parameters['LEAF-3']

        ip_addr_11 = '2.1.1.10/32'
        ip_addr_12 = '2.1.1.20/32'
        ip_addr_13 = '2.1.1.30/32'


        sym_rt_11 = testscript.parameters['LEAF-3'].execute('''show ip route ''' + ip_addr_11 + ''' vrf EVPN-VRF-37''')

        sym_rt_12 = testscript.parameters['LEAF-3'].execute('''show ip route ''' + ip_addr_12 + ''' vrf EVPN-VRF-37''')

        sym_rt_13 = testscript.parameters['LEAF-3'].execute('''show ip route ''' + ip_addr_13 + ''' vrf EVPN-VRF-37''')

        if "Asymmetric" not in sym_rt_11:
            log.info("PASS : Host Route '" + ip_addr_11 + "' is Symmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_11 + "' is Symmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_11 + "' is NOT Symmetric\n\n")
            status_msgs+="FAIL : Host Route '" + ip_addr_11 + "' is NOT Symmetric\n\n"
            fail_flag.append(0)

        if "Asymmetric" not in sym_rt_12:
            log.info("PASS : Host Route '" + ip_addr_12 + "' is Symmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_12 + "' is Symmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_12 + "' is NOT Symmetric\n\n")
            status_msgs+="FAIL : Host Route '" + ip_addr_12 + "' is NOT Symmetric\n\n"
            fail_flag.append(0)

        if "Asymmetric" not in sym_rt_13:
            log.info("PASS : Host Route '" + ip_addr_13 + "' is Symmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_13 + "' is Symmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_13 + "' is NOT Symmetric\n\n")
            status_msgs+="FAIL : Host Route '" + ip_addr_13 + "' is NOT Symmetric\n\n"
            fail_flag.append(0)

        ip_addr_21 = '2.1.2.10/32'
        ip_addr_22 = '2.1.2.20/32'
        ip_addr_23 = '2.1.2.30/32'

        sym_rt_21 = testscript.parameters['LEAF-3'].execute('''show ip route ''' + ip_addr_21 + ''' vrf EVPN-VRF-37''')

        sym_rt_22 = testscript.parameters['LEAF-3'].execute('''show ip route ''' + ip_addr_22 + ''' vrf EVPN-VRF-37''')

        sym_rt_23 = testscript.parameters['LEAF-3'].execute('''show ip route ''' + ip_addr_23 + ''' vrf EVPN-VRF-37''')

        if "Asymmetric" not in sym_rt_21:
            log.info("PASS : Host Route '" + ip_addr_21 + "' is Symmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_21 + "' is Symmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_21 + "' is NOT Symmetric\n\n")
            status_msgs+="FAIL : Host Route '" + ip_addr_21 + "' is NOT Symmetric\n\n"
            fail_flag.append(0)

        if "Asymmetric" not in sym_rt_22:
            log.info("PASS : Host Route '" + ip_addr_22 + "' is Symmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_22 + "' is Symmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_22 + "' is NOT Symmetric\n\n")
            status_msgs+="FAIL : Host Route '" + ip_addr_22 + "' is NOT Symmetric\n\n"
            fail_flag.append(0)

        if "Asymmetric" not in sym_rt_23:
            log.info("PASS : Host Route '" + ip_addr_23 + "' is Symmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_23 + "' is Symmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_23 + "' is NOT Symmetric\n\n")
            status_msgs+="FAIL : Host Route '" + ip_addr_23 + "' is NOT Symmetric\n\n"
            fail_flag.append(0)

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

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

class TC006_VERIFY_Asymmetric_Route(aetest.Testcase):
    """VERIFY_Asymmetric_Route"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def VERIFY_Asymmetric_Route(self, testscript):
        """ VERIFY_Asymmetric_Route subsection: Verify Asymmetric Route """

        fail_flag=[]
        status_msgs=''
        
        LEAF_3 = testscript.parameters['LEAF-3']

        ip_addr_11 = '2.1.3.10/32'
        ip_addr_12 = '2.1.3.20/32'
        ip_addr_13 = '2.1.3.30/32'

        sym_rt_11 = testscript.parameters['LEAF-3'].execute('''show ip route ''' + ip_addr_11 + ''' vrf EVPN-VRF-38''')

        sym_rt_12 = testscript.parameters['LEAF-3'].execute('''show ip route ''' + ip_addr_12 + ''' vrf EVPN-VRF-38''')

        sym_rt_13 = testscript.parameters['LEAF-3'].execute('''show ip route ''' + ip_addr_13 + ''' vrf EVPN-VRF-38''')

        if "Asymmetric" in sym_rt_11:
            log.info("PASS : Host Route '" + ip_addr_11 + "' is Asymmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_11 + "' is Asymmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_11 + "' is NOT Asymmetric\n\n")
            status_msgs+="FAIL : Host Route '" + ip_addr_11 + "' is NOT Asymmetric\n\n"
            fail_flag.append(0)

        if "Asymmetric" in sym_rt_12:
            log.info("PASS : Host Route '" + ip_addr_12 + "' is Asymmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_12 + "' is Asymmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_12 + "' is NOT Asymmetric\n\n")
            status_msgs+="FAIL : Host Route '" + ip_addr_12 + "' is NOT Asymmetric\n\n"
            fail_flag.append(0)

        if "Asymmetric" in sym_rt_13:
            log.info("PASS : Host Route '" + ip_addr_13 + "' is Asymmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_13 + "' is Asymmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_13 + "' is NOT Asymmetric\n\n")
            status_msgs+="FAIL : Host Route '" + ip_addr_13 + "' is NOT Asymmetric\n\n"
            fail_flag.append(0)

        ip_addr_21 = '2.1.4.10/32'
        ip_addr_22 = '2.1.4.20/32'
        ip_addr_23 = '2.1.4.30/32'

        sym_rt_21 = testscript.parameters['LEAF-3'].execute('''show ip route ''' + ip_addr_21 + ''' vrf EVPN-VRF-38''')

        sym_rt_22 = testscript.parameters['LEAF-3'].execute('''show ip route ''' + ip_addr_22 + ''' vrf EVPN-VRF-38''')

        sym_rt_23 = testscript.parameters['LEAF-3'].execute('''show ip route ''' + ip_addr_23 + ''' vrf EVPN-VRF-38''')

        if "Asymmetric" in sym_rt_21:
            log.info("PASS : Host Route '" + ip_addr_21 + "' is Asymmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_21 + "' is Asymmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_21 + "' is NOT Asymmetric\n\n")
            status_msgs+="FAIL : Host Route '" + ip_addr_21 + "' is NOT Asymmetric\n\n"
            fail_flag.append(0)

        if "Asymmetric" in sym_rt_22:
            log.info("PASS : Host Route '" + ip_addr_22 + "' is Asymmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_22 + "' is Asymmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_22 + "' is NOT Asymmetric\n\n")
            status_msgs+="FAIL : Host Route '" + ip_addr_22 + "' is NOT Asymmetric\n\n"
            fail_flag.append(0)

        if "Asymmetric" in sym_rt_23:
            log.info("PASS : Host Route '" + ip_addr_23 + "' is Asymmetric\n\n")
            status_msgs+="PASS : Host Route '" + ip_addr_23 + "' is Asymmetric\n\n"
        else:
            log.debug("FAIL : Host Route '" + ip_addr_23 + "' is NOT Asymmetric\n\n")
            status_msgs+="FAIL : Host Route '" + ip_addr_23 + "' is NOT Asymmetric\n\n"
            fail_flag.append(0)

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        time.sleep(20)

        if ixLib.verify_traffic(3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

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

class TC007_Switch_from_Asym_L2VNI_with_SymL2L3VNI(aetest.Testcase):
    """ Switch_from_Asym_L2VNI_with_SymL2L3VNI """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Switch_from_Asym_L2VNI_on_LEAF_3(self, testscript):
        """ Switch from Asym L2VNI subsection: Switching from Asym L2VNI to Sym L2VNI on LEAF-3 """

        testscript.parameters['LEAF-3'].configure('''

          vlan 18
            no vn-segment 40018
            vn-segment 10018

          interface nve1
            no member vni 40018
            member vni 10018
              ingress-replication protocol bgp

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

        if ixLib.verify_traffic(3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def SwitchBack_to_Asym_L2VNI_on_LEAF_3(self, testscript):
        """ SwitchBack to Asym L2VNI subsection: Switching Back to Asym L2VNI from Sym L2VNI on LEAF-3 """

        testscript.parameters['LEAF-3'].configure('''

          vlan 18
            no vn-segment 10018
            vn-segment 40018

          interface nve1
            no member vni 10018
            member vni 40018
              ingress-replication protocol bgp

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

        if ixLib.verify_traffic(3) == 0:
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

class TC008_Switch_from_Asym_L2VNI_with_AsymL2L3VNI(aetest.Testcase):
    """ Switch_from_Asym_L2VNI_with_AsymL2L3VNI """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Switch_from_Asym_L2VNI_on_LEAF_3(self, testscript):
        """ Switch from Asym L2VNI subsection: Switching from Asym L2VNI to Sym L2VNI on LEAF-3 """

        testscript.parameters['LEAF-3'].configure('''

          vlan 20
            no vn-segment 40020
            vn-segment 10020

          interface nve1
            no member vni 40020
            member vni 10020
              ingress-replication protocol bgp

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

        if ixLib.verify_traffic(3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def SwitchBack_to_Asym_L2VNI_on_LEAF_3(self, testscript):
        """ SwitchBack to Asym L2VNI subsection: Switching Back to Asym L2VNI from Sym L2VNI on LEAF-3 """

        testscript.parameters['LEAF-3'].configure('''

          vlan 20
            no vn-segment 10020
            vn-segment 40020

          interface nve1
            no member vni 10020
            member vni 40020
              ingress-replication protocol bgp

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

        if ixLib.verify_traffic(3) == 0:
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

class TC009_Switch_from_Asym_L3VNI_with_SymL2VNI(aetest.Testcase):
    """ Switch_from_Asym_L3VNI_with_SymL2VNI """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Switch_from_Asym_L3VNI_on_LEAF_3(self, testscript):
        """ Switch from Asym L3VNI subsection: Switching from Asym L3VNI to Sym L3VNI on LEAF-3 """

        testscript.parameters['LEAF-3'].configure('''

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

        if ixLib.verify_traffic(3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def SwitchBack_Asym_L3VNI_on_LEAF_3(self, testscript):
        """ SwitchBack to Asym L3VNI subsection: Switching Back to Asym L3VNI from Sym L3VNI on LEAF-3 """

        testscript.parameters['LEAF-3'].configure('''

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

        if ixLib.verify_traffic(3) == 0:
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

class TC010Switch_from_Asym_L3VNI_with_AsymL2VNI(aetest.Testcase):
    """ Switch_from_Asym_L3VNI_with_AsymL2VNI """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Switch_from_Asym_L3VNI_on_LEAF_3(self, testscript):
        """ Switch from Asym L3VNI subsection: Switching from Asym L3VNI to Sym L3VNI on LEAF-3 """

        testscript.parameters['LEAF-3'].configure('''

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

        if ixLib.verify_traffic(3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['next_tc'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def SwitchBack_Asym_L3VNI_on_LEAF_3(self, testscript):
        """ SwitchBack to Asym L3VNI subsection: Switching Back to Asym L3VNI from Sym L3VNI on LEAF-3 """

        testscript.parameters['LEAF-3'].configure('''

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

        if ixLib.verify_traffic(3) == 0:
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

class TC011_Switch_RD_Auto_to_Manual(aetest.Testcase):
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

        testscript.parameters['LEAF-3'].configure('''

              vrf context EVPN-VRF-38
                rd 3:3

      ''')

        testscript.parameters['LEAF-1'].configure('''

                restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

      ''')

        testscript.parameters['LEAF-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['LEAF-3'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

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

        if ixLib.verify_traffic(3) == 0:
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

        testscript.parameters['LEAF-3'].configure('''

              vrf context EVPN-VRF-38
                no rd 3:3
                rd auto

      ''')

        testscript.parameters['LEAF-1'].configure('''

                restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

      ''')

        testscript.parameters['LEAF-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['LEAF-3'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

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

        if ixLib.verify_traffic(3) == 0:
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

class TC012_Switch_RT_Auto_to_Manual(aetest.Testcase):
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

        testscript.parameters['LEAF-3'].configure('''

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

                restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

      ''')

        testscript.parameters['LEAF-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['LEAF-3'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

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

        if ixLib.verify_traffic(3) == 0:
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

        testscript.parameters['LEAF-3'].configure('''

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

                restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

      ''')

        testscript.parameters['LEAF-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['LEAF-3'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

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

        if ixLib.verify_traffic(3) == 0:
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

class TC013_Switch_RT_Auto_to_Manual_Under_EVPN(aetest.Testcase):
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

        testscript.parameters['LEAF-3'].configure('''

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

                restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

      ''')

        testscript.parameters['LEAF-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['LEAF-3'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

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

        if ixLib.verify_traffic(3) == 0:
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

        testscript.parameters['LEAF-3'].configure('''

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

                restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

      ''')

        testscript.parameters['LEAF-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

        ''')

        testscript.parameters['LEAF-3'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''

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

        if ixLib.verify_traffic(3) == 0:
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

class TC014_Remove_Add_L2VNI_VLAN(aetest.Testcase):
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

        testscript.parameters['LEAF-3'].configure('''

                no vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + '''
                no vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                no vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                no vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 3) + '''

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
                    vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                    vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                    vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 3) + '''
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

        testscript.parameters['LEAF-3'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                    vn-segment 40018
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                    vn-segment ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                    vn-segment 40020
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

        if ixLib.verify_traffic(3) == 0:
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

class TC015_Remove_Add_L3VNI_VLAN(aetest.Testcase):
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

        testscript.parameters['LEAF-3'].configure('''

                no vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']) + '''
                no vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']) + 1) + '''

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
                    vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vni_start']) + 1) + '''
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

        testscript.parameters['LEAF-3'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
                    vn-segment 40038
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

        if ixLib.verify_traffic(3) == 0:
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

class TC016_Remove_Add_L2VNI_VN_Segment(aetest.Testcase):
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
                    no vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                    no vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                    no vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 3) + '''
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

        testscript.parameters['LEAF-3'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + '''
                    no vn-segment ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                    no vn-segment 40018
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                    no vn-segment ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                    no vn-segment 40020
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
                    vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                    vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                    vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 3) + '''
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

        testscript.parameters['LEAF-3'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
                    vn-segment 40018
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
                    vn-segment ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 2) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
                    vn-segment 40020
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

        if ixLib.verify_traffic(3) == 0:
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

class TC017_Remove_Add_L3VNI_VN_Segment(aetest.Testcase):
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
                    no vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vni_start']) + 1) + '''
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

        testscript.parameters['LEAF-3'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']) + '''
                    no vn-segment ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
                    no vn-segment 40038
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
                    vn-segment ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vni_start']) + 1) + '''
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

        testscript.parameters['LEAF-3'].configure('''

                  vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vni_start']) + '''
                    exit
                  vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
                    vn-segment 40038
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

        if ixLib.verify_traffic(3) == 0:
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

class TC018_Remove_Add_L2VNI_SVI(aetest.Testcase):
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

        testscript.parameters['LEAF-3'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          no interface vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + '''
          no interface vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
          no interface vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
          no interface vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 3) + '''

              ''')

        sleep(30)

        testscript.parameters['LEAF-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-3'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['LEAF-3'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)

        sleep(10)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success':
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

        if ixLib.verify_traffic(3) == 0:
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

class TC019_Remove_Add_L3VNI_SVI(aetest.Testcase):
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

        testscript.parameters['LEAF-3'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          no interface vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']) + '''
          no interface vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']) + 1) + '''

              ''')

        sleep(30)

        testscript.parameters['LEAF-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-3'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['LEAF-3'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)

        sleep(10)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success':
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

        if ixLib.verify_traffic(3) == 0:
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

class TC020_Remove_Add_L2VNI_Under_NVE(aetest.Testcase):
    """ Remove_Add_L2VNI_Under_NVE """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_Add_L2VNI_Under_NVE_on_All(self, testscript):
        """ Remove_Add_L2VNI_Under_NVE_on_All """

        testscript.parameters['LEAF-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no member vni ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + '''
            no member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + '''
            no member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
            no member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 3) + '''

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

        testscript.parameters['LEAF-3'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no member vni ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + '''
            no member vni 40018
            no member vni ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + 2) + '''
            no member vni 40020

              ''')

        sleep(30)

        testscript.parameters['LEAF-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-3'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['LEAF-3'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)

        sleep(10)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success':
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

        if ixLib.verify_traffic(3) == 0:
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

class TC021_Remove_Add_L3VNI_Under_NVE(aetest.Testcase):
    """ Remove_Add_L3VNI_Under_NVE """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_Add_L3VNI_Under_NVE_on_All(self, testscript):
        """ Remove_Add_L3VNI_Under_NVE_on_All """

        testscript.parameters['LEAF-1'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no member vni ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vni_start']) + '''
            no member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vni_start']) + 1) + '''

              ''')

        testscript.parameters['LEAF-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no member vni ''' + str(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vni_start']) + '''
            no member vni ''' + str(int(testscript.parameters['LEAF_2_dict']['VNI_data']['l3_vni_start']) + 1) + '''

              ''')

        testscript.parameters['LEAF-3'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            no member vni ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vni_start']) + '''
            no member vni 40038

              ''')

        sleep(30)

        testscript.parameters['LEAF-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-3'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['LEAF-3'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)

        sleep(10)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success':
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

        if ixLib.verify_traffic(3) == 0:
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

class TC022_Remove_Add_NVE_Interface(aetest.Testcase):
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

        testscript.parameters['LEAF-3'].configure('''

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

        testscript.parameters['LEAF-3'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['LEAF-3'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)

        sleep(10)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success':
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

        if ixLib.verify_traffic(3) == 0:
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

class TC023_Remove_Add_NVE_Host_Reach_Proto(aetest.Testcase):
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

        testscript.parameters['LEAF-3'].configure('''

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

        testscript.parameters['LEAF-3'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['LEAF-3'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)

        sleep(10)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success':
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

        if ixLib.verify_traffic(3) == 0:
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

class TC024_Remove_Add_NVE_Src_Interface(aetest.Testcase):
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

        testscript.parameters['LEAF-3'].configure('''

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

        testscript.parameters['LEAF-3'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['LEAF-3'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)

        sleep(10)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success':
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

        if ixLib.verify_traffic(3) == 0:
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

class TC025_Remove_Add_NVE_IR_Under_L2VNI_Members(aetest.Testcase):
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
            member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + '''
              no ingress-replication protocol bgp
            member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
              no ingress-replication protocol bgp
            member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 3) + '''
              no ingress-replication protocol bgp

              ''')

        testscript.parameters['LEAF-2'].configure('''

          delete bootflash:config_replace.cfg no-prompt

          copy running-config bootflash:config_replace.cfg

          interface nve1
            member vni ''' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + '''
              no ingress-replication protocol bgp
            member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 1) + '''
              no ingress-replication protocol bgp
            member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 2) + '''
              no ingress-replication protocol bgp
            member vni ''' + str(int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']) + 3) + '''
              no ingress-replication protocol bgp

              ''')

        testscript.parameters['LEAF-3'].configure('''

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

        sleep(30)

        testscript.parameters['LEAF-1'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        testscript.parameters['LEAF-3'].configure('''

                  configure replace bootflash:config_replace.cfg verbose

              ''')

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['LEAF-3'].execute('show config-replace log exec | i "Rollback Status"')

        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)

        sleep(10)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success':
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

        if ixLib.verify_traffic(3) == 0:
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

class TC026_Remove_Add_PIP_VIP(aetest.Testcase):
    """ Remove_PIP_VIP """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_PIP_VIP(self, testscript):
        """ Remove_PIP_VIP """

        testscript.parameters['LEAF-1'].configure('''

              interface nve 1
                no advertise virtual-rmac

              router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                address-family l2vpn evpn
                no advertise-pip

              ''')

        testscript.parameters['LEAF-2'].configure('''

              interface nve 1
                no advertise virtual-rmac

              router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                address-family l2vpn evpn
                no advertise-pip

              ''')

        sleep(60)

    @aetest.test
    def ReAdd_PIP_VIP(self, testscript):
        """ ReAdd_PIP_VIP """

        testscript.parameters['LEAF-1'].configure('''

              interface nve 1
                advertise virtual-rmac

              router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                address-family l2vpn evpn
                advertise-pip

              ''')

        testscript.parameters['LEAF-2'].configure('''

              interface nve 1
                advertise virtual-rmac

              router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                address-family l2vpn evpn
                advertise-pip

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

        if ixLib.verify_traffic(3) == 0:
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

class TC027_L2VNI_SVI_Link_Flap(aetest.Testcase):
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

        testscript.parameters['LEAF-3'].configure('''

          interface vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
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

        testscript.parameters['LEAF-3'].configure('''

          interface vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 1) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 2) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + 3) + '''
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

        if ixLib.verify_traffic(3) == 0:
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

class TC028_L3VNI_SVI_Link_Flap(aetest.Testcase):
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

        testscript.parameters['LEAF-3'].configure('''

          interface vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']) + '''
            shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
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

        testscript.parameters['LEAF-3'].configure('''

          interface vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']) + '''
            no shutdown
          interface vlan ''' + str(int(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']) + 1) + '''
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

        if ixLib.verify_traffic(3) == 0:
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

class TC029_SA_NVE_Flap(aetest.Testcase):
    """ SA_NVE_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def SA_NVE_Flap(self, testscript):
        """ SA_NVE_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface nve 1
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

        if ixLib.verify_traffic(3) == 0:
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

class TC030_vPC_NVE_Flap(aetest.Testcase):
    """ vPC_NVE_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

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

        if ixLib.verify_traffic(3) == 0:
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

class TC031_SA_UP_Link_Flap(aetest.Testcase):
    """ SA_UP_Link_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def SA_UP_Link_Flap(self, testscript):
        """ SA_UP_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface port-channel ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
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

        if ixLib.verify_traffic(3) == 0:
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

class TC032_vPC_UP_Link_Flap(aetest.Testcase):
    """ vPC_UP_Link_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

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

        if ixLib.verify_traffic(3) == 0:
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

class TC033_SA_Access_Link_Flap(aetest.Testcase):
    """ SA_Access_Link_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def SA_Access_Link_Flap(self, testscript):
        """ SA_Access_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_IXIA']) + '''
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

        if ixLib.verify_traffic(3) == 0:
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

class TC034_vPC_Access_Link_Flap(aetest.Testcase):
    """ vPC_Access_Link_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

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

        if ixLib.verify_traffic(3) == 0:
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

class TC035_Verify_NVE_PEERS(aetest.Testcase):
    """ Verify_NVE_PEERS """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_NVE_PEERS(self, testscript):
        """ Verify_NVE_PEERS """

        XML_Peer_IP = testscript.parameters['LEAF-3'].execute('''show nve peers | grep peer-ip | xml''')

        NVE_PEERS = json.loads(testscript.parameters['LEAF-3'].execute('''show nve peers | json'''))

        peer_ip_address_1 = str(testscript.parameters['LEAF_1_dict']['NVE_data']['VTEP_IP'])
        peer_ip_address_2 = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])
        peer_vip = str(testscript.parameters['LEAF_1_dict']['NVE_data']['VPC_VTEP_IP'])

        if peer_ip_address_1 in XML_Peer_IP:
            Peer_State_1 = Peer_State(NVE_PEERS, peer_ip_address_1)
            if Peer_State_1 == "Up":
                log.info("PASS : vPC1 PIP is Present & UP\n\n")
        else:
            log.debug("FAIL : vPC1 PIP is NOT Present\n\n")

        if peer_ip_address_2 in XML_Peer_IP:
            Peer_State_2 = Peer_State(NVE_PEERS, peer_ip_address_1)
            if Peer_State_2 == "Up":
                log.info("PASS : vPC2 PIP is Present & UP\n\n")
                self.passed(reason="vPC1 & vPC2 PIP is Present & UP")
        elif peer_vip in XML_Peer_IP:
            self.failed(reason="VIP is ONLY Present")
        else:
            self.failed(reason="Both PIP & VIP is NOT Present")

        sleep(10)

    @aetest.cleanup
    def cleanup(self):
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#

class TC036_SA_Loopback_Flap(aetest.Testcase):
    """ SA_Loopback_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def SA_Loopback_Flap(self, testscript):
        """ SA_Loopback_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['LEAF_3_dict']['NVE_data']['src_loop']) + '''
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

        if ixLib.verify_traffic(3) == 0:
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

class TC037_vPC_Loopback_Flap(aetest.Testcase):
    """ vPC_Loopback_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

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

        if ixLib.verify_traffic(3) == 0:
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

class TC038_Remove_Add_BGP_Configs(aetest.Testcase):
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

        if ixLib.verify_traffic(3) == 0:
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

class TC039_iCAM_Check(aetest.Testcase):
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

              ''', timeout=600)

        testscript.parameters['LEAF-2'].configure('''

          icam monitor scale

          show icam system | no-more

          show icam scale | no-more

          show icam scale vxlan | no-more

          show icam health | no-more

          show icam prediction scale vxlan 2030 Jan 01 01:01:01

              ''', timeout=600)

        testscript.parameters['LEAF-3'].configure('''

          icam monitor scale

          show icam system | no-more

          show icam scale | no-more

          show icam scale vxlan | no-more

          show icam health | no-more

          show icam prediction scale vxlan 2030 Jan 01 01:01:01

              ''', timeout=600)

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#

class TC040_Config_Replace(aetest.Testcase):
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
                vni 10018 l2
                  no route-target import 703:18
                  no route-target export 703:18
                vni 10020 l2
                  no route-target import 803:20
                  no route-target export 803:20

          configure replace bootflash:config_replace.cfg verbose

              ''', timeout=600)

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

              ''', timeout=600)

        testscript.parameters['LEAF-3'].configure('''

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

              ''', timeout=600)

        sleep(10)

        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace3 = testscript.parameters['LEAF-3'].execute('show config-replace log exec | i "Rollback Status"')
        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)
        match3 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace3)

        sleep(60)

        if match1[1] == 'Success' and match2[1] == 'Success' and match3[1] == 'Success':
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

        if ixLib.verify_traffic(3) == 0:
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

class TC041_FINAL_CC_CHECK(aetest.Testcase):
    """ FINAL_CC_CHECK """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONSISTENCY_CHECK(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        fail_flag = []
        status_msgs = '\n'

        for dut in post_test_process_dict['dut_list']:
            status = infraVerify.verifyBasicVxLANCC({'dut' : dut})
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
class TC042_vxlan_vpc_leaf1_LC_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf1LCReload(self, testscript):

        fail_flag = []
        status_msgs = '\n'
        leaf1_interfaces = []

        LEAF_1 = testscript.parameters['LEAF-1']
        for interf in LEAF_1.interfaces.keys():
            leaf1_interfaces.append(str(LEAF_1.interfaces[interf].intf))

        log.info("Passing LEAF-1 Interfaces ->")
        log.info(leaf1_interfaces)
        leaf1_mod_list = infraVerify.getModuleFromInt(LEAF_1, leaf1_interfaces)
        log.info("Module list is ->")
        log.info(leaf1_mod_list)

        for module in leaf1_mod_list:
            mod_arg_dict = {
                'dut'                       : LEAF_1,
                'mod_num'                   : module,
                'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|IF_DOWN_INTERFACE_REMOVED'
            }
            
            reload_status = infraEORTrig.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += "\nReload of module "+str(module)+" : PASS\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += "\nReload of module "+str(module)+" : FAIL\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])

            time.sleep(60)
            status_msgs += "\nTraffic Check after Reload of module "+str(module)+"\n"
            status_msgs += "--------------------------------------------------------\n"

            if ixLib.verify_traffic_live(2,3) == 0:
                fail_flag.append(0)
                log.debug("Traffic Verification failed")
            else:
                log.info("Traffic Verification Passed")

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#
class TC043_vxlan_vpc_leaf2_LC_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf2LCReload(self, testscript):

        fail_flag = []
        status_msgs = '\n'
        leaf2_interfaces = []

        LEAF_2 = testscript.parameters['LEAF-2']
        for interf in LEAF_2.interfaces.keys():
            leaf2_interfaces.append(str(LEAF_2.interfaces[interf].intf))

        log.info("Passing LEAF-1 Interfaces ->")
        log.info(leaf2_interfaces)
        leaf1_mod_list = infraVerify.getModuleFromInt(LEAF_2, leaf2_interfaces)
        log.info("Module list is ->")
        log.info(leaf1_mod_list)

        for module in leaf1_mod_list:
            mod_arg_dict = {
                'dut'                       : LEAF_2,
                'mod_num'                   : module,
                'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|IF_DOWN_INTERFACE_REMOVED'
            }

            reload_status = infraEORTrig.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += "\nReload of module "+str(module)+" : PASS\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += "\nReload of module "+str(module)+" : FAIL\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])

            time.sleep(60)
            status_msgs += "\nTraffic Check after Reload of module "+str(module)+"\n"
            status_msgs += "--------------------------------------------------------\n"

            if ixLib.verify_traffic_live(2, 3) == 0:
                fail_flag.append(0)
                log.debug("Traffic Verification failed")
            else:
                log.info("Traffic Verification Passed")

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#
class TC044_vxlan_leaf3_LC_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf2LCReload(self, testscript):

        fail_flag = []
        status_msgs = '\n'
        leaf3_interfaces = []

        LEAF_3 = testscript.parameters['LEAF-3']
        for interf in LEAF_3.interfaces.keys():
            leaf3_interfaces.append(str(LEAF_3.interfaces[interf].intf))

        log.info("Passing LEAF-1 Interfaces ->")
        log.info(leaf3_interfaces)
        leaf1_mod_list = infraVerify.getModuleFromInt(LEAF_3, leaf3_interfaces)
        log.info("Module list is ->")
        log.info(leaf1_mod_list)

        for module in leaf1_mod_list:
            mod_arg_dict = {
                'dut'                       : LEAF_3,
                'mod_num'                   : module,
                'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|IF_DOWN_INTERFACE_REMOVED'
            }

            reload_status = infraEORTrig.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += "\nReload of module "+str(module)+" : PASS\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += "\nReload of module "+str(module)+" : FAIL\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])

            time.sleep(60)
            status_msgs += "\nTraffic Check after Reload of module "+str(module)+"\n"
            status_msgs += "--------------------------------------------------------\n"

            if ixLib.verify_traffic_live(2, 3) == 0:
                fail_flag.append(0)
                log.debug("Traffic Verification failed")
            else:
                log.info("Traffic Verification Passed")

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)

        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#
class TC045_vxlan_vpc_leaf1_FM_all_reload(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf1FMReload(self, testscript):

        fail_flag = []
        status_msgs = '\n'
        LEAF_1 = testscript.parameters['LEAF-1']

        leaf1_fm_mod_list = []
        fabric_mod_out = json.loads(LEAF_1.execute("show mod fabric | json"))['TABLE_modinfo']['ROW_modinfo']
        for fm_data in fabric_mod_out:
            leaf1_fm_mod_list.append(fm_data['modinf'])

        for module in leaf1_fm_mod_list:
            mod_arg_dict = {
                'dut'                       : LEAF_1,
                'mod_num'                   : module,
                'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED'
            }

            reload_status = infraEORTrig.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += "\nReload of FM " + str(module) + " : PASS\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += "\nReload of FM " + str(module) + " : FAIL\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic_live(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
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
class TC046_vxlan_vpc_leaf2_FM_all_reload(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf2FMReload(self, testscript):

        fail_flag = []
        status_msgs = '\n'
        LEAF_2 = testscript.parameters['LEAF-2']

        leaf1_fm_mod_list = []
        fabric_mod_out = json.loads(LEAF_2.execute("show mod fabric | json"))['TABLE_modinfo']['ROW_modinfo']
        for fm_data in fabric_mod_out:
            leaf1_fm_mod_list.append(fm_data['modinf'])

        for module in leaf1_fm_mod_list:
            mod_arg_dict = {
                'dut'                       : LEAF_2,
                'mod_num'                   : module,
                'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED'
            }

            reload_status = infraEORTrig.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += "\nReload of FM " + str(module) + " : PASS\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += "\nReload of FM " + str(module) + " : FAIL\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic_live(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
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
class TC047_vxlan_leaf3_FM_all_reload(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf3FMReload(self, testscript):

        fail_flag = []
        status_msgs = '\n'
        LEAF_3 = testscript.parameters['LEAF-3']

        leaf1_fm_mod_list = []
        fabric_mod_out = json.loads(LEAF_3.execute("show mod fabric | json"))['TABLE_modinfo']['ROW_modinfo']
        for fm_data in fabric_mod_out:
            leaf1_fm_mod_list.append(fm_data['modinf'])

        for module in leaf1_fm_mod_list:
            mod_arg_dict = {
                'dut'                       : LEAF_3,
                'mod_num'                   : module,
                'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED'
            }

            reload_status = infraEORTrig.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += "\nReload of FM " + str(module) + " : PASS\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += "\nReload of FM " + str(module) + " : FAIL\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic_live(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
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
class TC048_vxlan_vpc_leaf1_SC_all_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf1SCReload(self, testscript):

        fail_flag = []
        status_msgs = '\n'
        LEAF_1 = testscript.parameters['LEAF-1']

        leaf1_sc_mod_list = []
        sc_mod_out = json.loads(LEAF_1.execute("show mod | json"))['TABLE_modwwninfo']['ROW_modwwninfo']
        for sc_data in sc_mod_out:
            if "SC" in sc_data['slottype']:
                leaf1_sc_mod_list.append(sc_data['modwwn'])

        for module in leaf1_sc_mod_list:
            mod_arg_dict = {
                'dut'                       : LEAF_1,
                'mod_num'                   : module,
                'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED'
            }

            reload_status = infraEORTrig.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += "\nReload of SC " + str(module) + " : PASS\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += "Reload of SC " + str(module) + " : FAIL\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic_live(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
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
class TC049_vxlan_vpc_leaf2_SC_all_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf2SCReload(self, testscript):

        fail_flag = []
        status_msgs = '\n'
        LEAF_2 = testscript.parameters['LEAF-2']

        leaf1_sc_mod_list = []
        sc_mod_out = json.loads(LEAF_2.execute("show mod | json"))['TABLE_modwwninfo']['ROW_modwwninfo']
        for sc_data in sc_mod_out:
            if "SC" in sc_data['slottype']:
                leaf1_sc_mod_list.append(sc_data['modwwn'])

        for module in leaf1_sc_mod_list:
            mod_arg_dict = {
                'dut'                       : LEAF_2,
                'mod_num'                   : module,
                'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED'
            }

            reload_status = infraEORTrig.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += "\nReload of SC " + str(module) + " : PASS\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += "Reload of SC " + str(module) + " : FAIL\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic_live(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
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
class TC050_vxlan_leaf3_SC_all_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf3SCReload(self, testscript):

        fail_flag = []
        status_msgs = '\n'
        LEAF_3 = testscript.parameters['LEAF-3']

        leaf1_sc_mod_list = []
        sc_mod_out = json.loads(LEAF_3.execute("show mod | json"))['TABLE_modwwninfo']['ROW_modwwninfo']
        for sc_data in sc_mod_out:
            if "SC" in sc_data['slottype']:
                leaf1_sc_mod_list.append(sc_data['modwwn'])

        for module in leaf1_sc_mod_list:
            mod_arg_dict = {
                'dut'                       : LEAF_3,
                'mod_num'                   : module,
                'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED'
            }

            reload_status = infraEORTrig.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += "\nReload of SC " + str(module) + " : PASS\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += "Reload of SC " + str(module) + " : FAIL\n"
                status_msgs += "===========================================\n"
                status_msgs += str(reload_status['logs'])

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic_live(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
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
class TC051_vxlan_vpc_leaf1_SSO(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf1SSO(self, testscript):

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_1.configure("copy r s", timeout = 600)

        # Perform Device Reload
        result = infraEORTrig.verifyDeviceSSO({'dut':LEAF_1})
        if result:
            log.info("SSO completed Successfully")
        else:
            log.debug("SSO Failed")
            self.failed("SSO Failed", goto=['cleanup'])

        log.info("Waiting for 120 sec for the topology to come UP")
        time.sleep(120)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic_live(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
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
class TC052_vxlan_vpc_leaf2_SSO(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf2SSO(self, testscript):

        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_2.configure("copy r s", timeout = 600)

        # Perform Device Reload
        result = infraEORTrig.verifyDeviceSSO({'dut':LEAF_2})
        if result:
            log.info("SSO completed Successfully")
        else:
            log.debug("SSO Failed")
            self.failed("SSO Failed", goto=['cleanup'])

        log.info("Waiting for 120 sec for the topology to come UP")
        time.sleep(120)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic_live(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
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
class TC053_vxlan_leaf3_SSO(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf3SSO(self, testscript):

        LEAF_3 = testscript.parameters['LEAF-3']
        LEAF_3.configure("copy r s", timeout = 600)

        # Perform Device Reload
        result = infraEORTrig.verifyDeviceSSO({'dut':LEAF_3})
        if result:
            log.info("SSO completed Successfully")
        else:
            log.debug("SSO Failed")
            self.failed("SSO Failed", goto=['cleanup'])

        log.info("Waiting for 120 sec for the topology to come UP")
        time.sleep(120)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic_live(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
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
class TC054_VERIFY_VPC_PRIMARY_VTEP_DEVICE_ASCII_RELOAD(aetest.Testcase):
    """HA_VERIFICATION"""

    @aetest.test
    def TRIGGER_verify_device_ascii_reload(self, testscript):
        """ HA_VERIFICATION subsection: Device ASCII Reload """

        LEAF_1 = testscript.parameters['LEAF-1']

        LEAF_1.configure("copy r s", timeout = 600)

        # Perform Device Reload
        result = infraTrig.switchReload(LEAF_1)
        if result:
            log.info("Reload completed Successfully")
        else:
            log.debug("Reload Failed")
            self.failed("Reload Failed", goto=['cleanup'])

        log.info("Waiting for 120 sec for the topology to come UP")
        time.sleep(240)

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic_live(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
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
class TC055_VERIFY_VPC_SECONDARY_VTEP_DEVICE_ASCII_RELOAD(aetest.Testcase):
    """HA_VERIFICATION"""

    @aetest.test
    def TRIGGER_verify_device_ascii_reload(self, testscript):
        """ HA_VERIFICATION subsection: Device ASCII Reload """

        LEAF_2 = testscript.parameters['LEAF-2']

        LEAF_2.configure("copy r s", timeout = 600)

        # Perform Device Reload
        result = infraTrig.switchReload(LEAF_2)
        if result:
            log.info("Reload completed Successfully")
        else:
            log.debug("Reload Failed")
            self.failed("Reload Failed", goto=['cleanup'])

        log.info("Waiting for 120 sec for the topology to come UP")
        time.sleep(240)

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic_live(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
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
class TC056_VERIFY_STD_VTEP_DEVICE_ASCII_RELOAD(aetest.Testcase):
    """HA_VERIFICATION"""

    @aetest.test
    def TRIGGER_verify_device_ascii_reload(self, testscript):
        """ HA_VERIFICATION subsection: Device ASCII Reload """

        LEAF_3 = testscript.parameters['LEAF-3']

        LEAF_3.configure("copy r s", timeout = 600)

        # Perform Device Reload
        result = infraTrig.switchReload(LEAF_3)
        if result:
            log.info("Reload completed Successfully")
        else:
            log.debug("Reload Failed")
            self.failed("Reload Failed", goto=['cleanup'])

        log.info("Waiting for 120 sec for the topology to come UP")
        time.sleep(240)

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic_live(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
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
