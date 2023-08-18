#!/usr/bin/env python

###################################################################
###                  Importing Libraries                        ###
###################################################################
import logging
import pdb
import sys
import copy
import time
import yaml
import re
import json
import ipaddress as ip
from randmac import RandMac as randMac
from yaml import Loader
from ats import aetest
from pyats import aetest
from pyats.log.utils import banner

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

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
fnlLib      = vxlanEVPN_FNL_lib.configure39KVxlanFnL()
verifyFnL   = vxlanEVPN_FNL_lib.verifyFnLconfiguration()

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
infraEORTrigger = infra_lib.infraEORTrigger()

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

def pretty(d, indent=0):
    for key, value in d.items():
        log.info('\t' * indent + str(key))
        if isinstance(value, dict):
            pretty(value, indent+1)
        else:
            log.info('\t' * (indent+1) + str(value))

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

# noinspection PyGlobalUndefined
class COMMON_SETUP(aetest.CommonSetup):
    """ Common Setup """

    # *****************************************************************************************************************************#
    @aetest.subsection
    def connecting_to_devices(self, testscript, testbed, uut_list):
        """ common setup subsection: Connecting to devices """

        # =============================================================================================================================#
        # Grab the device object of the uut device with that name

        SPINE = testscript.parameters['SPINE'] = testbed.devices[uut_list['SPINE']]

        LEAF_1 = testscript.parameters['LEAF-1'] = testbed.devices[uut_list['LEAF-1']]
        LEAF_2 = testscript.parameters['LEAF-2'] = testbed.devices[uut_list['LEAF-2']]
        LEAF_3 = testscript.parameters['LEAF-3'] = testbed.devices[uut_list['LEAF-3']]

        FAN_1 = testscript.parameters['FAN-1'] = testbed.devices[uut_list['FAN-1']]

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
        FAN_1.connect()

        device_list.append(SPINE)
        device_list.append(LEAF_1)
        device_list.append(LEAF_2)
        device_list.append(LEAF_3)
        device_list.append(FAN_1)

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

        global post_test_process_dict
        global cc_verification_dict
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        # =============================================================================================================================#
        # Import script_flags into testscript.parameters
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

            if 'brcm_flag' in script_flags.keys():
                testscript.parameters['script_flags']['brcm_flag'] = script_flags['brcm_flag']
            else:
                testscript.parameters['script_flags']['brcm_flag'] = 0

            # if 'eor_flag' in script_flags.keys():
            #     testscript.parameters['script_flags']['eor_flag'] = script_flags['eor_flag']
            # else:
            #     testscript.parameters['script_flags']['eor_flag'] = 0
        else:
            testscript.parameters['script_flags']['skip_device_config'] = 0
            testscript.parameters['script_flags']['skip_tgen_config'] = 0
            testscript.parameters['script_flags']['skip_device_cleanup'] = 0

        post_test_process_dict = {}
        post_test_process_dict = job_file_params['postTestArgs']
        post_test_process_dict['dut_list'] = [LEAF_1, LEAF_2, LEAF_3]

        # cc_verification_dict = {}
        # # cc_verification_dict = job_file_params['postTestArgs']
        # if not testscript.parameters['script_flags']['eor_flag']:
        #     cc_verification_dict['cc_check'] = 1
        # cc_verification_dict['cores_check'] = 0
        # cc_verification_dict['logs_check'] = 1
        # cc_verification_dict['fnl_flag'] = 1
        # cc_verification_dict['dut_list'] = [LEAF_1, LEAF_2, LEAF_3]

        log.info("===> Post Test Check Process Parameters")
        log.info(post_test_process_dict)

        # log.info("===> CC Verification Parameters")
        # log.info(cc_verification_dict)

        # Flags to control pre-clean, config and EOR Trigger test-cases
        resn = "Skipped by the user via job file"
        # eorCCresn = "Skipping CC since EOR does not support VxLAN CC"
        log.info(resn)
        if job_file_params['script_flags']['skip_device_config']:
            aetest.skip.affix(section=DEVICE_BRINGUP_enable_feature_set, reason=resn)
            aetest.skip.affix(section=DEVICE_BRINGUP_configure_SPINE, reason=resn)
            aetest.skip.affix(section=DEVICE_BRINGUP_configure_LEAF_1_2, reason=resn)
            aetest.skip.affix(section=DEVICE_BRINGUP_configure_LEAF_3, reason=resn)
            aetest.skip.affix(section=DEVICE_BRINGUP_configure_FAN_1, reason=resn)
        if job_file_params['script_flags']['skip_eor_triggers']:
            aetest.skip.affix(section=TC022_vxlan_vpc_leaf1_LC_reload, reason=resn)
            aetest.skip.affix(section=TC023_vxlan_vpc_leaf2_LC_reload, reason=resn)
            aetest.skip.affix(section=TC024_vxlan_leaf3_LC_reload, reason=resn)
            aetest.skip.affix(section=TC025_vxlan_vpc_leaf1_FM_all_reload, reason=resn)
            aetest.skip.affix(section=TC026_vxlan_vpc_leaf2_FM_all_reload, reason=resn)
            aetest.skip.affix(section=TC027_vxlan_leaf3_FM_all_reload, reason=resn)
            aetest.skip.affix(section=TC028_vxlan_vpc_leaf1_SC_all_reload, reason=resn)
            aetest.skip.affix(section=TC029_vxlan_vpc_leaf2_SC_all_reload, reason=resn)
            aetest.skip.affix(section=TC030_vxlan_leaf3_SC_all_reload, reason=resn)
            aetest.skip.affix(section=TC031_vxlan_vpc_leaf1_SSO, reason=resn)
            aetest.skip.affix(section=TC032_vxlan_vpc_leaf2_SSO, reason=resn)
            aetest.skip.affix(section=TC033_vxlan_leaf3_SSO, reason=resn)
        # if testscript.parameters['script_flags']['eor_flag']:
        #     aetest.skip.affix(section=CC_01_VERIFY_CC, reason=eorCCresn)
        #     aetest.skip.affix(section=CC_02_VERIFY_CC, reason=eorCCresn)
        #     aetest.skip.affix(section=CC_03_VERIFY_CC, reason=eorCCresn)
        #     aetest.skip.affix(section=CC_04_VERIFY_CC, reason=eorCCresn)
        #     aetest.skip.affix(section=CC_05_VERIFY_CC, reason=eorCCresn)

        # =============================================================================================================================#
        # Import Configuration File and create required Structures

        with open(configurationFile) as cfgFile:
            configuration = yaml.load(cfgFile, Loader=Loader)

        testscript.parameters['LEAF_1_dict']            = configuration['LEAF_1_dict']
        testscript.parameters['LEAF_2_dict']            = configuration['LEAF_2_dict']
        testscript.parameters['LEAF_3_dict']            = configuration['LEAF_3_dict']
        testscript.parameters['forwardingSysDict']      = configuration['FWD_SYS_dict']

        testscript.parameters['LEAF_2_TGEN_dict']       = configuration['LEAF_2_TGEN_data']
        testscript.parameters['LEAF_3_TGEN_dict']       = configuration['LEAF_3_TGEN_data']

        testscript.parameters['leafVPCDictData']        = {LEAF_1 : configuration['LEAF_1_dict'], LEAF_2 : configuration['LEAF_2_dict']}
        testscript.parameters['leavesDictList']         = [configuration['LEAF_1_dict'], configuration['LEAF_2_dict'], configuration['LEAF_3_dict']]
        testscript.parameters['leavesDict']             = {LEAF_1 : configuration['LEAF_1_dict'],
                                                           LEAF_2 : configuration['LEAF_2_dict'],
                                                           LEAF_3 : configuration['LEAF_3_dict']}

        testscript.parameters['VTEP_List'] = [testscript.parameters['LEAF_1_dict'], testscript.parameters['LEAF_2_dict'], testscript.parameters['LEAF_3_dict']]
        testscript.parameters['nve_peer_ip_lst'] = getNvePeerList(testscript.parameters['VTEP_List'])

    # *****************************************************************************************************************************#
    @aetest.subsection
    def get_interfaces(self, testscript):
        """ common setup subsection: Getting required Connections for Test """

        # SPINE   = testscript.parameters['SPINE']
        # LEAF_1  = testscript.parameters['LEAF-1']
        # LEAF_2  = testscript.parameters['LEAF-2']
        LEAF_3  = testscript.parameters['LEAF-3']
        FAN_1   = testscript.parameters['FAN-1']
        IXIA    = testscript.parameters['IXIA']

        # =============================================================================================================================#

        log.info("================================================")
        log.info("All Available Interfaces from the YAML file are:")
        for dut in device_list:
            log.info("\n\n--->" + str(dut) + " Interface list")
            for interface in dut.interfaces.keys():
                log.info(str(interface) + " --> " + str(dut.interfaces[interface].intf))

        # =============================================================================================================================#
        # Fetching the IXIA interfaces
        testscript.parameters['intf_LEAF_3_to_IXIA']        = LEAF_3.interfaces['LEAF_to_IXIA'].intf
        testscript.parameters['intf_FAN_1_to_IXIA']         = FAN_1.interfaces['FAN_to_IXIA'].intf

        testscript.parameters['intf_IXIA_to_FAN_1']         = IXIA.interfaces['IXIA_to_FAN-1'].intf
        testscript.parameters['intf_IXIA_to_LEAF_3']        = IXIA.interfaces['IXIA_to_LEAF-3'].intf

        testscript.parameters['ixia_int_list'] = str(testscript.parameters['intf_IXIA_to_FAN_1']) + " " + str(testscript.parameters['intf_IXIA_to_LEAF_3'])

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
                                    +-----------+                  |
                                    |   FAN-1   |                  |
                                    +-----------+                  |
                                          |                        |      
                                          |                        |      
                                        Ixia                     Ixia     
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

        spineFeatureList        = ['ospf', 'pim', 'lacp']
        vpcLeafFeatureList      = ['vpc', 'ospf', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'hsrp', 'lacp', 'nv overlay']
        LeafFeatureList         = ['ospf', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'hsrp', 'lacp', 'nv overlay']
        fanOutFeatureList       = ['lacp']
        configFeatureSet_status = []
        configFeatureSet_msgs = ""

        # --------------------------------
        # Configure Features on SPINE
        featureConfigureSpine_status = infraConfig.configureVerifyFeature(testscript.parameters['SPINE'], spineFeatureList)
        if featureConfigureSpine_status['result']:
            log.info("Passed Configuring features on SPINE")
        else:
            log.debug("Failed configuring features on SPINE")
            configFeatureSet_msgs += featureConfigureSpine_status['log']
            configFeatureSet_status.append(0)

        # --------------------------------
        # Configure Feature-set on LEAF-1
        featureConfigureLeaf1_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-1'], vpcLeafFeatureList)
        if featureConfigureLeaf1_status['result']:
            log.info("Passed Configuring features on LEAF-1")
        else:
            log.debug("Failed configuring features on LEAF-1")
            configFeatureSet_msgs += featureConfigureLeaf1_status['log']
            configFeatureSet_status.append(0)

        # --------------------------------
        # Configure Feature-set on LEAF-2
        featureConfigureLeaf2_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-2'], vpcLeafFeatureList)
        if featureConfigureLeaf2_status['result']:
            log.info("Passed Configuring features on LEAF-2")
        else:
            log.debug("Failed configuring features on LEAF-2")
            configFeatureSet_msgs += featureConfigureLeaf1_status['log']
            configFeatureSet_status.append(0)

        # --------------------------------
        # Configure Feature-set on LEAF-3
        featureConfigureLeaf3_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-3'], LeafFeatureList)
        if featureConfigureLeaf3_status['result']:
            log.info("Passed Configuring features on LEAF-3")
        else:
            log.debug("Failed configuring features on LEAF-3")
            configFeatureSet_msgs += featureConfigureLeaf1_status['log']
            configFeatureSet_status.append(0)

        # --------------------------------
        # Configure Feature-set on FAN-1
        featureConfigureFan1_status = infraConfig.configureVerifyFeature(testscript.parameters['FAN-1'], fanOutFeatureList)
        if featureConfigureFan1_status['result']:
            log.info("Passed Configuring features on FAN-1")
        else:
            log.debug("Failed configuring features on FAN-1")
            configFeatureSet_msgs += featureConfigureFan1_status['log']
            configFeatureSet_status.append(0)

        if 0 in configFeatureSet_status:
            self.failed(reason=configFeatureSet_msgs, goto=['common_cleanup'])

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

        fnlLib.configureFnLSpines([testscript.parameters['SPINE']], testscript.parameters['forwardingSysDict'] , testscript.parameters['leavesDictList'])

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
            self.errored('Exception occurred while configuring on SPINE', goto=['cleanup'])

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

        nve_peer_list = getNvePeerList(testscript.parameters['VTEP_List'])
        fnlLib.configureFnLVPCLeafs(testscript.parameters['forwardingSysDict'], testscript.parameters['leafVPCDictData'], nve_peer_list)

        vlan_id_start = testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']
        vlan_id_stop = int(vlan_id_start) + int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])
        vlan_id_stop = int(vlan_id_stop) + int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])

        try:
            LEAF_1.configure("ip igmp snooping vxlan")
            
            if not testscript.parameters['script_flags']['brcm_flag']:
                LEAF_1.configure('''system nve infra-vlans ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['backup_svi']) + ''' force''')

            LEAF_1.configure('''
                vlan ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['backup_svi']) + '''
                    state active
                    no shut
                    
                interface vlan ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['backup_svi']) + '''
                    ip address ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['backup_svi_ip']) + '''
                    no shutdown
                    ip route ospf ''' + str(testscript.parameters['forwardingSysDict']['OSPF_AS']) + ''' area 0
                    ip ospf network point-to-point
                
                interface po ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
                    switchport
                    switchport mode trunk
                    switchport trunk allowed vlan '''+str(vlan_id_start)+'''-'''+str(vlan_id_stop)+'''
                    no shut
            ''')
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
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-1', goto=['cleanup'])

        try:
            LEAF_2.configure("ip igmp snooping vxlan")
            
            if not testscript.parameters['script_flags']['brcm_flag']:
                LEAF_2.configure('''system nve infra-vlans ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['backup_svi']) + ''' force''')

            LEAF_2.configure('''
                vlan ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['backup_svi']) + '''
                    state active
                    no shut

                interface vlan ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['backup_svi']) + '''
                    ip address ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['backup_svi_ip']) + '''
                    no shutdown
                    ip route ospf ''' + str(testscript.parameters['forwardingSysDict']['OSPF_AS']) + ''' area 0
                    ip ospf network point-to-point
                    
                interface po ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + '''
                    switchport
                    switchport mode trunk
                    switchport trunk allowed vlan '''+str(vlan_id_start)+'''-'''+str(vlan_id_stop)+'''
                    no shut
            ''')
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
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-2', goto=['cleanup'])

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

        nve_peer_list = getNvePeerList(testscript.parameters['VTEP_List'])
        fnlLib.configureFnLLeaf(testscript.parameters['LEAF-3'],testscript.parameters['forwardingSysDict'],testscript.parameters['LEAF_3_dict'],nve_peer_list)
        vlan_id_start = testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']
        vlan_id_stop = int(vlan_id_start) + int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])
        vlan_id_stop = int(vlan_id_stop) + int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])

        try:
            # LEAF_3.configure('''
            #     no interface vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
            # ''', timeout=300)

            LEAF_3.configure('''
                ip igmp snooping vxlan
                vlan configuration ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                  ip igmp snooping querier 1.1.1.1
            ''')
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
                            no shutdown
                    ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-3', goto=['cleanup'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class DEVICE_BRINGUP_configure_FAN_1(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_FAN_1(self, testscript):
        """ Device Bring-up subsection: Configuring FAN_1 """

        FAN_1 = testscript.parameters['FAN-1']
        po_cfg_flag = 0
        fanOut1_vlanConfiguration = ""

        vlan_id_start = testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']
        vlan_id_stop = int(vlan_id_start) + int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])
        vlan_id_stop = int(vlan_id_stop) + int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])

        fanOut1_vlanConfiguration += '''vlan ''' + str(vlan_id_start) + '''-'''+ str(vlan_id_stop)+'''
                                        state active
                                        no shut'''

        try:
            FAN_1.configure(fanOut1_vlanConfiguration)
            for interf in FAN_1.interfaces.keys():
                if "FAN_to_LEAF" in interf:
                    if not po_cfg_flag:
                        FAN_1.configure('''
                            no interface port-channel ''' + str(FAN_1.interfaces[interf].PO) + '''
                            interface port-channel ''' + str(FAN_1.interfaces[interf].PO) + '''
                                switchport
                                switchport mode trunk
                                no shutdown
                                no shut
                        ''')
                        po_cfg_flag = 1
                    FAN_1.configure('''
                        interface ''' + str(FAN_1.interfaces[interf].intf) + '''
                            channel-group ''' + str(FAN_1.interfaces[interf].PO) + ''' force mode active
                            no shut
                    ''')
                elif "FAN_to_IXIA" in interf:
                    FAN_1.configure('''
                        default interface ''' + str(FAN_1.interfaces[interf].intf) + '''
                        interface ''' + str(FAN_1.interfaces[interf].intf) + '''
                            switchport
                            switchport mode trunk
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
    """This is description for my testcase one"""

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
            self.passed("PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            self.failed("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n", goto=['common_cleanup'])

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyFnL.verifyFnLNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'], goto=['common_cleanup'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyFnL.verifyFnLVNIData(testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'], goto=['common_cleanup'])

    @aetest.test
    def verify_HSRP(self, testscript):
        """ VERIFY_NETWORK subsection: Verify HSRP """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        hsrp_arg_dict = {
            'dut_1'         : LEAF_1,
            'dut_2'         : LEAF_2,
            'vlan_start'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']),
            'vlan_count'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])+int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])
        }

        hsrpValidation = verifyFnL.verifyFnLHSRP(hsrp_arg_dict)

        if hsrpValidation['status']:
            log.info("PASS : Successfully verified HSRP Data\n\n")
            self.passed(reason=hsrpValidation['log'])
        else:
            log.info("FAIL : Failed to verify HSRP Data\n\n")
            self.failed(reason=hsrpValidation['log'], goto=['common_cleanup'])

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

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            # Get IXIA paraameters
            ixia_chassis_ip = testscript.parameters['ixia_chassis_ip']
            ixia_tcl_server = testscript.parameters['ixia_tcl_server']
            ixia_tcl_port = testscript.parameters['ixia_tcl_port']
            ixia_int_list = testscript.parameters['ixia_int_list']

            ix_int_1 = testscript.parameters['intf_IXIA_to_FAN_1']
            ix_int_2 = testscript.parameters['intf_IXIA_to_LEAF_3']

            ixiaArgDict = {
                            'chassis_ip'    : ixia_chassis_ip,
                            'port_list'     : ixia_int_list,
                            'tcl_server'    : ixia_tcl_server,
                            'tcl_port'      : ixia_tcl_port
            }

            log.info("Ixia Args Dict is:")
            log.info(ixiaArgDict)

            result = ixLib.connect_to_ixia(ixiaArgDict)
            if result == 0:
                log.debug("Connecting to ixia failed")
                self.errored("Connecting to ixia failed", goto=['cleanup'])

            ch_key = result['port_handle']
            for ch_p in ixia_chassis_ip.split('.'):
                ch_key = ch_key[ch_p]

            log.info("Port Handles are:")
            log.info(ch_key)

            testscript.parameters['port_handle_1'] = ch_key[ix_int_1]
            testscript.parameters['port_handle_2'] = ch_key[ix_int_2]

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

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

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            TOPO_1_dict = {'topology_name': 'FAN-1-TG',
                           'device_grp_name': 'FAN-1-TG',
                           'port_handle': testscript.parameters['port_handle_1']}

            TOPO_2_dict = {'topology_name': 'FAN-2-TG',
                           'device_grp_name': 'FAN-2-TG',
                           'port_handle': testscript.parameters['port_handle_2']}

            testscript.parameters['IX_TP1'] = ixLib.create_topo_device_grp(TOPO_1_dict)
            if testscript.parameters['IX_TP1'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed", goto=['cleanup'])
            else:
                log.info("Created BL1-TG Topology Successfully")

            testscript.parameters['IX_TP2'] = ixLib.create_topo_device_grp(TOPO_2_dict)
            if testscript.parameters['IX_TP2'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed", goto=['cleanup'])
            else:
                log.info("Created BL2-TG Topology Successfully")

            testscript.parameters['IX_TP1']['port_handle'] = testscript.parameters['port_handle_1']
            testscript.parameters['IX_TP2']['port_handle'] = testscript.parameters['port_handle_2']
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

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

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            P1 = testscript.parameters['port_handle_1']
            P2 = testscript.parameters['port_handle_2']

            # Retrieving TGEN Data from Config file
            P1_tgen_dict = testscript.parameters['LEAF_2_TGEN_dict']
            P2_tgen_dict = testscript.parameters['LEAF_3_TGEN_dict']

            # Retrieving VTEP Data from Config file
            P1_staticIR_dict = testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']
            P2_staticIR_dict = testscript.parameters['LEAF_3_dict']['STATIC_IR_VNI_data']
            P1_MCast_dict    = testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']
            P2_MCast_dict    = testscript.parameters['LEAF_3_dict']['MCAST_VNI_data']

            # Setting UP P1 parameters
            P1_staticIR_v4_start = str((ip.IPv4Interface(ip.IPv4Interface(P1_staticIR_dict['l2_vlan_ipv4_start'] + P1_staticIR_dict['l2_vlan_ipv4_mask']).network)+60).ip)
            P1_staticIR_v4_gw_start = str((ip.IPv4Interface(ip.IPv4Interface(P1_staticIR_dict['l2_vlan_ipv4_start'] + P1_staticIR_dict['l2_vlan_ipv4_mask']).network)+1).ip)

            P1_MCAST_v4_start = str((ip.IPv4Interface(ip.IPv4Interface(P1_MCast_dict['l2_vlan_ipv4_start'] + P1_MCast_dict['l2_vlan_ipv4_mask']).network) + 60).ip)
            P1_MCAST_v4_gw_start = str((ip.IPv4Interface(ip.IPv4Interface(P1_MCast_dict['l2_vlan_ipv4_start'] + P1_MCast_dict['l2_vlan_ipv4_mask']).network) + 1).ip)

            P1_staticIR_v6_start = str((ip.IPv6Interface(ip.IPv6Interface(P1_staticIR_dict['l2_vlan_ipv6_start'] + P1_staticIR_dict['l2_vlan_ipv6_mask']).network)+60).ip)
            P1_staticIR_v6_gw_start = str((ip.IPv6Interface(ip.IPv6Interface(P1_staticIR_dict['l2_vlan_ipv6_start'] + P1_staticIR_dict['l2_vlan_ipv6_mask']).network)+1).ip)

            P1_MCAST_v6_start = str((ip.IPv6Interface(ip.IPv6Interface(P1_MCast_dict['l2_vlan_ipv6_start'] + P1_MCast_dict['l2_vlan_ipv6_mask']).network) + 60).ip)
            P1_MCAST_v6_gw_start = str((ip.IPv6Interface(ip.IPv6Interface(P1_MCast_dict['l2_vlan_ipv6_start'] + P1_MCast_dict['l2_vlan_ipv6_mask']).network) + 1).ip)

            # Setting UP P2 parameters
            P2_staticIR_v4_start = str((ip.IPv4Interface(ip.IPv4Interface(P2_staticIR_dict['l2_vlan_ipv4_start'] + P2_staticIR_dict['l2_vlan_ipv4_mask']).network)+70).ip)
            P2_staticIR_v4_gw_start = str((ip.IPv4Interface(ip.IPv4Interface(P2_staticIR_dict['l2_vlan_ipv4_start'] + P2_staticIR_dict['l2_vlan_ipv4_mask']).network)+1).ip)

            P2_MCAST_v4_start = str((ip.IPv4Interface(ip.IPv4Interface(P2_MCast_dict['l2_vlan_ipv4_start'] + P2_MCast_dict['l2_vlan_ipv4_mask']).network) + 70).ip)
            P2_MCAST_v4_gw_start = str((ip.IPv4Interface(ip.IPv4Interface(P2_MCast_dict['l2_vlan_ipv4_start'] + P2_MCast_dict['l2_vlan_ipv4_mask']).network) + 1).ip)

            P2_staticIR_v6_start = str((ip.IPv6Interface(ip.IPv6Interface(P2_staticIR_dict['l2_vlan_ipv6_start'] + P2_staticIR_dict['l2_vlan_ipv6_mask']).network)+70).ip)
            P2_staticIR_v6_gw_start = str((ip.IPv6Interface(ip.IPv6Interface(P2_staticIR_dict['l2_vlan_ipv6_start'] + P2_staticIR_dict['l2_vlan_ipv6_mask']).network)+1).ip)

            P2_MCAST_v6_start = str((ip.IPv6Interface(ip.IPv6Interface(P2_MCast_dict['l2_vlan_ipv6_start'] + P2_MCast_dict['l2_vlan_ipv6_mask']).network) + 70).ip)
            P2_MCAST_v6_gw_start = str((ip.IPv6Interface(ip.IPv6Interface(P2_MCast_dict['l2_vlan_ipv6_start'] + P2_MCast_dict['l2_vlan_ipv6_mask']).network) + 1).ip)

            P1_staticIR_mac_start = str(randMac("00:00:21:00:00:00", True)).replace("'","")
            P2_staticIR_mac_start = str(randMac("00:00:23:00:00:00", True)).replace("'", "")
            P1_MCAST_mac_start = str(randMac("00:00:22:00:00:00", True)).replace("'", "")
            P2_MCAST_mac_start = str(randMac("00:00:24:00:00:00", True)).replace("'", "")

            # Setting UP P1 Static IR IXIA Stream parameters
            P1_staticIR_int_dict_1 = {'dev_grp_hndl'     : testscript.parameters['IX_TP1']['dev_grp_hndl'],
                             'port_hndl'        : P1,
                             'no_of_ints'       : str(P1_staticIR_dict['vlan_count']),
                             'phy_mode'         : P1_tgen_dict['phy_mode'],
                             'mac'              : P1_staticIR_mac_start,
                             'mac_step'         : P1_tgen_dict['mac_step'],
                             'protocol'         : P1_tgen_dict['protocol'],
                             'v4_addr'          : P1_staticIR_v4_start,
                             'v4_addr_step'     : P1_tgen_dict['v4_addr_step'],
                             'v4_gateway'       : P1_staticIR_v4_gw_start,
                             'v4_gateway_step'  : P1_tgen_dict['v4_gateway_step'],
                             'v4_netmask'       : P1_tgen_dict['v4_netmask'],
                             'v6_addr'          : P1_staticIR_v6_start,
                             'v6_addr_step'     : P1_tgen_dict['v6_addr_step'],
                             'v6_gateway'       : P1_staticIR_v6_gw_start,
                             'v6_gateway_step'  : P1_tgen_dict['v6_gateway_step'],
                             'v6_netmask'       : P1_tgen_dict['v6_netmask'],
                             'vlan_id'          : str(P1_staticIR_dict['l2_vlan_start']),
                             'vlan_id_step'     : P1_tgen_dict['vlan_id_step']}

            # Setting UP P2 Static IR IXIA Stream parameters
            P2_staticIR_int_dict_1 = {'dev_grp_hndl'     : testscript.parameters['IX_TP2']['dev_grp_hndl'],
                             'port_hndl'        : P2,
                             'no_of_ints'       : str(P2_staticIR_dict['vlan_count']),
                             'phy_mode'         : P2_tgen_dict['phy_mode'],
                             'mac'              : P2_staticIR_mac_start,
                             'mac_step'         : P2_tgen_dict['mac_step'],
                             'protocol'         : P2_tgen_dict['protocol'],
                             'v4_addr'          : P2_staticIR_v4_start,
                             'v4_addr_step'     : P2_tgen_dict['v4_addr_step'],
                             'v4_gateway'       : P2_staticIR_v4_gw_start,
                             'v4_gateway_step'  : P2_tgen_dict['v4_gateway_step'],
                             'v4_netmask'       : P2_tgen_dict['v4_netmask'],
                             'v6_addr'          : P2_staticIR_v6_start,
                             'v6_addr_step'     : P2_tgen_dict['v6_addr_step'],
                             'v6_gateway'       : P2_staticIR_v6_gw_start,
                             'v6_gateway_step'  : P2_tgen_dict['v6_gateway_step'],
                             'v6_netmask'       : P2_tgen_dict['v6_netmask'],
                             'vlan_id'          : str(P2_staticIR_dict['l2_vlan_start']),
                             'vlan_id_step'     : P2_tgen_dict['vlan_id_step']}

            # Setting UP P1 MCAST IXIA Stream parameters
            P1_MCast_int_dict_1 = {'dev_grp_hndl'     : testscript.parameters['IX_TP1']['dev_grp_hndl'],
                             'port_hndl'        : P1,
                             'no_of_ints'       : str(P1_MCast_dict['vlan_count']),
                             'phy_mode'         : P1_tgen_dict['phy_mode'],
                             'mac'              : P1_MCAST_mac_start,
                             'mac_step'         : P1_tgen_dict['mac_step'],
                             'protocol'         : P1_tgen_dict['protocol'],
                             'v4_addr'          : P1_MCAST_v4_start,
                             'v4_addr_step'     : P1_tgen_dict['v4_addr_step'],
                             'v4_gateway'       : P1_MCAST_v4_gw_start,
                             'v4_gateway_step'  : P1_tgen_dict['v4_gateway_step'],
                             'v4_netmask'       : P1_tgen_dict['v4_netmask'],
                             'v6_addr'          : P1_MCAST_v6_start,
                             'v6_addr_step'     : P1_tgen_dict['v6_addr_step'],
                             'v6_gateway'       : P1_MCAST_v6_gw_start,
                             'v6_gateway_step'  : P1_tgen_dict['v6_gateway_step'],
                             'v6_netmask'       : P1_tgen_dict['v6_netmask'],
                             'vlan_id'          : str(P1_MCast_dict['l2_vlan_start']),
                             'vlan_id_step'     : P1_tgen_dict['vlan_id_step']}

            # Setting UP P2 MCAST IXIA Stream parameters
            P2_MCast_int_dict_1 = {'dev_grp_hndl'     : testscript.parameters['IX_TP2']['dev_grp_hndl'],
                             'port_hndl'        : P2,
                             'no_of_ints'       : str(P2_MCast_dict['vlan_count']),
                             'phy_mode'         : P2_tgen_dict['phy_mode'],
                             'mac'              : P2_MCAST_mac_start,
                             'mac_step'         : P2_tgen_dict['mac_step'],
                             'protocol'         : P2_tgen_dict['protocol'],
                             'v4_addr'          : P2_MCAST_v4_start,
                             'v4_addr_step'     : P2_tgen_dict['v4_addr_step'],
                             'v4_gateway'       : P2_MCAST_v4_gw_start,
                             'v4_gateway_step'  : P2_tgen_dict['v4_gateway_step'],
                             'v4_netmask'       : P2_tgen_dict['v4_netmask'],
                             'v6_addr'          : P2_MCAST_v6_start,
                             'v6_addr_step'     : P2_tgen_dict['v6_addr_step'],
                             'v6_gateway'       : P2_MCAST_v6_gw_start,
                             'v6_gateway_step'  : P2_tgen_dict['v6_gateway_step'],
                             'v6_netmask'       : P2_tgen_dict['v6_netmask'],
                             'vlan_id'          : str(P1_MCast_dict['l2_vlan_start']),
                             'vlan_id_step'     : P2_tgen_dict['vlan_id_step']}

            P1_StaticIR_IX_int_data = ixLib.configure_multi_ixia_interface(P1_staticIR_int_dict_1)
            P2_StaticIR_IX_int_data = ixLib.configure_multi_ixia_interface(P2_staticIR_int_dict_1)

            P1_Mcast_IX_int_data = ixLib.configure_multi_ixia_interface(P1_MCast_int_dict_1)
            P2_Mcast_IX_int_data = ixLib.configure_multi_ixia_interface(P2_MCast_int_dict_1)

            if P1_StaticIR_IX_int_data == 0 or P2_StaticIR_IX_int_data == 0 or P1_Mcast_IX_int_data == 0 or P2_Mcast_IX_int_data == 0:
                log.debug("Configuring IXIA Interface failed")
                self.errored("Configuring IXIA Interface failed", goto=['cleanup'])
            else:
                log.info("Configured IXIA Interface Successfully")

            # Pushing the Traffic handles to testscript.parameters
            testscript.parameters['IX_TP1']['eth_handle'] = []
            testscript.parameters['IX_TP1']['ipv4_handle'] = []
            testscript.parameters['IX_TP1']['ipv6_handle'] = []
            testscript.parameters['IX_TP2']['eth_handle'] = []
            testscript.parameters['IX_TP2']['ipv4_handle'] = []
            testscript.parameters['IX_TP2']['ipv6_handle'] = []

            testscript.parameters['IX_TP1']['eth_handle'].append(P1_StaticIR_IX_int_data['eth_handle'])
            testscript.parameters['IX_TP1']['ipv4_handle'].append(P1_StaticIR_IX_int_data['ipv4_handle'])
            testscript.parameters['IX_TP1']['ipv6_handle'].append(P1_StaticIR_IX_int_data['ipv6_handle'])

            testscript.parameters['IX_TP1']['eth_handle'].append(P1_Mcast_IX_int_data['eth_handle'])
            testscript.parameters['IX_TP1']['ipv4_handle'].append(P1_Mcast_IX_int_data['ipv4_handle'])
            testscript.parameters['IX_TP1']['ipv6_handle'].append(P1_Mcast_IX_int_data['ipv6_handle'])

            testscript.parameters['IX_TP1']['topo_int_handle'] = P1_StaticIR_IX_int_data['topo_int_handle'].split(" ")

            testscript.parameters['IX_TP2']['eth_handle'].append(P2_StaticIR_IX_int_data['eth_handle'])
            testscript.parameters['IX_TP2']['ipv4_handle'].append(P2_StaticIR_IX_int_data['ipv4_handle'])
            testscript.parameters['IX_TP2']['ipv6_handle'].append(P2_StaticIR_IX_int_data['ipv6_handle'])

            testscript.parameters['IX_TP2']['eth_handle'].append(P2_Mcast_IX_int_data['eth_handle'])
            testscript.parameters['IX_TP2']['ipv4_handle'].append(P2_Mcast_IX_int_data['ipv4_handle'])
            testscript.parameters['IX_TP2']['ipv6_handle'].append(P2_Mcast_IX_int_data['ipv6_handle'])

            testscript.parameters['IX_TP2']['topo_int_handle'] = P2_StaticIR_IX_int_data['topo_int_handle'].split(" ")

            log.info("IXIA Port 1 Handles")
            log.info(testscript.parameters['IX_TP1'])
            log.info("IXIA Port 2 Handles")
            log.info(testscript.parameters['IX_TP2'])

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

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

        #IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']

        P2_TGEN_dict = testscript.parameters['LEAF_3_TGEN_dict']

        # Retrieving VTEP Data from Config file
        P1_staticIR_dict = testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']
        P1_MCast_dict = testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']

        P2_staticIR_start_ip = str((ip.IPv4Interface(ip.IPv4Interface(P1_staticIR_dict['l2_vlan_ipv4_start'] + P1_staticIR_dict['l2_vlan_ipv4_mask']).network) + 60).ip)
        P2_MCast_start_ip = str((ip.IPv4Interface(ip.IPv4Interface(P1_MCast_dict['l2_vlan_ipv4_start'] + P1_staticIR_dict['l2_vlan_ipv4_mask']).network) + 60).ip)
        MCast2_grps_ip = str((ip.IPv4Interface(ip.IPv4Interface(P2_TGEN_dict['mcast_grp_ip'] + P1_MCast_dict['l2_vlan_ipv4_mask']).network) + 12801).ip)

        IGMP_dict_1 = {'ipv4_hndl'                  : IX_TP2['ipv4_handle'][0],
                     'igmp_ver'                     : P2_TGEN_dict['igmp_ver'],
                     'mcast_grp_ip'                 : P2_TGEN_dict['mcast_grp_ip'],
                     'mcast_grp_ip_step'            : P2_TGEN_dict['mcast_grp_ip_step'],
                     'no_of_grps'                   : P2_TGEN_dict['no_of_grps'],
                     'mcast_src_ip'                 : P2_staticIR_start_ip,
                     'mcast_src_ip_step'            : P2_TGEN_dict['v4_addr_step'],
                     'mcast_src_ip_step_per_port'   : P2_TGEN_dict['v4_addr_step'],
                     'mcast_grp_ip_step_per_port'   : P2_TGEN_dict['v4_addr_step'],
                     'mcast_no_of_srcs'             : P2_TGEN_dict['no_of_mcast_sources'],
                     'topology_handle'              : IX_TP2['topo_hndl']
                     }

        IGMP_dict_2 = {'ipv4_hndl'                  : IX_TP2['ipv4_handle'][1],
                     'igmp_ver'                     : P2_TGEN_dict['igmp_ver'],
                     'mcast_grp_ip'                 : MCast2_grps_ip,
                     'mcast_grp_ip_step'            : P2_TGEN_dict['mcast_grp_ip_step'],
                     'no_of_grps'                   : P2_TGEN_dict['no_of_grps'],
                     'mcast_src_ip'                 : P2_MCast_start_ip,
                     'mcast_src_ip_step'            : P2_TGEN_dict['v4_addr_step'],
                     'mcast_src_ip_step_per_port'   : P2_TGEN_dict['v4_addr_step'],
                     'mcast_grp_ip_step_per_port'   : P2_TGEN_dict['v4_addr_step'],
                     'mcast_no_of_srcs'             : P2_TGEN_dict['no_of_mcast_sources'],
                     'topology_handle'              : IX_TP2['topo_hndl']
                     }

        IGMP_EML_1 = ixLib.emulate_igmp_groupHost(IGMP_dict_1)
        IGMP_EML_2 = ixLib.emulate_igmp_groupHost(IGMP_dict_2)
        #ForkedPdb().set_trace()

        if IGMP_EML_1 == 0 and IGMP_EML_2 == 0:
            log.debug("Configuring IGMP failed")
            self.errored("Configuring IGMP failed", goto=['cleanup'])
        else:
            log.info("Configured IGMP Successfully")

        testscript.parameters['IX_TP2']['igmpHost_handle'] = []
        testscript.parameters['IX_TP2']['igmp_group_handle'] = []
        testscript.parameters['IX_TP2']['igmp_source_handle'] = []
        testscript.parameters['IX_TP2']['igmpMcastGrpList'] = []

        testscript.parameters['IX_TP2']['igmpHost_handle'].append(IGMP_EML_1['igmpHost_handle'])
        testscript.parameters['IX_TP2']['igmp_group_handle'].append(IGMP_EML_1['igmp_group_handle'])
        testscript.parameters['IX_TP2']['igmp_source_handle'].append(IGMP_EML_1['igmp_source_handle'])
        testscript.parameters['IX_TP2']['igmpMcastGrpList'].append(IGMP_EML_1['igmpMcastGrpList'])

        testscript.parameters['IX_TP2']['igmpHost_handle'].append(IGMP_EML_2['igmpHost_handle'])
        testscript.parameters['IX_TP2']['igmp_group_handle'].append(IGMP_EML_2['igmp_group_handle'])
        testscript.parameters['IX_TP2']['igmp_source_handle'].append(IGMP_EML_2['igmp_source_handle'])
        testscript.parameters['IX_TP2']['igmpMcastGrpList'].append(IGMP_EML_2['igmpMcastGrpList'])

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
            self.errored("Starting Protocols failed", goto=['cleanup'])
        else:
            log.info("Started Protocols Successfully")

        time.sleep(60)

        proto_result = ixLib.stop_protocols()
        if proto_result == 0:
            log.debug("Stopped Protocols failed")
            self.errored("Stopped Protocols failed", goto=['cleanup'])
        else:
            log.info("Stopped Protocols Successfully")

        time.sleep(30)

        proto_result = ixLib.start_protocols()
        if proto_result == 0:
            log.debug("Starting Protocols failed")
            self.errored("Starting Protocols failed", goto=['cleanup'])
        else:
            log.info("Started Protocols Successfully")

        time.sleep(120)

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class IXIA_CONFIGURATION_CONFIGURE_UCAST_IXIA_TRAFFIC(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONFIGURE_UCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']

            UCAST_v4_dict = {   'src_hndl'  : IX_TP1['ipv4_handle'],
                                'dst_hndl'  : IX_TP2['ipv4_handle'],
                                'circuit'   : 'ipv4',
                                'TI_name'   : "UCAST_V4",
                                'rate_pps'  : "1000",
                                'bi_dir'    : 1
                          }

            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
                                'dst_hndl'  : IX_TP2['ipv6_handle'],
                                'circuit'   : 'ipv6',
                                'TI_name'   : "UCAST_V6",
                                'rate_pps'  : "1000",
                                'bi_dir'    : 1
                          }

            UCAST_v4_TI = ixLib.configure_ixia_traffic_item(UCAST_v4_dict)
            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)

            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
                log.debug("Configuring UCast TI failed")
                self.errored("Configuring UCast TI failed", goto=['cleanup'])

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

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

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']

            BCAST_v4_dict = {
                                'src_hndl'      : IX_TP1['port_handle'],
                                'dst_hndl'      : IX_TP2['port_handle'],
                                'TI_name'       : "BCAST_V4",
                                'frame_size'    : "70",
                                'rate_pps'      : "1000",
                                'src_mac'       : "00:00:25:00:00:01",
                                'srcmac_step'   : "00:00:00:00:00:01",
                                'srcmac_count'  : "100",
                                'vlan_id'       : str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']),
                                'vlanid_step'   : "1",
                                'vlanid_count'  : "100",
                                'ip_src_addrs'  : "3.1.1.10",
                                'ip_step'       : "0.0.1.0",
                          }

            BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)

            if BCAST_v4_TI == 0:
                log.debug("Configuring BCast TI failed")
                self.errored("Configuring BCast TI failed", goto=['cleanup'])

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class IXIA_CONFIGURATION_CONFIGURE_UNKNOWN_UCAST_IXIA_TRAFFIC(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONFIGURE_UNKNOWN_UCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']

            UNKNOWN_UCAST_v4_dict = {
                                'src_hndl'      : IX_TP1['port_handle'],
                                'dst_hndl'      : IX_TP2['port_handle'],
                                'TI_name'       : "UKNOWN_UCAST_V4",
                                'frame_size'    : "64",
                                'rate_pps'      : "1000",
                                'dst_mac'       : "00:00:29:00:00:01",
                                'dstmac_step'   : "00:00:00:00:00:01",
                                'dstmac_count'  : "100",
                                'src_mac'       : "00:00:28:00:00:01",
                                'srcmac_step'   : "00:00:00:00:00:01",
                                'srcmac_count'  : "100",
                                'vlan_id'       : str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']),
                                'vlanid_step'   : "1",
                                'vlanid_count'  : "100",
                          }

            UNKNOWN_UCAST_v4_TI = ixLib.configure_ixia_UNKNOWN_UCAST_traffic_item(UNKNOWN_UCAST_v4_dict)

            if UNKNOWN_UCAST_v4_TI == 0:
                log.debug("Configuring UNKNOWN_UCAST TI failed")
                self.errored("Configuring UNKNOWN_UCAST TI failed", goto=['cleanup'])

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class IXIA_CONFIGURATION_CONFIGURE_MCAST_IXIA_TRAFFIC(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONFIGURE_MCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']

            # Creating TAGs for SRC IP Handles
            TAG_dict = {'subject_handle'            : IX_TP1['ipv4_handle'],
                        'topo_handle'               : IX_TP1['topo_hndl'],
                        'TAG_count_per_item'        : 50
            }

            SRC_IP_TAG = ixLib.configure_tag_config_multiplier(TAG_dict)
            if SRC_IP_TAG == 0:
                log.debug("Configuring TAGS for SRC IP failed")

            # Creating TAGs for DST IP Handles
            TAG_dict = {'subject_handle'            : IX_TP2['ipv4_handle'],
                        'topo_handle'               : IX_TP2['topo_hndl'],
                        'TAG_count_per_item'        : 50
            }

            DST_IP_TAG = ixLib.configure_tag_config_multiplier(TAG_dict)
            if DST_IP_TAG == 0:
                log.debug("Configuring TAGS for DST IP failed")

            # Creating TAGs for IGMP Host Handles
            TAG_dict = {'subject_handle'            : IX_TP2['igmp_group_handle'],
                        'topo_handle'               : IX_TP2['topo_hndl'],
                        'TAG_count_per_item'        : 50
            }

            IGMP_Host_TAG = ixLib.configure_tag_config_multiplier(TAG_dict)
            if IGMP_Host_TAG == 0:
                log.debug("Configuring TAGS for IGMP Hosts failed")

            MCAST_dict = {'src_ipv4_topo_handle'    : IX_TP1['topo_hndl'],
                          'total_tags'              : 100,
                          'TI_name'                 : "M_cast",
                          'rate_pps'                : "1000",
                          'frame_size'              : "70",
                          }

            MCAST_TI = ixLib.configure_v4_mcast_traffic_item_per_tag(MCAST_dict)

            if MCAST_TI == 0:
                log.debug("Configuring MCast TI failed")
                self.errored("Configuring MCast TI failed", goto=['cleanup'])

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class IXIA_CONFIGURATION_APPLY_VERIFY_TRAFFIC(aetest.Testcase):
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
            self.errored("Applying IXIA TI failed", goto=['cleanup'])

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2,3) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class TC001_VERIFY_L2_VLAN_SHUT_NO_SHUT(aetest.Testcase):
    """ L2_DISRUPTIVE_VERIFICATION - verify_L2_VLAN_shut_no_shut  """

    @aetest.setup
    def TRIGGER_verify_L2_VLAN_shut_no_shut(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify L2 VLAN shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        # ----------------------------------------------------
        # Counter Variables
        # ----------------------------------------------------
        vlan_id_start = testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']
        vlan_id_stop = int(vlan_id_start) + int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])
        vlan_id_stop = int(vlan_id_stop) + int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])

        staticIR_l2_vlan_id = testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']
        Mcast_l2_vlan_id = testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vlan_start']

        # ----------------------------------------------------
        # Perform VLAN shut on LEAF-1 and LEAF-2
        # ---------------------------------------------------

        LEAF_1.configure('''vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                                        shut''')

        LEAF_2.configure('''vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                                        shut''')
        time.sleep(30)

        # ----------------------------------------------------
        # Verify SVI on LEAF-1 and LEAF-2
        # ---------------------------------------------------
        staticIR_l2_vlan_count = int(staticIR_l2_vlan_id) + int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])
        while staticIR_l2_vlan_id < staticIR_l2_vlan_count:

            LEAF_1_l2vlan_out = LEAF_1.execute("sh int vlan " + str(staticIR_l2_vlan_id) + " brief | xml | i i 'state>'")
            LEAF_2_l2vlan_out = LEAF_2.execute("sh int vlan " + str(staticIR_l2_vlan_id) + " brief | xml | i i 'state>'")

            if (">down<" in LEAF_1_l2vlan_out) and (">down<" in LEAF_2_l2vlan_out):
                log.info("LEAF-1 and LEAF-2 L2 VLAN is DOWN after shut/no-shut")
            else:
                log.debug("LEAF-1 and LEAF-2 L2 VLAN is not DOWN after shut/no-shut")

            staticIR_l2_vlan_id+=1

        Mcast_l2_vlan_count = int(Mcast_l2_vlan_id) + int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])
        while Mcast_l2_vlan_id < Mcast_l2_vlan_count:

            LEAF_1_l2vlan_out = LEAF_1.execute("sh int vlan " + str(Mcast_l2_vlan_id) + " brief | xml | i i 'state>'")
            LEAF_2_l2vlan_out = LEAF_2.execute("sh int vlan " + str(Mcast_l2_vlan_id) + " brief | xml | i i 'state>'")

            if (">down<" in LEAF_1_l2vlan_out) and (">down<" in LEAF_2_l2vlan_out):
                log.info("LEAF-1 and LEAF-2 L2 VLAN is DOWN after shut/no-shut")
            else:
                log.debug("LEAF-1 and LEAF-2 L2 VLAN is not DOWN after shut/no-shut")

            Mcast_l2_vlan_id+=1

        # ----------------------------------------------------
        # Perform VLAN shut on LEAF-1 and LEAF-2
        # ---------------------------------------------------

        LEAF_1.configure('''vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                                        no shut''')

        LEAF_2.configure('''vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                                        no shut''')

        time.sleep(30)

        # ----------------------------------------------------
        # Verify SVI on LEAF-1 and LEAF-2
        # ---------------------------------------------------
        staticIR_l2_vlan_id = testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']
        Mcast_l2_vlan_id = testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vlan_start']

        staticIR_l2_vlan_count = int(staticIR_l2_vlan_id) + int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])
        while staticIR_l2_vlan_id < staticIR_l2_vlan_count:

            LEAF_1_l2vlan_out = LEAF_1.execute(
                "sh int vlan " + str(staticIR_l2_vlan_id) + " brief | xml | i i 'state>'")
            LEAF_2_l2vlan_out = LEAF_2.execute(
                "sh int vlan " + str(staticIR_l2_vlan_id) + " brief | xml | i i 'state>'")

            if (">up<" in LEAF_1_l2vlan_out) and (">up<" in LEAF_2_l2vlan_out):
                log.info("LEAF-1 and LEAF-2 L2 VLAN is UP after shut/no-shut")
            else:
                log.debug("LEAF-1 and LEAF-2 L2 VLAN is not UP after shut/no-shut")

            staticIR_l2_vlan_id += 1

        Mcast_l2_vlan_count = int(Mcast_l2_vlan_id) + int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])
        while Mcast_l2_vlan_id < Mcast_l2_vlan_count:

            LEAF_1_l2vlan_out = LEAF_1.execute("sh int vlan " + str(Mcast_l2_vlan_id) + " brief | xml | i i 'state>'")
            LEAF_2_l2vlan_out = LEAF_2.execute("sh int vlan " + str(Mcast_l2_vlan_id) + " brief | xml | i i 'state>'")

            if (">up<" in LEAF_1_l2vlan_out) and (">up<" in LEAF_2_l2vlan_out):
                log.info("LEAF-1 and LEAF-2 L2 VLAN is UP after shut/no-shut")
            else:
                log.debug("LEAF-1 and LEAF-2 L2 VLAN is not UP after shut/no-shut")

            Mcast_l2_vlan_id += 1

        time.sleep(30)

    @aetest.test
    def verify_HSRP(self, testscript):
        """ VERIFY_NETWORK subsection: Verify HSRP """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        hsrp_arg_dict = {
            'dut_1'         : LEAF_1,
            'dut_2'         : LEAF_2,
            'vlan_start'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']),
            'vlan_count'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])+int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])
        }

        hsrpValidation = verifyFnL.verifyFnLHSRP(hsrp_arg_dict)

        if hsrpValidation['status']:
            log.info("PASS : Successfully verified HSRP Data\n\n")
            self.passed(reason=hsrpValidation['log'])
        else:
            log.info("FAIL : Failed to verify HSRP Data\n\n")
            self.failed(reason=hsrpValidation['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
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
class TC002_VERIFY_L2_VLAN_SUSPEND_RESUME(aetest.Testcase):
    """ L2_DISRUPTIVE_VERIFICATION - verify_L2_VLAN_suspend_resume  """

    @aetest.setup
    def TRRIGGER_verify_L2_VLAN_suspend_resume(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify L2 VLAN suspend and resume """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        # ----------------------------------------------------
        # Counter Variables
        # ----------------------------------------------------
        vlan_id_start = testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']
        vlan_id_stop = int(vlan_id_start) + int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])
        vlan_id_stop = int(vlan_id_stop) + int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])

        staticIR_l2_vlan_id = testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']
        Mcast_l2_vlan_id = testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vlan_start']

        # ----------------------------------------------------
        # Perform VLAN shut on LEAF-1 and LEAF-2
        # ---------------------------------------------------

        LEAF_1.configure('''vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                                        state suspend''')

        LEAF_2.configure('''vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                                        state suspend''')
        time.sleep(30)

        LEAF_1.configure('''vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                                        no state suspend''')

        LEAF_2.configure('''vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                                        no state suspend''')

        # ----------------------------------------------------
        # Verify SVI on LEAF-1 and LEAF-2
        # ---------------------------------------------------
        staticIR_l2_vlan_count = int(staticIR_l2_vlan_id) + int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])
        while staticIR_l2_vlan_id < staticIR_l2_vlan_count:

            LEAF_1_l2vlan_out = LEAF_1.execute(
                "sh int vlan " + str(staticIR_l2_vlan_id) + " brief | xml | i i 'state>'")
            LEAF_2_l2vlan_out = LEAF_2.execute(
                "sh int vlan " + str(staticIR_l2_vlan_id) + " brief | xml | i i 'state>'")

            if (">up<" in LEAF_1_l2vlan_out) and (">up<" in LEAF_2_l2vlan_out):
                log.info("LEAF-1 and LEAF-2 L2 VLAN is UP after shut/no-shut")
            else:
                log.debug("LEAF-1 and LEAF-2 L2 VLAN is not UP after shut/no-shut")
                self.failed("LEAF-1 and LEAF-2 L2 VLAN is not UP after shut/no-shut")

            staticIR_l2_vlan_id += 1

        Mcast_l2_vlan_count = int(Mcast_l2_vlan_id) + int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])
        while Mcast_l2_vlan_id < Mcast_l2_vlan_count:

            LEAF_1_l2vlan_out = LEAF_1.execute("sh int vlan " + str(Mcast_l2_vlan_id) + " brief | xml | i i 'state>'")
            LEAF_2_l2vlan_out = LEAF_2.execute("sh int vlan " + str(Mcast_l2_vlan_id) + " brief | xml | i i 'state>'")

            if (">up<" in LEAF_1_l2vlan_out) and (">up<" in LEAF_2_l2vlan_out):
                log.info("LEAF-1 and LEAF-2 L2 VLAN is UP after shut/no-shut")
            else:
                log.debug("LEAF-1 and LEAF-2 L2 VLAN is not UP after shut/no-shut")
                self.failed("LEAF-1 and LEAF-2 L2 VLAN is not UP after shut/no-shut")

            Mcast_l2_vlan_id += 1

        time.sleep(30)

    @aetest.test
    def verify_HSRP(self, testscript):
        """ VERIFY_NETWORK subsection: Verify HSRP """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        hsrp_arg_dict = {
            'dut_1'         : LEAF_1,
            'dut_2'         : LEAF_2,
            'vlan_start'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']),
            'vlan_count'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])+int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])
        }

        hsrpValidation = verifyFnL.verifyFnLHSRP(hsrp_arg_dict)

        if hsrpValidation['status']:
            log.info("PASS : Successfully verified HSRP Data\n\n")
            self.passed(reason=hsrpValidation['log'])
        else:
            log.info("FAIL : Failed to verify HSRP Data\n\n")
            self.failed(reason=hsrpValidation['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
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
class TC003_VERIFY_VPC_ACCESS_PO_SHUT_NO_SHUT(aetest.Testcase):
    """ L2_DISRUPTIVE_VERIFICATION - verify_VPC_shut_no_shut  """

    @aetest.test
    def Trigger_VPC_PO_shut_no_shut(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC PO shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        vpc_po_num = testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Perform flap
        LEAF_1.configure('''
                      interface po'''+str(vpc_po_num)+'''
                      shut
                      no shut
                      ''')

        LEAF_2.configure('''
                      interface po'''+str(vpc_po_num)+'''
                      shut
                      no shut
                      ''')

        time.sleep(20)

    @aetest.test
    def VERIFY_VPC_STATE(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC post VPC PO shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify VPC
        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info("PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            log.info("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")
            self.failed()

    @aetest.test
    def VERIFY_VPC_PO_STATE(self, testscript):

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        vpc_po_num = testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the state
        LEAF_1_VPC_PO_out = LEAF_1.execute("sh int po"+str(vpc_po_num)+" brief | xml | i i 'state>'")
        LEAF_2_VPC_PO_out = LEAF_2.execute("sh int po"+str(vpc_po_num)+" brief | xml | i i 'state>'")

        if ">up<" in LEAF_1_VPC_PO_out:
            log.info("LEAF-1 VPC PO is UP after shut/no-shut")
        else:
            log.debug("LEAF-1 VPC PO is not UP after shut/no-shut")
            self.failed("LEAF-1 VPC PO is not UP after shut/no-shut", goto=['cleanup'])

        if ">up<" in LEAF_2_VPC_PO_out:
            log.info("LEAF-2 VPC PO is UP after shut/no-shut")
        else:
            log.debug("LEAF-2 VPC PO is not UP after shut/no-shut")
            self.failed("LEAF-2 VPC PO is not UP after shut/no-shut", goto=['cleanup'])

        time.sleep(60)

    @aetest.test
    def verify_HSRP(self, testscript):
        """ VERIFY_NETWORK subsection: Verify HSRP """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        hsrp_arg_dict = {
            'dut_1'         : LEAF_1,
            'dut_2'         : LEAF_2,
            'vlan_start'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']),
            'vlan_count'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])+int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])
        }

        hsrpValidation = verifyFnL.verifyFnLHSRP(hsrp_arg_dict)

        if hsrpValidation['status']:
            log.info("PASS : Successfully verified HSRP Data\n\n")
            self.passed(reason=hsrpValidation['log'])
        else:
            log.info("FAIL : Failed to verify HSRP Data\n\n")
            self.failed(reason=hsrpValidation['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):
        """ L2_DISRUPTIVE_VERIFICATION subsection: verify_traffic_post_VPC_PO_shut_no_shut """

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2,3) == 0:
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
class TC004_VERIFY_VPC_PEER_LINK_SHUT_NO_SHUT(aetest.Testcase):
    """ L2_DISRUPTIVE_VERIFICATION - verify_VPC_peer_link_shut_no_shut  """

    @aetest.test
    def TRIGGER_VPC_peer_link_shut_no_shut(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC Peer-Link shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']

        peer_link_po_num = testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Perform Flap
        LEAF_1.configure('''
                      interface po'''+str(peer_link_po_num)+'''
                      shut
                      no shut
                      ''')

        time.sleep(120)

    @aetest.test
    def VERIFY_VPC_STATE(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC post VPC PO shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify VPC
        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info("PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            log.info("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")
            self.failed()

    @aetest.test
    def VERIFY_VPC_PEER_LINK_STATE(self, testscript):

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        peer_link_po_num = testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the state
        LEAF_1_VPC_PL_out = LEAF_1.execute("sh int po"+str(peer_link_po_num)+" brief | xml | i i 'state>'")
        LEAF_2_VPC_PL_out = LEAF_2.execute("sh int po"+str(peer_link_po_num)+" brief | xml | i i 'state>'")

        if ">up<" in LEAF_1_VPC_PL_out:
            log.info("LEAF-1 VPC Peer-Link is UP after shut/no-shut")
        else:
            log.debug("LEAF-1 VPC Peer-Link is not UP after shut/no-shut")
            self.failed("LEAF-1 VPC Peer-Link is not UP after shut/no-shut", goto=['cleanup'])

        if ">up<" in LEAF_2_VPC_PL_out:
            log.info("LEAF-2 VPC Peer-Link is UP after shut/no-shut")
        else:
            log.debug("LEAF-2 VPC Peer-Link is not UP after shut/no-shut")
            self.failed("LEAF-2 VPC Peer-Link is not UP after shut/no-shut", goto=['cleanup'])

        time.sleep(20)

    @aetest.test
    def verify_HSRP(self, testscript):
        """ VERIFY_NETWORK subsection: Verify HSRP """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        hsrp_arg_dict = {
            'dut_1'         : LEAF_1,
            'dut_2'         : LEAF_2,
            'vlan_start'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']),
            'vlan_count'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])+int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])
        }

        hsrpValidation = verifyFnL.verifyFnLHSRP(hsrp_arg_dict)

        if hsrpValidation['status']:
            log.info("PASS : Successfully verified HSRP Data\n\n")
            self.passed(reason=hsrpValidation['log'])
        else:
            log.info("FAIL : Failed to verify HSRP Data\n\n")
            self.failed(reason=hsrpValidation['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify Traffic post VPC Peer-Link shut/no-shut """

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2,3) == 0:
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
class TC005_VERIFY_VPC_DOMAIN_SHUT_NO_SHUT(aetest.Testcase):
    """ L2_DISRUPTIVE_VERIFICATION - verify_VPC_domain_shut_no_shut  """

    @aetest.test
    def TRIGGER_verify_VPC_domain_shut_no_shut(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC domain shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        peer_link_po_num = testscript.parameters['LEAF_1_dict']['VPC_data']['domain_id']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Perform Flap
        LEAF_1.configure('''
                      vpc domain '''+str(peer_link_po_num)+'''
                      shut
                      no shut
                      ''')

        LEAF_2.configure('''
                      vpc domain '''+str(peer_link_po_num)+'''
                      shut
                      no shut
                      ''')

        time.sleep(120)

    @aetest.test
    def VERIFY_VPC_STATE(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC post VPC PO shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify VPC
        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info("PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(
                LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            log.info("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")
            self.failed()

    @aetest.test
    def verify_HSRP(self, testscript):
        """ VERIFY_NETWORK subsection: Verify HSRP """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        hsrp_arg_dict = {
            'dut_1'         : LEAF_1,
            'dut_2'         : LEAF_2,
            'vlan_start'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']),
            'vlan_count'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])+int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])
        }

        hsrpValidation = verifyFnL.verifyFnLHSRP(hsrp_arg_dict)

        if hsrpValidation['status']:
            log.info("PASS : Successfully verified HSRP Data\n\n")
            self.passed(reason=hsrpValidation['log'])
        else:
            log.info("FAIL : Failed to verify HSRP Data\n\n")
            self.failed(reason=hsrpValidation['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify Traffic post VPC domain shut/no-shut """

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2,3) == 0:
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
class TC006_VERIFY_HSRP_PRIORITY_SWAP(aetest.Testcase):
    """ L2_DISRUPTIVE_VERIFICATION - VERIFY_HSRP_PRIORITY_SWAP  """

    @aetest.test
    def TRIGGER_verify_HSRP_priority_swap(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC domain shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        hsrp_arg_dict = {
            'dut_1'         : LEAF_1,
            'dut_2'         : LEAF_2,
            'vlan_start'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']),
            'vlan_count'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])+int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])
        }

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Perform HSRP Swap
        for vlan in range(hsrp_arg_dict['vlan_start'], hsrp_arg_dict['vlan_start'] + hsrp_arg_dict['vlan_count'], 1):

            dev_1_hsrp_v4_json = json.loads(LEAF_1.execute('sh hsrp group ' + str(vlan) + ' brief ipv4 | json'))['TABLE_grp_detail']['ROW_grp_detail']
            dev_1_hsrp_v6_json = json.loads(LEAF_1.execute('sh hsrp group ' + str(vlan) + ' brief ipv6 | json'))['TABLE_grp_detail']['ROW_grp_detail']

            dev_1_v4_hsrp_priority = dev_1_hsrp_v4_json['sh_prio']
            dev_1_v6_hsrp_priority = dev_1_hsrp_v6_json['sh_prio']

            dev_2_hsrp_v4_json = json.loads(LEAF_2.execute('sh hsrp group ' + str(vlan) + ' brief ipv4 | json'))['TABLE_grp_detail']['ROW_grp_detail']
            dev_2_hsrp_v6_json = json.loads(LEAF_2.execute('sh hsrp group ' + str(vlan) + ' brief ipv6 | json'))['TABLE_grp_detail']['ROW_grp_detail']

            dev_2_v4_hsrp_priority = dev_2_hsrp_v4_json['sh_prio']
            dev_2_v6_hsrp_priority = dev_2_hsrp_v6_json['sh_prio']

            LEAF_1.configure("""
                interface vlan """+str(vlan)+"""
                    hsrp """+str(vlan)+""" ipv4
                        no priority
                        priority """+str(dev_2_v4_hsrp_priority)+"""
                    hsrp """+str(vlan)+""" ipv6
                        no priority
                        priority """+str(dev_2_v6_hsrp_priority)+"""
            """)

            LEAF_2.configure("""
                interface vlan """+str(vlan)+"""
                    hsrp """+str(vlan)+""" ipv4
                        no priority
                        priority """+str(dev_1_v4_hsrp_priority)+"""
                    hsrp """+str(vlan)+""" ipv6
                        no priority
                        priority """+str(dev_1_v6_hsrp_priority)+"""
            """)

        time.sleep(60)

    @aetest.test
    def VERIFY_VPC_STATE(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC post VPC PO shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify VPC
        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info("PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(
                LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            log.info("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")
            self.failed()

    @aetest.test
    def verify_HSRP(self, testscript):
        """ VERIFY_NETWORK subsection: Verify HSRP """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        hsrp_arg_dict = {
            'dut_1'         : LEAF_1,
            'dut_2'         : LEAF_2,
            'vlan_start'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']),
            'vlan_count'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])+int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])
        }

        hsrpValidation = verifyFnL.verifyFnLHSRP(hsrp_arg_dict)

        if hsrpValidation['status']:
            log.info("PASS : Successfully verified HSRP Data\n\n")
            self.passed(reason=hsrpValidation['log'])
        else:
            log.info("FAIL : Failed to verify HSRP Data\n\n")
            self.failed(reason=hsrpValidation['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify Traffic post VPC domain shut/no-shut """

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2,3) == 0:
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
class TC007_VERIFY_TOGGLE_FEATURE_HSRP(aetest.Testcase):
    """ L2_DISRUPTIVE_VERIFICATION - VERIFY_TOGGLE_FEATURE_HSRP  """

    @aetest.test
    def create_backup_HSRP_config_files(self, testscript):
        """ TRM_FEATURE_DISABLE_VERIFICATION subsection: Create backup config files in bootflash """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # delete any old file
        LEAF_1.configure("delete bootflash:automation_hsrp_test.txt no")
        LEAF_2.configure("delete bootflash:automation_hsrp_test.txt no")

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # copy configs to bootflash
        LEAF_1.configure("show running-config hsrp > bootflash:automation_hsrp_test.txt", timeout=600)
        LEAF_2.configure("show running-config hsrp > bootflash:automation_hsrp_test.txt", timeout=600)

    @aetest.test
    def TRIGGER_VERIFY_TOGGLE_FEATURE_HSRP(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC domain shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        LEAF_1.configure("no feature hsrp", timeout=300)
        LEAF_2.configure("no feature hsrp", timeout=300)

        time.sleep(60)

        LEAF_1.configure("copy bootflash:automation_hsrp_test.txt running-config echo-commands", timeout=600)
        LEAF_2.configure("copy bootflash:automation_hsrp_test.txt running-config echo-commands", timeout=600)
        LEAF_1.execute("copy r s", timeout=600)
        LEAF_2.execute("copy r s", timeout=600)

        time.sleep(120)

    @aetest.test
    def VERIFY_VPC_STATE(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC post VPC PO shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify VPC
        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info("PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(
                LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            log.info("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")
            self.failed()

    @aetest.test
    def verify_HSRP(self, testscript):
        """ VERIFY_NETWORK subsection: Verify HSRP """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        hsrp_arg_dict = {
            'dut_1'         : LEAF_1,
            'dut_2'         : LEAF_2,
            'vlan_start'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']),
            'vlan_count'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])+int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])
        }

        hsrpValidation = verifyFnL.verifyFnLHSRP(hsrp_arg_dict)

        if hsrpValidation['status']:
            log.info("PASS : Successfully verified HSRP Data\n\n")
            self.passed(reason=hsrpValidation['log'])
        else:
            log.info("FAIL : Failed to verify HSRP Data\n\n")
            self.failed(reason=hsrpValidation['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify Traffic post VPC domain shut/no-shut """

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2,3) == 0:
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
class TC008_VERIFY_HSRP_VIP_CHANGE_REVERT(aetest.Testcase):
    """ L2_DISRUPTIVE_VERIFICATION - VERIFY_TOGGLE_FEATURE_HSRP  """

    @aetest.test
    def TRIGGER_verify_HSRP_VIP_CHANGE(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify HSRP VIP change """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        hsrp_arg_dict = {
            'dut_1'         : LEAF_1,
            'dut_2'         : LEAF_2,
            'vlan_start'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']),
            'vlan_count'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])+int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])
        }

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Perform HSRP Swap
        for vlan in range(hsrp_arg_dict['vlan_start'], hsrp_arg_dict['vlan_start'] + hsrp_arg_dict['vlan_count'], 1):

            dev_1_hsrp_v4_json = json.loads(LEAF_1.execute('sh hsrp group ' + str(vlan) + ' brief ipv4 | json'))['TABLE_grp_detail']['ROW_grp_detail']
            dev_1_v6_hsrp_vip = str(LEAF_1.execute('sh hsrp group ' + str(vlan) + ' detail ipv6 | sec "Secondary" | in "[0-9A-z]+:"')).strip(' ')

            dev_1_v4_hsrp_vip_old = str(dev_1_hsrp_v4_json['sh_vip'])
            dev_1_v6_hsrp_vip_old = str(dev_1_v6_hsrp_vip)
            dev_1_v4_hsrp_vip_new = str(ip.IPv4Address(dev_1_hsrp_v4_json['sh_vip'])+99)
            dev_1_v6_hsrp_vip_new = str(ip.IPv6Address(dev_1_v6_hsrp_vip)+99)

            dev_2_hsrp_v4_json = json.loads(LEAF_2.execute('sh hsrp group ' + str(vlan) + ' brief ipv4 | json'))['TABLE_grp_detail']['ROW_grp_detail']
            dev_2_v6_hsrp_vip = str(LEAF_2.execute('sh hsrp group ' + str(vlan) + ' detail ipv6 | sec "Secondary" | in "[0-9A-z]+:"')).strip(' ')

            dev_2_v4_hsrp_vip_old = str(dev_2_hsrp_v4_json['sh_vip'])
            dev_2_v6_hsrp_vip_old = str(dev_2_v6_hsrp_vip)
            dev_2_v4_hsrp_vip_new = str(ip.IPv4Address(dev_2_hsrp_v4_json['sh_vip'])+99)
            dev_2_v6_hsrp_vip_new = str(ip.IPv6Address(dev_2_v6_hsrp_vip)+99)

            LEAF_1.configure("""
                interface vlan """+str(vlan)+"""
                    hsrp """+str(vlan)+""" ipv4
                        no ip """+str(dev_1_v4_hsrp_vip_old)+"""
                        ip """+str(dev_1_v4_hsrp_vip_new)+"""
                    hsrp """+str(vlan)+""" ipv6
                        no ip """+str(dev_1_v6_hsrp_vip_old)+"""
                        ip """+str(dev_1_v6_hsrp_vip_new)+"""
            """)

            LEAF_2.configure("""
                interface vlan """+str(vlan)+"""
                    hsrp """+str(vlan)+""" ipv4
                        no ip """+str(dev_2_v4_hsrp_vip_old)+"""
                        ip """+str(dev_2_v4_hsrp_vip_new)+"""
                    hsrp """+str(vlan)+""" ipv6
                        no ip """+str(dev_2_v6_hsrp_vip_old)+"""
                        ip """+str(dev_2_v6_hsrp_vip_new)+"""
            """)

        time.sleep(60)

    @aetest.test
    def VERIFY_VPC_STATE(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC post VPC PO shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify VPC
        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info("PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(
                LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            log.info("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")
            self.failed()

    @aetest.test
    def verify_HSRP(self, testscript):
        """ VERIFY_NETWORK subsection: Verify HSRP """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        hsrp_arg_dict = {
            'dut_1'         : LEAF_1,
            'dut_2'         : LEAF_2,
            'vlan_start'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']),
            'vlan_count'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])+int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])
        }

        hsrpValidation = verifyFnL.verifyFnLHSRP(hsrp_arg_dict)

        if hsrpValidation['status']:
            log.info("PASS : Successfully verified HSRP Data\n\n")
            self.passed(reason=hsrpValidation['log'])
        else:
            log.info("FAIL : Failed to verify HSRP Data\n\n")
            self.failed(reason=hsrpValidation['log'])

    @aetest.test
    def TRIGGER_verify_HSRP_VIP_REVERT(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify HSRP VIP change """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        hsrp_arg_dict = {
            'dut_1'         : LEAF_1,
            'dut_2'         : LEAF_2,
            'vlan_start'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']),
            'vlan_count'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])+int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])
        }

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Perform HSRP Swap
        for vlan in range(hsrp_arg_dict['vlan_start'], hsrp_arg_dict['vlan_start'] + hsrp_arg_dict['vlan_count'], 1):

            dev_1_hsrp_v4_json = json.loads(LEAF_1.execute('sh hsrp group ' + str(vlan) + ' brief ipv4 | json'))['TABLE_grp_detail']['ROW_grp_detail']
            dev_1_v6_hsrp_vip = str(LEAF_1.execute('sh hsrp group ' + str(vlan) + ' detail ipv6 | sec "Secondary" | in "[0-9A-z]+:"')).strip(' ')

            dev_1_v4_hsrp_vip_old = str(dev_1_hsrp_v4_json['sh_vip'])
            dev_1_v6_hsrp_vip_old = str(dev_1_v6_hsrp_vip)
            dev_1_v4_hsrp_vip_new = str(ip.IPv4Address(dev_1_hsrp_v4_json['sh_vip'])-99)
            dev_1_v6_hsrp_vip_new = str(ip.IPv6Address(dev_1_v6_hsrp_vip)-99)

            dev_2_hsrp_v4_json = json.loads(LEAF_2.execute('sh hsrp group ' + str(vlan) + ' brief ipv4 | json'))['TABLE_grp_detail']['ROW_grp_detail']
            dev_2_v6_hsrp_vip = str(LEAF_2.execute('sh hsrp group ' + str(vlan) + ' detail ipv6 | sec "Secondary" | in "[0-9A-z]+:"')).strip(' ')

            dev_2_v4_hsrp_vip_old = str(dev_2_hsrp_v4_json['sh_vip'])
            dev_2_v6_hsrp_vip_old = str(dev_2_v6_hsrp_vip)
            dev_2_v4_hsrp_vip_new = str(ip.IPv4Address(dev_2_hsrp_v4_json['sh_vip'])-99)
            dev_2_v6_hsrp_vip_new = str(ip.IPv6Address(dev_2_v6_hsrp_vip)-99)

            LEAF_1.configure("""
                interface vlan """+str(vlan)+"""
                    hsrp """+str(vlan)+""" ipv4
                        no ip """+str(dev_1_v4_hsrp_vip_old)+"""
                        ip """+str(dev_1_v4_hsrp_vip_new)+"""
                    hsrp """+str(vlan)+""" ipv6
                        no ip """+str(dev_1_v6_hsrp_vip_old)+"""
                        ip """+str(dev_1_v6_hsrp_vip_new)+"""
            """)

            LEAF_2.configure("""
                interface vlan """+str(vlan)+"""
                    hsrp """+str(vlan)+""" ipv4
                        no ip """+str(dev_2_v4_hsrp_vip_old)+"""
                        ip """+str(dev_2_v4_hsrp_vip_new)+"""
                    hsrp """+str(vlan)+""" ipv6
                        no ip """+str(dev_2_v6_hsrp_vip_old)+"""
                        ip """+str(dev_2_v6_hsrp_vip_new)+"""
            """)

        time.sleep(60)

    @aetest.test
    def VERIFY_VPC_STATE_POST_REVERT(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC post VPC PO shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify VPC
        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info("PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(
                LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            log.info("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")
            self.failed()

    @aetest.test
    def verify_HSRP_POST_REVERT(self, testscript):
        """ VERIFY_NETWORK subsection: Verify HSRP """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        hsrp_arg_dict = {
            'dut_1'         : LEAF_1,
            'dut_2'         : LEAF_2,
            'vlan_start'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']),
            'vlan_count'    : int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count'])+int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['vlan_count'])
        }

        hsrpValidation = verifyFnL.verifyFnLHSRP(hsrp_arg_dict)

        if hsrpValidation['status']:
            log.info("PASS : Successfully verified HSRP Data\n\n")
            self.passed(reason=hsrpValidation['log'])
        else:
            log.info("FAIL : Failed to verify HSRP Data\n\n")
            self.failed(reason=hsrpValidation['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify Traffic post VPC domain shut/no-shut """

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2,3) == 0:
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
class TC009_VERIFY_SPINE_UPLINK_SHUT_NO_SHUT(aetest.Testcase):
    """ VXLAN_DISRUPTIVE_VERIFICATION - verify_uplink_to_SPINE_shut_no_shut """

    @aetest.test
    def TRIGGER_verify_uplink_to_SPINE_shut_no_shut(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify L2 VLAN SVI shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Perform Flap
        LEAF_1.configure('''
                      interface po'''+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])+'''
                      shut
                      no shut
                      ''', timeout=600)

        LEAF_2.configure('''
                      interface po'''+str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id'])+'''
                      shut
                      no shut
                      ''', timeout=600)

        LEAF_3.configure('''
                      interface po'''+str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id'])+'''
                      shut
                      no shut
                      ''', timeout=600)

        time.sleep(120)

    @aetest.test
    def VERIFY_SPINE_UPLINK_STATUS(self, testscript):

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the state
        LEAF_1_uplink_out = LEAF_1.execute("sh int po"+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])+" brief | xml | i i 'state>'")
        LEAF_2_uplink_out = LEAF_2.execute("sh int po"+str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id'])+" brief | xml | i i 'state>'")
        LEAF_3_uplink_out = LEAF_3.execute("sh int po"+str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id'])+" brief | xml | i i 'state>'")

        if ">up<" in LEAF_1_uplink_out:
            log.info("LEAF-1 Uplink is UP after shut/no-shut")
        else:
            log.debug("LEAF-1 Uplink is not UP after shut/no-shut")
            self.failed("LEAF-1 Uplink is not UP after shut/no-shut", goto=['cleanup'])

        if ">up<" in LEAF_2_uplink_out:
            log.info("LEAF-2 Uplink is UP after shut/no-shut")
        else:
            log.debug("LEAF-2 Uplink is not UP after shut/no-shut")
            self.failed("LEAF-2 Uplink is not UP after shut/no-shut", goto=['cleanup'])

        if ">up<" in LEAF_3_uplink_out:
            log.info("LEAF-3 Uplink is UP after shut/no-shut")
        else:
            log.debug("LEAF-3 Uplink is not UP after shut/no-shut")
            self.failed("LEAF-3 Uplink is not UP after shut/no-shut", goto=['cleanup'])

        time.sleep(120)

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyFnL.verifyFnLNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyFnL.verifyFnLVNIData(testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 3) == 0:
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
class TC010_VERIFY_NVE_INT_SHUT_NO_SHUT(aetest.Testcase):
    """ VXLAN_DISRUPTIVE_VERIFICATION - verify_NVE_INT_shut_no_shut """

    @aetest.test
    def TRIGGER_verify_NVE_INT_shut_no_shut(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify NVE Interface shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Perform Flap
        LEAF_1.configure('''
                      interface nve 1
                      shut
                      no shut
                      ''', timeout=600)

        LEAF_2.configure('''
                      interface nve 1
                      shut
                      no shut
                      ''', timeout=600)

        time.sleep(20)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the state
        LEAF_1_nve_out = LEAF_1.execute("sh int nve 1 brief | xml | i i state>")
        LEAF_2_nve_out = LEAF_2.execute("sh int nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_1_nve_out:
            log.info("NVE INT is UP after shut/no-shut")
        else:
            log.debug("NVE INT is not UP after shut/no-shut")
            self.failed("NVE INT is not UP after shut/no-shut", goto=['cleanup'])

        if ">up<" in LEAF_2_nve_out:
            log.info("NVE INT is UP after shut/no-shut")
        else:
            log.debug("NVE INT is not UP after shut/no-shut")
            self.failed("NVE INT is not UP after shut/no-shut", goto=['cleanup'])

        time.sleep(200)

    @aetest.test
    def verify_NVE_peering_post_trigger(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyFnL.verifyFnLNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI_post_trigger(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyFnL.verifyFnLVNIData(testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2,3) == 0:
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
class TC011_VERIFY_NVE_SOURCE_INT_CHANGE(aetest.Testcase):
    """ VXLAN_DISRUPTIVE_VERIFICATION - verify_nve_source_int_change """

    @aetest.test
    def TRIGGER_verify_nve_source_int_change(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify L2 VLAN SVI shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Create a new loopback
        LEAF_3.configure('''
                        interface loopback2
                          ip address 2.30.30.30/32
                          ip ospf network point-to-point
                          ip router ospf '''+str(testscript.parameters['forwardingSysDict']['OSPF_AS'])+''' area 0.0.0.0
                          ip pim sparse-mode
                      ''', timeout=600)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Change NVE source loopback
        LEAF_1.configure('''
                        interface nve 1
                          shut''', timeout=600)

        LEAF_2.configure('''
                        interface nve 1
                          shut''', timeout=600)

        LEAF_3.configure('''
                        interface nve 1
                          shut
                          source-interface loopback2 ''', timeout=600)

        vni_id_iter = 0
        cfg_change = "interface nve 1"
        vni_id = testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start']
        while vni_id_iter < testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count']:
            cfg_change += """
                              member vni """ + str(vni_id) + """
                                ingress-replication protocol static
                                no peer-ip  """ + str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']) + """
                                peer-ip 2.30.30.30
                             """
            vni_id += 1
            vni_id_iter += 1

        LEAF_1.configure(cfg_change)
        LEAF_2.configure(cfg_change)

        LEAF_1.configure('''
                        interface nve 1
                          no shut
                          ''', timeout=600)

        LEAF_2.configure('''
                        interface nve 1
                          no shut
                          ''', timeout=600)

        LEAF_3.configure('''
                        interface nve 1
                          no shut
                          ''', timeout=600)

        time.sleep(60)

        LEAF_1.configure('''
                        interface nve 1
                          shut
                          no shut
                          ''', timeout=600)

        LEAF_2.configure('''
                        interface nve 1
                          shut
                          no shut
                          ''', timeout=600)

        LEAF_3.configure('''
                        interface nve 1
                          shut
                          no shut
                          ''', timeout=600)

        time.sleep(300)

    @aetest.test
    def verify_nve_source_int_change(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify L2 VLAN SVI shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify NVE UP
        LEAF_3_nve_out = LEAF_3.execute("sh int nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_3_nve_out:
            log.info("NVE INT is UP after shut/no-shut")
        else:
            log.debug("NVE INT is not UP after shut/no-shut")
            self.failed("NVE INT is not UP after shut/no-shut")

        time.sleep(120)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify NVE Peers with new IP 2.30.30.30
        #LEAF_1_NVE_data = LEAF_1.execute("sh nve peers peer-ip " + str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']) + " detail | xml | i i peer-state")
        #LEAF_2_NVE_data = LEAF_2.execute("sh nve peers peer-ip " + str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']) + " detail | xml | i i peer-state")

        LEAF_1_NVE_data = LEAF_1.execute("sh nve peers peer-ip 2.30.30.30 detail | xml | i i peer-state")
        LEAF_2_NVE_data = LEAF_2.execute("sh nve peers peer-ip 2.30.30.30 detail | xml | i i peer-state")

        if "Up" in LEAF_1_NVE_data:
            log.info("PASS : Successfully verified NVE Peering for LEAF-1\n\n")
        else:
            log.info("FAIL : Failed to verify NVE Peering for LEAF-1\n\n")
            self.failed()

        if "Up" in LEAF_2_NVE_data:
            log.info("PASS : Successfully verified NVE Peering for LEAF-2\n\n")
        else:
            log.info("FAIL : Failed to verify NVE Peering for LEAF-2\n\n")
            self.failed()

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def REVERT_vni_mcast_grp(self, testscript):

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Change NVE source loopback
        LEAF_1.configure('''
                        interface nve 1
                          shut''', timeout=600)

        LEAF_2.configure('''
                        interface nve 1
                          shut''', timeout=600)

        LEAF_3.configure('''
                        no interface loopback2
                        interface nve 1
                          shut
                          source-interface ''' + str(testscript.parameters['LEAF_3_dict']['NVE_data']['src_loop']) + '''
                      ''', timeout=600)

        vni_id_iter = 0
        cfg_change = ""
        vni_id = testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start']
        while vni_id_iter < testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['vlan_count']:
            cfg_change += """
                            interface nve 1
                              member vni """ + str(vni_id) + """
                                ingress-replication protocol static
                                no peer-ip 2.30.30.30
                                peer-ip  """ + str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']) + """
                             """
            vni_id += 1
            vni_id_iter += 1

        LEAF_1.configure(cfg_change)
        LEAF_2.configure(cfg_change)

        LEAF_1.configure('''
                        interface nve 1
                          no shut
                          ''', timeout=600)

        LEAF_2.configure('''
                        interface nve 1
                          no shut
                          ''', timeout=600)

        LEAF_3.configure('''
                        interface nve 1
                          no shut
                          ''', timeout=600)

        time.sleep(120)

    @aetest.test
    def verify_NVE_peering_post_revert(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyFnL.verifyFnLNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI_post_revert(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyFnL.verifyFnLVNIData(testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_TRAFFIC_post_revert(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 3) == 0:
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
class TC012_VERIFY_CHANGE_VNI_MCAST_GRP(aetest.Testcase):
    """ VXLAN_DISRUPTIVE_VERIFICATION - verify_change_vni_mcast_grp """

    @aetest.test
    def TRIGGER_verify_change_vni_mcast_grp(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify change in VNI MCast group """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        MCAST_vni = testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_start']
        MCAST_vni_umcast_ip = ip.IPv4Interface(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_mcast_ip'])

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Restart BGP
        LEAF_1.configure("""
                        interface nve1
                        shut
                          member vni """ +str(MCAST_vni)+ """
                            mcast-group """ + str((MCAST_vni_umcast_ip+100).ip) + """                        
                        no shut
                         """, timeout=600)

        LEAF_2.configure("""
                        interface nve1
                        shut
                          member vni """ +str(MCAST_vni)+ """
                            mcast-group """ + str((MCAST_vni_umcast_ip+100).ip) + """
                        no shut
                         """, timeout=600)

        LEAF_3.configure("""
                        interface nve1
                        shut
                          member vni """ +str(MCAST_vni)+ """
                            mcast-group """ + str((MCAST_vni_umcast_ip+100).ip) + """
                        no shut
                         """, timeout=600)

        time.sleep(30)

    @aetest.test
    def verify_NVE_peering_post_trigger(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyFnL.verifyFnLNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI_post_trigger(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        temp_leaves_dict = {}
        testIter = 0
        for key in testscript.parameters['leavesDict'].keys():
            temp_leaves_dict[key] = copy.deepcopy(testscript.parameters['leavesDictList'][testIter])
            testIter+=1

        vniStatusMsgs = ""
        vniStatusFlag = []
        new_staticIR_l2_vni = str(int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start'])+500)
        l2_vlan_id = str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start'])
        log.info("=== verifying the new StaticIR VNI ===")
        for leaf in temp_leaves_dict.keys():

            # Get VNI data
            vniStatusMsgs += "For VNI --> " + str(new_staticIR_l2_vni) + "\n"
            vniData = leaf.execute("sh nve vni " + str(new_staticIR_l2_vni) + " | xml | i '<vni>|state>|<type>|<mcast>'")

            # Verify VNI state to be UP
            if re.search("<vni-state>Up<", vniData, re.I):
                vniStatusMsgs += "\t PASS : VNI State is UP\n"
                vniStatusFlag.append(1)
            else:
                vniStatusMsgs += "\t FAIL : VNI State is not UP\n"
                vniStatusFlag.append(0)

            # Verify MCAST type to be UnicastStatic
            if re.search("<mcast>UnicastStatic", vniData, re.I):
                vniStatusMsgs += "\t PASS : VNI MCAST Type (UnicastStatic) Match Verified Successfully\n"
                vniStatusFlag.append(1)
            else:
                vniStatusMsgs += "\t FAIL : VNI MCAST Type (UnicastStatic) Match Failed\n"
                vniStatusFlag.append(0)

            # Verify VNI type to be L2/L3
            if re.search("<type>L2", vniData, re.I):
                vniStatusMsgs += "\t PASS : VNI Type (L2) Match Verified Successfully\n"
                vniStatusFlag.append(1)
            else:
                vniStatusMsgs += "\t FAIL : VNI Type (L2) Match Failed\n"
                vniStatusFlag.append(0)

            if re.search("\[" + str(l2_vlan_id) + "\]</type>", vniData, re.I):
                vniStatusMsgs += "\t PASS : L2 VLAN ID Mapping Verified Successfully\n"
                vniStatusFlag.append(1)
            else:
                vniStatusMsgs += "\t FAIL : L2 VLAN ID Mapping Failed\n"
                vniStatusFlag.append(0)

        new_Mcast_l2_vni = str(int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_start'])+500)
        l2_vlan_id = str(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vlan_start'])
        test_MCAST_umcast_ip = ip.IPv4Interface(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_mcast_ip'])
        log.info("=== verifying the new MCast VNI ===")
        for leaf in temp_leaves_dict.keys():
            # Get L3 VNI data
            vniStatusMsgs += "For VNI --> " + str(new_Mcast_l2_vni) + "\n"
            vniData = leaf.execute("sh nve vni " + str(new_Mcast_l2_vni) + " | xml | i '<vni>|state>|<type>|<mcast>'")

            # Verify VNI state to be UP
            if re.search("<vni-state>Up<", vniData, re.I):
                vniStatusMsgs += "\t PASS : VNI State is UP\n"
                vniStatusFlag.append(1)
            else:
                vniStatusMsgs += "\t FAIL : VNI State is not UP\n"
                vniStatusFlag.append(0)

            if re.search("<mcast>" + str((test_MCAST_umcast_ip+100).ip) + "<", vniData, re.I):
                vniStatusMsgs += "\t PASS : VNI Mcast IP (" + str((test_MCAST_umcast_ip+100).ip) + ") Match Verified Successfully\n"
                vniStatusFlag.append(1)
            else:
                vniStatusMsgs += "\t FAIL : VNI Mcast IP Match Failed\n"
                vniStatusFlag.append(0)

            # Verify VNI type to be L2/L3
            if re.search("<type>L2", vniData, re.I):
                vniStatusMsgs += "\t PASS : VNI Type (L2) Match Verified Successfully\n"
                vniStatusFlag.append(1)
            else:
                vniStatusMsgs += "\t FAIL : VNI Type (L2) Match Failed\n"
                vniStatusFlag.append(0)

            if re.search("\[" + str(l2_vlan_id) + "\]</type>", vniData, re.I):
                vniStatusMsgs += "\t PASS : L2 VLAN ID Mapping Verified Successfully\n"
                vniStatusFlag.append(1)
            else:
                vniStatusMsgs += "\t FAIL : L2 VLAN ID Mapping Failed\n"
                vniStatusFlag.append(0)

        if 0 in vniStatusFlag:
            log.info("FAIL : Failed to verify changed NVE VNI Data ======>\n\n")
            log.info(vniStatusMsgs)

        for leaf in temp_leaves_dict.keys():
            temp_leaves_dict[leaf]['STATIC_IR_VNI_data']['l2_vni_start'] += 2
            temp_leaves_dict[leaf]['STATIC_IR_VNI_data']['l2_vlan_start'] += 2
            temp_leaves_dict[leaf]['STATIC_IR_VNI_data']['vlan_count'] = 48
            temp_leaves_dict[leaf]['MCAST_VNI_data']['l2_vni_start'] += 2
            temp_leaves_dict[leaf]['MCAST_VNI_data']['l2_vlan_start'] += 2
            temp_leaves_dict[leaf]['MCAST_VNI_data']['vlan_count'] = 48
            temp_leaves_dict[leaf]['MCAST_VNI_data']['l2_vni_mcast_ip'] = '225.1.1.12'

        nveVniData = verifyFnL.verifyFnLVNIData(temp_leaves_dict)

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def REVERT_vni_mcast_grp(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify change in VNI MCast group """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        MCAST_vni = testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_start']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Restart BGP
        LEAF_1.configure("""
                        interface nve1
                          member vni """ + str(MCAST_vni) + """
                            no mcast-group
                            mcast-group """ + str(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_mcast_ip']) + """
                        shut
                        no shut
                         """, timeout=600)

        LEAF_2.configure("""
                        interface nve1
                          member vni """ + str(MCAST_vni) + """
                            no mcast-group
                            mcast-group """ + str(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_mcast_ip']) + """
                        shut
                        no shut
                         """, timeout=600)

        LEAF_3.configure("""
                        interface nve1
                          member vni """ + str(MCAST_vni) + """
                            no mcast-group
                            mcast-group """ + str(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_mcast_ip']) + """
                        shut
                        no shut
                         """, timeout=600)

        time.sleep(30)

    @aetest.test
    def verify_NVE_peering_post_revert(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyFnL.verifyFnLNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI_post_revert(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyFnL.verifyFnLVNIData(testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_TRAFFIC_after_revert(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2,3) == 0:
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
class TC013_VERIFY_CHANGE_VNI_VLAN_MAP(aetest.Testcase):
    """ VXLAN_DISRUPTIVE_VERIFICATION - verify_change_vni_vlan_map """

    @aetest.test
    def TRIGGER_verify_change_vni_vlan_map(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify Changing VLAN to VNI mapping (remove and re-add) """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        test_MCAST_umcast_ip = ip.IPv4Interface(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_mcast_ip'])

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Restart BGP
        LEAF_1.configure("""
                        vlan """ + str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']) + """
                          no vn-segment
                          vn-segment """ + str(int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start'])+500) + """
                        shut
                        no shut
                        
                        vlan """ + str(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vlan_start']) + """
                          no vn-segment
                          vn-segment """ + str(int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_start'])+500) + """
                        shut
                        no shut
                        
                        interface nve 1
                          member vni """ + str(int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start'])+500) + """
                            ingress-replication protocol static
                            peer-ip """ + str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']) + """
                          member vni """ + str(int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_start'])+500) + """
                            mcast-group """ + str((test_MCAST_umcast_ip+100).ip) + """
                        shut
                        no shut
                         """, timeout=600)

        LEAF_2.configure("""
                        vlan """ + str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']) + """
                          no vn-segment
                          vn-segment """ + str(int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start'])+500) + """
                        shut
                        no shut
                        
                        vlan """ + str(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vlan_start']) + """
                          no vn-segment
                          vn-segment """ + str(int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_start'])+500) + """
                        shut
                        no shut
                        
                        interface nve 1
                          member vni """ + str(int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start'])+500) + """
                            ingress-replication protocol static
                            peer-ip """ + str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']) + """
                          member vni """ + str(int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_start'])+500) + """
                            mcast-group """ + str((test_MCAST_umcast_ip+100).ip) + """
                        shut
                        no shut
                         """, timeout=600)

        LEAF_3.configure("""
                        vlan """ + str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']) + """
                          no vn-segment
                          vn-segment """ + str(int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start'])+500) + """
                        shut
                        no shut
                        
                        vlan """ + str(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vlan_start']) + """
                          no vn-segment
                          vn-segment """ + str(int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_start'])+500) + """
                        shut
                        no shut
                        
                        interface nve 1
                          member vni """ + str(int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start'])+500) + """
                            ingress-replication protocol static
                            peer-ip """ + str(testscript.parameters['LEAF_1_dict']['NVE_data']['VPC_VTEP_IP']) + """
                          member vni """ + str(int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_start'])+500) + """
                            mcast-group """ + str((test_MCAST_umcast_ip+100).ip) + """
                        shut
                        no shut
                         """, timeout=600)
        time.sleep(60)

    @aetest.test
    def verify_NVE_peering_post_trigger(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyFnL.verifyFnLNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI_post_trigger(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        temp_leaves_dict = {}
        testIter = 0
        for key in testscript.parameters['leavesDict'].keys():
            temp_leaves_dict[key] = copy.deepcopy(testscript.parameters['leavesDictList'][testIter])
            testIter+=1

        vniStatusMsgs = ""
        vniStatusFlag = []
        new_staticIR_l2_vni = str(int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start'])+500)
        l2_vlan_id = str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start'])
        log.info("=== verifying the new StaticIR VNI ===")
        for leaf in temp_leaves_dict.keys():

            # Get VNI data
            vniStatusMsgs += "For VNI --> " + str(new_staticIR_l2_vni) + "\n"
            vniData = leaf.execute("sh nve vni " + str(new_staticIR_l2_vni) + " | xml | i '<vni>|state>|<type>|<mcast>'")

            # Verify VNI state to be UP
            if re.search("<vni-state>Up<", vniData, re.I):
                vniStatusMsgs += "\t PASS : VNI State is UP\n"
                vniStatusFlag.append(1)
            else:
                vniStatusMsgs += "\t FAIL : VNI State is not UP\n"
                vniStatusFlag.append(0)

            # Verify MCAST type to be UnicastStatic
            if re.search("<mcast>UnicastStatic", vniData, re.I):
                vniStatusMsgs += "\t PASS : VNI MCAST Type (UnicastStatic) Match Verified Successfully\n"
                vniStatusFlag.append(1)
            else:
                vniStatusMsgs += "\t FAIL : VNI MCAST Type (UnicastStatic) Match Failed\n"
                vniStatusFlag.append(0)

            # Verify VNI type to be L2/L3
            if re.search("<type>L2", vniData, re.I):
                vniStatusMsgs += "\t PASS : VNI Type (L2) Match Verified Successfully\n"
                vniStatusFlag.append(1)
            else:
                vniStatusMsgs += "\t FAIL : VNI Type (L2) Match Failed\n"
                vniStatusFlag.append(0)

            if re.search("\[" + str(l2_vlan_id) + "\]</type>", vniData, re.I):
                vniStatusMsgs += "\t PASS : L2 VLAN ID Mapping Verified Successfully\n"
                vniStatusFlag.append(1)
            else:
                vniStatusMsgs += "\t FAIL : L2 VLAN ID Mapping Failed\n"
                vniStatusFlag.append(0)

        new_Mcast_l2_vni = str(int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_start'])+500)
        l2_vlan_id = str(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vlan_start'])
        test_MCAST_umcast_ip = ip.IPv4Interface(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_mcast_ip'])
        log.info("=== verifying the new MCast VNI ===")
        for leaf in temp_leaves_dict.keys():
            # Get L3 VNI data
            vniStatusMsgs += "For VNI --> " + str(new_Mcast_l2_vni) + "\n"
            vniData = leaf.execute("sh nve vni " + str(new_Mcast_l2_vni) + " | xml | i '<vni>|state>|<type>|<mcast>'")

            # Verify VNI state to be UP
            if re.search("<vni-state>Up<", vniData, re.I):
                vniStatusMsgs += "\t PASS : VNI State is UP\n"
                vniStatusFlag.append(1)
            else:
                vniStatusMsgs += "\t FAIL : VNI State is not UP\n"
                vniStatusFlag.append(0)

            if re.search("<mcast>" + str((test_MCAST_umcast_ip+100).ip) + "<", vniData, re.I):
                vniStatusMsgs += "\t PASS : VNI Mcast IP (" + str((test_MCAST_umcast_ip+100).ip) + ") Match Verified Successfully\n"
                vniStatusFlag.append(1)
            else:
                vniStatusMsgs += "\t FAIL : VNI Mcast IP Match Failed\n"
                vniStatusFlag.append(0)

            # Verify VNI type to be L2/L3
            if re.search("<type>L2", vniData, re.I):
                vniStatusMsgs += "\t PASS : VNI Type (L2) Match Verified Successfully\n"
                vniStatusFlag.append(1)
            else:
                vniStatusMsgs += "\t FAIL : VNI Type (L2) Match Failed\n"
                vniStatusFlag.append(0)

            if re.search("\[" + str(l2_vlan_id) + "\]</type>", vniData, re.I):
                vniStatusMsgs += "\t PASS : L2 VLAN ID Mapping Verified Successfully\n"
                vniStatusFlag.append(1)
            else:
                vniStatusMsgs += "\t FAIL : L2 VLAN ID Mapping Failed\n"
                vniStatusFlag.append(0)

        if 0 in vniStatusFlag:
            log.info("FAIL : Failed to verify changed NVE VNI Data ======>\n\n")
            log.info(vniStatusMsgs)

        for leaf in temp_leaves_dict.keys():
            temp_leaves_dict[leaf]['STATIC_IR_VNI_data']['l2_vni_start'] += 2
            temp_leaves_dict[leaf]['STATIC_IR_VNI_data']['l2_vlan_start'] += 2
            temp_leaves_dict[leaf]['STATIC_IR_VNI_data']['vlan_count'] = 48
            temp_leaves_dict[leaf]['MCAST_VNI_data']['l2_vni_start'] += 2
            temp_leaves_dict[leaf]['MCAST_VNI_data']['l2_vlan_start'] += 2
            temp_leaves_dict[leaf]['MCAST_VNI_data']['vlan_count'] = 48
            temp_leaves_dict[leaf]['MCAST_VNI_data']['l2_vni_mcast_ip'] = '225.1.1.12'

        nveVniData = verifyFnL.verifyFnLVNIData(temp_leaves_dict)

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2,3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def REVERT_vni_vlan_map(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify Changing VLAN to VNI mapping (remove and re-add) """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        LEAF_1.configure("""
                        vlan """ + str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']) + """
                          no vn-segment
                          vn-segment """ + str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start']) + """
                        shut
                        no shut
                        exit

                        vlan """ + str(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vlan_start']) + """
                          no vn-segment
                          vn-segment """ + str(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_start']) + """
                        shut
                        no shut
                        exit                        

                        interface nve 1
                          member vni """ + str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start']) + """
                          ingress-replication protocol static
                            peer-ip """ + str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']) + """
                          no member vni """ + str(int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start']) + 500) + """
                          no member vni """ + str(int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_start']) + 500) + """
                        shut
                        no shut
                         """, timeout=600)

        LEAF_2.configure("""
                        vlan """ + str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']) + """
                          no vn-segment
                          vn-segment """ + str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start']) + """
                        shut
                        no shut
                        exit

                        vlan """ + str(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vlan_start']) + """
                          no vn-segment
                          vn-segment """ + str(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_start']) + """
                        shut
                        no shut
                        exit

                        interface nve 1
                          member vni """ + str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start']) + """
                          ingress-replication protocol static
                            peer-ip """ + str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']) + """
                          no member vni """ + str(int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start']) + 500) + """
                          no member vni """ + str(int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_start']) + 500) + """
                        shut
                        no shut
                         """, timeout=600)

        LEAF_3.configure("""
                         vlan """ + str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vlan_start']) + """
                          no vn-segment
                          vn-segment """ + str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start']) + """
                        shut
                        no shut
                        exit

                        vlan """ + str(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vlan_start']) + """
                          no vn-segment
                          vn-segment """ + str(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_start']) + """
                        shut
                        no shut
                        exit

                        interface nve 1
                          member vni """ + str(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start']) + """
                          ingress-replication protocol static
                            peer-ip """ + str(testscript.parameters['LEAF_1_dict']['NVE_data']['VPC_VTEP_IP']) + """
                          no member vni """ + str(int(testscript.parameters['LEAF_1_dict']['STATIC_IR_VNI_data']['l2_vni_start']) + 500) + """
                          no member vni """ + str(int(testscript.parameters['LEAF_1_dict']['MCAST_VNI_data']['l2_vni_start']) + 500) + """
                        shut
                        no shut
                         """, timeout=600)

        time.sleep(60)
        
    @aetest.test
    def verify_NVE_peering_post_revert(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyFnL.verifyFnLNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI_post_revert(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyFnL.verifyFnLVNIData(testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_TRAFFIC_post_revert(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2,3) == 0:
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
class TC014_VERIFY_CLEAR_IGMP_SNOOPING_GROUPS_VLAN_ALL(aetest.Testcase):
    """ VXLAN_DISRUPTIVE_VERIFICATION - verify_clear_igmp_snooping_groups_vlan_all """

    @aetest.test
    def TRIGGER_verify_clear_igmp_snooping_groups_vlan_all(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify Clear IGMP Snooping Groups """

        ixLib.stop_protocols()
        LEAF_3 = testscript.parameters['LEAF-3']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Clear IGMP Snooping groups
        LEAF_3.configure('clear ip igmp snooping groups * vlan all', timeout=600)

        ixLib.start_protocols()
        time.sleep(120)

    @aetest.test
    def verify_igmp_joins_add_back(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify Clear IGMP Snooping Groups """

        LEAF_3 = testscript.parameters['LEAF-3']

        # ----------------------------------------------------
        # LEAF-3 Counter Variables
        # ----------------------------------------------------
        mcastGrp_IP = ip.IPv4Interface(testscript.parameters['LEAF_3_TGEN_dict']['mcast_grp_ip'])
        l2_vlan_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['STATIC_IR_VNI_data']['l2_vlan_start']
        mcastGrp_status = []
        # --------------------------------------------------------
        # Verify IGMP Snooping Groups fot StaticIR VLANs on LEAF-3
        # --------------------------------------------------------
        while l2_vlan_count_iter < testscript.parameters['LEAF_3_dict']['STATIC_IR_VNI_data']['vlan_count']:

            mcast_grp_output = LEAF_3.execute("sh ip igmp snoop groups vlan " + str(l2_vlan_id) + " | grep " + str(mcastGrp_IP.ip))
            if str(l2_vlan_id) in mcast_grp_output and str(mcastGrp_IP.ip) in mcast_grp_output:
                log.info("IP IGMP Snooping Groups is created in RCV - FHR Leaf")
            else:
                log.debug("IP IGMP Snooping Groups is not created in RCV - FHR Leaf")
                mcastGrp_status.append(0)

            l2_vlan_count_iter += 1
            l2_vlan_id += 1
            mcastGrp_IP += 256

        # ----------------------------------------------------
        # LEAF-3 Counter Variables
        # ----------------------------------------------------
        l2_vlan_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['MCAST_VNI_data']['l2_vlan_start']
        # --------------------------------------------------------
        # Verify IGMP Snooping Groups fot StaticIR VLANs on LEAF-3
        # --------------------------------------------------------
        while l2_vlan_count_iter < testscript.parameters['LEAF_3_dict']['MCAST_VNI_data']['vlan_count']:

            mcast_grp_output = LEAF_3.execute(
                "sh ip igmp snoop groups vlan " + str(l2_vlan_id) + " | grep " + str(mcastGrp_IP.ip))
            if str(l2_vlan_id) in mcast_grp_output and str(mcastGrp_IP.ip) in mcast_grp_output:
                log.info("IP IGMP Snooping Groups is created in RCV - FHR Leaf")
            else:
                log.debug("IP IGMP Snooping Groups is not created in RCV - FHR Leaf")
                mcastGrp_status.append(0)

            l2_vlan_count_iter += 1
            l2_vlan_id += 1
            mcastGrp_IP += 256

        if 0 in mcastGrp_status:
            self.failed("IP IGMP Snooping Groups verification Failed")

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
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
class TC015_VERIFY_CLEAR_IP_ROUTE_MROUTE_ALL(aetest.Testcase):
    """ VXLAN_DISRUPTIVE_VERIFICATION - verify_clear_igmp_snooping_groups_vlan_all """

    @aetest.test
    def TRIGGER_verify_clear_ip_route_mroute_all(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify Clear IGMP Snooping Groups """

        ixLib.stop_protocols()
        LEAF_3 = testscript.parameters['LEAF-3']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Clear IGMP Snooping groups
        LEAF_3.configure('clear ip route vrf all *', timeout=600)
        LEAF_3.configure('clear ip mroute * vrf all', timeout=600)

        ixLib.start_protocols()
        time.sleep(120)

    @aetest.test
    def verify_igmp_joins_add_back(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify Clear IGMP Snooping Groups """

        LEAF_3 = testscript.parameters['LEAF-3']

        # ----------------------------------------------------
        # LEAF-3 Counter Variables
        # ----------------------------------------------------
        mcastGrp_IP = ip.IPv4Interface(testscript.parameters['LEAF_3_TGEN_dict']['mcast_grp_ip'])
        l2_vlan_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['STATIC_IR_VNI_data']['l2_vlan_start']
        mcastGrp_status = []
        # --------------------------------------------------------
        # Verify IGMP Snooping Groups fot StaticIR VLANs on LEAF-3
        # --------------------------------------------------------
        while l2_vlan_count_iter < testscript.parameters['LEAF_3_dict']['STATIC_IR_VNI_data']['vlan_count']:

            mcast_grp_output = LEAF_3.execute(
                "sh ip igmp snoop groups vlan " + str(l2_vlan_id) + " | grep " + str(mcastGrp_IP.ip))
            if str(l2_vlan_id) in mcast_grp_output and str(mcastGrp_IP.ip) in mcast_grp_output:
                log.info("IP IGMP Snooping Groups is created in RCV - FHR Leaf")
            else:
                log.debug("IP IGMP Snooping Groups is not created in RCV - FHR Leaf")
                mcastGrp_status.append(0)

            l2_vlan_count_iter += 1
            l2_vlan_id += 1
            mcastGrp_IP += 256

        # ----------------------------------------------------
        # LEAF-3 Counter Variables
        # ----------------------------------------------------
        l2_vlan_count_iter = 0
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['MCAST_VNI_data']['l2_vlan_start']
        # --------------------------------------------------------
        # Verify IGMP Snooping Groups fot StaticIR VLANs on LEAF-3
        # --------------------------------------------------------
        while l2_vlan_count_iter < testscript.parameters['LEAF_3_dict']['MCAST_VNI_data']['vlan_count']:

            mcast_grp_output = LEAF_3.execute(
                "sh ip igmp snoop groups vlan " + str(l2_vlan_id) + " | grep " + str(mcastGrp_IP.ip))
            if str(l2_vlan_id) in mcast_grp_output and str(mcastGrp_IP.ip) in mcast_grp_output:
                log.info("IP IGMP Snooping Groups is created in RCV - FHR Leaf")
            else:
                log.debug("IP IGMP Snooping Groups is not created in RCV - FHR Leaf")
                mcastGrp_status.append(0)

            l2_vlan_count_iter += 1
            l2_vlan_id += 1
            mcastGrp_IP += 256

        if 0 in mcastGrp_status:
            self.failed("IP IGMP Snooping Groups verification Failed")

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed")
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
class TC016_CREATE_CONFIGURATION_BACKUP(aetest.Testcase):
    """TRM_FEATURE_DISABLE_VERIFICATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def create_backup_config_files(self, testscript):
        """ TRM_FEATURE_DISABLE_VERIFICATION subsection: Create backup config files in bootflash """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # delete any old file
        LEAF_1.configure("delete bootflash:automation_test.txt no")
        LEAF_2.configure("delete bootflash:automation_test.txt no")
        LEAF_3.configure("delete bootflash:automation_test.txt no")

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # copy configs to bootflash
        LEAF_1.configure("copy running-config bootflash:automation_test.txt", timeout=600)
        LEAF_2.configure("copy running-config bootflash:automation_test.txt", timeout=600)
        LEAF_3.configure("copy running-config bootflash:automation_test.txt", timeout=600)

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#
class TC017_VERIFY_FEATURE_DISABLE_ENABLE_NV_OVERLAY_VN_SEGMENT(aetest.Testcase):
    """verify_no_feature_nv_overlay_vn_segment"""

    @aetest.test
    def TRIGGER_verify_no_feature_nv_overlay_vn_segment(self, testscript):
        """ TRM_FEATURE_DISABLE_VERIFICATION subsection: Verify toggle of feature nv overlay, feature vn-segment-vlan-based """

        LEAF_3 = testscript.parameters['LEAF-3']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Remove feature nv overlay, vn-segment-vlan-based
        LEAF_3.configure("no feature nv overlay", timeout=300)
        LEAF_3.configure("no feature vn-segment-vlan-based", timeout=300)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the run conf
        LEAF_3_FT_nv_overlay_run_output = LEAF_3.execute("show run | grep 'feature nv overlay'")

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify in run conf that the feature is removed
        if "feature nv overlay" in LEAF_3_FT_nv_overlay_run_output:
            log.info(
                "Failed to verify removing configuring feature ngmvpn and feature present in running-config on LEAF_3")
        else:
            log.info(
                "Successfully verified removing configuring feature ngmvpn and feature not present in running-config on LEAF_3")

        time.sleep(40)
        LEAF_3.execute("copy r s")

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the start conf
        LEAF_3_FT_nv_overlay_start_output = LEAF_3.execute("show start | grep 'feature nv overlay'")

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify in start conf that the feature is removed
        if "feature nv overlay" in LEAF_3_FT_nv_overlay_start_output:
            log.info(
                "Failed to verify configuring removing feature nv overlay and feature present in startup-config on LEAF-3")
            self.failed()
        else:
            log.info(
                "Successfully verified removing configuring feature nv overlay and feature not present in startup-config on LEAF-3")

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Replay configurations
        LEAF_3.configure("copy bootflash:automation_test.txt running-config echo-commands", timeout=600)
        time.sleep(40)
        LEAF_3.execute("copy r s", timeout=600)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Start and stop the IGMP protocols on IXIA
        ixLib.stop_protocols()
        ixLib.start_protocols()

        time.sleep(20)

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyFnL.verifyFnLNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyFnL.verifyFnLVNIData(testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 3) == 0:
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
class TC018_VERIFY_NVE_PROCESS_RESTART(aetest.Testcase):
    """verify_nve_process_restart"""

    @aetest.test
    def TRIGGER_verify_nve_process_restart(self, testscript):
        """ TRM_PROCESS_KILL_VERIFICATION subsection: Verify killing process NVE """

        LEAF_3 = testscript.parameters['LEAF-3']

        if infraTrig.verifyProcessRestart(LEAF_3,"nve"):
            log.info("Successfully restarted process NVE")
        else:
            log.debug("Failed to restarted process NVE")
            self.failed("Failed to restarted process NVE", goto=['cleanup'])

        time.sleep(120)

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyFnL.verifyFnLNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyFnL.verifyFnLVNIData(testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        # Updating the exclude patter to account for process restart
        post_test_process_dict['exclude_log_check_pattern'] = 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|PEER_KEEP_ALIVE_RECV_FAIL|AUTHPRIV-2-SYSTEM_MSG|dcos_sshd|LICMGR-3-LOG_SMART_LIC_COMM_FAILED|POAP-2-POAP_FAILURE|SERVICE_TERMINATED: Service \"urib\"|signal 9 \(no core\)'
        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])
        # Resetting the exclude pattern
        post_test_process_dict['exclude_log_check_pattern'] = 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|PEER_KEEP_ALIVE_RECV_FAIL|AUTHPRIV-2-SYSTEM_MSG|dcos_sshd|LICMGR-3-LOG_SMART_LIC_COMM_FAILED|POAP-2-POAP_FAILURE'

# *****************************************************************************************************************************#
class TC019_VERIFY_IGMP_PROCESS_RESTART(aetest.Testcase):
    """verify_igmp_process_restart"""

    @aetest.test
    def TRIGGER_verify_igmp_process_restart(self, testscript):
        """ TRM_PROCESS_KILL_VERIFICATION subsection: Verify killing process IGMP """

        LEAF_3 = testscript.parameters['LEAF-3']

        if infraTrig.verifyProcessRestart(LEAF_3, "igmp"):
            log.info("Successfully restarted process IGMP")
        else:
            log.debug("Failed to restarted process IGMPP")
            self.failed("Failed to restarted process IGMP", goto=['cleanup'])

        time.sleep(60)

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyFnL.verifyFnLNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyFnL.verifyFnLVNIData(testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        # Updating the exclude patter to account for process restart
        post_test_process_dict['exclude_log_check_pattern'] = 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|PEER_KEEP_ALIVE_RECV_FAIL|AUTHPRIV-2-SYSTEM_MSG|dcos_sshd|LICMGR-3-LOG_SMART_LIC_COMM_FAILED|POAP-2-POAP_FAILURE|SERVICE_TERMINATED: Service \"urib\"|signal 9 \(no core\)|IGMP process has restarted'
        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])
        # Resetting the exclude pattern
        post_test_process_dict['exclude_log_check_pattern'] = 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|PEER_KEEP_ALIVE_RECV_FAIL|AUTHPRIV-2-SYSTEM_MSG|dcos_sshd|LICMGR-3-LOG_SMART_LIC_COMM_FAILED|POAP-2-POAP_FAILURE'

# *****************************************************************************************************************************#
class TC020_VERIFY_L2RIB_PROCESS_RESTART(aetest.Testcase):
    """verify_l2rib_process_restart"""

    @aetest.test
    def TRIGGER_verify_l2rib_process_restart(self, testscript):
        """ TRM_PROCESS_KILL_VERIFICATION subsection: Verify killing process L2RIB """

        LEAF_3 = testscript.parameters['LEAF-3']

        if infraTrig.verifyProcessRestart(LEAF_3, "l2rib"):
            log.info("Successfully restarted process L2RIB")
        else:
            log.debug("Failed to restarted process L2RIB")
            self.failed("Failed to restarted process L2RIB", goto=['cleanup'])

        time.sleep(60)

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyFnL.verifyFnLNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyFnL.verifyFnLVNIData(testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        # Updating the exclude patter to account for process restart
        post_test_process_dict['exclude_log_check_pattern'] = 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|PEER_KEEP_ALIVE_RECV_FAIL|AUTHPRIV-2-SYSTEM_MSG|dcos_sshd|LICMGR-3-LOG_SMART_LIC_COMM_FAILED|POAP-2-POAP_FAILURE|SERVICE_TERMINATED: Service \"urib\"|signal 9 \(no core\)|IGMP process has restarted'
        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])
        # Resetting the exclude pattern
        post_test_process_dict['exclude_log_check_pattern'] = 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|PEER_KEEP_ALIVE_RECV_FAIL|AUTHPRIV-2-SYSTEM_MSG|dcos_sshd|LICMGR-3-LOG_SMART_LIC_COMM_FAILED|POAP-2-POAP_FAILURE'

# *****************************************************************************************************************************#
class TC021_VERIFY_UFDM_PROCESS_RESTART(aetest.Testcase):
    """verify_ufdm_process_restart"""

    @aetest.test
    def TRIGGER_verify_ufdm_process_restart(self, testscript):
        """ TRM_PROCESS_KILL_VERIFICATION subsection: Verify killing process UFDM """

        LEAF_3 = testscript.parameters['LEAF-3']

        if infraTrig.verifyProcessRestart(LEAF_3, "ufdm"):
            log.info("Successfully restarted process UFDM")
        else:
            log.debug("Failed to restarted process UFDM")
            self.failed("Failed to restarted process UFDM", goto=['cleanup'])

        time.sleep(60)

    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyFnL.verifyFnLNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyFnL.verifyFnLVNIData(testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        # Updating the exclude patter to account for process restart
        post_test_process_dict['exclude_log_check_pattern'] = 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|PEER_KEEP_ALIVE_RECV_FAIL|AUTHPRIV-2-SYSTEM_MSG|dcos_sshd|LICMGR-3-LOG_SMART_LIC_COMM_FAILED|POAP-2-POAP_FAILURE|SERVICE_TERMINATED: Service \"urib\"|signal 9 \(no core\)'
        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])
        # Resetting the exclude pattern
        post_test_process_dict['exclude_log_check_pattern'] = 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED|PEER_KEEP_ALIVE_RECV_FAIL|AUTHPRIV-2-SYSTEM_MSG|dcos_sshd|LICMGR-3-LOG_SMART_LIC_COMM_FAILED|POAP-2-POAP_FAILURE'

# *****************************************************************************************************************************#
# <--- CC not supported on FnL Deployment
# class CC_04_VERIFY_CC(aetest.Testcase):
#     """ Consistency Checker - CC_04_VERIFY_CC  """
#
#     @aetest.test
#     def verify_CC(self, testscript):
#         """ VERIFY_NETWORK subsection: Verify CC """
#
#         # Using only cc_check
#         status = infraVerify.postTestVerification(cc_verification_dict)
#         if status['status'] == 0:
#             self.failed(reason=status['logs'])
#         else:
#             self.passed(reason=status['logs'])

# *****************************************************************************************************************************#
class TC022_vxlan_vpc_leaf1_LC_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf1LCReload(self, testscript):

        fail_flag = []
        status_msgs = ''
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

            reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += '''
                Reload of module '''+str(module)+''' : PASS
                ===========================================
                ''' + str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += '''
                Reload of module '''+str(module)+''' : FAIL
                ===========================================
                ''' + str(reload_status['logs'])

            time.sleep(60)
            status_msgs += '''
                    Traffic Check after Reload of module '''+str(module)+'''
                    --------------------------------------------------------
            '''
            if ixLib.verify_traffic(2,3) == 0:
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
class TC023_vxlan_vpc_leaf2_LC_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf2LCReload(self, testscript):

        fail_flag = []
        status_msgs = ''
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

            reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += '''
                Reload of module ''' + str(module) + ''' : PASS
                ===========================================
                ''' + str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += '''
                Reload of module ''' + str(module) + ''' : FAIL
                ===========================================
                ''' + str(reload_status['logs'])

            time.sleep(60)
            status_msgs += '''
                    Traffic Check after Reload of module ''' + str(module) + '''
                    --------------------------------------------------------
            '''
            if ixLib.verify_traffic(2, 3) == 0:
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
class TC024_vxlan_leaf3_LC_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf2LCReload(self, testscript):

        fail_flag = []
        status_msgs = ''
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

            reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += '''
                Reload of module ''' + str(module) + ''' : PASS
                ===========================================
                ''' + str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += '''
                Reload of module ''' + str(module) + ''' : FAIL
                ===========================================
                ''' + str(reload_status['logs'])

            time.sleep(60)
            status_msgs += '''
                    Traffic Check after Reload of module ''' + str(module) + '''
                    --------------------------------------------------------
            '''
            if ixLib.verify_traffic(2, 3) == 0:
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
class TC025_vxlan_vpc_leaf1_FM_all_reload(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf1FMReload(self, testscript):

        fail_flag = []
        status_msgs = ''
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

            reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : PASS
                ===========================================
                ''' + str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : FAIL
                ===========================================
                ''' + str(reload_status['logs'])

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
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
class TC026_vxlan_vpc_leaf2_FM_all_reload(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf2FMReload(self, testscript):

        fail_flag = []
        status_msgs = ''
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

            reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : PASS
                ===========================================
                ''' + str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : FAIL
                ===========================================
                ''' + str(reload_status['logs'])

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
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
class TC027_vxlan_leaf3_FM_all_reload(aetest.Testcase):

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf3FMReload(self, testscript):

        fail_flag = []
        status_msgs = ''
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

            reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : PASS
                ===========================================
                ''' + str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : FAIL
                ===========================================
                ''' + str(reload_status['logs'])

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
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
class TC028_vxlan_vpc_leaf1_SC_all_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf1SCReload(self, testscript):

        fail_flag = []
        status_msgs = ''
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

            reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : PASS
                ===========================================
                ''' + str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : FAIL
                ===========================================
                ''' + str(reload_status['logs'])

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
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
class TC029_vxlan_vpc_leaf2_SC_all_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf2SCReload(self, testscript):

        fail_flag = []
        status_msgs = ''
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

            reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : PASS
                ===========================================
                ''' + str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : FAIL
                ===========================================
                ''' + str(reload_status['logs'])

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
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
class TC030_vxlan_leaf3_SC_all_reload(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf3SCReload(self, testscript):

        fail_flag = []
        status_msgs = ''
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

            reload_status = infraEORTrigger.verifyModuleReload(mod_arg_dict)
            if reload_status['status']:
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : PASS
                ===========================================
                ''' + str(reload_status['logs'])
            else:
                fail_flag.append(0)
                status_msgs += '''
                Reload of FM ''' + str(module) + ''' : FAIL
                ===========================================
                ''' + str(reload_status['logs'])

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
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
class TC031_vxlan_vpc_leaf1_SSO(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf1SSO(self, testscript):

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_1.configure("copy r s")

        # Perform Device Reload
        result = infraEORTrigger.verifyDeviceSSO({'dut':LEAF_1})
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

        if ixLib.verify_traffic(2,3) == 0:
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
class TC032_vxlan_vpc_leaf2_SSO(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf2SSO(self, testscript):

        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_2.configure("copy r s")

        # Perform Device Reload
        result = infraEORTrigger.verifyDeviceSSO({'dut':LEAF_2})
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

        if ixLib.verify_traffic(2,3) == 0:
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
class TC033_vxlan_leaf3_SSO(aetest.Testcase):
    ###    This is description for my testcase two

    @aetest.setup
    def setup(self):
        pass

    @aetest.test
    def leaf3SSO(self, testscript):

        LEAF_3 = testscript.parameters['LEAF-3']
        LEAF_3.configure("copy r s")

        # Perform Device Reload
        result = infraEORTrigger.verifyDeviceSSO({'dut':LEAF_3})
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

        if ixLib.verify_traffic(2,3) == 0:
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
class TC034_VERIFY_VPC_PRIMARY_VTEP_DEVICE_RELOAD(aetest.Testcase):
    """HA_VERIFICATION"""

    @aetest.test
    def TRIGGER_verify_device_reload(self, testscript):
        """ HA_VERIFICATION subsection: Device Reload """

        LEAF_1 = testscript.parameters['LEAF-1']

        LEAF_1.configure("copy r s")

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
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyFnL.verifyFnLNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyFnL.verifyFnLVNIData(testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 3) == 0:
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
class TC035_VERIFY_VPC_SECONDARY_VTEP_DEVICE_RELOAD(aetest.Testcase):
    """HA_VERIFICATION"""

    @aetest.test
    def TRIGGER_verify_device_reload(self, testscript):
        """ HA_VERIFICATION subsection: Device Reload """

        LEAF_2 = testscript.parameters['LEAF-2']

        LEAF_2.configure("copy r s")

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
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyFnL.verifyFnLNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyFnL.verifyFnLVNIData(testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 3) == 0:
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
class TC036_VERIFY_STD_VTEP_DEVICE_RELOAD(aetest.Testcase):
    """HA_VERIFICATION"""

    @aetest.test
    def TRIGGER_verify_device_reload(self, testscript):
        """ HA_VERIFICATION subsection: Device Reload """

        LEAF_3 = testscript.parameters['LEAF-3']

        LEAF_3.configure("copy r s")

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
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyFnL.verifyFnLNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyFnL.verifyFnLVNIData(testscript.parameters['leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 3) == 0:
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
# <--- CC not supported on FnL Deployment
# class CC_05_VERIFY_CC(aetest.Testcase):
#     """ Consistency Checker - CC_05_VERIFY_CC  """
#
#     @aetest.test
#     def verify_CC(self, testscript):
#         """ VERIFY_NETWORK subsection: Verify CC """
#
#         # Using only cc_check
#         status = infraVerify.postTestVerification(cc_verification_dict)
#         if status['status'] == 0:
#             self.failed(reason=status['logs'])
#         else:
#             self.passed(reason=status['logs'])

########################################################################
####                       COMMON CLEANUP SECTION                    ###
########################################################################
#
## Remove the BASE CONFIGURATION that was applied earlier in the 
## common cleanup section, clean the left over

class common_cleanup(aetest.CommonCleanup):
    """ Common Cleanup for Sample Test """

    @aetest.subsection
    def restore_terminal_width(self, BL1):
        """ Common Cleanup subsection """
        log.info(banner("script common cleanup starts here"))

    @aetest.subsection
    def restore_terminal_width(self, BL2):
        """ Common Cleanup subsection """
        log.info(banner("script common cleanup starts here"))

    @aetest.subsection
    def restore_terminal_width(self, CORE):
        """ Common Cleanup subsection """
        log.info(banner("script common cleanup starts here"))

    @aetest.subsection
    def restore_terminal_width(self, SPINE):
        """ Common Cleanup subsection """
        log.info(banner("script common cleanup starts here"))


if __name__ == '__main__':  # pragma: no cover
    aetest.main()
