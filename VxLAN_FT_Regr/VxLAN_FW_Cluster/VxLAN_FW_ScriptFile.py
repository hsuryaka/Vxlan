#!/usr/bin/env python

###################################################################
###                  Importing Libraries                        ###
###################################################################
import json
import logging
import pdb
import re
import sys
import time
import yaml
from yaml import Loader
from time import sleep

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

#################################################################################
from pyats import aetest
from pyats.log.utils import banner
from pyats.aereport.utils.argsvalidator import ArgsValidator
ArgVal = ArgsValidator()
import logging

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
from VxLAN_PYlib import vxlanEVPN_FNL_lib
evpnLib     = vxlanEVPN_FNL_lib.configure39KVxlanEvpn()
verifyEvpn  = vxlanEVPN_FNL_lib.verifyEVPNconfiguration()

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
infraConfig = infra_lib.infraConfigure()
infraVerify = infra_lib.infraVerify()
infraEORTrigger = infra_lib.infraEORTrigger()

# ------------------------------------------------------
# Import and initialize NIA specific libraries
# ------------------------------------------------------
from VxLAN_PYlib import vxlanNIA_lib
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

def Peer_State(json_input, peer_ip):
    for i in json_input['TABLE_nve_peers']['ROW_nve_peers']:
        if i['peer-ip'] == peer_ip:
            return i['peer-state']
    return 0

def hname(hn, Dmirror_Int):
    for i in hn['TABLE']['ROW']:
        if i['name'] == Dmirror_Int:
            return i['hname']
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

    log.info(banner("Common Setup"))

    @aetest.subsection
    def connecting_to_devices(self, testscript, testbed, uut_list):
        """ common setup subsection: Connecting to devices """

        log.info(banner("Connecting to Devices"))
        global post_test_process_dict

        # =============================================================================================================================#
        # Grab the device object of the uut device with that name
        SPINE = testscript.parameters['SPINE'] = testbed.devices[uut_list['N5T-7004-SPINE-1']]

        LEAF_1 = testscript.parameters['LEAF-1'] = testbed.devices[uut_list['LEAF-1']]
        LEAF_2 = testscript.parameters['LEAF-2'] = testbed.devices[uut_list['LEAF-2']]
        LEAF_3 = testscript.parameters['LEAF-3'] = testbed.devices[uut_list['LEAF-3']]

        FAN = testscript.parameters['FAN'] = testbed.devices[uut_list['MyXB-ACCESS']]

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

        global post_test_process_dict
        LEAF_1  = testscript.parameters['LEAF-1']
        LEAF_2  = testscript.parameters['LEAF-2']
        LEAF_3  = testscript.parameters['LEAF-3']
        FAN     = testscript.parameters['FAN']

        # =============================================================================================================================#
        # Import script_flags into testscript.parameters
        # Setting up the Post Test Check Parameters
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
            if 'eor_flag' in script_flags.keys():
                testscript.parameters['script_flags']['eor_flag'] = script_flags['eor_flag']
            else:
                testscript.parameters['script_flags']['eor_flag'] = 0
        else:
            testscript.parameters['script_flags']['skip_device_config'] = 0
            testscript.parameters['script_flags']['skip_tgen_config'] = 0
            testscript.parameters['script_flags']['skip_device_cleanup'] = 0
            testscript.parameters['script_flags']['eor_flag'] = 0

        post_test_process_dict = {}
        post_test_process_dict = job_file_params['postTestArgs']
        post_test_process_dict['dut_list'] = [LEAF_1, LEAF_2, LEAF_3]
        log.info("===> Post Test Check Process Parameters")
        log.info(post_test_process_dict)

        # Flags to control pre-clean, config and EOR Trigger test-cases
        resn = "Skipped by the user via job file"
        log.info(resn)
        if job_file_params['script_flags']['eor_flag']:
            aetest.skip.affix(section=TC034_FINAL_CC_CHECK, reason=resn)
        if job_file_params['script_flags']['skip_device_config']:
            aetest.skip.affix(section=DEVICE_BRINGUP_enable_feature_set, reason=resn)
            aetest.skip.affix(section=DEVICE_BRINGUP_Configure_SPINE, reason=resn)
            aetest.skip.affix(section=DEVICE_BRINGUP_Configure_LEAF_1_2, reason=resn)
            aetest.skip.affix(section=DEVICE_BRINGUP_Configure_LEAF_3, reason=resn)

        # =============================================================================================================================#
        # Import Configuration File and create required Structures

        with open(configurationFile) as cfgFile:
            configuration = yaml.load(cfgFile, Loader=Loader)

        testscript.parameters['LEAF_1_dict']            = configuration['LEAF_1_dict']
        testscript.parameters['LEAF_2_dict']            = configuration['LEAF_2_dict']
        testscript.parameters['LEAF_3_dict']            = configuration['LEAF_3_dict']
        testscript.parameters['FAN_dict']               = configuration['FAN_dict']

        testscript.parameters['LEAF_12_TGEN_dict']      = configuration['LEAF_12_TGEN_data']
        testscript.parameters['LEAF_1_TGEN_dict']       = configuration['LEAF_1_TGEN_data']
        testscript.parameters['LEAF_3_TGEN_dict']       = configuration['LEAF_3_TGEN_data']


        testscript.parameters['forwardingSysDict']      = configuration['FWD_SYS_dict']

        testscript.parameters['leafVPCDictData']        = {LEAF_1 : configuration['LEAF_1_dict'], LEAF_2 : configuration['LEAF_2_dict']}
        testscript.parameters['leavesDictList']         = [configuration['LEAF_1_dict'], configuration['LEAF_2_dict'], configuration['LEAF_3_dict']]
        testscript.parameters['spine_leavesDictList']   = [configuration['LEAF_1_dict'], configuration['LEAF_2_dict'], configuration['LEAF_3_dict']]
        testscript.parameters['leavesDict']             = {LEAF_1 : configuration['LEAF_1_dict'],
                                                           LEAF_2 : configuration['LEAF_2_dict'],
                                                           LEAF_3 : configuration['LEAF_3_dict']}
        
        testscript.parameters['bgp_nbr_leafList']       = {LEAF_1 : configuration['LEAF_1_dict'],
                                                           LEAF_2 : configuration['LEAF_2_dict'],
                                                           LEAF_3 : configuration['LEAF_3_dict']}

        testscript.parameters['VTEP_List'] = [testscript.parameters['LEAF_1_dict'], testscript.parameters['LEAF_2_dict'], testscript.parameters['LEAF_3_dict']]

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

        testscript.parameters['intf_LEAF_1_to_IXIA']        = LEAF_1.interfaces['LEAF_to_IXIA'].intf
        testscript.parameters['intf_LEAF_3_to_IXIA']        = LEAF_3.interfaces['LEAF_to_IXIA'].intf
        testscript.parameters['intf_FAN_to_IXIA']           = FAN.interfaces['FAN_to_IXIA'].intf

        testscript.parameters['intf_IXIA_to_FAN']           = IXIA.interfaces['IXIA_to_FAN'].intf
        testscript.parameters['intf_IXIA_to_LEAF_1']        = IXIA.interfaces['IXIA_to_LEAF-1'].intf
        testscript.parameters['intf_IXIA_to_LEAF_3']        = IXIA.interfaces['IXIA_to_LEAF-3'].intf

        testscript.parameters['intf_FAN_to_LEAF_1']         = FAN.interfaces['FAN_to_LEAF-1_1'].intf
        testscript.parameters['intf_FAN_to_LEAF_2']         = FAN.interfaces['FAN_to_LEAF-2_1'].intf

        testscript.parameters['ixia_int_list'] = str(testscript.parameters['intf_IXIA_to_FAN']) + " " + \
                                                 str(testscript.parameters['intf_IXIA_to_LEAF_1']) + " " + \
                                                 str(testscript.parameters['intf_IXIA_to_LEAF_3'])

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
            +---------+       +-----------+    +-----------+    +-----------+
            |   IXIA  |-------|   LEAF-1  |====|   LEAF-2  |    |   LEAF-3  |
            +---------+       +-----------+    +-----------+    +-----------+
                                   \\             /                 |
                                    \\           /                  |
                                     \\         /                   |
                                      \\       /                    |
                                    +-----------+             +-----------+
                                    |   LEAF-4  |             |   IXIA    |
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

            testscript.parameters['leafLst']                = leafLst               = [testscript.parameters['LEAF-1'], testscript.parameters['LEAF-2'], testscript.parameters['LEAF-3']]
            testscript.parameters['spineFeatureList']       = spineFeatureList      = ['ospf', 'bgp', 'pim', 'lacp', 'nv overlay']
            testscript.parameters['vpcLeafFeatureList']     = vpcLeafFeatureList    = ['vpc', 'ospf', 'pim', 'bgp', 'interface-vlan', 'vn-segment-vlan-based', 'lacp', 'nv overlay', 'fabric forwarding', 'hsrp']
            testscript.parameters['LeafFeatureList']        = LeafFeatureList       = ['ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp', 'nv overlay', 'fabric forwarding']
            testscript.parameters['fanOutFeatureList']      = fanOutFeatureList     = ['lacp']
            testscript.parameters['esi_uut_list']           = esi_uut_list          = [testscript.parameters['LEAF-1'], testscript.parameters['LEAF-2']]
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
                configFeatureSet_msgs += featureConfigureLeaf2_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-3
            featureConfigureLeaf3_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-3'], LeafFeatureList)
            if featureConfigureLeaf3_status['result']:
                log.info("Passed Configuring features on LEAF-3")
            else:
                log.debug("Failed configuring features on LEAF-3")
                configFeatureSet_msgs += featureConfigureLeaf3_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on FAN
            featureConfigureFAN_status = infraConfig.configureVerifyFeature(testscript.parameters['FAN'], LeafFeatureList)
            if featureConfigureFAN_status['result']:
                log.info("Passed Configuring features on FAN")
            else:
                log.debug("Failed configuring features on FAN")
                configFeatureSet_msgs += featureConfigureFAN_status['log']
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
            featureConfigureFan_status = infraConfig.configureVerifyFeature(testscript.parameters['FAN'], fanOutFeatureList)
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
class DEVICE_BRINGUP_Configure_SPINE(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Configure_SPINE(self, testscript):
        """ Device Bring-up subsection: Configuring SPINE """

        SPINE = testscript.parameters['SPINE']
        evpnLib.configureEVPNSpines([testscript.parameters['SPINE']], testscript.parameters['forwardingSysDict'] , testscript.parameters['spine_leavesDictList'])

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
class DEVICE_BRINGUP_Configure_LEAF_1_2(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Configure_LEAF_1_2(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        evpnLib.configureEVPNVPCLeafs(testscript.parameters['forwardingSysDict'], testscript.parameters['leafVPCDictData'])

        try:
            LEAF_1.configure('''
                route-map set_esi permit 10
                    match tag 101 
                    match evpn route-type 1 2 
                    set community 23456:12345 
                route-map set_esi permit 15

                    
                router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                    address-family l2vpn evpn
                        originate-map set_esi
                        advertise-pip
            ''', timeout=60)

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
            LEAF_2.configure('''
                route-map set_esi permit 10
                    match tag 101 
                    match evpn route-type 1 2 
                    set community 23456:12345 
                route-map set_esi permit 15

                    
                router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                    address-family l2vpn evpn
                        originate-map set_esi
                        advertise-pip
            ''', timeout=60)

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
            self.errored('Exception occurred while configuring on LEAF-2', goto=['common_cleanup'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class DEVICE_BRINGUP_Configure_LEAF_3(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Configure_LEAF_3(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-3 """

        LEAF_3 = testscript.parameters['LEAF-3']
        evpnLib.configureEVPNLeaf(testscript.parameters['LEAF-3'], testscript.parameters['forwardingSysDict'], testscript.parameters['LEAF_3_dict'])

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

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class DEVICE_BRINGUP_Configure_FAN(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Configure_FAN_VTEP(self, testscript):
        """ Device Bring-up subsection: Configuring FAN VTEP """
        
        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            fanOut1_vlanConfiguration = ""
            FAN = testscript.parameters['FAN']

            l3_vrf_count_iter = 0
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                l2_vlan_count_iter = 0
                fanOut1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                    # Incrementing L2 VLAN Iteration counters
                    fanOut1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                    state active\n
                                                    no shut\n'''
                    l2_vlan_count_iter += 1
                    l2_vlan_id += 1
                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1
            try:
                FAN.configure(fanOut1_vlanConfiguration)
                FAN.configure('''
                interface port-channel '''+str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po'])+'''
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
                self.errored('Exception occurred while configuring on FAN VTEP', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per Request")

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

#*****************************************************************************************************************************#
class DEVICE_BRINGUP_VERIFY_NETWORK(aetest.Testcase):
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
            log.info("PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            log.info("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")
            self.failed()

    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict'],testscript.parameters['bgp_nbr_leafList'])

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

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

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

        result_clean = ixLib.end_session()

        if result_clean == 0:
            log.debug("CleanUP to ixia failed")
            self.errored("CleanUP to ixia failed", goto=['cleanup'])

        # Get IXIA paraameters
        ixia_chassis_ip = testscript.parameters['ixia_chassis_ip']
        ixia_tcl_server = testscript.parameters['ixia_tcl_server']
        ixia_tcl_port = testscript.parameters['ixia_tcl_port']
        ixia_int_list = testscript.parameters['ixia_int_list']

        ix_int_1 = testscript.parameters['intf_IXIA_to_FAN']
        ix_int_2 = testscript.parameters['intf_IXIA_to_LEAF_1']
        ix_int_3 = testscript.parameters['intf_IXIA_to_LEAF_3']

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
        testscript.parameters['port_handle_3'] = ch_key[ix_int_3]

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

        TOPO_3_dict = {'topology_name': 'LEAF-3-TG',
                       'device_grp_name': 'LEAF-3-TG',
                       'port_handle': testscript.parameters['port_handle_3']}

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

        testscript.parameters['IX_TP3'] = ixLib.create_topo_device_grp(TOPO_3_dict)
        if testscript.parameters['IX_TP3'] == 0:
            log.debug("Creating Topology failed")
            self.errored("Creating Topology failed", goto=['cleanup'])
        else:
            log.info("Created BL3-TG Topology Successfully")

        testscript.parameters['IX_TP1']['port_handle'] = testscript.parameters['port_handle_1']
        testscript.parameters['IX_TP2']['port_handle'] = testscript.parameters['port_handle_2']
        testscript.parameters['IX_TP3']['port_handle'] = testscript.parameters['port_handle_3']

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

        P1_dict = testscript.parameters['LEAF_12_TGEN_dict']
        P2_dict = testscript.parameters['LEAF_1_TGEN_dict']
        P3_dict = testscript.parameters['LEAF_3_TGEN_dict']

        P1_int_dict_1 = {'dev_grp_hndl'         : testscript.parameters['IX_TP1']['dev_grp_hndl'],
                         'port_hndl'            : P1,
                         'phy_mode'             : P1_dict['phy_mode'],
                         'no_of_ints'           : P1_dict['no_of_ints'],
                         'mac'                  : P1_dict['mac'],
                         'mac_step'             : P1_dict['mac_step'],
                         'protocol'             : P1_dict['protocol'],
                         'v4_addr'              : P1_dict['v4_addr'],
                         'v4_addr_step'         : P1_dict['v4_addr_step'],
                         'v4_gateway'           : P1_dict['v4_gateway'],
                         'v4_gateway_step'      : P1_dict['v4_gateway_step'],
                         'v4_netmask'           : P1_dict['v4_netmask'],
                         'v6_addr'              : P1_dict['v6_addr'],
                         'v6_addr_step'         : P1_dict['v6_addr_step'],
                         'v6_gateway'           : P1_dict['v6_gateway'],
                         'v6_gateway_step'      : P1_dict['v6_gateway_step'],
                         'v6_netmask'           : P1_dict['v6_netmask'],
                         'vlan_id'              : P1_dict['vlan_id'],
                         'vlan_id_step'         : P1_dict['vlan_id_step']}

        P2_int_dict_1 = {'dev_grp_hndl'         : testscript.parameters['IX_TP2']['dev_grp_hndl'],
                         'port_hndl'            : P2,
                         'phy_mode'             : P2_dict['phy_mode'],
                         'no_of_ints'           : P2_dict['no_of_ints'],
                         'mac'                  : P2_dict['mac'],
                         'mac_step'             : P2_dict['mac_step'],
                         'protocol'             : P2_dict['protocol'],
                         'v4_addr'              : P2_dict['v4_addr'],
                         'v4_addr_step'         : P2_dict['v4_addr_step'],
                         'v4_gateway'           : P2_dict['v4_gateway'],
                         'v4_gateway_step'      : P2_dict['v4_gateway_step'],
                         'v4_netmask'           : P2_dict['v4_netmask'],
                         'v6_addr'              : P2_dict['v6_addr'],
                         'v6_addr_step'         : P2_dict['v6_addr_step'],
                         'v6_gateway'           : P2_dict['v6_gateway'],
                         'v6_gateway_step'      : P2_dict['v6_gateway_step'],
                         'v6_netmask'           : P2_dict['v6_netmask'],
                         'vlan_id'              : P2_dict['vlan_id'],
                         'vlan_id_step'         : P2_dict['vlan_id_step']}

        P3_int_dict_1 = {'dev_grp_hndl'         : testscript.parameters['IX_TP3']['dev_grp_hndl'],
                         'port_hndl'            : P3,
                         'phy_mode'             : P3_dict['phy_mode'],
                         'no_of_ints'           : P3_dict['no_of_ints'],
                         'mac'                  : P3_dict['mac'],
                         'mac_step'             : P3_dict['mac_step'],
                         'protocol'             : P3_dict['protocol'],
                         'v4_addr'              : P3_dict['v4_addr'],
                         'v4_addr_step'         : P3_dict['v4_addr_step'],
                         'v4_gateway'           : P3_dict['v4_gateway'],
                         'v4_gateway_step'      : P3_dict['v4_gateway_step'],
                         'v4_netmask'           : P3_dict['v4_netmask'],
                         'v6_addr'              : P3_dict['v6_addr'],
                         'v6_addr_step'         : P3_dict['v6_addr_step'],
                         'v6_gateway'           : P3_dict['v6_gateway'],
                         'v6_gateway_step'      : P3_dict['v6_gateway_step'],
                         'v6_netmask'           : P3_dict['v6_netmask'],
                         'vlan_id'              : P3_dict['vlan_id'],
                         'vlan_id_step'         : P3_dict['vlan_id_step']}


        P1_IX_int_data = ixLib.configure_multi_ixia_interface(P1_int_dict_1)
        P2_IX_int_data = ixLib.configure_multi_ixia_interface(P2_int_dict_1)
        P3_IX_int_data = ixLib.configure_multi_ixia_interface(P3_int_dict_1)

        log.info(P1_IX_int_data)
        log.info(P2_IX_int_data)
        log.info(P3_IX_int_data)

        if P1_IX_int_data == 0 or P2_IX_int_data == 0 or P3_IX_int_data == 0:
            log.debug("Configuring IXIA Interface failed")
            self.errored("Configuring IXIA Interface failed", goto=['cleanup'])
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

        log.info("IXIA Port 1 Handles")
        log.info(testscript.parameters['IX_TP1'])
        log.info("IXIA Port 2 Handles")
        log.info(testscript.parameters['IX_TP2'])
        log.info("IXIA Port 3 Handles")
        log.info(testscript.parameters['IX_TP3'])

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

        P1_TGEN_dict = testscript.parameters['LEAF_12_TGEN_dict']
        P2_TGEN_dict = testscript.parameters['LEAF_1_TGEN_dict']
        P3_TGEN_dict = testscript.parameters['LEAF_3_TGEN_dict']

        IGMP_dict_1 = {'ipv4_hndl'                      : IX_TP1['ipv4_handle'],
                       'igmp_ver'                       : P1_TGEN_dict['igmp_ver'],
                       'mcast_grp_ip'                   : P1_TGEN_dict['mcast_grp_ip'],
                       'mcast_grp_ip_step'              : P1_TGEN_dict['mcast_grp_ip_step'],
                       'no_of_grps'                     : P1_TGEN_dict['no_of_grps'],
                       'mcast_src_ip'                   : P3_TGEN_dict['v4_addr'],
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
                       'mcast_src_ip'                   : P3_TGEN_dict['v4_addr'],
                       'mcast_src_ip_step'              : P2_TGEN_dict['v4_addr_step'],
                       'mcast_src_ip_step_per_port'     : P2_TGEN_dict['v4_addr_step'],
                       'mcast_grp_ip_step_per_port'     : P2_TGEN_dict['v4_addr_step'],
                       'mcast_no_of_srcs'               : P2_TGEN_dict['no_of_mcast_sources'],
                       'topology_handle'                : IX_TP2['topo_hndl']
                       }

        IGMP_EML_1 = ixLib.emulate_igmp_groupHost(IGMP_dict_1)
        IGMP_EML_2 = ixLib.emulate_igmp_groupHost(IGMP_dict_2)
        # ForkedPdb().set_trace()

        if IGMP_EML_1 == 0 and IGMP_EML_2 == 0:
            log.debug("Configuring IGMP failed")
            self.errored("Configuring IGMP failed", goto=['cleanup'])
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

        IX_TP1 = testscript.parameters['IX_TP1'] # END NODE
        IX_TP2 = testscript.parameters['IX_TP2'] # LEAF-1
        IX_TP3 = testscript.parameters['IX_TP3'] # LEAF-3

        P3_dict = testscript.parameters['LEAF_3_TGEN_dict']

        BCAST_STD_VPC_v4_dict = {
                            'src_hndl'      : IX_TP3['port_handle'],
                            'dst_hndl'      : [IX_TP1['port_handle'],IX_TP2['port_handle']],
                            'TI_name'       : "BCAST_STD_VPC_END_NODE",
                            'frame_size'    : "70",
                            'rate_pps'      : "1000",
                            'src_mac'       : "00:00:30:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : P3_dict['no_of_ints'],
                            'vlan_id'       : P3_dict['vlan_id'],
                            'vlanid_step'   : "1",
                            'vlanid_count'  : P3_dict['no_of_ints'],
                            'ip_src_addrs'  : "30.1.1.10",
                            'ip_step'       : "0.0.1.0",
                      }

        BCAST_STD_VPC_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_STD_VPC_v4_dict)

        if BCAST_STD_VPC_v4_TI == 0:
            log.debug("Configuring BCast TI failed")
            self.errored("Configuring BCast TI failed", goto=['cleanup'])

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

        P3_dict = testscript.parameters['LEAF_3_TGEN_dict']

        UKNOWN_UCAST_STD_VPC_V4_dict = {
                            'src_hndl'      : IX_TP3['port_handle'],
                            'dst_hndl'      : [IX_TP1['port_handle'],IX_TP2['port_handle']],
                            'TI_name'       : "UKNOWN_UCAST_STD_VPC_V4",
                            'frame_size'    : "64",
                            'rate_pps'      : "1000",
                            'dst_mac'       : "00:00:45:00:00:01",
                            'dstmac_step'   : "00:00:00:00:00:01",
                            'dstmac_count'  : P3_dict['no_of_ints'],
                            'src_mac'       : "00:00:41:00:00:01",
                            'srcmac_step'   : "00:00:00:00:00:01",
                            'srcmac_count'  : "100",
                            'vlan_id'       : P3_dict['vlan_id'],
                            'vlanid_step'   : "1",
                            'vlanid_count'  : P3_dict['no_of_ints'],
                      }

        UKNOWN_UCAST_STD_VPC_V4_TI = ixLib.configure_ixia_UNKNOWN_UCAST_traffic_item(UKNOWN_UCAST_STD_VPC_V4_dict)

        if UKNOWN_UCAST_STD_VPC_V4_TI == 0:
            log.debug("Configuring UNKNOWN_UCAST TI failed")
            self.errored("Configuring UNKNOWN_UCAST TI failed", goto=['cleanup'])

    @aetest.cleanup
    def cleanup(self):
        pass
        """ testcase clean up """

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
            IX_TP3 = testscript.parameters['IX_TP3']


            UCAST_v4_dict_12 = {'src_hndl'  : IX_TP1['ipv4_handle'],
                                'dst_hndl'  : IX_TP2['ipv4_handle'],
                                'circuit'   : 'ipv4',
                                'TI_name'   : "UCAST_V4_TP1_TP2",
                                'rate_pps'  : "1000",
                                'bi_dir'    : 1
                                }

            UCAST_v4_dict_13 = {'src_hndl'  : IX_TP2['ipv4_handle'],
                                'dst_hndl'  : IX_TP3['ipv4_handle'],
                                'circuit'   : 'ipv4',
                                'TI_name'   : "UCAST_V4_TP2_TP3",
                                'rate_pps'  : "1000",
                                'bi_dir'    : 1
                                }

            UCAST_v4_dict_14 = {'src_hndl'  : IX_TP1['ipv4_handle'],
                                'dst_hndl'  : IX_TP3['ipv4_handle'],
                                'circuit'   : 'ipv4',
                                'TI_name'   : "UCAST_V4_TP1_TP3",
                                'rate_pps'  : "1000",
                                'bi_dir'    : 1
                                }

            UCAST_v6_dict_15 = {'src_hndl'  : IX_TP1['ipv6_handle'],
                                'dst_hndl'  : IX_TP2['ipv6_handle'],
                                'circuit'   : 'ipv6',
                                'TI_name'   : "UCAST_V6_TP1_TP2",
                                'rate_pps'  : "1000",
                                'bi_dir'    : 1
                                }

            UCAST_v6_dict_16 = {'src_hndl'  : IX_TP2['ipv6_handle'],
                                'dst_hndl'  : IX_TP3['ipv6_handle'],
                                'circuit'   : 'ipv6',
                                'TI_name'   : "UCAST_V6_TP2_TP3",
                                'rate_pps'  : "1000",
                                'bi_dir'    : 1
                                }

            UCAST_v6_dict_17 = {'src_hndl'  : IX_TP1['ipv6_handle'],
                                'dst_hndl'  : IX_TP3['ipv6_handle'],
                                'circuit'   : 'ipv6',
                                'TI_name'   : "UCAST_V6_TP1_TP3",
                                'rate_pps'  : "1000",
                                'bi_dir'    : 1
                                }

            UCAST_v4_TI_12 = ixLib.configure_ixia_traffic_item(UCAST_v4_dict_12)
            UCAST_v4_TI_13 = ixLib.configure_ixia_traffic_item(UCAST_v4_dict_13)
            UCAST_v4_TI_14 = ixLib.configure_ixia_traffic_item(UCAST_v4_dict_14)
            UCAST_v6_TI_15 = ixLib.configure_ixia_traffic_item(UCAST_v6_dict_15)
            UCAST_v6_TI_16 = ixLib.configure_ixia_traffic_item(UCAST_v6_dict_16)
            UCAST_v6_TI_17 = ixLib.configure_ixia_traffic_item(UCAST_v6_dict_17)

            if UCAST_v4_TI_12 == 0 or UCAST_v4_TI_13 == 0 or UCAST_v4_TI_14 == 0 or UCAST_v6_TI_15 == 0 or UCAST_v6_TI_16 == 0 or UCAST_v6_TI_17 == 0:
                log.debug("Configuring UCast TI failed")
                self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

        time.sleep(100)

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class IXIA_CONFIGURATION_CONFIGURE_ROUTED_UCAST_IXIA_TRAFFIC(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONFIGURE_ROUTED_UCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']
            IX_TP3 = testscript.parameters['IX_TP3']

            vrf_count = int(testscript.parameters['forwardingSysDict']['VRF_count'])
            vlan_per_vrf = int(testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count'])

            UCAST_v4_dict_12 = {'src_hndl'              : IX_TP1['ipv4_handle'],
                                'dst_hndl'              : IX_TP2['ipv4_handle'],
                                'circuit'               : 'ipv4',
                                'TI_name'               : "RTD_UCAST_V4_TP1_TP2",
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

            UCAST_v4_dict_13 = {'src_hndl'              : IX_TP2['ipv4_handle'],
                                'dst_hndl'              : IX_TP3['ipv4_handle'],
                                'circuit'               : 'ipv4',
                                'TI_name'               : "RTD_UCAST_V4_TP2_TP3",
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

            UCAST_v4_dict_14 = {'src_hndl'              : IX_TP1['ipv4_handle'],
                                'dst_hndl'              : IX_TP3['ipv4_handle'],
                                'circuit'               : 'ipv4',
                                'TI_name'               : "RTD_UCAST_V4_TP1_TP3",
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

            UCAST_v6_dict_15 = {'src_hndl'              : IX_TP1['ipv6_handle'],
                                'dst_hndl'              : IX_TP2['ipv6_handle'],
                                'circuit'               : 'ipv6',
                                'TI_name'               : "RTD_UCAST_V6_TP1_TP2",
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

            UCAST_v6_dict_16 = {'src_hndl'              : IX_TP2['ipv6_handle'],
                                'dst_hndl'              : IX_TP3['ipv6_handle'],
                                'circuit'               : 'ipv6',
                                'TI_name'               : "RTD_UCAST_V6_TP2_TP3",
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

            UCAST_v6_dict_17 = {'src_hndl'              : IX_TP1['ipv6_handle'],
                                'dst_hndl'              : IX_TP3['ipv6_handle'],
                                'circuit'               : 'ipv6',
                                'TI_name'               : "RTD_UCAST_V6_TP1_TP3",
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

            UCAST_v4_TI_12 = ixLib.configure_multi_endpoint_ixia_traffic_item(UCAST_v4_dict_12)
            UCAST_v4_TI_13 = ixLib.configure_multi_endpoint_ixia_traffic_item(UCAST_v4_dict_13)
            UCAST_v4_TI_14 = ixLib.configure_multi_endpoint_ixia_traffic_item(UCAST_v4_dict_14)
            UCAST_v6_TI_15 = ixLib.configure_multi_endpoint_ixia_traffic_item(UCAST_v6_dict_15)
            UCAST_v6_TI_16 = ixLib.configure_multi_endpoint_ixia_traffic_item(UCAST_v6_dict_16)
            UCAST_v6_TI_17 = ixLib.configure_multi_endpoint_ixia_traffic_item(UCAST_v6_dict_17)

            if UCAST_v4_TI_12 == 0 or UCAST_v4_TI_13 == 0 or UCAST_v4_TI_14 == 0 or UCAST_v6_TI_15 == 0 or UCAST_v6_TI_16 == 0 or UCAST_v6_TI_17 == 0:
                log.debug("Configuring UCast TI failed")
                self.errored("Configuring UCast TI failed", goto=['cleanup'])
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

        time.sleep(100)

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

        IX_TP1 = testscript.parameters['IX_TP1']
        IX_TP2 = testscript.parameters['IX_TP2']
        IX_TP3 = testscript.parameters['IX_TP3']

        forwardingSysDict = testscript.parameters['forwardingSysDict']
        total_vlans = int(forwardingSysDict['VRF_count']) * int(forwardingSysDict['VLAN_PER_VRF_count'])

        # Creating TAGs for SRC IP Handles
        TAG_dict = {'subject_handle': IX_TP3['ipv4_handle'],
                    'topo_handle': IX_TP3['topo_hndl'],
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

        MCAST_dict = {'src_ipv4_topo_handle': IX_TP3['topo_hndl'],
                      'total_tags': str(int(total_vlans)),
                      'TI_name': "MCAST_STD_END_NODE_ORPH",
                      'rate_pps': "1000",
                      'frame_size': "70",
                      }

        MCAST_TI = ixLib.configure_v4_mcast_traffic_item_per_tag(MCAST_dict)

        if MCAST_TI == 0:
            log.debug("Configuring MCast TI failed")
            self.errored("Configuring MCast TI failed", goto=['cleanup'])

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
            self.errored("Applying IXIA TI failed", goto=['cleanup'])

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class IXIA_CONFIGURATION_VERIFY_IXIA_TRAFFIC(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class TC001_VERIFY_NETWORK_POST_TRAFFIC(aetest.Testcase):
    """Verify the Network after IXIA Configuration"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict'],testscript.parameters['bgp_nbr_leafList'])

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

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

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
class TC002_VERIFY_IXIA_TRAFFIC(aetest.Testcase):
    """ Verify the IXIA Traffic """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class TC003_Configure_ESI_on_VPC_Acc_PO(aetest.Testcase):
    """ Configure ESI value and ESI tag on vPC Port-channel """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Configure_ESI(self, testscript):
        """ Configure ESI value and ESI tag on vPC Port-channel"""

        testscript.parameters['LEAF-1'].configure('''
    
                  interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
                  ethernet-segment vpc
                    esi ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) + ''' tag ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) + '''
                    no shutdown
    
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
                  interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + '''
                  ethernet-segment vpc
                    esi ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) + ''' tag ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) + '''
                    no shutdown
    
              ''')
        time.sleep(60)
    
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class TC004_Verify_ESI_CONFIG(aetest.Testcase):
    """ Verify_ESI_Config  """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Verify_ESI_Config(self, testscript):
        """ Verify_ESI_Config """
        time.sleep(30)
        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')


    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """
        time.sleep(30)
        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class TC005_VPC_PO_Link_Flap(aetest.Testcase):
    """ SA_UP_Link_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def VPC_PO_Link_Flap(self, testscript):
        """ SA_UP_Link_Flap """

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
        sleep(120)

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
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
class TC006_vPC_NVE_Flap(aetest.Testcase):
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
        sleep(120)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#
class TC007_vPC_Remove_Add_VN_Segment(aetest.Testcase):
    """ vPC_Remove_Add_VN_Segment """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

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
        sleep(60)

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
        sleep(120)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#
class TC008_vPC_Remove_Add_Member_VNI(aetest.Testcase):
    """ vPC_Remove_Add_Member_VNI """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

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
        sleep(60)

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
        sleep(120)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
    
    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')    

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])
# *****************************************************************************************************************************#
class TC009_vPC_Loopback_Flap(aetest.Testcase):
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
        sleep(160)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#
class TC010_SA_Remove_Add_VLAN(aetest.Testcase):
    """ SA_Remove_Add_VLAN """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def SA_Remove_Add_VLAN(self, testscript):
        """ SA_Remove_Add_VLAN """

        testscript.parameters['LEAF-3'].configure('''
    
                  no vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + '''
                  vlan ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']) + '''
                    vn-segment ''' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']) + '''
    
              ''')
        sleep(120)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')


    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#
class TC011_vPC_Remove_Add_VLAN(aetest.Testcase):
    """ vPC_Remove_Add_VLAN """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

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
        sleep(120)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#
class TC012_Remove_Add_NVE_Configs(aetest.Testcase):
    """ Remove_Add_NVE_Configs """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_Add_NVE_Configs(self, testscript):
        """ Remove_Add_NVE_Configs """

        testscript.parameters['LEAF-1'].configure('''
    
                  delete bootflash:temp_nve_configs.txt no-prompt
                  
                  show running-config interface nve 1 > bootflash:temp_nve_configs.txt
                  
                  no interface nve 1
                  
                  copy bootflash:temp_nve_configs.txt running-config echo-commands
    
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
                  delete bootflash:temp_nve_configs.txt no-prompt
                  
                  show running-config interface nve 1 > bootflash:temp_nve_configs.txt
                  
                  no interface nve 1
                  
                  copy bootflash:temp_nve_configs.txt running-config echo-commands
    
              ''')
        sleep(120)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching') 
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#
class TC013_Remove_Add_BGP_Configs(aetest.Testcase):
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
        sleep(120)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')
    

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#
class TC014_Clear_IP_ROUTES(aetest.Testcase):
    """ Clear_IP_ROUTES """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Clear_IP_ROUTES(self, testscript):
        """ Clear_IP_ROUTES """

        testscript.parameters['LEAF-1'].configure('''

                  clear ip route vrf all *
                  clear ip mroute * vrf all

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  clear ip route vrf all *
                  clear ip mroute * vrf all
                  
              ''')
        sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')   
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#
class TC015_Clear_BGP(aetest.Testcase):
    """ Clear_BGP """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Clear_BGP(self, testscript):
        """ Clear_BGP """

        testscript.parameters['LEAF-1'].configure('''

                  clear ip bgp vrf all *

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  clear ip bgp vrf all *

              ''')
        sleep(120)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#
class TC016_Process_Restart(aetest.Testcase):
    """ Process_Restart """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Process_Restart(self, testscript):
        """ Process_Restart """

        testscript.parameters['LEAF-1'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                  restart ospf ''' + str(testscript.parameters['forwardingSysDict']['OSPF_AS']) + '''
                  restart pim

              ''')

        testscript.parameters['LEAF-2'].configure('''

                  restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                  restart ospf ''' + str(testscript.parameters['forwardingSysDict']['OSPF_AS']) + '''
                  restart pim
                  
              ''')
        sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])
# *****************************************************************************************************************************#
class TC017_Config_Replace_ESI_tag(aetest.Testcase):
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
          
                interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
                  no ethernet-segment vpc
             ''',timeout=120)
    

        testscript.parameters['LEAF-2'].configure('''
    
          delete bootflash:config_replace.cfg no-prompt
          copy running-config bootflash:config_replace.cfg
    
           interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + '''
                no ethernet-segment vpc
              ''', timeout=120)

        testscript.parameters['LEAF-1'].execute('configure replace bootflash:config_replace.cfg verbose')
        testscript.parameters['LEAF-2'].execute('configure replace bootflash:config_replace.cfg verbose')

        sleep(120)

    
        ConfigReplace1 = testscript.parameters['LEAF-1'].execute('show config-replace log exec | i "Rollback Status"')
        ConfigReplace2 = testscript.parameters['LEAF-2'].execute('show config-replace log exec | i "Rollback Status"')
        match1 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace1)
        match2 = re.search(r'Rollback Status\s+\:\s+(Success)', ConfigReplace2)

        sleep(60)

        if match1[1] == 'Success' and match2[1] == 'Success':
            self.passed(reason="Rollback Passed")
        else:
            self.failed(reason="Rollback Failed")

        sleep(30)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#
class TC018_Modify_ESI_Tag(aetest.Testcase):
    """ Process_Restart """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Modify_ESI_Tag(self, testscript):
        """ Modify ESI TAG Value """

        testscript.parameters['LEAF-1'].configure('''
                delete bootflash:config_replace.cfg no-prompt
                copy running-config bootflash:config_replace.cfg
          
                interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
                  no ethernet-segment vpc
                  ethernet-segment vpc
                    esi ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) + ''' tag 201
                    no shutdown
             ''',timeout=120)
    

        testscript.parameters['LEAF-2'].configure('''
    
          delete bootflash:config_replace.cfg no-prompt
          copy running-config bootflash:config_replace.cfg
    
           interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + '''
                no ethernet-segment vpc
                ethernet-segment vpc
                    esi ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['ESI_Value']) + ''' tag 201
                    no shutdown
    
              ''', timeout=120)
        sleep(120)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """
        time.sleep(60)
        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))
        esi_tag_value = '201'

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (esi_tag_value == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])
# *****************************************************************************************************************************#
class TC019_Modify_ESI_Value(aetest.Testcase):
    """ Process_Restart """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Modify_ESI_Value(self, testscript):
        """ Modify ESI Value """

        testscript.parameters['LEAF-1'].configure('''
                delete bootflash:config_replace.cfg no-prompt
                copy running-config bootflash:config_replace.cfg
          
                interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
                  no ethernet-segment vpc
                  ethernet-segment vpc
                    esi 0012.0000.0000.1200.1111 tag ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) + '''
                    no shutdown
             ''',timeout=120)
    

        testscript.parameters['LEAF-2'].configure('''
    
          delete bootflash:config_replace.cfg no-prompt
          copy running-config bootflash:config_replace.cfg
    
           interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + '''
                no ethernet-segment vpc
                ethernet-segment vpc
                    esi 0012.0000.0000.1200.1111 tag ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) + '''
                    no shutdown
    
              ''', timeout=120)
        sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """


        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))
        esi_tag_value = '101'
        esi_value = '0012.0000.0000.1200.1111'

        if (esi_value == esi_config['TABLE_es']['ROW_es']['esi']) and (esi_tag_value == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """
        esi_value = '0012.0000.0000.1200.1111'
        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (esi_value == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

   
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])
# *****************************************************************************************************************************#
class TC020_NVE_loopback_flap(aetest.Testcase):
    """ vPC_NVE_Flap """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def vPC_NVE_loopback_Flap(self, testscript):
        """ vPC_NVE_Flap """

        testscript.parameters['LEAF-1'].configure('''
    
                  interface loopback 1
                  shutdown
                  no shutdown
    
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
                  interface loopback 1
                  shutdown
                  no shutdown
    
              ''')
        sleep(120)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """
        esi_tag_value = '101'
        esi_value = '0012.0000.0000.1200.1111'

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (esi_value == esi_config['TABLE_es']['ROW_es']['esi']) and (esi_tag_value == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))
        esi_value = '0012.0000.0000.1200.1111'

        if (esi_value == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

# *****************************************************************************************************************************#
class TC021_Remove_Add_RouteMap(aetest.Testcase):
    """ Remove/Re-add Route MAP on Global """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_add_RouteMap(self, testscript):
        """ Remove/Re-add Route MAP on Global """

        testscript.parameters['LEAF-1'].configure('''

                no route-map set_esi permit 10
                no route-map set_esi permit 15


                route-map set_esi permit 10
                    match tag 101 
                    match evpn route-type 1 2 
                    set community 23456:12345 
                route-map set_esi permit 15
            ''', timeout=30)
        sleep(30)
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """
        esi_tag_value = '101'
        esi_value = '0012.0000.0000.1200.1111'

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (esi_value == esi_config['TABLE_es']['ROW_es']['esi']) and (esi_tag_value == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')   
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """
        esi_value = '0012.0000.0000.1200.1111'

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (esi_value == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class TC022_Remove_Add_BGP_RouteMap(aetest.Testcase):
    """ Remove/Re-add  Route Map Under BGP EVPN AF  """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_add_BGP_RouteMap(self, testscript):
        """ Remove/Re-add  Route Map Under BGP EVPN AF """

        testscript.parameters['LEAF-1'].configure('''
                    
                router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                    address-family l2vpn evpn
                        no originate-map set_esi
                        advertise-pip
            ''', timeout=30)
        
        testscript.parameters['LEAF-1'].configure('''
                    
                router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                    address-family l2vpn evpn
                        originate-map set_esi
                        advertise-pip
            ''', timeout=30)
        sleep(60)
    
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """
        esi_tag_value = '101'
        esi_value = '0012.0000.0000.1200.1111'
        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (esi_value == esi_config['TABLE_es']['ROW_es']['esi']) and (esi_tag_value == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """
        
        esi_value = '0012.0000.0000.1200.1111'
        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (esi_value == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class TC023_Remove_Add_ESI(aetest.Testcase):
    """ Remove/Re-add ESI under VPC Port-channel """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_Add_ESI_VPC_PO(self, testscript):
        """ Remove/Re-add ESI under VPC Port-channel """

        testscript.parameters['LEAF-1'].configure('''
    
                  interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
                  no ethernet-segment vpc    
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
                  interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + '''
                  no ethernet-segment vpc
              ''')

        sleep(10)

        testscript.parameters['LEAF-1'].configure('''
    
                  interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
                  ethernet-segment vpc
                    esi ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) + ''' tag ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) + '''
                    no shutdown
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
                  interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + '''
                  ethernet-segment vpc
                    esi ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) + ''' tag ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) + '''
                    no shutdown
              ''')
        sleep(60)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")

# *****************************************************************************************************************************#
class TC024_Remove_Add_NVE_Source_interface(aetest.Testcase):
    """ Remove/Re-add NVE Source interface """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Remove_Add_NVE_Source_Int(self, testscript):
        """ Remove/Re-add NVE Source loopback  """

        testscript.parameters['LEAF-1'].configure('''
    
                  interface nve 1
                  no source-interface   
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
                  interface nve 1
                  no source-interface 
              ''')

        sleep(10)

        testscript.parameters['LEAF-1'].configure('''
    
                  interface nve 1
                  source-interface loopback1  
                  no shutdown
              ''')

        testscript.parameters['LEAF-2'].configure('''
    
                  interface nve 1
                  source-interface loopback1
                  no shutdown
              ''')

        sleep(120)

    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2,2) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")

    @aetest.test
    def Verify_ESI_State(self, testscript):
        """ Verify_ESI_Config """

        esi_config = json.loads(testscript.parameters['LEAF-1'].execute('''show nve ethernet-segment | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == esi_config['TABLE_es']['ROW_es']['esi']) and (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_tag']) == esi_config['TABLE_es']['ROW_es']['tag']) and (esi_config['TABLE_es']['ROW_es']['es-state'] == 'Up'):
            log.debug("PASS : ESI Value and ESI tag are same and status is Up\n\n")
            self.passed(reason= "ESI value and tag are Present")
        else:
            log.debug("FAIL : ESI Config values are not matching\n\n")
            self.failed(reason= 'ESI Config values are not matching')
        sleep(10)

    @aetest.test
    def Verify_l2route_ead(self, testscript):
        """ Verify l2route ead """

        l2route_ead = json.loads(testscript.parameters['LEAF-1'].execute('''sh l2route evpn ead all | json'''))

        if (str(testscript.parameters['LEAF_1_dict']['VPC_data']['ESI_Value']) == l2route_ead['TABLE_l2route_evpn_ead_all']['ROW_l2route_evpn_ead_all']['esi']):
            log.debug("PASS : ESI Value is present l2route ead all\n\n")
            self.passed(reason= "ESI value  Present l2route ead all")
        else:
            log.debug("FAIL : ESI value is not present l2route ead all\n\n")
            self.failed(reason= 'ESI Config values are not matching')

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
