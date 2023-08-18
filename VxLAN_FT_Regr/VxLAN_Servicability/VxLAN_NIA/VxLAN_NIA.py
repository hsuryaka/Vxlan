#!/usr/bin/env python

###################################################################
###                  Importing Libraries                        ###
###################################################################
import logging
import time
import yaml
import json
import re
from yaml import Loader
from pyats import aetest
from pyats.log.utils import banner

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# ------------------------------------------------------
# Import and initialize EVPN specific libraries
# ------------------------------------------------------
import vxlanEVPN_FNL_lib
evpnLib     = vxlanEVPN_FNL_lib.configure39KVxlanEvpn()
verifyEvpn  = vxlanEVPN_FNL_lib.verifyEVPNconfiguration()

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
###                  User Libraries                             ###
###################################################################
# Make sure that VPC_1 is always primary and VPC_2 is secondary
def EnsureVpcRole(vpc_1,vpc_2):

    no_of_iterations = 1
    status_flag = 0

    while no_of_iterations <= 3:

        vpc_1_role_data = json.loads(vpc_1.execute("show vpc role | json", timeout=300))
        vpc_2_role_data = json.loads(vpc_2.execute("show vpc role | json", timeout=300))

        if (vpc_1_role_data['vpc-current-role'] == 'primary') and (vpc_2_role_data['vpc-current-role'] == 'secondary'):
            log.info("VPC Peers are in expected roles")
            status_flag = 1
            break

        if ('operational' in vpc_1_role_data['vpc-current-role']) and ('operational' in vpc_2_role_data['vpc-current-role']):
            log.info("VPC Peers are in operational roles, performing preempt")
            vpc_1.execute('vpc role preempt', timeout = 300)
            time.sleep(60)

        no_of_iterations += 1

    return status_flag



###################################################################
###                  GLOBAL VARIABLES                           ###
###################################################################

device_list         = []
device_mgmt_list    = []

###################################################################
###                  COMMON SETUP SECTION                       ###
###################################################################

class COMMON_SETUP(aetest.CommonSetup):
    """ Common Setup """

    @aetest.subsection
    def connecting_to_devices(self, testscript, testbed, uut_list, configurationFile, topology_flag, script_flags=None):
        """ common setup subsection: Connecting to devices """

        # =============================================================================================================================#
        # Grab the device object of the uut device with that name
        if script_flags is None:
            script_flags = {}
        SPINE = testscript.parameters['SPINE'] = testbed.devices[uut_list['SPINE']]

        LEAF_1 = testscript.parameters['LEAF-1'] = testbed.devices[uut_list['LEAF-1']]
        LEAF_2 = testscript.parameters['LEAF-2'] = testbed.devices[uut_list['LEAF-2']]
        LEAF_3 = testscript.parameters['LEAF-3'] = testbed.devices[uut_list['LEAF-3']]

        FAN_1 = testscript.parameters['FAN-1'] = testbed.devices[uut_list['FAN-1']]
        FAN_2 = testscript.parameters['FAN-2'] = testbed.devices[uut_list['FAN-2']]

        IXIA = testscript.parameters['IXIA'] = testbed.devices[uut_list['ixia']]

        testscript.parameters['ixia_chassis_ip'] = str(IXIA.connections.a.ip)
        testscript.parameters['ixia_tcl_server'] = str(IXIA.connections.alt.ip)
        testscript.parameters['ixia_tcl_port'] = str(IXIA.connections.alt.port)

        # =============================================================================================================================#
        # Connect to the device
        SPINE.connect()
        SPINE.connect(alias='mgmt', via='alt')
        LEAF_1.connect()
        LEAF_1.connect(alias='mgmt', via='alt')
        LEAF_2.connect()
        LEAF_2.connect(alias='mgmt', via='alt')
        LEAF_3.connect()
        LEAF_3.connect(alias='mgmt', via='alt')
        FAN_1.connect()
        FAN_2.connect()

        device_list.append(SPINE)
        device_list.append(LEAF_1)
        device_list.append(LEAF_2)
        device_list.append(LEAF_3)
        device_list.append(FAN_1)
        device_list.append(FAN_2)

        device_mgmt_list.append(SPINE.mgmt)
        device_mgmt_list.append(LEAF_1.mgmt)
        device_mgmt_list.append(LEAF_2.mgmt)
        device_mgmt_list.append(LEAF_3.mgmt)

        testscript.parameters['SPINE_mgmt'] = SPINE.mgmt
        testscript.parameters['LEAF-1_mgmt'] = LEAF_1.mgmt
        testscript.parameters['LEAF-2_mgmt'] = LEAF_2.mgmt
        testscript.parameters['LEAF-3_mgmt'] = LEAF_3.mgmt

        # =============================================================================================================================#
        # Make sure that the connection went fine

        for dut in device_list:
            if not hasattr(dut, 'execute'):
                self.failed()

            if dut.execute != dut.connectionmgr.default.execute:
                self.failed()

        # =============================================================================================================================#
        # Import script_flags into testscript.parameters
        testscript.parameters['topology_flag'] = topology_flag
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

        testscript.parameters['LEAF_1_dict']                    = configuration['LEAF_1_dict']
        testscript.parameters['LEAF_2_dict']                    = configuration['LEAF_2_dict']
        testscript.parameters['LEAF_3_dict']                    = configuration['LEAF_3_dict']
        testscript.parameters['forwardingSysDict']              = configuration['FWD_SYS_dict']

        testscript.parameters['LEAF_12_TGEN_dict']               = configuration['LEAF_12_TGEN_data']
        testscript.parameters['LEAF_3_TGEN_dict']               = configuration['LEAF_3_TGEN_data']
        testscript.parameters['LEAF_12_SUB_INT_TGEN_data']       = configuration['LEAF_12_SUB_INT_TGEN_data']
        testscript.parameters['LEAF_3_SUB_INT_TGEN_data']       = configuration['LEAF_3_SUB_INT_TGEN_data']

        testscript.parameters['leafVPCDictData']                = {LEAF_1: configuration['LEAF_1_dict'],
                                                                    LEAF_2: configuration['LEAF_2_dict']}
        testscript.parameters['leavesDictList']                 = [configuration['LEAF_1_dict'], configuration['LEAF_2_dict'],
                                                                    configuration['LEAF_3_dict']]
        testscript.parameters['leavesDict']                     = {LEAF_1: configuration['LEAF_1_dict'],
                                                                    LEAF_2: configuration['LEAF_2_dict'],
                                                                    LEAF_3: configuration['LEAF_3_dict']}

        testscript.parameters['VTEP_List']                      = [testscript.parameters['LEAF_1_dict'],
                                                                    testscript.parameters['LEAF_2_dict'],
                                                                    testscript.parameters['LEAF_3_dict']]
        # =============================================================================================================================#
        # Setting UP few necessary Variables
        testscript.parameters['STD_VTEP_ACCESS_PO_id'] = "20"


    # *****************************************************************************************************************************#
    @aetest.subsection
    def get_interfaces(self, testscript):
        """ common setup subsection: Getting required Connections for Test """

        SPINE   = testscript.parameters['SPINE']
        LEAF_1  = testscript.parameters['LEAF-1']
        LEAF_2  = testscript.parameters['LEAF-2']
        LEAF_3  = testscript.parameters['LEAF-3']
        FAN_1   = testscript.parameters['FAN-1']
        FAN_2   = testscript.parameters['FAN-2']
        IXIA    = testscript.parameters['IXIA']

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
        testscript.parameters['intf_LEAF_1_to_FAN_1'] = LEAF_1.interfaces['LEAF-1_to_FAN-1'].intf
        testscript.parameters['intf_LEAF_1_to_IXIA'] = LEAF_1.interfaces['LEAF-1_to_IXIA'].intf

        testscript.parameters['intf_LEAF_2_to_LEAF_1_1'] = LEAF_2.interfaces['LEAF-2_to_LEAF-1_1'].intf
        testscript.parameters['intf_LEAF_2_to_LEAF_1_2'] = LEAF_2.interfaces['LEAF-2_to_LEAF-1_2'].intf
        testscript.parameters['intf_LEAF_2_to_SPINE'] = LEAF_2.interfaces['LEAF-2_to_SPINE'].intf
        testscript.parameters['intf_LEAF_2_to_FAN_1'] = LEAF_2.interfaces['LEAF-2_to_FAN-1'].intf

        testscript.parameters['intf_LEAF_3_to_SPINE'] = LEAF_3.interfaces['LEAF-3_to_SPINE'].intf
        testscript.parameters['intf_LEAF_3_to_FAN_2'] = LEAF_3.interfaces['LEAF-3_to_FAN-2'].intf
        testscript.parameters['intf_LEAF_3_to_IXIA'] = LEAF_3.interfaces['LEAF-3_to_IXIA'].intf

        testscript.parameters['intf_FAN_1_to_LEAF_1'] = FAN_1.interfaces['FAN-1_to_LEAF-1'].intf
        testscript.parameters['intf_FAN_1_to_LEAF_2'] = FAN_1.interfaces['FAN-1_to_LEAF-2'].intf
        testscript.parameters['intf_FAN_1_to_IXIA'] = FAN_1.interfaces['FAN-1_to_IXIA'].intf

        testscript.parameters['intf_FAN_2_to_LEAF_3'] = FAN_2.interfaces['FAN-2_to_LEAF-3'].intf
        testscript.parameters['intf_FAN_2_to_IXIA'] = FAN_2.interfaces['FAN-2_to_IXIA'].intf

        testscript.parameters['intf_IXIA_to_FAN_1'] = IXIA.interfaces['IXIA_to_FAN-1'].intf
        testscript.parameters['intf_IXIA_to_FAN_2'] = IXIA.interfaces['IXIA_to_FAN-2'].intf
        testscript.parameters['intf_IXIA_to_LEAF_1'] = IXIA.interfaces['IXIA_to_LEAF-1'].intf
        testscript.parameters['intf_IXIA_to_LEAF_3'] = IXIA.interfaces['IXIA_to_LEAF-3'].intf

        testscript.parameters['ixia_int_list'] = str(testscript.parameters['intf_IXIA_to_FAN_1']) + " " + str(testscript.parameters['intf_IXIA_to_FAN_2']) \
                                                 + " " + str(testscript.parameters['intf_IXIA_to_LEAF_1']) + " " + str(testscript.parameters['intf_IXIA_to_LEAF_3'])

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
                     IXIA---|   LEAF-1  |====|   LEAF-2  |    |   LEAF-3  |--- IXIA
                            +-----------+    +-----------+    +-----------+
                                   \\             /                 |
                                    \\           /                  |
                                     \\         /                   |
                                      \\       /                    |
                                    +-----------+             +-----------+
                                    |   FAN-1   |             |   FAN-2   |
                                    +-----------+             +-----------+
                                          |                         |      
                                          |                         |      
                                        IXIA                      IXIA     
        """

        log.info("Topology to be used is")
        log.info(topology)

# *****************************************************************************************************************************#

class DEVICE_BRINGUP(aetest.Testcase):
    """Device Bring-up Test-Case"""

    # *****************************************************************************************************************************#
    @aetest.test
    def enable_feature_set(self, testscript):
        """ Device Bring-up subsection: Configuring Features and Feature-sets """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            leafLst                 = [testscript.parameters['LEAF-1'], testscript.parameters['LEAF-2'], testscript.parameters['LEAF-3']]
            spineFeatureList        = ['ospf', 'bgp', 'pim', 'lacp', 'nv overlay']
            vpcLeafFeatureList      = ['vpc', 'ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp', 'nv overlay']
            LeafFeatureList         = ['ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp', 'nv overlay']
            fanOutFeatureList       = ['lacp']
            configFeatureSet_status = []
            configFeatureSet_msgs = ""

            # --------------------------------
            # Configure Feature Set on Leafs
            featureSetConfigureLeafs_status = infraConfig.configureVerifyFeatureSet(leafLst, ['mpls'])
            if featureSetConfigureLeafs_status['result']:
                log.info("Passed Configuring feature Sets on all Leafs")
            else:
                log.debug("Failed Configuring feature Sets on all Leafs")
                configFeatureSet_msgs += featureSetConfigureLeafs_status['log']
                configFeatureSet_status.append(0)

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
            featureSetConfigureLeaf1_status = infraConfig.configureVerifyFeatureSet(testscript.parameters['LEAF-1'], ['mpls'])
            if featureSetConfigureLeaf1_status['result']:
                log.info("Passed Configuring feature-sets on LEAF-1")
            else:
                log.debug("Failed configuring feature-sets on LEAF-1")
                configFeatureSet_msgs += featureSetConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            featureConfigureLeaf1_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-1'], vpcLeafFeatureList)
            if featureConfigureLeaf1_status['result']:
                log.info("Passed Configuring features on LEAF-1")
            else:
                log.debug("Failed configuring features on LEAF-1")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-2
            featureSetConfigureLeaf2_status = infraConfig.configureVerifyFeatureSet(testscript.parameters['LEAF-2'], ['mpls'])
            if featureSetConfigureLeaf2_status['result']:
                log.info("Passed Configuring feature-sets on LEAF-2")
            else:
                log.debug("Failed configuring feature-sets on LEAF-2")
                configFeatureSet_msgs += featureSetConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            featureConfigureLeaf2_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-2'], vpcLeafFeatureList)
            if featureConfigureLeaf2_status['result']:
                log.info("Passed Configuring features on LEAF-2")
            else:
                log.debug("Failed configuring features on LEAF-2")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-3
            featureSetConfigureLeaf3_status = infraConfig.configureVerifyFeatureSet(testscript.parameters['LEAF-3'], ['mpls'])
            if featureSetConfigureLeaf3_status['result']:
                log.info("Passed Configuring feature-sets on LEAF-3")
            else:
                log.debug("Failed configuring feature-sets on LEAF-3")
                configFeatureSet_msgs += featureSetConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

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

            # --------------------------------
            # Configure Feature-set on FAN-2
            featureConfigureFan2_status = infraConfig.configureVerifyFeature(testscript.parameters['FAN-2'], fanOutFeatureList)
            if featureConfigureFan2_status['result']:
                log.info("Passed Configuring features on FAN-2")
            else:
                log.debug("Failed configuring features on FAN-2")
                configFeatureSet_msgs += featureConfigureFan2_status['log']
                configFeatureSet_status.append(0)


            if 0 in configFeatureSet_status:
                self.failed(reason=configFeatureSet_msgs, goto=['common_cleanup'])

        else:
            self.passed(reason="Skipped Device Configuration as per request")

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_SPINE(self, testscript):
        """ Device Bring-up subsection: Configuring SPINE """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNSpines([testscript.parameters['SPINE']], testscript.parameters['forwardingSysDict'] , testscript.parameters['leavesDictList'])

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
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_LEAF_1_2(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNVPCLeafs(testscript.parameters['forwardingSysDict'], testscript.parameters['leafVPCDictData'])

            try:
                testscript.parameters['LEAF-1'].configure('''
                    
                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_SPINE']) + '''
                    channel-group ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                    no shutdown
                    
                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_FAN_1']) + '''
                    channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + ''' force mode active
                    no shutdown
                    
                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_2_1']) + '''
                    no switchport
                    vrf member peer-keep-alive
                    ip address ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['kp_al_ip']) + '''/24
                    no shutdown
                    
                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_2_2']) + '''
                    channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po']) + ''' force mode active
                    no shutdown
                    
                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_IXIA']) + '''
                    no switchport
                    no shut
                    
                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_IXIA']) + '''.1
                    vrf member ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + '''1
                    encapsulation dot1q ''' + str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['vlan_id']) + '''
                    ip address ''' + str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v4_gateway']) + '''/24
                    ipv6 address ''' + str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v6_gateway']) + '''/64
                    no shutdown
                
              ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on LEAF-1', goto=['common_cleanup'])

            try:
                testscript.parameters['LEAF-2'].configure('''
                    
                  interface ''' + str(testscript.parameters['intf_LEAF_2_to_SPINE']) + '''
                    channel-group ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                    no shutdown
                    
                  interface ''' + str(testscript.parameters['intf_LEAF_2_to_FAN_1']) + '''
                    channel-group ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + ''' force mode active
                    no shutdown
                    
                  interface ''' + str(testscript.parameters['intf_LEAF_2_to_LEAF_1_1']) + '''
                    no switchport
                    vrf member peer-keep-alive
                    ip address ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['kp_al_ip']) + '''/24
                    no shutdown
                    
                  interface ''' + str(testscript.parameters['intf_LEAF_2_to_LEAF_1_2']) + '''
                    channel-group ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['peer_link_po']) + ''' force mode active
                    no shutdown
                    
                  interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                    shutdown
            ''')

            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on LEAF-2', goto=['common_cleanup'])

        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_LEAF_3(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-3 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNLeaf(testscript.parameters['LEAF-3'], testscript.parameters['forwardingSysDict'], testscript.parameters['LEAF_3_dict'])

            try:
                testscript.parameters['LEAF-3'].configure('''
                    
                    interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''
                      channel-group ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown
                      
                    interface port-channel '''+str(testscript.parameters['STD_VTEP_ACCESS_PO_id'])+'''
                      switchport
                      switchport mode trunk
                      no shutdown
                    
                    interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                      channel-group '''+str(testscript.parameters['STD_VTEP_ACCESS_PO_id'])+''' force mode active
                      no shutdown
                    
                    interface ''' + str(testscript.parameters['intf_LEAF_3_to_IXIA']) + '''
                      no switchport
                      no shutdown
                    
                    interface ''' + str(testscript.parameters['intf_LEAF_3_to_IXIA']) + '''.1
                      vrf member ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + '''1
                      encapsulation dot1q ''' + str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['vlan_id']) + '''
                      ip address ''' + str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v4_gateway']) + '''/24
                      ipv6 address ''' + str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v6_gateway']) + '''/64
                      no shutdown
                    
              ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on LEAF-3', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_FAN_1(self, testscript):
        """ Device Bring-up subsection: Configuring FAN_1 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            fanOut1_vlanConfiguration   = ""

            l3_vrf_count_iter           = 0
            l2_vlan_id                  = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            l3_vlan_id                  = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                l2_vlan_count_iter = 0
                fanOut1_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''
                                                state active
                                                no shut
                                                '''
                while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                    # Incrementing L2 VLAN Iteration counters
                    fanOut1_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''
                                                    state active
                                                    no shut
                                                    '''
                    l2_vlan_count_iter += 1
                    l2_vlan_id += 1
                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1

            try:
                testscript.parameters['FAN-1'].configure(
                                    str(fanOut1_vlanConfiguration) + '''
                                      
                                    interface port-channel200
                                      switchport
                                      switchport mode trunk
                                      no shutdown
                                      
                                    interface '''+str(testscript.parameters['intf_FAN_1_to_LEAF_1'])+'''
                                      channel-group 200 force mode active
                                      no shutdown
                                      
                                    interface '''+str(testscript.parameters['intf_FAN_1_to_LEAF_2'])+'''
                                      channel-group 200 force mode active
                                      no shutdown
                                      
                                    interface '''+str(testscript.parameters['intf_FAN_1_to_IXIA'])+'''
                                      switchport
                                      switchport mode trunk
                                      no shut
                                      
                                ''')

            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FAN-1', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per Request")

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_FAN_2(self, testscript):
        """ Device Bring-up subsection: Configuring FAN_2 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            fanOut2_vlanConfiguration = ""

            l3_vrf_count_iter = 0
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                l2_vlan_count_iter = 0
                fanOut2_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''
                                                state active
                                                no shut
                                                '''
                while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                    # Incrementing L2 VLAN Iteration counters
                    fanOut2_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''
                                                    state active
                                                    no shut
                                                    '''
                    l2_vlan_count_iter += 1
                    l2_vlan_id += 1
                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1

            try:
                testscript.parameters['FAN-2'].configure(
                    str(fanOut2_vlanConfiguration) + '''
                                    
                                    interface port-channel '''+str(testscript.parameters['STD_VTEP_ACCESS_PO_id'])+'''
                                      switchport
                                      switchport mode trunk
                                      no shutdown
                                    
                                    interface '''+str(testscript.parameters['intf_FAN_2_to_LEAF_3'])+'''
                                      channel-group '''+str(testscript.parameters['STD_VTEP_ACCESS_PO_id'])+''' force mode active
                                      no shutdown
    
                                    interface '''+str(testscript.parameters['intf_FAN_2_to_IXIA'])+'''
                                      switchport
                                      switchport mode trunk
                                      no shut
    
                                ''')

            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FAN-2', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per Request")

    # =============================================================================================================================#
    @aetest.test
    def perform_copy_r_s(self, testscript):
        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Save all configurations (copy r s) """

        testscript.parameters['LEAF-1'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-3'].configure("copy r s", timeout=300)

        time.sleep(300)

    # *****************************************************************************************************************************#

# *****************************************************************************************************************************#
class VERIFY_NETWORK(aetest.Testcase):
    """This is description for my testcase one"""

    # =============================================================================================================================#
    @aetest.test
    def verify_vpc(self, testscript):
        """ VERIFY_NETWORK subsection: Verify VPC """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        if EnsureVpcRole(LEAF_1,LEAF_2) == 1:

            VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

            if VPCStatus['result']:
                log.info(VPCStatus['log'])
                log.info("PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Successfully Verified\n\n")
            else:
                log.info(VPCStatus['log'])
                log.info("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")
                self.failed()
        else:
            self.failed(reason="VPC Peers are not in expected roles")

    # =============================================================================================================================#
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        testscript.parameters['LEAF-2'].configure('''
              interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                no shutdown
        ''')
        time.sleep(120)

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        testscript.parameters['LEAF-2'].configure('''
              interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                shutdown
        ''')
        time.sleep(120)

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
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

    # *****************************************************************************************************************************#

# *****************************************************************************************************************************#
class IXIA_CONFIGURATION(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    # =============================================================================================================================#
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
            ix_int_2 = testscript.parameters['intf_IXIA_to_FAN_2']
            ix_int_3 = testscript.parameters['intf_IXIA_to_LEAF_1']
            ix_int_4 = testscript.parameters['intf_IXIA_to_LEAF_3']

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
                self.errored("Connecting to ixia failed", goto=['next_tc'])

            ch_key = result['port_handle']
            for ch_p in ixia_chassis_ip.split('.'):
                ch_key = ch_key[ch_p]

            log.info("Port Handles are:")
            log.info(ch_key)

            testscript.parameters['port_handle_1'] = ch_key[ix_int_1]
            testscript.parameters['port_handle_2'] = ch_key[ix_int_2]
            testscript.parameters['port_handle_3'] = ch_key[ix_int_3]
            testscript.parameters['port_handle_4'] = ch_key[ix_int_4]

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
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

            TOPO_3_dict = {'topology_name': 'LEAF-1-TG',
                           'device_grp_name': 'LEAF-1-TG',
                           'port_handle': testscript.parameters['port_handle_3']}

            TOPO_4_dict = {'topology_name': 'LEAF-3-TG',
                           'device_grp_name': 'LEAF-3-TG',
                           'port_handle': testscript.parameters['port_handle_4']}

            testscript.parameters['IX_TP1'] = ixLib.create_topo_device_grp(TOPO_1_dict)
            if testscript.parameters['IX_TP1'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed", goto=['next_tc'])
            else:
                log.info("Created FAN-1-TG Topology Successfully")

            testscript.parameters['IX_TP2'] = ixLib.create_topo_device_grp(TOPO_2_dict)
            if testscript.parameters['IX_TP2'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed", goto=['next_tc'])
            else:
                log.info("Created FAN-2-TG Topology Successfully")

            testscript.parameters['IX_TP3'] = ixLib.create_topo_device_grp(TOPO_3_dict)
            if testscript.parameters['IX_TP3'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed", goto=['next_tc'])
            else:
                log.info("Created LEAF-1-TG Topology Successfully")

            testscript.parameters['IX_TP4'] = ixLib.create_topo_device_grp(TOPO_4_dict)
            if testscript.parameters['IX_TP4'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed", goto=['next_tc'])
            else:
                log.info("Created LEAF-3-TG Topology Successfully")

            testscript.parameters['IX_TP1']['port_handle'] = testscript.parameters['port_handle_1']
            testscript.parameters['IX_TP2']['port_handle'] = testscript.parameters['port_handle_2']
            testscript.parameters['IX_TP3']['port_handle'] = testscript.parameters['port_handle_3']
            testscript.parameters['IX_TP4']['port_handle'] = testscript.parameters['port_handle_4']
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_IXIA_INTERFACES(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure IXIA Interfaces """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            P1 = testscript.parameters['port_handle_1']
            P2 = testscript.parameters['port_handle_2']
            P3 = testscript.parameters['port_handle_3']
            P4 = testscript.parameters['port_handle_4']

            # Retrieving TGEN Data from Config file
            P1_tgen_dict            = testscript.parameters['LEAF_12_TGEN_dict']
            P1_SUB_INT_tgen_dict    = testscript.parameters['LEAF_12_SUB_INT_TGEN_data']
            P2_tgen_dict            = testscript.parameters['LEAF_3_TGEN_dict']
            P2_SUB_INT_tgen_dict    = testscript.parameters['LEAF_3_SUB_INT_TGEN_data']

            P1_int_dict_1 = {'dev_grp_hndl'         : testscript.parameters['IX_TP1']['dev_grp_hndl'],
                             'port_hndl'            : P1,
                             'no_of_ints'           : str(P1_tgen_dict['no_of_ints']),
                             'phy_mode'             : P1_tgen_dict['phy_mode'],
                             'mac'                  : P1_tgen_dict['mac'],
                             'mac_step'             : P1_tgen_dict['mac_step'],
                             'protocol'             : P1_tgen_dict['protocol'],
                             'v4_addr'              : P1_tgen_dict['v4_addr'],
                             'v4_addr_step'         : P1_tgen_dict['v4_addr_step'],
                             'v4_gateway'           : P1_tgen_dict['v4_gateway'],
                             'v4_gateway_step'      : P1_tgen_dict['v4_gateway_step'],
                             'v4_netmask'           : P1_tgen_dict['v4_netmask'],
                             'v6_addr'              : P1_tgen_dict['v6_addr'],
                             'v6_addr_step'         : P1_tgen_dict['v6_addr_step'],
                             'v6_gateway'           : P1_tgen_dict['v6_gateway'],
                             'v6_gateway_step'      : P1_tgen_dict['v6_gateway_step'],
                             'v6_netmask'           : P1_tgen_dict['v6_netmask'],
                             'vlan_id'              : str(P1_tgen_dict['vlan_id']),
                             'vlan_id_step'         : P1_tgen_dict['vlan_id_step']}

            P1_sub_int_dict_1 = {'dev_grp_hndl'     : testscript.parameters['IX_TP3']['dev_grp_hndl'],
                             'port_hndl'            : P3,
                             'no_of_ints'           : str(P1_SUB_INT_tgen_dict['no_of_ints']),
                             'phy_mode'             : P1_SUB_INT_tgen_dict['phy_mode'],
                             'mac'                  : P1_SUB_INT_tgen_dict['mac'],
                             'mac_step'             : P1_SUB_INT_tgen_dict['mac_step'],
                             'protocol'             : P1_SUB_INT_tgen_dict['protocol'],
                             'v4_addr'              : P1_SUB_INT_tgen_dict['v4_addr'],
                             'v4_addr_step'         : P1_SUB_INT_tgen_dict['v4_addr_step'],
                             'v4_gateway'           : P1_SUB_INT_tgen_dict['v4_gateway'],
                             'v4_gateway_step'      : P1_SUB_INT_tgen_dict['v4_gateway_step'],
                             'v4_netmask'           : P1_SUB_INT_tgen_dict['v4_netmask'],
                             'v6_addr'              : P1_SUB_INT_tgen_dict['v6_addr'],
                             'v6_addr_step'         : P1_SUB_INT_tgen_dict['v6_addr_step'],
                             'v6_gateway'           : P1_SUB_INT_tgen_dict['v6_gateway'],
                             'v6_gateway_step'      : P1_SUB_INT_tgen_dict['v6_gateway_step'],
                             'v6_netmask'           : P1_SUB_INT_tgen_dict['v6_netmask'],
                             'vlan_id'              : str(P1_SUB_INT_tgen_dict['vlan_id']),
                             'vlan_id_step'         : P1_SUB_INT_tgen_dict['vlan_id_step']}

            P2_int_dict_1 = {'dev_grp_hndl'         : testscript.parameters['IX_TP2']['dev_grp_hndl'],
                             'port_hndl'            : P2,
                             'no_of_ints'           : str(P2_tgen_dict['no_of_ints']),
                             'phy_mode'             : P2_tgen_dict['phy_mode'],
                             'mac'                  : P2_tgen_dict['mac'],
                             'mac_step'             : P2_tgen_dict['mac_step'],
                             'protocol'             : P2_tgen_dict['protocol'],
                             'v4_addr'              : P2_tgen_dict['v4_addr'],
                             'v4_addr_step'         : P2_tgen_dict['v4_addr_step'],
                             'v4_gateway'           : P2_tgen_dict['v4_gateway'],
                             'v4_gateway_step'      : P2_tgen_dict['v4_gateway_step'],
                             'v4_netmask'           : P2_tgen_dict['v4_netmask'],
                             'v6_addr'              : P2_tgen_dict['v6_addr'],
                             'v6_addr_step'         : P2_tgen_dict['v6_addr_step'],
                             'v6_gateway'           : P2_tgen_dict['v6_gateway'],
                             'v6_gateway_step'      : P2_tgen_dict['v6_gateway_step'],
                             'v6_netmask'           : P2_tgen_dict['v6_netmask'],
                             'vlan_id'              : str(P2_tgen_dict['vlan_id']),
                             'vlan_id_step'         : P2_tgen_dict['vlan_id_step']}

            P2_sub_int_dict_1 = {'dev_grp_hndl'     : testscript.parameters['IX_TP4']['dev_grp_hndl'],
                             'port_hndl'            : P4,
                             'no_of_ints'           : str(P2_SUB_INT_tgen_dict['no_of_ints']),
                             'phy_mode'             : P2_SUB_INT_tgen_dict['phy_mode'],
                             'mac'                  : P2_SUB_INT_tgen_dict['mac'],
                             'mac_step'             : P2_SUB_INT_tgen_dict['mac_step'],
                             'protocol'             : P2_SUB_INT_tgen_dict['protocol'],
                             'v4_addr'              : P2_SUB_INT_tgen_dict['v4_addr'],
                             'v4_addr_step'         : P2_SUB_INT_tgen_dict['v4_addr_step'],
                             'v4_gateway'           : P2_SUB_INT_tgen_dict['v4_gateway'],
                             'v4_gateway_step'      : P2_SUB_INT_tgen_dict['v4_gateway_step'],
                             'v4_netmask'           : P2_SUB_INT_tgen_dict['v4_netmask'],
                             'v6_addr'              : P2_SUB_INT_tgen_dict['v6_addr'],
                             'v6_addr_step'         : P2_SUB_INT_tgen_dict['v6_addr_step'],
                             'v6_gateway'           : P2_SUB_INT_tgen_dict['v6_gateway'],
                             'v6_gateway_step'      : P2_SUB_INT_tgen_dict['v6_gateway_step'],
                             'v6_netmask'           : P2_SUB_INT_tgen_dict['v6_netmask'],
                             'vlan_id'              : str(P2_SUB_INT_tgen_dict['vlan_id']),
                             'vlan_id_step'         : P2_SUB_INT_tgen_dict['vlan_id_step']}

            P1_IX_int_data = ixLib.configure_multi_ixia_interface(P1_int_dict_1)
            P2_IX_int_data = ixLib.configure_multi_ixia_interface(P2_int_dict_1)
            P1_IX_sub_int_data = ixLib.configure_multi_ixia_interface(P1_sub_int_dict_1)
            P2_IX_sub_int_data = ixLib.configure_multi_ixia_interface(P2_sub_int_dict_1)

            if P1_IX_int_data == 0 or P2_IX_int_data == 0 or P1_IX_sub_int_data == 0 or P2_IX_sub_int_data == 0:
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

            testscript.parameters['IX_TP3']['eth_handle'] = P1_IX_sub_int_data['eth_handle']
            testscript.parameters['IX_TP3']['ipv4_handle'] = P1_IX_sub_int_data['ipv4_handle']
            testscript.parameters['IX_TP3']['ipv6_handle'] = P1_IX_sub_int_data['ipv6_handle']
            testscript.parameters['IX_TP3']['topo_int_handle'] = P1_IX_sub_int_data['topo_int_handle'].split(" ")

            testscript.parameters['IX_TP4']['eth_handle'] = P2_IX_sub_int_data['eth_handle']
            testscript.parameters['IX_TP4']['ipv4_handle'] = P2_IX_sub_int_data['ipv4_handle']
            testscript.parameters['IX_TP4']['ipv6_handle'] = P2_IX_sub_int_data['ipv6_handle']
            testscript.parameters['IX_TP4']['topo_int_handle'] = P2_IX_sub_int_data['topo_int_handle'].split(" ")

            log.info("IXIA Port 1 Handles")
            log.info(testscript.parameters['IX_TP1'])
            log.info("IXIA Port 2 Handles")
            log.info(testscript.parameters['IX_TP2'])
            log.info("IXIA Port 3 Handles")
            log.info(testscript.parameters['IX_TP3'])
            log.info("IXIA Port 4 Handles")
            log.info(testscript.parameters['IX_TP4'])

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
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

        time.sleep(120)

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_UCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']
            IX_TP3 = testscript.parameters['IX_TP3']
            IX_TP4 = testscript.parameters['IX_TP4']


            UCAST_v4_dict = {   'src_hndl'  : IX_TP1['ipv4_handle'],
                                'dst_hndl'  : IX_TP2['ipv4_handle'],
                                'circuit'   : 'ipv4',
                                'TI_name'   : "UCAST_V4",
                                'rate_pps'  : "1000",
                                'bi_dir'    : 1
                          }

            sub_int_UCAST_v4_dict = {   'src_hndl'  : IX_TP3['ipv4_handle'],
                                'dst_hndl'  : IX_TP4['ipv4_handle'],
                                'circuit'   : 'ipv4',
                                'TI_name'   : "UCAST_sub_int_V4",
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

            sub_int_UCAST_v6_dict = {   'src_hndl'  : IX_TP3['ipv6_handle'],
                                'dst_hndl'  : IX_TP4['ipv6_handle'],
                                'circuit'   : 'ipv6',
                                'TI_name'   : "UCAST_sub_int_V6",
                                'rate_pps'  : "1000",
                                'bi_dir'    : 1
                          }

            UCAST_v4_TI = ixLib.configure_ixia_traffic_item(UCAST_v4_dict)
            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)
            UCAST_v4_sub_int_TI = ixLib.configure_ixia_traffic_item(sub_int_UCAST_v4_dict)
            UCAST_v6_sub_int_TI = ixLib.configure_ixia_traffic_item(sub_int_UCAST_v6_dict)

            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0 or UCAST_v4_sub_int_TI == 0 or UCAST_v6_sub_int_TI == 0:
                log.debug("Configuring UCast TI failed")
                self.errored("Configuring UCast TI failed", goto=['next_tc'])

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['next_tc'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2,3) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class FLAP_VPC_PO_on_VPC_PRIMARY(aetest.Testcase):
    """START_IXIA_TRAFFIC"""

    # =============================================================================================================================#
    @aetest.test
    def flap_VPC_PO_on_vpc_primary(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        testscript.parameters["LEAF-1"].configure('''
                interface port-channel''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
                    shut
        ''')

        time.sleep(10)

        testscript.parameters["LEAF-1"].configure('''
                interface port-channel''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
                    no shut
        ''')

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2,3) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class SHUT_SECONDARY_VPC_UPLINK(aetest.Testcase):
    """START_IXIA_TRAFFIC"""

    # =============================================================================================================================#
    @aetest.test
    def SHUT_SECONDARY_VPC_UPLINK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        testscript.parameters["LEAF-2"].configure('''
                interface port-channel''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                    shut
        ''')

        time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2,3) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class START_IXIA_TRAFFIC(aetest.Testcase):
    """START_IXIA_TRAFFIC"""

    # =============================================================================================================================#
    @aetest.test
    def start_ixia_traffic(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        if ixLib.start_traffic() == 0:
            log.debug("Starting Traffic failed")
            self.failed("Starting Traffic failed", goto=['cleanup'])

# *****************************************************************************************************************************#
class VERIFY_NIA_FSV_INNER_VxLAN_IPv4_STD_VTEP_IIF_OIF_PO(aetest.Testcase):
    """VERIFY_NIA_FSV_INNER_VxLAN_IPv4_STD_VTEP_IIF_OIF_PO"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_CC_COUNT(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # NIA CLI CC flags
        niaCCStatus = []

        # Declare the parameters required for the NIA CLI
        niaCLIEncapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_TGEN_dict']['v4_addr']),
                'dest'          : str(testscript.parameters['LEAF_12_TGEN_dict']['v4_addr']),
                'smac'          : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'iif'           : "port-channel"+str(testscript.parameters['STD_VTEP_ACCESS_PO_id']),
                'vlan'          : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'macAddr'       : [str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),str(testscript.parameters['LEAF_12_TGEN_dict']['mac'])],
                'module'        : ['1'],
                'port'          : ['Vlan' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']), testscript.parameters['intf_LEAF_3_to_FAN_2'], 'nve1'],
                'vlan'          : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [{
                                "encap": {
                                    "dst": str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP']),
                                    "iif": str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']),
                                    "l2vni": int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),
                                    "l3vni": 0,
                                    "src": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                                    "type": "VxLAN"
                                },
                                "log_oif": "nve1",
                                "oif": "nve1",
                                "phy_oif": "nve1"
                }],
            }
        }

        # Build NIA CLI
        niaCLI = "show nia validate flow"
        niaCLI += " src " + str(niaCLIEncapInner_v4['cli_params']['src'])
        niaCLI += " smac " + str(niaCLIEncapInner_v4['cli_params']['smac'])
        niaCLI += " dest " + str(niaCLIEncapInner_v4['cli_params']['dest'])
        niaCLI += " dmac " + str(niaCLIEncapInner_v4['cli_params']['dmac'])
        niaCLI += " iif " + str(niaCLIEncapInner_v4['cli_params']['iif'])
        niaCLI += " vlan " + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])
        niaCLI += " cc 1 "

        niaCLIOutput = testscript.parameters['LEAF-3'].execute(str(niaCLI) + '| grep \'"cmd":\' | i i "vxlan"', timeout=1200)

        if not 'show consistency-checker vxlan l2 mac-address' in niaCLIOutput:
            log.info("NIA : VxLAN L2 MAC-ADDRESS CC is not being executed")
            niaCCStatus.append(0)
        if not 'show consistency-checker vxlan l3 single-route' in niaCLIOutput:
            log.info("NIA : VxLAN L3 SINGLE-ROUTE CC is not being executed")
            niaCCStatus.append(0)
        if not 'show consistency-checker vxlan vlan' in niaCLIOutput:
            log.info("NIA : VxLAN VLAN CC is not being executed")
            niaCCStatus.append(0)

        if 0 in niaCCStatus:
            self.failed(reason="FAIL : Few of the VxLAN CC are not being run as part of NIA CLI CC invocation")
        else:
            self.passed(reason="PASS : All 3 VxLAN CC are being run as part of NIA CLI CC invocation")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_ENCAP_v4(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        # Declare the parameters required for the NIA CLI
        niaCLIEncapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_TGEN_dict']['v4_addr']),
                'dest'          : str(testscript.parameters['LEAF_12_TGEN_dict']['v4_addr']),
                'smac'          : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'iif'           : "port-channel"+str(testscript.parameters['STD_VTEP_ACCESS_PO_id']),
                'vlan'          : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : "port-channel"+str(testscript.parameters['STD_VTEP_ACCESS_PO_id']),
                'in_lif'        : 'vlan' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'in_po_mbrs'    : [str(testscript.parameters['intf_LEAF_3_to_FAN_2'])],
                'in_vlan'       : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),str(testscript.parameters['LEAF_12_TGEN_dict']['mac'])],
                'module'        : ['1'],
                'port'          : ['Vlan' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                                   testscript.parameters['intf_LEAF_3_to_FAN_2'],
                                   'nve1',
                                   "port-channel"+str(testscript.parameters['STD_VTEP_ACCESS_PO_id'])
                                  ],
                'vlan'          : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [{
                                "encap": {
                                    "dst": VPC_VTEP_IP,
                                    "iif": str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']),
                                    "l2vni": int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),
                                    "l3vni": 0,
                                    "src": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                                    "type": "VxLAN"
                                },
                                "log_oif": "nve1",
                                "oif": "nve1",
                                "phy_oif": "nve1"
                }],
            }
        }
        #elam_params
        if testscript.parameters['topology_flag'] == 0:
            niaCLIEncapInner_v4['cli_params']['traffic'] = '1'
            niaCLIEncapInner_v4['element_params']['iif'] = testscript.parameters['intf_LEAF_3_to_FAN_2']
            niaCLIEncapInner_v4['elam_params'] = {
                    'Packet Type'               : 'IPv4',
                    'Source IP'                 : str(testscript.parameters['LEAF_3_TGEN_dict']['v4_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_12_TGEN_dict']['v4_addr']),
                    'Source MAC'                : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                    'Destination MAC'           : "00:00:00:0A:AA:AA",
                    'src_vlan'                  : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                    'Source Bridge Domain'      : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                    'Destination Bridge Domain' : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_3_to_SPINE']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_3_to_FAN_2'])]
            }

        niaInnerEncapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-3'],niaCLIEncapInner_v4,testscript.parameters['LEAF-3_mgmt'])

        if not niaInnerEncapValidation['result']:
            log.info(niaInnerEncapValidation['log'])
            self.failed(reason="NIA VxLAN Inner ENCAP CLI Failed")
        else:
            log.info(niaInnerEncapValidation['log'])
            self.passed(reason="NIA VxLAN Inner ENCAP CLI Passed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_DECAP_v4(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Fetching the neighbor device's ID (Serial number)
        nbr_device_data = json.loads(testscript.parameters['LEAF-3'].execute("show cdp neigh interf " + str(testscript.parameters['intf_LEAF_3_to_FAN_2'])+ " det | json"))
        nbr_device_data_parsing = re.search('\((\\w+)\)', nbr_device_data['TABLE_cdp_neighbor_detail_info']['ROW_cdp_neighbor_detail_info']['device_id'], re.I)
        nbr_device_id = nbr_device_data_parsing.group(1)

        LEAF_1_mac_data = json.loads(testscript.parameters['LEAF-1'].execute("show vdc | json"))
        LEAF_1_mac = LEAF_1_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        LEAF_3_mac_data = json.loads(testscript.parameters['LEAF-3'].execute("show vdc | json"))
        LEAF_3_mac = LEAF_3_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        # Declare the parameters required for the NIA CLI
        niaCLIDecapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_12_TGEN_dict']['v4_addr']),
                'dest'          : str(testscript.parameters['LEAF_3_TGEN_dict']['v4_addr']),
                'smac'          : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'iif'           : 'nve1',
                'vlan'          : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'iif'           : "nve1",
                'in_lif'        : "nve1",
                'in_po_mbrs'    : [],
                'in_vlan'       : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),str(testscript.parameters['LEAF_12_TGEN_dict']['mac'])],
                'module'        : ['1'],
                'port'          : [testscript.parameters['intf_LEAF_3_to_FAN_2'],
                                   "Po"+str(testscript.parameters['STD_VTEP_ACCESS_PO_id']),
                                   "nve1",
                                   "Po" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id'])
                                  ],
                'vlan'          : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [{
                                    "log_oif"       : "Po"+str(testscript.parameters['STD_VTEP_ACCESS_PO_id']),
                                    "nbr"           : str(testscript.parameters['FAN-2'].alias),
                                    "nbr_phy_iif"   : str(testscript.parameters['intf_FAN_2_to_LEAF_3']),
                                    "nbr_sr_num"    : str(nbr_device_id),
                                    "nbr_vlan"      : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                                    "phy_oif"       : str(testscript.parameters['intf_LEAF_3_to_FAN_2'])
                                }],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIDecapInner_v4['cli_params']['traffic'] = '2'
            niaCLIDecapInner_v4['cli_params']['upper_iif'] = "port-channel" + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id'])
            niaCLIDecapInner_v4['element_params']['iif'] = testscript.parameters['intf_LEAF_3_to_SPINE']
            niaCLIDecapInner_v4['elam_params'] = {
                    'Packet Type'               : 'IPv4',
                    'Source IP'                 : str(testscript.parameters['LEAF_12_TGEN_dict']['v4_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_3_TGEN_dict']['v4_addr']),
                    'Source MAC'                : str(LEAF_1_mac),
                    'Destination MAC'           : str(LEAF_3_mac),
                    'src_vlan'                  : "",
                    'Source Bridge Domain'      : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']),
                    'Destination Bridge Domain' : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_3_to_FAN_2']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_3_to_SPINE'])]
            }

        niaInnerDecapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-3'],niaCLIDecapInner_v4,testscript.parameters['LEAF-3_mgmt'])

        if not niaInnerDecapValidation['result']:
            log.info(niaInnerDecapValidation['log'])
            self.failed(reason="NIA VxLAN Inner DECAP CLI Failed")
        else:
            log.info(niaInnerDecapValidation['log'])
            self.passed(reason="NIA VxLAN Inner DECAP CLI Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        for device in device_list:
            device.execute("show ver in bu")

        for device in device_mgmt_list:
            device.execute("show ver in bu")

# *****************************************************************************************************************************#
class VERIFY_NIA_FSV_INNER_VxLAN_IPv6_STD_VTEP_IIF_OIF_PO(aetest.Testcase):
    """VERIFY_NIA_FSV_INNER_VxLAN_IPv6_STD_VTEP_IIF_OIF_PO"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_CC_COUNT(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # NIA CLI CC flags
        niaCCStatus = []

        # Declare the parameters required for the NIA CLI
        niaCLIEncapInner_v6 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_TGEN_dict']['v6_addr']),
                'dest'          : str(testscript.parameters['LEAF_12_TGEN_dict']['v6_addr']),
                'smac'          : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'iif'           : "port-channel"+str(testscript.parameters['STD_VTEP_ACCESS_PO_id']),
                'vlan'          : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'macAddr'       : [str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),str(testscript.parameters['LEAF_12_TGEN_dict']['mac'])],
                'module'        : ['1'],
                'port'          : ['Vlan' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']), testscript.parameters['intf_LEAF_3_to_FAN_2'], 'nve1'],
                'vlan'          : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [{
                                "encap": {
                                    "dst": str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP']),
                                    "iif": str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']),
                                    "l2vni": int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),
                                    "l3vni": 0,
                                    "src": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                                    "type": "VxLAN"
                                },
                                "log_oif": "nve1",
                                "oif": "nve1",
                                "phy_oif": "nve1"
                }],
            }
        }

        # Build NIA CLI
        niaCLI = "show nia validate flow"
        niaCLI += " src " + str(niaCLIEncapInner_v6['cli_params']['src'])
        niaCLI += " smac " + str(niaCLIEncapInner_v6['cli_params']['smac'])
        niaCLI += " dest " + str(niaCLIEncapInner_v6['cli_params']['dest'])
        niaCLI += " dmac " + str(niaCLIEncapInner_v6['cli_params']['dmac'])
        niaCLI += " iif " + str(niaCLIEncapInner_v6['cli_params']['iif'])
        niaCLI += " vlan " + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])
        niaCLI += " cc 1 "

        niaCLIOutput = testscript.parameters['LEAF-3'].execute(str(niaCLI) + '| grep \'"cmd":\' | i i "vxlan"', timeout=1200)

        if not 'show consistency-checker vxlan l2 mac-address' in niaCLIOutput:
            log.info("NIA : VxLAN L2 MAC-ADDRESS CC is not being executed")
            niaCCStatus.append(0)
        if not 'show consistency-checker vxlan l3 single-route' in niaCLIOutput:
            log.info("NIA : VxLAN L3 SINGLE-ROUTE CC is not being executed")
            niaCCStatus.append(0)
        if not 'show consistency-checker vxlan vlan' in niaCLIOutput:
            log.info("NIA : VxLAN VLAN CC is not being executed")
            niaCCStatus.append(0)

        if 0 in niaCCStatus:
            self.failed(reason="FAIL : Few of the VxLAN CC are not being run as part of NIA CLI CC invocation")
        else:
            self.passed(reason="PASS : All 3 VxLAN CC are being run as part of NIA CLI CC invocation")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_ENCAP_v6(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        # Declare the parameters required for the NIA CLI
        niaCLIEncapInner_v6 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_TGEN_dict']['v6_addr']),
                'dest'          : str(testscript.parameters['LEAF_12_TGEN_dict']['v6_addr']),
                'smac'          : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'iif'           : "port-channel"+str(testscript.parameters['STD_VTEP_ACCESS_PO_id']),
                'vlan'          : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : "port-channel" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']),
                'in_lif'        : 'vlan' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'in_po_mbrs'    : [str(testscript.parameters['intf_LEAF_3_to_FAN_2'])],
                'in_vlan'       : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),str(testscript.parameters['LEAF_12_TGEN_dict']['mac'])],
                'module'        : ['1'],
                'port'          : ['Vlan' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                                   testscript.parameters['intf_LEAF_3_to_FAN_2'],
                                   'nve1',
                                   "port-channel"+str(testscript.parameters['STD_VTEP_ACCESS_PO_id'])
                                  ],
                'vlan'          : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [{
                                "encap": {
                                    "dst": VPC_VTEP_IP,
                                    "iif": str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']),
                                    "l2vni": int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),
                                    "l3vni": 0,
                                    "src": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                                    "type": "VxLAN"
                                },
                                "log_oif": "nve1",
                                "oif": "nve1",
                                "phy_oif": "nve1"
                }],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIEncapInner_v6['cli_params']['traffic'] = '1'
            niaCLIEncapInner_v6['element_params']['iif'] = testscript.parameters['intf_LEAF_3_to_FAN_2']
            niaCLIEncapInner_v6['elam_params'] = {
                    'Packet Type'               : 'IPv6',
                    'Source IP'                 : str(testscript.parameters['LEAF_3_TGEN_dict']['v6_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_12_TGEN_dict']['v6_addr']),
                    'Source MAC'                : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                    'Destination MAC'           : "00:00:00:0A:AA:AA",
                    'src_vlan'                  : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                    'Source Bridge Domain'      : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                    'Destination Bridge Domain' : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_3_to_SPINE']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_3_to_FAN_2'])]
            }

        niaInnerEncapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-3'],niaCLIEncapInner_v6,testscript.parameters['LEAF-3_mgmt'])

        if not niaInnerEncapValidation['result']:
            log.info(niaInnerEncapValidation['log'])
            self.failed(reason="NIA VxLAN Inner ENCAP CLI Failed")
        else:
            log.info(niaInnerEncapValidation['log'])
            self.passed(reason="NIA VxLAN Inner ENCAP CLI Passed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_DECAP_v6(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Fetching the neighbor device's ID (Serial number)
        nbr_device_data = json.loads(testscript.parameters['LEAF-3'].execute("show cdp neigh interf " + str(testscript.parameters['intf_LEAF_3_to_FAN_2'])+ " det | json"))
        nbr_device_data_parsing = re.search('\((\\w+)\)', nbr_device_data['TABLE_cdp_neighbor_detail_info']['ROW_cdp_neighbor_detail_info']['device_id'], re.I)
        nbr_device_id = nbr_device_data_parsing.group(1)

        LEAF_1_mac_data = json.loads(testscript.parameters['LEAF-1'].execute("show vdc | json"))
        LEAF_1_mac = LEAF_1_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        LEAF_3_mac_data = json.loads(testscript.parameters['LEAF-3'].execute("show vdc | json"))
        LEAF_3_mac = LEAF_3_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        # Declare the parameters required for the NIA CLI
        niaCLIDecapInner_v6 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_12_TGEN_dict']['v6_addr']),
                'dest'          : str(testscript.parameters['LEAF_3_TGEN_dict']['v6_addr']),
                'smac'          : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'iif'           : 'nve1',
                'vlan'          : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'iif'           : "nve1",
                'in_lif'        : "nve1",
                'in_po_mbrs'    : [],
                'in_vlan'       : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),str(testscript.parameters['LEAF_12_TGEN_dict']['mac'])],
                'module'        : ['1'],
                'port'          : [testscript.parameters['intf_LEAF_3_to_FAN_2'],
                                   "Po"+str(testscript.parameters['STD_VTEP_ACCESS_PO_id']),
                                   "nve1",
                                   "Po" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id'])
                                  ],
                'vlan'          : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [{
                                    "log_oif"       : "Po"+str(testscript.parameters['STD_VTEP_ACCESS_PO_id']),
                                    "nbr"           : str(testscript.parameters['FAN-2'].alias),
                                    "nbr_phy_iif"   : str(testscript.parameters['intf_FAN_2_to_LEAF_3']),
                                    "nbr_sr_num"    : str(nbr_device_id),
                                    "nbr_vlan"      : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                                    "phy_oif"       : str(testscript.parameters['intf_LEAF_3_to_FAN_2'])
                                }],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIDecapInner_v6['cli_params']['traffic'] = '2'
            niaCLIDecapInner_v6['cli_params']['upper_iif'] = "port-channel" + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id'])
            niaCLIDecapInner_v6['element_params']['iif'] = testscript.parameters['intf_LEAF_3_to_SPINE']
            niaCLIDecapInner_v6['elam_params'] = {
                    'Packet Type'               : 'IPv6',
                    'Source IP'                 : str(testscript.parameters['LEAF_12_TGEN_dict']['v6_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_3_TGEN_dict']['v6_addr']),
                    'Source MAC'                : str(LEAF_1_mac),
                    'Destination MAC'           : str(LEAF_3_mac),
                    'src_vlan'                  : "",
                    'Source Bridge Domain'      : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']),
                    'Destination Bridge Domain' : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_3_to_FAN_2']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_3_to_SPINE'])]
            }

        niaInnerDecapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-3'],niaCLIDecapInner_v6,testscript.parameters['LEAF-3_mgmt'])

        if not niaInnerDecapValidation['result']:
            log.info(niaInnerDecapValidation['log'])
            self.failed(reason="NIA VxLAN Inner DECAP CLI Failed")
        else:
            log.info(niaInnerDecapValidation['log'])
            self.passed(reason="NIA VxLAN Inner DECAP CLI Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for device in device_list:
            device.execute("show ver in bu")

        for device in device_mgmt_list:
            device.execute("show ver in bu")

# *****************************************************************************************************************************#
class VERIFY_NIA_FSV_OUTER_VxLAN_STD_VTEP_IIF_OIF_PO(aetest.Testcase):
    """VERIFY_NIA_FSV_OUTER_VxLAN_IPv4_STD_VTEP_IIF_OIF_PO"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_OUTER_ENCAP_v4(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        # Fetching the neighbor device's ID (Serial number)
        nbr_device_data = json.loads(testscript.parameters['LEAF-3'].execute("show cdp neigh interf " + str(testscript.parameters['intf_LEAF_3_to_SPINE'])+ " det | json"))
        nbr_device_data_parsing = re.search('\((\\w+)\)', nbr_device_data['TABLE_cdp_neighbor_detail_info']['ROW_cdp_neighbor_detail_info']['device_id'], re.I)
        nbr_device_id = nbr_device_data_parsing.group(1)

        niaCLIEncapOuter_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                'dest'          : VPC_VTEP_IP,
                'iif'           : str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']),
                'vlan'          : 0,
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']),
                'in_lif'        : str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']),
                'in_po_mbrs'    : [],
                'in_vlan'       : '0',
                'in_vrf'        : 'default',
                'macAddr'       : [],
                'module'        : ['1'],
                'port'          : [str(testscript.parameters['intf_LEAF_3_to_SPINE']), "port-channel" + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id'])],
                'vlan'          : [],
                'vni'           : [],
                'vpc'           : [],
                'iif_vrf'       : 'default',
                'route'         : [
                                {
                                    "ip": VPC_VTEP_IP + "/32",
                                    "type": "ipv4",
                                    "vrf": "default"
                                },
                                {
                                    "ip": str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']),
                                    "type": "ipv4",
                                    "vrf": "default"
                                }
                ],
                'last_path'     : [],
                'paths'         : [{
                                    "log_oif"       : "port-channel" + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']),
                                    "nbr"           : str(str(testscript.parameters['SPINE'].alias)),
                                    "nbr_phy_iif"   : str(testscript.parameters['intf_SPINE_to_LEAF_3']),
                                    "nbr_sr_num"    : str(nbr_device_id),
                                    "nbr_vlan"      : "0",
                                    "phy_oif"       : str(testscript.parameters['intf_LEAF_3_to_SPINE'])
                                }],
            }
        }

        niaOuterEncapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-3'],niaCLIEncapOuter_v4,testscript.parameters['LEAF-3_mgmt'])

        if not niaOuterEncapValidation['result']:
            log.info(niaOuterEncapValidation['log'])
            self.failed(reason="NIA VxLAN Outer ENCAP CLI Failed")
        else:
            log.info(niaOuterEncapValidation['log'])
            self.passed(reason="NIA VxLAN Outer ENCAP CLI Passed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_OUTER_DECAP_v4(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        # Declare the parameters required for the NIA CLI
        niaCLIDecapOuter_v4 = {
            'cli_params': {
                'src'           : VPC_VTEP_IP,
                'dest'          : str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                'iif'           : "port-channel"+str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']),
                'vlan'          : 0,
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : "port-channel"+str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']),
                'in_lif'        : "port-channel"+str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']),
                'in_po_mbrs'    : [str(testscript.parameters['intf_LEAF_3_to_SPINE'])],
                'in_vlan'       : '0',
                'in_vrf'        : 'default',
                'macAddr'       : [],
                'module'        : ['1'],
                'port'          : [str(testscript.parameters['intf_LEAF_3_to_SPINE']), "port-channel"+str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']),],
                'vlan'          : [],
                'vni'           : [],
                'vpc'           : [],
                'iif_vrf'       : 'default',
                'route'         : [
                                {
                                    "ip": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']) + "/32",
                                    "type": "ipv4",
                                    "vrf": "default"
                                },
                ],
                'last_path'     : [],
                'paths'         : [],
            }
        }

        niaOuterDecapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-3'],niaCLIDecapOuter_v4,testscript.parameters['LEAF-3_mgmt'])

        if not niaOuterDecapValidation['result']:
            log.info(niaOuterDecapValidation['log'])
            self.failed(reason="NIA VxLAN Outer DECAP CLI Failed")
        else:
            log.info(niaOuterDecapValidation['log'])
            self.passed(reason="NIA VxLAN Outer DECAP CLI Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for device in device_list:
            device.execute("show ver in bu")

        for device in device_mgmt_list:
            device.execute("show ver in bu")

# *****************************************************************************************************************************#
class UNSHUT_SECONDARY_VPC_UPLINK_BEFORE_CONFIG_CHANGE(aetest.Testcase):
    """START_IXIA_TRAFFIC"""

    # =============================================================================================================================#
    @aetest.test
    def UNSHUT_SECONDARY_VPC_UPLINK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        testscript.parameters["LEAF-2"].configure('''
                interface port-channel''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                    no shut
        ''')

        time.sleep(200)

    # =============================================================================================================================#
    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        testscript.parameters['LEAF-2'].configure('''
              interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                no shutdown
        ''')
        time.sleep(120)

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        testscript.parameters['LEAF-2'].configure('''
              interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                shutdown
        ''')
        time.sleep(60)

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2,3) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """

        for device in device_list:
            device.execute("show ver in bu")

        for device in device_mgmt_list:
            device.execute("show ver in bu")

# *****************************************************************************************************************************#
class STOP_IXIA_TRAFFIC_FOR_CONFIG_CHANGE(aetest.Testcase):
    """STOP_IXIA_TRAFFIC"""

    # =============================================================================================================================#
    @aetest.test
    def stop_ixia_traffic(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        if ixLib.start_traffic() == 0:
            log.debug("Starting Traffic failed")
            self.failed("Starting Traffic failed", goto=['cleanup'])

# *****************************************************************************************************************************#
class CHANGE_CONNECTIONS_FROM_PO_to_INT(aetest.Testcase):
    """CHANGE_CONNECTIONS_FROM_PO_to_INT"""

    # =============================================================================================================================#
    @aetest.test
    def CHANGE_ACCESS_FACING_INT(self, testscript):
        """ CHANGE_ACCESS_FACING_INT """

        fail_flag = []
        fail_logs = ""

        try:
            testscript.parameters['LEAF-3'].configure('''
                
                no interface port-channel ''' + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) + '''
                default interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                
                interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  switchport
                  switchport mode trunk
                  no shutdown
                  
          ''', timeout = 1200)

        except Exception as error:
            fail_logs += "Unable to configure change from PO to INT on LEAF-3 - Encountered Exception \n"+ str(error)
            fail_flag.append(0)

        try:
            testscript.parameters['FAN-2'].configure('''

                no interface port-channel ''' + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) + '''
                default interface ''' + str(testscript.parameters['intf_FAN_2_to_LEAF_3']) + '''

                interface ''' + str(testscript.parameters['intf_FAN_2_to_LEAF_3']) + '''
                  switchport
                  switchport mode trunk
                  no shutdown
                  
          ''', timeout = 1200)

        except Exception as error:
            fail_logs += "Unable to configure change from PO to INT on LEAF-3 - Encountered Exception \n" + str(error)
            fail_flag.append(0)

        if 0 in fail_flag:
            log.debug(fail_logs)
            self.failed(reason=fail_logs)
        else:
            self.passed()

    # =============================================================================================================================#
    @aetest.test
    def CHANGE_SPINE_FACING_INT(self, testscript):
        """ CHANGE_SPINE_FACING_INT """

        fail_flag           = []
        fail_logs           = ""
        forwardingSysDict   = testscript.parameters['forwardingSysDict']
        leaf_dict           = testscript.parameters['LEAF_3_dict']

        # --------------------------------
        # Configuring LEAF to SPINE Uplink
        leaf_uplink_configs = '''

            no interface port-channel ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
            default interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''

            interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''                
              ip address ''' + str(leaf_dict['SPINE_1_UPLINK_PO']['leaf_spine_po_v4']) + str(leaf_dict['SPINE_1_UPLINK_PO']['leaf_spine_mask_v4']) + '''
              ip ospf network point-to-point
              ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
              ip pim sparse-mode
              no shutdown
        '''
        if 'leaf_spine_po_v6' in leaf_dict['SPINE_1_UPLINK_PO'].keys():
            leaf_uplink_configs += '''          ipv6 address ''' + \
                                   str(leaf_dict['SPINE_1_UPLINK_PO']['leaf_spine_po_v6']) + \
                                   str(leaf_dict['SPINE_1_UPLINK_PO']['leaf_spine_mask_v6']) + '''\n'''

        try:
            testscript.parameters['LEAF-3'].configure(leaf_uplink_configs, timeout=1200)
        except Exception as error:
            fail_logs += "Unable to configure change from PO to INT on LEAF-3 - Encountered Exception \n" + str(error)
            fail_flag.append(0)

        # --------------------------------
        # Configuring SPINE to LEAF Uplink FAN-1
        spine_downlink_configs = '''
            no interface port-channel''' + str(leaf_dict['SPINE_1_UPLINK_PO']['po_id']) + '''
            default interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_3']) + '''
            
            interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_3']) + '''
                no switchport
                ip address ''' + str(leaf_dict['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + str(leaf_dict['SPINE_1_UPLINK_PO']['spine_leaf_mask_v4']) + '''
                ip ospf network point-to-point
                ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                ip pim sparse-mode
                no shutdown
        '''

        if 'spine_leaf_po_v6' in leaf_dict['SPINE_1_UPLINK_PO'].keys():
            spine_downlink_configs += '''          ipv6 address ''' + \
                                  str(leaf_dict['SPINE_1_UPLINK_PO']['spine_leaf_po_v6']) + \
                                  str(leaf_dict['SPINE_1_UPLINK_PO']['spine_leaf_mask_v6']) + '''\n'''

        try:
            testscript.parameters['SPINE'].configure(spine_downlink_configs, timeout=1200)
        except Exception as error:
            fail_logs += "Unable to configure change from PO to INT on SPINE - Encountered Exception \n" + str(error)
            fail_flag.append(0)

        if 0 in fail_flag:
            log.debug(fail_logs)
            self.failed(reason=fail_logs)
        else:
            self.passed()

    # =============================================================================================================================#
    @aetest.test
    def perform_copy_r_s(self, testscript):
        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Save all configurations (copy r s) """

        testscript.parameters['LEAF-1'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-3'].configure("copy r s", timeout=300)

        time.sleep(300)

    # =============================================================================================================================#
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        testscript.parameters['LEAF-2'].configure('''
              interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                no shutdown
        ''')
        time.sleep(120)

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        testscript.parameters['LEAF-2'].configure('''
              interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                shutdown
        ''')
        time.sleep(120)

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
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

    # =============================================================================================================================#
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

        time.sleep(120)

    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['next_tc'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2,3) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class SHUT_SECONDARY_VPC_UPLINK_AFTER_CONFIG_CHANGE(aetest.Testcase):
    """START_IXIA_TRAFFIC"""

    # =============================================================================================================================#
    @aetest.test
    def SHUT_SECONDARY_VPC_UPLINK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        testscript.parameters["LEAF-2"].configure('''
                interface port-channel''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                    shut
        ''')

        time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2,3) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class START_IXIA_TRAFFIC_POST_CONVERTING_FROM_PO_INT(aetest.Testcase):
    """START_IXIA_TRAFFIC"""

    # =============================================================================================================================#
    @aetest.test
    def start_ixia_traffic(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        if ixLib.start_traffic() == 0:
            log.debug("Starting Traffic failed")
            self.failed("Starting Traffic failed", goto=['cleanup'])

# *****************************************************************************************************************************#
class VERIFY_NIA_FSV_INNER_VxLAN_IPv4_STD_VTEP_IIF_OIF_INT(aetest.Testcase):
    """VERIFY_NIA_FSV_INNER_VxLAN_IPv4_STD_VTEP_IIF_OIF_INT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_CC_COUNT(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # NIA CLI CC flags
        niaCCStatus = []

        # Declare the parameters required for the NIA CLI
        niaCLIEncapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_TGEN_dict']['v4_addr']),
                'dest'          : str(testscript.parameters['LEAF_12_TGEN_dict']['v4_addr']),
                'smac'          : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'iif'           : testscript.parameters['intf_LEAF_3_to_FAN_2'],
                'vlan'          : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'macAddr'       : [str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),str(testscript.parameters['LEAF_12_TGEN_dict']['mac'])],
                'module'        : ['1'],
                'port'          : ['Vlan' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']), testscript.parameters['intf_LEAF_3_to_FAN_2'], 'nve1'],
                'vlan'          : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [{
                                "encap": {
                                    "dst": str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP']),
                                    "iif": str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']),
                                    "l2vni": int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),
                                    "l3vni": 0,
                                    "src": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                                    "type": "VxLAN"
                                },
                                "log_oif": "nve1",
                                "oif": "nve1",
                                "phy_oif": "nve1"
                }],
            }
        }

        # Build NIA CLI
        niaCLI = "show nia validate flow"
        niaCLI += " src " + str(niaCLIEncapInner_v4['cli_params']['src'])
        niaCLI += " smac " + str(niaCLIEncapInner_v4['cli_params']['smac'])
        niaCLI += " dest " + str(niaCLIEncapInner_v4['cli_params']['dest'])
        niaCLI += " dmac " + str(niaCLIEncapInner_v4['cli_params']['dmac'])
        niaCLI += " iif " + str(niaCLIEncapInner_v4['cli_params']['iif'])
        niaCLI += " vlan " + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])
        niaCLI += " cc 1 "

        niaCLIOutput = testscript.parameters['LEAF-3'].execute(str(niaCLI) + '| grep \'"cmd":\' | i i "vxlan"')

        if not 'show consistency-checker vxlan l2 mac-address' in niaCLIOutput:
            log.info("NIA : VxLAN L2 MAC-ADDRESS CC is not being executed")
            niaCCStatus.append(0)
        if not 'show consistency-checker vxlan l3 single-route' in niaCLIOutput:
            log.info("NIA : VxLAN L3 SINGLE-ROUTE CC is not being executed")
            niaCCStatus.append(0)
        if not 'show consistency-checker vxlan vlan' in niaCLIOutput:
            log.info("NIA : VxLAN VLAN CC is not being executed")
            niaCCStatus.append(0)

        if 0 in niaCCStatus:
            self.failed(reason="FAIL : Few of the VxLAN CC are not being run as part of NIA CLI CC invocation")
        else:
            self.passed(reason="PASS : All 3 VxLAN CC are being run as part of NIA CLI CC invocation")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_ENCAP_v4(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        # Declare the parameters required for the NIA CLI
        niaCLIEncapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_TGEN_dict']['v4_addr']),
                'dest'          : str(testscript.parameters['LEAF_12_TGEN_dict']['v4_addr']),
                'smac'          : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'iif'           : testscript.parameters['intf_LEAF_3_to_FAN_2'],
                'vlan'          : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : str(testscript.parameters['intf_LEAF_3_to_FAN_2']),
                'in_lif'        : 'vlan' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'in_po_mbrs'    : [],
                'in_vlan'       : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),str(testscript.parameters['LEAF_12_TGEN_dict']['mac'])],
                'module'        : ['1'],
                'port'          : ['Vlan' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']), testscript.parameters['intf_LEAF_3_to_FAN_2'], 'nve1'],
                'vlan'          : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [{
                                "encap": {
                                    "dst": VPC_VTEP_IP,
                                    "iif": str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']),
                                    "l2vni": int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),
                                    "l3vni": 0,
                                    "src": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                                    "type": "VxLAN"
                                },
                                "log_oif": "nve1",
                                "oif": "nve1",
                                "phy_oif": "nve1"
                }],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIEncapInner_v4['cli_params']['traffic'] = '1'
            niaCLIEncapInner_v4['element_params']['iif'] = testscript.parameters['intf_LEAF_3_to_FAN_2']
            niaCLIEncapInner_v4['elam_params'] = {
                    'Packet Type'               : 'IPv4',
                    'Source IP'                 : str(testscript.parameters['LEAF_3_TGEN_dict']['v4_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_12_TGEN_dict']['v4_addr']),
                    'Source MAC'                : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                    'Destination MAC'           : "00:00:00:0A:AA:AA",
                    'src_vlan'                  : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                    'Source Bridge Domain'      : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                    'Destination Bridge Domain' : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_3_to_SPINE']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_3_to_FAN_2'])]
            }

        niaInnerEncapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-3'],niaCLIEncapInner_v4,testscript.parameters['LEAF-3_mgmt'])

        if not niaInnerEncapValidation['result']:
            log.info(niaInnerEncapValidation['log'])
            self.failed(reason="NIA VxLAN Inner ENCAP CLI Failed")
        else:
            log.info(niaInnerEncapValidation['log'])
            self.passed(reason="NIA VxLAN Inner ENCAP CLI Passed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_DECAP_v4(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Fetching the neighbor device's ID (Serial number)
        nbr_device_data = json.loads(testscript.parameters['LEAF-3'].execute("show cdp neigh interf " + str(testscript.parameters['intf_LEAF_3_to_FAN_2'])+ " det | json"))
        nbr_device_data_parsing = re.search('\((\\w+)\)', nbr_device_data['TABLE_cdp_neighbor_detail_info']['ROW_cdp_neighbor_detail_info']['device_id'], re.I)
        nbr_device_id = nbr_device_data_parsing.group(1)

        LEAF_1_mac_data = json.loads(testscript.parameters['LEAF-1'].execute("show vdc | json"))
        LEAF_1_mac = LEAF_1_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        LEAF_3_mac_data = json.loads(testscript.parameters['LEAF-3'].execute("show vdc | json"))
        LEAF_3_mac = LEAF_3_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        # Declare the parameters required for the NIA CLI
        niaCLIDecapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_12_TGEN_dict']['v4_addr']),
                'dest'          : str(testscript.parameters['LEAF_3_TGEN_dict']['v4_addr']),
                'smac'          : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'iif'           : 'nve1',
                'vlan'          : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'iif'           : "nve1",
                'in_lif'        : "nve1",
                'in_po_mbrs'    : [],
                'in_vlan'       : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),str(testscript.parameters['LEAF_12_TGEN_dict']['mac'])],
                'module'        : ['1'],
                'port'          : [testscript.parameters['intf_LEAF_3_to_FAN_2'], 'nve1'],
                'vlan'          : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [{
                                    "log_oif"       : str(testscript.parameters['intf_LEAF_3_to_FAN_2']),
                                    "nbr"           : str(testscript.parameters['FAN-2'].alias),
                                    "nbr_phy_iif"   : str(testscript.parameters['intf_FAN_2_to_LEAF_3']),
                                    "nbr_sr_num"    : str(nbr_device_id),
                                    "nbr_vlan"      : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                                    "phy_oif"       : str(testscript.parameters['intf_LEAF_3_to_FAN_2'])
                                }],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIDecapInner_v4['cli_params']['traffic'] = '2'
            niaCLIDecapInner_v4['cli_params']['upper_iif'] = str(testscript.parameters['intf_LEAF_3_to_SPINE'])
            niaCLIDecapInner_v4['element_params']['iif'] = testscript.parameters['intf_LEAF_3_to_SPINE']
            niaCLIDecapInner_v4['elam_params'] = {
                    'Packet Type'               : 'IPv4',
                    'Source IP'                 : str(testscript.parameters['LEAF_12_TGEN_dict']['v4_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_3_TGEN_dict']['v4_addr']),
                    'Source MAC'                : str(LEAF_1_mac),
                    'Destination MAC'           : str(LEAF_3_mac),
                    'src_vlan'                  : "",
                    'Source Bridge Domain'      : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']),
                    'Destination Bridge Domain' : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_3_to_FAN_2']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_3_to_SPINE'])]
            }

        niaInnerDecapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-3'],niaCLIDecapInner_v4,testscript.parameters['LEAF-3_mgmt'])

        if not niaInnerDecapValidation['result']:
            log.info(niaInnerDecapValidation['log'])
            self.failed(reason="NIA VxLAN Inner DECAP CLI Failed")
        else:
            log.info(niaInnerDecapValidation['log'])
            self.passed(reason="NIA VxLAN Inner DECAP CLI Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for device in device_list:
            device.execute("show ver in bu")

        for device in device_mgmt_list:
            device.execute("show ver in bu")

# *****************************************************************************************************************************#
class VERIFY_NIA_FSV_INNER_VxLAN_IPv6_STD_VTEP_IIF_OIF_INT(aetest.Testcase):
    """VERIFY_NIA_FSV_INNER_VxLAN_IPv6_STD_VTEP_IIF_OIF_INT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_CC_COUNT(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # NIA CLI CC flags
        niaCCStatus = []

        # Declare the parameters required for the NIA CLI
        niaCLIEncapInner_v4 = {
            'cli_params': {
                'src': str(testscript.parameters['LEAF_3_TGEN_dict']['v6_addr']),
                'dest': str(testscript.parameters['LEAF_12_TGEN_dict']['v6_addr']),
                'smac': str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'dmac': str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'iif': testscript.parameters['intf_LEAF_3_to_FAN_2'],
                'vlan': str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'cc_flag': '1',
            },
            'element_params': {
                'BD': [],
                'macAddr': [str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                            str(testscript.parameters['LEAF_12_TGEN_dict']['mac'])],
                'module': ['1'],
                'port': ['Vlan' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                         testscript.parameters['intf_LEAF_3_to_FAN_2'], 'nve1'],
                'vlan': [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'vni': [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start'])],
                'vpc': [],
                'iif_vrf': str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route': [],
                'last_path': [],
                'paths': [{
                    "encap": {
                        "dst": str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP']),
                        "iif": str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']),
                        "l2vni": int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),
                        "l3vni": 0,
                        "src": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                        "type": "VxLAN"
                    },
                    "log_oif": "nve1",
                    "oif": "nve1",
                    "phy_oif": "nve1"
                }],
            }
        }

        # Build NIA CLI
        niaCLI = "show nia validate flow"
        niaCLI += " src " + str(niaCLIEncapInner_v4['cli_params']['src'])
        niaCLI += " smac " + str(niaCLIEncapInner_v4['cli_params']['smac'])
        niaCLI += " dest " + str(niaCLIEncapInner_v4['cli_params']['dest'])
        niaCLI += " dmac " + str(niaCLIEncapInner_v4['cli_params']['dmac'])
        niaCLI += " iif " + str(niaCLIEncapInner_v4['cli_params']['iif'])
        niaCLI += " vlan " + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])
        niaCLI += " cc 1 "

        niaCLIOutput = testscript.parameters['LEAF-3'].execute(str(niaCLI) + '| grep \'"cmd":\' | i i "vxlan"')

        if not 'show consistency-checker vxlan l2 mac-address' in niaCLIOutput:
            log.info("NIA : VxLAN L2 MAC-ADDRESS CC is not being executed")
            niaCCStatus.append(0)
        if not 'show consistency-checker vxlan l3 single-route' in niaCLIOutput:
            log.info("NIA : VxLAN L3 SINGLE-ROUTE CC is not being executed")
            niaCCStatus.append(0)
        if not 'show consistency-checker vxlan vlan' in niaCLIOutput:
            log.info("NIA : VxLAN VLAN CC is not being executed")
            niaCCStatus.append(0)

        if 0 in niaCCStatus:
            self.failed(reason="FAIL : Few of the VxLAN CC are not being run as part of NIA CLI CC invocation")
        else:
            self.passed(reason="PASS : All 3 VxLAN CC are being run as part of NIA CLI CC invocation")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_ENCAP_v6(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        # Declare the parameters required for the NIA CLI
        niaCLIEncapInner_v6 = {
            'cli_params': {
                'src'       : str(testscript.parameters['LEAF_3_TGEN_dict']['v6_addr']),
                'dest'      : str(testscript.parameters['LEAF_12_TGEN_dict']['v6_addr']),
                'smac'      : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'dmac'      : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'iif'       : testscript.parameters['intf_LEAF_3_to_FAN_2'],
                'vlan'      : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'cc_flag'   : '1',
            },
            'element_params'    : {
                'BD'            : [],
                'iif'           : str(testscript.parameters['intf_LEAF_3_to_FAN_2']),
                'in_lif'        : 'vlan' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'in_po_mbrs'    : [],
                'in_vlan'       : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                                    str(testscript.parameters['LEAF_12_TGEN_dict']['mac'])],
                'module'        : ['1'],
                'port'          : ['Vlan' + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                                    testscript.parameters['intf_LEAF_3_to_FAN_2'], 'nve1'],
                'vlan'          : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [{
                                    "encap": {
                                        "dst": VPC_VTEP_IP,
                                        "iif": str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']),
                                        "l2vni": int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),
                                        "l3vni": 0,
                                        "src": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                                        "type": "VxLAN"
                                    },
                                "log_oif": "nve1",
                                "oif": "nve1",
                                "phy_oif": "nve1"
                            }],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIEncapInner_v6['cli_params']['traffic'] = '1'
            niaCLIEncapInner_v6['element_params']['iif'] = testscript.parameters['intf_LEAF_3_to_FAN_2']
            niaCLIEncapInner_v6['elam_params'] = {
                    'Packet Type'               : 'IPv6',
                    'Source IP'                 : str(testscript.parameters['LEAF_3_TGEN_dict']['v6_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_12_TGEN_dict']['v6_addr']),
                    'Source MAC'                : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                    'Destination MAC'           : "00:00:00:0A:AA:AA",
                    'src_vlan'                  : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                    'Source Bridge Domain'      : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                    'Destination Bridge Domain' : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_3_to_SPINE']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_3_to_FAN_2'])]
            }

        niaInnerEncapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-3'], niaCLIEncapInner_v6,testscript.parameters['LEAF-3_mgmt'])

        if not niaInnerEncapValidation['result']:
            log.info(niaInnerEncapValidation['log'])
            self.failed(reason="NIA VxLAN Inner ENCAP CLI Failed")
        else:
            log.info(niaInnerEncapValidation['log'])
            self.passed(reason="NIA VxLAN Inner ENCAP CLI Passed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_DECAP_v6(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Fetching the neighbor device's ID (Serial number)
        nbr_device_data = json.loads(testscript.parameters['LEAF-3'].execute(
            "show cdp neigh interf " + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + " det | json"))
        nbr_device_data_parsing = re.search('\((\\w+)\)', nbr_device_data['TABLE_cdp_neighbor_detail_info']['ROW_cdp_neighbor_detail_info']['device_id'], re.I)
        nbr_device_id = nbr_device_data_parsing.group(1)

        LEAF_1_mac_data = json.loads(testscript.parameters['LEAF-1'].execute("show vdc | json"))
        LEAF_1_mac = LEAF_1_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        LEAF_3_mac_data = json.loads(testscript.parameters['LEAF-3'].execute("show vdc | json"))
        LEAF_3_mac = LEAF_3_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        # Declare the parameters required for the NIA CLI
        niaCLIDecapInner_v6 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_12_TGEN_dict']['v6_addr']),
                'dest'          : str(testscript.parameters['LEAF_3_TGEN_dict']['v6_addr']),
                'smac'          : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'iif'           : 'nve1',
                'vlan'          : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'iif'           : "nve1",
                'in_lif'        : "nve1",
                'in_po_mbrs'    : [],
                'in_vlan'       : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                                    str(testscript.parameters['LEAF_12_TGEN_dict']['mac'])],
                'module'        : ['1'],
                'port'          : [testscript.parameters['intf_LEAF_3_to_FAN_2'], 'nve1'],
                'vlan'          : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [{
                                    "log_oif": str(testscript.parameters['intf_LEAF_3_to_FAN_2']),
                                    "nbr": str(testscript.parameters['FAN-2'].alias),
                                    "nbr_phy_iif": str(testscript.parameters['intf_FAN_2_to_LEAF_3']),
                                    "nbr_sr_num": str(nbr_device_id),
                                    "nbr_vlan": str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                                    "phy_oif": str(testscript.parameters['intf_LEAF_3_to_FAN_2'])
                }],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIDecapInner_v6['cli_params']['traffic'] = '2'
            niaCLIDecapInner_v6['cli_params']['upper_iif'] = str(testscript.parameters['intf_LEAF_3_to_SPINE'])
            niaCLIDecapInner_v6['element_params']['iif'] = testscript.parameters['intf_LEAF_3_to_SPINE']
            niaCLIDecapInner_v6['elam_params'] = {
                    'Packet Type'               : 'IPv6',
                    'Source IP'                 : str(testscript.parameters['LEAF_12_TGEN_dict']['v6_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_3_TGEN_dict']['v6_addr']),
                    'Source MAC'                : str(LEAF_1_mac),
                    'Destination MAC'           : str(LEAF_3_mac),
                    'src_vlan'                  : "",
                    'Source Bridge Domain'      : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']),
                    'Destination Bridge Domain' : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_3_to_FAN_2']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_3_to_SPINE'])]
            }

        niaInnerDecapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-3'], niaCLIDecapInner_v6,testscript.parameters['LEAF-3_mgmt'])

        if not niaInnerDecapValidation['result']:
            log.info(niaInnerDecapValidation['log'])
            self.failed(reason="NIA VxLAN Inner DECAP CLI Failed")
        else:
            log.info(niaInnerDecapValidation['log'])
            self.passed(reason="NIA VxLAN Inner DECAP CLI Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for device in device_list:
            device.execute("show ver in bu")

        for device in device_mgmt_list:
            device.execute("show ver in bu")

# *****************************************************************************************************************************#
class VERIFY_NIA_FSV_OUTER_VxLAN_STD_VTEP_IIF_OIF_INT(aetest.Testcase):
    """VERIFY_NIA_FSV_OUTER_VxLAN_IPv4_STD_VTEP_IIF_OIF_INT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_OUTER_ENCAP_v4(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        # Fetching the neighbor device's ID (Serial number)
        nbr_device_data = json.loads(testscript.parameters['LEAF-3'].execute("show cdp neigh interf " + str(testscript.parameters['intf_LEAF_3_to_SPINE'])+ " det | json"))
        nbr_device_data_parsing = re.search('\((\\w+)\)', nbr_device_data['TABLE_cdp_neighbor_detail_info']['ROW_cdp_neighbor_detail_info']['device_id'], re.I)
        nbr_device_id = nbr_device_data_parsing.group(1)

        niaCLIEncapOuter_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                'dest'          : VPC_VTEP_IP,
                'iif'           : str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']),
                'vlan'          : 0,
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']),
                'in_lif'        : str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']),
                'in_po_mbrs'    : [],
                'in_vlan'       : '0',
                'in_vrf'        : 'default',
                'macAddr'       : [],
                'module'        : ['1'],
                'port'          : [str(testscript.parameters['intf_LEAF_3_to_SPINE'])],
                'vlan'          : [],
                'vni'           : [],
                'vpc'           : [],
                'iif_vrf'       : 'default',
                'route'         : [
                                {
                                    "ip": VPC_VTEP_IP + "/32",
                                    "type": "ipv4",
                                    "vrf": "default"
                                },
                                {
                                    "ip": str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']),
                                    "type": "ipv4",
                                    "vrf": "default"
                                }
                ],
                'last_path'     : [],
                'paths'         : [{
                                    "log_oif"       : str(testscript.parameters['intf_LEAF_3_to_SPINE']),
                                    "nbr"           : str(testscript.parameters['SPINE'].alias),
                                    "nbr_phy_iif"   : str(testscript.parameters['intf_SPINE_to_LEAF_3']),
                                    "nbr_sr_num"    : str(nbr_device_id),
                                    "nbr_vlan"      : "0",
                                    "phy_oif"       : str(testscript.parameters['intf_LEAF_3_to_SPINE'])
                                }],
            }
        }

        niaOuterEncapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-3'],niaCLIEncapOuter_v4,testscript.parameters['LEAF-3_mgmt'])

        if not niaOuterEncapValidation['result']:
            log.info(niaOuterEncapValidation['log'])
            self.failed(reason="NIA VxLAN Outer ENCAP CLI Failed")
        else:
            log.info(niaOuterEncapValidation['log'])
            self.passed(reason="NIA VxLAN Outer ENCAP CLI Passed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_OUTER_DECAP_v4(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        # Declare the parameters required for the NIA CLI
        niaCLIDecapOuter_v4 = {
            'cli_params': {
                'src'           : VPC_VTEP_IP,
                'dest'          : str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                'iif'           : str(testscript.parameters['intf_LEAF_3_to_SPINE']),
                'vlan'          : 0,
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : str(testscript.parameters['intf_LEAF_3_to_SPINE']),
                'in_lif'        : str(testscript.parameters['intf_LEAF_3_to_SPINE']),
                'in_po_mbrs'    : [],
                'in_vlan'       : '0',
                'in_vrf'        : 'default',
                'macAddr'       : [],
                'module'        : ['1'],
                'port'          : [str(testscript.parameters['intf_LEAF_3_to_SPINE'])],
                'vlan'          : [],
                'vni'           : [],
                'vpc'           : [],
                'iif_vrf'       : 'default',
                'route'         : [
                                {
                                    "ip": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']) + "/32",
                                    "type": "ipv4",
                                    "vrf": "default"
                                },
                ],
                'last_path'     : [],
                'paths'         : [],
            }
        }

        niaOuterDecapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-3'],niaCLIDecapOuter_v4,testscript.parameters['LEAF-3_mgmt'])

        if not niaOuterDecapValidation['result']:
            log.info(niaOuterDecapValidation['log'])
            self.failed(reason="NIA VxLAN Outer DECAP CLI Failed")
        else:
            log.info(niaOuterDecapValidation['log'])
            self.passed(reason="NIA VxLAN Outer DECAP CLI Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for device in device_list:
            device.execute("show ver in bu")

        for device in device_mgmt_list:
            device.execute("show ver in bu")

# *****************************************************************************************************************************#
class VERIFY_NIA_FSV_OUTER_VxLAN_SPINE_IIF_PO_OIF_INT(aetest.Testcase):
    """VERIFY_NIA_FSV_OUTER_VxLAN_SPINE_IIF_PO_OIF_INT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VPC_VTEP_TO_STD_VTEP(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        # Fetching the neighbor device's ID (Serial number)
        nbr_device_data = json.loads(testscript.parameters['SPINE'].execute(
            "show cdp neigh interf " + str(testscript.parameters['intf_SPINE_to_LEAF_3']) + " det | json"))
        nbr_device_data_parsing = re.search('\((\\w+)\)', nbr_device_data['TABLE_cdp_neighbor_detail_info'][
            'ROW_cdp_neighbor_detail_info']['device_id'], re.I)
        nbr_device_id = nbr_device_data_parsing.group(1)

        # Declare the parameters required for the NIA CLI
        niaCLIDecapOuter_v4 = {
            'cli_params': {
                'src'           : VPC_VTEP_IP,
                'dest'          : str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                'iif'           : "port-channel"+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']),
                'vlan'          : 0,
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : "port-channel"+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']),
                'in_lif'        : "port-channel"+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']),
                'in_po_mbrs'    : [str(testscript.parameters['intf_SPINE_to_LEAF_1'])],
                'in_vlan'       : '0',
                'in_vrf'        : 'default',
                'macAddr'       : [],
                'module'        : ['1'],
                'port'          : ["port-channel"+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']),
                                   testscript.parameters['intf_SPINE_to_LEAF_1'],
                                   testscript.parameters['intf_SPINE_to_LEAF_3']],
                'vlan'          : [],
                'vni'           : [],
                'vpc'           : [],
                'iif_vrf'       : 'default',
                'route'         : [
                                {
                                    "ip": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']) + "/32",
                                    "type": "ipv4",
                                    "vrf": "default"
                                },
                                {
                                    "ip": str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['leaf_spine_po_v4']),
                                    "type": "ipv4",
                                    "vrf": "default"
                                },
                ],
                'last_path'     : [],
                'paths'         : [{
                                    "log_oif"       : str(testscript.parameters['intf_SPINE_to_LEAF_3']),
                                    "nbr"           : str(testscript.parameters['LEAF-3'].alias),
                                    "nbr_phy_iif"   : str(testscript.parameters['intf_LEAF_3_to_SPINE']),
                                    "nbr_sr_num"    : str(nbr_device_id),
                                    "nbr_vlan"      : '0',
                                    "phy_oif"       : str(testscript.parameters['intf_SPINE_to_LEAF_3'])
                                }],
            }
        }

        niaOuterDecapValidation = niaLib.verifyNIACLI(testscript.parameters['SPINE'],niaCLIDecapOuter_v4,testscript.parameters['SPINE_mgmt'])

        if not niaOuterDecapValidation['result']:
            log.info(niaOuterDecapValidation['log'])
            self.failed(reason="NIA VxLAN Outer DECAP CLI Failed")
        else:
            log.info(niaOuterDecapValidation['log'])
            self.passed(reason="NIA VxLAN Outer DECAP CLI Passed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VPC_VTEP_TO_STD_VTEP_TRAFFIC_3(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        LEAF_1_mac_data = json.loads(testscript.parameters['LEAF-1'].execute("show vdc | json"))
        LEAF_1_mac = LEAF_1_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        SPINE_mac_data = json.loads(testscript.parameters['SPINE'].execute("show vdc | json"))
        SPINE_mac = SPINE_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        # Declare the parameters required for the NIA CLI
        niaCLIDecapOuter_v4 = {
            'cli_params': {
                'src'           : VPC_VTEP_IP,
                'dest'          : str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                'iif'           : "port-channel"+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']),
                'vlan'          : 0,
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : "port-channel"+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']),
                'in_lif'        : "port-channel"+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']),
                'in_po_mbrs'    : [str(testscript.parameters['intf_SPINE_to_LEAF_1'])],
                'in_vlan'       : '0',
                'in_vrf'        : 'default',
                'macAddr'       : [],
                'module'        : ['1'],
                'port'          : ["port-channel"+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']),
                                   testscript.parameters['intf_SPINE_to_LEAF_1']],
                'vlan'          : [],
                'vni'           : [],
                'vpc'           : [],
                'iif_vrf'       : 'default',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIDecapOuter_v4['cli_params']['traffic'] = '3'
            niaCLIDecapOuter_v4['element_params']['iif'] = str(testscript.parameters['intf_SPINE_to_LEAF_1'])
            niaCLIDecapOuter_v4['elam_params'] = {
                    'Packet Type'               : 'IPv4',
                    'Source IP'                 : VPC_VTEP_IP,
                    'Destination IP'            : str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                    'Source MAC'                : str(LEAF_1_mac),
                    'Destination MAC'           : str(SPINE_mac),
                    'src_vlan'                  : "",
                    'Egress Interface'          : str(testscript.parameters['intf_SPINE_to_LEAF_3']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_SPINE_to_LEAF_1'])]
            }

            niaOuterDecapValidation = niaLib.verifyNIACLI(testscript.parameters['SPINE'],niaCLIDecapOuter_v4,testscript.parameters['SPINE_mgmt'])

            if not niaOuterDecapValidation['result']:
                log.info(niaOuterDecapValidation['log'])
                self.failed(reason="NIA VxLAN Outer DECAP CLI Failed")
            else:
                log.info(niaOuterDecapValidation['log'])
                self.passed(reason="NIA VxLAN Outer DECAP CLI Passed")
        else:
            self.skipped(reason="BRCM Platform, hence skipping the TC")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for device in device_list:
            device.execute("show ver in bu")

        for device in device_mgmt_list:
            device.execute("show ver in bu")

# *****************************************************************************************************************************#
class VERIFY_NIA_FSV_OUTER_VxLAN_SPINE_IIF_INT_OIF_PO(aetest.Testcase):
    """VERIFY_NIA_FSV_OUTER_VxLAN_SPINE_IIF_PO_OIF_INT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_STD_VTEP_TO_VPC_VTEP(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        testscript.parameters["LEAF-2"].configure('''
                interface port-channel''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                    no shut
        ''')

        time.sleep(60)

        # Fetching the VPC-1 neighbor device's ID (Serial number)
        nbr_device_data_1 = json.loads(testscript.parameters['SPINE'].execute("show cdp neigh interf " + str(testscript.parameters['intf_SPINE_to_LEAF_1']) + " det | json"))
        nbr_device_data_parsing_1 = re.search('\((\\w+)\)', nbr_device_data_1['TABLE_cdp_neighbor_detail_info']['ROW_cdp_neighbor_detail_info']['device_id'], re.I)
        nbr_device_id_1 = nbr_device_data_parsing_1.group(1)

        # Fetching the VPC-1 neighbor device's ID (Serial number)
        nbr_device_data_2 = json.loads(testscript.parameters['SPINE'].execute("show cdp neigh interf " + str(testscript.parameters['intf_SPINE_to_LEAF_2']) + " det | json"))
        nbr_device_data_parsing_2 = re.search('\((\\w+)\)', nbr_device_data_2['TABLE_cdp_neighbor_detail_info']['ROW_cdp_neighbor_detail_info']['device_id'], re.I)
        nbr_device_id_2 = nbr_device_data_parsing_2.group(1)

        testscript.parameters["LEAF-2"].configure('''
                interface port-channel''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                    shut
        ''')

        time.sleep(60)

        # Declare the parameters required for the NIA CLI
        niaCLIDecapOuter_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                'dest'          : VPC_VTEP_IP,
                'iif'           : str(testscript.parameters['intf_SPINE_to_LEAF_3']),
                'vlan'          : 0,
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : str(testscript.parameters['intf_SPINE_to_LEAF_3']),
                'in_lif'        : str(testscript.parameters['intf_SPINE_to_LEAF_3']),
                'in_po_mbrs'    : [],
                'in_vlan'       : '0',
                'in_vrf'        : 'default',
                'macAddr'       : [],
                'module'        : ['1'],
                'port'          : ["port-channel"+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']),
                                   testscript.parameters['intf_SPINE_to_LEAF_1'],
                                   testscript.parameters['intf_SPINE_to_LEAF_3']],
                'vlan'          : [],
                'vni'           : [],
                'vpc'           : [],
                'iif_vrf'       : 'default',
                'route'         : [
                                {
                                    "ip": VPC_VTEP_IP + "/32",
                                    "type": "ipv4",
                                    "vrf": "default"
                                },
                                {
                                    "ip": str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['leaf_spine_po_v4']),
                                    "type": "ipv4",
                                    "vrf": "default"
                                }
                ],
                'last_path'     : [],
                'paths'         : [{
                                    "log_oif"       : "port-channel"+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']),
                                    "nbr"           : str(testscript.parameters['LEAF-1'].alias),
                                    "nbr_phy_iif"   : str(testscript.parameters['intf_LEAF_1_to_SPINE']),
                                    "nbr_sr_num"    : str(nbr_device_id_1),
                                    "nbr_vlan"      : '0',
                                    "phy_oif"       : str(testscript.parameters['intf_SPINE_to_LEAF_1'])
                                }],
            }
        }

        niaOuterDecapValidation = niaLib.verifyNIACLI(testscript.parameters['SPINE'],niaCLIDecapOuter_v4,testscript.parameters['SPINE_mgmt'])

        if not niaOuterDecapValidation['result']:
            log.info(niaOuterDecapValidation['log'])
            self.failed(reason="NIA VxLAN Outer DECAP CLI Failed")
        else:
            log.info(niaOuterDecapValidation['log'])
            self.passed(reason="NIA VxLAN Outer DECAP CLI Passed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_STD_VTEP_TO_VPC_VTEP_TRAFFIC_3(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        LEAF_3_mac_data = json.loads(testscript.parameters['LEAF-3'].execute("show vdc | json"))
        LEAF_3_mac = LEAF_3_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        SPINE_mac_data = json.loads(testscript.parameters['SPINE'].execute("show vdc | json"))
        SPINE_mac = SPINE_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        # Declare the parameters required for the NIA CLI
        niaCLIDecapOuter_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                'dest'          : VPC_VTEP_IP,
                'iif'           : str(testscript.parameters['intf_SPINE_to_LEAF_3']),
                'vlan'          : 0,
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : str(testscript.parameters['intf_SPINE_to_LEAF_3']),
                'in_lif'        : str(testscript.parameters['intf_SPINE_to_LEAF_3']),
                'in_po_mbrs'    : [],
                'in_vlan'       : '0',
                'in_vrf'        : 'default',
                'macAddr'       : [],
                'module'        : ['1'],
                'port'          : [testscript.parameters['intf_SPINE_to_LEAF_3']],
                'vlan'          : [],
                'vni'           : [],
                'vpc'           : [],
                'iif_vrf'       : 'default',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIDecapOuter_v4['cli_params']['traffic'] = '3'
            niaCLIDecapOuter_v4['elam_params'] = {
                    'Packet Type'               : 'IPv4',
                    'Source IP'                 : str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                    'Destination IP'            : VPC_VTEP_IP,
                    'Source MAC'                : str(LEAF_3_mac),
                    'Destination MAC'           : str(SPINE_mac),
                    'src_vlan'                  : "",
                    'Egress Interface'          : str(testscript.parameters['intf_SPINE_to_LEAF_1']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_SPINE_to_LEAF_3'])]
            }

            niaOuterDecapValidation = niaLib.verifyNIACLI(testscript.parameters['SPINE'],niaCLIDecapOuter_v4,testscript.parameters['SPINE_mgmt'])

            if not niaOuterDecapValidation['result']:
                log.info(niaOuterDecapValidation['log'])
                self.failed(reason="NIA VxLAN Outer DECAP CLI Failed")
            else:
                log.info(niaOuterDecapValidation['log'])
                self.passed(reason="NIA VxLAN Outer DECAP CLI Passed")

        else:
            self.skipped(reason="BRCM Platform, hence skipping the TC")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for device in device_list:
            device.execute("show ver in bu")

        for device in device_mgmt_list:
            device.execute("show ver in bu")

# *****************************************************************************************************************************#
class UNSHUT_SECONDARY_VPC_UPLINK_BEFORE_CONFIG_REVERT(aetest.Testcase):
    """START_IXIA_TRAFFIC"""

    # =============================================================================================================================#
    @aetest.test
    def UNSHUT_SECONDARY_VPC_UPLINK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        testscript.parameters["LEAF-2"].configure('''
                interface port-channel''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                    no shut
        ''')

        time.sleep(200)

    # =============================================================================================================================#
    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        testscript.parameters['LEAF-2'].configure('''
              interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                no shutdown
        ''')
        time.sleep(120)

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        testscript.parameters['LEAF-2'].configure('''
              interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                shutdown
        ''')
        time.sleep(120)

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2,3) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class STOP_IXIA_TRAFFIC_FOR_REVERTING_CONFIG_CHANGE(aetest.Testcase):
    """STOP_IXIA_TRAFFIC"""

    # =============================================================================================================================#
    @aetest.test
    def stop_ixia_traffic(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        if ixLib.start_traffic() == 0:
            log.debug("Starting Traffic failed")
            self.failed("Starting Traffic failed", goto=['cleanup'])

# *****************************************************************************************************************************#
class REVERT_CONNECTIONS_FROM_INT_to_PO(aetest.Testcase):
    """CHANGE_CONNECTIONS_FROM_PO_to_INT"""

    # =============================================================================================================================#
    @aetest.test
    def CHANGE_ACCESS_FACING_INT(self, testscript):
        """ CHANGE_ACCESS_FACING_INT """

        fail_flag = []
        fail_logs = ""

        try:
            testscript.parameters['LEAF-3'].configure('''

                no interface port-channel ''' + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) + '''
                default interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                
                interface port-channel ''' + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) + '''
                  switchport
                  switchport mode trunk
                  no shutdown
                
                interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  channel-group ''' + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) + ''' force mode active
                  no shutdown

          ''', timeout=1200)

        except Exception as error:
            fail_logs += "Unable to configure change from PO to INT on LEAF-3 - Encountered Exception \n" + str(error)
            fail_flag.append(0)

        try:
            testscript.parameters['FAN-2'].configure('''

                no interface port-channel ''' + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) + '''
                default interface ''' + str(testscript.parameters['intf_FAN_2_to_LEAF_3']) + '''
                
                interface port-channel ''' + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) + '''
                  switchport
                  switchport mode trunk
                  no shutdown
                
                interface ''' + str(testscript.parameters['intf_FAN_2_to_LEAF_3']) + '''
                  channel-group ''' + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) + ''' force mode active
                  no shutdown

          ''', timeout=1200)

        except Exception as error:
            fail_logs += "Unable to configure change from PO to INT on LEAF-3 - Encountered Exception \n" + str(error)
            fail_flag.append(0)

        if 0 in fail_flag:
            log.debug(fail_logs)
            self.failed(reason=fail_logs)
        else:
            self.passed()

    # =============================================================================================================================#
    @aetest.test
    def CHANGE_SPINE_FACING_INT(self, testscript):
        """ CHANGE_SPINE_FACING_INT """

        fail_flag = []
        fail_logs = ""
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        leaf_dict = testscript.parameters['LEAF_3_dict']

        # --------------------------------
        # Configuring LEAF to SPINE Uplink
        leaf_uplink_configs = '''

            no interface port-channel ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
            default interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''

            interface port-channel ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''                
              ip address ''' + str(leaf_dict['SPINE_1_UPLINK_PO']['leaf_spine_po_v4']) + str(leaf_dict['SPINE_1_UPLINK_PO']['leaf_spine_mask_v4']) + '''
              ip ospf network point-to-point
              ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
              ip pim sparse-mode
              no shutdown
        '''
        if 'leaf_spine_po_v6' in leaf_dict['SPINE_1_UPLINK_PO'].keys():
            leaf_uplink_configs += '''          ipv6 address ''' + \
                                   str(leaf_dict['SPINE_1_UPLINK_PO']['leaf_spine_po_v6']) + \
                                   str(leaf_dict['SPINE_1_UPLINK_PO']['leaf_spine_mask_v6']) + '''\n'''

        leaf_uplink_configs += '''
            interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''
              channel-group ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
              no shutdown
        '''

        try:
            testscript.parameters['LEAF-3'].configure(leaf_uplink_configs, timeout=1200)
        except Exception as error:
            fail_logs += "Unable to configure change from PO to INT on LEAF-3 - Encountered Exception \n" + str(error)
            fail_flag.append(0)

        # --------------------------------
        # Configuring SPINE to LEAF Uplink FAN-1
        spine_downlink_configs = '''
            no interface port-channel''' + str(leaf_dict['SPINE_1_UPLINK_PO']['po_id']) + '''
            default interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_3']) + '''

            interface port-channel''' + str(leaf_dict['SPINE_1_UPLINK_PO']['po_id']) + '''
                no switchport
                ip address ''' + str(leaf_dict['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + str(leaf_dict['SPINE_1_UPLINK_PO']['spine_leaf_mask_v4']) + '''
                ip ospf network point-to-point
                ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                ip pim sparse-mode
                no shutdown
        '''

        if 'spine_leaf_po_v6' in leaf_dict['SPINE_1_UPLINK_PO'].keys():
            spine_downlink_configs += '''          ipv6 address ''' + \
                                      str(leaf_dict['SPINE_1_UPLINK_PO']['spine_leaf_po_v6']) + \
                                      str(leaf_dict['SPINE_1_UPLINK_PO']['spine_leaf_mask_v6']) + '''\n'''

        spine_downlink_configs += '''
            interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_3']) + '''
              channel-group ''' + str(leaf_dict['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
              no shutdown
        '''

        try:
            testscript.parameters['SPINE'].configure(spine_downlink_configs, timeout=1200)
        except Exception as error:
            fail_logs += "Unable to configure change from PO to INT on SPINE - Encountered Exception \n" + str(error)
            fail_flag.append(0)

        if 0 in fail_flag:
            log.debug(fail_logs)
            self.failed(reason=fail_logs)
        else:
            self.passed()

    # =============================================================================================================================#
    @aetest.test
    def perform_copy_r_s(self, testscript):
        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Save all configurations (copy r s) """

        testscript.parameters['LEAF-1'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-3'].configure("copy r s", timeout=300)

        time.sleep(300)

    # =============================================================================================================================#
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        testscript.parameters['LEAF-2'].configure('''
              interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                no shutdown
        ''')
        time.sleep(120)

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        testscript.parameters['LEAF-2'].configure('''
              interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                shutdown
        ''')
        time.sleep(120)

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
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

    # =============================================================================================================================#
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

        time.sleep(120)

    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['next_tc'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2, 3) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class SHUT_SECONDARY_VPC_UPLINK_AFTER_CONFIG_REVERT(aetest.Testcase):
    """START_IXIA_TRAFFIC"""

    # =============================================================================================================================#
    @aetest.test
    def SHUT_SECONDARY_VPC_UPLINK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        testscript.parameters["LEAF-2"].configure('''
                interface port-channel''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                    shut
        ''')

        time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2,3) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class START_IXIA_TRAFFIC_POST_CONVERTING_FROM_INT_PO(aetest.Testcase):
    """START_IXIA_TRAFFIC"""

    # =============================================================================================================================#
    @aetest.test
    def start_ixia_traffic(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        if ixLib.start_traffic() == 0:
            log.debug("Starting Traffic failed")
            self.failed("Starting Traffic failed", goto=['cleanup'])

# *****************************************************************************************************************************#
class VERIFY_NIA_FSV_INNER_VxLAN_IPv4_VPC_VTEP_IIF_OIF_PO(aetest.Testcase):
    """VERIFY_NIA_FSV_INNER_VxLAN_IPv4_VPC_VTEP_IIF_OIF_PO"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_CC_COUNT(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # NIA CLI CC flags
        niaCCStatus = []

        # Declare the parameters required for the NIA CLI
        niaCLIEncapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_12_TGEN_dict']['v4_addr']),
                'dest'          : str(testscript.parameters['LEAF_3_TGEN_dict']['v4_addr']),
                'smac'          : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'iif'           : "port-channel"+str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']),
                'vlan'          : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'macAddr'       : [str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),str(testscript.parameters['LEAF_3_TGEN_dict']['mac'])],
                'module'        : ['1'],
                'port'          : ['Vlan' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']), testscript.parameters['intf_LEAF_3_to_FAN_2'], 'nve1'],
                'vlan'          : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [{
                                "encap": {
                                    "dst": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                                    "iif": str(testscript.parameters['LEAF_1_dict']['NVE_data']['src_loop']),
                                    "l2vni": int(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),
                                    "l3vni": 0,
                                    "src": str(testscript.parameters['LEAF_1_dict']['NVE_data']['VPC_VTEP_IP']),
                                    "type": "VxLAN"
                                },
                                "log_oif": "nve1",
                                "oif": "nve1",
                                "phy_oif": "nve1"
                }],
            }
        }

        # Build NIA CLI
        niaCLI = "show nia validate flow"
        niaCLI += " src " + str(niaCLIEncapInner_v4['cli_params']['src'])
        niaCLI += " smac " + str(niaCLIEncapInner_v4['cli_params']['smac'])
        niaCLI += " dest " + str(niaCLIEncapInner_v4['cli_params']['dest'])
        niaCLI += " dmac " + str(niaCLIEncapInner_v4['cli_params']['dmac'])
        niaCLI += " iif " + str(niaCLIEncapInner_v4['cli_params']['iif'])
        niaCLI += " vlan " + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])
        niaCLI += " cc 1 "

        niaCLIOutput = testscript.parameters['LEAF-1'].execute(str(niaCLI) + '| grep \'"cmd":\' | i i "vxlan"', timeout=1200)

        if not 'show consistency-checker vxlan l2 mac-address' in niaCLIOutput:
            log.info("NIA : VxLAN L2 MAC-ADDRESS CC is not being executed")
            niaCCStatus.append(0)
        if not 'show consistency-checker vxlan l3 single-route' in niaCLIOutput:
            log.info("NIA : VxLAN L3 SINGLE-ROUTE CC is not being executed")
            niaCCStatus.append(0)
        if not 'show consistency-checker vxlan vlan' in niaCLIOutput:
            log.info("NIA : VxLAN VLAN CC is not being executed")
            niaCCStatus.append(0)

        if 0 in niaCCStatus:
            self.failed(reason="FAIL : Few of the VxLAN CC are not being run as part of NIA CLI CC invocation")
        else:
            self.passed(reason="PASS : All 3 VxLAN CC are being run as part of NIA CLI CC invocation")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_ENCAP_v4(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        # Declare the parameters required for the NIA CLI
        niaCLIEncapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_12_TGEN_dict']['v4_addr']),
                'dest'          : str(testscript.parameters['LEAF_3_TGEN_dict']['v4_addr']),
                'smac'          : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'iif'           : "port-channel"+str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']),
                'vlan'          : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : "port-channel"+str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']),
                'in_lif'        : 'vlan' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                'in_po_mbrs'    : [str(testscript.parameters['intf_LEAF_1_to_FAN_1'])],
                'in_vlan'       : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),str(testscript.parameters['LEAF_3_TGEN_dict']['mac'])],
                'module'        : ['1'],
                'port'          : ['Vlan' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                                   testscript.parameters['intf_LEAF_1_to_FAN_1'],
                                   'nve1',
                                   "port-channel"+str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po'])
                                  ],
                'vlan'          : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start'])],
                'vpc'           : ['port-channel'+str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']), 'port-channel'+str(testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po'])],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [{
                                "encap": {
                                    "dst": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                                    "iif": str(testscript.parameters['LEAF_1_dict']['NVE_data']['src_loop']),
                                    "l2vni": int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']),
                                    "l3vni": 0,
                                    "src": VPC_VTEP_IP,
                                    "type": "VxLAN"
                                },
                                "log_oif": "nve1",
                                "oif": "nve1",
                                "phy_oif": "nve1"
                }],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIEncapInner_v4['cli_params']['traffic'] = '1'
            niaCLIEncapInner_v4['element_params']['iif'] = testscript.parameters['intf_LEAF_1_to_FAN_1']
            niaCLIEncapInner_v4['elam_params'] = {
                    'Packet Type'               : 'IPv4',
                    'Source IP'                 : str(testscript.parameters['LEAF_12_TGEN_dict']['v4_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_3_TGEN_dict']['v4_addr']),
                    'Source MAC'                : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                    'Destination MAC'           : "00:00:00:0A:AA:AA",
                    'src_vlan'                  : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                    'Source Bridge Domain'      : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                    'Destination Bridge Domain' : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_1_to_SPINE']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_1_to_FAN_1'])]
            }

        niaInnerEncapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-1'],niaCLIEncapInner_v4,testscript.parameters['LEAF-1_mgmt'])

        if not niaInnerEncapValidation['result']:
            log.info(niaInnerEncapValidation['log'])
            self.failed(reason="NIA VxLAN Inner ENCAP CLI Failed")
        else:
            log.info(niaInnerEncapValidation['log'])
            self.passed(reason="NIA VxLAN Inner ENCAP CLI Passed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_DECAP_v4(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Fetching the neighbor device's ID (Serial number)
        nbr_device_data = json.loads(testscript.parameters['LEAF-1'].execute("show cdp neigh interf " + str(testscript.parameters['intf_LEAF_1_to_FAN_1'])+ " det | json"))
        nbr_device_data_parsing = re.search('\((\\w+)\)', nbr_device_data['TABLE_cdp_neighbor_detail_info']['ROW_cdp_neighbor_detail_info']['device_id'], re.I)
        nbr_device_id = nbr_device_data_parsing.group(1)

        LEAF_1_mac_data = json.loads(testscript.parameters['LEAF-1'].execute("show vdc | json"))
        LEAF_1_mac = LEAF_1_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        LEAF_3_mac_data = json.loads(testscript.parameters['LEAF-3'].execute("show vdc | json"))
        LEAF_3_mac = LEAF_3_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        # Declare the parameters required for the NIA CLI
        niaCLIDecapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_TGEN_dict']['v4_addr']),
                'dest'          : str(testscript.parameters['LEAF_12_TGEN_dict']['v4_addr']),
                'smac'          : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'iif'           : 'nve1',
                'vlan'          : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start'])],
                'iif'           : "nve1",
                'in_lif'        : "nve1",
                'in_po_mbrs'    : [],
                'in_vlan'       : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),str(testscript.parameters['LEAF_3_TGEN_dict']['mac'])],
                'module'        : ['1'],
                'port'          : [testscript.parameters['intf_LEAF_1_to_FAN_1'],
                                   "port-channel"+str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']),
                                   "nve1"
                                  ],
                'vlan'          : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start'])],
                'vpc'           : ['port-channel'+str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']), 'port-channel'+str(testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po'])],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [{
                                    "log_oif"       : "Po"+str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']),
                                    "nbr"           : str(testscript.parameters['FAN-1'].alias),
                                    "nbr_phy_iif"   : str(testscript.parameters['intf_FAN_1_to_LEAF_1']),
                                    "nbr_sr_num"    : str(nbr_device_id),
                                    "nbr_vlan"      : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                                    "phy_oif"       : str(testscript.parameters['intf_LEAF_1_to_FAN_1'])
                                }],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIDecapInner_v4['cli_params']['traffic'] = '2'
            niaCLIDecapInner_v4['cli_params']['upper_iif'] = "port-channel" + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])
            niaCLIDecapInner_v4['element_params']['iif'] = testscript.parameters['intf_LEAF_1_to_SPINE']
            niaCLIDecapInner_v4['elam_params'] = {
                    'Packet Type'               : 'IPv4',
                    'Source IP'                 : str(testscript.parameters['LEAF_3_TGEN_dict']['v4_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_12_TGEN_dict']['v4_addr']),
                    'Source MAC'                : str(LEAF_3_mac),
                    'Destination MAC'           : str(LEAF_1_mac),
                    'src_vlan'                  : "",
                    'Source Bridge Domain'      : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']),
                    'Destination Bridge Domain' : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_1_to_FAN_1']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_1_to_SPINE'])]
            }

        niaInnerDecapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-1'],niaCLIDecapInner_v4,testscript.parameters['LEAF-1_mgmt'])

        if not niaInnerDecapValidation['result']:
            log.info(niaInnerDecapValidation['log'])
            self.failed(reason="NIA VxLAN Inner DECAP CLI Failed")
        else:
            log.info(niaInnerDecapValidation['log'])
            self.passed(reason="NIA VxLAN Inner DECAP CLI Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for device in device_list:
            device.execute("show ver in bu")

        for device in device_mgmt_list:
            device.execute("show ver in bu")

# *****************************************************************************************************************************#
class VERIFY_NIA_FSV_INNER_VxLAN_IPv6_VPC_VTEP_IIF_OIF_PO(aetest.Testcase):
    """VERIFY_NIA_FSV_INNER_VxLAN_IPv6_STD_VTEP_IIF_OIF_PO"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_CC_COUNT(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # NIA CLI CC flags
        niaCCStatus = []

        # Declare the parameters required for the NIA CLI
        niaCLIEncapInner_v6 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_TGEN_dict']['v6_addr']),
                'dest'          : str(testscript.parameters['LEAF_12_TGEN_dict']['v6_addr']),
                'smac'          : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'iif'           : "port-channel"+str(testscript.parameters['STD_VTEP_ACCESS_PO_id']),
                'vlan'          : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'cc_flag'       : '1',
            },
        }

        # Build NIA CLI
        niaCLI = "show nia validate flow"
        niaCLI += " src " + str(niaCLIEncapInner_v6['cli_params']['src'])
        niaCLI += " smac " + str(niaCLIEncapInner_v6['cli_params']['smac'])
        niaCLI += " dest " + str(niaCLIEncapInner_v6['cli_params']['dest'])
        niaCLI += " dmac " + str(niaCLIEncapInner_v6['cli_params']['dmac'])
        niaCLI += " iif " + str(niaCLIEncapInner_v6['cli_params']['iif'])
        niaCLI += " vlan " + str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])
        niaCLI += " cc 1 "

        niaCLIOutput = testscript.parameters['LEAF-3'].execute(str(niaCLI) + '| grep \'"cmd":\' | i i "vxlan"', timeout=1200)

        if not 'show consistency-checker vxlan l2 mac-address' in niaCLIOutput:
            log.info("NIA : VxLAN L2 MAC-ADDRESS CC is not being executed")
            niaCCStatus.append(0)
        if not 'show consistency-checker vxlan l3 single-route' in niaCLIOutput:
            log.info("NIA : VxLAN L3 SINGLE-ROUTE CC is not being executed")
            niaCCStatus.append(0)
        if not 'show consistency-checker vxlan vlan' in niaCLIOutput:
            log.info("NIA : VxLAN VLAN CC is not being executed")
            niaCCStatus.append(0)

        if 0 in niaCCStatus:
            self.failed(reason="FAIL : Few of the VxLAN CC are not being run as part of NIA CLI CC invocation")
        else:
            self.passed(reason="PASS : All 3 VxLAN CC are being run as part of NIA CLI CC invocation")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_ENCAP_v6(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        # Declare the parameters required for the NIA CLI
        niaCLIEncapInner_v6 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_12_TGEN_dict']['v6_addr']),
                'dest'          : str(testscript.parameters['LEAF_3_TGEN_dict']['v6_addr']),
                'smac'          : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'iif'           : "port-channel"+str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']),
                'vlan'          : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : "port-channel" + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']),
                'in_lif'        : 'vlan' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                'in_po_mbrs'    : [str(testscript.parameters['intf_LEAF_1_to_FAN_1'])],
                'in_vlan'       : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),str(testscript.parameters['LEAF_3_TGEN_dict']['mac'])],
                'module'        : ['1'],
                'port'          : ['Vlan' + str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                                   testscript.parameters['intf_LEAF_1_to_FAN_1'],
                                   'nve1',
                                   "port-channel"+str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po'])
                                  ],
                'vlan'          : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start'])],
                'vpc'           : ['port-channel'+str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']), 'port-channel'+str(testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po'])],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [{
                                "encap": {
                                    "dst": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                                    "iif": str(testscript.parameters['LEAF_1_dict']['NVE_data']['src_loop']),
                                    "l2vni": int(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']),
                                    "l3vni": 0,
                                    "src": VPC_VTEP_IP,
                                    "type": "VxLAN"
                                },
                                "log_oif": "nve1",
                                "oif": "nve1",
                                "phy_oif": "nve1"
                }],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIEncapInner_v6['cli_params']['traffic'] = '1'
            niaCLIEncapInner_v6['element_params']['iif'] = testscript.parameters['intf_LEAF_1_to_FAN_1']
            niaCLIEncapInner_v6['elam_params'] = {
                    'Packet Type'               : 'IPv6',
                    'Source IP'                 : str(testscript.parameters['LEAF_12_TGEN_dict']['v6_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_3_TGEN_dict']['v6_addr']),
                    'Source MAC'                : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                    'Destination MAC'           : "00:00:00:0A:AA:AA",
                    'src_vlan'                  : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                    'Source Bridge Domain'      : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                    'Destination Bridge Domain' : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_1_to_SPINE']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_1_to_FAN_1'])]
            }

        niaInnerEncapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-1'],niaCLIEncapInner_v6,testscript.parameters['LEAF-1_mgmt'])

        if not niaInnerEncapValidation['result']:
            log.info(niaInnerEncapValidation['log'])
            self.failed(reason="NIA VxLAN Inner ENCAP CLI Failed")
        else:
            log.info(niaInnerEncapValidation['log'])
            self.passed(reason="NIA VxLAN Inner ENCAP CLI Passed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_DECAP_v6(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Fetching the neighbor device's ID (Serial number)
        nbr_device_data = json.loads(testscript.parameters['LEAF-1'].execute("show cdp neigh interf " + str(testscript.parameters['intf_LEAF_1_to_FAN_1'])+ " det | json"))
        nbr_device_data_parsing = re.search('\((\\w+)\)', nbr_device_data['TABLE_cdp_neighbor_detail_info']['ROW_cdp_neighbor_detail_info']['device_id'], re.I)
        nbr_device_id = nbr_device_data_parsing.group(1)

        LEAF_1_mac_data = json.loads(testscript.parameters['LEAF-1'].execute("show vdc | json"))
        LEAF_1_mac = LEAF_1_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        LEAF_3_mac_data = json.loads(testscript.parameters['LEAF-3'].execute("show vdc | json"))
        LEAF_3_mac = LEAF_3_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        # Declare the parameters required for the NIA CLI
        niaCLIDecapInner_v6 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_TGEN_dict']['v6_addr']),
                'dest'          : str(testscript.parameters['LEAF_12_TGEN_dict']['v6_addr']),
                'smac'          : str(testscript.parameters['LEAF_3_TGEN_dict']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),
                'iif'           : 'nve1',
                'vlan'          : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [str(testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start'])],
                'iif'           : "nve1",
                'in_lif'        : "nve1",
                'in_po_mbrs'    : [],
                'in_vlan'       : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_12_TGEN_dict']['mac']),str(testscript.parameters['LEAF_3_TGEN_dict']['mac'])],
                'module'        : ['1'],
                'port'          : [testscript.parameters['intf_LEAF_1_to_FAN_1'],
                                   "nve1",
                                   "port-channel" + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po'])
                                  ],
                'vlan'          : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start'])],
                'vpc'           : ['port-channel'+str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']), 'port-channel'+str(testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po'])],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [],
                'last_path'     : [],
                'paths'         : [{
                                    "log_oif"       : "Po"+str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']),
                                    "nbr"           : str(testscript.parameters['FAN-1'].alias),
                                    "nbr_phy_iif"   : str(testscript.parameters['intf_FAN_1_to_LEAF_1']),
                                    "nbr_sr_num"    : str(nbr_device_id),
                                    "nbr_vlan"      : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                                    "phy_oif"       : str(testscript.parameters['intf_LEAF_1_to_FAN_1'])
                                }],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIDecapInner_v6['cli_params']['traffic'] = '2'
            niaCLIDecapInner_v6['cli_params']['upper_iif'] = "port-channel" + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])
            niaCLIDecapInner_v6['element_params']['iif'] = testscript.parameters['intf_LEAF_1_to_SPINE']
            niaCLIDecapInner_v6['elam_params'] = {
                    'Packet Type'               : 'IPv6',
                    'Source IP'                 : str(testscript.parameters['LEAF_3_TGEN_dict']['v6_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_12_TGEN_dict']['v6_addr']),
                    'Source MAC'                : str(LEAF_3_mac),
                    'Destination MAC'           : str(LEAF_1_mac),
                    'src_vlan'                  : "",
                    'Source Bridge Domain'      : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']),
                    'Destination Bridge Domain' : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_1_to_FAN_1']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_1_to_SPINE'])]
            }

        niaInnerDecapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-1'],niaCLIDecapInner_v6,testscript.parameters['LEAF-1_mgmt'])

        if not niaInnerDecapValidation['result']:
            log.info(niaInnerDecapValidation['log'])
            self.failed(reason="NIA VxLAN Inner DECAP CLI Failed")
        else:
            log.info(niaInnerDecapValidation['log'])
            self.passed(reason="NIA VxLAN Inner DECAP CLI Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for device in device_list:
            device.execute("show ver in bu")

        for device in device_mgmt_list:
            device.execute("show ver in bu")

# *****************************************************************************************************************************#
class VERIFY_NIA_FSV_OUTER_VxLAN_VPC_VTEP_IIF_OIF_PO(aetest.Testcase):
    """VERIFY_NIA_FSV_OUTER_VxLAN_IPv4_STD_VTEP_IIF_OIF_PO"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_OUTER_ENCAP_v4(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_1_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_1_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_1_dict']['NVE_data']['VTEP_IP'])

        # Fetching the neighbor device's ID (Serial number)
        nbr_device_data = json.loads(testscript.parameters['LEAF-1'].execute("show cdp neigh interf " + str(testscript.parameters['intf_LEAF_1_to_SPINE'])+ " det | json"))
        nbr_device_data_parsing = re.search('\((\\w+)\)', nbr_device_data['TABLE_cdp_neighbor_detail_info']['ROW_cdp_neighbor_detail_info']['device_id'], re.I)
        nbr_device_id = nbr_device_data_parsing.group(1)

        niaCLIEncapOuter_v4 = {
            'cli_params': {
                'src'           : VPC_VTEP_IP,
                'dest'          : str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                'iif'           : str(testscript.parameters['LEAF_1_dict']['NVE_data']['src_loop']),
                'vlan'          : 0,
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : str(testscript.parameters['LEAF_1_dict']['NVE_data']['src_loop']),
                'in_lif'        : str(testscript.parameters['LEAF_1_dict']['NVE_data']['src_loop']),
                'in_po_mbrs'    : [],
                'in_vlan'       : '0',
                'in_vrf'        : 'default',
                'macAddr'       : [],
                'module'        : ['1'],
                'port'          : [str(testscript.parameters['intf_LEAF_1_to_SPINE']), "port-channel" + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])],
                'vlan'          : [],
                'vni'           : [],
                'vpc'           : [],
                'iif_vrf'       : 'default',
                'route'         : [
                                {
                                    "ip": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']) + "/32",
                                    "type": "ipv4",
                                    "vrf": "default"
                                },
                                {
                                    "ip": str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']),
                                    "type": "ipv4",
                                    "vrf": "default"
                                }
                ],
                'last_path'     : [],
                'paths'         : [{
                                    "log_oif"       : "port-channel" + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']),
                                    "nbr"           : str(str(testscript.parameters['SPINE'].alias)),
                                    "nbr_phy_iif"   : str(testscript.parameters['intf_SPINE_to_LEAF_1']),
                                    "nbr_sr_num"    : str(nbr_device_id),
                                    "nbr_vlan"      : "0",
                                    "phy_oif"       : str(testscript.parameters['intf_LEAF_1_to_SPINE'])
                                }],
            }
        }

        niaOuterEncapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-1'],niaCLIEncapOuter_v4,testscript.parameters['LEAF-1_mgmt'])

        if not niaOuterEncapValidation['result']:
            log.info(niaOuterEncapValidation['log'])
            self.failed(reason="NIA VxLAN Outer ENCAP CLI Failed")
        else:
            log.info(niaOuterEncapValidation['log'])
            self.passed(reason="NIA VxLAN Outer ENCAP CLI Passed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_OUTER_DECAP_v4(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_1_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_1_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_1_dict']['NVE_data']['VTEP_IP'])

        # Declare the parameters required for the NIA CLI
        niaCLIDecapOuter_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                'dest'          : VPC_VTEP_IP,
                'iif'           : "port-channel"+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']),
                'vlan'          : 0,
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : "port-channel"+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']),
                'in_lif'        : "port-channel"+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']),
                'in_po_mbrs'    : [str(testscript.parameters['intf_LEAF_1_to_SPINE'])],
                'in_vlan'       : '0',
                'in_vrf'        : 'default',
                'macAddr'       : [],
                'module'        : ['1'],
                'port'          : [str(testscript.parameters['intf_LEAF_1_to_SPINE']), "port-channel"+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']),],
                'vlan'          : [],
                'vni'           : [],
                'vpc'           : [],
                'iif_vrf'       : 'default',
                'route'         : [
                                {
                                    "ip": VPC_VTEP_IP + "/32",
                                    "type": "ipv4",
                                    "vrf": "default"
                                },
                ],
                'last_path'     : [],
                'paths'         : [],
            }
        }

        niaOuterDecapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-1'],niaCLIDecapOuter_v4,testscript.parameters['LEAF-1_mgmt'])

        if not niaOuterDecapValidation['result']:
            log.info(niaOuterDecapValidation['log'])
            self.failed(reason="NIA VxLAN Outer DECAP CLI Failed")
        else:
            log.info(niaOuterDecapValidation['log'])
            self.passed(reason="NIA VxLAN Outer DECAP CLI Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for device in device_list:
            device.execute("show ver in bu")

        for device in device_mgmt_list:
            device.execute("show ver in bu")

# *****************************************************************************************************************************#
class VERIFY_NIA_FSV_INNER_VxLAN_IPv4_STD_VTEP_IIF_SUB_INT(aetest.Testcase):
    """VERIFY_NIA_FSV_INNER_VxLAN_IPv4_STD_VTEP_IIF_SUB_INT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_ENCAP_v4(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        LEAF_3_mac_data = json.loads(testscript.parameters['LEAF-3'].execute("show vdc | json"))
        LEAF_3_mac = LEAF_3_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        # Declare the parameters required for the NIA CLI
        niaCLIEncapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v4_addr']),
                'dest'          : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v4_addr']),
                'smac'          : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac']),
                'iif'           : str(testscript.parameters['intf_LEAF_3_to_IXIA'])+".1",
                'vlan'          : '0',
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : str(testscript.parameters['intf_LEAF_3_to_IXIA'])+".1",
                'in_lif'        : str(testscript.parameters['intf_LEAF_3_to_IXIA'])+".1",
                'in_po_mbrs'    : [],
                'in_vlan'       : '0',
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac'])],
                'module'        : ['1'],
                'port'          : [str(testscript.parameters['intf_LEAF_3_to_IXIA'])+".1", 'nve1'],
                'vlan'          : [],
                'vni'           : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [{
                                    'ip': VPC_VTEP_IP,
                                    'type':'ipv4',
                                    'vrf': str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1'}
                                  ],
                'last_path'     : [],
                'paths'         : [{
                                "encap": {
                                    "dst": VPC_VTEP_IP,
                                    "iif": str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']),
                                    "l2vni": 0,
                                    "l3vni": str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vni_start']),
                                    "src": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                                    "type": "VxLAN"
                                },
                                "log_oif": "nve1",
                                "oif": "nve1",
                                "phy_oif": "nve1"
                }],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIEncapInner_v4['cli_params']['traffic'] = '1'
            niaCLIEncapInner_v4['element_params']['iif'] = testscript.parameters['intf_LEAF_3_to_IXIA']
            niaCLIEncapInner_v4['elam_params'] = {
                    'Packet Type'               : 'IPv4',
                    'Source IP'                 : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v4_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v4_addr']),
                    'Source MAC'                : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),
                    'Destination MAC'           : str(LEAF_3_mac),
                    'src_vlan'                  : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['vlan_id']),
                    'Destination Bridge Domain' : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_1_to_SPINE']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_1_to_IXIA'])]
            }

        niaInnerEncapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-3'],niaCLIEncapInner_v4,testscript.parameters['LEAF-3_mgmt'])

        if not niaInnerEncapValidation['result']:
            log.info(niaInnerEncapValidation['log'])
            self.failed(reason="NIA VxLAN Inner ENCAP CLI Failed")
        else:
            log.info(niaInnerEncapValidation['log'])
            self.passed(reason="NIA VxLAN Inner ENCAP CLI Passed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_DECAP_v4(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        LEAF_1_mac_data = json.loads(testscript.parameters['LEAF-1'].execute("show vdc | json"))
        LEAF_1_mac = LEAF_1_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        LEAF_3_mac_data = json.loads(testscript.parameters['LEAF-3'].execute("show vdc | json"))
        LEAF_3_mac = LEAF_3_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        # Declare the parameters required for the NIA CLI
        niaCLIDecapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v4_addr']),
                'dest'          : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v4_addr']),
                'smac'          : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),
                'iif'           : 'nve1',
                'vlan'          : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'iif'           : "nve1",
                'in_lif'        : "nve1",
                'in_po_mbrs'    : [],
                'in_vlan'       : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac'])],
                'module'        : ['1'],
                'port'          : [str(testscript.parameters['intf_LEAF_3_to_IXIA'])+".1", 'nve1'],
                'vlan'          : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [{
                                    'ip': str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v4_addr'])+"/32",
                                    'type':'ipv4',
                                    'vrf': str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1'}
                                  ],
                'last_path'     : [{
                                     'log_oif': str(testscript.parameters['intf_LEAF_3_to_IXIA'])+".1",
                                     'phy_oif': str(testscript.parameters['intf_LEAF_3_to_IXIA']),
                                     'vlan': '1301'
                                  }],
                'paths'         : [],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIDecapInner_v4['cli_params']['traffic'] = '2'
            niaCLIDecapInner_v4['cli_params']['upper_iif'] = "port-channel" + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id'])
            niaCLIDecapInner_v4['element_params']['iif'] = testscript.parameters['intf_LEAF_3_to_SPINE']
            niaCLIDecapInner_v4['elam_params'] = {
                    'Packet Type'               : 'IPv4',
                    'Source IP'                 : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v4_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v4_addr']),
                    'Source MAC'                : str(LEAF_1_mac),
                    'Destination MAC'           : str(LEAF_3_mac),
                    'src_vlan'                  : "",
                    'Source Bridge Domain'      : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_1_to_IXIA']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_1_to_SPINE'])]
            }

        niaInnerDecapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-3'],niaCLIDecapInner_v4,testscript.parameters['LEAF-3_mgmt'])

        if not niaInnerDecapValidation['result']:
            log.info(niaInnerDecapValidation['log'])
            self.failed(reason="NIA VxLAN Inner DECAP CLI Failed")
        else:
            log.info(niaInnerDecapValidation['log'])
            self.passed(reason="NIA VxLAN Inner DECAP CLI Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for device in device_list:
            device.execute("show ver in bu")

        for device in device_mgmt_list:
            device.execute("show ver in bu")

# *****************************************************************************************************************************#
class VERIFY_NIA_FSV_INNER_VxLAN_IPv6_STD_VTEP_IIF_SUB_INT(aetest.Testcase):
    """VERIFY_NIA_FSV_INNER_VxLAN_IPv6_STD_VTEP_IIF_SUB_INT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_ENCAP_v6(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        LEAF_3_mac_data = json.loads(testscript.parameters['LEAF-3'].execute("show vdc | json"))
        LEAF_3_mac = LEAF_3_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        # Declare the parameters required for the NIA CLI
        niaCLIEncapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v6_addr']),
                'dest'          : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v6_addr']),
                'smac'          : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac']),
                'iif'           : str(testscript.parameters['intf_LEAF_3_to_IXIA'])+".1",
                'vlan'          : '0',
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : str(testscript.parameters['intf_LEAF_3_to_IXIA'])+".1",
                'in_lif'        : str(testscript.parameters['intf_LEAF_3_to_IXIA'])+".1",
                'in_po_mbrs'    : [],
                'in_vlan'       : '0',
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac'])],
                'module'        : ['1'],
                'port'          : [str(testscript.parameters['intf_LEAF_3_to_IXIA'])+".1", 'nve1'],
                'vlan'          : [],
                'vni'           : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [{
                                    'ip': VPC_VTEP_IP,
                                    'type':'ipv4',
                                    'vrf': str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1'}
                                  ],
                'last_path'     : [],
                'paths'         : [{
                                "encap": {
                                    "dst": VPC_VTEP_IP,
                                    "iif": str(testscript.parameters['LEAF_2_dict']['NVE_data']['src_loop']),
                                    "l2vni": 0,
                                    "l3vni": str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vni_start']),
                                    "src": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                                    "type": "VxLAN"
                                },
                                "log_oif": "nve1",
                                "oif": "nve1",
                                "phy_oif": "nve1"
                }],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIEncapInner_v4['cli_params']['traffic'] = '1'
            niaCLIEncapInner_v4['element_params']['iif'] = testscript.parameters['intf_LEAF_3_to_IXIA']
            niaCLIEncapInner_v4['elam_params'] = {
                    'Packet Type'               : 'IPv6',
                    'Source IP'                 : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v6_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v6_addr']),
                    'Source MAC'                : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),
                    'Destination MAC'           : str(LEAF_3_mac),
                    'src_vlan'                  : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['vlan_id']),
                    'Destination Bridge Domain' : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_1_to_SPINE']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_1_to_IXIA'])]
            }

        niaInnerEncapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-3'],niaCLIEncapInner_v4,testscript.parameters['LEAF-3_mgmt'])

        if not niaInnerEncapValidation['result']:
            log.info(niaInnerEncapValidation['log'])
            self.failed(reason="NIA VxLAN Inner ENCAP CLI Failed")
        else:
            log.info(niaInnerEncapValidation['log'])
            self.passed(reason="NIA VxLAN Inner ENCAP CLI Passed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_DECAP_v6(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        LEAF_1_mac_data = json.loads(testscript.parameters['LEAF-1'].execute("show vdc | json"))
        LEAF_1_mac = LEAF_1_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        LEAF_3_mac_data = json.loads(testscript.parameters['LEAF-3'].execute("show vdc | json"))
        LEAF_3_mac = LEAF_3_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        # Declare the parameters required for the NIA CLI
        niaCLIDecapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v6_addr']),
                'dest'          : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v6_addr']),
                'smac'          : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),
                'iif'           : 'nve1',
                'vlan'          : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'iif'           : "nve1",
                'in_lif'        : "nve1",
                'in_po_mbrs'    : [],
                'in_vlan'       : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']),
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac'])],
                'module'        : ['1'],
                'port'          : [str(testscript.parameters['intf_LEAF_3_to_IXIA'])+".1", 'nve1'],
                'vlan'          : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vni_start']),str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [{
                                    'ip': str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v6_addr'])+"/128",
                                    'type':'ipv6',
                                    'vrf': str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1'}
                                  ],
                'last_path'     : [{
                                     'log_oif': str(testscript.parameters['intf_LEAF_3_to_IXIA'])+".1",
                                     'phy_oif': str(testscript.parameters['intf_LEAF_3_to_IXIA']),
                                     'vlan': '1301'
                                  }],
                'paths'         : [],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIDecapInner_v4['cli_params']['traffic'] = '2'
            niaCLIDecapInner_v4['cli_params']['upper_iif'] = "port-channel" + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id'])
            niaCLIDecapInner_v4['element_params']['iif'] = testscript.parameters['intf_LEAF_3_to_SPINE']
            niaCLIDecapInner_v4['elam_params'] = {
                    'Packet Type'               : 'IPv6',
                    'Source IP'                 : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v6_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v6_addr']),
                    'Source MAC'                : str(LEAF_1_mac),
                    'Destination MAC'           : str(LEAF_3_mac),
                    'src_vlan'                  : "",
                    'Source Bridge Domain'      : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_1_to_IXIA']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_1_to_SPINE'])]
            }

        niaInnerDecapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-3'],niaCLIDecapInner_v4,testscript.parameters['LEAF-3_mgmt'])

        if not niaInnerDecapValidation['result']:
            log.info(niaInnerDecapValidation['log'])
            self.failed(reason="NIA VxLAN Inner DECAP CLI Failed")
        else:
            log.info(niaInnerDecapValidation['log'])
            self.passed(reason="NIA VxLAN Inner DECAP CLI Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for device in device_list:
            device.execute("show ver in bu")

        for device in device_mgmt_list:
            device.execute("show ver in bu")

# *****************************************************************************************************************************#
class VERIFY_NIA_FSV_INNER_VxLAN_IPv4_VPC_VTEP_IIF_SUB_INT(aetest.Testcase):
    """VERIFY_NIA_FSV_INNER_VxLAN_IPv4_VPC_VTEP_IIF_SUB_INT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_ENCAP_v4(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        LEAF_1_mac_data = json.loads(testscript.parameters['LEAF-1'].execute("show vdc | json"))
        LEAF_1_mac = LEAF_1_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        # Declare the parameters required for the NIA CLI
        niaCLIEncapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v4_addr']),
                'dest'          : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v4_addr']),
                'smac'          : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),
                'iif'           : str(testscript.parameters['intf_LEAF_1_to_IXIA'])+".1",
                'vlan'          : '0',
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : str(testscript.parameters['intf_LEAF_1_to_IXIA'])+".1",
                'in_lif'        : str(testscript.parameters['intf_LEAF_1_to_IXIA'])+".1",
                'in_po_mbrs'    : [],
                'in_vlan'       : '0',
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac'])],
                'module'        : ['1'],
                'port'          : [str(testscript.parameters['intf_LEAF_1_to_IXIA'])+".1", 'nve1'],
                'vlan'          : [],
                'vni'           : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [{
                                    'ip': str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                                    'type':'ipv4',
                                    'vrf': str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1'}
                                  ],
                'last_path'     : [],
                'paths'         : [{
                                "encap": {
                                    "dst": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                                    "iif": str(testscript.parameters['LEAF_1_dict']['NVE_data']['src_loop']),
                                    "l2vni": 0,
                                    "l3vni": str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vni_start']),
                                    "src": VPC_VTEP_IP,
                                    "type": "VxLAN"
                                },
                                "log_oif": "nve1",
                                "oif": "nve1",
                                "phy_oif": "nve1"
                }],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIEncapInner_v4['cli_params']['traffic'] = '1'
            niaCLIEncapInner_v4['element_params']['iif'] = testscript.parameters['intf_LEAF_1_to_IXIA']
            niaCLIEncapInner_v4['elam_params'] = {
                    'Packet Type'               : 'IPv4',
                    'Source IP'                 : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v4_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v4_addr']),
                    'Source MAC'                : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac']),
                    'Destination MAC'           : str(LEAF_1_mac),
                    'src_vlan'                  : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['vlan_id']),
                    'Destination Bridge Domain' : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_3_to_SPINE']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_3_to_IXIA'])]
            }

        niaInnerEncapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-1'],niaCLIEncapInner_v4,testscript.parameters['LEAF-3_mgmt'])

        if not niaInnerEncapValidation['result']:
            log.info(niaInnerEncapValidation['log'])
            self.failed(reason="NIA VxLAN Inner ENCAP CLI Failed")
        else:
            log.info(niaInnerEncapValidation['log'])
            self.passed(reason="NIA VxLAN Inner ENCAP CLI Passed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_DECAP_v4(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        LEAF_1_mac_data = json.loads(testscript.parameters['LEAF-1'].execute("show vdc | json"))
        LEAF_1_mac = LEAF_1_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        LEAF_3_mac_data = json.loads(testscript.parameters['LEAF-3'].execute("show vdc | json"))
        LEAF_3_mac = LEAF_3_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        # Declare the parameters required for the NIA CLI
        niaCLIDecapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v4_addr']),
                'dest'          : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v4_addr']),
                'smac'          : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac']),
                'iif'           : 'nve1',
                'vlan'          : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start'])],
                'iif'           : "nve1",
                'in_lif'        : "nve1",
                'in_po_mbrs'    : [],
                'in_vlan'       : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac'])],
                'module'        : ['1'],
                'port'          : [str(testscript.parameters['intf_LEAF_1_to_IXIA'])+".1", 'nve1'],
                'vlan'          : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']),str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [{
                                    'ip': str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v4_addr'])+"/32",
                                    'type':'ipv4',
                                    'vrf': str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1'}
                                  ],
                'last_path'     : [{
                                     'log_oif': str(testscript.parameters['intf_LEAF_1_to_IXIA'])+".1",
                                     'phy_oif': str(testscript.parameters['intf_LEAF_1_to_IXIA']),
                                     'vlan': '1201'
                                  }],
                'paths'         : [],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIDecapInner_v4['cli_params']['traffic'] = '2'
            niaCLIDecapInner_v4['cli_params']['upper_iif'] = "port-channel" + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])
            niaCLIDecapInner_v4['element_params']['iif'] = testscript.parameters['intf_LEAF_1_to_SPINE']
            niaCLIDecapInner_v4['elam_params'] = {
                    'Packet Type'               : 'IPv4',
                    'Source IP'                 : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v4_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v4_addr']),
                    'Source MAC'                : str(LEAF_3_mac),
                    'Destination MAC'           : str(LEAF_1_mac),
                    'src_vlan'                  : "",
                    'Source Bridge Domain'      : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_3_to_IXIA']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_3_to_SPINE'])]
            }

        niaInnerDecapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-1'],niaCLIDecapInner_v4,testscript.parameters['LEAF-3_mgmt'])

        if not niaInnerDecapValidation['result']:
            log.info(niaInnerDecapValidation['log'])
            self.failed(reason="NIA VxLAN Inner DECAP CLI Failed")
        else:
            log.info(niaInnerDecapValidation['log'])
            self.passed(reason="NIA VxLAN Inner DECAP CLI Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for device in device_list:
            device.execute("show ver in bu")

        for device in device_mgmt_list:
            device.execute("show ver in bu")

# *****************************************************************************************************************************#
class VERIFY_NIA_FSV_INNER_VxLAN_IPv6_VPC_VTEP_IIF_SUB_INT(aetest.Testcase):
    """VERIFY_NIA_FSV_INNER_VxLAN_IPv6_VPC_VTEP_IIF_SUB_INT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_ENCAP_v6(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_2_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_2_dict']['NVE_data']['VTEP_IP'])

        LEAF_1_mac_data = json.loads(testscript.parameters['LEAF-1'].execute("show vdc | json"))
        LEAF_1_mac = LEAF_1_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        # Declare the parameters required for the NIA CLI
        niaCLIEncapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v6_addr']),
                'dest'          : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v6_addr']),
                'smac'          : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),
                'iif'           : str(testscript.parameters['intf_LEAF_1_to_IXIA'])+".1",
                'vlan'          : '0',
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [],
                'iif'           : str(testscript.parameters['intf_LEAF_1_to_IXIA'])+".1",
                'in_lif'        : str(testscript.parameters['intf_LEAF_1_to_IXIA'])+".1",
                'in_po_mbrs'    : [],
                'in_vlan'       : '0',
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac'])],
                'module'        : ['1'],
                'port'          : [str(testscript.parameters['intf_LEAF_1_to_IXIA'])+".1", 'nve1'],
                'vlan'          : [],
                'vni'           : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [{
                                    'ip': str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                                    'type':'ipv4',
                                    'vrf': str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1'}
                                  ],
                'last_path'     : [],
                'paths'         : [{
                                "encap": {
                                    "dst": str(testscript.parameters['LEAF_3_dict']['NVE_data']['VTEP_IP']),
                                    "iif": str(testscript.parameters['LEAF_1_dict']['NVE_data']['src_loop']),
                                    "l2vni": 0,
                                    "l3vni": str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vni_start']),
                                    "src": VPC_VTEP_IP,
                                    "type": "VxLAN"
                                },
                                "log_oif": "nve1",
                                "oif": "nve1",
                                "phy_oif": "nve1"
                }],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIEncapInner_v4['cli_params']['traffic'] = '1'
            niaCLIEncapInner_v4['element_params']['iif'] = testscript.parameters['intf_LEAF_1_to_IXIA']
            niaCLIEncapInner_v4['elam_params'] = {
                    'Packet Type'               : 'IPv6',
                    'Source IP'                 : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v6_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v6_addr']),
                    'Source MAC'                : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac']),
                    'Destination MAC'           : str(LEAF_1_mac),
                    'src_vlan'                  : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['vlan_id']),
                    'Destination Bridge Domain' : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_3_to_SPINE']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_3_to_IXIA'])]
            }

        niaInnerEncapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-1'],niaCLIEncapInner_v4,testscript.parameters['LEAF-3_mgmt'])

        if not niaInnerEncapValidation['result']:
            log.info(niaInnerEncapValidation['log'])
            self.failed(reason="NIA VxLAN Inner ENCAP CLI Failed")
        else:
            log.info(niaInnerEncapValidation['log'])
            self.passed(reason="NIA VxLAN Inner ENCAP CLI Passed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_NIA_VxLAN_INNER_DECAP_v6(self, testscript):
        """ Verify NIA VxLAN Inner ENCAP CLI (IPv4) execution """

        LEAF_1_mac_data = json.loads(testscript.parameters['LEAF-1'].execute("show vdc | json"))
        LEAF_1_mac = LEAF_1_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        LEAF_3_mac_data = json.loads(testscript.parameters['LEAF-3'].execute("show vdc | json"))
        LEAF_3_mac = LEAF_3_mac_data['TABLE_vdc']['ROW_vdc']['mac']

        # Declare the parameters required for the NIA CLI
        if 'VPC_VTEP_IP' in testscript.parameters['LEAF_1_dict']['NVE_data'].keys():
            VPC_VTEP_IP = str(testscript.parameters['LEAF_1_dict']['NVE_data']['VPC_VTEP_IP'])
        else:
            VPC_VTEP_IP = str(testscript.parameters['LEAF_1_dict']['NVE_data']['VTEP_IP'])

        # Declare the parameters required for the NIA CLI
        niaCLIDecapInner_v4 = {
            'cli_params': {
                'src'           : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v6_addr']),
                'dest'          : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v6_addr']),
                'smac'          : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),
                'dmac'          : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac']),
                'iif'           : 'nve1',
                'vlan'          : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']),
                'cc_flag'       : '1',
            },
            'element_params': {
                'BD'            : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start'])],
                'iif'           : "nve1",
                'in_lif'        : "nve1",
                'in_po_mbrs'    : [],
                'in_vlan'       : str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                'in_vrf'        : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'macAddr'       : [str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['mac']),str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['mac'])],
                'module'        : ['1'],
                'port'          : [str(testscript.parameters['intf_LEAF_1_to_IXIA'])+".1", 'nve1'],
                'vlan'          : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start'])],
                'vni'           : [str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']),str(testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vni_start'])],
                'vpc'           : [],
                'iif_vrf'       : str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1',
                'route'         : [{
                                    'ip': str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v6_addr'])+"/128",
                                    'type':'ipv6',
                                    'vrf': str(testscript.parameters['forwardingSysDict']['VRF_string']) + '1'}
                                  ],
                'last_path'     : [{
                                     'log_oif': str(testscript.parameters['intf_LEAF_1_to_IXIA'])+".1",
                                     'phy_oif': str(testscript.parameters['intf_LEAF_1_to_IXIA']),
                                     'vlan': '1201'
                                  }],
                'paths'         : [],
            }
        }

        if testscript.parameters['topology_flag'] == 0:
            niaCLIDecapInner_v4['cli_params']['traffic'] = '2'
            niaCLIDecapInner_v4['cli_params']['upper_iif'] = "port-channel" + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id'])
            niaCLIDecapInner_v4['element_params']['iif'] = testscript.parameters['intf_LEAF_1_to_SPINE']
            niaCLIDecapInner_v4['elam_params'] = {
                    'Packet Type'               : 'IPv6',
                    'Source IP'                 : str(testscript.parameters['LEAF_3_SUB_INT_TGEN_data']['v6_addr']),
                    'Destination IP'            : str(testscript.parameters['LEAF_12_SUB_INT_TGEN_data']['v6_addr']),
                    'Source MAC'                : str(LEAF_3_mac),
                    'Destination MAC'           : str(LEAF_1_mac),
                    'src_vlan'                  : "",
                    'Source Bridge Domain'      : str(testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']),
                    'Egress Interface'          : str(testscript.parameters['intf_LEAF_3_to_IXIA']),
                    'Ingress Interface'         : [str(testscript.parameters['intf_LEAF_3_to_SPINE'])]
            }

        niaInnerDecapValidation = niaLib.verifyNIACLI(testscript.parameters['LEAF-1'],niaCLIDecapInner_v4,testscript.parameters['LEAF-1_mgmt'])

        if not niaInnerDecapValidation['result']:
            log.info(niaInnerDecapValidation['log'])
            self.failed(reason="NIA VxLAN Inner DECAP CLI Failed")
        else:
            log.info(niaInnerDecapValidation['log'])
            self.passed(reason="NIA VxLAN Inner DECAP CLI Passed")

    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        for device in device_list:
            device.execute("show ver in bu")

        for device in device_mgmt_list:
            device.execute("show ver in bu")

# *****************************************************************************************************************************#
class UNSHUT_SECONDARY_VPC_UPLINK_END(aetest.Testcase):
    """START_IXIA_TRAFFIC"""

    # =============================================================================================================================#
    @aetest.test
    def UNSHUT_SECONDARY_VPC_UPLINK(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        testscript.parameters["LEAF-2"].configure('''
                interface port-channel''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                    no shut
        ''')

        time.sleep(200)

    # =============================================================================================================================#
    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        testscript.parameters['LEAF-2'].configure('''
              interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                shutdown
        ''')
        time.sleep(120)

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2,3) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class STOP_IXIA_TRAFFIC(aetest.Testcase):
    """STOP_IXIA_TRAFFIC"""

    # =============================================================================================================================#
    @aetest.test
    def stop_ixia_traffic(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """
        if ixLib.start_traffic() == 0:
            log.debug("Starting Traffic failed")
            self.failed("Starting Traffic failed", goto=['cleanup'])


########################################################################
####                       COMMON CLEANUP SECTION                    ###
########################################################################
#
## Remove the BASE CONFIGURATION that was applied earlier in the 
## common cleanup section, clean the left over

class common_cleanup(aetest.CommonCleanup):
    """ Common Cleanup for Sample Test """

    @aetest.subsection
    def restore_terminal_width(self):
        """ Common Cleanup subsection """
        log.info(banner("script common cleanup starts here"))

    @aetest.subsection
    def restore_terminal_width(self):
        """ Common Cleanup subsection """
        log.info(banner("script common cleanup starts here"))

    @aetest.subsection
    def restore_terminal_width(self):
        """ Common Cleanup subsection """
        log.info(banner("script common cleanup starts here"))

    @aetest.subsection
    def restore_terminal_width(self):
        """ Common Cleanup subsection """
        log.info(banner("script common cleanup starts here"))


if __name__ == '__main__':  # pragma: no cover
    aetest.main()
