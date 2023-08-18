#!/usr/bin/env python

import ipaddress as ip
import json
###################################################################
###                  Importing Libraries                        ###
###################################################################
import logging
import time

import yaml
from pyats import aetest
from pyats.log.utils import banner
from yaml import Loader

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

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

###################################################################
###                  User Library Methods                       ###
###################################################################

# -- NA -- #

###################################################################
###                  GLOBAL VARIABLES                           ###
###################################################################
device_list = []


###################################################################
###                  COMMON SETUP SECTION                       ###
###################################################################

# *****************************************************************************************************************************#
class COMMON_SETUP(aetest.CommonSetup):
    """ Common Setup """

    @aetest.subsection
    def connecting_to_devices(self, testscript, testbed, uut_list, configurationFile, script_flags=None):
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
        LEAF_1.connect()
        LEAF_2.connect()
        LEAF_3.connect()
        FAN_1.connect()
        FAN_2.connect()

        device_list.append(SPINE)
        device_list.append(LEAF_1)
        device_list.append(LEAF_2)
        device_list.append(LEAF_3)
        device_list.append(FAN_1)
        device_list.append(FAN_2)

        # =============================================================================================================================#
        # Make sure that the connection went fine

        for dut in device_list:
            if not hasattr(dut, 'execute'):
                self.failed()

            if dut.execute != dut.connectionmgr.default.execute:
                self.failed()

        # =============================================================================================================================#
        # Import script_flags into testscript.parameters
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
        testscript.parameters['forwardingSysDict'] = configuration['FWD_SYS_dict']

        testscript.parameters['LEAF_12_TGEN_dict'] = configuration['LEAF_12_TGEN_data']
        testscript.parameters['LEAF_3_TGEN_dict'] = configuration['LEAF_3_TGEN_data']

        testscript.parameters['leafVPCDictData'] = {LEAF_1: configuration['LEAF_1_dict'],
                                                    LEAF_2: configuration['LEAF_2_dict']}

        testscript.parameters['leavesDictList'] = [configuration['LEAF_1_dict'],
                                                   configuration['LEAF_2_dict'],
                                                   configuration['LEAF_3_dict']]

        testscript.parameters['leavesDict'] = {LEAF_1: configuration['LEAF_1_dict'],
                                               LEAF_2: configuration['LEAF_2_dict'],
                                               LEAF_3: configuration['LEAF_3_dict']}

        testscript.parameters['leavesDevices'] = [LEAF_1, LEAF_2, LEAF_3]

        testscript.parameters['VTEP_List'] = [testscript.parameters['LEAF_1_dict'],
                                              testscript.parameters['LEAF_2_dict'],
                                              testscript.parameters['LEAF_3_dict']]

        # =============================================================================================================================#
        # Setting UP few necessary Variables
        testscript.parameters['STD_VTEP_ACCESS_PO_id'] = "200"

    # *****************************************************************************************************************************#

    @aetest.subsection
    def get_interfaces(self, testscript):
        """ common setup subsection: Getting required Connections for Test """

        SPINE = testscript.parameters['SPINE']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
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
        testscript.parameters['intf_LEAF_1_to_FAN_1'] = LEAF_1.interfaces['LEAF-1_to_FAN-1'].intf

        testscript.parameters['intf_LEAF_2_to_LEAF_1_1'] = LEAF_2.interfaces['LEAF-2_to_LEAF-1_1'].intf
        testscript.parameters['intf_LEAF_2_to_LEAF_1_2'] = LEAF_2.interfaces['LEAF-2_to_LEAF-1_2'].intf
        testscript.parameters['intf_LEAF_2_to_SPINE'] = LEAF_2.interfaces['LEAF-2_to_SPINE'].intf
        testscript.parameters['intf_LEAF_2_to_FAN_1'] = LEAF_2.interfaces['LEAF-2_to_FAN-1'].intf

        testscript.parameters['intf_LEAF_3_to_SPINE'] = LEAF_3.interfaces['LEAF-3_to_SPINE'].intf
        testscript.parameters['intf_LEAF_3_to_FAN_2'] = LEAF_3.interfaces['LEAF-3_to_FAN-2'].intf

        testscript.parameters['intf_FAN_1_to_LEAF_1'] = FAN_1.interfaces['FAN-1_to_LEAF-1'].intf
        testscript.parameters['intf_FAN_1_to_LEAF_2'] = FAN_1.interfaces['FAN-1_to_LEAF-2'].intf
        testscript.parameters['intf_FAN_1_to_IXIA'] = FAN_1.interfaces['FAN-1_to_IXIA'].intf

        testscript.parameters['intf_FAN_2_to_LEAF_3'] = FAN_2.interfaces['FAN-2_to_LEAF-3'].intf
        testscript.parameters['intf_FAN_2_to_IXIA'] = FAN_2.interfaces['FAN-2_to_IXIA'].intf

        testscript.parameters['intf_IXIA_to_FAN_1'] = IXIA.interfaces['IXIA_to_FAN-1'].intf
        testscript.parameters['intf_IXIA_to_FAN_2'] = IXIA.interfaces['IXIA_to_FAN-2'].intf

        testscript.parameters['ixia_int_list'] = str(testscript.parameters['intf_IXIA_to_FAN_1']) + " " + str(
            testscript.parameters['intf_IXIA_to_FAN_2'])

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
                                    +-----------+             +-----------+
                                    |   FAN-1   |             |   FAN-2   |
                                    +-----------+             +-----------+
                                          |                         |      
                                          |                         |      
                                        Ixia                      Ixia     
        """

        log.info("Topology to be used is")
        log.info(topology)


# *****************************************************************************************************************************#
class DEVICE_BRINGUP(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.test
    def enable_feature_set(self, testscript):
        """ Device Bring-up subsection: Configuring Features and Feature-sets """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            leafLst = [testscript.parameters['LEAF-1'], testscript.parameters['LEAF-2'],
                       testscript.parameters['LEAF-3']]
            spineFeatureList = ['ospf', 'bgp', 'pim', 'lacp', 'nv overlay']
            vpcLeafFeatureList = ['vpc', 'ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp',
                                  'nv overlay']
            LeafFeatureList = ['ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp', 'nv overlay']
            fanOutFeatureList = ['lacp']
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
            featureSetConfigureLeaf1_status = infraConfig.configureVerifyFeatureSet(testscript.parameters['LEAF-1'],
                                                                                    ['mpls'])
            if featureSetConfigureLeaf1_status['result']:
                log.info("Passed Configuring feature-sets on LEAF-1")
            else:
                log.debug("Failed configuring feature-sets on LEAF-1")
                configFeatureSet_msgs += featureSetConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

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
            featureSetConfigureLeaf2_status = infraConfig.configureVerifyFeatureSet(testscript.parameters['LEAF-2'],
                                                                                    ['mpls'])
            if featureSetConfigureLeaf2_status['result']:
                log.info("Passed Configuring feature-sets on LEAF-2")
            else:
                log.debug("Failed configuring feature-sets on LEAF-2")
                configFeatureSet_msgs += featureSetConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

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
            featureSetConfigureLeaf3_status = infraConfig.configureVerifyFeatureSet(testscript.parameters['LEAF-3'],
                                                                                    ['mpls'])
            if featureSetConfigureLeaf3_status['result']:
                log.info("Passed Configuring feature-sets on LEAF-3")
            else:
                log.debug("Failed configuring feature-sets on LEAF-3")
                configFeatureSet_msgs += featureSetConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            featureConfigureLeaf3_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-3'],
                                                                              LeafFeatureList)
            if featureConfigureLeaf3_status['result']:
                log.info("Passed Configuring features on LEAF-3")
            else:
                log.debug("Failed configuring features on LEAF-3")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on FAN-1
            featureConfigureFan1_status = infraConfig.configureVerifyFeature(testscript.parameters['FAN-1'],
                                                                             fanOutFeatureList)
            if featureConfigureFan1_status['result']:
                log.info("Passed Configuring features on FAN-1")
            else:
                log.debug("Failed configuring features on FAN-1")
                configFeatureSet_msgs += featureConfigureFan1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on FAN-2
            featureConfigureFan2_status = infraConfig.configureVerifyFeature(testscript.parameters['FAN-2'],
                                                                             fanOutFeatureList)
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
                self.errored('Exception occurred while configuring on SPINE')
        else:
            self.skipped(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_LEAF_1_2(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNVPCLeafs(testscript.parameters['forwardingSysDict'],
                                          testscript.parameters['leafVPCDictData'])

            try:
                testscript.parameters['LEAF-1'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_SPINE']) + '''
                    channel-group ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                    no shutdown

                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_FAN_1']) + '''
                    channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + ''' force mode active
                    no shutdown

                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_2_1']) + '''
                    vrf member peer-keep-alive
                    ip address ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['kp_al_ip']) + '''/24
                    no shutdown

                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_2_2']) + '''
                    channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po']) + ''' force mode active
                    no shutdown
                  
                  interface nve 1
                    fabric-ready time 30

              ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on LEAF-1')

            try:
                testscript.parameters['LEAF-2'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_2_to_SPINE']) + '''
                    channel-group ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                    no shutdown

                  interface ''' + str(testscript.parameters['intf_LEAF_2_to_FAN_1']) + '''
                    channel-group ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + ''' force mode active
                    no shutdown

                  interface ''' + str(testscript.parameters['intf_LEAF_2_to_LEAF_1_1']) + '''
                    vrf member peer-keep-alive
                    ip address ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['kp_al_ip']) + '''/24
                    no shutdown

                  interface ''' + str(testscript.parameters['intf_LEAF_2_to_LEAF_1_2']) + '''
                    channel-group ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['peer_link_po']) + ''' force mode active
                    no shutdown

                  interface nve 1
                    fabric-ready time 30

              ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on LEAF-2')
        else:
            self.skipped(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_LEAF_3(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-3 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNLeaf(testscript.parameters['LEAF-3'], testscript.parameters['forwardingSysDict'],
                                      testscript.parameters['LEAF_3_dict'])

            try:
                testscript.parameters['LEAF-3'].configure('''

                    interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''
                      no switchport
                      channel-group ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown

                    interface port-channel ''' + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) + '''
                      switchport
                      switchport mode trunk
                      no shut

                    interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                      no switchport
                      channel-group ''' + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) + ''' force mode active
                      no shutdown

                    interface nve 1
                        fabric-ready time 30

              ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on LEAF-3')

        else:
            self.skipped(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_FAN_1(self, testscript):
        """ Device Bring-up subsection: Configuring FAN_1 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            # Do not perform configurations if skip_device_config flag is set
            if not testscript.parameters['script_flags']['skip_device_config']:

                fanOut1_vlanConfiguration = ""
                forwardingSysDict = testscript.parameters['forwardingSysDict']
                l2_vlan_id_start = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
                l3_vlan_id_start = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']
                total_l2_vlans = int(forwardingSysDict['VRF_count']) * int(forwardingSysDict['VLAN_PER_VRF_count'])
                l2_vlan_id_stop = int(l2_vlan_id_start) + total_l2_vlans
                l3_vlan_id_stop = int(l3_vlan_id_start) + int(forwardingSysDict['VRF_count'])

                fanOut1_vlanConfiguration += '''
                                                vlan ''' + str(l2_vlan_id_start) + '''-''' + str(l2_vlan_id_stop) + '''
                                                state active
                                                no shut'''

                fanOut1_vlanConfiguration += '''
                                                vlan ''' + str(l3_vlan_id_start) + '''-''' + str(l3_vlan_id_stop) + '''
                                                state active
                                                no shut'''

                try:
                    testscript.parameters['FAN-1'].configure(
                        str(fanOut1_vlanConfiguration) + '''

                                        interface port-channel ''' + str(
                            testscript.parameters['STD_VTEP_ACCESS_PO_id']) + '''
                                          switchport
                                          switchport mode trunk
                                          no shutdown

                                        interface ''' + str(testscript.parameters['intf_FAN_1_to_LEAF_1']) + '''
                                          channel-group 200 force mode active
                                          no shutdown

                                        interface ''' + str(testscript.parameters['intf_FAN_1_to_LEAF_2']) + '''
                                          channel-group 200 force mode active
                                          no shutdown

                                        interface ''' + str(testscript.parameters['intf_FAN_1_to_IXIA']) + '''
                                          switchport
                                          switchport mode trunk
                                          spanning-tree port type edge trunk
                                          no shut
                                    ''')

                except Exception as error:
                    log.debug("Unable to configure - Encountered Exception " + str(error))
                    self.errored('Exception occurred while configuring on FAN-1', goto=['common_cleanup'])
            else:
                self.passed(reason="Skipped Device Configurations as per Request")

        else:
            self.skipped(reason="Skipped Device Configurations as per Request")

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_FAN_2(self, testscript):
        """ Device Bring-up subsection: Configuring FAN_2 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            fanOut2_vlanConfiguration = ""
            forwardingSysDict = testscript.parameters['forwardingSysDict']
            l2_vlan_id_start = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            l3_vlan_id_start = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']
            total_l2_vlans = int(forwardingSysDict['VRF_count']) * int(forwardingSysDict['VLAN_PER_VRF_count'])
            l2_vlan_id_stop = int(l2_vlan_id_start) + total_l2_vlans
            l3_vlan_id_stop = int(l3_vlan_id_start) + int(forwardingSysDict['VRF_count'])

            fanOut2_vlanConfiguration += '''
                                            vlan ''' + str(l2_vlan_id_start) + '''-''' + str(l2_vlan_id_stop) + '''
                                            state active
                                            no shut'''

            fanOut2_vlanConfiguration += '''
                                            vlan ''' + str(l3_vlan_id_start) + '''-''' + str(l3_vlan_id_stop) + '''
                                            state active
                                            no shut'''

            try:
                testscript.parameters['FAN-2'].configure(
                    str(fanOut2_vlanConfiguration) + '''

                                    interface port-channel200
                                      switchport
                                      switchport mode trunk
                                      no shutdown

                                    interface ''' + str(testscript.parameters['intf_FAN_2_to_LEAF_3']) + '''
                                      channel-group ''' + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) + ''' force mode active
                                      no shutdown

                                    interface ''' + str(testscript.parameters['intf_FAN_2_to_IXIA']) + '''
                                      switchport
                                      switchport mode trunk
                                      spanning-tree port type edge trunk
                                      no shut

                                ''')

            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FAN-2', goto=['common_cleanup'])
        else:
            self.skipped(reason="Skipped Device Configurations as per Request")

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

        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info(
                "PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            self.failed("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")

    # =============================================================================================================================#
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

    # =============================================================================================================================#
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

    # *****************************************************************************************************************************#


# *****************************************************************************************************************************#
class ENABLE_L2_TRM_CONFIGURATION(aetest.Testcase):
    """ENABLE_L2_TRM_CONFIGURATION"""

    # =============================================================================================================================#
    @aetest.setup
    def configure_feature_ngmvpn(self, testscript):
        """ ENABLE_L2_TRM_CONFIGURATION setup subsection: Configuring feature ngmvpn """

        #featureConfigStatus_spine = infraConfig.configureVerifyFeature(testscript.parameters['SPINE'], "ngmvpn")
        featureConfigStatus_leaves = infraConfig.configureVerifyFeature(testscript.parameters['leavesDevices'],
                                                                        "ngmvpn")

        # if (featureConfigStatus_spine['result']) is 1 and (featureConfigStatus_leaves['result'] is 1):
        #     log.info("PASS : Successfully Configured Feature ngmvpn on SPINE\n\n")
        #     self.passed(reason=str(featureConfigStatus_spine['log']) + str(featureConfigStatus_leaves['log']))
        # else:
        #     log.info("FAIL : Failed to Configured Feature ngmvpn on SPINE \n\n")
        #     self.failed(reason=str(featureConfigStatus_spine['log']) + str(featureConfigStatus_leaves['log']))

    # =============================================================================================================================#
    @aetest.test
    def verify_feature_ngmvpn(self, testscript):
        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Verify feature ngmvpn """

        fail_flag = []
        fail_msgs = ""

        #spine_trm_feature_output = testscript.parameters['SPINE'].execute("show feature | grep ngmvpn")
        leaf1_trm_feature_output = testscript.parameters['LEAF-1'].execute("show feature | grep ngmvpn")
        leaf2_trm_feature_output = testscript.parameters['LEAF-2'].execute("show feature | grep ngmvpn")
        leaf3_trm_feature_output = testscript.parameters['LEAF-3'].execute("show feature | grep ngmvpn")

        # if "enabled" in spine_trm_feature_output:
        #     fail_msgs += " Enabling feature ngmvpn on SPINE is Successful\n"
        # else:
        #     fail_msgs += " Enabling feature ngmvpn on SPINE has failed\n"
        #     fail_flag.append(0)

        if "enabled" in leaf1_trm_feature_output:
            fail_msgs += " Enabling feature ngmvpn on LEAF-1 is Successful\n"
        else:
            fail_msgs += " Enabling feature ngmvpn on LEAF-1 has failed\n"
            fail_flag.append(0)

        if "enabled" in leaf2_trm_feature_output:
            fail_msgs += " Enabling feature ngmvpn on LEAF-2 is Successful\n"
        else:
            fail_msgs += " Enabling feature ngmvpn on LEAF-2 has failed\n"
            fail_flag.append(0)

        if "enabled" in leaf3_trm_feature_output:
            fail_msgs += " Enabling feature ngmvpn on LEAF-3 is Successful\n"
        else:
            fail_msgs += " Enabling feature ngmvpn on LEAF-3 has failed\n"
            fail_flag.append(0)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def configure_ngmvpn_AF_and_igmp_querier(self, testscript):
        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Configure IGMP Querier """

        forwardingSysDict = testscript.parameters['forwardingSysDict']

        # ----------------------------------------------------
        # Configuring on SPINE
        # ----------------------------------------------------

        testscript.parameters['SPINE'].configure('''
                                                  router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                                                    address-family ipv4 mvpn
                                                    template peer ibgp_evpn
                                                      address-family ipv4 mvpn
                                                        send-community
                                                        send-community extended
                                                        route-reflector-client
                                                  ''')

        # ----------------------------------------------------
        # LEAF-1 Counter Variables
        # ----------------------------------------------------
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0

        vrf_id = forwardingSysDict['VRF_id_start']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']

        # ----------------------------------------------------
        # Configuring on LEAF-1
        # ----------------------------------------------------

        testscript.parameters['LEAF-1'].configure("""
                                                  ip igmp snooping vxlan
                                                  advertise evpn multicast                                                  
                                                  """)

        testscript.parameters['LEAF-1'].configure('''
                                                  router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                                                    address-family ipv4 mvpn
                                                    neighbor ''' + str(
            testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + ''' remote-as ''' + str(
            forwardingSysDict['BGP_AS_num']) + '''
                                                      address-family ipv4 mvpn
                                                        send-community
                                                        send-community extended
                                                  ''')

        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            testscript.parameters['LEAF-1'].configure('''
                                                      vrf context ''' + str(forwardingSysDict['VRF_string']) + str(
                vrf_id) + '''
                                                        address-family ipv4 unicast
                                                          route-target both auto mvpn
                                                        address-family ipv6 unicast
                                                          route-target both auto mvpn
                                                      ''')

            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
                testscript.parameters['LEAF-1'].configure('''
                                                            vlan configuration ''' + str(l2_vlan_id) + '''
                                                              ip igmp snooping querier 1.1.1.1
                                                        ''')
                l2_vlan_count_iter += 1
                l2_vlan_id += 1

            l3_vrf_count_iter += 1
            l2_vlan_count_iter = 0
            vrf_id += 1

        # ----------------------------------------------------
        # LEAF-2 Counter Variables
        # ----------------------------------------------------
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0

        vrf_id = forwardingSysDict['VRF_id_start']
        l2_vlan_id = testscript.parameters['LEAF_2_dict']['VNI_data']['l2_vlan_start']

        # ----------------------------------------------------
        # Configuring on LEAF-2
        # ----------------------------------------------------

        testscript.parameters['LEAF-2'].configure("""
                                                  ip igmp snooping vxlan
                                                  advertise evpn multicast                                                  
                                                  """)

        testscript.parameters['LEAF-2'].configure('''
                                                  router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                                                    address-family ipv4 mvpn
                                                    neighbor ''' + str(
            testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + ''' remote-as ''' + str(
            forwardingSysDict['BGP_AS_num']) + '''
                                                      address-family ipv4 mvpn
                                                        send-community
                                                        send-community extended
                                                  ''')

        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            testscript.parameters['LEAF-2'].configure('''
                                                      vrf context ''' + str(forwardingSysDict['VRF_string']) + str(
                vrf_id) + '''
                                                        address-family ipv4 unicast
                                                          route-target both auto mvpn
                                                        address-family ipv6 unicast
                                                          route-target both auto mvpn
                                                      ''')

            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
                testscript.parameters['LEAF-2'].configure('''
                                                            vlan configuration ''' + str(l2_vlan_id) + '''
                                                              ip igmp snooping querier 1.1.1.1
                                                        ''')
                l2_vlan_count_iter += 1
                l2_vlan_id += 1

            l3_vrf_count_iter += 1
            l2_vlan_count_iter = 0
            vrf_id += 1

        # ----------------------------------------------------
        # LEAF-3 Counter Variables
        # ----------------------------------------------------
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0

        vrf_id = forwardingSysDict['VRF_id_start']
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']

        # ----------------------------------------------------
        # Configuring on LEAF-3
        # ----------------------------------------------------

        testscript.parameters['LEAF-3'].configure("""
                                                  ip igmp snooping vxlan
                                                  advertise evpn multicast                                                  
                                                  """)

        testscript.parameters['LEAF-3'].configure('''
                                                  router bgp ''' + str(forwardingSysDict['BGP_AS_num']) + '''
                                                    address-family ipv4 mvpn
                                                    neighbor ''' + str(
            testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + ''' remote-as ''' + str(
            forwardingSysDict['BGP_AS_num']) + '''
                                                      address-family ipv4 mvpn
                                                        send-community
                                                        send-community extended
                                                  ''')

        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            testscript.parameters['LEAF-3'].configure('''
                                                      vrf context ''' + str(forwardingSysDict['VRF_string']) + str(
                vrf_id) + '''
                                                        address-family ipv4 unicast
                                                          route-target both auto mvpn
                                                        address-family ipv6 unicast
                                                          route-target both auto mvpn
                                                      ''')

            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
                testscript.parameters['LEAF-3'].configure('''
                                                            vlan configuration ''' + str(l2_vlan_id) + '''
                                                              ip igmp snooping querier 1.1.1.1
                                                        ''')
                l2_vlan_count_iter += 1
                l2_vlan_id += 1

            l3_vrf_count_iter += 1
            l2_vlan_count_iter = 0
            vrf_id += 1

    # =============================================================================================================================#
    @aetest.test
    def verify_igmp_querier(self, testscript):
        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Save all configurations (copy r s) """

        forwardingSysDict = testscript.parameters['forwardingSysDict']
        fail_flag = []
        fail_msgs = ""

        # ----------------------------------------------------
        # LEAF-1 Counter Variables
        # ----------------------------------------------------
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0
        vrf_id = forwardingSysDict['VRF_id_start']
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']

        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
                igmpQuerierOutput = json.loads(testscript.parameters['LEAF-1'].execute(
                    "sh ip igmp snooping querier vlan " + str(l2_vlan_id) + " | json"))

                if igmpQuerierOutput['TABLE_vlan']['ROW_vlan']['QuerierName'] != "Switch querier":
                    fail_flag.append(0)
                    fail_msgs += str(testscript.parameters['LEAF-1'].alias) + " -- " + str(
                        l2_vlan_id) + " is not is Switch querier state"

                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            l3_vrf_count_iter += 1
            l2_vlan_count_iter = 0
            vrf_id += 1

        # ----------------------------------------------------
        # LEAF-2 Counter Variables
        # ----------------------------------------------------
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0
        vrf_id = forwardingSysDict['VRF_id_start']
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']

        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
                igmpQuerierOutput = json.loads(testscript.parameters['LEAF-2'].execute(
                    "sh ip igmp snooping querier vlan " + str(l2_vlan_id) + " | json"))

                if igmpQuerierOutput['TABLE_vlan']['ROW_vlan']['QuerierName'] != "Switch querier":
                    fail_flag.append(0)
                    fail_msgs += str(testscript.parameters['LEAF-2'].alias) + " -- " + str(
                        l2_vlan_id) + " is not is Switch querier state"

                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            l3_vrf_count_iter += 1
            l2_vlan_count_iter = 0
            vrf_id += 1

        # ----------------------------------------------------
        # LEAF-3 Counter Variables
        # ----------------------------------------------------
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0
        vrf_id = forwardingSysDict['VRF_id_start']
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']

        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
                igmpQuerierOutput = json.loads(testscript.parameters['LEAF-3'].execute(
                    "sh ip igmp snooping querier vlan " + str(l2_vlan_id) + " | json"))

                if igmpQuerierOutput['TABLE_vlan']['ROW_vlan']['QuerierName'] != "Switch querier":
                    fail_flag.append(0)
                    fail_msgs += str(testscript.parameters['LEAF-3'].alias) + " -- " + str(
                        l2_vlan_id) + " is not is Switch querier state"

                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            l3_vrf_count_iter += 1
            l2_vlan_count_iter = 0
            vrf_id += 1

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def perform_copy_r_s(self, testscript):
        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Save all configurations (copy r s) """

        testscript.parameters['LEAF-1'].configure("copy r s")
        testscript.parameters['LEAF-2'].configure("copy r s")
        testscript.parameters['LEAF-3'].configure("copy r s")

        time.sleep(300)

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

            ixiaArgDict = {
                'chassis_ip': ixia_chassis_ip,
                'port_list': ixia_int_list,
                'tcl_server': ixia_tcl_server,
                'tcl_port': ixia_tcl_port
            }

            log.info("Ixia Args Dict is:")
            log.info(ixiaArgDict)

            ixLib.end_session()
            time.sleep(20)
            result = ixLib.connect_to_ixia(ixiaArgDict)
            if result == 0:
                log.debug("Connecting to ixia failed")
                self.errored("Connecting to ixia failed")

            ch_key = result['port_handle']
            for ch_p in ixia_chassis_ip.split('.'):
                ch_key = ch_key[ch_p]

            log.info("Port Handles are:")
            log.info(ch_key)

            testscript.parameters['port_handle_1'] = ch_key[ix_int_1]
            testscript.parameters['port_handle_2'] = ch_key[ix_int_2]

        else:
            self.skipped(reason="Skipped TGEN Configurations as per request")

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

            testscript.parameters['IX_TP1'] = ixLib.create_topo_device_grp(TOPO_1_dict)
            if testscript.parameters['IX_TP1'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed")
            else:
                log.info("Created BL1-TG Topology Successfully")

            testscript.parameters['IX_TP2'] = ixLib.create_topo_device_grp(TOPO_2_dict)
            if testscript.parameters['IX_TP2'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed")
            else:
                log.info("Created BL2-TG Topology Successfully")

            testscript.parameters['IX_TP1']['port_handle'] = testscript.parameters['port_handle_1']
            testscript.parameters['IX_TP2']['port_handle'] = testscript.parameters['port_handle_2']
        else:
            self.skipped(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_IXIA_INTERFACES(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure IXIA Interfaces """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            P1 = testscript.parameters['port_handle_1']
            P2 = testscript.parameters['port_handle_2']

            # Retrieving TGEN Data from Config file
            P1_tgen_dict = testscript.parameters['LEAF_12_TGEN_dict']
            P2_tgen_dict = testscript.parameters['LEAF_3_TGEN_dict']

            P1_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP1']['dev_grp_hndl'],
                             'port_hndl': P1,
                             'no_of_ints': str(P1_tgen_dict['no_of_ints']),
                             'phy_mode': P1_tgen_dict['phy_mode'],
                             'mac': P1_tgen_dict['mac'],
                             'mac_step': P1_tgen_dict['mac_step'],
                             'protocol': P1_tgen_dict['protocol'],
                             'v4_addr': P1_tgen_dict['v4_addr'],
                             'v4_addr_step': P1_tgen_dict['v4_addr_step'],
                             'v4_gateway': P1_tgen_dict['v4_gateway'],
                             'v4_gateway_step': P1_tgen_dict['v4_gateway_step'],
                             'v4_netmask': P1_tgen_dict['v4_netmask'],
                             'v6_addr': P1_tgen_dict['v6_addr'],
                             'v6_addr_step': P1_tgen_dict['v6_addr_step'],
                             'v6_gateway': P1_tgen_dict['v6_gateway'],
                             'v6_gateway_step': P1_tgen_dict['v6_gateway_step'],
                             'v6_netmask': P1_tgen_dict['v6_netmask'],
                             'vlan_id': str(P1_tgen_dict['vlan_id']),
                             'vlan_id_step': P1_tgen_dict['vlan_id_step']}

            P2_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP2']['dev_grp_hndl'],
                             'port_hndl': P2,
                             'no_of_ints': str(P2_tgen_dict['no_of_ints']),
                             'phy_mode': P2_tgen_dict['phy_mode'],
                             'mac': P2_tgen_dict['mac'],
                             'mac_step': P2_tgen_dict['mac_step'],
                             'protocol': P2_tgen_dict['protocol'],
                             'v4_addr': P2_tgen_dict['v4_addr'],
                             'v4_addr_step': P2_tgen_dict['v4_addr_step'],
                             'v4_gateway': P2_tgen_dict['v4_gateway'],
                             'v4_gateway_step': P2_tgen_dict['v4_gateway_step'],
                             'v4_netmask': P2_tgen_dict['v4_netmask'],
                             'v6_addr': P2_tgen_dict['v6_addr'],
                             'v6_addr_step': P2_tgen_dict['v6_addr_step'],
                             'v6_gateway': P2_tgen_dict['v6_gateway'],
                             'v6_gateway_step': P2_tgen_dict['v6_gateway_step'],
                             'v6_netmask': P2_tgen_dict['v6_netmask'],
                             'vlan_id': str(P2_tgen_dict['vlan_id']),
                             'vlan_id_step': P2_tgen_dict['vlan_id_step']}

            P1_IX_int_data = ixLib.configure_multi_ixia_interface(P1_int_dict_1)
            P2_IX_int_data = ixLib.configure_multi_ixia_interface(P2_int_dict_1)

            if P1_IX_int_data == 0 or P2_IX_int_data == 0:
                log.debug("Configuring IXIA Interface failed")
                self.errored("Configuring IXIA Interface failed")
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

        else:
            self.skipped(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_IXIA_IGMP_GROUPS(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP2 = testscript.parameters['IX_TP2']
            P1_TGEN_dict = testscript.parameters['LEAF_12_TGEN_dict']
            P2_TGEN_dict = testscript.parameters['LEAF_3_TGEN_dict']

            IGMP_dict_1 = {'ipv4_hndl': IX_TP2['ipv4_handle'],
                           'igmp_ver': P2_TGEN_dict['igmp_ver'],
                           'mcast_grp_ip': P2_TGEN_dict['mcast_grp_ip'],
                           'mcast_grp_ip_step': P2_TGEN_dict['mcast_grp_ip_step'],
                           'no_of_grps': P2_TGEN_dict['no_of_grps'],
                           'mcast_src_ip': P1_TGEN_dict['v4_addr'],
                           'mcast_src_ip_step': P2_TGEN_dict['v4_addr_step'],
                           'mcast_src_ip_step_per_port': P2_TGEN_dict['v4_addr_step'],
                           'mcast_grp_ip_step_per_port': P2_TGEN_dict['v4_addr_step'],
                           'mcast_no_of_srcs': P2_TGEN_dict['no_of_mcast_sources'],
                           'topology_handle': IX_TP2['topo_hndl']
                           }

            IGMP_EML = ixLib.emulate_igmp_groupHost(IGMP_dict_1)

            if IGMP_EML == 0:
                log.debug("Configuring IGMP failed")
                self.errored("Configuring IGMP failed")
            else:
                log.info("Configured IGMP Successfully")

            testscript.parameters['IX_TP2']['igmpHost_handle'] = []
            testscript.parameters['IX_TP2']['igmp_group_handle'] = []
            testscript.parameters['IX_TP2']['igmp_source_handle'] = []
            testscript.parameters['IX_TP2']['igmpMcastGrpList'] = []

            testscript.parameters['IX_TP2']['igmpHost_handle'].append(IGMP_EML['igmpHost_handle'])
            testscript.parameters['IX_TP2']['igmp_group_handle'].append(IGMP_EML['igmp_group_handle'])
            testscript.parameters['IX_TP2']['igmp_source_handle'].append(IGMP_EML['igmp_source_handle'])
            testscript.parameters['IX_TP2']['igmpMcastGrpList'].append(IGMP_EML['igmpMcastGrpList'])

        else:
            self.skipped(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def START_IXIA_PROTOCOLS(self):
        """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

        # _result_ = ixiahlt.test_control(action='configure_all')
        # print(_result_)
        proto_result = ixLib.start_protocols()
        if proto_result == 0:
            log.debug("Starting Protocols failed")
            self.errored("Starting Protocols failed")
        else:
            log.info("Started Protocols Successfully")

        time.sleep(60)

        proto_result = ixLib.stop_protocols()
        if proto_result == 0:
            log.debug("Stopped Protocols failed")
            self.errored("Stopped Protocols failed")
        else:
            log.info("Stopped Protocols Successfully")

        time.sleep(30)

        proto_result = ixLib.start_protocols()
        if proto_result == 0:
            log.debug("Starting Protocols failed")
            self.errored("Starting Protocols failed")
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

            UCAST_v4_dict = {'src_hndl': IX_TP1['ipv4_handle'],
                             'dst_hndl': IX_TP2['ipv4_handle'],
                             'circuit': 'ipv4',
                             'TI_name': "UCAST_V4",
                             'rate_pps': "1000",
                             'bi_dir': 1
                             }

            UCAST_v6_dict = {'src_hndl': IX_TP1['ipv6_handle'],
                             'dst_hndl': IX_TP2['ipv6_handle'],
                             'circuit': 'ipv6',
                             'TI_name': "UCAST_V6",
                             'rate_pps': "1000",
                             'bi_dir': 1
                             }

            UCAST_v4_TI = ixLib.configure_ixia_traffic_item(UCAST_v4_dict)
            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)

            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
                log.debug("Configuring UCast TI failed")
                self.errored("Configuring UCast TI failed")

        else:
            self.skipped(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_BCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']

            BCAST_v4_dict = {
                'src_hndl': IX_TP1['port_handle'],
                'dst_hndl': IX_TP2['port_handle'],
                'TI_name': "BCAST_V4",
                'frame_size': "70",
                'rate_pps': "1000",
                'src_mac': "00:00:25:00:00:01",
                'srcmac_step': "00:00:00:00:00:01",
                'srcmac_count': "50",
                'vlan_id': str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                'vlanid_step': "1",
                'vlanid_count': "50",
                'ip_src_addrs': "9.1.1.10",
                'ip_step': "0.0.1.0",
            }

            BCAST_v4_TI = ixLib.configure_ixia_BCAST_traffic_item(BCAST_v4_dict)

            if BCAST_v4_TI == 0:
                log.debug("Configuring BCast TI failed")
                self.errored("Configuring BCast TI failed")

        else:
            self.skipped(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_UNKNOWN_UCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']

            UNKNOWN_UCAST_v4_dict = {
                'src_hndl': IX_TP1['port_handle'],
                'dst_hndl': IX_TP2['port_handle'],
                'TI_name': "UKNOWN_UCAST_V4",
                'frame_size': "64",
                'rate_pps': "1000",
                'dst_mac': "00:00:29:00:00:01",
                'dstmac_step': "00:00:00:00:00:01",
                'dstmac_count': "50",
                'src_mac': "00:00:28:00:00:01",
                'srcmac_step': "00:00:00:00:00:01",
                'srcmac_count': "50",
                'vlan_id': str(testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']),
                'vlanid_step': "1",
                'vlanid_count': "50",
            }

            UNKNOWN_UCAST_v4_TI = ixLib.configure_ixia_UNKNOWN_UCAST_traffic_item(UNKNOWN_UCAST_v4_dict)

            if UNKNOWN_UCAST_v4_TI == 0:
                log.debug("Configuring UNKNOWN_UCAST TI failed")
                self.errored("Configuring UNKNOWN_UCAST TI failed")

        else:
            self.skipped(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_MCAST_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']

            # Creating TAGs for SRC IP Handles
            TAG_dict = {'subject_handle': IX_TP1['ipv4_handle'],
                        'topo_handle': IX_TP1['topo_hndl'],
                        'TAG_count_per_item': 50
                        }

            SRC_IP_TAG = ixLib.configure_tag_config_multiplier(TAG_dict)
            if SRC_IP_TAG == 0:
                log.debug("Configuring TAGS for SRC IP failed")

            # Creating TAGs for DST IP Handles
            TAG_dict = {'subject_handle': IX_TP2['ipv4_handle'],
                        'topo_handle': IX_TP2['topo_hndl'],
                        'TAG_count_per_item': 50
                        }

            DST_IP_TAG = ixLib.configure_tag_config_multiplier(TAG_dict)
            if DST_IP_TAG == 0:
                log.debug("Configuring TAGS for DST IP failed")

            # Creating TAGs for IGMP Host Handles
            TAG_dict = {'subject_handle': IX_TP2['igmp_group_handle'],
                        'topo_handle': IX_TP2['topo_hndl'],
                        'TAG_count_per_item': 50
                        }

            IGMP_Host_TAG = ixLib.configure_tag_config_multiplier(TAG_dict)
            if IGMP_Host_TAG == 0:
                log.debug("Configuring TAGS for IGMP Hosts failed")

            MCAST_dict = {'src_ipv4_topo_handle': IX_TP1['topo_hndl'],
                          'total_tags': 50,
                          'TI_name': "M_cast",
                          'rate_pps': "1000",
                          'frame_size': "70",
                          }

            MCAST_TI = ixLib.configure_v4_mcast_traffic_item_per_tag(MCAST_dict)

            if MCAST_TI == 0:
                log.debug("Configuring MCast TI failed")
                self.errored("Configuring MCast TI failed")

        else:
            self.skipped(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2, 3) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed")
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")


# *****************************************************************************************************************************#
class TRM_MCAST_VERIFICATION(aetest.Testcase):
    """ TRM_MCAST_VERIFICATION """

    # =============================================================================================================================#
    @aetest.test
    def verify_mcast_group_entry(self, testscript):
        """ TRM_MCAST_VERIFICATION subsection: Verify MCast Group Entry """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        LEAF_3_TGEN_data = testscript.parameters['LEAF_3_TGEN_dict']
        fail_flag = []
        fail_msgs = ""

        # ----------------------------------------------------
        # LEAF-1 Counter Variables
        # ----------------------------------------------------
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0
        mcast_grp_ip = ip.IPv4Interface(LEAF_3_TGEN_data['mcast_grp_ip']).ip
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']

        # ----------------------------------------------------
        # Verify IGMP Snooping Groups on LEAF-2
        # ---------------------------------------------------
        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:

                mcast_grp_output = LEAF_1.execute(
                    "sh ip igmp snoop groups vlan " + str(l2_vlan_id) + " | i i " + str(mcast_grp_ip) + " | i i nve1")
                if (str(l2_vlan_id) in mcast_grp_output) and (str(mcast_grp_ip) in mcast_grp_output) and (
                        "nve1" in mcast_grp_output):
                    pass
                else:
                    fail_flag.append(0)
                    fail_msgs += "IP IGMP Snooping Groups " + str(mcast_grp_ip) + " is not created for " + str(
                        l2_vlan_id) + " in " + str(LEAF_1.alias) + "\n"

                l2_vlan_count_iter += 1
                l2_vlan_id += 1
                mcast_grp_ip += 256
            l3_vrf_count_iter += 1
            l2_vlan_count_iter = 0

        # ----------------------------------------------------
        # LEAF-2 Counter Variables
        # ----------------------------------------------------
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0
        mcast_grp_ip = ip.IPv4Interface(LEAF_3_TGEN_data['mcast_grp_ip']).ip
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']

        # ----------------------------------------------------
        # Verify IGMP Snooping Groups on LEAF-2
        # ---------------------------------------------------
        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:

                mcast_grp_output = LEAF_2.execute(
                    "sh ip igmp snoop groups vlan " + str(l2_vlan_id) + " | i i " + str(mcast_grp_ip) + " | i i nve1")
                if (str(l2_vlan_id) in mcast_grp_output) and (str(mcast_grp_ip) in mcast_grp_output) and (
                        "nve1" in mcast_grp_output):
                    pass
                else:
                    fail_flag.append(0)
                    fail_msgs += "IP IGMP Snooping Groups " + str(mcast_grp_ip) + " is not created for " + str(
                        l2_vlan_id) + " in " + str(LEAF_2.alias) + "\n"

                l2_vlan_count_iter += 1
                l2_vlan_id += 1
                mcast_grp_ip += 256
            l3_vrf_count_iter += 1
            l2_vlan_count_iter = 0

        # ----------------------------------------------------
        # LEAF-3 Counter Variables
        # ----------------------------------------------------
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0
        mcast_grp_ip = ip.IPv4Interface(LEAF_3_TGEN_data['mcast_grp_ip']).ip
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']

        # ----------------------------------------------------
        # Verify IGMP Snooping Groups on LEAF-3
        # ---------------------------------------------------
        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:

                mcast_grp_output = LEAF_3.execute("sh ip igmp snoop groups vlan " + str(l2_vlan_id) + " | i i " + str(
                    mcast_grp_ip) + " | i i Po" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']))
                if (str(l2_vlan_id) in mcast_grp_output) and (str(mcast_grp_ip) in mcast_grp_output) and (
                        "Po" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) in mcast_grp_output):
                    pass
                else:
                    fail_flag.append(0)
                    fail_msgs += "IP IGMP Snooping Groups " + str(mcast_grp_ip) + " is not created for " + str(
                        l2_vlan_id) + " in " + str(LEAF_3.alias) + "\n"

                l2_vlan_count_iter += 1
                l2_vlan_id += 1
                mcast_grp_ip += 256
            l3_vrf_count_iter += 1
            l2_vlan_count_iter = 0

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#

    @aetest.test
    def verify_mcast_group_entry_leave(self, testscript):
        """ TRM_MCAST_VERIFICATION subsection: Verify MCast Group Entry Leave """

        LEAF_3 = testscript.parameters['LEAF-3']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        LEAF_3_TGEN_data = testscript.parameters['LEAF_3_TGEN_dict']
        fail_flag = []
        fail_msgs = ""

        ixLib.stop_protocols()
        time.sleep(60)

        # ----------------------------------------------------
        # LEAF-3 Counter Variables
        # ----------------------------------------------------
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0
        mcast_grp_ip = ip.IPv4Interface(LEAF_3_TGEN_data['mcast_grp_ip']).ip
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']

        # ----------------------------------------------------
        # Verify IGMP Snooping Groups on LEAF-3
        # ---------------------------------------------------
        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:

                mcast_grp_output = LEAF_3.execute("sh ip igmp snoop groups vlan " + str(l2_vlan_id) + " | i i " + str(
                    mcast_grp_ip) + " | i i Po" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']))
                if (str(l2_vlan_id) in mcast_grp_output) and (str(mcast_grp_ip) in mcast_grp_output) and (
                        "Po" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) in mcast_grp_output):
                    fail_flag.append(0)
                    fail_msgs += "IP IGMP Snooping Groups " + str(mcast_grp_ip) + " is still present for " + str(
                        l2_vlan_id) + " in " + str(LEAF_3.alias) + "\n"

                l2_vlan_count_iter += 1
                l2_vlan_id += 1
                mcast_grp_ip += 256
            l3_vrf_count_iter += 1
            l2_vlan_count_iter = 0

        ixLib.start_protocols()
        time.sleep(60)

        # ----------------------------------------------------
        # LEAF-3 Counter Variables
        # ----------------------------------------------------
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0
        mcast_grp_ip = ip.IPv4Interface(LEAF_3_TGEN_data['mcast_grp_ip']).ip
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']

        # ----------------------------------------------------
        # Verify IGMP Snooping Groups on LEAF-3
        # ---------------------------------------------------
        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:

                mcast_grp_output = LEAF_3.execute("sh ip igmp snoop groups vlan " + str(l2_vlan_id) + " | i i " + str(
                    mcast_grp_ip) + " | i i Po" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']))
                if (str(l2_vlan_id) in mcast_grp_output) and (str(mcast_grp_ip) in mcast_grp_output) and (
                        "Po" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) in mcast_grp_output):
                    pass
                else:
                    fail_flag.append(0)
                    fail_msgs += "IP IGMP Snooping Groups " + str(mcast_grp_ip) + " is not created for " + str(
                        l2_vlan_id) + " in " + str(LEAF_3.alias) + "\n"

                l2_vlan_count_iter += 1
                l2_vlan_id += 1
                mcast_grp_ip += 256
            l3_vrf_count_iter += 1
            l2_vlan_count_iter = 0

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        time.sleep(20)

        if ixLib.verify_traffic(2, 3) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class L2_DISRUPTIVE_verify_L2_VLAN_shut_no_shut(aetest.Testcase):
    """ L2_DISRUPTIVE_VERIFICATION """

    # =============================================================================================================================#
    @aetest.test
    def verify_L2_VLAN_shut_no_shut(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify L2 VLAN shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        forwardingSysDict = testscript.parameters['forwardingSysDict']

        fail_flag = []
        fail_msgs = ""

        # ----------------------------------------------------
        # Counter Variables
        # ----------------------------------------------------
        vlan_id_start = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        total_vlans = int(forwardingSysDict['VRF_count']) * int(forwardingSysDict['VLAN_PER_VRF_count'])
        vlan_id_stop = int(vlan_id_start) + total_vlans

        # ----------------------------------------------------
        # Perform VLAN shut on LEAF-1 and LEAF-2
        # ---------------------------------------------------

        LEAF_1.configure('''
                      vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                      shut
                      ''')

        LEAF_2.configure('''
                      vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                      shut
                      ''')

        time.sleep(30)

        # ----------------------------------------------------
        # Counter Variables
        # ----------------------------------------------------
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0

        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:

                LEAF_1_l2vlan_out = LEAF_1.execute("sh int vlan " + str(l2_vlan_id) + " brief | xml | i i 'state>'")
                LEAF_2_l2vlan_out = LEAF_2.execute("sh int vlan " + str(l2_vlan_id) + " brief | xml | i i 'state>'")

                if (">down<" in LEAF_1_l2vlan_out) and (">down<" in LEAF_2_l2vlan_out):
                    log.info("LEAF-1 and LEAF-2 L2 VLAN is DOWN after shut/no-shut")
                else:
                    # fail_flag.append(0)
                    fail_msgs += "LEAF-1 and LEAF-2 L2 VLAN " + str(l2_vlan_id) + " is not DOWN after shut/no-shut\n"

                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            l2_vlan_count_iter = 0
            l3_vrf_count_iter += 1

        # ----------------------------------------------------
        # Perform VLAN no shut on LEAF-1 and LEAF-2
        # ---------------------------------------------------

        LEAF_1.configure('''
                      vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                      no shut
                      ''')

        LEAF_2.configure('''
                      vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                      no shut
                      ''')

        time.sleep(60)

        # ----------------------------------------------------
        # Counter Variables
        # ----------------------------------------------------
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0

        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:

                LEAF_1_l2vlan_out = LEAF_1.execute("sh int vlan " + str(l2_vlan_id) + " brief | xml | i i 'state>'")
                LEAF_2_l2vlan_out = LEAF_2.execute("sh int vlan " + str(l2_vlan_id) + " brief | xml | i i 'state>'")

                if (">up<" in LEAF_1_l2vlan_out) and (">up<" in LEAF_2_l2vlan_out):
                    log.info("LEAF-1 and LEAF-2 L2 VLAN is UP after shut/no-shut")
                else:
                    fail_flag.append(0)
                    fail_msgs += "LEAF-1 and LEAF-2 L2 VLAN " + str(l2_vlan_id) + " is not UP after shut/no-shut\n"

                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            l2_vlan_count_iter = 0
            l3_vrf_count_iter += 1

        time.sleep(30)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed")

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Send traffic to populate stats # work-around
        ixLib.start_traffic()
        time.sleep(60)
        ixLib.stop_traffic()
        time.sleep(60)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class L2_DISRUPTIVE_verify_L2_VLAN_suspend_resume(aetest.Testcase):
    """ L2_DISRUPTIVE_VERIFICATION """

    # =============================================================================================================================#
    @aetest.test
    def verify_L2_VLAN_suspend_resume(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify L2 VLAN suspend and resume """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        forwardingSysDict = testscript.parameters['forwardingSysDict']

        fail_flag = []
        fail_msgs = ""

        # ----------------------------------------------------
        # Counter Variables
        # ----------------------------------------------------
        vlan_id_start = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        total_vlans = int(forwardingSysDict['VRF_count']) * int(forwardingSysDict['VLAN_PER_VRF_count'])
        vlan_id_stop = int(vlan_id_start) + total_vlans

        # ----------------------------------------------------
        # Perform VLAN shut on LEAF-1 and LEAF-2
        # ---------------------------------------------------

        LEAF_1.configure('''
                      vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                      state suspend
                      ''')

        LEAF_2.configure('''
                      vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                      state suspend
                      ''')

        time.sleep(30)

        LEAF_1.configure('''
                      vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                      no state suspend
                      ''')

        LEAF_2.configure('''
                      vlan ''' + str(vlan_id_start) + '''-''' + str(vlan_id_stop) + '''
                      no state suspend
                      ''')

        time.sleep(60)

        # ----------------------------------------------------
        # Counter Variables
        # ----------------------------------------------------
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0

        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:

                LEAF_1_l2vlan_out = LEAF_1.execute("sh int vlan " + str(l2_vlan_id) + " brief | xml | i i 'state>'")
                LEAF_2_l2vlan_out = LEAF_2.execute("sh int vlan " + str(l2_vlan_id) + " brief | xml | i i 'state>'")

                if (">up<" in LEAF_1_l2vlan_out) and (">up<" in LEAF_2_l2vlan_out):
                    log.info("LEAF-1 and LEAF-2 L2 VLAN is UP after shut/no-shut")
                else:
                    fail_flag.append(0)
                    fail_msgs += "LEAF-1 and LEAF-2 L2 VLAN " + str(l2_vlan_id) + " is not UP after shut/no-shut \n"

                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            l2_vlan_count_iter = 0
            l3_vrf_count_iter += 1

        time.sleep(60)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Send traffic to populate stats # work-around
        ixLib.start_traffic()
        time.sleep(60)
        ixLib.stop_traffic()
        time.sleep(60)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class L2_DISRUPTIVE_verify_VPC_PO_shut_no_shut(aetest.Testcase):
    """ L2_DISRUPTIVE_VERIFICATION """

    # =============================================================================================================================#
    @aetest.test
    def verify_VPC_PO_shut_no_shut(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC PO shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        vpc_po_num = testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']

        fail_flag = []
        fail_msgs = ""

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Perform flap
        LEAF_1.configure('''
                      interface po''' + str(vpc_po_num) + '''
                      shut
                      no shut
                      ''')

        LEAF_2.configure('''
                      interface po''' + str(vpc_po_num) + '''
                      shut
                      no shut
                      ''')

        time.sleep(240)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the state
        LEAF_1_VPC_PO_out = LEAF_1.execute("sh int po" + str(vpc_po_num) + " brief | xml | i i 'state>'")
        LEAF_2_VPC_PO_out = LEAF_2.execute("sh int po" + str(vpc_po_num) + " brief | xml | i i 'state>'")

        if ">up<" in LEAF_1_VPC_PO_out:
            log.info("LEAF-1 VPC PO is UP after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "LEAF-1 VPC PO is not UP after shut/no-shut\n"

        if ">up<" in LEAF_2_VPC_PO_out:
            log.info("LEAF-2 VPC PO is UP after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "LEAF-2 VPC PO is not UP after shut/no-shut\n"

        time.sleep(120)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_vpc_post_VPC_PO_shut_no_shut(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC post VPC PO shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify VPC
        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info(
                "PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            self.failed("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")

        time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic_post_VPC_PO_shut_no_shut(self):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify Traffic post VPC PO shut/no-shut """

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Send traffic to populate stats # work-around
        ixLib.start_traffic()
        time.sleep(60)
        ixLib.stop_traffic()
        time.sleep(60)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class L2_DISRUPTIVE_verify_VPC_peer_link_shut_no_shut(aetest.Testcase):
    """ L2_DISRUPTIVE_VERIFICATION """

    # =============================================================================================================================#
    @aetest.test
    def verify_VPC_peer_link_shut_no_shut(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC Peer-Link shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        peer_link_po_num = testscript.parameters['LEAF_1_dict']['VPC_data']['peer_link_po']

        fail_flag = []
        fail_msgs = ""

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Perform Flap
        LEAF_1.configure('''
                      interface po''' + str(peer_link_po_num) + '''
                      shut
                      no shut
                      ''')

        time.sleep(120)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the state
        LEAF_1_VPC_PL_out = LEAF_1.execute("sh int po" + str(peer_link_po_num) + " brief | xml | i i 'state>'")
        LEAF_2_VPC_PL_out = LEAF_2.execute("sh int po" + str(peer_link_po_num) + " brief | xml | i i 'state>'")

        if ">up<" in LEAF_1_VPC_PL_out:
            log.info("LEAF-1 VPC Peer-Link is UP after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "LEAF-1 VPC Peer-Link is not UP after shut/no-shut\n"

        if ">up<" in LEAF_2_VPC_PL_out:
            log.info("LEAF-2 VPC Peer-Link is UP after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "LEAF-2 VPC Peer-Link is not UP after shut/no-shut\n"

        time.sleep(20)

    # =============================================================================================================================#
    @aetest.test
    def verify_vpc_post_VPC_peer_link_shut_no_shut(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC post VPC Peer-Link shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify VPC
        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info(
                "PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            self.failed("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic_post_VPC_peer_link_shut_no_shut(self):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify Traffic post VPC Peer-Link shut/no-shut """

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class L2_DISRUPTIVE_verify_VPC_domain_shut_no_shut(aetest.Testcase):
    """ L2_DISRUPTIVE_VERIFICATION """

    # =============================================================================================================================#
    @aetest.test
    def verify_VPC_domain_shut_no_shut(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC domain shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        fail_flag = []
        fail_msgs = ""

        peer_link_po_num = testscript.parameters['LEAF_1_dict']['VPC_data']['domain_id']
        vpc_po_num = testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Perform Flap
        LEAF_1.configure('''
                      vpc domain ''' + str(peer_link_po_num) + '''
                      shut
                      no shut
                      ''')

        LEAF_2.configure('''
                      vpc domain ''' + str(peer_link_po_num) + '''
                      shut
                      no shut
                      ''')

        time.sleep(120)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the state
        LEAF_1_VPC_PO_out = LEAF_1.execute("sh int po" + str(vpc_po_num) + " brief | xml | i i 'state>'")
        LEAF_2_VPC_PO_out = LEAF_2.execute("sh int po" + str(vpc_po_num) + " brief | xml | i i 'state>'")

        if ">up<" in LEAF_1_VPC_PO_out:
            log.info("LEAF-1 VPC PO is UP after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "LEAF-1 VPC PO is not UP after shut/no-shut\n"

        if ">up<" in LEAF_2_VPC_PO_out:
            log.info("LEAF-2 VPC PO is UP after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "LEAF-2 VPC PO is not UP after shut/no-shut\n"

        time.sleep(30)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_vpc_post_VPC_domain_shut_no_shut(self, testscript):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify VPC post VPC domain shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify VPC
        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)

        if VPCStatus['result']:
            log.info(VPCStatus['log'])
            log.info(
                "PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Successfully Verified\n\n")
        else:
            log.info(VPCStatus['log'])
            self.failed("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")

        time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic_post_VPC_domain_shut_no_shut(self):
        """ L2_DISRUPTIVE_VERIFICATION subsection: Verify Traffic post VPC domain shut/no-shut """

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Send traffic to populate stats # work-around
        ixLib.start_traffic()
        time.sleep(60)
        ixLib.stop_traffic()
        time.sleep(60)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class VXLAN_DISRUPTIVE_verify_change_vni_mcast_grp(aetest.Testcase):
    """ VXLAN_DISRUPTIVE_VERIFICATION """

    # =============================================================================================================================#
    @aetest.test
    def verify_change_vni_mcast_grp(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify change in VNI MCast group """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        l2_vni_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']
        l2_mcast_grp_ip = ip.IPv4Interface(testscript.parameters['LEAF_1_dict']['NVE_data']['l2_mcast_grp_ip'])

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Restart BGP
        LEAF_1.configure("""
                        interface nve1
                        shut
                          member vni """ + str(l2_vni_id) + """
                            no mcast-group
                            mcast-group """ + str((l2_mcast_grp_ip + 100).ip) + """
                        no shut
                         """)

        LEAF_2.configure("""
                        interface nve1
                        shut
                          member vni """ + str(l2_vni_id) + """
                            no mcast-group
                            mcast-group """ + str((l2_mcast_grp_ip + 100).ip) + """
                        no shut
                         """)

        LEAF_3.configure("""
                        interface nve1
                        shut
                          member vni """ + str(l2_vni_id) + """
                            no mcast-group
                            mcast-group """ + str((l2_mcast_grp_ip + 100).ip) + """
                        no shut
                         """)
        time.sleep(45)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic_post_change_vni_mcast_grp(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.test
    def verify_revert_vni_mcast_grp(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify change in VNI MCast group """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        l2_vni_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']
        l2_mcast_grp_ip = ip.IPv4Interface(testscript.parameters['LEAF_1_dict']['NVE_data']['l2_mcast_grp_ip'])

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Restart BGP
        LEAF_1.configure("""
                        interface nve1
                        shut
                          member vni """ + str(l2_vni_id) + """
                            no mcast-group
                            mcast-group """ + str(l2_mcast_grp_ip.ip) + """
                        no shut
                         """)

        LEAF_2.configure("""
                        interface nve1
                        shut
                          member vni """ + str(l2_vni_id) + """
                            no mcast-group
                            mcast-group """ + str(l2_mcast_grp_ip.ip) + """
                        no shut
                         """)

        LEAF_3.configure("""
                        interface nve1
                        shut
                          member vni """ + str(l2_vni_id) + """
                            no mcast-group
                            mcast-group """ + str(l2_mcast_grp_ip.ip) + """
                        no shut
                         """)
        time.sleep(45)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic_post_revert_vni_mcast_grp(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class VXLAN_DISRUPTIVE_verify_change_vni_vlan_map(aetest.Testcase):
    """ VXLAN_DISRUPTIVE_VERIFICATION """

    # =============================================================================================================================#
    @aetest.test
    def verify_change_vni_vlan_map(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify Changing VLAN to VNI mapping (remove and re-add) """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        fail_flag = []
        fail_msgs = ""

        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vni_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Restart BGP
        LEAF_1.configure("""
                        vlan """ + str(l2_vlan_id) + """
                          no vn-segment
                          vn-segment """ + str(int(l2_vni_id) + 500) + """
                        shut
                        no shut

                        interface nve 1
                        shut
                          member vni """ + str(int(l2_vni_id) + 500) + """
                            mcast-group 224.1.1.101
                        no shut

                        evpn
                            vni """ + str(int(l2_vni_id) + 500) + """ l2
                              rd auto
                              route-target import auto
                              route-target export auto
                         """)

        LEAF_2.configure("""
                        vlan """ + str(l2_vlan_id) + """
                          no vn-segment
                          vn-segment """ + str(int(l2_vni_id) + 500) + """
                        shut
                        no shut

                        interface nve 1
                        shut
                          member vni """ + str(int(l2_vni_id) + 500) + """
                            mcast-group 224.1.1.101
                        no shut

                        evpn
                            vni """ + str(int(l2_vni_id) + 500) + """ l2
                              rd auto
                              route-target import auto
                              route-target export auto
                         """)

        LEAF_3.configure("""
                        vlan """ + str(l2_vlan_id) + """
                          no vn-segment
                          vn-segment """ + str(int(l2_vni_id) + 500) + """
                        shut
                        no shut

                        interface nve 1
                        shut
                          member vni """ + str(int(l2_vni_id) + 500) + """
                            mcast-group 224.1.1.101
                        no shut

                        evpn
                            vni """ + str(int(l2_vni_id) + 500) + """ l2
                              rd auto
                              route-target import auto
                              route-target export auto
                         """)
        time.sleep(60)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the state
        LEAF_1_nve_out = LEAF_1.execute("sh int nve 1 brief | xml | i i state>")
        LEAF_2_nve_out = LEAF_2.execute("sh int nve 1 brief | xml | i i state>")
        LEAF_3_nve_out = LEAF_3.execute("sh int nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_1_nve_out:
            log.info("NVE INT is UP on LEAF-1 after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP on LEAF-1 after change vni vlan map\n"

        if ">up<" in LEAF_2_nve_out:
            log.info("NVE INT is UP on LEAF-2 after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP on LEAF-2 after change vni vlan map\n"

        if ">up<" in LEAF_3_nve_out:
            log.info("NVE INT is UP on LEAF-3 after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP on LEAF-3 after change vni vlan map\n"

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the state
        LEAF_1_l2vlan_out = LEAF_1.execute("sh int vlan " + str(l2_vlan_id) + " brief | xml | i i 'state>'")
        LEAF_2_l2vlan_out = LEAF_2.execute("sh int vlan " + str(l2_vlan_id) + " brief | xml | i i 'state>'")
        LEAF_3_l2vlan_out = LEAF_3.execute("sh int vlan " + str(l2_vlan_id) + " brief | xml | i i 'state>'")

        if ">up<" in LEAF_1_l2vlan_out:
            log.info("LEAF-1 L2 VLAN is UP on LEAF-1 after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "LEAF-1 L2 VLAN is not UP after change vni vlan map\n"

        if ">up<" in LEAF_2_l2vlan_out:
            log.info("LEAF-2 L2 VLAN is UP on LEAF-2 after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "LEAF-2 L2 VLAN is not UP after change vni vlan map\n"

        if ">up<" in LEAF_3_l2vlan_out:
            log.info("LEAF-3 L2 VLAN is UP on LEAF-3 after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "LEAF-3 L2 VLAN is not UP after change vni vlan map\n"

        time.sleep(10)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic_post_change_vni_vlan_map(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.test
    def verify_revert_vni_vlan_map(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify Changing VLAN to VNI mapping (remove and re-add) """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        fail_flag = []
        fail_msgs = ""

        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vni_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vni_start']
        l2_mcast_grp_ip = ip.IPv4Interface(testscript.parameters['LEAF_1_dict']['NVE_data']['l2_mcast_grp_ip'])

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Restart BGP
        LEAF_1.configure("""
                        vlan """ + str(l2_vlan_id) + """
                          no vn-segment
                          vn-segment """ + str(int(l2_vni_id)) + """
                        shut
                        no shut

                        interface nve 1
                        shut
                          no member vni """ + str(int(l2_vni_id) + 500) + """
                          member vni """ + str(l2_vni_id) + """
                            mcast-group """ + str(l2_mcast_grp_ip.ip) + """
                        no shut

                        evpn
                            no vni """ + str(int(l2_vni_id) + 500) + """ l2
                            vni """ + str(l2_vni_id) + """ l2
                              rd auto
                              route-target import auto
                              route-target export auto
                         """)

        LEAF_2.configure("""
                        vlan """ + str(l2_vlan_id) + """
                          no vn-segment
                          vn-segment """ + str(int(l2_vni_id)) + """
                        shut
                        no shut

                        interface nve 1
                        shut
                          no member vni """ + str(int(l2_vni_id) + 500) + """
                          member vni """ + str(l2_vni_id) + """
                            mcast-group """ + str(l2_mcast_grp_ip.ip) + """
                        no shut

                        evpn
                            no vni """ + str(int(l2_vni_id) + 500) + """ l2
                            vni """ + str(l2_vni_id) + """ l2
                              rd auto
                              route-target import auto
                              route-target export auto
                         """)

        LEAF_3.configure("""
                        vlan """ + str(l2_vlan_id) + """
                          no vn-segment
                          vn-segment """ + str(int(l2_vni_id)) + """
                        shut
                        no shut

                        interface nve 1
                        shut
                          no member vni """ + str(int(l2_vni_id) + 500) + """
                          member vni """ + str(l2_vni_id) + """
                            mcast-group """ + str(l2_mcast_grp_ip.ip) + """
                        no shut

                        evpn
                            no vni """ + str(int(l2_vni_id) + 500) + """ l2
                            vni """ + str(l2_vni_id) + """ l2
                              rd auto
                              route-target import auto
                              route-target export auto
                         """)
        time.sleep(60)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the state
        LEAF_1_nve_out = LEAF_1.execute("sh int nve 1 brief | xml | i i state>")
        LEAF_2_nve_out = LEAF_2.execute("sh int nve 1 brief | xml | i i state>")
        LEAF_3_nve_out = LEAF_3.execute("sh int nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_1_nve_out:
            log.info("NVE INT is UP on LEAF-1 after revert vni vlan map")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP on LEAF-1 after revert vni vlan map\n"

        if ">up<" in LEAF_2_nve_out:
            log.info("NVE INT is UP on LEAF-2 after revert vni vlan map")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP on LEAF-2 after revert vni vlan map\n"

        if ">up<" in LEAF_3_nve_out:
            log.info("NVE INT is UP on LEAF-3 after revert vni vlan map")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP on LEAF-3 after revert vni vlan map\n"

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the state
        LEAF_1_l2vlan_out = LEAF_1.execute("sh int vlan " + str(l2_vlan_id) + " brief | xml | i i 'state>'")
        LEAF_2_l2vlan_out = LEAF_2.execute("sh int vlan " + str(l2_vlan_id) + " brief | xml | i i 'state>'")
        LEAF_3_l2vlan_out = LEAF_3.execute("sh int vlan " + str(l2_vlan_id) + " brief | xml | i i 'state>'")

        if ">up<" in LEAF_1_l2vlan_out:
            log.info("LEAF-1 L2 VLAN is UP on LEAF-1 after revert vni vlan map")
        else:
            fail_flag.append(0)
            fail_msgs += "LEAF-1 L2 VLAN is not UP after revert vni vlan map\n"

        if ">up<" in LEAF_2_l2vlan_out:
            log.info("LEAF-2 L2 VLAN is UP on LEAF-1 after revert vni vlan map")
        else:
            fail_flag.append(0)
            fail_msgs += "LEAF-2 L2 VLAN is not UP after revert vni vlan map\n"

        if ">up<" in LEAF_3_l2vlan_out:
            log.info("LEAF-3 L2 VLAN is UP on LEAF-1 after revert vni vlan map")
        else:
            fail_flag.append(0)
            fail_msgs += "LEAF-3 L2 VLAN is not UP after revert vni vlan map\n"

        time.sleep(60)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic_post_revert_vni_vlan_map(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class VXLAN_DISRUPTIVE_verify_NVE_INT_shut_no_shut(aetest.Testcase):
    """ VXLAN_DISRUPTIVE_VERIFICATION """

    # =============================================================================================================================#
    @aetest.test
    def verify_NVE_INT_shut_no_shut(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify NVE Interface shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        fail_flag = []
        fail_msgs = ""

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Perform Flap
        LEAF_1.configure('''
                      interface nve 1
                      shut
                      no shut
                      ''')

        LEAF_2.configure('''
                      interface nve 1
                      shut
                      no shut
                      ''')

        time.sleep(120)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the state
        LEAF_1_nve_out = LEAF_1.execute("sh int nve 1 brief | xml | i i state>")
        LEAF_2_nve_out = LEAF_2.execute("sh int nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_1_nve_out:
            log.info("NVE INT is UP on LEAF-1 after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP on LEAF-1 after shut/no-shut"

        if ">up<" in LEAF_2_nve_out:
            log.info("NVE INT is UP on LEAF-2 after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP on LEAF-2 after shut/no-shut"

        time.sleep(60)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class VXLAN_DISRUPTIVE_verify_restart_bgp(aetest.Testcase):
    """ VXLAN_DISRUPTIVE_VERIFICATION """

    # =============================================================================================================================#
    @aetest.test
    def verify_restart_bgp(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify Restart BGP """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        forwardingSysDict = testscript.parameters['forwardingSysDict']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Restart BGP
        LEAF_1.configure('restart bgp ' + str(forwardingSysDict['BGP_AS_num']))
        LEAF_2.configure('restart bgp ' + str(forwardingSysDict['BGP_AS_num']))

        time.sleep(60)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class VXLAN_DISRUPTIVE_verify_uplink_to_SPINE_shut_no_shut(aetest.Testcase):
    """ VXLAN_DISRUPTIVE_VERIFICATION """

    # =============================================================================================================================#
    @aetest.test
    def verify_uplink_to_SPINE_shut_no_shut(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify L2 VLAN SVI shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        fail_flag = []
        fail_msgs = ""

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Perform Flap
        LEAF_1.configure('''
                      interface po''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                      shut
                      no shut
                      ''')

        LEAF_2.configure('''
                      interface po''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                      shut
                      no shut
                      ''')

        LEAF_3.configure('''
                      interface po''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                      shut
                      no shut
                      ''')

        time.sleep(120)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the state
        LEAF_1_uplink_out = LEAF_1.execute("sh int po" + str(
            testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + " brief | xml | i i 'state>'")
        LEAF_2_uplink_out = LEAF_2.execute("sh int po" + str(
            testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + " brief | xml | i i 'state>'")
        LEAF_3_uplink_out = LEAF_3.execute("sh int po" + str(
            testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + " brief | xml | i i 'state>'")

        if ">up<" in LEAF_1_uplink_out:
            log.info("LEAF-1 Uplink is UP after SPINE uplink shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "LEAF-1 Uplink is not UP after SPINE uplink shut/no-shut\n"

        if ">up<" in LEAF_2_uplink_out:
            log.info("LEAF-2 Uplink is UP after SPINE uplink shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "LEAF-2 Uplink is not UP after SPINE uplink shut/no-shut\n"

        if ">up<" in LEAF_3_uplink_out:
            log.info("LEAF-3 Uplink is UP after SPINE uplink shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "LEAF-3 Uplink is not UP after SPINE uplink shut/no-shut\n"

        time.sleep(120)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_BGP_sessions(self, testscript):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify BGP Peering with SPINE
        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict'],
                                                                testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_NVE_peering(self, testscript):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify NVE Peers
        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class VXLAN_DISRUPTIVE_verify_nve_source_int_change(aetest.Testcase):
    """ VXLAN_DISRUPTIVE_VERIFICATION """

    # =============================================================================================================================#
    @aetest.test
    def verify_nve_source_int_change(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify L2 VLAN SVI shut/no-shut """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        fail_flag = []
        fail_msgs = ""

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Create a new loopback
        LEAF_3.configure('''
                        interface loopback10
                          ip address 3.30.30.30/32
                          ip ospf network point-to-point
                          ip router ospf INFRA area 0.0.0.0
                          ip pim sparse-mode
                      ''')

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Change NVE source loopback
        LEAF_3.configure('''
                        interface nve 1
                          shut
                          source-interface loopback 10
                          no shut
                      ''')

        time.sleep(120)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify NVE UP
        LEAF_3_nve_out = LEAF_3.execute("sh int nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_3_nve_out:
            log.info("NVE INT is UP after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP after source change\n"

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify NVE Peers with new IP
        LEAF_1_NVE_data = LEAF_1.execute("sh nve peers peer-ip 3.30.30.30 detail | xml | i i peer-state")
        LEAF_2_NVE_data = LEAF_2.execute("sh nve peers peer-ip 3.30.30.30 detail | xml | i i peer-state")

        if "Up" not in LEAF_1_NVE_data:
            log.info("PASS : Successfully verified NVE Peering for LEAF-1\n\n")
        else:
            fail_flag.append(0)
            fail_msgs += "FAIL : Failed to verify NVE Peering for LEAF-1\n"

        if "Up" not in LEAF_2_NVE_data:
            log.info("PASS : Successfully verified NVE Peering for LEAF-2\n\n")
        else:
            fail_flag.append(0)
            fail_msgs += "FAIL : Failed to verify NVE Peering for LEAF-2\n"

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic_after_change_source(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed(reason="Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")

    # =============================================================================================================================#
    @aetest.test
    def verify_nve_source_int_revert(self, testscript):

        LEAF_3 = testscript.parameters['LEAF-3']

        fail_flag = []
        fail_msgs = ""

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Change NVE source loopback
        LEAF_3.configure('''
                        interface nve 1
                          shut
                          source-interface ''' + str(testscript.parameters['LEAF_3_dict']['NVE_data']['src_loop']) + '''
                          no shut
                      ''')

        time.sleep(120)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify NVE UP
        LEAF_3_nve_out = LEAF_3.execute("sh int nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_3_nve_out:
            log.info("NVE INT is UP after revert source change")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP after revert source change \n"

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify NVE Peers
        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            fail_flag.append(0)
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            fail_msgs += nvePeerData['log'] + "\n"

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic_after_change_source(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed(reason="Traffic Verification Failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class VXLAN_DISRUPTIVE_verify_clear_igmp_snooping_groups_vlan_all(aetest.Testcase):
    """ VXLAN_DISRUPTIVE_VERIFICATION """

    # =============================================================================================================================#
    @aetest.test
    def verify_clear_igmp_snooping_groups_vlan_all(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify Clear IGMP Snooping Groups """

        ixLib.stop_protocols()

        LEAF_3 = testscript.parameters['LEAF-3']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        LEAF_3_TGEN_data = testscript.parameters['LEAF_3_TGEN_dict']

        fail_flag = []
        fail_msgs = ""

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Clear IGMP Snooping groups
        LEAF_3.configure('clear ip igmp snooping groups * vlan all')

        ixLib.start_protocols()
        time.sleep(120)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the igmp groups
        # ----------------------------------------------------
        # LEAF-3 Counter Variables
        # ----------------------------------------------------
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0
        mcast_grp_ip = ip.IPv4Interface(LEAF_3_TGEN_data['mcast_grp_ip']).ip
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']

        # ----------------------------------------------------
        # Verify IGMP Snooping Groups on LEAF-3
        # ---------------------------------------------------
        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:

                mcast_grp_output = LEAF_3.execute("sh ip igmp snoop groups vlan " + str(l2_vlan_id) + " | i i " + str(
                    mcast_grp_ip) + " | i i Po" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']))
                if (str(l2_vlan_id) in mcast_grp_output) and (str(mcast_grp_ip) in mcast_grp_output) and (
                        "Po" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) in mcast_grp_output):
                    pass
                else:
                    fail_flag.append(0)
                    fail_msgs += "IP IGMP Snooping Groups " + str(mcast_grp_ip) + " is not created for " + str(
                        l2_vlan_id) + " in " + str(LEAF_3.alias) + "\n"

                l2_vlan_count_iter += 1
                l2_vlan_id += 1
                mcast_grp_ip += 256
            l3_vrf_count_iter += 1
            l2_vlan_count_iter = 0

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed(reason="Traffic Verification Failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class VXLAN_DISRUPTIVE_verify_clear_ip_route_mroute_all(aetest.Testcase):
    """ VXLAN_DISRUPTIVE_VERIFICATION """

    # =============================================================================================================================#
    @aetest.test
    def verify_clear_ip_route_mroute_all(self, testscript):
        """ VXLAN_DISRUPTIVE_VERIFICATION subsection: Verify Clear IP mroute * """

        ixLib.stop_protocols()

        LEAF_3 = testscript.parameters['LEAF-3']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        LEAF_3_TGEN_data = testscript.parameters['LEAF_3_TGEN_dict']

        fail_flag = []
        fail_msgs = ""

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Clear ip route and ip mrotue
        LEAF_3.configure('clear ip route vrf all *')
        LEAF_3.configure('clear ip mroute * vrf all')

        ixLib.start_protocols()
        time.sleep(20)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the igmp groups
        # ----------------------------------------------------
        # LEAF-3 Counter Variables
        # ----------------------------------------------------
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0
        mcast_grp_ip = ip.IPv4Interface(LEAF_3_TGEN_data['mcast_grp_ip']).ip
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']

        # ----------------------------------------------------
        # Verify IGMP Snooping Groups on LEAF-3
        # ---------------------------------------------------
        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:

                mcast_grp_output = LEAF_3.execute("sh ip igmp snoop groups vlan " + str(l2_vlan_id) + " | i i " + str(
                    mcast_grp_ip) + " | i i Po" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']))
                if (str(l2_vlan_id) in mcast_grp_output) and (str(mcast_grp_ip) in mcast_grp_output) and (
                        "Po" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) in mcast_grp_output):
                    pass
                else:
                    fail_flag.append(0)
                    fail_msgs += "IP IGMP Snooping Groups " + str(mcast_grp_ip) + " is not created for " + str(
                        l2_vlan_id) + " in " + str(LEAF_3.alias) + "\n"

                l2_vlan_count_iter += 1
                l2_vlan_id += 1
                mcast_grp_ip += 256
            l3_vrf_count_iter += 1
            l2_vlan_count_iter = 0

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed(reason="Traffic Verification Failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class TRM_PROCESS_KILL_verify_nve_process_restart(aetest.Testcase):
    """TRM_PROCESS_KILL_VERIFICATION"""

    # =============================================================================================================================#
    @aetest.test
    def verify_nve_process_restart(self, testscript):
        """ TRM_PROCESS_KILL_VERIFICATION subsection: Verify killing process NVE """

        LEAF_3 = testscript.parameters['LEAF-3']

        fail_flag = []
        fail_msgs = ""

        if infraTrig.verifyProcessRestart(LEAF_3, "nve"):
            log.info("Successfully restarted process NVE")
        else:
            fail_flag.append(0)
            fail_msgs += "Failed to restarted process NVE\n"

        time.sleep(120)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify NVE UP
        LEAF_3_nve_out = LEAF_3.execute("sh int nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_3_nve_out:
            log.info("NVE INT is UP after process restart")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP after process restart\n"

        time.sleep(120)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify NVE Peers with new IP
        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
        else:
            fail_flag.append(0)
            fail_msgs += "FAIL : Failed to verify NVE Peering\n"

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class TRM_PROCESS_KILL_verify_bgp_process_restart(aetest.Testcase):
    """TRM_PROCESS_KILL_VERIFICATION"""

    # =============================================================================================================================#
    @aetest.test
    def verify_bgp_process_restart(self, testscript):
        """ TRM_PROCESS_KILL_VERIFICATION subsection: Verify killing process BGP """

        LEAF_3 = testscript.parameters['LEAF-3']

        fail_flag = []
        fail_msgs = ""

        if infraTrig.verifyProcessRestart(LEAF_3, "bgp"):
            log.info("Successfully restarted process BGP")
        else:
            fail_flag.append(0)
            fail_msgs += "Failed to restarted process BGP\n"

        time.sleep(60)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify NVE UP
        LEAF_3_nve_out = LEAF_3.execute("sh int nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_3_nve_out:
            log.info("NVE INT is UP after process restart")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP after process restart\n"

        time.sleep(120)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class TRM_PROCESS_KILL_verify_igmp_process_restart(aetest.Testcase):
    """TRM_PROCESS_KILL_VERIFICATION"""

    # =============================================================================================================================#
    @aetest.test
    def verify_igmp_process_restart(self, testscript):
        """ TRM_PROCESS_KILL_VERIFICATION subsection: Verify killing process IGMP """

        LEAF_3 = testscript.parameters['LEAF-3']

        fail_flag = []
        fail_msgs = ""

        if infraTrig.verifyProcessRestart(LEAF_3, "igmp"):
            log.info("Successfully restarted process IGMP")
        else:
            fail_flag.append(0)
            fail_msgs += "Failed to restarted process IGMPP\n"

        time.sleep(60)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify NVE UP
        LEAF_3_nve_out = LEAF_3.execute("sh int nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_3_nve_out:
            log.info("NVE INT is UP after process restart")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP after process restart\n"

        time.sleep(120)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class TRM_PROCESS_KILL_verify_l2rib_process_restart(aetest.Testcase):
    """TRM_PROCESS_KILL_VERIFICATION"""

    # =============================================================================================================================#
    @aetest.test
    def verify_l2rib_process_restart(self, testscript):
        """ TRM_PROCESS_KILL_VERIFICATION subsection: Verify killing process L2RIB """

        LEAF_3 = testscript.parameters['LEAF-3']

        fail_flag = []
        fail_msgs = ""

        if infraTrig.verifyProcessRestart(LEAF_3, "l2rib"):
            log.info("Successfully restarted process L2RIB")
        else:
            fail_flag.append(0)
            fail_msgs += "Failed to restarted process L2RIB\n"

        time.sleep(60)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify NVE UP
        LEAF_3_nve_out = LEAF_3.execute("sh int nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_3_nve_out:
            log.info("NVE INT is UP after process restart")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP after process restart\n"

        time.sleep(120)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class TRM_PROCESS_KILL_verify_mfdm_process_restart(aetest.Testcase):
    """TRM_PROCESS_KILL_VERIFICATION"""

    # =============================================================================================================================#
    @aetest.test
    def verify_mfdm_process_restart(self, testscript):
        """ TRM_PROCESS_KILL_VERIFICATION subsection: Verify killing process MFDM """

        LEAF_3 = testscript.parameters['LEAF-3']

        fail_flag = []
        fail_msgs = ""

        if infraTrig.verifyProcessRestart(LEAF_3, "mfdm"):
            log.info("Successfully restarted process MFDM")
        else:
            fail_flag.append(0)
            fail_msgs += "Failed to restarted process MFDM\n"

        time.sleep(60)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify NVE UP
        LEAF_3_nve_out = LEAF_3.execute("sh int nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_3_nve_out:
            log.info("NVE INT is UP after process restart")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP after process restart\n"

        time.sleep(120)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class TRM_PROCESS_KILL_verify_ufdm_process_restart(aetest.Testcase):
    """TRM_PROCESS_KILL_VERIFICATION"""

    # =============================================================================================================================#
    @aetest.test
    def verify_ufdm_process_restart(self, testscript):
        """ TRM_PROCESS_KILL_VERIFICATION subsection: Verify killing process UFDM """

        LEAF_3 = testscript.parameters['LEAF-3']

        fail_flag = []
        fail_msgs = ""

        if infraTrig.verifyProcessRestart(LEAF_3, "ufdm"):
            log.info("Successfully restarted process UFDM")
        else:
            fail_flag.append(0)
            fail_msgs += "Failed to restarted process UFDM\n"

        time.sleep(60)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify NVE UP
        LEAF_3_nve_out = LEAF_3.execute("sh int nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_3_nve_out:
            log.info("NVE INT is UP after process restart")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP after process restart\n"

        time.sleep(120)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class TRM_FEATURE_DISABLE_verify_no_feature_ngmvpn(aetest.Testcase):
    """TRM_FEATURE_DISABLE_VERIFICATION"""

    # =============================================================================================================================#
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

    # =============================================================================================================================#
    @aetest.test
    def verify_no_feature_ngmvpn(self, testscript):
        """ TRM_FEATURE_DISABLE_VERIFICATION subsection: Verify feature toggle of NGMVPN """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        fail_flag = []
        fail_msgs = ""

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Remove feature ngmvpn
        LEAF_1.configure("no feature ngmvpn", timeout=600)
        LEAF_2.configure("no feature ngmvpn", timeout=600)
        LEAF_3.configure("no feature ngmvpn", timeout=600)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the run conf
        LEAF_1_FT_ngmvpn_run_output = LEAF_1.execute("show run | grep 'feature ngmvpn'")
        LEAF_2_FT_ngmvpn_run_output = LEAF_2.execute("show run | grep 'feature ngmvpn'")
        LEAF_3_FT_ngmvpn_run_output = LEAF_3.execute("show run | grep 'feature ngmvpn'")

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify in run conf that feature is removed
        if "feature ngmvpn" in LEAF_1_FT_ngmvpn_run_output:
            fail_flag.append(0)
            fail_msgs += "Failed to verify removing configuring feature ngmvpn and feature present in running-config on LEAF_1\n"
        else:
            log.info(
                "Successfully verified removing configuring feature ngmvpn and feature not present in running-config on LEAF_1")

        if "feature ngmvpn" in LEAF_2_FT_ngmvpn_run_output:
            fail_flag.append(0)
            fail_msgs += "Failed to verify removing configuring feature ngmvpn and feature present in running-config on LEAF_2\n"
        else:
            log.info(
                "Successfully verified removing configuring feature ngmvpn and feature not present in running-config on LEAF_2")

        if "feature ngmvpn" in LEAF_3_FT_ngmvpn_run_output:
            fail_flag.append(0)
            fail_msgs += "Failed to verify removing configuring feature ngmvpn and feature present in running-config on LEAF_3\n"
        else:
            log.info(
                "Successfully verified removing configuring feature ngmvpn and feature not present in running-config on LEAF_3")

        testscript.parameters['LEAF-1'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-3'].configure("copy r s", timeout=300)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the start conf
        LEAF_1_FT_ngmvpn_start_output = LEAF_1.execute("show start | grep ngmvpn")
        LEAF_2_FT_ngmvpn_start_output = LEAF_2.execute("show start | grep ngmvpn")
        LEAF_3_FT_ngmvpn_start_output = LEAF_3.execute("show start | grep ngmvpn")

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify in start conf that feature is removed
        if "feature ngmvpn" in LEAF_1_FT_ngmvpn_start_output:
            fail_flag.append(0)
            fail_msgs += "Failed to verify removing configuring feature ngmvpn and feature present in startup-config on LEAF-1\n"
        else:
            log.info(
                "Successfully verified removing configuring feature ngmvpn and feature not present in startup-config on LEAF-1")

        if "feature ngmvpn" in LEAF_2_FT_ngmvpn_start_output:
            fail_flag.append(0)
            fail_msgs += "Failed to verify removing configuring feature ngmvpn and feature present in startup-config on LEAF-2\n"
        else:
            log.info(
                "Successfully verified removing configuring feature ngmvpn and feature not present in startup-config on LEAF-2")

        if "feature ngmvpn" in LEAF_3_FT_ngmvpn_start_output:
            fail_flag.append(0)
            fail_msgs += "Failed to verify configuring removing feature ngmvpn and feature present in startup-config on LEAF-3\n"
        else:
            log.info(
                "Successfully verified removing configuring feature ngmvpn and feature not present in startup-config on LEAF-3")

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def replay_configurations(self, testscript):
        """ TRM_FEATURE_DISABLE_VERIFICATION subsection: Verify feature toggle of NGMVPN """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Replay configs
        # LEAF_1.configure("copy bootflash:automation_test.txt running-config echo-commands", timeout=1200)
        # LEAF_2.configure("copy bootflash:automation_test.txt running-config echo-commands", timeout=1200)
        # LEAF_3.configure("copy bootflash:automation_test.txt running-config echo-commands", timeout=1200)

        LEAF_1.configure("configure replace bootflash:automation_test.txt verbose", timeout=1200)
        LEAF_2.configure("configure replace bootflash:automation_test.txt verbose", timeout=1200)
        LEAF_3.configure("configure replace bootflash:automation_test.txt verbose", timeout=1200)

        LEAF_1.execute("copy r s", timeout=1200)
        LEAF_2.execute("copy r s", timeout=1200)
        LEAF_3.execute("copy r s", timeout=1200)

        time.sleep(120)

    # =============================================================================================================================#
    @aetest.test
    def verify_network_post_config_replay(self, testscript):
        """ TRM_FEATURE_DISABLE_VERIFICATION subsection: Verify feature toggle of NGMVPN """

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        forwardingSysDict = testscript.parameters['forwardingSysDict']
        LEAF_3_TGEN_data = testscript.parameters['LEAF_3_TGEN_dict']

        fail_flag = []
        fail_msgs = ""

        # ----------------------------------------------------
        # LEAF-3 Counter Variables
        # ----------------------------------------------------
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0
        mcast_grp_ip = ip.IPv4Interface(LEAF_3_TGEN_data['mcast_grp_ip']).ip
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']

        # ----------------------------------------------------
        # Verify IGMP Snooping Groups on LEAF-3
        # ---------------------------------------------------
        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:

                L1_mcast_grp_output = LEAF_1.execute(
                    "sh ip igmp snoop groups vlan " + str(l2_vlan_id) + " | i i " + str(mcast_grp_ip) + " | i i nve1")
                if (str(l2_vlan_id) in L1_mcast_grp_output) and (str(mcast_grp_ip) in L1_mcast_grp_output) and (
                        "nve1" in L1_mcast_grp_output):
                    log.info("LEAF-1 IP IGMP Snooping Groups is created in RCV - FHR Leaf")
                else:
                    fail_flag.append(0)
                    fail_msgs += "LEAF-1 IP IGMP Snooping Groups " + str(mcast_grp_ip) + " is not created for " + str(
                        l2_vlan_id) + " in " + str(LEAF_3.alias) + "\n"

                L2_mcast_grp_output = LEAF_2.execute(
                    "sh ip igmp snoop groups vlan " + str(l2_vlan_id) + " | i i " + str(mcast_grp_ip) + " | i i nve1")
                if (str(l2_vlan_id) in L2_mcast_grp_output) and (str(mcast_grp_ip) in L2_mcast_grp_output) and (
                        "nve1" in L2_mcast_grp_output):
                    log.info("LEAF-2 IP IGMP Snooping Groups is created in RCV - FHR Leaf")
                else:
                    fail_flag.append(0)
                    fail_msgs += "LEAF-2 IP IGMP Snooping Groups " + str(mcast_grp_ip) + " is not created for " + str(
                        l2_vlan_id) + " in " + str(LEAF_3.alias) + "\n"

                L3_mcast_grp_output = LEAF_3.execute(
                    "sh ip igmp snoop groups vlan " + str(l2_vlan_id) + " | i i " + str(
                        mcast_grp_ip) + " | i i Po" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']))
                if (str(l2_vlan_id) in L3_mcast_grp_output) and (str(mcast_grp_ip) in L3_mcast_grp_output) and (
                        "Po" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) in L3_mcast_grp_output):
                    log.info("LEAF-3 IP IGMP Snooping Groups is created in RCV - FHR Leaf")
                else:
                    fail_flag.append(0)
                    fail_msgs += "LEAF-3 IP IGMP Snooping Groups " + str(mcast_grp_ip) + " is not created for " + str(
                        l2_vlan_id) + " in " + str(LEAF_3.alias) + "\n"

                l2_vlan_count_iter += 1
                l2_vlan_id += 1
                mcast_grp_ip += 256
            l3_vrf_count_iter += 1
            l2_vlan_count_iter = 0

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed("Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")


# *****************************************************************************************************************************#
class TRM_FEATURE_DISABLE_verify_no_feature_nv_overlay_vn_segment(aetest.Testcase):
    """TRM_FEATURE_DISABLE_VERIFICATION"""

    # =============================================================================================================================#
    @aetest.test
    def verify_no_feature_nv_overlay_vn_segment(self, testscript):
        """ TRM_FEATURE_DISABLE_VERIFICATION subsection: Verify toggle of feature nv overlay, feature vn-segment-vlan-based """

        LEAF_3 = testscript.parameters['LEAF-3']

        fail_flag = []
        fail_msgs = ""

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Remove feature nv overlay, vn-segment-vlan-based
        LEAF_3.configure("no feature nv overlay")
        LEAF_3.configure("no feature vn-segment-vlan-based", timeout=300)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the run conf
        LEAF_3_FT_nv_overlay_run_output = LEAF_3.execute("show run | grep 'feature nv overlay'")

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify in run conf that the feature is removed
        if "feature nv overlay" in LEAF_3_FT_nv_overlay_run_output:
            fail_flag.append(0)
            fail_msgs += "Failed to verify removing configuring feature ngmvpn and feature present in running-config on LEAF_3\n"
        else:
            log.info(
                "Successfully verified removing configuring feature ngmvpn and feature not present in running-config on LEAF_3")

        time.sleep(10)
        LEAF_3.execute("copy r s", timeout=1200)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the start conf
        LEAF_3_FT_nv_overlay_start_output = LEAF_3.execute("show start | grep 'feature nv overlay'")

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify in start conf that the feature is removed
        if "feature nv overlay" in LEAF_3_FT_nv_overlay_start_output:
            fail_flag.append(0)
            fail_msgs += "Failed to verify configuring removing feature nv overlay and feature present in startup-config on LEAF-3\n"
        else:
            log.info(
                "Successfully verified removing configuring feature nv overlay and feature not present in startup-config on LEAF-3")

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def replay_configurations(self, testscript):

        LEAF_3 = testscript.parameters['LEAF-3']

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Replay configurations
        # LEAF_3.configure("copy bootflash:automation_test.txt running-config echo-commands", timeout=1200)
        LEAF_3.configure("configure replace bootflash:automation_test.txt verbose", timeout=1200)

        testscript.parameters['LEAF-1'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-3'].configure("copy r s", timeout=300)

        time.sleep(120)

    # =============================================================================================================================#
    @aetest.test
    def verify_network_post_config_replay(self, testscript):

        LEAF_3 = testscript.parameters['LEAF-3']
        LEAF_3_TGEN_data = testscript.parameters['LEAF_3_TGEN_dict']
        forwardingSysDict = testscript.parameters['forwardingSysDict']

        fail_flag = []
        fail_msgs = ""

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Start and stop the IGMP protocols on IXIA
        ixLib.stop_protocols()
        ixLib.start_protocols()

        time.sleep(20)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the igmp groups
        # ----------------------------------------------------
        # LEAF-3 Counter Variables
        # ----------------------------------------------------
        l3_vrf_count_iter = 0
        l2_vlan_count_iter = 0
        mcast_grp_ip = ip.IPv4Interface(LEAF_3_TGEN_data['mcast_grp_ip']).ip
        l2_vlan_id = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']

        # ----------------------------------------------------
        # Verify IGMP Snooping Groups on LEAF-3
        # ---------------------------------------------------
        while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:

                mcast_grp_output = LEAF_3.execute("sh ip igmp snoop groups vlan " + str(l2_vlan_id) + " | i i " + str(
                    mcast_grp_ip) + " | i i Po" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']))
                if (str(l2_vlan_id) in mcast_grp_output) and (str(mcast_grp_ip) in mcast_grp_output) and (
                        "Po" + str(testscript.parameters['STD_VTEP_ACCESS_PO_id']) in mcast_grp_output):
                    pass
                else:
                    fail_flag.append(0)
                    fail_msgs += "IP IGMP Snooping Groups " + str(mcast_grp_ip) + " is not created for " + str(
                        l2_vlan_id) + " in " + str(LEAF_3.alias) + "\n"

                l2_vlan_count_iter += 1
                l2_vlan_id += 1
                mcast_grp_ip += 256
            l3_vrf_count_iter += 1
            l2_vlan_count_iter = 0

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_traffic(self):
        # Send traffic to populate stats # work-around
        ixLib.start_traffic()
        time.sleep(60)
        ixLib.stop_traffic()
        time.sleep(60)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 2) == 0:
            self.failed(reason="Traffic Verification failed")
        else:
            log.info("Traffic Verification Passed")

# *****************************************************************************************************************************#
class HA_VERIFICATION(aetest.Testcase):
    """HA_VERIFICATION"""

    # =============================================================================================================================#
    @aetest.test
    def verify_device_ascii_reload(self, testscript):
        """ HA_VERIFICATION subsection: Device ASCII Reload """

        LEAF_3 = testscript.parameters['LEAF-3']

        LEAF_3.configure("copy r s")

        # Perform Device Reload
        result = infraTrig.switchReload(LEAF_3)
        if result:
            log.info("Reload completed Successfully")
        else:
            log.debug("Reload Failed")
            self.failed("Reload Failed")

        log.info("Waiting for 120 sec for the topology to come UP")
        time.sleep(240)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify NVE UP
        LEAF_3_nve_out = LEAF_3.execute("sh int nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_3_nve_out:
            log.info("NVE INT is UP after shut/no-shut")
        else:
            log.debug("NVE INT is not UP after Reload")
            self.failed("NVE INT is not UP after Reload")

        time.sleep(120)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify NVE Peers with new IP
        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        # if ixLib.verify_traffic(2, 2) == 0:
        #     log.debug("Traffic Verification failed")
        #     self.failed("Traffic Verification failed")
        # else:
        #     log.info("Traffic Verification Passed")



########################################################################
####                       COMMON CLEANUP SECTION                    ###
########################################################################
#
## Remove the BASE CONFIGURATION that was applied earlier in the
## common cleanup section, clean the left over

class common_cleanup(aetest.CommonCleanup):
    """ Common Cleanup for Sample Test """

    @aetest.subsection
    def end_IXIA_session(self):
        """ Common Cleanup subsection """
        ixLib.end_session()
        log.info("Ending Ixia session")

    @aetest.subsection
    def restore_terminal_width(self):
        """ Common Cleanup subsection """
        log.info(banner("script common cleanup starts here"))


if __name__ == '__main__':  # pragma: no cover
    aetest.main()
