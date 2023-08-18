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


import pdb
import sys
import copy

# ------------------------------------------------------
# Import and initialize EVPN specific libraries
# ------------------------------------------------------
import vxlanEVPN_FNL_lib
evpnLib     = vxlanEVPN_FNL_lib.configure39KVxlanEvpn()
verifyEvpn  = vxlanEVPN_FNL_lib.verifyEVPNconfiguration()

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
###                  GLOBAL VARIABLES                           ###
###################################################################

device_list     = []

###################################################################
###                  COMMON SETUP SECTION                       ###
###################################################################

# Configure and setup all devices and test equipment in this section.
# This should represent the BASE CONFIGURATION that is applicable
# for the bunch of test cases that would follow.

def verify_vxlan_mh_mac_cc (hdl, log):
    loop_cnt = 1
    while loop_cnt <= 5:
        out = hdl.iexec('show consistency-checker vxlan mh mac-addresses')
        check = 0
        if re.search('Consistency check: PASSED',out,re.I):
            check = 1
        if re.search('Consistency check: FAIL',out,re.I):
            check = 2

        if check == 2:
            return 0
        elif check == 1:
            return 1
        loop_cnt += 1
        log.info('CC failed..sleep for 5 seconds to try again..')
        sleep(5)

    return 0

def convert_ip_str_to_hex(peer_ip_str):
     # Convert the Peer IP addr into hex
     a = peer_ip_str.split('.')
     b = hex(int(a[0]))[2:].zfill(2) + hex(int(a[1]))[2:].zfill(2) + hex(int(a[2]))[2:].zfill(2) + hex(int(a[3]))[2:].zfill(2)
     b = b.replace('0x', '')
     b = "0x" + b[1:]
     return b

def verify_vxlan_mh_pathlist_cc (hdl, log):
    loop_cnt = 1
    while loop_cnt <= 5:
        out = hdl.iexec('show consistency-checker vxlan mh pathlist')
        check = 0
        if re.search('Consistency check: PASSED',out,re.I):
            check = 1
        if re.search('Consistency check: FAIL',out,re.I):
            check = 2

        if check == 2:
            return 0
        elif check == 1:
            return 1
        loop_cnt += 1
        log.info('CC failed..sleep for 5 seconds to try again..')
        sleep(5)

    return 0

def get_pv_port_num_and_ovlan_ivlan_mvlan(dut):

    #get one interface name from cc
    intf_name = ""
    out = dut.execute("show consistency-checker vxlan pv")
    lines = out.split("\n")
    for line in lines:
        if "vlan xlate checks for interface" in line:
            new = line.split("interface")
            new = new[1].split(":")[0]
            intf_name = new.strip()
        if intf_name != "":
            break

    #get the interface number from hardware mapping
    intf_num = 0
    cmd = 'show int hardware-mappings | grep -w %s' % intf_name
    output = dut.execute(cmd)
    words = list(map(str.strip, output.split(' ')))
    words = ' '.join(words).split()
    intf_num = hex(int(words[4]))

    #get the vlan from running config
    vlan = 0
    ivlan=0
    map_vlan = 0
    cmd = 'show running-config int %s' % intf_name
    output = dut.execute(cmd)
    lines = output.split("\n")
    for line in lines:
        if "switchport vlan mapping" in line:
            if "enable" not in line:
                if "inner" in line:
                    words = list(map(str.strip,line.split(" ")))
                    words = ' '.join(words).split()
                    print(words)
                    vlan = hex(int(words[3]))
                    ivlan = hex(int(words[5]))
                    map_vlan = hex(int(words[6]))
                else:
                    words = list(map(str.strip,line.split(" ")))
                    words = ' '.join(words).split()
                    vlan = hex(int(words[3]))
                    map_vlan = hex(int(words[4]))
    #print("return",str(intf_num),str(vlan))
    
    return intf_num, vlan, ivlan, map_vlan

def verify_vxlan_pv_cc (hdl, log):
    loop_cnt = 1
    while loop_cnt <= 5:
        out = hdl.execute('show consistency-checker vxlan pv')
        check = 0
        if re.search('No intfs configured in pv',out,re.I):
            check = 1
        if re.search('Vxlan pv Overall status       : PASS',out,re.I):
            check = 1
        if re.search('Vxlan pv Overall status       : FAIL',out,re.I):
            check = 2

        if check == 2:
            return 0
        elif check == 1:
            return 1
        loop_cnt += 1
        log.info('CC failed..sleep for 5 seconds to try again..')
        sleep(5)

    return 0

class COMMON_SETUP(aetest.CommonSetup):
    """ Common Setup """

    log.info(banner("Common Setup"))

    @aetest.subsection
    def connecting_to_devices(self, testscript, testbed, uut_list, configurationFile, script_flags=None):
        """ common setup subsection: Connecting to devices """

        log.info(banner("Connecting to Devices"))

        # =============================================================================================================================#
        # Grab the device object of the uut device with that name
        SPINE = testscript.parameters['SPINE'] = testbed.devices[uut_list['SPINE']]

        LEAF_1 = testscript.parameters['LEAF-1'] = testbed.devices[uut_list['LEAF-1']]
        LEAF_2 = testscript.parameters['LEAF-2'] = testbed.devices[uut_list['LEAF-2']]
        LEAF_3 = testscript.parameters['LEAF-3'] = testbed.devices[uut_list['LEAF-3']]

        FAN_1 = testscript.parameters['FAN-1'] = testbed.devices[uut_list['FAN-1']]
        FAN_2 = testscript.parameters['FAN-2'] = testbed.devices[uut_list['FAN-2']]

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

        testscript.parameters['LEAF_1_dict']            = configuration['LEAF_1_dict']
        testscript.parameters['LEAF_2_dict']            = configuration['LEAF_2_dict']
        testscript.parameters['LEAF_12_TGEN_dict']       = configuration['LEAF_12_TGEN_data']

        testscript.parameters['LEAF_3_dict']            = configuration['LEAF_3_dict']
        testscript.parameters['LEAF_3_TGEN_dict']       = configuration['LEAF_3_TGEN_data']

        testscript.parameters['forwardingSysDict']      = configuration['FWD_SYS_dict']

        testscript.parameters['leafVPCDictData']        = {LEAF_1 : configuration['LEAF_2_dict'], LEAF_2 : configuration['LEAF_3_dict']}
        testscript.parameters['leavesDictList']         = [configuration['LEAF_1_dict'], configuration['LEAF_2_dict'], configuration['LEAF_3_dict']]
        testscript.parameters['leavesDict']             = {LEAF_1 : configuration['LEAF_1_dict'],
                                                           LEAF_2 : configuration['LEAF_2_dict'],
                                                           LEAF_3 : configuration['LEAF_3_dict']}

        testscript.parameters['VTEP_List'] = [testscript.parameters['LEAF_1_dict'], testscript.parameters['LEAF_2_dict'], testscript.parameters['LEAF_3_dict']]

    # *****************************************************************************************************************************#

    @aetest.subsection
    def get_interfaces(self, testscript):
        """ common setup subsection: Getting required Connections for Test """

        log.info(banner("Retrieve the interfaces from Yaml file"))

        SPINE = testscript.parameters['SPINE']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']

        # =============================================================================================================================#

        log.info("================================================")
        log.info("All Available Interfaces from the YAML file are:")
        for dut in device_list:
            log.info("\n\n--->" + str(dut) + " Interface list")
            for interface in dut.interfaces.keys():
                log.info(str(interface) + " --> " + str(dut.interfaces[interface].intf))

        # =============================================================================================================================#
        # Fetching the specific interfaces
        testscript.parameters['intf_SPINE_to_LEAF_1']       = SPINE.interfaces['SPINE_to_LEAF-1'].intf
        testscript.parameters['intf_SPINE_to_LEAF_2']       = SPINE.interfaces['SPINE_to_LEAF-2'].intf
        testscript.parameters['intf_SPINE_to_LEAF_3']       = SPINE.interfaces['SPINE_to_LEAF-3'].intf

        testscript.parameters['intf_LEAF_1_to_SPINE']       = LEAF_1.interfaces['LEAF-1_to_SPINE'].intf
        testscript.parameters['intf_LEAF_1_to_FAN_1']       = LEAF_1.interfaces['LEAF-1_to_FAN-1'].intf

        testscript.parameters['intf_LEAF_2_to_SPINE']       = LEAF_2.interfaces['LEAF-2_to_SPINE'].intf
        testscript.parameters['intf_LEAF_2_to_FAN_1']       = LEAF_2.interfaces['LEAF-2_to_FAN-1'].intf

        testscript.parameters['intf_LEAF_3_to_SPINE']       = LEAF_3.interfaces['LEAF-3_to_SPINE'].intf
        testscript.parameters['intf_LEAF_3_to_FAN_2']       = LEAF_3.interfaces['LEAF-3_to_FAN-2'].intf

        testscript.parameters['intf_FAN_1_to_LEAF_1']       = FAN_1.interfaces['FAN-1_to_LEAF-1'].intf
        testscript.parameters['intf_FAN_1_to_LEAF_2']       = FAN_1.interfaces['FAN-1_to_LEAF-2'].intf

        testscript.parameters['intf_FAN_2_to_LEAF_3']       = FAN_2.interfaces['FAN-2_to_LEAF-3'].intf

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
                            |   LEAF-1  |    |   LEAF-2  |    |   LEAF-3  |
                            +-----------+    +-----------+    +-----------+
                                   \\             /                 |
                                    \\           /                  |
                                     \\         /                   |
                                      \\       /                    |
                                    +-----------+             +-----------+
                                    |   FAN-1   |             |   FAN-2   |
                                    +-----------+             +-----------+     
        """

        log.info("Topology to be used is")
        log.info(topology)


# *****************************************************************************************************************************#


class DEVICE_BRINGUP(aetest.Testcase):
    """Device Bring-up Test-Case"""

    log.info(banner("Device Bring UP"))

    @aetest.test
    def enable_feature_set(self, testscript):
        """ Device Bring-up subsection: Configuring Features and Feature-sets """

        log.info(banner("Enabling Feature Set"))

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            testscript.parameters['leafLst']            = leafLst           = [testscript.parameters['LEAF-1'], testscript.parameters['LEAF-2'], testscript.parameters['LEAF-3']]
            testscript.parameters['spineFeatureList']   = spineFeatureList  = ['ospf', 'bgp', 'pim', 'lacp', 'nv overlay']
            testscript.parameters['LeafFeatureList']    = LeafFeatureList   = ['ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp', 'nv overlay', 'fabric forwarding']
            testscript.parameters['fanOutFeatureList']  = fanOutFeatureList = ['lacp', 'interface-vlan']
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
            # Configure Feature Set on Leafs
            featureSetConfigureLeafs_status = infraConfig.configureVerifyFeatureSet(leafLst, ['mpls'])
            if featureSetConfigureLeafs_status['result']:
                log.info("Passed Configuring feature Sets on all Leafs")
            else:
                log.debug("Failed Configuring feature Sets on all Leafs")
                configFeatureSet_msgs += featureSetConfigureLeafs_status['log']
                configFeatureSet_status.append(0)

            featureConfigureLeaf1_status = infraConfig.configureVerifyFeature(leafLst, LeafFeatureList)
            if featureConfigureLeaf1_status['result']:
                log.info("Passed Configuring features on LEAFs")
            else:
                log.debug("Failed configuring features on LEAFs")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on FANOUTs
            featureConfigureFan1_status = infraConfig.configureVerifyFeature([testscript.parameters['FAN-1'], testscript.parameters['FAN-2']], fanOutFeatureList)
            if featureConfigureFan1_status['result']:
                log.info("Passed Configuring features on FAN boxes")
            else:
                log.debug("Failed configuring features on FAN boxes")
                configFeatureSet_msgs += featureConfigureFan1_status['log']
                configFeatureSet_status.append(0)

            if 0 in configFeatureSet_status:
                self.failed(reason=configFeatureSet_msgs, goto=['common_cleanup'])

        else:
            self.passed(reason="Skipped Device Configuration as per request")


    # *****************************************************************************************************************************#

    @aetest.test
    def configure_SPINE(self, testscript):
        """ Device Bring-up subsection: Configuring SPINE """

        log.info(banner("Configuring SPINE"))

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
    def configure_LEAF_1(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        log.info(banner("Configuring LEAF-1"))

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNLeaf(testscript.parameters['LEAF-1'], testscript.parameters['forwardingSysDict'], testscript.parameters['LEAF_1_dict'])

            try:
                testscript.parameters['LEAF-1'].configure('''
                
                  evpn esi multihoming

                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_SPINE']) + '''
                    channel-group ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                    no shutdown
                
                  interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                    evpn multihoming core-tracking

                  router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                    vrf EVPN-VRF-1
                    address-family ipv4 unicast
                    redistribute hmm route-map ANY
                    vrf EVPN-VRF-2
                    address-family ipv4 unicast
                    redistribute hmm route-map ANY

                  interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + '''
                    switchport
                    switchport mode trunk
                    ethernet-segment 1234
                    system-mac 0102.0103.0234
                  
                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_FAN_1']) + '''
                    channel-group ''' + str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po']) + ''' force mode active
                    no shutdown
              ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on LEAF-1', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_LEAF_2(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-2 """

        log.info(banner("Configuring LEAF-2"))

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNLeaf(testscript.parameters['LEAF-2'], testscript.parameters['forwardingSysDict'], testscript.parameters['LEAF_2_dict'])

            try:
                testscript.parameters['LEAF-2'].configure('''
                  
                  evpn esi multihoming
                    
                  interface ''' + str(testscript.parameters['intf_LEAF_2_to_SPINE']) + '''
                    channel-group ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                    no shutdown
                    
                  interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                    evpn multihoming core-tracking

                  router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                    vrf EVPN-VRF-1
                    address-family ipv4 unicast
                    redistribute hmm route-map ANY
                    vrf EVPN-VRF-2
                    address-family ipv4 unicast
                    redistribute hmm route-map ANY

                  interface port-channel ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + '''
                    switchport
                    switchport mode trunk
                    ethernet-segment 1234
                    system-mac 0102.0103.0234
                    
                  interface ''' + str(testscript.parameters['intf_LEAF_2_to_FAN_1']) + '''
                    channel-group ''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + ''' force mode active
                    no shutdown                   
              ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on LEAF-1', goto=['common_cleanup'])

        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_LEAF_3(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-3 """

        log.info(banner("Configuring LEAF-3"))

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNLeaf(testscript.parameters['LEAF-3'], testscript.parameters['forwardingSysDict'], testscript.parameters['LEAF_3_dict'])

            try:
                testscript.parameters['LEAF-3'].configure('''
                    
                    evpn esi multihoming

                    interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''
                      channel-group ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown
                    
                    interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                      switchport
                      switchport mode trunk
                      no shutdown

                    router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                      address-family l2vpn evpn
                      maximum-paths 64
                      maximum-paths ibgp 64
                    
              ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on LEAF-3', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

        time.sleep(300)

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_FAN_1(self, testscript):
        """ Device Bring-up subsection: Configuring FAN_1 """

        log.info(banner("Configuring FAN-1"))

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
                                      
                                    interface port-channel''' + str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po']) + '''
                                      switchport
                                      switchport mode trunk
                                      no shutdown
                                      
                                    interface {0}
                                      channel-group 200 force mode active
                                      no shutdown
                                      
                                    interface {1}
                                      channel-group 200 force mode active
                                      no shutdown

                                    interface vlan 301
                                      ip address 2.1.1.10/24
                                      no shutdown

                                    ping 2.1.1.1
                                      
                                '''.format(testscript.parameters['intf_FAN_1_to_LEAF_1'],
                                           testscript.parameters['intf_FAN_1_to_LEAF_2']))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FAN-1', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per Request")

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_FAN_2(self, testscript):
        """ Device Bring-up subsection: Configuring FAN_2 """

        log.info(banner("Configuring FAN-2"))

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            fanOut2_vlanConfiguration = ""

            l3_vrf_count_iter = 0
            l2_vlan_id = testscript.parameters['LEAF_3_dict']['VNI_data']['l2_vlan_start']
            l3_vlan_id = testscript.parameters['LEAF_3_dict']['VNI_data']['l3_vlan_start']

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
    
                                    interface {0}
                                      switchport
                                      switchport mode trunk
                                      no shutdown
    
                                '''.format(testscript.parameters['intf_FAN_2_to_LEAF_3']))
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FAN-2', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per Request")

    # =============================================================================================================================#
    @aetest.test
    def perform_copy_r_s(self, testscript):
        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Save all configurations (copy r s) """

        log.info(banner("Performing Copy R S"))

        testscript.parameters['LEAF-1'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-3'].configure("copy r s", timeout=300)

        time.sleep(300)

    # *****************************************************************************************************************************#


class VERIFY_NETWORK(aetest.Testcase):
    """This is description for my testcase one"""

    # =============================================================================================================================#
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    #=============================================================================================================================#
    # @aetest.test
    # def verify_NVE_peering(self, testscript):
    #     """ VERIFY_NETWORK subsection: Verify NVE Peering """
    
    #     nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])
    
    #     if nvePeerData['result'] is 1:
    #         log.info("PASS : Successfully verified NVE Peering\n\n")
    #         self.passed(reason=nvePeerData['log'])
    #     else:
    #         log.info("FAIL : Failed to verify NVE Peering\n\n")
    #         self.failed(reason=nvePeerData['log'])

    #=============================================================================================================================#
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

    #*****************************************************************************************************************************#


class BRCM_MH_CC_PATHLIST_VALIDATION(aetest.Testcase):
    """ BRCM_MH_CC_PATHLIST_VALIDATION """

    @aetest.test
    def Validate_VxLAN_MH_PATHLIST_CC(self, testscript):
        loop_cnt = 1
        while loop_cnt <= 5:
            out = testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist')
            check = 0
            if re.search('Consistency check: PASSED',out,re.I):
                check = 1
            if re.search('Consistency check: FAIL',out,re.I):
                check = 2

            if check == 2:
                log.error("Consistency check fail for VxLAN MH Pathlist\n")
                self.failed("Consistency check fail for Vxlan MH Pathlist\n")
            elif check == 1:
                log.info("Consistency check pass for VxLAN MH Pathlist\n")
                self.passed("Consistency check pass for Vxlan MH Pathlist\n")
            loop_cnt += 1
            log.info('CC failed..sleep for 5 seconds to try again..')
            sleep(5)

        log.error("Consistency check fail for VxLAN MH Pathlist\n")
        self.failed("Consistency check fail for Vxlan MH Pathlist\n")

    # =============================================================================================================================#
    @aetest.test
    def VALIDATE_MH_PATH_LIST_BRIEF_CC(self, testscript):
        """ Validate BRCM MH PATH LIST BRIEF CC """

        brcmMHPathListCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHPathListCC['result']['status']:
            self.failed(reason="BRCM MH Path List BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH Path List BRIEF CC Passed")

    # =============================================================================================================================#
    @aetest.test
    def VALIDATE_MH_PATH_LIST_DETAIL_CC(self, testscript):
        """ Validate BRCM MH PATH LIST DETAIL CC """

        brcmMHPathListCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist detail | no'))

        if "CC_STATUS_NOT_OK" in brcmMHPathListCC['result']['status']:
            self.failed(reason="BRCM MH Path List DETAIL CC Failed")
        else:
            self.passed(reason="BRCM MH Path List DETAIL CC Passed")


    @aetest.test
    def Modify_ING_DVP_TABLE(self, testscript):
        """ Modify_ING_DVP_TABLE """

        testscript.parameters['LEAF-3'].execute('bcm mod 1 "0:dump chg ing_dvp_table"')
        testscript.parameters['LEAF-3'].execute('bcm-shell mod 1 "0:mod ing_dvp_table 1 1 ENABLE_VPLAG_RESOLUTION=0"')

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist brief | no'))
        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            testscript.parameters['LEAF-3'].execute('bcm-shell mod 1 "0:mod ing_dvp_table 1 1 ENABLE_VPLAG_RESOLUTION=1"')
            brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist brief | no'))
            if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
                self.failed(reason="BRCM MH Pathlist BRIEF CC Failed")
            else:
                self.passed(reason="BRCM MH Pathlist BRIEF CC Passed")
        else:
            self.failed(reason="BRCM MH Pathlist BRIEF CC Passed")


    @aetest.test
    def Modify_L3_ECMP(self, testscript):
        """ Modify_L3_ECMP """

        output = testscript.parameters['LEAF-3'].execute('bcm-shell mod 1 "0:d chg l3_ecmp"')
        dvp_value = re.findall(r'DVP=0x([a-f0-9]{4})',output)

        testscript.parameters['LEAF-3'].execute('bcm-shell mod 1 "0:mod l3_ecmp 0 1 DVP=0"')

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            cmd = 'bcm-shell mod 1 "0:mod l3_ecmp 0 1 DVP=0x{}"'.format(dvp_value[0])
            testscript.parameters['LEAF-3'].execute(cmd)
            brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist brief | no'))
            if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
                self.failed(reason="BRCM MH Pathlist BRIEF CC Failed")
            else:
                self.passed(reason="BRCM MH Pathlist BRIEF CC Passed")
        else:
            self.failed(reason="BRCM MH Pathlist BRIEF CC Failed")


    @aetest.test
    def Modify_L3_ECMP_GRP(self, testscript):
        """ Modify_L3_ECMP_GRP """

        testscript.parameters['LEAF-3'].execute('bcm-shell mod 1 "0:d chg l3_ecmp_group"')
        testscript.parameters['LEAF-3'].execute('bcm-shell mod 1 "0:mod l3_ecmp_group 1 1 COUNT=0"')

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            testscript.parameters['LEAF-3'].execute('bcm-shell mod 1 "0:mod l3_ecmp_group 1 1 COUNT=1"')
            brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist brief | no'))
            if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
                self.failed(reason="BRCM MH Pathlist BRIEF CC Failed")
            else:
                self.passed(reason="BRCM MH Pathlist BRIEF CC Passed")
        else:
            self.failed(reason="BRCM MH Pathlist BRIEF CC Failed")


    @aetest.test
    def Modify_EGR_DVP_ATTRIBUTE(self, testscript):
        """ Modify_EGR_DVP_ATTRIBUTE """

        def convert_ip_str_to_hex(peer_ip_str):
        # Convert the Peer IP addr into hex
            a = peer_ip_str.split('.')
            b = hex(int(a[0]))[2:].zfill(2) + hex(int(a[1]))[2:].zfill(2) + hex(int(a[2]))[2:].zfill(2) + hex(int(a[3]))[2:].zfill(2)
            b = b.replace('0x', '')
            b = "0x" + b[1:]
            return b

        # Get all the resultant path lists from Sw and modify DIP 
        output = testscript.parameters['LEAF-3'].execute("sh forwarding distribution internal es-pathlist 1")
        lines = output.split('\n')
        peer_list_arr = []
        for line in lines:
            if 'Peer-list' in line:
                match = re.match(r"(.*)rpl_id: (.*), Peer Cnt:(.*), Peer-list:(.*)", line, re.M|re.I)
                peer_count = int(match.group(3),0) # Peer Count
                if (peer_count < 2):
                    continue
                rpl_id = int(match.group(2),0) # RPL_id
                peer_list_str = (((match.group(4)).split('(')[1]).split(')')[0]).split() # Remove the brackets
                #print "RPL ID: %d" %(rpl_id)
                if(len(peer_list_str) < 2):
                    continue
                peer_list_arr = []
                for peer in peer_list_str:
                    peer_list_arr.append(convert_ip_str_to_hex(peer))

        print(peer_list_arr)
        output =''
        cmd = 'bcm-shell mod {} "{}:d chg egr_dvp_attribute" | grep -i "VXLAN:DIP={}"'.format(1,0,peer_list_arr[0])
        output = testscript.parameters['LEAF-3'].execute(cmd)
        #print(output)
        entry_index = 0
        
        if output != None:
            lines = output.split(",")
            for line in lines:
                #print("--->",line)
                if "EGR_DVP_ATTRIBUTE.epipe" in line:
                    new = line.split("epipe0[")
                    new = new[1].split("]")
                    print("--->",new)
                    entry_index = new[0]
                    break

        #modify the DIP back to correct value to check if CC passes
        cmd = 'bcm-shell mod {} "{}:mod egr_dvp_attribute {} 1 VXLAN:DIP=0"'.format(1,0,entry_index)
        output = testscript.parameters['LEAF-3'].configure(cmd)
        #print(cmd)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            cmd = 'bcm-shell mod {} "{}:mod egr_dvp_attribute {} 1 VXLAN:DIP={}"'.format(1,0,entry_index,peer_list_arr[0])
            output = testscript.parameters['LEAF-3'].execute(cmd)
            print(cmd)
            brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist brief | no'))
            if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
                self.failed(reason="BRCM MH Pathlist BRIEF CC Failed")
            else:
                self.passed(reason="BRCM MH Pathlist BRIEF CC Passed")
        else:
            self.failed(reason="BRCM MH  Pathlist BRIEF CC Failed")

    @aetest.test
    def Local_Link_Flap(self, testscript):
        """ Local_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH Pathlist BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH Pathlist BRIEF CC Passed")

    @aetest.test
    def Remote_Link_Flap(self, testscript):
        """ Remote_Link_Flap """

        testscript.parameters['LEAF-1'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_SPINE']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        testscript.parameters['LEAF-2'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_2_to_SPINE']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH Pathlist BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH Pathlist BRIEF CC Passed")


    @aetest.test
    def NVE_Flap(self, testscript):
        """ NVE_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface nve 1
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH Pathlist BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH Pathlist BRIEF CC Passed")


    @aetest.test
    def Remove_Add_ESI(self, testscript):
        """ Remove_Add_ESI """

        testscript.parameters['LEAF-3'].configure('''

                  no evpn esi multihoming
                  evpn esi multihoming
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH Pathlist BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH Pathlist BRIEF CC Passed")

    @aetest.test
    def UP_Link_Flap(self, testscript):
        """ UP_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface port-channel ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH Pathlist BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH Pathlist BRIEF CC Passed")

    @aetest.test
    def Access_Link_Flap(self, testscript):
        """ Access_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH Pathlist BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH Pathlist BRIEF CC Passed")


    @aetest.test
    def Remove_Add_VLAN(self, testscript):
        """ Remove_Add_VLAN """

        testscript.parameters['LEAF-3'].configure('''

                  no vlan 10,11,301-304
                  vlan 10,11,301-304
                  vlan 10
                    vn-segment 11000
                  vlan 11
                    vn-segment 11001
                  vlan 301
                    vn-segment 20001
                  vlan 302
                    vn-segment 20002
                  vlan 303
                    vn-segment 20003
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh pathlist brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH Pathlist BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH Pathlist BRIEF CC Passed")


class BRCM_MH_CC_MAC_ADDRESS_VALIDATION(aetest.Testcase):

    # =============================================================================================================================#
    @aetest.test
    def VALIDATE_MH_MAC_BRIEF_CC(self, testscript):
        """ Validate BRCM MH MAC BRIEF CC """

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")

    # =============================================================================================================================#
    @aetest.test
    def VALIDATE_MH_MAC_DETAIL_CC(self, testscript):
        """ Validate BRCM MH MAC DETAIL CC """

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses detail | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC DETAIL CC Failed")
        else:
            self.passed(reason="BRCM MH MAC DETAIL CC Passed")


    @aetest.test
    def Validate_VxLAN_MH_MAC_CC_Test(self, testscript):
        loop_cnt = 1
        while loop_cnt <= 5:
            out = testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses')
            check = 0
            if re.search('Consistency check: PASSED',out,re.I):
                check = 1
            if re.search('Consistency check: FAIL',out,re.I):
                check = 2

            if check == 2:
                log.error("Consistency check fail for VxLAN MH MAC\n")
                self.failed("Consistency check fail for Vxlan MH MAC\n")
            elif check == 1:
                log.info("Consistency check pass for VxLAN MH MAC\n")
                self.passed("Consistency check pass for Vxlan MH MAC\n")
            loop_cnt += 1
            log.info('CC failed..sleep for 5 seconds to try again..')
            sleep(5)

        log.error("Consistency check fail for VxLAN MH MAC\n")
        self.failed("Consistency check fail for Vxlan MH MAC\n")


    @aetest.test
    def Modify_L2_Entry(self, testscript):
        """ Validate BRCM MH MAC BRIEF CC """

        #modify nan esi mac entry to verify if cc fails
        cli_str = "sh mac address-table "
        output = testscript.parameters['LEAF-3'].execute(cli_str)
        lines = output.split('\n')
        next_hop_list = ""
        mac = ""
        for line in lines[6:]:
            #print line
            words = line.split()
            if(len(words) == 0):
                continue
            if(words[1] == '-'):
                continue
            vlan = int(words[1])
            mac = words[2]
            next_hop_list = None
            if 'nve1' in line:
                print(line)
                next_hop = line.split('nve1(')[1]
                next_hop = next_hop.split(')')[0]
                if ' ' in next_hop:
                    next_hop_list = next_hop.split()
                if next_hop_list != None:
                    break;

        mac = mac.replace(".","")

        cmd = 'bcm mod 1 "dump chg L2_ENTRY" | grep "{}"'.format(mac)
        output = testscript.parameters['LEAF-3'].execute(cmd)
        #print(output)
        entry_index = 0

        if output != None:
            lines = output.split(",")
            for line in lines:
                #print("--->",line)
                if "L2_ENTRY.ipipe" in line:
                    new = line.split("ipipe0[")
                    new = new[1].split("]")
                    print("--->",new)
                    entry_index = new[0]
                    break

        #print("-------->",entry_index)
        cmd = 'bcm-shell mod {} "{}:mod L2_ENTRY {} 1 VALID=0"'.format(1,0,entry_index)
        print(cmd)
        output = testscript.parameters['LEAF-3'].execute(cmd)

        testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses')

        cmd = 'bcm-shell mod {} "{}:mod L2_ENTRY {} 1 VALID=1"'.format(1,0,entry_index)
        output = testscript.parameters['LEAF-3'].execute(cmd)
        
        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))
            
        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")


    @aetest.test
    def Local_Link_Flap(self, testscript):
        """ Local_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")

    @aetest.test
    def Remote_Link_Flap(self, testscript):
        """ Remote_Link_Flap """

        testscript.parameters['LEAF-1'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_SPINE']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        testscript.parameters['LEAF-2'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_2_to_SPINE']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")


    @aetest.test
    def NVE_Flap(self, testscript):
        """ NVE_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface nve 1
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")


    @aetest.test
    def Remove_Add_ESI(self, testscript):
        """ Remove_Add_ESI """

        testscript.parameters['LEAF-3'].configure('''

                  no evpn esi multihoming
                  evpn esi multihoming
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")

    @aetest.test
    def UP_Link_Flap(self, testscript):
        """ UP_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface port-channel ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")

    @aetest.test
    def Access_Link_Flap(self, testscript):
        """ Access_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")


    @aetest.test
    def Remove_Add_VLAN(self, testscript):
        """ Remove_Add_VLAN """

        testscript.parameters['LEAF-3'].configure('''

                  no vlan 10,11,301-304
                  vlan 10,11,301-304
                  vlan 10
                    vn-segment 11000
                  vlan 11
                    vn-segment 11001
                  vlan 301
                    vn-segment 20001
                  vlan 302
                    vn-segment 20002
                  vlan 303
                    vn-segment 20003
                  
              ''')

        sleep(35)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")


class BRCM_MH_CC_SINGLE_MAC_ADDRESS_VALIDATION(aetest.Testcase):


    # =============================================================================================================================#
    @aetest.test
    def VALIDATE_MH_MAC_BRIEF_CC(self, testscript):
        """ Validate BRCM MH MAC BRIEF CC """

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")

    # =============================================================================================================================#
    @aetest.test
    def VALIDATE_MH_MAC_DETAIL_CC(self, testscript):
        """ Validate BRCM MH MAC DETAIL CC """

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses detail | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC DETAIL CC Failed")
        else:
            self.passed(reason="BRCM MH MAC DETAIL CC Passed")


    @aetest.test
    def Validate_VxLAN_MH_MAC_CC_Test(self, testscript):
        loop_cnt = 1
        while loop_cnt <= 5:
            out = testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses')
            check = 0
            if re.search('Consistency check: PASSED',out,re.I):
                check = 1
            if re.search('Consistency check: FAIL',out,re.I):
                check = 2

            if check == 2:
                log.error("Consistency check fail for VxLAN MH MAC\n")
                self.failed("Consistency check fail for Vxlan MH MAC\n")
            elif check == 1:
                log.info("Consistency check pass for VxLAN MH MAC\n")
                self.passed("Consistency check pass for Vxlan MH MAC\n")
            loop_cnt += 1
            log.info('CC failed..sleep for 5 seconds to try again..')
            sleep(5)

        log.error("Consistency check fail for VxLAN MH MAC\n")
        self.failed("Consistency check fail for Vxlan MH MAC\n")


    @aetest.test
    def Modify_L2_Entry(self, testscript):
        """ Validate BRCM MH MAC BRIEF CC """

        #modify nan esi mac entry to verify if cc fails
        cli_str = "sh mac address-table "
        output = testscript.parameters['LEAF-3'].execute(cli_str)
        lines = output.split('\n')
        next_hop_list = ""
        mac = ""
        for line in lines[6:]:
            #print line
            words = line.split()
            if(len(words) == 0):
                continue
            if(words[1] == '-'):
                continue
            vlan = int(words[1])
            mac = words[2]
            next_hop_list = None
            if 'nve1' in line:
                print(line)
                next_hop = line.split('nve1(')[1]
                next_hop = next_hop.split(')')[0]
                if ' ' in next_hop:
                    next_hop_list = next_hop.split()
                if next_hop_list != None:
                    break;

        mac = mac.replace(".","")

        cmd = 'bcm mod 1 "dump chg L2_ENTRY" | grep "{}"'.format(mac)
        output = testscript.parameters['LEAF-3'].execute(cmd)
        #print(output)
        entry_index = 0

        if output != None:
            lines = output.split(",")
            for line in lines:
                #print("--->",line)
                if "L2_ENTRY.ipipe" in line:
                    new = line.split("ipipe0[")
                    new = new[1].split("]")
                    print("--->",new)
                    entry_index = new[0]
                    break

        #print("-------->",entry_index)
        cmd = 'bcm-shell mod {} "{}:mod L2_ENTRY {} 1 VALID=0"'.format(1,0,entry_index)
        print(cmd)
        output = testscript.parameters['LEAF-3'].execute(cmd)

        testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses')

        cmd = 'bcm-shell mod {} "{}:mod L2_ENTRY {} 1 VALID=1"'.format(1,0,entry_index)
        output = testscript.parameters['LEAF-3'].execute(cmd)
        
        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))
            
        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")


    @aetest.test
    def Validate_L2_MAC_CC(self, testscript):
        """ Validate BRCM MH MAC BRIEF CC """

        #modify nan esi mac entry to verify if cc fails
        cli_str = "sh mac address-table "
        output = testscript.parameters['LEAF-3'].execute(cli_str)
        lines = output.split('\n')
        next_hop_list = ""
        mac = ""
        for line in lines[6:]:
            #print line
            words = line.split()
            if(len(words) == 0):
                continue
            if(words[1] == '-'):
                continue
            vlan = int(words[1])
            mac = words[2]
            next_hop_list = None
            if 'nve1' in line:
                print(line)
                next_hop = line.split('nve1(')[1]
                next_hop = next_hop.split(')')[0]
                if ' ' in next_hop:
                    next_hop_list = next_hop.split()
                if next_hop_list != None:
                    break;

        cmd = 'show consistency-checker vxlan l2 mac-address {} module 1 brief | no'.format(mac)
        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute(cmd))
        
        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")      

    @aetest.test
    def Local_Link_Flap(self, testscript):
        """ Local_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")

    @aetest.test
    def Remote_Link_Flap(self, testscript):
        """ Remote_Link_Flap """

        testscript.parameters['LEAF-1'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_SPINE']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        testscript.parameters['LEAF-2'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_2_to_SPINE']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        sleep(50)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")


    @aetest.test
    def NVE_Flap(self, testscript):
        """ NVE_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface nve 1
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")


    @aetest.test
    def Remove_Add_ESI(self, testscript):
        """ Remove_Add_ESI """

        testscript.parameters['LEAF-3'].configure('''

                  no evpn esi multihoming
                  evpn esi multihoming
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")

    @aetest.test
    def UP_Link_Flap(self, testscript):
        """ UP_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface port-channel ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")

    @aetest.test
    def Access_Link_Flap(self, testscript):
        """ Access_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")


    @aetest.test
    def Remove_Add_VLAN(self, testscript):
        """ Remove_Add_VLAN """

        testscript.parameters['LEAF-3'].configure('''

                  no vlan 10,11,301-304
                  vlan 10,11,301-304
                  vlan 10
                    vn-segment 11000
                  vlan 11
                    vn-segment 11001
                  vlan 301
                    vn-segment 20001
                  vlan 302
                    vn-segment 20002
                  vlan 303
                    vn-segment 20003
                  
              ''')

        sleep(25)

        brcmMHMacCC = json.loads(testscript.parameters['LEAF-3'].execute('show consistency-checker vxlan mh mac-addresses brief | no'))

        if "CC_STATUS_NOT_OK" in brcmMHMacCC['result']['status']:
            self.failed(reason="BRCM MH MAC BRIEF CC Failed")
        else:
            self.passed(reason="BRCM MH MAC BRIEF CC Passed")


class BRCM_MH_CC_PV_VALIDATION(aetest.Testcase):

    # =============================================================================================================================#
    @aetest.test
    def VALIDATE_SINGLE_PV_MAP_CC(self, testscript):
        """ Validate BRCM MH MAC BRIEF CC """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  switchport
                  switchport mode trunk
                  switchport vlan mapping enable
                  switchport vlan mapping 1000 301
                  switchport trunk allowed vlan 301
                  no shutdown
                  
              ''')

        sleep(25)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.info("Consistency check pass for Vxlan PV\n")
        else:
            log.error("Consistency check fail for Vxlan PV\n")

        testscript.parameters['LEAF-3'].configure('''

                  default interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  
              ''')

    # =============================================================================================================================#
    @aetest.test
    def VALIDATE_OVERLAP_PV_MAP_CC(self, testscript):
        """ Validate BRCM MH MAC DETAIL CC """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  switchport
                  switchport mode trunk
                  switchport vlan mapping enable
                  switchport vlan mapping 1000 301
                  switchport vlan mapping 301 302 
                  switchport trunk allowed vlan 301-302
                  no shutdown
                  
              ''')
        
        sleep(25)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.info("Consistency check pass for Vxlan PV\n")
        else:
            log.error("Consistency check fail for Vxlan PV\n")

        testscript.parameters['LEAF-3'].configure('''

                  default interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  
              ''')

    # =============================================================================================================================#
    @aetest.test
    def VALIDATE_MULTI_OVERLAP_PV_MAP_CC(self, testscript):
        """ Validate BRCM MH MAC DETAIL CC """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  switchport
                  switchport mode trunk
                  switchport vlan mapping enable
                  switchport vlan mapping 1000 301
                  switchport vlan mapping 301 302
                  switchport vlan mapping 302 303 
                  switchport vlan mapping 303 304
                  switchport trunk allowed vlan 301-304
                  no shutdown
                  
              ''')
        
        sleep(25)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.info("Consistency check pass for Vxlan PV\n")
        else:
            log.error("Consistency check fail for Vxlan PV\n")

        testscript.parameters['LEAF-3'].configure('''

                  default interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  
              ''')

    # =============================================================================================================================#
    @aetest.test
    def VALIDATE_INNER_PV_MAP_CC(self, testscript):
        """ Validate BRCM MH MAC DETAIL CC """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  switchport
                  switchport mode trunk
                  switchport vlan mapping enable 
                  switchport vlan mapping 200 inner 300 301 
                  switchport trunk allowed vlan 301
                  no shutdown
                  
              ''')
        
        sleep(25)


        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.info("Consistency check pass for Vxlan PV\n")
        else:
            log.error("Consistency check fail for Vxlan PV\n")

        testscript.parameters['LEAF-3'].configure('''

                  default interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  
              ''')

    # =============================================================================================================================#
    @aetest.test
    def VALIDATE_SINGLE_PLUS_OVERLAP_PV_MAP_CC(self, testscript):
        """ Validate BRCM MH MAC DETAIL CC """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  switchport
                  switchport mode trunk
                  switchport vlan mapping enable
                  switchport vlan mapping 1000 301 
                  switchport vlan mapping 1001 302 
                  switchport vlan mapping 302 303
                  switchport trunk allowed vlan 301-303
                  no shutdown
                  
              ''')

        sleep(25)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.info("Consistency check pass for Vxlan PV\n")
        else:
            log.error("Consistency check fail for Vxlan PV\n")

        testscript.parameters['LEAF-3'].configure('''

                  default interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  
              ''')

    # =============================================================================================================================#
    @aetest.test
    def VALIDATE_OVERLAP_PLUS_INNER_PV_MAP_CC(self, testscript):
        """ Validate BRCM MH MAC DETAIL CC """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  switchport
                  switchport mode trunk
                  switchport vlan mapping enable
                  switchport vlan mapping 1001 301
                  switchport vlan mapping 301 302
                  switchport vlan mapping 200 inner 300 303
                  switchport trunk allowed vlan 301-303
                  no shutdown
                  
              ''')
        
        sleep(25)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.info("Consistency check pass for Vxlan PV\n")
        else:
            log.error("Consistency check fail for Vxlan PV\n")

        testscript.parameters['LEAF-3'].configure('''

                  default interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  
              ''')

    # =============================================================================================================================#
    @aetest.test
    def VALIDATE_SINGLE_PLUS_INNER_PV_MAP_CC(self, testscript):
        """ Validate BRCM MH MAC DETAIL CC """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  switchport
                  switchport mode trunk
                  switchport vlan mapping enable
                  switchport vlan mapping 1001 301
                  switchport vlan mapping 200 inner 300 302
                  switchport trunk allowed vlan 301-302
                  no shutdown
                  
              ''')
        
        sleep(25)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.info("Consistency check pass for Vxlan PV\n")
        else:
            log.error("Consistency check fail for Vxlan PV\n")

        testscript.parameters['LEAF-3'].configure('''

                  default interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  switchport
                  switchport mode trunk
                  switchport vlan mapping enable 
                  switchport vlan mapping 200 inner 300 301 
                  switchport trunk allowed vlan 301
                  no shutdown
                  
              ''')

        sleep(25)

    #=============================================================================================================================#

    @aetest.test
    def VERIFY_PV_SINGLE_INGRESS_MAP(self, testscript):
        """ Validate BRCM MH MAC DETAIL CC """

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")

        log.info("Inside setup of vxlan_pv_single_map_verify")
        #get the port num and mapped vlan on which pv cc is pass
        #self.module = 1, self.unit_no = 0
        self.port_num, self.vlan, self.ivlan, self.map_vlan = get_pv_port_num_and_ovlan_ivlan_mvlan(testscript.parameters['LEAF-3'])

        pv_output = ''
        #modify the entry in bcm table to check failure
        cmd = 'bcm-shell module 1 "0:dump VLAN_XLATE" | grep -i XLATE:VLAN_ID=%s | grep -i XLATE:PORT_NUM=%s' \
                %(str(self.vlan), str(self.port_num))
        pv_output = testscript.parameters['LEAF-3'].execute(cmd)
        self.entry_index = 0
        self.new_vlan_id = 0

        if pv_output != None:
            lines = pv_output.split(",")
            for line in lines:
                #print("--->",line)
                if "VLAN_XLATE.ipipe" in line:
                    new = line.split("ipipe0[")
                    new = new[1].split("]")
                    #print("--->",new)
                    self.entry_index = new[0]

                if "XLATE:NEW_VLAN_ID" in line:
                    new = line.split("=")
                    #new_vlan_id = new[1][2:]
                    self.new_vlan_id = new[1]

        #print("Now modify it--->",new_vlan_id,index);
        cmd = 'bcm-shell module 1 "0: modi VLAN_XLATE %s 1 XLATE:NEW_VLAN_ID=%s"'\
                %(self.entry_index, "0x0")
        pv_output = testscript.parameters['LEAF-3'].execute(cmd)
        #log.info(cmd)
        pass

        testFailed=0
        #simply run the consistency check and see if it fails after above modification
        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")

        #verify if any test failed    
        if testFailed == 1:
            log.error("Vxlan PV cc vxlan_pv_single_map_verify test failed")
            self.failed("Vxlan PV cc vxlan_pv_single_map_verify test failed")

        log.info('Vxlan Mh Mac cc vxlan_pv_single_map_verify successful')

        log.info("Inside cleanup of vxlan_pv_single_map_verify")
        #modify the entry in bcm table to correct the failure done in setup step
        #print("Now modify it--->",new_vlan_id,index);
        cmd = 'bcm-shell module 1 "0: modi VLAN_XLATE %s 1 XLATE:NEW_VLAN_ID=%s"'\
                %(self.entry_index, str(self.new_vlan_id))
        pv_output = testscript.parameters['LEAF-3'].execute(cmd)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")

    @aetest.test
    def VERIFY_PV_SINGLE_EGRESS_MAP(self, testscript):

        log.info("Inside setup of VERIFY_PV_SINGLE_EGRESS_MAP")
        #get the port num and mapped vlan on which pv cc is pass
        #self.module = 1, self.unit_no = 0
        self.port_num, self.vlan, self.ivlan, self.map_vlan = get_pv_port_num_and_ovlan_ivlan_mvlan(testscript.parameters['LEAF-3'])

        #modify the entry in bcm table to check failure
        cmd = 'bcm-shell module 1 "0:dump EGR_VLAN_XLATE" | grep -i XLATE:OLD_VLAN_ID=%s | grep -i XLATE:PORT_GROUP_ID=%s' \
                %(str(self.map_vlan), str(self.port_num))
        pv_output = testscript.parameters['LEAF-3'].execute(cmd)
        self.entry_index = 0
        self.new_vlan_id = 0

        if pv_output:
            lines = pv_output.split(",")
            for line in lines:
                #print("--->",line)
                if "EGR_VLAN_XLATE.epipe" in line:
                    new = line.split("epipe0[")
                    new = new[1].split("]")
                    #print("--->",new)
                    self.entry_index = new[0]

                if "XLATE:NEW_VLAN_ID" in line:
                    new = line.split("=")
                    #new_vlan_id = new[1][2:]
                    self.new_vlan_id = new[1]

        #print("Now modify it--->",new_vlan_id,index);
        cmd = 'bcm-shell module 1 "0: modi EGR_VLAN_XLATE %s 1 XLATE:NEW_VLAN_ID=%s"'\
                %(self.entry_index, "0x0")
        pv_output = testscript.parameters['LEAF-3'].execute(cmd)
        #log.info(cmd)
        pass

        testFailed=0

        #simply run the consistency check and see if it fails after above modification
        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")

        #verify if any test failed    
        if testFailed == 1:
            log.error("Vxlan PV cc vxlan_pv_single_map_verify test failed")
            self.failed("Vxlan PV cc vxlan_pv_single_map_verify test failed")

        log.info('Vxlan Mh Mac cc vxlan_pv_single_map_verify successful')


        log.info("Inside cleanup of vxlan_pv_single_map_verify")
        #modify the entry in bcm table to correct the failure done in setup step
        #print("Now modify it--->",new_vlan_id,index);
        cmd = 'bcm-shell module 1 "0: modi EGR_VLAN_XLATE %s 1 XLATE:NEW_VLAN_ID=%s"'\
                %(self.entry_index, str(self.new_vlan_id))
        pv_output = testscript.parameters['LEAF-3'].execute(cmd)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")

    @aetest.test
    def VERIFY_PV_SINGLE_INGRESS_OVLAN(self, testscript):

            log.info("Inside setup of VERIFY_PV_SINGLE_INGRESS_OVLAN")
            #get the port num and mapped vlan on which pv cc is pass
            #self.module = 1, self.unit_no = 0
            self.port_num, self.vlan, self.ivlan, self.map_vlan = get_pv_port_num_and_ovlan_ivlan_mvlan(testscript.parameters['LEAF-3'])

            pv_output = ''
            #modify the entry in bcm table to check failure
            cmd = 'bcm-shell module 1 "0:dump VLAN_XLATE" | grep -i XLATE:VLAN_ID=%s | grep -i XLATE:PORT_NUM=%s' \
                    %(str(self.vlan), str(self.port_num))
            pv_output = testscript.parameters['LEAF-3'].execute(cmd)
            self.entry_index = 0
            self.new_vlan_id = 0

            if pv_output != None:
                lines = pv_output.split(",")
                for line in lines:
                    #print("--->",line)
                    if "VLAN_XLATE.ipipe" in line:
                        new = line.split("ipipe0[")
                        new = new[1].split("]")
                        #print("--->",new)
                        self.entry_index = new[0]

                    if "XLATE:NEW_VLAN_ID" in line:
                        new = line.split("=")
                        #new_vlan_id = new[1][2:]
                        self.new_vlan_id = new[1]

            #print("Now modify it--->",new_vlan_id,index);
            cmd = 'bcm-shell module 1 "0: modi VLAN_XLATE %s 1 XLATE:VLAN_ID=%s"'\
                    %(self.entry_index, "0x0")
            pv_output = testscript.parameters['LEAF-3'].execute(cmd)
            #log.info(cmd)
            pass

            testFailed=0

            #simply run the consistency check and see if it fails after above modification
            if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
                log.error("Consistency check pass for Vxlan PV\n")
                testFailed=1
            else:
                log.info("Consistency check fail for Vxlan PV\n")

            #verify if any test failed    
            if testFailed == 1:
                log.error("Vxlan PV cc vxlan_pv_single_map_verify test failed")
                self.failed("Vxlan PV cc vxlan_pv_single_map_verify test failed")

            log.info('Vxlan Mh Mac cc vxlan_pv_single_map_verify successful')

            log.info("Inside cleanup of vxlan_pv_single_map_verify")
            #modify the entry in bcm table to correct the failure done in setup step
            #print("Now modify it--->",new_vlan_id,index);
            cmd = 'bcm-shell module 1 "0: modi VLAN_XLATE %s 1 XLATE:VLAN_ID=%s"'\
                    %(self.entry_index, str(self.vlan))
            pv_output = testscript.parameters['LEAF-3'].execute(cmd)

            if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
                log.error("Consistency check pass for Vxlan PV\n")
                testFailed=1
            else:
                log.info("Consistency check fail for Vxlan PV\n")

    @aetest.test
    def VERIFY_PV_SINGLE_EGRESS_OVLAN(self, testscript):

        log.info("Inside setup of VERIFY_PV_SINGLE_EGRESS_OVLAN")
        #get the port num and mapped vlan on which pv cc is pass
        #self.module = 1, self.unit_no = 0
        self.port_num, self.vlan, self.ivlan, self.map_vlan = get_pv_port_num_and_ovlan_ivlan_mvlan(testscript.parameters['LEAF-3'])

        pv_output = ''
        #modify the entry in bcm table to check failure
        cmd = 'bcm-shell module 1 "0:dump EGR_VLAN_XLATE" | grep -i XLATE:OLD_VLAN_ID=%s | grep -i XLATE:PORT_GROUP_ID=%s' \
                %(str(self.map_vlan), str(self.port_num))
        pv_output = testscript.parameters['LEAF-3'].execute(cmd)
        self.entry_index = 0
        self.new_vlan_id = 0

        if pv_output != None:
            lines = pv_output.split(",")
            for line in lines:
                #print("--->",line)
                if "EGR_VLAN_XLATE.epipe" in line:
                    new = line.split("epipe0[")
                    new = new[1].split("]")
                    #print("--->",new)
                    self.entry_index = new[0]

                if "XLATE:NEW_VLAN_ID" in line:
                    new = line.split("=")
                    #new_vlan_id = new[1][2:]
                    self.new_vlan_id = new[1]

        #print("Now modify it--->",new_vlan_id,index);
        cmd = 'bcm-shell module 1 "0: modi EGR_VLAN_XLATE %s 1 XLATE:NEW_VLAN_ID=%s"'\
                %(self.entry_index, "0x0")
        pv_output = testscript.parameters['LEAF-3'].execute(cmd)
        #log.info(cmd)
        pass

        testFailed=0

        #simply run the consistency check and see if it fails after above modification
        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")

        #verify if any test failed    
        if testFailed == 1:
            log.error("Vxlan PV cc vxlan_pv_single_map_verify test failed")
            self.failed("Vxlan PV cc vxlan_pv_single_map_verify test failed")

        log.info('Vxlan Mh Mac cc vxlan_pv_single_map_verify successful')

        log.info("Inside cleanup of vxlan_pv_single_map_verify")
        #modify the entry in bcm table to correct the failure done in setup step
        #print("Now modify it--->",new_vlan_id,index);
        cmd = 'bcm-shell module 1 "0: modi EGR_VLAN_XLATE %s 1 XLATE:NEW_VLAN_ID=%s"'\
                %(self.entry_index, str(self.new_vlan_id))
        pv_output = testscript.parameters['LEAF-3'].execute(cmd)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")

    @aetest.test
    def VERIFY_PV_SINGLE_INGRESS_IVLAN(self, testscript):

        log.info("Inside setup of VERIFY_PV_SINGLE_INGRESS_IVLAN")
        #get the port num and mapped vlan on which pv cc is pass
        #self.module = 1, self.unit_no = 0
        self.port_num, self.vlan, self.ivlan, self.map_vlan = get_pv_port_num_and_ovlan_ivlan_mvlan(testscript.parameters['LEAF-3'])

        pv_output = ''
        #modify the entry in bcm table to check failure
        cmd = 'bcm-shell module 1 "0:dump VLAN_XLATE" | grep -i XLATE:VLAN_ID=%s | grep -i XLATE:PORT_NUM=%s | grep XLATE:IVID=%s'\
                %(str(self.vlan), str(self.port_num), str(self.ivlan))
        pv_output = testscript.parameters['LEAF-3'].execute(cmd)
        self.entry_index = 0
        self.new_vlan_id = 0

        if pv_output != None:
            lines = pv_output.split(",")
            for line in lines:
                #print("--->",line)
                if "VLAN_XLATE.ipipe" in line:
                    new = line.split("ipipe0[")
                    new = new[1].split("]")
                    #print("--->",new)
                    self.entry_index = new[0]

                if "XLATE:NEW_VLAN_ID" in line:
                    new = line.split("=")
                    #new_vlan_id = new[1][2:]
                    self.new_vlan_id = new[1]

        #print("Now modify it--->",new_vlan_id,index);
        cmd = 'bcm-shell module 1 "0: mod VLAN_XLATE %s 1 XLATE:IVID=%s"'\
                %(self.entry_index, "0x0")
        pv_output = testscript.parameters['LEAF-3'].execute(cmd)
        #log.info(cmd)
        pass

        testFailed=0

        #simply run the consistency check and see if it fails after above modification
        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")

        #verify if any test failed    
        if testFailed == 1:
            log.error("Vxlan PV cc vxlan_pv_single_map_verify test failed")
            self.failed("Vxlan PV cc vxlan_pv_single_map_verify test failed")

        log.info('Vxlan Mh Mac cc vxlan_pv_single_map_verify successful')


        log.info("Inside cleanup of vxlan_pv_single_map_verify")
        #modify the entry in bcm table to correct the failure done in setup step
        #print("Now modify it--->",new_vlan_id,index);
        cmd = 'bcm-shell module 1 "0: modi VLAN_XLATE %s 1 XLATE:IVID=%s"'\
                %(self.entry_index, str(self.ivlan))
        pv_output = testscript.parameters['LEAF-3'].execute(cmd)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")


    @aetest.test
    def VERIFY_PV_SINGLE_EGRESS_IVLAN(self, testscript):

        log.info("Inside setup of VERIFY_PV_SINGLE_EGRESS_IVLAN")
        #get the port num and mapped vlan on which pv cc is pass
        #self.module = 1, self.unit_no = 0
        self.port_num, self.vlan, self.ivlan, self.map_vlan = get_pv_port_num_and_ovlan_ivlan_mvlan(testscript.parameters['LEAF-3'])

        #modify the entry in bcm table to check failure
        pv_output = ''
        cmd = 'bcm-shell module 1 "0:dump EGR_VLAN_XLATE" | grep -i XLATE:OLD_VLAN_ID=%s | grep -i XLATE:PORT_GROUP_ID=%s' \
                %(str(self.map_vlan), str(self.port_num))
        pv_output = testscript.parameters['LEAF-3'].execute(cmd)
        self.entry_index = 0
        self.new_vlan_id = 0

        if pv_output != None:
            lines = pv_output.split(",")
            for line in lines:
                #print("--->",line)
                if "EGR_VLAN_XLATE.epipe" in line:
                    new = line.split("epipe0[")
                    new = new[1].split("]")
                    #print("--->",new)
                    self.entry_index = new[0]

                if "XLATE:NEW_VLAN_ID" in line:
                    new = line.split("=")
                    #new_vlan_id = new[1][2:]
                    self.new_vlan_id = new[1]

        #print("Now modify it--->",new_vlan_id,index);
        cmd = 'bcm-shell module 1 "0: modi EGR_VLAN_XLATE %s 1 XLATE:NEW_IVID=%s"'\
                %(self.entry_index, "0x0")
        pv_output = testscript.parameters['LEAF-3'].execute(cmd)
        #log.info(cmd)
        pass

        testFailed=0

        #simply run the consistency check and see if it fails after above modification
        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")

        #verify if any test failed    
        if testFailed == 1:
            log.error("Vxlan PV cc vxlan_pv_single_map_verify test failed")
            self.failed("Vxlan PV cc vxlan_pv_single_map_verify test failed")

        log.info('Vxlan Mh Mac cc vxlan_pv_single_map_verify successful')

        log.info("Inside cleanup of vxlan_pv_single_map_verify")
        #modify the entry in bcm table to correct the failure done in setup step
        #print("Now modify it--->",new_vlan_id,index);
        cmd = 'bcm-shell module 1 "0: modi EGR_VLAN_XLATE %s 1 XLATE:NEW_IVID=%s"'\
                %(self.entry_index, str(self.ivlan))
        pv_output = testscript.parameters['LEAF-3'].execute(cmd)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")


    @aetest.test
    def Local_Link_Flap(self, testscript):
        """ Local_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")

    @aetest.test
    def Remote_Link_Flap(self, testscript):
        """ Remote_Link_Flap """

        testscript.parameters['LEAF-1'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_1_to_SPINE']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        testscript.parameters['LEAF-2'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_2_to_SPINE']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")


    @aetest.test
    def NVE_Flap(self, testscript):
        """ NVE_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface nve 1
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")


    @aetest.test
    def Remove_Add_ESI(self, testscript):
        """ Remove_Add_ESI """

        testscript.parameters['LEAF-3'].configure('''

                  no evpn esi multihoming
                  evpn esi multihoming
                  
              ''')

        sleep(25)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")

    @aetest.test
    def UP_Link_Flap(self, testscript):
        """ UP_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface port-channel ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")

    @aetest.test
    def Access_Link_Flap(self, testscript):
        """ Access_Link_Flap """

        testscript.parameters['LEAF-3'].configure('''

                  interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
                  shutdown
                  no shutdown
                  
              ''')

        sleep(25)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")


    @aetest.test
    def Remove_Add_VLAN(self, testscript):
        """ Remove_Add_VLAN """

        testscript.parameters['LEAF-3'].configure('''

                  no vlan 10,11,301-304
                  vlan 10,11,301-304
                  vlan 10
                    vn-segment 11000
                  vlan 11
                    vn-segment 11001
                  vlan 301
                    vn-segment 20001
                  vlan 302
                    vn-segment 20002
                  vlan 303
                    vn-segment 20003
                  
              ''')

        sleep(25)

        if verify_vxlan_pv_cc(testscript.parameters['LEAF-3'], True):
            log.error("Consistency check pass for Vxlan PV\n")
            testFailed=1
        else:
            log.info("Consistency check fail for Vxlan PV\n")

# # ########################################################################
# # ####                       COMMON CLEANUP SECTION                    ###
# # ########################################################################
# # #
# # ## Remove the BASE CONFIGURATION that was applied earlier in the 
# # ## common cleanup section, clean the left over


class common_cleanup(aetest.CommonCleanup):
    """ Common Cleanup for Sample Test """

    @aetest.subsection
    def cleanUP_LEAF1(self, testscript):
        """ Common Cleanup subsection """
        log.info(banner("LEAF1 common cleanup starts here"))

        if not testscript.parameters['script_flags']['skip_device_cleanup']:

            vrfConfigurations = ''
            l3_vrf_count_iter = 1
            while l3_vrf_count_iter <= testscript.parameters['forwardingSysDict']['VRF_count']:
                vrfConfigurations += 'no vrf context ' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(l3_vrf_count_iter) + '\n'
                l3_vrf_count_iter += 1

            featureConfigurations = ''
            for feature in testscript.parameters['LeafFeatureList']:
                featureConfigurations += 'no feature ' + str(feature) + '\n'

            testscript.parameters['LEAF-1'].configure('''                        
    
                        default interface ''' + str(testscript.parameters['intf_LEAF_1_to_SPINE']) + '''
                        default interface ''' + str(testscript.parameters['intf_LEAF_1_to_FAN_1']) + '''
    
                        no vlan 10-11,301-304
                        no interface loop0
                        no interface loop1
                        
                        no interface port-channel200
                        no interface port-channel211
                        
                        no feature nv overlay
                        no nv overlay evpn
    
                    ''' + str(vrfConfigurations) + '''
                    ''' + str(featureConfigurations) + '''
                    
                        no feature-set mpls
                    
                    ''', timeout=900)
            testscript.parameters['LEAF-1'].execute("show run | no", timeout=900)

        else:
            self.passed(reason="Skipped device cleanup as requested")

    @aetest.subsection
    def cleanUP_LEAF2(self, testscript):
        """ Common Cleanup subsection """
        log.info(banner("LEAF2 common cleanup starts here"))

        if not testscript.parameters['script_flags']['skip_device_cleanup']:

            vrfConfigurations = ''
            l3_vrf_count_iter = 1
            while l3_vrf_count_iter <= testscript.parameters['forwardingSysDict']['VRF_count']:
                vrfConfigurations += 'no vrf context ' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(l3_vrf_count_iter) + '\n'
                l3_vrf_count_iter += 1

            featureConfigurations = ''
            for feature in testscript.parameters['LeafFeatureList']:
                featureConfigurations += 'no feature ' + str(feature) + '\n'

            testscript.parameters['LEAF-2'].configure('''                        
    
                        default interface ''' + str(testscript.parameters['intf_LEAF_2_to_SPINE']) + '''
                        default interface ''' + str(testscript.parameters['intf_LEAF_2_to_FAN_1']) + '''
    
                        no vlan 10-11,301-304
                        no interface loop0
                        no interface loop1
    
                        no interface port-channel200
                        no interface port-channel212
                        
                        no feature nv overlay
                        no nv overlay evpn
    
                    ''' + str(vrfConfigurations) + '''
                    ''' + str(featureConfigurations) + '''
    
                        no feature-set mpls
    
                    ''', timeout=900)
            testscript.parameters['LEAF-2'].execute("show run | no", timeout=900)

        else:
            self.passed(reason="Skipped device cleanup as requested")

    @aetest.subsection
    def cleanUP_LEAF3(self, testscript):
        """ Common Cleanup subsection """
        log.info(banner("LEAF3 common cleanup starts here"))

        if not testscript.parameters['script_flags']['skip_device_cleanup']:

            vrfConfigurations = ''
            l3_vrf_count_iter = 1
            while l3_vrf_count_iter <= testscript.parameters['forwardingSysDict']['VRF_count']:
                vrfConfigurations += 'no vrf context ' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(l3_vrf_count_iter) + '\n'
                l3_vrf_count_iter += 1

            featureConfigurations = ''
            for feature in testscript.parameters['LeafFeatureList']:
                featureConfigurations += 'no feature ' + str(feature) + '\n'

            testscript.parameters['LEAF-3'].configure('''                        
    
                        default interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''
                        default interface ''' + str(testscript.parameters['intf_LEAF_3_to_FAN_2']) + '''
    
                        no vlan 10-11,301-304
                        no interface loop0
                        no interface loop1
    
                        no interface port-channel200
                        no interface port-channel213
                        
                        no feature nv overlay
                        no nv overlay evpn
    
                    ''' + str(vrfConfigurations) + '''
                    ''' + str(featureConfigurations) + '''
    
                        no feature-set mpls
    
                    ''', timeout=900)
            testscript.parameters['LEAF-3'].execute("show run | no", timeout=900)

        else:
            self.passed(reason="Skipped device cleanup as requested")

    @aetest.subsection
    def cleanUP_SPINE(self, testscript):
        """ Common Cleanup subsection """
        log.info(banner("SPINE common cleanup starts here"))

        if not testscript.parameters['script_flags']['skip_device_cleanup']:

            featureConfigurations = ''
            for feature in testscript.parameters['spineFeatureList']:
                featureConfigurations += 'no feature ' + str(feature) + '\n'

            testscript.parameters['SPINE'].configure('''                        
    
                        default interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_1']) + '''
                        default interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_2']) + '''
                        default interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_3']) + '''
    
                        no vlan 10-11,301-304
                        no interface loop0
    
                        no interface port-channel211
                        no interface port-channel212
                        no interface port-channel213
                        
                        ''' + str(featureConfigurations) + '''
                    ''', timeout=900)
            testscript.parameters['SPINE'].execute("show run | no", timeout=900)

        else:
            self.passed(reason="Skipped device cleanup as requested")

    @aetest.subsection
    def cleanUP_FAN1(self, testscript):
        """ Common Cleanup subsection """
        log.info(banner("FAN-1 common cleanup starts here"))

        if not testscript.parameters['script_flags']['skip_device_cleanup']:

            featureConfigurations = ''
            for feature in testscript.parameters['fanOutFeatureList']:
                featureConfigurations += 'no feature ' + str(feature) + '\n'

            testscript.parameters['FAN-1'].configure('''                        
    
                        default interface ''' + str(testscript.parameters['intf_FAN_1_to_LEAF_1']) + '''
                        default interface ''' + str(testscript.parameters['intf_FAN_1_to_LEAF_2']) + '''
    
                        no vlan 10-11,301-304
    
                        no interface port-channel200
                        
                        ''' + str(featureConfigurations) + '''
    
                    ''', timeout=900)
            testscript.parameters['FAN-1'].execute("show run | no", timeout=900)

        else:
            self.passed(reason="Skipped device cleanup as requested")

    @aetest.subsection
    def cleanUP_FAN2(self, testscript):
        """ Common Cleanup subsection """
        log.info(banner("FAN-2 common cleanup starts here"))

        if not testscript.parameters['script_flags']['skip_device_cleanup']:

            featureConfigurations = ''
            for feature in testscript.parameters['fanOutFeatureList']:
                featureConfigurations += 'no feature ' + str(feature) + '\n'

            testscript.parameters['FAN-2'].configure('''                        
    
                        default interface ''' + str(testscript.parameters['intf_FAN_2_to_LEAF_3']) + '''
    
                        no vlan 10-11,301-304
    
                        no interface port-channel200
                        
                        ''' + str(featureConfigurations) + '''
    
                    ''', timeout=900)
            testscript.parameters['FAN-1'].execute("show run | no", timeout=900)

        else:
            self.passed(reason="Skipped device cleanup as requested")

if __name__ == '__main__':  # pragma: no cover
    aetest.main()
