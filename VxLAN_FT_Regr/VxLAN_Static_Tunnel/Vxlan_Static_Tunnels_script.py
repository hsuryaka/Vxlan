#!/usr/bin/env python

###################################################################
###                  Importing Libraries                        ###
###################################################################
import logging
import time
import yaml
import ipaddress as ip
from yaml import Loader
from pyats import aetest
from pyats.log.utils import banner
import re
from pyats.aereport.utils.argsvalidator import ArgsValidator
ArgVal = ArgsValidator()

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

import unicon.statemachine.statemachine
from unicon.eal.dialogs import Statement, Dialog

tcl_dependencies = [
 '/auto/dc3-india/script_repository/IXIA_9.00_64bit//lib/PythonApi',
 '/auto/dc3-india/script_repository/IXIA_9.00_64bit//lib/TclApi/IxTclProtocol',
 '/auto/dc3-india/script_repository/IXIA_9.00_64bit//lib/TclApi/IxTclNetwork'
 ]
from ixiatcl import IxiaTcl 
from ixiahlt import IxiaHlt
from ixiangpf import IxiaNgpf
from ixiaerror import IxiaError

ixiatcl = IxiaTcl(tcl_autopath=tcl_dependencies)#
#ixiatcl = IxiaTcl()
ixiahlt = IxiaHlt(ixiatcl)
ixiangpf = IxiaNgpf(ixiahlt)
# ------------------------------------------------------
# Import and initialize EVPN specific libraries
# ------------------------------------------------------
import vxlanStatic_tunnels_lib
staticLib     = vxlanStatic_tunnels_lib.configureVxlanStatic()
verifyEvpn  = vxlanStatic_tunnels_lib.verifyEVPNconfiguration()

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

#-------------------------------------------------------
#Import tcam libraries
#-------------------------------------------------------
#import tcam_lib
# ------------------------------------------------------
# Import and initialize NIA specific libraries
# ------------------------------------------------------
#import vxlanNIA_lib
#niaLib = vxlanNIA_lib.verifyVxlanNIA()

###Declare global variables
#global stream_id
stream_id = ''
###################################################################
###                  User Library Methods                       ###
###################################################################

def increment_prefix_network(pref, count):
    size = 1 << (pref.network.max_prefixlen - pref.network.prefixlen)
    pref_lst = []
    for i in range(count):
        pref_lst.append(str((pref.ip+size*i)) + "/" + str(pref.network.prefixlen))
    return pref_lst

def verifyDevicePingsForIxiaTraffic(testscript):

    forwardingSysDict = testscript.parameters['forwardingSysDict']
    vrf_id = forwardingSysDict['VRF_id_start']
    l2_vlan_ipv4_start =  testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_start']
    l2_vlan_ipv4_mask = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_ipv4_mask']

    # ----------------------------------------------------
    # LEAF-1 Counter Variables
    # ----------------------------------------------------
    l3_vrf_count_iter = 0
    l2_vlan_count_iter = 0
    ip_index = 0

    total_ip_count = int(forwardingSysDict['VLAN_PER_VRF_count']) * int(forwardingSysDict['VRF_count'])
    l2_ipv4s = increment_prefix_network(ip.IPv4Interface(str(l2_vlan_ipv4_start) + str(l2_vlan_ipv4_mask)),total_ip_count)

    while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
        while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:

            testscript.parameters['LEAF-1'].configure('''ping '''+str(l2_ipv4s[ip_index])+''' vrf '''+'EVPN-VRF-'+str(vrf_id))
            testscript.parameters['LEAF-2'].configure('''ping '''+str(l2_ipv4s[ip_index])+''' vrf '''+'EVPN-VRF-'+str(vrf_id))
            testscript.parameters['LEAF-3'].configure('''ping '''+str(l2_ipv4s[ip_index])+''' vrf '''+'EVPN-VRF-'+str(vrf_id))

            l2_vlan_count_iter += 1
        l3_vrf_count_iter += 1
        vrf_id += 1

def configure_ixia_IP_UCAST_L3_traffic_item(args_dict):
    # Define Arguments Definition
    args_def = [
        
        ('src_hndl' , 'm', [str, list]),
        ('dst_hndl' , 'm', [str, list]),
        ('TI_name' , 'm', [str]),
        ('circuit' , 'm', [str]),
        ('rate_pps' , 'm', [str]),
        ('bi_dir' , 'm', [str, int, bool]),
        ('end_point_set', '0', [str, int, bool]),
    ]
    
    # Validate Arguments
    try:
        ArgVal.validate(args_def, **args_dict)
    except Exception as e:
        log.info("Exception seen:" + str(e))
        # log.info(help_string)
        return 0

    _result_ = ixiahlt.traffic_config(
        mode                           = "create",
        traffic_generator              = "ixnetwork_540",
        endpointset_count              = "1",
        emulation_src_handle           = args_dict['src_hndl'],
        emulation_dst_handle           = args_dict['dst_hndl'],
        bidirectional                  = args_dict['bi_dir'],
        name                           = args_dict['TI_name'],
        circuit_endpoint_type          = args_dict['circuit'],
        rate_pps                       = args_dict['rate_pps'],
        frame_size                     = args_dict['frame_size'],
        transmit_mode                  = "continuous",
        vlan                           = "enable",
        vlan_id                        = args_dict['vlan_id'],
        vlan_id_tracking               = 1,
        vlan_id_mode                   = "increment",
        vlan_id_step                   = args_dict['vlanid_step'],
        vlan_id_count                  = args_dict['vlanid_count'],
        )
    log.info("_result_['status']:"+str(_result_['status']))
    log.info(_result_)

    if _result_['status'] == "1":
        log.info("Configured Traffic Item successfully")
        return _result_['stream_id']
    else:
        log.info("Configuring Traffic Item Failed")
        return 0

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

    @aetest.subsection
    def connecting_to_devices(self, testscript, testbed, uut_list, configurationFile, script_flags=None):
        """ common setup subsection: Connecting to devices """

        # =============================================================================================================================#
        # Grab the device object of the uut device with that name
        if script_flags is None:
            script_flags = {}
        SPINE = testscript.parameters['SPINE'] = testbed.devices[uut_list['SPINE']]
        #LB    = testscript.parameters['LB'] = testbed.devices[uut_list['LB']]
        LEAF_1 = testscript.parameters['LEAF-1'] = testbed.devices[uut_list['LEAF-1']]
        LEAF_2 = testscript.parameters['LEAF-2'] = testbed.devices[uut_list['LEAF-2']]
        #LEAF_3 = testscript.parameters['LEAF-3'] = testbed.devices[uut_list['LEAF-3']]

        #FAN_1 = testscript.parameters['FAN-1'] = testbed.devices[uut_list['FAN-1']]
        #FAN_2 = testscript.parameters['FAN-2'] = testbed.devices[uut_list['FAN-2']]

        IXIA = testscript.parameters['IXIA'] = testbed.devices[uut_list['ixia']]

        testscript.parameters['ixia_chassis_ip'] = str(IXIA.connections.a.ip)
        testscript.parameters['ixia_tcl_server'] = str(IXIA.connections.alt.ip)
        testscript.parameters['ixia_tcl_port'] = str(IXIA.connections.alt.port)

        # =============================================================================================================================#
        # Connect to the device
        SPINE.connect()
       
        LEAF_1.connect()
        LEAF_2.connect()
        
        #FAN_1.connect()
        #FAN_2.connect()

        device_list.append(SPINE)
        
        device_list.append(LEAF_1)
        device_list.append(LEAF_2)
       
        #device_list.append(FAN_1)
        #device_list.append(FAN_2)

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
        #testscript.parameters['LEAF_3_dict']            = configuration['LEAF_3_dict']
        testscript.parameters['SPINE_1_dict']            = configuration['SPINE_1_dict']
        #testscript.parameters['LB_dict']            = configuration['LB_dict']
        testscript.parameters['forwardingSysDict']      = configuration['FWD_SYS_dict']

        testscript.parameters['LEAF_2_TGEN_dict']       = configuration['LEAF_2_TGEN_data']
        testscript.parameters['LEAF_3_TGEN_dict']       = configuration['LEAF_3_TGEN_data']

        #testscript.parameters['leafVPCDictData']        = {LEAF_1 : configuration['LEAF_1_dict'], LEAF_2 : configuration['LEAF_2_dict']}
        testscript.parameters['leavesDictList']         = [configuration['LEAF_1_dict'], configuration['LEAF_2_dict']]
        testscript.parameters['leavesDict']             = {LEAF_1 : configuration['LEAF_1_dict'],
                                                           LEAF_2 : configuration['LEAF_2_dict']}
        testscript.parameters['tcam_config_dict']       = configuration['tcam_config_dict']

        testscript.parameters['VTEP_List'] = [testscript.parameters['LEAF_1_dict'], testscript.parameters['LEAF_2_dict']]
        #testscript.parameters['FAN_1_dict']       = configuration['FAN_1_dict']
        #testscript.parameters['FAN_2_dict']       = configuration['FAN_2_dict']
        
        

    # *****************************************************************************************************************************#

    @aetest.subsection
    def get_interfaces(self, testscript):
        """ common setup subsection: Getting required Connections for Test """

        SPINE = testscript.parameters['SPINE']
        #LB    = testscript.parameters['LB']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        #LEAF_3 = testscript.parameters['LEAF-3']
        #FAN_1 = testscript.parameters['FAN-1']
        #FAN_2 = testscript.parameters['FAN-2']
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
        testscript.parameters['intf_SPINE_to_LEAF_1']       = SPINE.interfaces['SPINE_to_LEAF-1'].intf
        testscript.parameters['intf_SPINE_to_LEAF_2']       = SPINE.interfaces['SPINE_to_LEAF-2'].intf
        #testscript.parameters['intf_SPINE_to_LEAF_3']       = SPINE.interfaces['SPINE_to_LEAF-3'].intf

        #testscript.parameters['intf_LEAF_1_to_LEAF_2_1']    = LEAF_1.interfaces['LEAF-1_to_LEAF-2_1'].intf
        #testscript.parameters['intf_LEAF_1_to_LEAF_2_2']    = LEAF_1.interfaces['LEAF-1_to_LEAF-2_2'].intf
        testscript.parameters['intf_LEAF_1_to_SPINE']       = LEAF_1.interfaces['LEAF-1_to_SPINE'].intf
        #testscript.parameters['intf_LEAF_1_to_FAN_2']       = LEAF_1.interfaces['LEAF-1_to_FAN-2'].intf
        testscript.parameters['intf_LEAF_1_to_IXIA']       = LEAF_1.interfaces['LEAF-1_to_IXIA'].intf

        #testscript.parameters['intf_LEAF_2_to_LEAF_1_1']    = LEAF_2.interfaces['LEAF-2_to_LEAF-1_1'].intf
        #testscript.parameters['intf_LEAF_2_to_LEAF_1_2']    = LEAF_2.interfaces['LEAF-2_to_LEAF-1_2'].intf
        testscript.parameters['intf_LEAF_2_to_SPINE']       = LEAF_2.interfaces['LEAF-2_to_SPINE'].intf
        testscript.parameters['intf_LEAF_2_to_IXIA']       = LEAF_2.interfaces['LEAF-2_to_IXIA'].intf
        
        testscript.parameters['intf_IXIA_to_LEAF_1']         = IXIA.interfaces['IXIA_to_LEAF-1'].intf
        testscript.parameters['intf_IXIA_to_LEAF_2']         = IXIA.interfaces['IXIA_to_LEAF-2'].intf
        
        testscript.parameters['ixia_int_list'] = str(testscript.parameters['intf_IXIA_to_LEAF_1']) + " " + str(testscript.parameters['intf_IXIA_to_LEAF_2'])
        #testscript.parameters['intf_FAN_1_to_LEAF_1']       = FAN_1.interfaces['FAN-1_to_LEAF-1'].intf
        #testscript.parameters['intf_FAN_1_to_LEAF_2']       = FAN_1.interfaces['FAN-1_to_LEAF-2'].intf
        #testscript.parameters['intf_FAN_1_to_IXIA']         = FAN_1.interfaces['FAN-1_to_IXIA'].intf

        #testscript.parameters['intf_FAN_2_to_LEAF_1']       = FAN_2.interfaces['FAN-2_to_LEAF-1'].intf
        #testscript.parameters['intf_FAN_2_to_IXIA']         = FAN_2.interfaces['FAN-2_to_IXIA'].intf

        

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
                                           /               \\
                                          /                 \\
                                         /                   \\
                                        /                     \\
                                       /                       \\
                                      /                         \\
                            +-----------+                     +-----------+
                            |   LEAF-1  |                     |   LEAF-2 |
                            +-----------+                     +-----------+
                                   \\                              |
                                    \\                             |
                                     \\                            |
                                      \\                           |
                                    +-----------+                   |
                                          |                         |      
                                          |                         |      
                                        Fan2                      Fan1     
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

            leafLst                 = [testscript.parameters['LEAF-1'], testscript.parameters['LEAF-2']]
            spineFeatureList        = ['ospf','ospfv3', 'bgp', 'pim', 'lacp', 'nv overlay']
            #vpcLeafFeatureList      = ['vpc','ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp', 'nv overlay']
            LeafFeatureList         = ['ospf','ospfv3', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp','ofm']
            #FanFeatureList       = ['ospf', 'interface-vlan', 'bfd']
            configFeatureSet_status = []
            configFeatureSet_msgs = ""

            # --------------------------------
            # Configure Feature Set on Leafs
#            featureSetConfigureLeafs_status = infraConfig.configureVerifyFeatureSet(leafLst, ['mpls'])
#            if featureSetConfigureLeafs_status['result']:
#                log.info("Passed Configuring feature Sets on all Leafs")
#            else:
#                log.debug("Failed Configuring feature Sets on all Leafs")
#                configFeatureSet_msgs += featureSetConfigureLeafs_status['log']
#                configFeatureSet_status.append(0)
            # --------------------------------
            # Configure checkpoint on switches
            try:
                testscript.parameters['SPINE'].execute('checkpoint spine1')
                testscript.parameters['LEAF-1'].execute('checkpoint Leaf-1')
                testscript.parameters['LEAF-2'].execute('checkpoint Leaf-2')
                #testscript.parameters['FAN-1'].execute('checkpoint FAN-1')
                #testscript.parameters['FAN-2'].execute('checkpoint FAN-2')
            except Exception as error:
                log.debug("Unable to configure chckpoint- Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring checkpoint', goto=['common_cleanup'])
                
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
#            featureSetConfigureLeaf1_status = infraConfig.configureVerifyFeatureSet(testscript.parameters['LEAF-1'], ['mpls'])
#            if featureSetConfigureLeaf1_status['result']:
#                log.info("Passed Configuring feature-sets on LEAF-1")
#            else:
#                log.debug("Failed configuring feature-sets on LEAF-1")
#                configFeatureSet_msgs += featureSetConfigureLeaf1_status['log']
#                configFeatureSet_status.append(0)

            featureConfigureLeaf1_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-1'], LeafFeatureList)
            if featureConfigureLeaf1_status['result']:
                log.info("Passed Configuring features on LEAF-1")
            else:
                log.debug("Failed configuring features on LEAF-1")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-2
#            featureSetConfigureLeaf2_status = infraConfig.configureVerifyFeatureSet(testscript.parameters['LEAF-2'], ['mpls'])
#            if featureSetConfigureLeaf2_status['result']:
#                log.info("Passed Configuring feature-sets on LEAF-2")
#            else:
#                log.debug("Failed configuring feature-sets on LEAF-2")
#                configFeatureSet_msgs += featureSetConfigureLeaf1_status['log']
#                configFeatureSet_status.append(0)

            featureConfigureLeaf2_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-2'], LeafFeatureList)
            if featureConfigureLeaf2_status['result']:
                log.info("Passed Configuring features on LEAF-2")
            else:
                log.debug("Failed configuring features on LEAF-2")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-3
#            featureSetConfigureLeaf3_status = infraConfig.configureVerifyFeatureSet(testscript.parameters['LEAF-3'], ['mpls'])
#            if featureSetConfigureLeaf3_status['result']:
#                log.info("Passed Configuring feature-sets on LEAF-3")
#            else:
#                log.debug("Failed configuring feature-sets on LEAF-3")
#                configFeatureSet_msgs += featureSetConfigureLeaf1_status['log']
#                configFeatureSet_status.append(0)

#            featureConfigureLeaf3_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-3'], LeafFeatureList)
#            if featureConfigureLeaf3_status['result']:
#                log.info("Passed Configuring features on LEAF-3")
#            else:
#                log.debug("Failed configuring features on LEAF-3")
#                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
#                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LB
#            featureConfigureLB_status = infraConfig.configureVerifyFeature(testscript.parameters['LB'], LBFeatureList)
#            if featureConfigureLB_status['result']:
#                log.info("Passed Configuring features on LB")
#            else:
#                log.debug("Failed configuring features on LB")
#                configFeatureSet_msgs += featureConfigureLB_status['log']
#                configFeatureSet_status.append(0)

            


            if 0 in configFeatureSet_status:
                self.failed(reason=configFeatureSet_msgs, goto=['next_tc'])

        else:
            self.passed(reason="Skipped Device Configuration as per request")

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_SPINE(self, testscript):
        """ Device Bring-up subsection: Configuring SPINE """

        staticLib.configureEVPNSpines([testscript.parameters['SPINE']], testscript.parameters['forwardingSysDict'] , testscript.parameters['leavesDictList'])

        try:
            testscript.parameters['SPINE'].configure('''
            
                interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_1']) + '''
                  channel-group ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                  no shutdown
                  
                interface ''' + str(testscript.parameters['intf_SPINE_to_LEAF_2']) + '''
                  channel-group ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                  no shutdown
                  
                  
            ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on SPINE', goto=['cleanup'])

    # *****************************************************************************************************************************#

    @aetest.test
    def configure_LEAF_1_2(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        staticLib.configureStaticLeaf(testscript.parameters['LEAF-1'], testscript.parameters['forwardingSysDict'], testscript.parameters['LEAF_1_dict'], testscript.parameters['LEAF_2_dict'])
        staticLib.configureStaticLeaf(testscript.parameters['LEAF-2'], testscript.parameters['forwardingSysDict'], testscript.parameters['LEAF_2_dict'], testscript.parameters['LEAF_1_dict'])
        #forwardingSysDict = testscript.parameters['forwardingSysDict']

        try:
            testscript.parameters['LEAF-1'].configure('''
                
              interface ''' + str(testscript.parameters['intf_LEAF_1_to_SPINE']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                no shutdown
                
                
               interface ''' + str(testscript.parameters['intf_LEAF_1_to_IXIA']) + '''
                   switchport
                   switchport mode trunk
                   no shutdown  
               
                 
           ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-1', goto=['next_tc'])

        try:
            testscript.parameters['LEAF-2'].configure('''
                
              interface ''' + str(testscript.parameters['intf_LEAF_2_to_SPINE']) + '''
                channel-group ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                no shutdown
                
              interface ''' + str(testscript.parameters['intf_LEAF_2_to_IXIA']) + '''
                   switchport
                   switchport mode trunk
                   no shutdown
              ''')
              
              
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring on LEAF-2', goto=['cleanup'])

    # *****************************************************************************************************************************#


   
            
    #=============================================================================================================================#
    @aetest.test
    def perform_copy_r_s(self, testscript):
        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Save all configurations (copy r s) """

        testscript.parameters['LEAF-1'].configure("copy r s", timeout=300)
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=300)
        #testscript.parameters['LEAF-3'].configure("copy r s", timeout=300)

        time.sleep(60)

    # *****************************************************************************************************************************#


class VERIFY_NETWORK(aetest.Testcase):
    """This is description for my testcase one"""

    # =============================================================================================================================#
#    @aetest.test
#    def verify_vpc(self, testscript):
#        """ VERIFY_NETWORK subsection: Verify VPC """
#
#        LEAF_1 = testscript.parameters['LEAF-1']
#        LEAF_2 = testscript.parameters['LEAF-2']
#
#        VPCStatus = infraVerify.verifyVPCStatus(LEAF_1, LEAF_2)
#
#        if VPCStatus['result']:
#            log.info(VPCStatus['log'])
#            log.info("PASS : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Successfully Verified\n\n")
#        else:
#            log.info(VPCStatus['log'])
#            log.info("FAIL : VPC Status for '" + str(LEAF_1) + "' and '" + str(LEAF_2) + "' is Failed\n\n")
#            self.failed()

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

    # =============================================================================================================================#

    # =============================================================================================================================#
    @aetest.test
    def verifyTunnel(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        TunnelData = verifyEvpn.verifyTunnelProfile(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if TunnelData['result'] is 1:
            log.info("PASS : Successfully verified Tunnel Data\n\n")
            self.passed(reason=TunnelData['log'])
        else:
            log.info("FAIL : Failed to verify Tunnel Data\n\n")
            self.failed(reason=TunnelData['log'])

    # =============================================================================================================================#
    
            
class IXIA_CONFIGURATION(aetest.Testcase):
    

    # =============================================================================================================================#
    @aetest.test
    def CONNECT_IXIA_CHASSIS(self, testscript):
        

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            # Get IXIA paraameters
            ixia_chassis_ip = testscript.parameters['ixia_chassis_ip']
            ixia_tcl_server = testscript.parameters['ixia_tcl_server']
            ixia_tcl_port = testscript.parameters['ixia_tcl_port']
            ixia_int_list = testscript.parameters['ixia_int_list']

            ix_int_1 = testscript.parameters['intf_IXIA_to_LEAF_1']
            ix_int_2 = testscript.parameters['intf_IXIA_to_LEAF_2']

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

    # =============================================================================================================================#
    @aetest.test
    def CREATE_IXIA_TOPOLOGIES(self, testscript):
                
                                         
        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            TOPO_1_dict = {'topology_name': 'LEAF-1-TG',
                           'device_grp_name': 'LEAF-1-TG',
                           'port_handle': testscript.parameters['port_handle_1']}

            TOPO_2_dict = {'topology_name': 'LEAF-2-TG',
                           'device_grp_name': 'LEAF-2-TG',
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

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_IXIA_INTERFACES(self, testscript):
        

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            P1 = testscript.parameters['port_handle_1']
            P2 = testscript.parameters['port_handle_2']

            P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
            P2_dict = testscript.parameters['LEAF_3_TGEN_dict']

            P1_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP1']['dev_grp_hndl'],
                             'port_hndl': P1,
                             'no_of_ints': P1_dict['no_of_ints'],
                             'phy_mode': P1_dict['phy_mode'],
                             'mac': P1_dict['mac'],
                             'mac_step': P1_dict['mac_step'],
                             'protocol': P1_dict['protocol'],
                             'v4_addr': P1_dict['v4_addr'],
                             'v4_addr_step': P1_dict['v4_addr_step'],
                             'v4_gateway': P1_dict['v4_addr_gateway'],
                             'v4_gateway_step': P1_dict['v4_gateway_step'],
                             'v4_netmask': P1_dict['netmask'],
                             'v6_addr': P1_dict['v6_addr'],
                             'v6_addr_step': P1_dict['v6_addr_step'],
                             'v6_gateway': P1_dict['v6_gateway'],
                             'v6_gateway_step': P1_dict['v6_gateway_step'],
                             'v6_netmask': P1_dict['v6_netmask'],
                             'vlan_id': P1_dict['vlan_id'],
                             'vlan_user_priority': P1_dict['vlan_user_priority'],
                             'vlan_id_step': P1_dict['vlan_id_step'],
                             'frame_size': P1_dict['frame_size'],
                             'L3_dst_addr': P1_dict['L3_dst_addr']}

            P2_int_dict_1 = {'dev_grp_hndl': testscript.parameters['IX_TP2']['dev_grp_hndl'],
                             'port_hndl': P2,
                             'no_of_ints': P2_dict['no_of_ints'],
                             'phy_mode': P2_dict['phy_mode'],
                             'mac': P2_dict['mac'],
                             'mac_step': P2_dict['mac_step'],
                             'protocol': P2_dict['protocol'],
                             'v4_addr': P2_dict['v4_addr'],
                             'v4_addr_step': P2_dict['v4_addr_step'],
                             'v4_gateway': P2_dict['v4_addr_gateway'],
                             'v4_gateway_step': P2_dict['v4_gateway_step'],
                             'v4_netmask': P2_dict['netmask'],
                             'v6_addr': P2_dict['v6_addr'],
                             'v6_addr_step': P2_dict['v6_addr_step'],
                             'v6_gateway': P2_dict['v6_gateway'],
                             'v6_gateway_step': P2_dict['v6_gateway_step'],
                             'v6_netmask': P2_dict['v6_netmask'],
                             'vlan_id': P2_dict['vlan_id'],
                             'vlan_user_priority': P1_dict['vlan_user_priority'],
                             'vlan_id_step': P2_dict['vlan_id_step'],
                             'frame_size': P2_dict['frame_size'],
                             'L3_dst_addr': P2_dict['L3_dst_addr']}

            P1_IX_int_data = ixLib.configure_multi_ixia_interface(P1_int_dict_1)
            P2_IX_int_data = ixLib.configure_multi_ixia_interface(P2_int_dict_1)

            if P1_IX_int_data == 0 or P2_IX_int_data == 0:
                log.debug("Configuring IXIA Interface failed")
                self.errored("Configuring IXIA Interface failed", goto=['cleanup'])
            else:
                log.info("Configured IXIA Interface Successfully")

            testscript.parameters['IX_TP1']['eth_handle'] = P1_IX_int_data['eth_handle']
            testscript.parameters['IX_TP1']['ipv4_handle'] = P1_IX_int_data['ipv4_handle']
            testscript.parameters['IX_TP1']['ipv6_handle'] = P1_IX_int_data['ipv6_handle']
            #testscript.parameters['IX_TP1']['port_handle'] = P1_IX_int_data['port_handle']
            testscript.parameters['IX_TP1']['topo_int_handle'] = P1_IX_int_data['topo_int_handle'].split(" ")

            testscript.parameters['IX_TP2']['eth_handle'] = P2_IX_int_data['eth_handle']
            testscript.parameters['IX_TP2']['ipv4_handle'] = P2_IX_int_data['ipv4_handle']
            testscript.parameters['IX_TP2']['ipv6_handle'] = P2_IX_int_data['ipv6_handle']
            #testscript.parameters['IX_TP2']['port_handle'] = P2_IX_int_data['port_handle']
            testscript.parameters['IX_TP2']['topo_int_handle'] = P2_IX_int_data['topo_int_handle'].split(" ")

            log.info("IXIA Port 1 Handles")
            log.info(testscript.parameters['IX_TP1'])
            log.info("IXIA Port 2 Handles")
            log.info(testscript.parameters['IX_TP2'])

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
#     @aetest.test
#     def CONFIGURE_IXIA_IGMP_GROUPS(self, testscript):
#         """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """
# 
# #        #IX_TP1 = testscript.parameters['IX_TP1']
# #        IX_TP2 = testscript.parameters['IX_TP2']
# #        P1_TGEN_dict = testscript.parameters['LEAF_12_TGEN_dict']
# #        P2_dict = testscript.parameters['LEAF_3_TGEN_dict']
# #
# #       
# #
# #        IGMP_dict = {'ipv4_hndl': IX_TP2['ipv4_handle'],
# #                     'igmp_ver': P2_dict['igmp_ver'],
# #                     'mcast_grp_ip': P2_dict['mcast_grp_ip'],
# #                     'mcast_grp_ip_step': P2_dict['mcast_grp_ip_step'],
# #                     'no_of_grps': P2_dict['no_of_grps'],
# #                     'mcast_src_ip': P2_dict['v4_addr'],
# #                     'mcast_src_ip_step': P2_dict['v4_addr_step'],
# #                     'mcast_no_of_srcs': P2_dict['no_of_mcast_sources'],
# #                     }
# #
# #        IGMP_EML = ixLib.emulate_igmp_groupHost(IGMP_dict)
# #
# #        if IGMP_EML == 0:
# #            log.debug("Configuring IGMP failed")
# #            self.errored("Configuring IGMP failed", goto=['cleanup'])
# #        else:
# #            log.info("Configured IGMP Successfully")
# #
# #        testscript.parameters['IX_TP2']['igmpHost_handle'] = IGMP_EML['igmpHost_handle']
# #        testscript.parameters['IX_TP2']['igmp_group_handle'] = IGMP_EML['igmp_group_handle']
# #        testscript.parameters['IX_TP2']['igmp_source_handle'] = IGMP_EML['igmp_source_handle']
# #
# #        # _result_ = ixiahlt.test_control(action='configure_all')
# #        # print(_result_)
# #        proto_result = ixLib.start_protocols()
# #        if proto_result == 0:
# #            log.debug("Starting Protocols failed")
# #            self.errored("Starting Protocols failed", goto=['cleanup'])
# #        else:
# #            log.info("Started Protocols Successfully")
# 
#         # Do not perform configurations if skip_tgen_config flag is set
#         if not testscript.parameters['script_flags']['skip_tgen_config']:
# 
#             IX_TP2 = testscript.parameters['IX_TP2']
#             P1_TGEN_dict = testscript.parameters['LEAF_2_TGEN_dict']
#             P2_TGEN_dict = testscript.parameters['LEAF_3_TGEN_dict']
# 
#             IGMP_dict_1 = {'ipv4_hndl': IX_TP2['ipv4_handle'],
#                            'igmp_ver': P2_TGEN_dict['igmp_ver'],
#                            'mcast_grp_ip': P2_TGEN_dict['mcast_grp_ip'],
#                            'mcast_grp_ip_step': P2_TGEN_dict['mcast_grp_ip_step'],
#                            'no_of_grps': P2_TGEN_dict['no_of_grps'],
#                            'mcast_src_ip': P1_TGEN_dict['v4_addr'],
#                            'mcast_src_ip_step': P2_TGEN_dict['v4_addr_step'],
#                            'mcast_src_ip_step_per_port': P2_TGEN_dict['v4_addr_step'],
#                            'mcast_grp_ip_step_per_port': P2_TGEN_dict['v4_addr_step'],
#                            'mcast_no_of_srcs': P2_TGEN_dict['no_of_mcast_sources'],
#                            'topology_handle': IX_TP2['topo_hndl']
#                            }
# 
#             IGMP_EML = ixLib.emulate_igmp_groupHost(IGMP_dict_1)
# 
#             if IGMP_EML == 0:
#                 log.debug("Configuring IGMP failed")
#                 self.errored("Configuring IGMP failed")
#             else:
#                 log.info("Configured IGMP Successfully")
# 
#             testscript.parameters['IX_TP2']['igmpHost_handle'] = []
#             testscript.parameters['IX_TP2']['igmp_group_handle'] = []
#             testscript.parameters['IX_TP2']['igmp_source_handle'] = []
#             testscript.parameters['IX_TP2']['igmpMcastGrpList'] = []
# 
#             testscript.parameters['IX_TP2']['igmpHost_handle'].append(IGMP_EML['igmpHost_handle'])
#             testscript.parameters['IX_TP2']['igmp_group_handle'].append(IGMP_EML['igmp_group_handle'])
#             testscript.parameters['IX_TP2']['igmp_source_handle'].append(IGMP_EML['igmp_source_handle'])
#             testscript.parameters['IX_TP2']['igmpMcastGrpList'].append(IGMP_EML['igmpMcastGrpList'])
# 
#         else:
#             self.skipped(reason="Skipped TGEN Configurations as per request")

        

    # =============================================================================================================================#
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

    @aetest.test
    def Connect_to_ixia_session(self,testscript):
        """ IXIA_CONFIGURATION subsection: Connect to  IXIA session """
        
        
        ixnetwork_tcl_server = testscript.parameters['ixia_tcl_server']
        
        
        connect_status = ixiangpf.connect(
            ixnetwork_tcl_server    =  ixnetwork_tcl_server,
            session_resume_keys     = 0,
        )
        
        if connect_status['status'] != '1':
            log.debug("Connecting to the ixia session failed")
            self.errored("Connecting to the ixia session failed", goto=['cleanup'])
        else:
            log.info("Connected to the ixia session Successfully")
            
    @aetest.test
    def CONFIGURE_UCAST_L3_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure MCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']
            P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
            P2_dict = testscript.parameters['LEAF_3_TGEN_dict']

            UCAST_v4_dict = {   'src_hndl'  : IX_TP1['ipv4_handle'],
                                'dst_hndl'  : IX_TP2['ipv4_handle'],
                                #'ip_dscp'   : P1_dict['ip_dscp'],
                                'circuit'   : 'ipv4',
                                'TI_name'   : "UCAST_L3",
                                'rate_pps'  : "10000",
                                'bi_dir'    : 1,
                                'frame_size': '128',
                                #'src_mac'   : P1_dict['mac'],
                                #'dst_mac'   : '0000.000a.aaaa',
                                #'srcmac_step': '00:00:00:00:00:00',
                                #'dstmac_step': '00:00:00:00:00:00',
                                #'srcmac_count': '1',
                                #'dstmac_count': '1',
                                'vlan_id'    : P1_dict['vlan_id'],
                                'vlanid_step': '0',
                                'vlanid_count': '1',
                                #'vlan_user_priority': P1_dict['vlan_user_priority'],
                                #'ip_src_addrs' : P1_dict['v4_addr'],
                                #'ip_dst_addrs' : P1_dict['L3_dst_addr'],
                                #'ip_src_step' : '0.0.0.0',
                                #'ip_dst_step' : '0.0.0.0',
#                                'ip_step'    : P1_dict['v4_addr_step'],
                          }

#            UCAST_v6_dict = {   'src_hndl'  : IX_TP1['ipv6_handle'],
#                                'dst_hndl'  : IX_TP2['ipv6_handle'],
#                                'circuit'   : 'ipv6',
#                                'TI_name'   : "UCAST_V6",
#                                'rate_pps'  : "1000",
#                                'bi_dir'    : 1
#                          }

            UCAST_v4_TI = configure_ixia_IP_UCAST_L3_traffic_item(UCAST_v4_dict)
#            UCAST_v6_TI = ixLib.configure_ixia_traffic_item(UCAST_v6_dict)

#            if UCAST_v4_TI == 0 or UCAST_v6_TI == 0:
#                log.debug("Configuring UCast TI failed")
#                self.errored("Configuring UCast TI failed", goto=['cleanup'])
                
            if UCAST_v4_TI == 0:
                log.debug("Configuring UCast TI failed")
                self.errored("Configuring UCast TI failed", goto=['cleanup'])
            else:
                global stream_id
                stream_id = UCAST_v4_TI

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
            self.errored("Applying IXIA TI failed", goto=['cleanup'])
            
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

#        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#    
   
        
        
    # *****************************************************************************************************************************#
# *****************************************************************************************************************************#
class Verify_vxlan_encap(aetest.Testcase):
    """ Verify traffic is encapped with vxlan """

    @aetest.test
    def configure_span_session(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        
        try:
            LEAF_1.configure('''
              monitor session 1  
              source interface port-channel ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' tx
              destination interface sup-eth0
              no shut                
          ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring span session on LEAF-1', goto=['cleanup'])
            
    # =============================================================================================================================#        
    
    @aetest.test
    def verify_span_session(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            output=LEAF_1.execute("sh mon sess 1 | json-pretty")
            import json
            span_dict=json.loads(output)
            if span_dict['TABLE_session']['ROW_session']['state']!='up':
                log.debug("span session verify failed")
                self.errored("span session verify failed", goto=['cleanup'])
            elif span_dict['TABLE_session']['ROW_session']['TABLE_sources_tx']['ROW_sources_tx']['sources_tx']!='port-channel'+str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']):
                log.debug("span session verify failed")
                self.errored("span session verify failed", goto=['cleanup'])
            else:
                log.info("span session verify successful")
        except Exception as error:
            log.debug("Unable to verify - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying span session on Leaf1', goto=['cleanup'])
    # =============================================================================================================================#         
    @aetest.test
    def start_ixia_traffic(self,testscript):
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(10)
    @aetest.test
    def verify_encap(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        import re 
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
        
        fullstr="Virtual eXtensible Local Area Network"
        try:
            i=0
            while (i<10):
                output=LEAF_1.execute("ethanalyzer local interface inband display-filter 'ip.src=="+P1_dict['v4_addr']+"' limit-captured-frames 1 detail | i 'Virtual eXtensible Local Area Network'")
                
                if fullstr.lower() in output.lower():
                    log.info("Traffic is vxlan encapsulated.")
                    break
                
                i=i+1        
            else:
                log.info("Traffic is not vxlan encapsulated.")
                self.failed("Traffic is not vxlan encapsulated",goto=['cleanup'])
                    
        except Exception as error:
            log.debug("Unable to verify - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying vxlan encapsulation on Leaf1', goto=['cleanup'])
    
            
    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 0,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['common_cleanup'])      
            
  # *****************************************************************************************************************************#
class remove_tunnel_route(aetest.Testcase):
    """ Verify traffic stops when tunnel route is removed """

        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed before removing tunnel route")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
        
    @aetest.test
    def remove_route(self, forwardingSysDict, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        vrf_id = forwardingSysDict['VRF_id_start']
        remote_leaf_route=P2_dict['NVE_data']['network_add_start']
        l3_vn_seg_id = P1_dict['VNI_data']['l3_vni_start']
        l3_vrf_count_iter= 0
        l3_vlan_id = P1_dict['VNI_data']['l3_vlan_start']
        l3_vn_seg_id = P1_dict['VNI_data']['l3_vni_start']

        l2_vlan_id = P1_dict['VNI_data']['l2_vlan_start']
        l2_vn_seg_id = P1_dict['VNI_data']['l2_vni_start']
        
        try:
            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                LEAF_1.configure('''
                  tunnel-profile '''+ str(testscript.parameters['forwardingSysDict']['tunnel_profile']) +'''
                  no route vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(vrf_id) + ''' ''' + str(remote_leaf_route) +str(P2_dict['NVE_data']['v4_netmask']) + ''' ''' + str(P2_dict['NVE_data']['VTEP_IP']) + ''' next-hop-vrf default vni ''' + str(l3_vn_seg_id) + ''' dest-vtep-mac ''' + str(P2_dict['router_mac']) +'''
                ''')
                # Incrementing L3 VRF Iteration counters
                remote_leaf_route= ip.ip_address(remote_leaf_route) + P2_dict['NVE_data']['network_add_incr']
                l3_vrf_count_iter += 1
                l3_vlan_id += 1
                l3_vn_seg_id += 1
                vrf_id += 1 
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring span session on LEAF-1', goto=['cleanup'])
    
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_ROUTE_REMOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 1:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed. Trraffic still going through after removing tunnel route.")
            else:
                log.info("Traffic Verification Passed. Traffic is failing as expected ude to removal of tunnel route.")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
     # =============================================================================================================================#
    @aetest.test
    def verifyTunnel_after_route_remove(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        TunnelData = verifyEvpn.verifyTunnelProfile(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if TunnelData['result'] is 1:
            log.info("PASS : Successfully verified Tunnel Data. Tunnel still up.\n\n")
            self.passed(reason=TunnelData['log'])
        else:
            log.info("FAIL : Failed to verify Tunnel Data.\n\n")
            self.failed(reason=TunnelData['log'])
    # =============================================================================================================================#
    
    
    @aetest.test
    def Add_tunnel_route(self, forwardingSysDict, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        vrf_id = forwardingSysDict['VRF_id_start']
        remote_leaf_route=P2_dict['NVE_data']['network_add_start']
        l3_vn_seg_id = P1_dict['VNI_data']['l3_vni_start']
        l3_vrf_count_iter= 0
        l3_vlan_id = P1_dict['VNI_data']['l3_vlan_start']
        l3_vn_seg_id = P1_dict['VNI_data']['l3_vni_start']

        l2_vlan_id = P1_dict['VNI_data']['l2_vlan_start']
        l2_vn_seg_id = P1_dict['VNI_data']['l2_vni_start']
        
        try:
            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                LEAF_1.configure('''
                  tunnel-profile '''+ str(testscript.parameters['forwardingSysDict']['tunnel_profile']) +'''
                  route vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(vrf_id) + ''' ''' + str(remote_leaf_route) +str(P2_dict['NVE_data']['v4_netmask']) + ''' ''' + str(P2_dict['NVE_data']['VTEP_IP']) + ''' next-hop-vrf default vni ''' + str(l3_vn_seg_id) + ''' dest-vtep-mac ''' + str(P2_dict['router_mac']) +'''
                ''')
                # Incrementing L3 VRF Iteration counters
                remote_leaf_route= ip.ip_address(remote_leaf_route) + P2_dict['NVE_data']['network_add_incr']
                l3_vrf_count_iter += 1
                l3_vlan_id += 1
                l3_vn_seg_id += 1
                vrf_id += 1 
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring span session on LEAF-1', goto=['cleanup'])
            
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_ROUTE_ADD(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed after adding tunnel route")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
    
     # =============================================================================================================================#
    @aetest.test
    def verifyTunnel_after_route_add(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        TunnelData = verifyEvpn.verifyTunnelProfile(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if TunnelData['result'] is 1:
            log.info("PASS : Successfully verified Tunnel Data. Tunnel still up.\n\n")
            self.passed(reason=TunnelData['log'])
        else:
            log.info("FAIL : Failed to verify Tunnel Data.\n\n")
            self.failed(reason=TunnelData['log'])
    
    @aetest.test
    def verify_cc(self,testscript):
        cc_list=['sh consistency-checker l2 module 1 brief','sh consistency-checker l3-interface module 1 brief']
        import json
        for cc_cli in cc_list:
            for leaf in testscript.parameters['leavesDict']:
                
                output=leaf.execute(cc_cli)
                a=json.loads(output)
                if a['result']['status']!="CC_STATUS_OK":
                    log.info("FAIL : CC failed.\n\n")
                    self.failed('CC failed',goto=['cleanup'])
        else:
            log.info("PASS : Successfully verified CC.\n\n")
            
    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['common_cleanup'])            
            
  # *****************************************************************************************************************************#
class remove_route_to_remote_vtep(aetest.Testcase):
    """ Verify traffic stops when route to remote vtep is removed """

        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed before removing tunnel route")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
        
    @aetest.test
    def remove_route_to_remote_vtep(self, forwardingSysDict, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        
        
        try:
            
                LEAF_1.configure('''
                  int port-channel ''' + str(P1_dict['SPINE_1_UPLINK_PO']['po_id']) + '''
                  no ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                ''')
                
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while removing route to rremote vtep on LEAF-1', goto=['cleanup'])
    
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_ROUTE_REMOVE(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 1:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed. Trraffic still going through after removing tunnel route.")
            else:
                log.info("Traffic Verification Passed. Traffic is failing as expected ude to removal of tunnel route.")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
     # =============================================================================================================================#
    @aetest.test
    def verifyTunnel_after_route_remove(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        TunnelData = verifyEvpn.verifyTunnelProfile(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if TunnelData['result'] is 1:
            log.info("PASS : Successfully verified Tunnel Data. Tunnel still up.\n\n")
            self.passed(reason=TunnelData['log'])
        else:
            log.info("FAIL : Failed to verify Tunnel Data.\n\n")
            self.failed(reason=TunnelData['log'])
    # =============================================================================================================================#
    
    
    @aetest.test
    def Add_route_to_remote_vtep(self, forwardingSysDict, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        
        
        try:
            
                LEAF_1.configure('''
                  int port-channel ''' + str(P1_dict['SPINE_1_UPLINK_PO']['po_id']) + '''
                  ip router ospf ''' + str(forwardingSysDict['OSPF_AS']) + ''' area 0.0.0.0
                ''')
                time.sleep(15)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while adding route to remote vtep on LEAF-1', goto=['common_cleanup'])
            
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_ROUTE_ADD(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed after adding tunnel route")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
    
     # =============================================================================================================================#
    @aetest.test
    def verifyTunnel_after_route_add(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        TunnelData = verifyEvpn.verifyTunnelProfile(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if TunnelData['result'] is 1:
            log.info("PASS : Successfully verified Tunnel Data. Tunnel still up.\n\n")
            self.passed(reason=TunnelData['log'])
        else:
            log.info("FAIL : Failed to verify Tunnel Data.\n\n")
            self.failed(reason=TunnelData['log'])
    
    @aetest.test
    def verify_cc(self,testscript):
        cc_list=['sh consistency-checker l2 module 1 brief','sh consistency-checker l3-interface module 1 brief']
        import json
        for cc_cli in cc_list:
            for leaf in testscript.parameters['leavesDict']:
                
                output=leaf.execute(cc_cli)
                a=json.loads(output)
                if a['result']['status']!="CC_STATUS_OK":
                    log.info("FAIL : CC failed.\n\n")
                    self.failed('CC failed',goto=['cleanup'])
        else:
            log.info("PASS : Successfully verified CC.\n\n")
            
    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['common_cleanup'])         
 
  # *****************************************************************************************************************************#
class Modify_source_tunnel_ip(aetest.Testcase):
    """ Verify traffic after modifying source tunnel ip"""

        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed before removing tunnel route")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
    
    @aetest.test
    def create_checkpoint(self, forwardingSysDict, testscript):
        """create checkpoint on Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        
        try:
            
                LEAF_1.execute('''
                  checkpoint static_tunnel1
                ''')
                LEAF_2.execute('''
                  checkpoint static_tunnel2
                ''')
                
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while moodifying the tunnel source ip', goto=['cleanup'])    
        
    @aetest.test
    def remove_route_to_remote_vtep(self, forwardingSysDict, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        
        
        try:
            
                LEAF_1.configure('''
                  int loopback 1
                  ip add 2.25.25.25/32
                ''')
                
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while moodifying the tunnel source ip', goto=['cleanup'])
    
        # =============================================================================================================================#
        
    @aetest.test
    def moddify_tunnel_route_remote_vtep(self, forwardingSysDict, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        vrf_id = forwardingSysDict['VRF_id_start']
        remote_leaf_route=P1_dict['NVE_data']['network_add_start']
        l3_vn_seg_id = P1_dict['VNI_data']['l3_vni_start']
        l3_vrf_count_iter= 0
        l3_vlan_id = P1_dict['VNI_data']['l3_vlan_start']
        l3_vn_seg_id = P1_dict['VNI_data']['l3_vni_start']

        l2_vlan_id = P1_dict['VNI_data']['l2_vlan_start']
        l2_vn_seg_id = P1_dict['VNI_data']['l2_vni_start']
        
        try:
            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                LEAF_2.configure('''
                  tunnel-profile '''+ str(testscript.parameters['forwardingSysDict']['tunnel_profile']) +'''
                  route vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(vrf_id) + ''' ''' + str(remote_leaf_route) +str(P1_dict['NVE_data']['v4_netmask']) + ''' ''' + '2.25.25.25' + ''' next-hop-vrf default vni ''' + str(l3_vn_seg_id) + ''' dest-vtep-mac ''' + str(P1_dict['router_mac']) +'''
                ''')
                # Incrementing L3 VRF Iteration counters
                remote_leaf_route= ip.ip_address(remote_leaf_route) + P1_dict['NVE_data']['network_add_incr']
                l3_vrf_count_iter += 1
                l3_vlan_id += 1
                l3_vn_seg_id += 1
                vrf_id += 1 
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring span session on LEAF-1', goto=['cleanup'])
            
    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_TUNNEL_IP_CHG(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed after adding tunnel ip change")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
     # =============================================================================================================================#
    @aetest.test
    def verifyTunnel_after_tunnel_ip_chg(self, testscript, forwardingSysDict):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """
        P1_dict = testscript.parameters['LEAF_1_dict']
        LEAF_1 = testscript.parameters['LEAF-1']
        
        #TunnelData = verifyEvpn.verifyTunnelProfile(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'],P1_dict['NVE_data']['VTEP_IP'])
        output=LEAF_1.execute('sh tunnel-profile ' +str(testscript.parameters['forwardingSysDict']['tunnel_profile'])+ ' | json-pretty')
        import json
        a=json.loads(output)
        if a['TABLE_tunnel']['ROW_tunnel']['encap-type']=='Vxlan' or a['TABLE_tunnel']['ROW_tunnel']['status']=='1' or a['TABLE_tunnel']['ROW_tunnel']['src-vtep']=='2.25.25.25':
            log.info('Tunnel profile is UP on '+str(LEAF_1)+'\n')
        else:
            log.info('Tunnel profile is not UP on '+str(LEAF_1)+'\n')
            self.failed('Tunnel profile is not UP on '+str(LEAF_1)+'\n')
             
    # =============================================================================================================================#
    
    @aetest.test
    def remove_tunnel_profile(self, forwardingSysDict, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        
        
        try:
            
                LEAF_1.configure('''
                  no tunnel-profile test
                ''')
                
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while moodifying the tunnel source ip', goto=['cleanup'])
    
    # =============================================================================================================================#
    @aetest.test
    def rollback_to_checkpoint(self, forwardingSysDict, testscript):
        """rollback to checkpoint on Leaf's"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        try:
            
                output=LEAF_1.execute('''
                  rollback running-config checkpoint static_tunnel1 verbose
                ''')
                output=str(output)
                output=output.split('\\n')
                for line in output:
                    if 'Rollback completed successfully' in line:
                        log.info('rollback passed')
                        time.sleep(20)
                        break
                    else:
                        continue
                else:
                    log.info('rollback failed on '+str(LEAF_1)+'\n')
                    self.failed('Rollback failed on Leaf1.Reconfigure the switch before running furthr tests.',goto=['common_cleanup'])
                
                
                output=LEAF_2.execute('''
                  rollback running-config checkpoint static_tunnel2 verbose
                ''')
                output=str(output)
                output=output.split('\\n')
                for line in output:
                    if 'Rollback completed successfully' in line:
                        log.info('rollback passed')
                        time.sleep(20)
                        break
                    else:
                        continue
                else:
                    log.info('rollback failed on '+str(LEAF_2)+'\n')
                    self.failed('Rollback failed on Leaf2.Reconfigure the switch before running furthr tests.',goto=['common_cleanup'])
                    
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while moodifying the tunnel source ip', goto=['cleanup'])
            
    
     # =============================================================================================================================#
    @aetest.test
    def verifyTunnel_after_rollback(self, testscript, forwardingSysDict):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """
        P1_dict = testscript.parameters['LEAF_1_dict']
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        
        #TunnelData = verifyEvpn.verifyTunnelProfile(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'],P1_dict['NVE_data']['VTEP_IP'])
        output=LEAF_1.execute('sh tunnel-profile ' +str(testscript.parameters['forwardingSysDict']['tunnel_profile'])+ ' | json-pretty')
        import json
        a=json.loads(output)
        if a['TABLE_tunnel']['ROW_tunnel']['encap-type']=='Vxlan' or a['TABLE_tunnel']['ROW_tunnel']['status']=='1' or a['TABLE_tunnel']['ROW_tunnel']['src-vtep']==str(P1_dict['NVE_data']['VTEP_IP']):
            log.info('Tunnel profile is UP on '+str(LEAF_1)+'\n')
        else:
            log.info('Tunnel profile is not UP on '+str(LEAF_1)+'\n')
            self.failed('Tunnel profile is not UP on '+str(LEAF_1)+'\n')        
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_CHANGES_RESTORED(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed after adding back tunnel")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
    
    
    
    @aetest.test
    def verify_cc(self,testscript):
        cc_list=['sh consistency-checker l2 module 1 brief','sh consistency-checker l3-interface module 1 brief']
        import json
        for cc_cli in cc_list:
            for leaf in testscript.parameters['leavesDict']:
                
                output=leaf.execute(cc_cli)
                a=json.loads(output)
                if a['result']['status']!="CC_STATUS_OK":
                    log.info("FAIL : CC failed.\n\n")
                    self.failed('CC failed',goto=['cleanup'])
        else:
            log.info("PASS : Successfully verified CC.\n\n")
            
    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['common_cleanup'])
            
  # *****************************************************************************************************************************#
class Tunnel_loopback_flap(aetest.Testcase):
    """ Verify traffic stops when route to remote vtep is removed """

        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed before removing tunnel route")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
        
    @aetest.test
    def Tunnel_loopback_shut(self, forwardingSysDict, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        
        
        try:
            
                LEAF_1.configure('''
                  int loopback 1
                  shut
                ''')
                
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while removing route to rremote vtep on LEAF-1', goto=['cleanup'])
    
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_LOPBACK_SHUT(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 1:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed. Traffic still going through after shutting tunnel loopback.")
            else:
                log.info("Traffic Verification Passed. Traffic is failing as expected due to shut of tunnel loopback.")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
     # =============================================================================================================================#
    @aetest.test
    def verifyTunnel_after_loopback_shut(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        TunnelData = verifyEvpn.verifyTunnelProfile(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if TunnelData['result'] is 0:
            log.info("PASS : Successfully verified Tunnel Data. Tunnel is down.\n\n")
            self.passed(reason=TunnelData['log'])
        else:
            log.info("FAIL : Failed to verify Tunnel Data.\n\n")
            self.failed(reason=TunnelData['log'])
    # =============================================================================================================================#
    
    
    @aetest.test
    def Tunnel_loopback_noshut(self, forwardingSysDict, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        
        
        try:
            
                LEAF_1.configure('''
                  int loopback 1
                  no shut
                ''')
                time.sleep(15)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while adding route to remote vtep on LEAF-1', goto=['common_cleanup'])
            
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_TUNNEL_NOSHUT(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed after tunnel loopback noshut")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
    
     # =============================================================================================================================#
    @aetest.test
    def verifyTunnel_after_tunnel_noshut(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        TunnelData = verifyEvpn.verifyTunnelProfile(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if TunnelData['result'] is 1:
            log.info("PASS : Successfully verified Tunnel Data. Tunnel still up.\n\n")
            self.passed(reason=TunnelData['log'])
        else:
            log.info("FAIL : Failed to verify Tunnel Data.\n\n")
            self.failed(reason=TunnelData['log'])
    
    @aetest.test
    def verify_cc(self,testscript):
        cc_list=['sh consistency-checker l2 module 1 brief','sh consistency-checker l3-interface module 1 brief']
        import json
        for cc_cli in cc_list:
            for leaf in testscript.parameters['leavesDict']:
                
                output=leaf.execute(cc_cli)
                a=json.loads(output)
                if a['result']['status']!="CC_STATUS_OK":
                    log.info("FAIL : CC failed.\n\n")
                    self.failed('CC failed',goto=['cleanup'])
        else:
            log.info("PASS : Successfully verified CC.\n\n")
            
    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['common_cleanup'])
            
  # *****************************************************************************************************************************#
class Ofm_process_restart(aetest.Testcase):
    """ Verify traffic stops when route to remote vtep is removed """

        # =============================================================================================================================#
    # =============================================================================================================================#         
    @aetest.test
    def start_ixia_traffic(self,testscript):
    #--------------------------------------------------------------------------------#
        # Start traffic from ixia
        log.info("--- Populating the statistics --- \n")
        log.info("---- Running Traffic --- \n")
        log.info("Starting Traffic")

        traffic_run_status  = ixLib.start_traffic()

        if traffic_run_status is not 1:
           log.info("Failed: To start traffic")
           return 0
        else:
            log.info("\nTraffic started successfully\n")

        time.sleep(10)
        
    # =============================================================================================================================#
    @aetest.test
    def TRIGGER_verify_aclqos_process_restart(self, testscript):
        """ ACLQOS_PROCESS_KILL_VERIFICATION subsection: Verify killing process ACLQOS """

        LEAF_1 = testscript.parameters['LEAF-1']

        if infraTrig.verifyProcessRestart(LEAF_1,"ofm"):
            log.info("Successfully restarted process aclqos")
        else:
            log.debug("Failed to restarted process aclqos")
            self.failed("Failed to restarted process aclqos", goto=['cleanup'])

        time.sleep(60)
     # =============================================================================================================================#
    @aetest.test
    def verifyTunnel_after_ofm_restart(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        TunnelData = verifyEvpn.verifyTunnelProfile(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if TunnelData['result'] is 1:
            log.info("PASS : Successfully verified Tunnel Data. Tunnel is Up.\n\n")
            self.passed(reason=TunnelData['log'])
        else:
            log.info("FAIL : Failed to verify Tunnel Data.\n\n")
            self.failed(reason=TunnelData['log'])    
        
    # =============================================================================================================================#
    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
            time.sleep(10)
        
    
    
    
    # =============================================================================================================================#
    
    
    @aetest.test
    def verify_cc(self,testscript):
        cc_list=['sh consistency-checker l2 module 1 brief','sh consistency-checker l3-interface module 1 brief']
        import json
        for cc_cli in cc_list:
            for leaf in testscript.parameters['leavesDict']:
                
                output=leaf.execute(cc_cli)
                a=json.loads(output)
                if a['result']['status']!="CC_STATUS_OK":
                    log.info("FAIL : CC failed.\n\n")
                    self.failed('CC failed',goto=['cleanup'])
        else:
            log.info("PASS : Successfully verified CC.\n\n")
            
    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['common_cleanup'])
            
  # *****************************************************************************************************************************#
class Ping_remote_host(aetest.Testcase):
    """ Verify traffic stops when route to remote vtep is removed """

        # =============================================================================================================================#
   
     # =============================================================================================================================#
    @aetest.test
    def verifyTunnel(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        TunnelData = verifyEvpn.verifyTunnelProfile(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if TunnelData['result'] is 1:
            log.info("PASS : Successfully verified Tunnel Data. Tunnel is Up.\n\n")
            self.passed(reason=TunnelData['log'])
        else:
            log.info("FAIL : Failed to verify Tunnel Data.\n\n")
            self.failed(reason=TunnelData['log'])    
        
    # =============================================================================================================================#
    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
            time.sleep(10)
        
    
    @aetest.test
    def ping_remote_host(self,testscript,forwardingSysDict):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
        vrf_count=testscript.parameters['forwardingSysDict']['VRF_count']
        vrf_id=testscript.parameters['forwardingSysDict']['VRF_id_start']
        dest_ip=P1_dict['L3_dst_addr']
        
        vrf_no=0
        try:
            while vrf_no < vrf_count:
                output=LEAF_1.execute('ping ' + str(dest_ip) + ' vrf ' + testscript.parameters['forwardingSysDict']['VRF_string']+str(vrf_id) + ' count 20')
                m=re.search('([0-9]+) packets received',output)
                if not m:
                    log.info("FAIL : ping to remote host failed.\n\n")
                    self.failed("FAIL : ping to remote host failed", gotto=['cleanup'])
                elif m.group(1)=='20':
                    log.info("Ping to remote host works for vrf "+testscript.parameters['forwardingSysDict']['VRF_string']+str(vrf_id))
                else:
                    log.info("FAIL : ping to remote host failed.\n\n")
                    self.failed("FAIL : ping to remote host failed", gotto=['cleanup'])
                vrf_no+=1
                vrf_id+=1
                dest_ip=ip.ip_address(dest_ip)+256
        except Exception as error:
            log.debug("Error occured while pinging remote host:"+ str(error))
            self.failed("Error occured while pinging remote host", goto=['cleanup'])
    
    # =============================================================================================================================#
    
    
    @aetest.test
    def verify_cc(self,testscript):
        cc_list=['sh consistency-checker l2 module 1 brief','sh consistency-checker l3-interface module 1 brief']
        import json
        for cc_cli in cc_list:
            for leaf in testscript.parameters['leavesDict']:
                
                output=leaf.execute(cc_cli)
                a=json.loads(output)
                if a['result']['status']!="CC_STATUS_OK":
                    log.info("FAIL : CC failed.\n\n")
                    self.failed('CC failed',goto=['cleanup'])
        else:
            log.info("PASS : Successfully verified CC.\n\n")
            
    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['common_cleanup'])
            
  # *****************************************************************************************************************************#
class Ping_remote_vtep(aetest.Testcase):
    """ Verify traffic stops when route to remote vtep is removed """

        # =============================================================================================================================#
   
     # =============================================================================================================================#
    @aetest.test
    def verifyTunnel(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        TunnelData = verifyEvpn.verifyTunnelProfile(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if TunnelData['result'] is 1:
            log.info("PASS : Successfully verified Tunnel Data. Tunnel is Up.\n\n")
            self.passed(reason=TunnelData['log'])
        else:
            log.info("FAIL : Failed to verify Tunnel Data.\n\n")
            self.failed(reason=TunnelData['log'])    
        
    # =============================================================================================================================#
    @aetest.test
    def VERIFY_TRAFFIC(self):

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Verify Traffic
        if ixLib.verify_traffic(2, 3) == 0:
            log.debug("Traffic Verification failed")
            self.failed("Traffic Verification failed", goto=['cleanup'])
        else:
            log.info("Traffic Verification Passed")
            time.sleep(10)
        
    
    @aetest.test
    def ping_remote_vtep(self,testscript,forwardingSysDict):
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        vrf_count=testscript.parameters['forwardingSysDict']['VRF_count']
        vrf_id=testscript.parameters['forwardingSysDict']['VRF_id_start']
        dest_ip=P2_dict['NVE_data']['VTEP_IP']
        
        vrf_no=0
        try:
            output=LEAF_1.execute('ping ' + str(dest_ip) + ' count 20')
            m=re.search('([0-9]+) packets received',output)
            if not m:
                log.info("FAIL : ping to remote vtep failed.\n\n")
                self.failed("FAIL : ping to remote vtep failed", goto=['cleanup'])
            elif m.group(1)=='20':
                log.info("Ping to remote vtep works")
            else:
                log.info("FAIL : ping to remote vtep failed.\n\n")
                self.failed("FAIL : ping to remote vtep failed", goto=['cleanup'])
        except Exception as error:
            log.debug("Error occured while pinging remote host:"+ str(error))
            self.failed("Error occured while pinging remote host", goto=['cleanup'])
    
    # =============================================================================================================================#
    
    
    @aetest.test
    def verify_cc(self,testscript):
        cc_list=['sh consistency-checker l2 module 1 brief','sh consistency-checker l3-interface module 1 brief']
        import json
        for cc_cli in cc_list:
            for leaf in testscript.parameters['leavesDict']:
                
                output=leaf.execute(cc_cli)
                a=json.loads(output)
                if a['result']['status']!="CC_STATUS_OK":
                    log.info("FAIL : CC failed.\n\n")
                    self.failed('CC failed',goto=['cleanup'])
        else:
            log.info("PASS : Successfully verified CC.\n\n")
            
    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['common_cleanup'])

  # *****************************************************************************************************************************#
class Tunnel_Uplink_flap(aetest.Testcase):
    """ Verify traffic stops when route to remote vtep is removed """

        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed before removing tunnel route")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
        
    @aetest.test
    def Tunnel_Uplink_shut(self, forwardingSysDict, testscript):
        """Uplink shut Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        
        
        try:
            
                LEAF_1.configure('''
                  int PO ''' + str(P1_dict['SPINE_1_UPLINK_PO']['po_id'])+ '''
                  shut
                ''')
                
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting the uplink on LEAF-1', goto=['cleanup'])
    
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_Uplink_SHUT(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 1:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed. Traffic still going through after shutting tunnel uplink.")
            else:
                log.info("Traffic Verification Passed. Traffic is failing as expected due to shut of tunnel uplink.")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    
    # =============================================================================================================================#
    
    
    @aetest.test
    def Tunnel_Uplink_noshut(self, forwardingSysDict, testscript):
        """Uplink shut Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        
        
        try:
            
                LEAF_1.configure('''
                  int PO ''' + str(P1_dict['SPINE_1_UPLINK_PO']['po_id'])+ '''
                  no shut
                ''')
                time.sleep(20)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred during no shut of the uplink on LEAF-1', goto=['cleanup'])
            
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER__NOSHUT(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed after tunnel uplink noshut")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
    
     # =============================================================================================================================#
    @aetest.test
    def verifyTunnel_after_uplink_noshut(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        TunnelData = verifyEvpn.verifyTunnelProfile(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if TunnelData['result'] is 1:
            log.info("PASS : Successfully verified Tunnel Data. Tunnel still up.\n\n")
            self.passed(reason=TunnelData['log'])
        else:
            log.info("FAIL : Failed to verify Tunnel Data.\n\n")
            self.failed(reason=TunnelData['log'])
    
    @aetest.test
    def verify_cc(self,testscript):
        cc_list=['sh consistency-checker l2 module 1 brief','sh consistency-checker l3-interface module 1 brief']
        import json
        for cc_cli in cc_list:
            for leaf in testscript.parameters['leavesDict']:
                
                output=leaf.execute(cc_cli)
                a=json.loads(output)
                if a['result']['status']!="CC_STATUS_OK":
                    log.info("FAIL : CC failed.\n\n")
                    self.failed('CC failed',goto=['cleanup'])
        else:
            log.info("PASS : Successfully verified CC.\n\n")
            
    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['common_cleanup'])
            
  # *****************************************************************************************************************************#
class Vlan_vni_modify(aetest.Testcase):
    """ Verify traffic stops when route to remote vtep is removed """

        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed before removing tunnel route")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
        
    @aetest.test
    def Vlan_vnsegment_modify(self, forwardingSysDict, testscript):
        """Uplink shut Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        l3_vlan_id = P1_dict['VNI_data']['l3_vlan_start']
        l3_vn_seg_id = P1_dict['VNI_data']['l3_vni_start']

        l2_vlan_id = P1_dict['VNI_data']['l2_vlan_start']
        l2_vn_seg_id = P1_dict['VNI_data']['l2_vni_start']
        l3_vrf_count_iter = 0
        vrf_id = forwardingSysDict['VRF_id_start']
        new_l3_vn_seg_id =45001
        new_l2_vn_seg_id =40001
        
        try:
            
            while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            # Configure L3 VRF and L3 VNIs
                LEAF_1.configure('''
                        vlan ''' + str(l3_vlan_id) + '''
                          no vn-segment ''' + str(l3_vn_seg_id) + '''
                          vn-segment '''+ str(new_l3_vn_seg_id)+'''
                        ''')
                LEAF_1.configure('''
                    vrf context ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
                      no vni ''' + str(l3_vn_seg_id) + '''
                      vni ''' + str(new_l3_vn_seg_id))
                
                LEAF_2.configure('''
                        vlan ''' + str(l3_vlan_id) + '''
                          no vn-segment ''' + str(l3_vn_seg_id) + '''
                          vn-segment '''+ str(new_l3_vn_seg_id) +'''
                        ''')
                LEAF_2.configure('''
                    vrf context ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
                      no vni ''' + str(l3_vn_seg_id) + '''
                      vni ''' + str(new_l3_vn_seg_id))
                # # ----------------------------------------------------
                # # Inner while loop for L2 Configurations
                # # ----------------------------------------------------
                # l2_vlan_count_iter = 0
                # while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
                #     # Configure L2 VNIs
                #     LEAF_1.configure('''
                #         vlan ''' + str(l2_vlan_id) + '''
                #           no vn-segment ''' + str(l2_vn_seg_id) + '''
                #           vn-segment '''+ str(new_l2_vn_seg_id) + '''
                #           ''')
                #     LEAF_2.configure('''
                #         vlan ''' + str(l2_vlan_id) + '''
                #           no vn-segment ''' + str(l2_vn_seg_id) + '''
                #           vn-segment '''+ str(new_l2_vn_seg_id) + '''
                #           ''')
                #     # Incrementing L2 VLAN Iteration counters
                #     l2_vlan_count_iter += 1
                #     l2_vlan_id += 1
                #     l2_vn_seg_id += 1
                #     new_l2_vn_seg_id +=1
                    

                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1
                l3_vn_seg_id += 1
                vrf_id += 1
                new_l3_vn_seg_id+=1
                
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting the uplink on LEAF-1', goto=['cleanup'])
    
    # =============================================================================================================================#
    
    
    @aetest.test
    def Add_tunnel_route_for_new_vnsegment(self, forwardingSysDict, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        vrf_id = forwardingSysDict['VRF_id_start']
        remote_leaf_route=P2_dict['NVE_data']['network_add_start']
        remote_leaf_route_2=P1_dict['NVE_data']['network_add_start']
        l3_vn_seg_id = P1_dict['VNI_data']['l3_vni_start']
        l3_vrf_count_iter= 0
        l3_vlan_id = P1_dict['VNI_data']['l3_vlan_start']
        l3_vn_seg_id = P1_dict['VNI_data']['l3_vni_start']

        l2_vlan_id = P1_dict['VNI_data']['l2_vlan_start']
        l2_vn_seg_id = P1_dict['VNI_data']['l2_vni_start']
        new_l3_vn_seg_id=45001
        
        try:
            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                LEAF_1.configure('''
                  tunnel-profile '''+ str(testscript.parameters['forwardingSysDict']['tunnel_profile']) +'''
                  no route vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(vrf_id) + ''' ''' + str(remote_leaf_route) +str(P2_dict['NVE_data']['v4_netmask']) + ''' ''' + str(P2_dict['NVE_data']['VTEP_IP']) + ''' next-hop-vrf default vni ''' + str(l3_vn_seg_id) + ''' dest-vtep-mac ''' + str(P2_dict['router_mac']) +'''
                  route vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(vrf_id) + ''' ''' + str(remote_leaf_route) +str(P2_dict['NVE_data']['v4_netmask']) + ''' ''' + str(P2_dict['NVE_data']['VTEP_IP']) + ''' next-hop-vrf default vni ''' + str(new_l3_vn_seg_id) + ''' dest-vtep-mac ''' + str(P2_dict['router_mac']) +'''
                ''')
                LEAF_2.configure('''
                  tunnel-profile '''+ str(testscript.parameters['forwardingSysDict']['tunnel_profile']) +'''
                  no route vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(vrf_id) + ''' ''' + str(remote_leaf_route_2) +str(P1_dict['NVE_data']['v4_netmask']) + ''' ''' + str(P1_dict['NVE_data']['VTEP_IP']) + ''' next-hop-vrf default vni ''' + str(l3_vn_seg_id) + ''' dest-vtep-mac ''' + str(P1_dict['router_mac']) +'''
                  route vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(vrf_id) + ''' ''' + str(remote_leaf_route_2) +str(P1_dict['NVE_data']['v4_netmask']) + ''' ''' + str(P1_dict['NVE_data']['VTEP_IP']) + ''' next-hop-vrf default vni ''' + str(new_l3_vn_seg_id) + ''' dest-vtep-mac ''' + str(P1_dict['router_mac']) +'''
                ''')
                # Incrementing L3 VRF Iteration counters
                remote_leaf_route= ip.ip_address(remote_leaf_route) + P2_dict['NVE_data']['network_add_incr']
                remote_leaf_route_2= ip.ip_address(remote_leaf_route_2) + P1_dict['NVE_data']['network_add_incr']
                l3_vrf_count_iter += 1
                l3_vlan_id += 1
                l3_vn_seg_id += 1
                new_l3_vn_seg_id+=1
                vrf_id += 1 
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring span session on LEAF-1', goto=['cleanup'])
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_VNI_MODIFY(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed.")
            else:
                log.info("Traffic Verification Passed.")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
            
    
    # =============================================================================================================================#
    
    
    @aetest.test
    def Vlan_vnsegment_revert(self, forwardingSysDict, testscript):
        """Uplink shut Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        l3_vlan_id = P1_dict['VNI_data']['l3_vlan_start']
        l3_vn_seg_id = P1_dict['VNI_data']['l3_vni_start']

        l2_vlan_id = P1_dict['VNI_data']['l2_vlan_start']
        l2_vn_seg_id = P1_dict['VNI_data']['l2_vni_start']
        l3_vrf_count_iter = 0
        vrf_id = forwardingSysDict['VRF_id_start']
        new_l3_vn_seg_id =45001
        new_l2_vn_seg_id =40001
        
        try:
            
            while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            # Configure L3 VRF and L3 VNIs
                LEAF_1.configure('''
                        vlan ''' + str(l3_vlan_id) + '''
                          no vn-segment '''+ str(new_l3_vn_seg_id)+'''
                          vn-segment ''' + str(l3_vn_seg_id) + '''
                          
                        ''')
                LEAF_1.configure('''
                    vrf context ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
                      no vni ''' + str(new_l3_vn_seg_id) + '''
                      vni ''' + str(l3_vn_seg_id)
                      )
                
                LEAF_2.configure('''
                        vlan ''' + str(l3_vlan_id) + '''
                          no vn-segment '''+ str(new_l3_vn_seg_id) +'''
                          vn-segment ''' + str(l3_vn_seg_id) + '''
                          
                        ''')
                LEAF_2.configure('''
                    vrf context ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
                      no vni ''' + str(new_l3_vn_seg_id) + '''
                      vni ''' + str(l3_vn_seg_id)
                      )
                # # ----------------------------------------------------
                # # Inner while loop for L2 Configurations
                # # ----------------------------------------------------
                # l2_vlan_count_iter = 0
                # while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
                #     # Configure L2 VNIs
                #     LEAF_1.configure('''
                #         vlan ''' + str(l2_vlan_id) + '''
                #           no vn-segment '''+ str(new_l2_vn_seg_id) + '''
                #           vn-segment ''' + str(l2_vn_seg_id) + '''
                #           
                #           ''')
                #     LEAF_2.configure('''
                #         vlan ''' + str(l2_vlan_id) + '''
                #           no vn-segment '''+ str(new_l2_vn_seg_id) + '''
                #           vn-segment ''' + str(l2_vn_seg_id) + '''
                #           
                #           ''')
                #     # Incrementing L2 VLAN Iteration counters
                #     l2_vlan_count_iter += 1
                #     l2_vlan_id += 1
                #     l2_vn_seg_id += 1
                #     new_l2_vn_seg_id +=1
                    

                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1
                l3_vn_seg_id += 1
                vrf_id += 1
                new_l3_vn_seg_id+=1
                
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting the uplink on LEAF-1', goto=['cleanup'])
    
    # =============================================================================================================================#
    
    
    @aetest.test
    def Remove_tunnel_route_for_new_vnsegment(self, forwardingSysDict, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        vrf_id = forwardingSysDict['VRF_id_start']
        remote_leaf_route=P2_dict['NVE_data']['network_add_start']
        remote_leaf_route_2=P1_dict['NVE_data']['network_add_start']
        l3_vn_seg_id = P1_dict['VNI_data']['l3_vni_start']
        l3_vrf_count_iter= 0
        l3_vlan_id = P1_dict['VNI_data']['l3_vlan_start']
        l3_vn_seg_id = P1_dict['VNI_data']['l3_vni_start']

        l2_vlan_id = P1_dict['VNI_data']['l2_vlan_start']
        l2_vn_seg_id = P1_dict['VNI_data']['l2_vni_start']
        new_l3_vn_seg_id=45001
        
        try:
            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                LEAF_1.configure('''
                  tunnel-profile '''+ str(testscript.parameters['forwardingSysDict']['tunnel_profile']) +'''
                  no route vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(vrf_id) + ''' ''' + str(remote_leaf_route) +str(P2_dict['NVE_data']['v4_netmask']) + ''' ''' + str(P2_dict['NVE_data']['VTEP_IP']) + ''' next-hop-vrf default vni ''' + str(new_l3_vn_seg_id) + ''' dest-vtep-mac ''' + str(P2_dict['router_mac']) +'''
                  route vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(vrf_id) + ''' ''' + str(remote_leaf_route) +str(P2_dict['NVE_data']['v4_netmask']) + ''' ''' + str(P2_dict['NVE_data']['VTEP_IP']) + ''' next-hop-vrf default vni ''' + str(l3_vn_seg_id) + ''' dest-vtep-mac ''' + str(P2_dict['router_mac']) +'''
                ''')
                LEAF_2.configure('''
                  tunnel-profile '''+ str(testscript.parameters['forwardingSysDict']['tunnel_profile']) +'''
                  no route vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(vrf_id) + ''' ''' + str(remote_leaf_route_2) +str(P1_dict['NVE_data']['v4_netmask']) + ''' ''' + str(P1_dict['NVE_data']['VTEP_IP']) + ''' next-hop-vrf default vni ''' + str(new_l3_vn_seg_id) + ''' dest-vtep-mac ''' + str(P1_dict['router_mac']) +'''
                  route vrf ''' + str(testscript.parameters['forwardingSysDict']['VRF_string']) + str(vrf_id) + ''' ''' + str(remote_leaf_route_2) +str(P1_dict['NVE_data']['v4_netmask']) + ''' ''' + str(P1_dict['NVE_data']['VTEP_IP']) + ''' next-hop-vrf default vni ''' + str(l3_vn_seg_id) + ''' dest-vtep-mac ''' + str(P1_dict['router_mac']) +'''
                ''')
                # Incrementing L3 VRF Iteration counters
                remote_leaf_route= ip.ip_address(remote_leaf_route) + P2_dict['NVE_data']['network_add_incr']
                remote_leaf_route_2= ip.ip_address(remote_leaf_route_2) + P1_dict['NVE_data']['network_add_incr']
                l3_vrf_count_iter += 1
                l3_vlan_id += 1
                l3_vn_seg_id += 1
                new_l3_vn_seg_id+=1
                vrf_id += 1 
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring span session on LEAF-1', goto=['cleanup'])
        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_VNI_REVERT(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
    
     # =============================================================================================================================#
    @aetest.test
    def verifyTunnel_after_vn_segment_modify(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        TunnelData = verifyEvpn.verifyTunnelProfile(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if TunnelData['result'] is 1:
            log.info("PASS : Successfully verified Tunnel Data. Tunnel still up.\n\n")
            self.passed(reason=TunnelData['log'])
        else:
            log.info("FAIL : Failed to verify Tunnel Data.\n\n")
            self.failed(reason=TunnelData['log'])
    
    @aetest.test
    def verify_cc(self,testscript):
        cc_list=['sh consistency-checker l2 module 1 brief','sh consistency-checker l3-interface module 1 brief']
        import json
        for cc_cli in cc_list:
            for leaf in testscript.parameters['leavesDict']:
                
                output=leaf.execute(cc_cli)
                a=json.loads(output)
                if a['result']['status']!="CC_STATUS_OK":
                    log.info("FAIL : CC failed.\n\n")
                    self.failed('CC failed',goto=['cleanup'])
        else:
            log.info("PASS : Successfully verified CC.\n\n")
            
    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['common_cleanup'])
    
  # *****************************************************************************************************************************#
class Vlan_vni_remove_add(aetest.Testcase):
    """ Verify traffic stops when route to remote vtep is removed """

        # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed before removing tunnel route")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
        
        
    @aetest.test
    def Vlan_vnsegment_remove(self, forwardingSysDict, testscript):
        """Uplink shut Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        l3_vlan_id = P1_dict['VNI_data']['l3_vlan_start']
        l3_vn_seg_id = P1_dict['VNI_data']['l3_vni_start']

        l2_vlan_id = P1_dict['VNI_data']['l2_vlan_start']
        l2_vn_seg_id = P1_dict['VNI_data']['l2_vni_start']
        l3_vrf_count_iter = 0
        vrf_id = forwardingSysDict['VRF_id_start']
        new_l3_vn_seg_id =45001
        new_l2_vn_seg_id =40001
        
        try:
            
            while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            # Configure L3 VRF and L3 VNIs
                LEAF_1.configure('''
                        vlan ''' + str(l3_vlan_id) + '''
                          no vn-segment ''' + str(l3_vn_seg_id) + '''
                        ''')
                LEAF_1.configure('''
                    vrf context ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
                      no vni ''' + str(l3_vn_seg_id)
                      )
                
                LEAF_2.configure('''
                        vlan ''' + str(l3_vlan_id) + '''
                          no vn-segment ''' + str(l3_vn_seg_id) + '''
                        ''')
                LEAF_2.configure('''
                    vrf context ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
                      no vni ''' + str(l3_vn_seg_id)
                      )
                # # ----------------------------------------------------
                # # Inner while loop for L2 Configurations
                # # ----------------------------------------------------
                # l2_vlan_count_iter = 0
                # while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
                #     # Configure L2 VNIs
                #     LEAF_1.configure('''
                #         vlan ''' + str(l2_vlan_id) + '''
                #           no vn-segment ''' + str(l2_vn_seg_id) + '''
                #           ''')
                #     LEAF_2.configure('''
                #         vlan ''' + str(l2_vlan_id) + '''
                #           no vn-segment ''' + str(l2_vn_seg_id) + '''
                #           ''')
                #     # Incrementing L2 VLAN Iteration counters
                #     l2_vlan_count_iter += 1
                #     l2_vlan_id += 1
                #     l2_vn_seg_id += 1
                #     new_l2_vn_seg_id +=1
                    

                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1
                l3_vn_seg_id += 1
                vrf_id += 1
                new_l3_vn_seg_id+=1
                
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting the uplink on LEAF-1', goto=['cleanup'])
    
    # =============================================================================================================================#
    @aetest.test
    def Vlan_vnsegment_revert(self, forwardingSysDict, testscript):
        """Uplink shut Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        P1_dict = testscript.parameters['LEAF_1_dict']
        P2_dict = testscript.parameters['LEAF_2_dict']
        l3_vlan_id = P1_dict['VNI_data']['l3_vlan_start']
        l3_vn_seg_id = P1_dict['VNI_data']['l3_vni_start']

        l2_vlan_id = P1_dict['VNI_data']['l2_vlan_start']
        l2_vn_seg_id = P1_dict['VNI_data']['l2_vni_start']
        l3_vrf_count_iter = 0
        vrf_id = forwardingSysDict['VRF_id_start']
        new_l3_vn_seg_id =45001
        new_l2_vn_seg_id =40001
        
        try:
            
            while l3_vrf_count_iter < forwardingSysDict['VRF_count']:
            # Configure L3 VRF and L3 VNIs
                LEAF_1.configure('''
                        vlan ''' + str(l3_vlan_id) + '''
                          vn-segment ''' + str(l3_vn_seg_id) + '''
                          
                        ''')
                LEAF_1.configure('''
                    vrf context ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
                      vni ''' + str(l3_vn_seg_id)
                      )
                
                LEAF_2.configure('''
                        vlan ''' + str(l3_vlan_id) + '''
                          vn-segment ''' + str(l3_vn_seg_id) + '''
                          
                        ''')
                LEAF_2.configure('''
                    vrf context ''' + str(forwardingSysDict['VRF_string']) + str(vrf_id) + '''
                      vni ''' + str(l3_vn_seg_id)
                      )
                # # ----------------------------------------------------
                # # Inner while loop for L2 Configurations
                # # ----------------------------------------------------
                # l2_vlan_count_iter = 0
                # while l2_vlan_count_iter < forwardingSysDict['VLAN_PER_VRF_count']:
                #     # Configure L2 VNIs
                #     LEAF_1.configure('''
                #         vlan ''' + str(l2_vlan_id) + '''
                #           vn-segment ''' + str(l2_vn_seg_id) + '''
                #           
                #           ''')
                #     LEAF_2.configure('''
                #         vlan ''' + str(l2_vlan_id) + '''
                #           vn-segment ''' + str(l2_vn_seg_id) + '''
                #           
                #           ''')
                #     # Incrementing L2 VLAN Iteration counters
                #     l2_vlan_count_iter += 1
                #     l2_vlan_id += 1
                #     l2_vn_seg_id += 1
                #     new_l2_vn_seg_id +=1
                    

                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1
                l3_vn_seg_id += 1
                vrf_id += 1
                new_l3_vn_seg_id+=1
                
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting the uplink on LEAF-1', goto=['cleanup'])
    
    # =============================================================================================================================#
    
    
   
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_VNI_REVERT(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['cleanup'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")
    
     # =============================================================================================================================#
    @aetest.test
    def verifyTunnel_after_vn_segment_modify(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        TunnelData = verifyEvpn.verifyTunnelProfile(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if TunnelData['result'] is 1:
            log.info("PASS : Successfully verified Tunnel Data. Tunnel still up.\n\n")
            self.passed(reason=TunnelData['log'])
        else:
            log.info("FAIL : Failed to verify Tunnel Data.\n\n")
            self.failed(reason=TunnelData['log'])
    
    @aetest.test
    def verify_cc(self,testscript):
        cc_list=['sh consistency-checker l2 module 1 brief','sh consistency-checker l3-interface module 1 brief']
        import json
        for cc_cli in cc_list:
            for leaf in testscript.parameters['leavesDict']:
                
                output=leaf.execute(cc_cli)
                a=json.loads(output)
                if a['result']['status']!="CC_STATUS_OK":
                    log.info("FAIL : CC failed.\n\n")
                    self.failed('CC failed',goto=['cleanup'])
        else:
            log.info("PASS : Successfully verified CC.\n\n")
            
    # =============================================================================================================================#
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        post_test_process_dict = {
            'dut_list'                       : [LEAF_1],
            'cc_check'                  : 0,
            'cores_check'               : 1,
            'logs_check'                : 1,
            'fnl_flag'                  : 0,
            'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
            }
        try:
            # Stop Traffic from ixia
            log.info("--- Stopping Traffic ---- \n")
            log.info("Stopping Traffic")
            traffic_run_status = ixLib.stop_traffic()
            
            if traffic_run_status is not 1:
               log.info("Failed: To Stop traffic")
               return 0
            else:
                log.info("\nTraffic Stopped successfully\n")
            time.sleep(10)
            
            ##check for cores,cc,errors
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        except Exception as error:
            log.debug("Unable to do cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['common_cleanup'])
#########################################################################
#####                       COMMON CLEANUP SECTION                    ###
#########################################################################
##
### Remove the BASE CONFIGURATION that was applied earlier in the 
### common cleanup section, clean the left over

class common_cleanup(aetest.CommonCleanup):
    @aetest.subsection
    def Common_cleanup(self, testscript):
        
        """ Common Cleanup for Sample Test """
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        SPINE = testscript.parameters['SPINE']
    
        @aetest.subsection
        def restore_terminal_width(self, LEAF_1):
            """ Common Cleanup subsection """
            log.info(banner("script common cleanup starts here"))
        
        @aetest.subsection
        def restore_terminal_width(self, LEAF_2):
            """ Common Cleanup subsection """
            log.info(banner("script common cleanup starts here"))
        
        @aetest.subsection
        def restore_terminal_width(self, FAN_1):
            """ Common Cleanup subsection """
            log.info(banner("script common cleanup starts here"))
            
        @aetest.subsection
        def restore_terminal_width(self, FAN_2):
            """ Common Cleanup subsection """
            log.info(banner("script common cleanup starts here"))
            
        @aetest.subsection
        def restore_terminal_width(self, SPINE):
            """ Common Cleanup subsection """
            log.info(banner("script common cleanup starts here"))


if __name__ == '__main__':  # pragma: no cover
    aetest.main()
