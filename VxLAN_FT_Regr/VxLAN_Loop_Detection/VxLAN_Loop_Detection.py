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

def verify_loop_detection(testscript,dut,vlan,int):
    
    output=dut.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
    for line in output.split('\n'):
        m=re.search('^([0-9]+)\s+Eth([0-9]+\/[0-9]+)\s+BLOCKED',line)
        if m:
            if m.group(1)==str(vlan):
                if m.group(2)==int:
                    log.info('The loop has been detected and the port ETH'+str(m.group(2))+ ' is blocked for vlan '+ str(vlan))
                    return True
                else:
                    log.info('The loop has NOT been detected for vlan '+str(vlan))
                    return False
                    
            else:
                log.info('The loop has NOT been detected for vlan '+str(vlan))
                return False
                
        else:
            m=re.search('^([0-9]+)\s+Po([0-9]+)\s+BLOCKED',line)
            if m:
                if m.group(1)==str(vlan):
                    if m.group(2)==int:
                        log.info('The loop has been detected and the port-channel'+str(m.group(2))+ ' is blocked for vlan '+ str(vlan))
                        return True
                    else:
                        log.info('The loop has NOT been detected for vlan '+str(vlan))
                        return False
                        
                else:
                    log.info('The loop has NOT been detected for vlan '+str(vlan))
                    return False
            else:
                    log.info('The loop has NOT been detected for vlan '+str(vlan))
                    return False
            

def verify_loop_detection_for_PO_ints(testscript,dut,vlan,int1,int2):
    
    output=dut.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
    for line in output.split('\n'):
        m=re.search('^([0-9]+)\s+Po([0-9]+)\s+BLOCKED',line)
        if m:
            if m.group(1)==str(vlan):
                if m.group(2)==int1 or m.group(2)==int2:
                    log.info('The loop has been detected and the port-channel'+str(m.group(2))+ ' is blocked for vlan '+ str(vlan))
                    return True
                else:
                    log.info('The loop has NOT been detected.')
                    return False
                    
            else:
                log.info('The loop has NOT been detected for vlan '+str(vlan))
                return False
        else:
            log.info('No match found. The loop has NOT been detected for vlan '+str(vlan))
            return False
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
    def connecting_to_devices(self, testscript, testbed, uut_list):
        """ common setup subsection: Connecting to devices """
        
        # =============================================================================================================================#
        # Grab the device object of the uut device with that name
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

    # *****************************************************************************************************************************#
    @aetest.subsection
    def set_script_flags(self, testscript, configurationFile, job_file_params):

        global post_test_process_dict
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

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
        # log.info(resn)
        if job_file_params['script_flags']['skip_device_config']:
            aetest.skip.affix(section=DEVICE_BRINGUP_enable_feature_set, reason=resn)
            aetest.skip.affix(section=DEVICE_BRINGUP_configure_SPINE, reason=resn)
            aetest.skip.affix(section=DEVICE_BRINGUP_configure_LEAF_1_2, reason=resn)
            aetest.skip.affix(section=DEVICE_BRINGUP_configure_LEAF_3, reason=resn)
            aetest.skip.affix(section=DEVICE_BRINGUP_configure_FAN_1, reason=resn)
            aetest.skip.affix(section=DEVICE_BRINGUP_configure_FAN_2, reason=resn)

        # =============================================================================================================================#
        # Import Configuration File and create required Structures

        with open(configurationFile) as cfgFile:
            configuration = yaml.load(cfgFile, Loader=Loader)

        testscript.parameters['LEAF_1_dict']            = configuration['LEAF_1_dict']
        testscript.parameters['LEAF_2_dict']            = configuration['LEAF_2_dict']
        testscript.parameters['LEAF_3_dict']            = configuration['LEAF_3_dict']
        testscript.parameters['SPINE_1_dict']           = configuration['SPINE_1_dict']
        testscript.parameters['forwardingSysDict']      = configuration['FWD_SYS_dict']

        testscript.parameters['LEAF_2_TGEN_dict']       = configuration['LEAF_2_TGEN_data']
        testscript.parameters['LEAF_3_TGEN_dict']       = configuration['LEAF_3_TGEN_data']

        testscript.parameters['leafVPCDictData']        = {LEAF_1 : configuration['LEAF_1_dict'], LEAF_2 : configuration['LEAF_2_dict']}
        testscript.parameters['leavesDictList']         = [configuration['LEAF_1_dict'], configuration['LEAF_2_dict'], configuration['LEAF_3_dict']]
        testscript.parameters['leavesDict']             = {LEAF_1 : configuration['LEAF_1_dict'],
                                                           LEAF_2 : configuration['LEAF_2_dict'],
                                                           LEAF_3 : configuration['LEAF_3_dict']}
        testscript.parameters['tcam_config_dict']       = configuration['tcam_config_dict']
        #testscript.parameters['log'] = log

        testscript.parameters['VTEP_List'] = [testscript.parameters['LEAF_1_dict'], testscript.parameters['LEAF_2_dict'], testscript.parameters['LEAF_3_dict']]

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
        testscript.parameters['intf_SPINE_to_LEAF_1']       = SPINE.interfaces['SPINE_to_LEAF-1_1'].intf
        testscript.parameters['intf_SPINE_to_LEAF_2']       = SPINE.interfaces['SPINE_to_LEAF-2_1'].intf
        testscript.parameters['intf_SPINE_to_LEAF_3']       = SPINE.interfaces['SPINE_to_LEAF-3_1'].intf

        testscript.parameters['intf_LEAF_1_to_LEAF_2_1']    = LEAF_1.interfaces['LEAF_to_MCT_1'].intf
        testscript.parameters['intf_LEAF_1_to_LEAF_2_2']    = LEAF_1.interfaces['LEAF_to_MCT_2'].intf
        testscript.parameters['intf_LEAF_1_to_LEAF_2_3']    = LEAF_1.interfaces['LEAF_to_MCT_3'].intf
        testscript.parameters['intf_LEAF_1_to_SPINE']       = LEAF_1.interfaces['LEAF_to_SPINE_1'].intf
        testscript.parameters['intf_LEAF_1_to_FAN_1']       = LEAF_1.interfaces['LEAF_to_FAN_1_1'].intf
        testscript.parameters['intf_LEAF_1_to_FAN_2']       = LEAF_1.interfaces['LEAF_to_FAN_2_1'].intf
        testscript.parameters['intf_LEAF_1_to_LEAF_3']      = LEAF_1.interfaces['LEAF_1_to_LEAF_3_1'].intf
        testscript.parameters['intf_LEAF_1_to_LEAF_2_5']    = LEAF_1.interfaces['LEAF_to_MCT_4'].intf

        testscript.parameters['intf_LEAF_2_to_LEAF_1_1']    = LEAF_2.interfaces['LEAF_to_MCT_1'].intf
        testscript.parameters['intf_LEAF_2_to_LEAF_1_2']    = LEAF_2.interfaces['LEAF_to_MCT_2'].intf
        testscript.parameters['intf_LEAF_2_to_LEAF_1_3']    = LEAF_2.interfaces['LEAF_to_MCT_3'].intf
        testscript.parameters['intf_LEAF_2_to_SPINE']       = LEAF_2.interfaces['LEAF_to_SPINE_1'].intf
        testscript.parameters['intf_LEAF_2_to_FAN_1']       = LEAF_2.interfaces['LEAF_to_FAN_1_1'].intf
        testscript.parameters['intf_LEAF_2_to_FAN_2']       = LEAF_2.interfaces['LEAF_to_FAN_2_1'].intf

        testscript.parameters['intf_LEAF_3_to_SPINE']       = LEAF_3.interfaces['LEAF_to_SPINE_1'].intf
        testscript.parameters['intf_LEAF_3_to_FAN_2']       = LEAF_3.interfaces['LEAF_to_FAN_2_1'].intf
        testscript.parameters['intf_LEAF_3_to_IXIA']        = LEAF_3.interfaces['LEAF_to_IXIA'].intf
        testscript.parameters['intf_LEAF_3_to_LEAF_3_1']    = LEAF_3.interfaces['LEAF-3_to_LEAF-3_1'].intf
        testscript.parameters['intf_LEAF_3_to_LEAF_3_2']    = LEAF_3.interfaces['LEAF-3_to_LEAF-3_2'].intf
        testscript.parameters['intf_LEAF_3_to_LEAF_1']      = LEAF_3.interfaces['LEAF_3_to_LEAF_1_1'].intf

        testscript.parameters['intf_FAN_1_to_LEAF_1']       = FAN_1.interfaces['FAN_to_LEAF-1_1'].intf
        testscript.parameters['intf_FAN_1_to_LEAF_2']       = FAN_1.interfaces['FAN_to_LEAF-2_1'].intf
        testscript.parameters['intf_FAN_1_to_IXIA']         = FAN_1.interfaces['FAN_to_IXIA'].intf
        testscript.parameters['intf_FAN_1_to_FAN_2_1']      = FAN_1.interfaces['FAN-1_to_FAN-2_1'].intf
        testscript.parameters['intf_FAN_1_to_FAN_2_2']      = FAN_1.interfaces['FAN-1_to_FAN-2_2'].intf

        testscript.parameters['intf_FAN_2_to_LEAF_1']       = FAN_2.interfaces['FAN_to_LEAF-1_1'].intf
        testscript.parameters['intf_FAN_2_to_LEAF_2']       = FAN_2.interfaces['FAN_to_LEAF-2_1'].intf
        testscript.parameters['intf_FAN_2_to_FAN_1_1']      = FAN_2.interfaces['FAN-2_to_FAN-1_1'].intf
        testscript.parameters['intf_FAN_2_to_FAN_1_2']      = FAN_2.interfaces['FAN-2_to_FAN-1_2'].intf
        testscript.parameters['intf_FAN_2_to_LEAF_3']       = FAN_2.interfaces['FAN-2_to_LEAF-3_1'].intf

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


     # ==============================================================================================================================#
    # @aetest.subsection
    # def configureTCAM(self,testscript,testbed):
    # 
    #     #TCAM comfigurable DUTS are:
    #     testbed_obj = testbed
    #     tcam_configurable_duts = testscript.parameters['tcam_config_dict'].keys()
    #     log.info('{0} are the duts for which the tcam has to be carved'.format(tcam_configurable_duts))
    #     
    #     tcam_config_dict = testscript.parameters['tcam_config_dict']
    #     print(tcam_config_dict)
    #     
    #     tcam_dut_obj_list = {}
    #     for dut in tcam_configurable_duts:
    #         tcam_dut_obj_list[dut] = testbed.devices[dut]
    #     print(tcam_dut_obj_list)
    #     print(type(tcam_dut_obj_list))
    #     
    #     
    #     log.info('The value of tcam_dut_obj_list is {0} '.format(tcam_dut_obj_list))
    #     
    #     
    #     d = tcam_lib.configTcam(tcam_config_dict,tcam_dut_obj_list,log)
    #     print('d='+ str(d))
    #     #for dut in tcam_dut_obj_list.keys():
    #     #    tcam_dut_obj_list[dut].connect(via='console')
    #     #res = d.Nodes(dut)
    #
    # @aetest.subsection
    # def TRIGGER_verify_device_ascii_reload(self, testscript):
    #     """ HA_VERIFICATION subsection: Device ASCII Reload """
    # 
    #     LEAF_1 = testscript.parameters['LEAF-1']
    # 
    #     LEAF_1.execute("copy r s")
    # 
    #     # Perform Device Reload
    #     dialog = Dialog([
    #         Statement(pattern=r'.*Do you wish to proceed anyway.*',
    #                   action='sendline(y)',
    #                   loop_continue=True,
    #                   continue_timer=True)
    #     ])
    #     result= LEAF_1.reload(reload_command="reload", timeout=600,prompt_recovery=False, dialog=dialog)
    #     #result = infraTrig.switchASCIIreload(LEAF_1)
    #     log.info("result= " + str(result))
    #     if result:
    #         log.info("ASCII Reload completed Successfully")
    #         log.info("Waiging for 240 sec for the topology to come UP")
    #         time.sleep(240)
    #     else:
    #         log.debug("ASCII Reload Failed")
    #         self.failed("ASCII Reload Failed", goto=['cleanup'])
        
        
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
                        --- |   LEAF-1  |====|   LEAF-2  |    |   LEAF-3  |
                        |    +-----------+    +-----------+    +-----------+
                        |    \\           \  /         /         |   |    |
                        |     \\           /\         /          |   |    |
                        |      \\         /   \      /           |   |    |
                        |       \\       /      \   /            |   |    |
                        |     +-----------+    +---------+       |   |    |
                        |     |           |____|          |-------   |    |  
                        |     |    Fan1   |----| Fan-2    |          |    |  
                        |     |-----------|    |----------|        Ixia   |
                        |           |                                     |
                        |           |                                     |
                        |           |                                     |
                        |          ixia                                   |
                        |_________________________________________________|     
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

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            leafLst                 = [testscript.parameters['LEAF-1'], testscript.parameters['LEAF-2'], testscript.parameters['LEAF-3']]
            spineFeatureList        = ['ospf', 'bgp', 'pim', 'lacp', 'nv overlay']
            vpcLeafFeatureList      = ['vpc', 'ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp', 'nv overlay','ngoam']
            LeafFeatureList         = ['ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp', 'nv overlay','ngoam']
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
        evpnLib.configureEVPNSpines([testscript.parameters['SPINE']], testscript.parameters['forwardingSysDict'] , testscript.parameters['leavesDictList'])

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
        evpnLib.configureEVPNVPCLeafs(testscript.parameters['forwardingSysDict'], testscript.parameters['leafVPCDictData'])

        l3_vrf_count_iter = 0
        stp_config = ''
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

        while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
            l2_vlan_count_iter = 0
            while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                # Incrementing L2 VLAN Iteration counters
                stp_config += '''spanning-tree vlan ''' + str(l2_vlan_id) + ''' priority 8192\n'''
                l2_vlan_count_iter += 1
                l2_vlan_id += 1
            # Incrementing L3 VRF Iteration counters
            l3_vrf_count_iter += 1
            l3_vlan_id += 1

        try:
            LEAF_1.configure(stp_config, timeout=300)
            LEAF_1.configure('''
              router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num'])  + '''
                address-family l2vpn evpn
                  advertise-pip
              interface nve 1
                advertise virtual-rmac
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
            LEAF_2.configure(stp_config, timeout=300)
            LEAF_2.configure('''
              router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num'])  + '''
                address-family l2vpn evpn
                  advertise-pip
              interface nve 1
                advertise virtual-rmac
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

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            fanOut_vlanConfiguration = ""

            FAN_1 = testscript.parameters['FAN-1']
            l3_vrf_count_iter = 0
            po_cfg_flag = 0
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                l2_vlan_count_iter = 0
                fanOut_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                    # Incrementing L2 VLAN Iteration counters
                    fanOut_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                    state active\n
                                                    no shut\n'''
                    l2_vlan_count_iter += 1
                    l2_vlan_id += 1
                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1

            try:
                FAN_1.configure(fanOut_vlanConfiguration)
                FAN_1.configure('spanning-tree mode rapid-pvst', timeout=300)
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
                                spanning-tree port type edge trunk
                                spanning-tree bpdufilter enable
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
class DEVICE_BRINGUP_configure_FAN_2(aetest.Testcase):
    """Device Bring-up Test-Case"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def configure_FAN_2(self, testscript):
        """ Device Bring-up subsection: Configuring FAN_1 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            fanOut_vlanConfiguration = ""

            FAN_2 = testscript.parameters['FAN-2']
            l3_vrf_count_iter = 0
            po_cfg_flag = 0
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            l3_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l3_vlan_start']

            while l3_vrf_count_iter < testscript.parameters['forwardingSysDict']['VRF_count']:
                l2_vlan_count_iter = 0
                fanOut_vlanConfiguration += '''vlan ''' + str(l3_vlan_id) + '''\n
                                                state active\n
                                                no shut\n'''
                while l2_vlan_count_iter < testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']:
                    # Incrementing L2 VLAN Iteration counters
                    fanOut_vlanConfiguration += '''vlan ''' + str(l2_vlan_id) + '''\n
                                                    state active\n
                                                    no shut\n'''
                    l2_vlan_count_iter += 1
                    l2_vlan_id += 1
                # Incrementing L3 VRF Iteration counters
                l3_vrf_count_iter += 1
                l3_vlan_id += 1

            try:
                FAN_2.configure(fanOut_vlanConfiguration)
                FAN_2.configure('spanning-tree mode rapid-pvst', timeout=300)
                for interf in FAN_2.interfaces.keys():
                    if "FAN_to_LEAF" in interf:
                        if not po_cfg_flag:
                            FAN_2.configure('''
                                no interface port-channel ''' + str(FAN_2.interfaces[interf].PO) + '''
                                interface port-channel ''' + str(FAN_2.interfaces[interf].PO) + '''
                                    switchport
                                    switchport mode trunk
                                    no shutdown
                                    no shut
                            ''')
                            po_cfg_flag = 1
                        FAN_2.configure('''
                            interface ''' + str(FAN_2.interfaces[interf].intf) + '''
                                channel-group ''' + str(FAN_2.interfaces[interf].PO) + ''' force mode active
                                no shut
                        ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on FAN-2', goto=['common_cleanup'])
    
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

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

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
class IXIA_CONFIGURATION_CONNECT_IXIA_CHASSIS(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
    
    @aetest.test
    def CONNECT_IXIA_CHASSIS(self, testscript):
        

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
                                         
        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            TOPO_1_dict = {'topology_name': 'FAN-1-TG',
                           'device_grp_name': 'FAN-1-TG',
                           'port_handle': testscript.parameters['port_handle_1']}

            TOPO_2_dict = {'topology_name': 'LEAF-3-TG',
                           'device_grp_name': 'LEAF-3-TG',
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
            #testscript.parameters['IX_TP1']['port_handle'] = P1_IX_int_data['port_hndl']
            testscript.parameters['IX_TP1']['topo_int_handle'] = P1_IX_int_data['topo_int_handle'].split(" ")

            testscript.parameters['IX_TP2']['eth_handle'] = P2_IX_int_data['eth_handle']
            testscript.parameters['IX_TP2']['ipv4_handle'] = P2_IX_int_data['ipv4_handle']
            testscript.parameters['IX_TP2']['ipv6_handle'] = P2_IX_int_data['ipv6_handle']
            #testscript.parameters['IX_TP2']['port_handle'] = P2_IX_int_data['port_hndl']
            testscript.parameters['IX_TP2']['topo_int_handle'] = P2_IX_int_data['topo_int_handle'].split(" ")

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
class IXIA_CONFIGURATION_CONFIGURE_IGMP_GROUPS(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def CONFIGURE_IXIA_IGMP_GROUPS(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure IXIA IGMP Groups """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP2 = testscript.parameters['IX_TP2']
            P1_TGEN_dict = testscript.parameters['LEAF_2_TGEN_dict']
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
class IXIA_CONFIGURATION_MANUAL_CONNECT_IXIA_SESSION(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")
    
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
            P1_dict = testscript.parameters['LEAF_2_TGEN_dict']
            P2_dict = testscript.parameters['LEAF_3_TGEN_dict']

            BCAST_v4_dict = {
                                'src_hndl'      : IX_TP1['port_handle'],
                                'dst_hndl'      : IX_TP2['port_handle'],
                                'TI_name'       : "BCAST_V4",
                                'frame_size'    : "70",
                                'rate_pps'      : "1000",
                                'src_mac'       : P1_dict['mac'],
                                'srcmac_step'   : "00:00:00:00:00:01",
                                'srcmac_count'  : '1',
                                'vlan_id'       : P1_dict['vlan_id'],
                                'vlanid_step'   : "1",
                                'vlanid_count'  : "1",
                                'ip_src_addrs'  : P1_dict['v4_addr'],
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
        pass
        """ testcase clean up """

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
        pass
        """ testcase clean up """
            
# *****************************************************************************************************************************#
class IXIA_CONFIGURATION_VERIFY_IXIA_TRAFFIC(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

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

    @aetest.cleanup
    def cleanup(self):
        """ testcase clean up """
        log.info("Pass testcase cleanup")   

# *****************************************************************************************************************************#
class TC001_Enable_loop_detection_cli(aetest.Testcase):
    """ DSCP_ENCAP_DEFAULT_QOS """
            
    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

    @aetest.test
    def Enable_ngoam_loop_detection(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            LEAF_1.configure('''
                
              ngoam loop-detection                
          ''')
            LEAF_2.configure('''
                
              ngoam loop-detection                
          ''')
            LEAF_3.configure('''
                
              ngoam loop-detection                
          ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
    
    @aetest.test
    def Check_ngoam_running_cfg(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                prb_intvl=re.search('periodic-probe-interval ([0-9]+)',output)
                if prb_intvl.group(1)=='300':
                    rcry_intvl=re.search('port-recovery-interval ([0-9]+)',output)
                    if rcry_intvl.group(1)=='600':
                        log.info("ngoam looop-detectioon is enabled andd dddefault values are active")
                    else:
                        log.info("ngoam loop-detection recoovery interval does not match default value")
                        self.failed("ngoam loop-detection recoovery interval does not match default value", goto=['cleanup'])
                else:
                    log.info("ngoam loop-detection probe interval does not match default value")
                    self.failed("ngoam loop-detection probe interval does not match default value", goto=['cleanup'])
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_is_enabled(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Loop detection:(enabled)',output)
            if m:
                if m.group(1)=='enabled':
                    log.info("ngoam looop-detectioon is enabled ")
                else:
                    log.info("ngoam loop detection is not enabled")
                    self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is not enabled")
                self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self):
        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])
            
# *****************************************************************************************************************************#
class TC002_Disable_loop_detection_cli(aetest.Testcase):
    """ DSCP_ENCAP_DEFAULT_QOS """

    @aetest.setup
    def setup(self):
        log.info("Pass testcase setup")

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
            
            
    @aetest.test
    def Enable_ngoam_loop_detection(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            LEAF_1.configure('''  
              no ngoam loop-detection                
            ''')
            LEAF_2.configure('''    
              no ngoam loop-detection                
            ''')
            LEAF_3.configure('''    
              no ngoam loop-detection                
            ''')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
    
    @aetest.test
    def Check_ngoam_running_cfg(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection"  in output:
                log.info("ngoam loop-detection still enabled")
                self.failed("ngoam loop-detection still enabled", goto=['cleanup'])
            else:
                log.info("ngoam looop-detectioon is disabled after removing cli")
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_is_disabled(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            if output in "ERROR: Loop detection is not enabled":
                log.info("ngoam looop-detectioon is disabled ")
            else:
                log.info("ngoam loop detection is still enabled")
                self.failed("ngoam loop detection is still enabled", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying ngoam on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_POST_TC(self, testscript):
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
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            time.sleep(10)
            LEAF_1.configure('''    
              ngoam loop-detection                
            ''')
            LEAF_2.configure('''    
              ngoam loop-detection                
            ''')
            LEAF_3.configure('''    
              ngoam loop-detection                
            ''')
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

        except Exception as error:
            log.debug("Unable to cleanup-Encountered exception " + str(error))
            self.errored('Exception occurred while doing cleanup', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class TC003_Disable_Enable_loop_detection_for_vlans(aetest.Testcase):
    """ Disable_Enable_loop_detection_for_vlans """
            
    @aetest.test
    def Disable_ngoam_loop_detection_on_vlans(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''
                
              ngoam loop-detection
              disable vlan ''' + str(l2_vlan_id) +'''-''' + str(vlan_end)
             )
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Number of vlans disabled: ([0-9]+)',output)
            if m:
                if m.group(1)==str(no_of_vlans):
                    log.info("ngoam looop-detectioon is disabled for vlans specified")
                else:
                    log.info("ngoam loop detection is not disabled for said vlans")
                    self.failed("ngoam loop detection is not disabled for said vlans", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is not disabled for said vlans")
                self.failed("ngoam loop detection is not disabled for said vlans", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Check_ngoam_running_cfg(self, testscript):
        """verify disbaled vlans are present in ngoam running config"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                disabled_vlans=re.search('disable vlan ([0-9]+-[0-9]+)',output)
                if disabled_vlans.group(1)==str(l2_vlan_id) +'-' + str(vlan_end):
                    log.info("ngoam looop-detectioon disabled vlans are visible in running config")
                else:
                    log.info("ngoam looop-detectioon disabled vlans are not visible in running config")
                    self.failed("ngoam looop-detectioon disabled vlans are not visible in running config", goto=['cleanup'])
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while chcking ngoam running config', goto=['cleanup'])
    
    @aetest.test
    def Enable_ngoam_loop_detection_on_vlans(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''
                
              ngoam loop-detection
              no disable vlan ''' + str(l2_vlan_id) +'''-''' + str(vlan_end)
             )
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary_after_enabling_vlans(self, testscript):
        """verify the loop-detection summary dpesn't shsow vlans as disabled anymore"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Number of vlans disabled: ([0-9]+)',output)
            if m:
                if m.group(1)=='0':
                    log.info("ngoam looop-detectioon is enabled for vlans specified")
                else:
                    log.info("ngoam loop detection is disabled for said vlans")
                    self.failed("ngoam loop detection is disabled for said vlans", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is disabled for said vlans")
                self.failed("ngoam loop detection is disabled for said vlans", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying vlans are not disabled for loop-detection', goto=['cleanup'])
            
    @aetest.test
    def Check_ngoam_running_cfg_after_enabling_vlans(self, testscript):
        """verify disbaled vlans are present in ngoam running config"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                disabled_vlans=re.search('disable vlan ([0-9]+-[0-9]+)',output)
                if disabled_vlans:
                    log.info("ngoam looop-detectioon disabled vlans are still visible in running config")
                    self.failed("ngoam looop-detectioon disabled vlans are still visible in running config", goto=['cleanup'])
                else:
                    log.info("ngoam looop-detectioon disabled vlans are not in running config after enabling loop-detection on them")
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while chcking ngoam running config', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']

        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''
                ngoam loop-detection
                no disable vlan ''' + str(l2_vlan_id) +'-' + str(vlan_end)+'''
            ''')
            
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
            
        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class TC004_Disable_Enable_loop_detection_for_single_vlan(aetest.Testcase):
    """ Disable_Enable_loop_detection_for_vlans """
            
    @aetest.test
    def Disable_ngoam_loop_detection_on_vlans(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            LEAF_1.configure('''
                
              ngoam loop-detection
              disable vlan ''' + str(l2_vlan_id)
             )
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Number of vlans disabled: ([0-9]+)',output)
            if m:
                if m.group(1)=='1':
                    log.info("ngoam looop-detectioon is disabled for vlans specified")
                else:
                    log.info("ngoam loop detection is not disabled for said vlans")
                    self.failed("ngoam loop detection is not disabled for said vlans", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is not disabled for said vlans")
                self.failed("ngoam loop detection is not disabled for said vlans", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Check_ngoam_running_cfg(self, testscript):
        """verify disbaled vlans are present in ngoam running config"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                disabled_vlans=re.search('disable vlan ([0-9]+)',output)
                if disabled_vlans.group(1)==str(l2_vlan_id):
                    log.info("ngoam looop-detectioon disabled vlans are visible in running config")
                else:
                    log.info("ngoam looop-detectioon disabled vlans are not visible in running config")
                    self.failed("ngoam looop-detectioon disabled vlans are not visible in running config", goto=['cleanup'])
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while chcking ngoam running config', goto=['cleanup'])
    
    @aetest.test
    def Enable_ngoam_loop_detection_on_vlans(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            LEAF_1.configure('''
                
              ngoam loop-detection
              no disable vlan ''' + str(l2_vlan_id)
             )
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary_after_enabling_vlans(self, testscript):
        """verify the loop-detection summary dpesn't shsow vlans as disabled anymore"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Number of vlans disabled: ([0-9]+)',output)
            if m:
                if m.group(1)=='0':
                    log.info("ngoam looop-detectioon is enabled for vlans specified")
                else:
                    log.info("ngoam loop detection is disabled for said vlans")
                    self.failed("ngoam loop detection is disabled for said vlans", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is disabled for said vlans")
                self.failed("ngoam loop detection is disabled for said vlans", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying vlans are not disabled for loop-detection', goto=['cleanup'])
            
    @aetest.test
    def Check_ngoam_running_cfg_after_enabling_vlans(self, testscript):
        """verify disbaled vlans are present in ngoam running config"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                disabled_vlans=re.search('disable vlan ([0-9]+)',output)
                if disabled_vlans:
                    log.info("ngoam looop-detectioon disabled vlans are still visible in running config")
                    self.failed("ngoam looop-detectioon disabled vlans are still visible in running config", goto=['cleanup'])
                else:
                    log.info("ngoam looop-detectioon disabled vlans are not in running config after enabling loop-detection on them")
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while chcking ngoam running config', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        try:
            LEAF_1.configure('''                
                ngoam loop-detection
                no disable vlan ''' + str(l2_vlan_id)+'''
            ''')
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class TC005_Disable_Enable_loop_detection_for_mltple_vlans_ports(aetest.Testcase):
    """ Disable_Enable_loop_detection_for_vlans """
            
    @aetest.test
    def Disable_ngoam_loop_detection_on_vlans(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''
                
              ngoam loop-detection
              disable vlan ''' + str(l2_vlan_id) +'''-''' + str(vlan_end) + ''' port ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_3']) + ''', ''' +str(testscript.parameters['intf_LEAF_1_to_LEAF_2_5'])
             )
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while disabling loop-detection on vlans and ports', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Number of vlans disabled: ([0-9]+)',output)
            if m:
                if m.group(1)==str(no_of_vlans):
                    log.info("ngoam looop-detectioon is disabled for vlans specified")
                    n=re.search('Number of ports disabled: ([0-9]+)',output)
                    if n:
                        if n.group(1)=='2':
                            log.info("ngoam looop-detection is disabled for ports specified")
                        else:
                            log.info("ngoam loop detection is not disabled for said ports")
                            self.failed("ngoam loop detection is not disabled for said ports", goto=['cleanup'])
                else:
                    log.info("ngoam loop detection is not disabled for said vlans")
                    self.failed("ngoam loop detection is not disabled for said vlans", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is not disabled for said vlans/ports")
                self.failed("ngoam loop detection is not disabled for said vlans/ports", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying disabling loop-detection on vlans and ports', goto=['cleanup'])
            
    @aetest.test
    def Check_ngoam_running_cfg(self, testscript):
        """verify disbaled vlans are present in ngoam running config"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        inter1=str(testscript.parameters['intf_LEAF_1_to_LEAF_2_5'])
        port_num1=inter1.split('/')
        inter2=str(testscript.parameters['intf_LEAF_1_to_LEAF_3'])
        port_num2=inter2.split('/')
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                disabled_vlans=re.search('disable vlan ([0-9]+-[0-9]+) port (Ethernet[0-9]+\/[0-9]+\/?[0-9]+?, Ethernet[0-9]+\/[0-9]\/?[0-9]+?|Ethernet[0-9]+\/[0-9]+-[0-9]+)',output)
                if disabled_vlans.group(1)==str(l2_vlan_id) +'-' + str(vlan_end):
                    log.info("ngoam looop-detectioon disabled vlans are visible in running config")
                    if disabled_vlans.group(2)==str(testscript.parameters['intf_LEAF_1_to_LEAF_3']) + ''', ''' +str(testscript.parameters['intf_LEAF_1_to_LEAF_2_5']) or disabled_vlans.group(2)==str(testscript.parameters['intf_LEAF_1_to_LEAF_2_5']) + ''', ''' +str(testscript.parameters['intf_LEAF_1_to_LEAF_3']) or disabled_vlans.group(2)==str(testscript.parameters['intf_LEAF_1_to_LEAF_3']) +'-'+ str(port_num1[1]) or disabled_vlans.group(2)==str(testscript.parameters['intf_LEAF_1_to_LEAF_2_5']) +'-'+ str(port_num2[1]):
                        log.info("ngoam looop-detectioon disabled ports are visible in running config")
                    else:
                        log.info("ngoam looop-detectioon disabled ports are not visible in running config")
                        self.failed("ngoam looop-detectioon disabled ports are not visible in running config", goto=['cleanup'])
                else:
                    log.info("ngoam looop-detectioon disabled vlans/ports are not visible in running config")
                    self.failed("ngoam looop-detectioon disabled vlans/ports are not visible in running config", goto=['cleanup'])
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while chcking ngoam running config', goto=['cleanup'])
    
    @aetest.test
    def Enable_ngoam_loop_detection_on_vlans(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''
                
              ngoam loop-detection
              no disable vlan ''' + str(l2_vlan_id) +'''-''' + str(vlan_end) + ''' port ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_3']) + ''', ''' +str(testscript.parameters['intf_LEAF_1_to_LEAF_2_5'])
             )
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary_after_enabling_vlans(self, testscript):
        """verify the loop-detection summary dpesn't shsow vlans as disabled anymore"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Number of vlans disabled: ([0-9]+)',output)
            if m:
                if m.group(1)=='0':
                    log.info("ngoam looop-detectioon is enabled for vlans specified")
                    n=re.search('Number of ports disabled: ([0-9]+)',output)
                    if n:
                        if n.group(1)=='0':
                            log.info("ngoam looop-detection is enabled for ports specified")
                        else:
                            log.info("ngoam loop detection is not enabled for said ports")
                            self.failed("ngoam loop detection is not enabled for said ports", goto=['cleanup'])
                else:
                    log.info("ngoam loop detection is disabled for said vlans")
                    self.failed("ngoam loop detection is disabled for said vlans", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is disabled for said vlans")
                self.failed("ngoam loop detection is disabled for said vlans", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying vlans are not disabled for loop-detection', goto=['cleanup'])
            
    @aetest.test
    def Check_ngoam_running_cfg_after_enabling_vlans(self, testscript):
        """verify disbaled vlans are present in ngoam running config"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                disabled_vlans=re.search('disable vlan ([0-9]+-[0-9]+)',output)
                if disabled_vlans:
                    log.info("ngoam looop-detectioon disabled vlans are still visible in running config")
                    self.failed("ngoam looop-detectioon disabled vlans are still visible in running config", goto=['cleanup'])
                else:
                    log.info("ngoam looop-detectioon disabled vlans are not in running config after enabling loop-detection on them")
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while chcking ngoam running config', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']

        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''                
                ngoam loop-detection
                no disable vlan ''' + str(l2_vlan_id) +'''-''' + str(vlan_end) + ''' port ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_3']) + ''', ''' +str(testscript.parameters['intf_LEAF_1_to_LEAF_2_5'])+'''
            ''')
            
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class TC006_Disable_Enable_loop_detection_for_single_ports(aetest.Testcase):
    """ Disable_Enable_loop_detection_for_vlans """
            
    @aetest.test
    def Disable_ngoam_loop_detection_on_vlans(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''
                
              ngoam loop-detection
              disable vlan ''' + str(l2_vlan_id) +'''-''' + str(vlan_end) + ''' port ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_3']) 
             )
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while disabling loop-detection on vlans and ports', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Number of vlans disabled: ([0-9]+)',output)
            if m:
                if m.group(1)==str(no_of_vlans):
                    log.info("ngoam looop-detectioon is disabled for vlans specified")
                    n=re.search('Number of ports disabled: ([0-9]+)',output)
                    if n:
                        if n.group(1)=='1':
                            log.info("ngoam looop-detection is disabled for ports specified")
                        else:
                            log.info("ngoam loop detection is not disabled for said ports")
                            self.failed("ngoam loop detection is not disabled for said ports", goto=['cleanup'])
                else:
                    log.info("ngoam loop detection is not disabled for said vlans")
                    self.failed("ngoam loop detection is not disabled for said vlans", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is not disabled for said vlans/ports")
                self.failed("ngoam loop detection is not disabled for said vlans/ports", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying disabling loop-detection on vlans and ports', goto=['cleanup'])
            
    @aetest.test
    def Check_ngoam_running_cfg(self, testscript):
        """verify disbaled vlans are present in ngoam running config"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        inter1=str(testscript.parameters['intf_LEAF_1_to_LEAF_2_5'])
        port_num1=inter1.split('/')
        inter2=str(testscript.parameters['intf_LEAF_1_to_LEAF_3'])
        port_num2=inter2.split('/')
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                disabled_vlans=re.search('disable vlan ([0-9]+-[0-9]+) port (Ethernet[0-9]+\/[0-9]+)',output)
                if disabled_vlans:
                    if disabled_vlans.group(1)==str(l2_vlan_id) +'-' + str(vlan_end):
                        log.info("ngoam looop-detectioon disabled vlans are visible in running config")
                        if disabled_vlans.group(2)==str(testscript.parameters['intf_LEAF_1_to_LEAF_3']):
                            log.info("ngoam looop-detectioon disabled ports are visible in running config")
                        else:
                            log.info("ngoam looop-detectioon disabled ports are not visible in running config")
                            self.failed("ngoam looop-detectioon disabled ports are not visible in running config", goto=['cleanup'])
                    else:
                        log.info("ngoam looop-detectioon disabled vlans/ports are not visible in running config")
                        self.failed("ngoam looop-detectioon disabled vlans/ports are not visible in running config", goto=['cleanup'])
                else:
                    log.info("ngoam looop-detectioon disabled vlans/ports are not visible in running config")
                    self.failed("ngoam looop-detectioon disabled vlans/ports are not visible in running config", goto=['cleanup'])
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while chcking ngoam running config', goto=['cleanup'])
    
    @aetest.test
    def Enable_ngoam_loop_detection_on_vlans(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''
                
              ngoam loop-detection
              no disable vlan ''' + str(l2_vlan_id) +'''-''' + str(vlan_end) + ''' port ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_3'])
             )
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary_after_enabling_vlans(self, testscript):
        """verify the loop-detection summary dpesn't shsow vlans as disabled anymore"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Number of vlans disabled: ([0-9]+)',output)
            if m:
                if m.group(1)=='0':
                    log.info("ngoam looop-detectioon is enabled for vlans specified")
                    n=re.search('Number of ports disabled: ([0-9]+)',output)
                    if n:
                        if n.group(1)=='0':
                            log.info("ngoam looop-detection is enabled for ports specified")
                        else:
                            log.info("ngoam loop detection is not enabled for said ports")
                            self.failed("ngoam loop detection is not enabled for said ports", goto=['cleanup'])
                else:
                    log.info("ngoam loop detection is disabled for said vlans")
                    self.failed("ngoam loop detection is disabled for said vlans", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is disabled for said vlans")
                self.failed("ngoam loop detection is disabled for said vlans", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying vlans are not disabled for loop-detection', goto=['cleanup'])
            
    @aetest.test
    def Check_ngoam_running_cfg_after_enabling_vlans(self, testscript):
        """verify disbaled vlans are present in ngoam running config"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                disabled_vlans=re.search('disable vlan ([0-9]+-[0-9]+)',output)
                if disabled_vlans:
                    log.info("ngoam looop-detectioon disabled vlans are still visible in running config")
                    self.failed("ngoam looop-detectioon disabled vlans are still visible in running config", goto=['cleanup'])
                else:
                    log.info("ngoam looop-detectioon disabled vlans are not in running config after enabling loop-detection on them")
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while chcking ngoam running config', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']

        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''                
                ngoam loop-detection
                no disable vlan ''' + str(l2_vlan_id) +'''-''' + str(vlan_end) + ''' port ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_3'])+'''
            ''')
            
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class TC007_Non_default_probe_interval(aetest.Testcase):
    """ Non_default_probe_interval """        
    @aetest.test
    def Enable_ngoam_loop_detection(self, testscript):
        """Enable ngoam loop-detection"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            LEAF_1.configure('''
                
              ngoam loop-detection
              periodic-probe-interval 500
          ''')
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
    
    @aetest.test
    def Check_ngoam_running_cfg(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                prb_intvl=re.search('periodic-probe-interval ([0-9]+)',output)
                if prb_intvl.group(1)=='500':
                    rcry_intvl=re.search('port-recovery-interval ([0-9]+)',output)
                    if rcry_intvl.group(1)=='600':
                        log.info("ngoam looop-detectioon is enabled andd dddefault values are active")
                    else:
                        log.info("ngoam loop-detection recoovery interval does not match default value")
                        self.failed("ngoam loop-detection recoovery interval does not match default value", goto=['cleanup'])
                else:
                    log.info("ngoam loop-detection probe interval does not match default value")
                    self.failed("ngoam loop-detection probe interval does not match default value", goto=['cleanup'])
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_is_enabled(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Loop detection:(enabled)',output)
            if m:
                if m.group(1)=='enabled':
                    log.info("ngoam looop-detectioon is enabled ")
                    n=re.search('Periodic probe interval: ([0-9]+)',output)
                    if n:
                        if n.group(1)=='500':
                            log.info("ngoam looop-detectioon probe interval shows configured interval value")
                        else:
                            log.info("ngoam looop-detectioon probe interval does not show configured interval value")
                            self.failed("ngoam looop-detectioon probe interval does not show configured interval value", goto=['cleanup'])
                else:
                    log.info("ngoam loop detection is not enabled")
                    self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is not enabled")
                self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying prorbe interval timers', goto=['cleanup'])
            
    @aetest.test
    def Enable_loop_detection_default_values(self, testscript):
        """Enable ngoam loop-detection"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            LEAF_1.configure('''
                
              ngoam loop-detection
              no periodic-probe-interval 500
          ''')
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring loop-detection', goto=['cleanup'])
    
    @aetest.test
    def Check_ngoam_running_cfg_for_default_values(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                prb_intvl=re.search('periodic-probe-interval ([0-9]+)',output)
                if prb_intvl.group(1)=='300':
                    rcry_intvl=re.search('port-recovery-interval ([0-9]+)',output)
                    if rcry_intvl.group(1)=='600':
                        log.info("ngoam looop-detectioon is enabled andd dddefault values are active")
                    else:
                        log.info("ngoam loop-detection recoovery interval does not match default value")
                        self.failed("ngoam loop-detection recoovery interval does not match default value", goto=['cleanup'])
                else:
                    log.info("ngoam loop-detection probe interval does not match default value")
                    self.failed("ngoam loop-detection probe interval does not match default value", goto=['cleanup'])
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_is_enabled_for_default_values(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Loop detection:(enabled)',output)
            if m:
                if m.group(1)=='enabled':
                    log.info("ngoam looop-detectioon is enabled ")
                    n=re.search('Periodic probe interval: ([0-9]+)',output)
                    if n:
                        if n.group(1)=='300':
                            log.info("ngoam looop-detectioon probe interval shows configured interval value")
                        else:
                            log.info("ngoam looop-detectioon probe interval does not show configured interval value")
                            self.failed("ngoam looop-detectioon probe interval does not show configured interval value", goto=['cleanup'])
                else:
                    log.info("ngoam loop detection is not enabled")
                    self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is not enabled")
                self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying prorbe interval timers', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']

        try:
            LEAF_1.configure('''                
                ngoam loop-detection
                no periodic-probe-interval 500
            ''')
            
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])

# *****************************************************************************************************************************#
class TC008_Minimum_probe_interval(aetest.Testcase):
    """ Non_default_probe_interval """        
    @aetest.test
    def Enable_ngoam_loop_detection(self, testscript):
        """Enable ngoam loop-detection"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            LEAF_1.configure('''
                
              ngoam loop-detection
              periodic-probe-interval 60
          ''')
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
    
    @aetest.test
    def Check_ngoam_running_cfg(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                prb_intvl=re.search('periodic-probe-interval ([0-9]+)',output)
                if prb_intvl.group(1)=='60':
                    rcry_intvl=re.search('port-recovery-interval ([0-9]+)',output)
                    if rcry_intvl.group(1)=='600':
                        log.info("ngoam looop-detectioon is enabled andd dddefault values are active")
                    else:
                        log.info("ngoam loop-detection recoovery interval does not match default value")
                        self.failed("ngoam loop-detection recoovery interval does not match default value", goto=['cleanup'])
                else:
                    log.info("ngoam loop-detection probe interval does not match default value")
                    self.failed("ngoam loop-detection probe interval does not match default value", goto=['cleanup'])
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_is_enabled(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Loop detection:(enabled)',output)
            if m:
                if m.group(1)=='enabled':
                    log.info("ngoam looop-detectioon is enabled ")
                    n=re.search('Periodic probe interval: ([0-9]+)',output)
                    if n:
                        if n.group(1)=='60':
                            log.info("ngoam looop-detectioon probe interval shows configured interval value")
                        else:
                            log.info("ngoam looop-detectioon probe interval does not show configured interval value")
                            self.failed("ngoam looop-detectioon probe interval does not show configured interval value", goto=['cleanup'])
                else:
                    log.info("ngoam loop detection is not enabled")
                    self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is not enabled")
                self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying prorbe interval timers', goto=['cleanup'])
            
    @aetest.test
    def Enable_loop_detection_default_values(self, testscript):
        """Enable ngoam loop-detection"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            LEAF_1.configure('''
                
              ngoam loop-detection
              no periodic-probe-interval 60
          ''')
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring loop-detection', goto=['cleanup'])
    
    @aetest.test
    def Check_ngoam_running_cfg_for_default_values(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                prb_intvl=re.search('periodic-probe-interval ([0-9]+)',output)
                if prb_intvl.group(1)=='300':
                    rcry_intvl=re.search('port-recovery-interval ([0-9]+)',output)
                    if rcry_intvl.group(1)=='600':
                        log.info("ngoam looop-detectioon is enabled andd dddefault values are active")
                    else:
                        log.info("ngoam loop-detection recoovery interval does not match default value")
                        self.failed("ngoam loop-detection recoovery interval does not match default value", goto=['cleanup'])
                else:
                    log.info("ngoam loop-detection probe interval does not match default value")
                    self.failed("ngoam loop-detection probe interval does not match default value", goto=['cleanup'])
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_is_enabled_for_default_values(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Loop detection:(enabled)',output)
            if m:
                if m.group(1)=='enabled':
                    log.info("ngoam looop-detectioon is enabled ")
                    n=re.search('Periodic probe interval: ([0-9]+)',output)
                    if n:
                        if n.group(1)=='300':
                            log.info("ngoam looop-detectioon probe interval shows configured interval value")
                        else:
                            log.info("ngoam looop-detectioon probe interval does not show configured interval value")
                            self.failed("ngoam looop-detectioon probe interval does not show configured interval value", goto=['cleanup'])
                else:
                    log.info("ngoam loop detection is not enabled")
                    self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is not enabled")
                self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying prorbe interval timers', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']

        try:
            LEAF_1.configure('''                
                ngoam loop-detection
                no periodic-probe-interval 60
            ''')
            
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class TC009_Maximum_probe_interval(aetest.Testcase):
    """ Non_default_probe_interval """        
    @aetest.test
    def Enable_ngoam_loop_detection(self, testscript):
        """Enable ngoam loop-detection"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            LEAF_1.configure('''
                
              ngoam loop-detection
              periodic-probe-interval 3600
          ''')
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
    
    @aetest.test
    def Check_ngoam_running_cfg(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                prb_intvl=re.search('periodic-probe-interval ([0-9]+)',output)
                if prb_intvl.group(1)=='3600':
                    rcry_intvl=re.search('port-recovery-interval ([0-9]+)',output)
                    if rcry_intvl.group(1)=='600':
                        log.info("ngoam looop-detectioon is enabled andd dddefault values are active")
                    else:
                        log.info("ngoam loop-detection recoovery interval does not match default value")
                        self.failed("ngoam loop-detection recoovery interval does not match default value", goto=['cleanup'])
                else:
                    log.info("ngoam loop-detection probe interval does not match default value")
                    self.failed("ngoam loop-detection probe interval does not match default value", goto=['cleanup'])
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_is_enabled(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Loop detection:(enabled)',output)
            if m:
                if m.group(1)=='enabled':
                    log.info("ngoam looop-detectioon is enabled ")
                    n=re.search('Periodic probe interval: ([0-9]+)',output)
                    if n:
                        if n.group(1)=='3600':
                            log.info("ngoam looop-detectioon probe interval shows configured interval value")
                        else:
                            log.info("ngoam looop-detectioon probe interval does not show configured interval value")
                            self.failed("ngoam looop-detectioon probe interval does not show configured interval value", goto=['cleanup'])
                else:
                    log.info("ngoam loop detection is not enabled")
                    self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is not enabled")
                self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying prorbe interval timers', goto=['cleanup'])
    
    @aetest.test
    def Enable_loop_detection_default_values(self, testscript):
        """Enable ngoam loop-detection"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            LEAF_1.configure('''
                
              ngoam loop-detection
              no periodic-probe-interval 3600
          ''')
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring loop-detection', goto=['cleanup'])
    
    @aetest.test
    def Check_ngoam_running_cfg_for_default_values(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                prb_intvl=re.search('periodic-probe-interval ([0-9]+)',output)
                if prb_intvl.group(1)=='300':
                    rcry_intvl=re.search('port-recovery-interval ([0-9]+)',output)
                    if rcry_intvl.group(1)=='600':
                        log.info("ngoam looop-detectioon is enabled andd dddefault values are active")
                    else:
                        log.info("ngoam loop-detection recoovery interval does not match default value")
                        self.failed("ngoam loop-detection recoovery interval does not match default value", goto=['cleanup'])
                else:
                    log.info("ngoam loop-detection probe interval does not match default value")
                    self.failed("ngoam loop-detection probe interval does not match default value", goto=['cleanup'])
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_is_enabled_for_default_values(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Loop detection:(enabled)',output)
            if m:
                if m.group(1)=='enabled':
                    log.info("ngoam looop-detectioon is enabled ")
                    n=re.search('Periodic probe interval: ([0-9]+)',output)
                    if n:
                        if n.group(1)=='300':
                            log.info("ngoam looop-detectioon probe interval shows configured interval value")
                        else:
                            log.info("ngoam looop-detectioon probe interval does not show configured interval value")
                            self.failed("ngoam looop-detectioon probe interval does not show configured interval value", goto=['cleanup'])
                else:
                    log.info("ngoam loop detection is not enabled")
                    self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is not enabled")
                self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying prorbe interval timers', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']

        try:
            LEAF_1.configure('''                
                ngoam loop-detection
                no periodic-probe-interval 3600
            ''')
            
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class TC010_Non_default_port_recovery_interval(aetest.Testcase):
    """ Non_default_probe_interval """        
    @aetest.test
    def Enable_ngoam_loop_detection(self, testscript):
        """Enable ngoam loop-detection"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            LEAF_1.configure('''
                
              ngoam loop-detection
              port-recovery-interval 800
          ''')
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
    
    @aetest.test
    def Check_ngoam_running_cfg(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                prb_intvl=re.search('periodic-probe-interval ([0-9]+)',output)
                if prb_intvl.group(1)=='300':
                    rcry_intvl=re.search('port-recovery-interval ([0-9]+)',output)
                    if rcry_intvl.group(1)=='800':
                        log.info("ngoam looop-detectioon is enabled andd dddefault values are active")
                    else:
                        log.info("ngoam loop-detection recoovery interval does not match default value")
                        self.failed("ngoam loop-detection recoovery interval does not match default value", goto=['cleanup'])
                else:
                    log.info("ngoam loop-detection probe interval does not match default value")
                    self.failed("ngoam loop-detection probe interval does not match default value", goto=['cleanup'])
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_is_enabled(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Loop detection:(enabled)',output)
            if m:
                if m.group(1)=='enabled':
                    log.info("ngoam looop-detectioon is enabled ")
                    n=re.search('Port recovery interval: ([0-9]+)',output)
                    if n:
                        if n.group(1)=='800':
                            log.info("ngoam looop-detectioon port-recovery interval shows configured interval value")
                        else:
                            log.info("ngoam looop-detectioon port-recovery interval does not show configured interval value")
                            self.failed("ngoam looop-detectioon port-recovery interval does not show configured interval value", goto=['cleanup'])
                else:
                    log.info("ngoam loop detection is not enabled")
                    self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is not enabled")
                self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying port-recovery interval timers', goto=['cleanup'])
    
    @aetest.test
    def Enable_loop_detection_default_values(self, testscript):
        """Enable ngoam loop-detection"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            LEAF_1.configure('''
                
              ngoam loop-detection
              no port-recovery-interval 800
          ''')
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring loop-detection', goto=['cleanup'])
    
    @aetest.test
    def Check_ngoam_running_cfg_for_default_values(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                prb_intvl=re.search('periodic-probe-interval ([0-9]+)',output)
                if prb_intvl.group(1)=='300':
                    rcry_intvl=re.search('port-recovery-interval ([0-9]+)',output)
                    if rcry_intvl.group(1)=='600':
                        log.info("ngoam looop-detectioon is enabled andd dddefault values are active")
                    else:
                        log.info("ngoam loop-detection recovery interval does not match default value")
                        self.failed("ngoam loop-detection recovery interval does not match default value", goto=['cleanup'])
                else:
                    log.info("ngoam loop-detection probe interval does not match default value")
                    self.failed("ngoam loop-detection probe interval does not match default value", goto=['cleanup'])
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_is_enabled_for_default_values(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Loop detection:(enabled)',output)
            if m:
                if m.group(1)=='enabled':
                    log.info("ngoam looop-detectioon is enabled ")
                    n=re.search('Port recovery interval: ([0-9]+)',output)
                    if n:
                        if n.group(1)=='600':
                            log.info("ngoam looop-detectioon probe interval shows configured interval value")
                        else:
                            log.info("ngoam looop-detectioon probe interval does not show configured interval value")
                            self.failed("ngoam looop-detectioon probe interval does not show configured interval value", goto=['cleanup'])
                else:
                    log.info("ngoam loop detection is not enabled")
                    self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is not enabled")
                self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying prorbe interval timers', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']

        try:
            LEAF_1.configure('''                
                ngoam loop-detection
                no port-recovery-interval 800
            ''')
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        
        except Exception as error:
            log.debug("Unable to perform cleanup-Encountered exception " + str(error))
            self.errored('Exception occurred during LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class TC011_Maximum_port_recovery_interval(aetest.Testcase):
    """ Non_default_probe_interval """        
    @aetest.test
    def Enable_ngoam_loop_detection(self, testscript):
        """Enable ngoam loop-detection"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            LEAF_1.configure('''
                
              ngoam loop-detection
              port-recovery-interval 3600
          ''')
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring minimum port-recovery-interval', goto=['cleanup'])
    
    @aetest.test
    def Check_ngoam_running_cfg(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                prb_intvl=re.search('periodic-probe-interval ([0-9]+)',output)
                if prb_intvl.group(1)=='300':
                    rcry_intvl=re.search('port-recovery-interval ([0-9]+)',output)
                    if rcry_intvl.group(1)=='3600':
                        log.info("ngoam looop-detectioon is enabled andd dddefault values are active")
                    else:
                        log.info("ngoam loop-detection recoovery interval does not match default value")
                        self.failed("ngoam loop-detection recoovery interval does not match default value", goto=['cleanup'])
                else:
                    log.info("ngoam loop-detection probe interval does not match default value")
                    self.failed("ngoam loop-detection probe interval does not match default value", goto=['cleanup'])
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_is_enabled(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Loop detection:(enabled)',output)
            if m:
                if m.group(1)=='enabled':
                    log.info("ngoam looop-detectioon is enabled ")
                    n=re.search('Port recovery interval: ([0-9]+)',output)
                    if n:
                        if n.group(1)=='3600':
                            log.info("ngoam looop-detectioon port-recovery interval shows configured interval value")
                        else:
                            log.info("ngoam looop-detectioon port-recovery interval does not show configured interval value")
                            self.failed("ngoam looop-detectioon port-recovery interval does not show configured interval value", goto=['cleanup'])
                else:
                    log.info("ngoam loop detection is not enabled")
                    self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is not enabled")
                self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying port-recovery interval timers', goto=['cleanup'])
    
    @aetest.test
    def Enable_loop_detection_default_values(self, testscript):
        """Enable ngoam loop-detection"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            LEAF_1.configure('''
                
              ngoam loop-detection
              no port-recovery-interval 3600
          ''')
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring loop-detection', goto=['cleanup'])
    
    @aetest.test
    def Check_ngoam_running_cfg_for_default_values(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh run ngoam''')
            if "feature ngoam" not in output:
                log.info("feature ngoam not enabled")
                self.failed("feature ngoam not enabled", goto=['cleanup'])
            elif "ngoam loop-detection" not in output:
                log.info("ngoam loop-detection not enabled")
                self.failed("ngoam loop-detection not enabled", goto=['cleanup'])
            else:
                prb_intvl=re.search('periodic-probe-interval ([0-9]+)',output)
                if prb_intvl.group(1)=='300':
                    rcry_intvl=re.search('port-recovery-interval ([0-9]+)',output)
                    if rcry_intvl.group(1)=='600':
                        log.info("ngoam looop-detectioon is enabled andd dddefault values are active")
                    else:
                        log.info("ngoam loop-detection recovery interval does not match default value")
                        self.failed("ngoam loop-detection recovery interval does not match default value", goto=['cleanup'])
                else:
                    log.info("ngoam loop-detection probe interval does not match default value")
                    self.failed("ngoam loop-detection probe interval does not match default value", goto=['cleanup'])
            
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_is_enabled_for_default_values(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Loop detection:(enabled)',output)
            if m:
                if m.group(1)=='enabled':
                    log.info("ngoam looop-detectioon is enabled ")
                    n=re.search('Port recovery interval: ([0-9]+)',output)
                    if n:
                        if n.group(1)=='600':
                            log.info("ngoam looop-detectioon probe interval shows configured interval value")
                        else:
                            log.info("ngoam looop-detectioon probe interval does not show configured interval value")
                            self.failed("ngoam looop-detectioon probe interval does not show configured interval value", goto=['cleanup'])
                else:
                    log.info("ngoam loop detection is not enabled")
                    self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
            else:
                log.info("ngoam loop detection is not enabled")
                self.failed("ngoam loop detection is not enabled", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying prorbe interval timers', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']

        try:
            LEAF_1.configure('''                
                ngoam loop-detection
                no port-recovery-interval 3600
            ''')
            
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

        except Exception as error:
            log.debug("Unable to perform cleanup-Encountered exception " + str(error))
            self.errored('Exception occurred during LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class TC012_Send_manual_probe(aetest.Testcase):
    """ Disable_Enable_loop_detection_for_vlans """  
            
    @aetest.test
    def Enable_ngoam_loop_detection_on_vlans(self, testscript):
        """Enable_ngoam_loop_detection_on_vlans"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''
                
              ngoam loop-detection
              no disable vlan ''' + str(l2_vlan_id) +'''-''' + str(vlan_end)
             )
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while disabling loop-detection on vlans and ports', goto=['cleanup'])
            
    @aetest.test
    def Get_no_of_probes_sent(self, testscript):
        """Get_no_of_probes_sent"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Total number of probes sent: ([0-9]+)',output)
            if m:
                no_of_probes=m.group(1)
                log.info("no of probes sent:"+no_of_probes)
            else:
                log.info("could not get no of probes sent from loop-detectioon summary")
                self.failed("could not get no of probes sent from loop-detectioon summary", goto=['cleanup'])
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_1.execute('''ngoam loop-detection probe vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            time.sleep(2)
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Total number of probes sent: ([0-9]+)',output)
            if m:
                new_no_of_probes=m.group(1)
                log.info("no of probes sent after manual probe:"+new_no_of_probes)
            else:
                log.info("could not get no of probes sent from loop-detectioon summary")
                self.failed("could not get no of probes sent from loop-detectioon summary", goto=['cleanup'])
            if int(new_no_of_probes)-int(no_of_probes)==no_of_vlans:
                log.info("Probe sent after manual probe cli executed.")
            else:
                log.info("Probe not sent or number of probes sent does not match expected value")
                self.failed("Probe not sent or number of probes sent does not match expected value", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying disabling loop-detection on vlans and ports', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']

        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''                
                ngoam loop-detection
                no disable vlan ''' + str(l2_vlan_id) +'''-''' + str(vlan_end) + ''' port ''' + str(testscript.parameters['intf_LEAF_1_to_LEAF_3']) + ''', ''' +str(testscript.parameters['intf_LEAF_1_to_LEAF_2_5'])+'''
            ''')
            
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class TC013_Collect_ngoam_techsupport(aetest.Testcase):
    """ Disable_Enable_loop_detection_for_vlans """
            
    @aetest.test
    def Enable_ngoam_loop_detection_on_vlans(self, testscript):
        """Enable_ngoam_loop_detection_on_vlans"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''
              ngoam loop-detection
             ''')
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while disabling loop-detection on vlans and ports', goto=['cleanup'])
            
    @aetest.test
    def Collect_TS(self, testscript):
        """Get_no_of_probes_sent"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        
        try:
            LEAF_1.execute('delete bootflash:ngoam.TS no',timeout=120)
            LEAF_1.execute('delete bootflash:l2rib.TS no',timeout=120)
            LEAF_1.execute('delete bootflash:vxlan-evpn.TS no',timeout=120)

            LEAF_1.execute('sh tech-support ngoam > bootflash:ngoam.TS',timeout=1200)
            LEAF_1.execute('sh tech-support l2rib > bootflash:l2rib.TS',timeout=1200)
            LEAF_1.execute('sh tech-support vxlan-evpn > bootflash:vxlan-evpn.TS',timeout=1800)
            output=LEAF_1.execute('''dir bootflash:ngoam.TS''')
            m=re.search('[0-9]+\s+[a-zA-Z]+\s[0-9]+\s[0-9]+:[0-9]+:[0-9]+\s+[0-9]+\s+ngoam.TS',output)
            if m:
                log.info('collecting ngoam TS has passed')
                output=LEAF_1.execute('''dir bootflash:l2rib.TS''')
                n=re.search('[0-9]+\s+[a-zA-Z]+\s[0-9]+\s[0-9]+:[0-9]+:[0-9]+\s+[0-9]+\s+l2rib.TS',output)
                if n:
                    log.info('collecting L2rib TS has passed')
                    output=LEAF_1.execute('''dir bootflash:vxlan-evpn.TS''')
                    o=re.search('[0-9]+\s+[a-zA-Z]+\s[0-9]+\s[0-9]+:[0-9]+:[0-9]+\s+[0-9]+\s+vxlan-evpn.TS',output)
                    if o:
                        log.info('collecting vxlan-evpn TS has passed')
                    else:
                        log.info('collecting vxlan-evpn TS has failed')
                        self.failed('collecting vxlan-evpn TS has failed',goto=['cleanup'])
                else:
                    log.info('collecting L2rib TS has failed')
                    self.failed('collecting L2rib TS has failed',goto=['cleanup'])
            else:
                log.info('collecting ngoam TS has failed')
                self.failed('collecting ngoam TS has failed',goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying disabling loop-detection on vlans and ports', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']

        try:
            LEAF_1.configure('''
                           del bootflash:ngoam.TS no
                           del bootflash:l2rib.TS no
                           del bootflash:vxlan-evpn.TS no
            ''', timeout=600)
            
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
            
# *****************************************************************************************************************************#
class TC014_Enable_SLD_verify_probe(aetest.Testcase):
    """ Disable_Enable_loop_detection_for_vlans """
            
    @aetest.test
    def Enable_ngoam_loop_detection_on_vlans(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''
              ngoam loop-detection 
              '''
             )
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection status''')
            if 'BLOCKED' in output or 'RECOVERING' in output:
                log.info('Loop already present and detected in switch. Please ensure no loop for this tc.')
                self.failed('Loop already present and detected in switch. Please ensure no loop for this tc.',goto=['cleanup'])
            else:
                log.info('No loop detected in switch. Continuing to next section')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
            
    @aetest.test
    def Disable_spanning_tree_for_the_vlan(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_1.config('''no spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while disabling sspanning tree on LEAF-1', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next probe window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                probe_window=int(m.group(1))
                log.info("Got the next probe window time from loop-detection summary. Sleeing for that time window")
                time.sleep(probe_window+2)
            else:
                log.info("Couldn't get the next probe window time from loop-detection summary")
                self.failed("Couldn't get the next probe window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_after_probe(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection status''')
            if 'BLOCKED' in output or 'RECOVERING' in output:
                log.info('Loop detected in switch.')
                self.failed('Loop detected in switch.',goto=['cleanup'])
            else:
                log.info('No loop detected in switch. Continuing to next section')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
    
    @aetest.test
    def Enable_spanning_tree_for_the_vlan(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_1.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while enabling sspanning tree on LEAF-1', goto=['cleanup'])
    
    @aetest.test
    def Get_next_probe_window_time(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next probe window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                probe_window=int(m.group(1))
                log.info("Got the next probe window time from loop-detection summary. Sleeing for that time window")
                time.sleep(probe_window+2)
            else:
                log.info("Couldn't get the next probe window time from loop-detection summary")
                self.failed("Couldn't get the next probe window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_after_probe_with_stp(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection status''')
            if 'BLOCKED' in output or 'RECOVERING' in output:
                log.info('Loop detected in switch.')
                self.failed('Loop detected in switch.',goto=['cleanup'])
            else:
                log.info('No loop detected in switch. Pass')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']

        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_1.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])
        
        except Exception as error:
            log.debug("Error occurred during cleanup " + str(error))
            self.errored('Exception occurred during cleanup', goto=['next_tc'])

# *****************************************************************************************************************************#
class TC015_Back_to_Back_Link_loop_detection(aetest.Testcase):
    """  One Front-Panel Port to another Front-panel port on same Leaf """ 
            
    @aetest.test
    def Enable_ngoam_loop_detection(self, testscript):
        """Enable ngoam loop-detection"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_3.configure('''
                
              ngoam loop-detection
              periodic-probe-interval 60
              port-recovery-interval 300
              '''
             )
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Disable_spanning_tree_for_the_vlan(self, testscript):
        """Disable_spanning_tree_for_the_vlan"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_3.configure('''no spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while disabling sspanning tree on LEAF-1', goto=['cleanup'])
            
    @aetest.test
    def configure_back_to_back_interfaces(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_3.configure('''
                          interface '''+testscript.parameters['intf_LEAF_3_to_LEAF_3_1']+','+testscript.parameters['intf_LEAF_3_to_LEAF_3_2']+'''
                          no shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
            ''')
            time.sleep(25)
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring interrfacs for loop', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=testscript.parameters['intf_LEAF_3_to_LEAF_3_1']
        int2=testscript.parameters['intf_LEAF_3_to_LEAF_3_2']
        int_1=int1.split('Ethernet')
        int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        for vlan in l2_vlans:
            output=LEAF_3.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
            for line in output.split('\n'):
                m=re.search('^([0-9]+)\s+Eth([0-9]+\/[0-9]+)\s+BLOCKED',line)
                if m:
                    if m.group(1)==str(vlan):
                        if m.group(2)==int1 or m.group(2)==int2:
                            log.info('The loop has been detected and the port ETH'+str(m.group(2))+ ' is blocked for vlan '+ str(vlan))
                        else:
                            log.info('The loop has NOT been detected')
                            self.failed('The loop has NOT been detected',goto=['cleanup'])
                    else:
                        log.info('The loop has NOT been detected for vlan '+str(vlan))
                        self.failed('The loop has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                else:
                    log.info('The loop has NOT been detected')
                    self.failed('The loop has NOT been detected',goto=['cleanup'])
            
    @aetest.test
    def unconfigure_back_to_back_interfaces(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_3.config('''
                          interface '''+testscript.parameters['intf_LEAF_3_to_LEAF_3_2']+'''
                          shut
                          ''')
            time.sleep(5)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while removing loop', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_3.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    # @aetest.test
    # def Verify_loop_detection_status_2(self, testscript):
    #     """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
    #     LEAF_1 = testscript.parameters['LEAF-1']
    #     LEAF_2 = testscript.parameters['LEAF-2']
    #     LEAF_3 = testscript.parameters['LEAF-3']
    #     no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
    #     l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
    #     l2_vlans=[]
    #     int1=testscript.parameters['intf_LEAF_3_to_LEAF_3_1']
    #     int2=testscript.parameters['intf_LEAF_3_to_LEAF_3_2']
    #     int_1=int1.split('Ethernet')
    #     int1=int_1[1]
    #     int_2=int2.split('Ethernet')
    #     int2=int_2[1]
        
    #     for i in range (no_of_vlans):
    #         l2_vlans.append(l2_vlan_id)
    #         l2_vlan_id+=1
    #     for vlan in l2_vlans:
    #         output=LEAF_3.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
    #         for line in output.split('\n'):
    #             m=re.search('^([0-9]+)\s+Eth([0-9]+\/[0-9]+)\s+RECOVERING',line)
    #             if m:
    #                 if m.group(1)==str(vlan):
    #                     if m.group(2)==int1:
    #                         log.info('The loop clearing has been detected and the port '+'ETH'+m.group(2)+ ' is in Recovery for vlan '+ str(vlan))
    #                     else:
    #                         log.info('The loop clear has NOT been detected')
    #                         self.failed('The loop clear has NOT been detected',goto=['cleanup'])
    #                 else:
    #                     log.info('The loop clear has NOT been detected for vlan '+str(vlan))
    #                     self.failed('The loop clear has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
    #             else:
    #                 log.info('The loop clear has NOT been detected')
    #                 self.failed('The loop clear has NOT been detected',goto=['cleanup'])
    
    # @aetest.test
    # def Verify_loop_detection_summary_for_recovery(self, testscript):
    #     """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
    #     LEAF_1 = testscript.parameters['LEAF-1']
    #     LEAF_2 = testscript.parameters['LEAF-2']
    #     LEAF_3 = testscript.parameters['LEAF-3']
    #     no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
    #     try:
    #         output=LEAF_3.execute('''sh ngoam loop-detection summary''')
    #         m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
    #         if m:
    #             recovery_window=int(m.group(1))
    #             log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
    #             time.sleep(recovery_window+2)
    #         else:
    #             log.info("Couldn't get the next recovery window time from loop-detection summary")
    #             self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
    #     except Exception as error:
    #         log.debug("Unable to configure - Encountered Exception " + str(error))
    #         self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_after_loop_clear(self, testscript):
        """Verify_loop_detection_status"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_3.execute('''sh ngoam loop-detection status''')
            if 'BLOCKED' in output or 'RECOVERING' in output:
                log.info('Loop still present and detected in switch. ')
                self.failed('Loop still present and detected in switch.',goto=['cleanup'])
            else:
                log.info('No loop detected in switch. Continuing to next section')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
            
    @aetest.test
    def Enable_spanning_tree_for_the_vlan(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_3.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while enabling sspanning tree on LEAF-1', goto=['cleanup'])
    
    @aetest.test
    def configure_back_to_back_interfaces_STP(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_3.config('''
                          interface '''+testscript.parameters['intf_LEAF_3_to_LEAF_3_1']+','+testscript.parameters['intf_LEAF_3_to_LEAF_3_2']+'''
                          no shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
            ''')
            ###adding sleep to give stp time to converge
            time.sleep(60)
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring interrfacs for loop', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_STP_1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=testscript.parameters['intf_LEAF_3_to_LEAF_3_1']
        int2=testscript.parameters['intf_LEAF_3_to_LEAF_3_2']
        int_1=int1.split('Ethernet')
        int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        result=[]
        ###first we will check if the ports are blocked in STP.
        for vlan in l2_vlans:
            output=LEAF_3.execute('sh spanning-tree vlan '+ str(vlan) +' | i '+str(int1))
        
            n=re.search('^Eth[0-9]+\/[0-9]+\s+[a-zA-Z]+\s+(FWD|BLK).*',output)
            if n:
                if n.group(1)=='FWD':
                    output=LEAF_3.execute('sh spanning-tree vlan '+ str(vlan) +' | i '+str(int2))
                    p=re.search('^Eth[0-9]+\/[0-9]+\s+[a-zA-Z]+\s+(FWD|BLK).*',output)
                    if p:
                        if p.group(1)=='FWD':
                            #for vlan in l2_vlans:
                            output=LEAF_3.execute('sh ngoam loop-detection status | i ' + str(vlan))
                            for line in output.split('\n'):
                                m=re.search('^([0-9]+)\s+Eth([0-9]+\/[0-9]+)\s+BLOCKED',line)
                                if m:
                                    if m.group(1)==str(vlan):
                                        if m.group(2)==int1 or m.group(2)==int2:
                                            log.info('The loop has been detected and the port '+'ETH'+m.group(2)+ ' is blocked for vlan '+ str(vlan))
                                        else:
                                            log.info('The loop has NOT been detected')
                                            self.failed('The loop has NOT been detected',goto=['cleanup'])
                                    else:
                                        log.info('The loop has NOT been detected for vlan '+str(vlan))
                                        self.failed('The loop has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                                else:
                                    log.info('The loop has NOT been detected')
                                    self.failed('The loop has NOT been detected',goto=['cleanup'])
                        elif p.group(1)=='BLK':
                            log.info('Loop has been mitigated by STP for vlan '+str(vlan)+'.Port will not be blocked by SLD')
                            result.append(1)
                    else:
                        log.info('STP state not converged')
                        self.failed('STP state not converged',goto=['cleanup'])
                elif n.group(1)=='BLK':
                    log.info('Loop has been mitigated by STP for vlan '+str(vlan)+'.Port will not be blocked by SLD')
                    result.append(1)
            else:
                log.info('STP state not converged. Will check if SLD has blocked the port')
                output=LEAF_3.execute('sh ngoam loop-detection status | i ' + str(vlan))
                for line in output.split('\n'):
                    m=re.search('^([0-9]+)\s+Eth([0-9]+\/[0-9]+)\s+BLOCKED',line)
                    if m:
                        if m.group(1)==str(vlan):
                            if m.group(2)==int1 or m.group(2)==int2:
                                log.info('The loop has been detected and the port '+'ETH'+m.group(2)+ ' is blocked for vlan '+ str(vlan))
                            else:
                                log.info('The loop has NOT been detected')
                                self.failed('The loop has NOT been detected',goto=['cleanup'])
                        else:
                            log.info('The loop has NOT been detected for vlan '+str(vlan))
                            self.failed('The loop has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                    else:
                        log.info('The loop has NOT been detected')
                        self.failed('The loop has NOT been detected',goto=['cleanup'])
                #self.failed('STP state not converged',goto=['cleanup'])
        for i in result:
            if i==1:
                log.info('Skipping rest of th SLD sections')
                self.passed('Skipping rest of th SLD sections',goto=['cleanup'])
                break
            
    @aetest.test
    def unconfigure_back_to_back_interfaces_STP(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_3.config('''
                          interface '''+testscript.parameters['intf_LEAF_3_to_LEAF_3_2']+'''
                          shut
                          ''')
            time.sleep(5)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while removing loop', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary_STP(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_3.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_STP_2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=testscript.parameters['intf_LEAF_3_to_LEAF_3_1']
        int2=testscript.parameters['intf_LEAF_3_to_LEAF_3_2']
        int_1=int1.split('Ethernet')
        int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]
        
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        for vlan in l2_vlans:
            output=LEAF_3.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
            for line in output.split('\n'):
                m=re.search('^([0-9]+)\s+Eth([0-9]+\/[0-9]+)\s+RECOVERING',line)
                if m:
                    if m.group(1)==str(vlan):
                        if m.group(2)==int1:
                            log.info('The loop clearing has been detected and the port '+'ETH'+m.group(2)+ ' is in Recovery for vlan '+ str(vlan))
                        else:
                            log.info('The loop clear has NOT been detected')
                            self.failed('The loop clear has NOT been detected',goto=['cleanup'])
                    else:
                        log.info('The loop clear has NOT been detected for vlan '+str(vlan))
                        self.failed('The loop clear has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                else:
                    log.info('The loop clear has NOT been detected')
                    self.failed('The loop clear has NOT been detected',goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_summary_for_recovery_STP(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_after_loop_clear_STP(self, testscript):
        """Verify_loop_detection_status"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection status''')
            if 'BLOCKED' in output or 'RECOVERING' in output:
                log.info('Loop still present and detected in switch. ')
                self.failed('Loop still present and detected in switch.',goto=['cleanup'])
            else:
                log.info('No loop detected in switch. Continuing to next section')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_3 = testscript.parameters['LEAF-3']

        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']

        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_3.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_3.config('''
                interface '''+testscript.parameters['intf_LEAF_3_to_LEAF_3_2']+'''
                shut
            ''')
            
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])
        
# *****************************************************************************************************************************#
class TC016_Vpc1_to_Vpc2_Link_loop_detection(aetest.Testcase):
    """  One Front-Panel Port of vpc1 to another Front-panel port of vpc2 """
    leaf1_loop_detect=False
    leaf2_loop_detect=False      
            
    @aetest.test
    def Enable_ngoam_loop_detection(self, testscript):
        """Enable ngoam loop-detection"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''
                
              ngoam loop-detection
              periodic-probe-interval 60
              port-recovery-interval 300
              '''
             )
            LEAF_2.configure('''
                
              ngoam loop-detection
              periodic-probe-interval 60
              port-recovery-interval 300
              '''
             )
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Disable_spanning_tree_for_the_vlan(self, testscript):
        """Disable_spanning_tree_for_the_vlan"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_1.configure('''no spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_2.configure('''no spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while disabling sspanning tree on LEAF-1', goto=['cleanup'])
    
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
    
    @aetest.test
    def configure_loop_interfaces(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_1.configure('''
                          def interface '''+testscript.parameters['intf_LEAF_1_to_LEAF_2_3']+'''
                          interface '''+testscript.parameters['intf_LEAF_1_to_LEAF_2_3']+'''
                          no shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
            ''', timeout=800)
            LEAF_2.configure('''
                          def interface '''+testscript.parameters['intf_LEAF_2_to_LEAF_1_3']+'''
                          interface '''+testscript.parameters['intf_LEAF_2_to_LEAF_1_3']+'''
                          no shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
            ''', timeout=800)
            time.sleep(15)
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring interrfacs for loop', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=testscript.parameters['intf_LEAF_1_to_LEAF_2_3']
        int2=testscript.parameters['intf_LEAF_2_to_LEAF_1_3']
        int_1=int1.split('Ethernet')
        int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]
        global leaf1_loop_detect
        global leaf2_loop_detect
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        
        for vlan in l2_vlans:
            leaf1_loop_detect=verify_loop_detection(testscript,LEAF_1,vlan,int1)
            leaf2_loop_detect=verify_loop_detection(testscript,LEAF_2,vlan,int2)
            if leaf1_loop_detect or leaf2_loop_detect:
                log.info('Loop detected for vlan '+str(vlan))
                continue
            else:
                log.info('Loop not detected for vlan '+str(vlan))
                self.failed('The loop has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
            
    @aetest.test
    def unconfigure_loop_interfaces(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            if leaf1_loop_detect:
                LEAF_2.config('''
                              interface '''+testscript.parameters['intf_LEAF_2_to_LEAF_1_3']+'''
                              shut
                              ''')
            elif leaf2_loop_detect:
                LEAF_1.config('''
                              interface '''+testscript.parameters['intf_LEAF_1_to_LEAF_2_3']+'''
                              shut
                              ''')
            time.sleep(5)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while removing loop', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            elif leaf2_loop_detect:
                output=LEAF_2.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=testscript.parameters['intf_LEAF_1_to_LEAF_2_3']
        int2=testscript.parameters['intf_LEAF_2_to_LEAF_1_3']
        int_1=int1.split('Ethernet')
        int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]
        
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        for vlan in l2_vlans:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
            elif leaf2_loop_detect:
                output=LEAF_2.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
            for line in output.split('\n'):
                m=re.search('^([0-9]+)\s+Eth([0-9]+\/[0-9]+)\s+RECOVERING',line)
                if m:
                    if m.group(1)==str(vlan):
                        if m.group(2)==int1 or m.group(2)==int2:
                            log.info('The loop clearing has been detected and the port '+'ETH'+m.group(2)+ ' is in Recovery for vlan '+ str(vlan))
                        else:
                            log.info('The loop clear has NOT been detected')
                            self.failed('The loop clear has NOT been detected',goto=['cleanup'])
                    else:
                        log.info('The loop clear has NOT been detected for vlan '+str(vlan))
                        self.failed('The loop clear has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                else:
                    log.info('The loop clear has NOT been detected')
                    self.failed('The loop clear has NOT been detected',goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_summary_for_recovery(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            elif leaf2_loop_detect:
                output=LEAF_2.execute('''sh ngoam loop-detection summary''')
            
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_after_loop_clear(self, testscript):
        """Verify_loop_detection_status"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection status''')
            elif leaf2_loop_detect:
                output=LEAF_2.execute('''sh ngoam loop-detection status''')
            
            if 'BLOCKED' in output or 'RECOVERING' in output:
                log.info('Loop still present and detected in switch. ')
                self.failed('Loop still present and detected in switch.',goto=['cleanup'])
            else:
                log.info('No loop detected in switch. Continuing to next section')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
            
    @aetest.test
    def Enable_spanning_tree_for_the_vlan(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_1.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_2.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while enabling sspanning tree on LEAF-1', goto=['cleanup'])
    
    @aetest.test
    def configure_vpc1_to_vpc2_interfaces_STP(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_1.configure('''
                          def interface '''+testscript.parameters['intf_LEAF_1_to_LEAF_2_3']+'''
                          interface '''+testscript.parameters['intf_LEAF_1_to_LEAF_2_3']+'''
                          shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
                          no shut
            ''', timeout=800)
            LEAF_2.configure('''
                          def interface '''+testscript.parameters['intf_LEAF_2_to_LEAF_1_3']+'''
                          interface '''+testscript.parameters['intf_LEAF_2_to_LEAF_1_3']+'''
                          shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
                          no shut
            ''', timeout=800)
            ###adding sleep to give stp time to converge
            time.sleep(60)
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring interrfacs for loop', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_STP_1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=testscript.parameters['intf_LEAF_1_to_LEAF_2_3']
        int2=testscript.parameters['intf_LEAF_2_to_LEAF_1_3']
        int_1=int1.split('Ethernet')
        int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        result=[]
        ###first we will check if the ports are blocked in STP.
        #leaf_dut=[LEAF_1,LEAF_2]
        #for dut in leaf_dut:
            
        for vlan in l2_vlans:
            output=LEAF_1.execute('sh spanning-tree vlan '+ str(vlan) +' | i '+str(int1))
        
            n=re.search('^Eth[0-9]+\/[0-9]+\s+[a-zA-Z]+\s+(FWD|BLK).*',output)
            if n:
                if n.group(1)=='FWD':
                    output=LEAF_2.execute('sh spanning-tree vlan '+ str(vlan) +' | i '+str(int2))
                    p=re.search('^Eth[0-9]+\/[0-9]+\/?[0-9]+?\s+[a-zA-Z]+\s+(FWD|BLK).*',output)
                    if p:
                        if p.group(1)=='FWD':
                            log.info('Port in Stp foorwarding state')
                            break
                        elif p.group(1)=='BLK':
                            log.info('Loop has been mitigated by STP for vlan '+str(vlan)+'.Port will not be blocked by SLD')
                            result.append(1)
                            
                    else:
                        log.info('STP state unknown. Port might be blocked by SLD.We will verify in the next section')
                        
                elif n.group(1)=='BLK':
                    log.info('Loop has been mitigated by STP for vlan '+str(vlan)+'.Port will not be blocked by SLD')
                    result.append(1)
            else:
                log.info('STP state unknown. Port might be blocked by SLD.We will verify in the next section')
                #self.failed('STP state not converged',goto=['cleanup'])
        for i in result:
            if i==1:
                log.info('Skipping rest of th SLD sections')
                self.passed('Skipping rest of th SLD sections',goto=['cleanup'])
                break
            
    @aetest.test
    def Verify_loop_detection_status_STP(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=testscript.parameters['intf_LEAF_1_to_LEAF_2_3']
        int2=testscript.parameters['intf_LEAF_2_to_LEAF_1_3']
        int_1=int1.split('Ethernet')
        int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        
        for vlan in l2_vlans:
            leaf1_loop_detect=verify_loop_detection(testscript,LEAF_1,vlan,int1)
            leaf2_loop_detect=verify_loop_detection(testscript,LEAF_2,vlan,int2)
            if leaf1_loop_detect or leaf2_loop_detect:
                log.info('Loop detected for vlan '+str(vlan))
                continue
            else:
                log.info('Loop not detected for vlan '+str(vlan))
                self.failed('The loop has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
    
    @aetest.test
    def unconfigure_back_to_back_interfaces_STP(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            if leaf1_loop_detect:
                LEAF_2.config('''
                              interface '''+testscript.parameters['intf_LEAF_2_to_LEAF_1_3']+'''
                              shut
                              ''')
            elif leaf2_loop_detect:
                LEAF_1.config('''
                              interface '''+testscript.parameters['intf_LEAF_1_to_LEAF_2_3']+'''
                              shut
                              ''')
            time.sleep(5)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while removing loop', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary_STP(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            elif leaf2_loop_detect:
                output=LEAF_2.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_STP_2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=testscript.parameters['intf_LEAF_1_to_LEAF_2_3']
        int2=testscript.parameters['intf_LEAF_2_to_LEAF_1_3']
        int_1=int1.split('Ethernet')
        int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]

        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        for vlan in l2_vlans:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
            elif leaf2_loop_detect:
                output=LEAF_2.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
            for line in output.split('\n'):
                m=re.search('^([0-9]+)\s+Eth([0-9]+\/[0-9]+\/?[0-9]+?)\s+RECOVERING',line)
                if m:
                    if m.group(1)==str(vlan):
                        if m.group(2)==int1:
                            log.info('The loop clearing has been detected and the port '+'ETH'+m.group(2)+ ' is in Recovery for vlan '+ str(vlan))
                        else:
                            log.info('The loop clear has NOT been detected')
                            self.failed('The loop clear has NOT been detected',goto=['cleanup'])
                    else:
                        log.info('The loop clear has NOT been detected for vlan '+str(vlan))
                        self.failed('The loop clear has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                else:
                    log.info('The loop clear has NOT been detected')
                    self.failed('The loop clear has NOT been detected',goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_summary_for_recovery_STP(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            elif leaf2_loop_detect:
                output=LEAF_2.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_after_loop_clear_STP(self, testscript):
        """Verify_loop_detection_status"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection status''')
            elif leaf2_loop_detect:
                output=LEAF_2.execute('''sh ngoam loop-detection status''')
            if 'BLOCKED' in output or 'RECOVERING' in output:
                log.info('Loop still present and detected in switch. ')
                self.failed('Loop still present and detected in switch.',goto=['cleanup'])
            else:
                log.info('No loop detected in switch. Continuing to next section')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
            
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_POST_TC(self, testscript):
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
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']

        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']

        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_2.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_1.config('''
                interface '''+testscript.parameters['intf_LEAF_1_to_LEAF_2_3']+'''
                shut
            ''')
            status = infraVerify.postTestVerification(post_test_process_dict)
            if status['status'] == 0:
                self.failed(reason=status['logs'])
            else:
                self.passed(reason=status['logs'])

        except Exception as error:
            log.debug("Unable to unconfigure class map or policy map-Encountered exception " + str(error))
            self.errored('Exception occurred while unconfiguring qos on LEAF1', goto=['next_tc'])

# *****************************************************************************************************************************#
class TC017_Vpc1_to_standalone_Link_loop_detection(aetest.Testcase):
    """  One Front-Panel Port of vpc1 to another Front-panel port of vpc2 """
    global leaf1_loop_detect
    global leaf3_loop_detect
    leaf1_loop_detect=False
    leaf3_loop_detect=False
            
    @aetest.test
    def Enable_ngoam_loop_detection(self, testscript):
        """Enable ngoam loop-detection"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''
                
              ngoam loop-detection
              periodic-probe-interval 60
              port-recovery-interval 300
              '''
             )
            LEAF_3.configure('''
                
              ngoam loop-detection
              periodic-probe-interval 60
              port-recovery-interval 300
              '''
             )
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Disable_spanning_tree_for_the_vlan(self, testscript):
        """Disable_spanning_tree_for_the_vlan"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_1.configure('''no spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_2.configure('''no spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_3.configure('''no spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while disabling sspanning tree on LEAF-1', goto=['cleanup'])
    
    @aetest.test
    def configure_loop_interfaces(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_1.configure('''
                          interface '''+testscript.parameters['intf_LEAF_1_to_LEAF_3']+'''
                          no shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
            ''')
            LEAF_3.configure('''
                          interface '''+testscript.parameters['intf_LEAF_3_to_LEAF_1']+'''
                          no shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
            ''')
            time.sleep(15)
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring interrfacs for loop', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=testscript.parameters['intf_LEAF_1_to_LEAF_3']
        int2=testscript.parameters['intf_LEAF_3_to_LEAF_1']
        int_1=int1.split('Ethernet')
        int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]
        global leaf1_loop_detect
        global leaf3_loop_detect
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        
        for vlan in l2_vlans:
            leaf1_loop_detect=verify_loop_detection(testscript,LEAF_1,vlan,int1)
            leaf3_loop_detect=verify_loop_detection(testscript,LEAF_3,vlan,int2)
            if leaf1_loop_detect or leaf3_loop_detect:
                log.info('Loop detected for vlan '+str(vlan))
                continue
            else:
                log.info('Loop not detected for vlan '+str(vlan))
                self.failed('The loop has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
            
    @aetest.test
    def unconfigure_loop_interfaces(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            if leaf1_loop_detect:
                LEAF_3.config('''
                              interface '''+testscript.parameters['intf_LEAF_3_to_LEAF_1']+'''
                              shut
                              ''')
            elif leaf3_loop_detect:
                LEAF_1.config('''
                              interface '''+testscript.parameters['intf_LEAF_1_to_LEAF_3']+'''
                              shut
                              ''')
            time.sleep(5)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while removing loop', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            elif leaf3_loop_detect:
                output=LEAF_3.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    # @aetest.test
    # def Verify_loop_detection_status_2(self, testscript):
    #     """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
    #     LEAF_1 = testscript.parameters['LEAF-1']
    #     LEAF_2 = testscript.parameters['LEAF-2']
    #     LEAF_3 = testscript.parameters['LEAF-3']
    #     no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
    #     l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
    #     l2_vlans=[]
    #     int1=testscript.parameters['intf_LEAF_1_to_LEAF_3']
    #     int2=testscript.parameters['intf_LEAF_3_to_LEAF_1']
    #     int_1=int1.split('Ethernet')
    #     int1=int_1[1]
    #     int_2=int2.split('Ethernet')
    #     int2=int_2[1]
        
    #     #try:
    #     for i in range (no_of_vlans):
    #         l2_vlans.append(l2_vlan_id)
    #         l2_vlan_id+=1
    #     for vlan in l2_vlans:
    #         if leaf1_loop_detect:
    #             output=LEAF_1.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
    #         elif leaf3_loop_detect:
    #             output=LEAF_3.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
    #         for line in output.split('\n'):
    #             m=re.search('^([0-9]+)\s+Eth([0-9]+\/[0-9]+)\s+RECOVERING',line)
    #             if m:
    #                 if m.group(1)==str(vlan):
    #                     if m.group(2)==int1 or m.group(2)==int2:
    #                         log.info('The loop clearing has been detected and the port '+'ETH'+m.group(2)+ ' is in Recovery for vlan '+ str(vlan))
    #                     else:
    #                         log.info('The loop clear has NOT been detected')
    #                         self.failed('The loop clear has NOT been detected',goto=['cleanup'])
    #                 else:
    #                     log.info('The loop clear has NOT been detected for vlan '+str(vlan))
    #                     self.failed('The loop clear has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
    #             else:
    #                 log.info('The loop clear has NOT been detected')
    #                 self.failed('The loop clear has NOT been detected',goto=['cleanup'])
    #     #except Exception as error:
    #     #    log.debug("Unable to configure - Encountered Exception " + str(error))
    #     #    self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
    
    # @aetest.test
    # def Verify_loop_detection_summary_for_recovery(self, testscript):
    #     """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
    #     LEAF_1 = testscript.parameters['LEAF-1']
    #     LEAF_2 = testscript.parameters['LEAF-2']
    #     LEAF_3 = testscript.parameters['LEAF-3']
    #     no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
    #     try:
    #         if leaf1_loop_detect:
    #             output=LEAF_1.execute('''sh ngoam loop-detection summary''')
    #         elif leaf3_loop_detect:
    #             output=LEAF_3.execute('''sh ngoam loop-detection summary''')
            
    #         m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
    #         if m:
    #             recovery_window=int(m.group(1))
    #             log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
    #             time.sleep(recovery_window+2)
    #         else:
    #             log.info("Couldn't get the next recovery window time from loop-detection summary")
    #             self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
    #     except Exception as error:
    #         log.debug("Unable to configure - Encountered Exception " + str(error))
    #         self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_after_loop_clear(self, testscript):
        """Verify_loop_detection_status"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection status''')
            elif leaf3_loop_detect:
                output=LEAF_3.execute('''sh ngoam loop-detection status''')
            
            if 'BLOCKED' in output or 'RECOVERING' in output:
                log.info('Loop still present and detected in switch. ')
                self.failed('Loop still present and detected in switch.',goto=['cleanup'])
            else:
                log.info('No loop detected in switch. Continuing to next section')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
            
    @aetest.test
    def Enable_spanning_tree_for_the_vlan(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_1.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_2.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_3.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while enabling sspanning tree on LEAF-1', goto=['cleanup'])
    
    @aetest.test
    def configure_vpc1_to_vpc2_interfaces_STP(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_1.configure('''
                          interface '''+testscript.parameters['intf_LEAF_1_to_LEAF_3']+'''
                          shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
                          no shut
            ''')
            LEAF_3.configure('''
                          interface '''+testscript.parameters['intf_LEAF_3_to_LEAF_1']+'''
                          shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
                          no shut
            ''')
            ###adding sleep to give stp time to converge
            time.sleep(60)
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring interrfacs for loop', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_STP_1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=testscript.parameters['intf_LEAF_1_to_LEAF_3']
        int2=testscript.parameters['intf_LEAF_3_to_LEAF_1']
        int_1=int1.split('Ethernet')
        int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        result=[]
        ###first we will check if the ports are blocked in STP.
        #leaf_dut=[LEAF_1,LEAF_2]
        #for dut in leaf_dut:
            
        for vlan in l2_vlans:
            output=LEAF_1.execute('sh spanning-tree vlan '+ str(vlan) +' | i '+str(int1))
        
            n=re.search('^Eth[0-9]+\/[0-9]+\s+[a-zA-Z]+\s+(FWD|BLK).*',output)
            if n:
                if n.group(1)=='FWD':
                    output=LEAF_3.execute('sh spanning-tree vlan '+ str(vlan) +' | i '+str(int2))
                    p=re.search('^Eth[0-9]+\/[0-9]+\s+[a-zA-Z]+\s+(FWD|BLK).*',output)
                    if p:
                        if p.group(1)=='FWD':
                            log.info('Port in Stp foorwarding state')
                            break
                        elif p.group(1)=='BLK':
                            log.info('Loop has been mitigated by STP for vlan '+str(vlan)+'.Port will not be blocked by SLD')
                            result.append(1)
                            
                    else:
                        log.info('STP state unknown. Port might be blocked by SLD.We will verify in the next section')
                        
                elif n.group(1)=='BLK':
                    log.info('Loop has been mitigated by STP for vlan '+str(vlan)+'.Port will not be blocked by SLD')
                    result.append(1)
            else:
                log.info('STP state unknown. Port might be blocked by SLD.We will verify in the next section')
                
        for i in result:
            if i==1:
                log.info('Skipping rest of th SLD sections')
                self.passed('Skipping rest of th SLD sections',goto=['cleanup'])
                break
            
    @aetest.test
    def Verify_loop_detection_status_STP(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        global leaf1_loop_detect
        global leaf3_loop_detect
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=testscript.parameters['intf_LEAF_1_to_LEAF_3']
        int2=testscript.parameters['intf_LEAF_3_to_LEAF_1']
        int_1=int1.split('Ethernet')
        int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        
        for vlan in l2_vlans:
            leaf1_loop_detect=verify_loop_detection(testscript,LEAF_1,vlan,int1)
            leaf3_loop_detect=verify_loop_detection(testscript,LEAF_3,vlan,int2)
            log.info(' leaf1_loop_detect= '+ str(leaf1_loop_detect))
            log.info(' leaf3_loop_detect= '+ str(leaf3_loop_detect))
            if leaf1_loop_detect or leaf3_loop_detect:
                log.info('Loop detected for vlan '+str(vlan))
                continue
            else:
                log.info('Loop not detected for vlan '+str(vlan))
                self.failed('The loop has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
    
    @aetest.test
    def unconfigure_back_to_back_interfaces_STP(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            if leaf1_loop_detect:
                LEAF_3.config('''
                              interface '''+testscript.parameters['intf_LEAF_3_to_LEAF_1']+'''
                              shut
                              ''')
            elif leaf3_loop_detect:
                LEAF_1.config('''
                              interface '''+testscript.parameters['intf_LEAF_1_to_LEAF_3']+'''
                              shut
                              ''')
            time.sleep(5)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while removing loop', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary_STP(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            elif leaf3_loop_detect:
                output=LEAF_3.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_STP_2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=testscript.parameters['intf_LEAF_1_to_LEAF_3']
        int2=testscript.parameters['intf_LEAF_3_to_LEAF_1']
        int_1=int1.split('Ethernet')
        int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]
        
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        for vlan in l2_vlans:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
            elif leaf3_loop_detect:
                output=LEAF_3.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
            for line in output.split('\n'):
                m=re.search('^([0-9]+)\s+Eth([0-9]+\/[0-9]+)\s+RECOVERING',line)
                if m:
                    if m.group(1)==str(vlan):
                        if m.group(2)==int1 or m.group(2)==int2:
                            log.info('The loop clearing has been detected and the port '+'ETH'+m.group(2)+ ' is in Recovery for vlan '+ str(vlan))
                        else:
                            log.info('The loop clear has NOT been detected')
                            self.failed('The loop clear has NOT been detected',goto=['cleanup'])
                    else:
                        log.info('The loop clear has NOT been detected for vlan '+str(vlan))
                        self.failed('The loop clear has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                else:
                    log.info('The loop clear has NOT been detected')
                    self.failed('The loop clear has NOT been detected',goto=['cleanup'])
        #except Exception as error:
        #    log.debug("Unable to configure - Encountered Exception " + str(error))
        #    self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_summary_for_recovery_STP(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            elif leaf3_loop_detect:
                output=LEAF_3.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_after_loop_clear_STP(self, testscript):
        """Verify_loop_detection_status"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection status''')
            elif leaf3_loop_detect:
                output=LEAF_3.execute('''sh ngoam loop-detection status''')
            if 'BLOCKED' in output or 'RECOVERING' in output:
                log.info('Loop still present and detected in switch. ')
                self.failed('Loop still present and detected in switch.',goto=['cleanup'])
            else:
                log.info('No loop detected in switch. Continuing to next section')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']

        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        vlan_end=l2_vlans[len(l2_vlans)-1]
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        LEAF_1.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
        LEAF_2.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
        LEAF_3.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
        LEAF_1.config('''
            interface '''+testscript.parameters['intf_LEAF_1_to_LEAF_3']+'''
            shut
        ''')
        
        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])
            
# *****************************************************************************************************************************#
class TC018_Vpc1_Access_sw_to_standalone_Link_loop_detection(aetest.Testcase):
    """  One Front-Panel Port of vpc1 to another Front-panel port of vpc2 """
    global leaf1_loop_detect
    global leaf3_loop_detect
    leaf1_loop_detect=False
    leaf3_loop_detect=False
            
    @aetest.test
    def Enable_ngoam_loop_detection(self, testscript):
        """Enable ngoam loop-detection"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''
                
              ngoam loop-detection
              periodic-probe-interval 60
              port-recovery-interval 300
              '''
             )
            LEAF_2.configure('''
                
              ngoam loop-detection
              periodic-probe-interval 60
              port-recovery-interval 300
              '''
             )
            LEAF_3.configure('''
                
              ngoam loop-detection
              periodic-probe-interval 60
              port-recovery-interval 300
              '''
             )
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Disable_spanning_tree_for_the_vlan(self, testscript):
        """Disable_spanning_tree_for_the_vlan"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_1.configure('''no spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_2.configure('''no spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_3.configure('''no spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            FAN_2.configure('''no spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while disabling sspanning tree on LEAF-1', goto=['cleanup'])
    
    @aetest.test
    def configure_loop_interfaces(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            FAN_2.configure('''
                          interface '''+testscript.parameters['intf_FAN_2_to_LEAF_3'] +'''
                          no shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
            ''')
            LEAF_3.configure('''
                          interface '''+testscript.parameters['intf_LEAF_3_to_FAN_2']+'''
                          no shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
            ''')
            time.sleep(15)
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring interrfacs for loop', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary_1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next probe window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                probe_window=int(m.group(1))
                log.info("Got the next probe window time from loop-detection summary. Sleeing for that time window")
                time.sleep(probe_window+2)
            else:
                log.info("Couldn't get the next probe window time from loop-detection summary")
                self.failed("Couldn't get the next probe window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po'][1])
        int2=testscript.parameters['intf_LEAF_3_to_FAN_2']
        #int_1=int1.split('Ethernet')
        #int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]
        global leaf1_loop_detect
        global leaf3_loop_detect
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        
        for vlan in l2_vlans:
            leaf1_loop_detect=verify_loop_detection(testscript,LEAF_1,vlan,int1)
            leaf3_loop_detect=verify_loop_detection(testscript,LEAF_3,vlan,int2)
            if leaf1_loop_detect or leaf3_loop_detect:
                log.info('Loop detected for vlan '+str(vlan))
                continue
            else:
                log.info('Loop not detected for vlan '+str(vlan))
                self.failed('The loop has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
            
    @aetest.test
    def unconfigure_loop_interfaces(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            if leaf1_loop_detect:
                LEAF_3.config('''
                              interface '''+testscript.parameters['intf_LEAF_3_to_FAN_2']+'''
                              shut
                              ''')
            elif leaf3_loop_detect:
                FAN_2.config('''
                              interface '''+testscript.parameters['intf_FAN_2_to_LEAF_3']+'''
                              shut
                              ''')
            time.sleep(5)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while removing loop', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            elif leaf3_loop_detect:
                output=LEAF_3.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po'][1])
        int2=testscript.parameters['intf_LEAF_3_to_FAN_2']
        #int_1=int1.split('Ethernet')
        #int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]
        
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        for vlan in l2_vlans:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
            elif leaf3_loop_detect:
                output=LEAF_3.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
            for line in output.split('\n'):
                m=re.search('^([0-9]+)\s+Eth([0-9]+\/[0-9]+)\s+RECOVERING',line)
                if m:
                    if m.group(1)==str(vlan):
                        if m.group(2)==int2:
                            log.info('The loop clearing has been detected and the port '+'ETH'+m.group(2)+ ' is in Recovery for vlan '+ str(vlan))
                        else:
                            log.info('The loop clear has NOT been detected')
                            self.failed('The loop clear has NOT been detected',goto=['cleanup'])
                    else:
                        log.info('The loop clear has NOT been detected for vlan '+str(vlan))
                        self.failed('The loop clear has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                else:
                    m=re.search('^([0-9]+)\s+Po([0-9]+)\s+RECOVERING',line)
                    if m:
                        if m.group(1)==str(vlan):
                            if m.group(2)==int1:
                                log.info('The loop clearing has been detected and the portchannel '+m.group(2)+ ' is in Recovery for vlan '+ str(vlan))
                            elif m.group(2)==int2:
                                log.info('The loop clearing has been detected and the port '+'ETH'+m.group(2)+ ' is in Recovery for vlan '+ str(vlan))
                            else:
                                log.info('The loop clear has NOT been detected')
                                self.failed('The loop clear has NOT been detected',goto=['cleanup'])
                        else:
                            log.info('The loop clear has NOT been detected for vlan '+str(vlan))
                            self.failed('The loop clear has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                    else:
                        log.info('The loop clear has NOT been detected for vlan '+str(vlan))
                        self.failed('The loop clear has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                    
        #except Exception as error:
        #    log.debug("Unable to configure - Encountered Exception " + str(error))
        #    self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_summary_for_recovery(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            elif leaf3_loop_detect:
                output=LEAF_3.execute('''sh ngoam loop-detection summary''')
            
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_after_loop_clear(self, testscript):
        """Verify_loop_detection_status"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection status''')
            elif leaf3_loop_detect:
                output=LEAF_3.execute('''sh ngoam loop-detection status''')
            
            if 'BLOCKED' in output or 'RECOVERING' in output:
                log.info('Loop still present and detected in switch. ')
                self.failed('Loop still present and detected in switch.',goto=['cleanup'])
            else:
                log.info('No loop detected in switch. Continuing to next section')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
            
    @aetest.test
    def Enable_spanning_tree_for_the_vlan(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_1.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_2.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_3.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            #FAN_2.configure('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while enabling spanning tree on LEAF-1', goto=['cleanup'])
    
    @aetest.test
    def configure_vpc1_to_vpc2_interfaces_STP(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            FAN_2.configure('''
                          interface '''+testscript.parameters['intf_FAN_2_to_LEAF_3']+'''
                          shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
                          no shut
            ''')
            LEAF_3.configure('''
                          interface '''+testscript.parameters['intf_LEAF_3_to_FAN_2']+'''
                          shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
                          no shut
            ''')
            ###adding sleep to give stp time to converge
            time.sleep(60)
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring interrfacs for loop', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_STP_1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po'][1])
        int2=testscript.parameters['intf_LEAF_3_to_FAN_2']
        #int_1=int1.split('Ethernet')
        #int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        result=[]
        ###first we will check if the ports are blocked in STP.
        #leaf_dut=[LEAF_1,LEAF_2]
        #for dut in leaf_dut:
            
        for vlan in l2_vlans:
            output=LEAF_1.execute('sh spanning-tree vlan '+ str(vlan) +' | i Po'+str(int1))
        
            n=re.search('^Po[0-9]+\s+[a-zA-Z]+\s+(FWD|BLK).*',output)
            if n:
                if n.group(1)=='FWD':
                    output=LEAF_3.execute('sh spanning-tree vlan '+ str(vlan) +' | i '+str(int2))
                    p=re.search('^Eth[0-9]+\/[0-9]+\s+[a-zA-Z]+\s+(FWD|BLK).*',output)
                    if p:
                        if p.group(1)=='FWD':
                            log.info('Port in Stp foorwarding state')
                            break
                            
                        elif p.group(1)=='BLK':
                            log.info('Loop has been mitigated by STP for vlan '+str(vlan)+'.Port will not be blocked by SLD')
                            result.append(1)
                            
                    else:
                        log.info('STP state unknown. Port might be blocked by SLD.We will verify in the next section')
                        
                elif n.group(1)=='BLK':
                    log.info('Loop has been mitigated by STP for vlan '+str(vlan)+'.Port will not be blocked by SLD')
                    result.append(1)
            else:
                log.info('STP state unknown. Port might be blocked by SLD.We will verify in the next section')
                
        for i in result:
            if i==1:
                log.info('Skipping rest of th SLD sections')
                self.passed('Skipping rest of th SLD sections',goto=['cleanup'])
                break
            
    @aetest.test
    def Verify_loop_detection_status_STP(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        global leaf1_loop_detect
        global leaf3_loop_detect
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po'][1])
        int2=testscript.parameters['intf_LEAF_3_to_FAN_2']
        #int_1=int1.split('Ethernet')
        #int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        
        for vlan in l2_vlans:
            leaf1_loop_detect=verify_loop_detection(testscript,LEAF_1,vlan,int1)
            leaf3_loop_detect=verify_loop_detection(testscript,LEAF_3,vlan,int2)
            if leaf1_loop_detect or leaf3_loop_detect:
                log.info('Loop detected for vlan '+str(vlan))
                continue
            else:
                log.info('Loop not detected for vlan '+str(vlan))
                self.failed('The loop has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
    
    @aetest.test
    def unconfigure_back_to_back_interfaces_STP(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            if leaf1_loop_detect:
                LEAF_3.config('''
                              interface '''+testscript.parameters['intf_LEAF_3_to_FAN_2']+'''
                              shut
                              ''')
            elif leaf3_loop_detect:
                FAN_2.config('''
                              interface '''+testscript.parameters['intf_FAN_2_to_LEAF_3']+'''
                              shut
                              ''')
            time.sleep(5)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while removing loop', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary_STP(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            elif leaf3_loop_detect:
                output=LEAF_3.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_STP_2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po'][1])
        int2=testscript.parameters['intf_LEAF_3_to_FAN_2']
        #int_1=int1.split('Ethernet')
        #int1=int_1[1]
        int_2=int2.split('Ethernet')
        int2=int_2[1]
        
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        for vlan in l2_vlans:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
            elif leaf3_loop_detect:
                output=LEAF_3.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
            for line in output.split('\n'):
                m=re.search('^([0-9]+)\s+Eth([0-9]+\/[0-9]+)\s+RECOVERING',line)
                if m:
                    if m.group(1)==str(vlan):
                        if m.group(2)==int2:
                            log.info('The loop clearing has been detected and the port '+'ETH'+m.group(2)+ ' is in Recovery for vlan '+ str(vlan))
                        else:
                            log.info('The loop clear has NOT been detected')
                            self.failed('The loop clear has NOT been detected',goto=['cleanup'])
                    else:
                        log.info('The loop clear has NOT been detected for vlan '+str(vlan))
                        self.failed('The loop clear has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                else:
                    m=re.search('^([0-9]+)\s+Po([0-9]+)\s+RECOVERING',line)
                    if m:
                        if m.group(1)==str(vlan):
                            if m.group(2)==int1:
                                log.info('The loop clearing has been detected and the portchannel '+m.group(2)+ ' is in Recovery for vlan '+ str(vlan))
                            else:
                                log.info('The loop clear has NOT been detected')
                                self.failed('The loop clear has NOT been detected',goto=['cleanup'])
                        else:
                            log.info('The loop clear has NOT been detected for vlan '+str(vlan))
                            self.failed('The loop clear has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                    else:
                        log.info('The loop clear has NOT been detected')
                        self.failed('The loop clear has NOT been detected',goto=['cleanup'])
        #except Exception as error:
        #    log.debug("Unable to configure - Encountered Exception " + str(error))
        #    self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_summary_for_recovery_STP(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            elif leaf3_loop_detect:
                output=LEAF_3.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_after_loop_clear_STP(self, testscript):
        """Verify_loop_detection_status"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection status''')
            elif leaf3_loop_detect:
                output=LEAF_3.execute('''sh ngoam loop-detection status''')
            if 'BLOCKED' in output or 'RECOVERING' in output:
                log.info('Loop still present and detected in switch. ')
                self.failed('Loop still present and detected in switch.',goto=['cleanup'])
            else:
                log.info('No loop detected in switch. Continuing to next section')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_2 = testscript.parameters['FAN-2']

        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']

        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        vlan_end=l2_vlans[len(l2_vlans)-1]
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        LEAF_1.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
        LEAF_2.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
        LEAF_3.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
        FAN_2.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
        LEAF_3.config('''
            interface '''+testscript.parameters['intf_LEAF_3_to_FAN_2']+'''
            shut
        ''')
        
        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])
            
# *****************************************************************************************************************************#
class TC019_Vpc1_Access_sw_to_vpc2_acc_sw_Link_loop_detection(aetest.Testcase):
    """  One Front-Panel Port of vpc1 to another Front-panel port of vpc2 """
    leaf1_loop_detect=False
    leaf2_loop_detect=False
            
    @aetest.test
    def Enable_ngoam_loop_detection(self, testscript):
        """Enable ngoam loop-detection"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            LEAF_1.configure('''
                
              ngoam loop-detection
              periodic-probe-interval 60
              port-recovery-interval 300
              '''
             )
            LEAF_2.configure('''
                
              ngoam loop-detection
              periodic-probe-interval 60
              port-recovery-interval 300
              '''
             )
            LEAF_3.configure('''
                
              ngoam loop-detection
              periodic-probe-interval 60
              port-recovery-interval 300
              '''
             )
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while shutting vpc leg on LEAF switches', goto=['cleanup'])
            
    @aetest.test
    def Disable_spanning_tree_for_the_vlan(self, testscript):
        """Disable_spanning_tree_for_the_vlan"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_1.configure('''no spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_2.configure('''no spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_3.configure('''no spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            FAN_2.configure('''no spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            FAN_1.configure('''no spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while disabling sspanning tree on LEAF-1', goto=['cleanup'])
    
    @aetest.test
    def configure_loop_interfaces(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            FAN_2.configure('''
                          interface '''+testscript.parameters['intf_FAN_2_to_FAN_1_1'] +'''
                          no shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
            ''')
            FAN_1.configure('''
                          interface '''+testscript.parameters['intf_FAN_1_to_FAN_2_1']+'''
                          no shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
            ''')
            time.sleep(15)
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring interrfacs for loop', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary_1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next probe window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                probe_window=int(m.group(1))
                log.info("Got the next probe window time from loop-detection summary. Sleeing for that time window")
                time.sleep(probe_window+2)
            else:
                log.info("Couldn't get the next probe window time from loop-detection summary")
                self.failed("Couldn't get the next probe window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po'][0])
        int2=str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po'][1])
        #int_1=int1.split('Ethernet')
        #int1=int_1[1]
        #int_2=int2.split('Ethernet')
        #int2=int_2[1]
        global leaf1_loop_detect
        global leaf3_loop_detect
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        
        for vlan in l2_vlans:
            leaf1_loop_detect=verify_loop_detection_for_PO_ints(testscript,LEAF_1,vlan,int1,int2)
            leaf2_loop_detect=verify_loop_detection_for_PO_ints(testscript,LEAF_2,vlan,int1,int2)
            if leaf1_loop_detect or leaf2_loop_detect:
                log.info('Loop detected for vlan '+str(vlan))
                continue
            else:
                log.info('Loop not detected for vlan '+str(vlan))
                self.failed('The loop has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
            
    @aetest.test
    def unconfigure_loop_interfaces(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            if leaf1_loop_detect:
                FAN_2.config('''
                              interface '''+testscript.parameters['intf_FAN_2_to_FAN_1_1']+'''
                              shut
                              ''')
            elif leaf2_loop_detect:
                FAN_1.config('''
                              interface '''+testscript.parameters['intf_FAN_1_to_FAN_2_1']+'''
                              shut
                              ''')
            time.sleep(5)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while removing loop', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            elif leaf3_loop_detect:
                output=LEAF_2.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po'][0])
        int2=str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po'][1])
        #int_1=int1.split('Ethernet')
        #int1=int_1[1]
        #int_2=int2.split('Ethernet')
        #int2=int_2[1]
        
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        for vlan in l2_vlans:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
            elif leaf2_loop_detect:
                output=LEAF_2.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
            for line in output.split('\n'):
                m=re.search('^([0-9]+)\s+Eth([0-9]+\/[0-9]+)\s+RECOVERING',line)
                if m:
                    if m.group(1)==str(vlan):
                        if m.group(2)==int1 or m.group(2)==int2:
                            log.info('The loop clearing has been detected and the portchannel '+m.group(2)+ ' is in Recovery for vlan '+ str(vlan))
                        else:
                            log.info('The loop clear has NOT been detected')
                            self.failed('The loop clear has NOT been detected',goto=['cleanup'])
                    else:
                        log.info('The loop clear has NOT been detected for vlan '+str(vlan))
                        self.failed('The loop clear has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                else:
                    m=re.search('^([0-9]+)\s+Po([0-9]+)\s+RECOVERING',line)
                    if m:
                        if m.group(1)==str(vlan):
                            if m.group(2)==int1:
                                log.info('The loop clearing has been detected and the portchannel '+m.group(2)+ ' is in Recovery for vlan '+ str(vlan))
                            elif m.group(2)==int2:
                                log.info('The loop clearing has been detected and the portchannel '+m.group(2)+ ' is in Recovery for vlan '+ str(vlan))
                            else:
                                log.info('The loop clear has NOT been detected')
                                self.failed('The loop clear has NOT been detected',goto=['cleanup'])
                        else:
                            log.info('The loop clear has NOT been detected for vlan '+str(vlan))
                            self.failed('The loop clear has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                    else:
                        log.info('The loop clear has NOT been detected for vlan '+str(vlan))
                        self.failed('The loop clear has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                    
        #except Exception as error:
        #    log.debug("Unable to configure - Encountered Exception " + str(error))
        #    self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_summary_for_recovery(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            elif leaf2_loop_detect:
                output=LEAF_2.execute('''sh ngoam loop-detection summary''')
            
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_after_loop_clear(self, testscript):
        """Verify_loop_detection_status"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection status''')
            elif leaf2_loop_detect:
                output=LEAF_2.execute('''sh ngoam loop-detection status''')
            
            if 'BLOCKED' in output or 'RECOVERING' in output:
                log.info('Loop still present and detected in switch. ')
                self.failed('Loop still present and detected in switch.',goto=['cleanup'])
            else:
                log.info('No loop detected in switch. Continuing to next section')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
            
    @aetest.test
    def Enable_spanning_tree_for_the_vlan(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            LEAF_1.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_2.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            LEAF_3.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            #FAN_2.configure('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            #FAN_1.configure('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while enabling spanning tree on LEAF-1', goto=['cleanup'])
    
    @aetest.test
    def configure_vpc1_to_vpc2_interfaces_STP(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            FAN_2.configure('''
                          interface '''+testscript.parameters['intf_FAN_2_to_FAN_1_1']+'''
                          shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
                          no shut
            ''')
            FAN_1.configure('''
                          interface '''+testscript.parameters['intf_FAN_1_to_FAN_2_1']+'''
                          shut
                          switchport
                          switchport mode trunk
                          switchport trunk allowed vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end)+'''
                          no shut
            ''')
            ###adding sleep to give stp time to converge
            time.sleep(60)
            
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while configuring interrfacs for loop', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_STP_1(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po'][0])
        int2=str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po'][1])
        #int_1=int1.split('Ethernet')
        #int1=int_1[1]
        #int_2=int2.split('Ethernet')
        #int2=int_2[1]
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        result=[]
        ###first we will check if the ports are blocked in STP.
        #leaf_dut=[LEAF_1,LEAF_2]
        #for dut in leaf_dut:
            
        for vlan in l2_vlans:
            output=LEAF_1.execute('sh spanning-tree vlan '+ str(vlan) +' | i Po'+str(int1))
        
            n=re.search('^Po[0-9]+\s+[a-zA-Z]+\s+(FWD|BLK).*',output)
            if n:
                if n.group(1)=='FWD':
                    output=LEAF_2.execute('sh spanning-tree vlan '+ str(vlan) +' | i Po'+str(int2))
                    p=re.search('^Po[0-9]+\s+[a-zA-Z]+\s+(FWD|BLK).*',output)
                    if p:
                        if p.group(1)=='FWD':
                            log.info('Port in Stp forwarding state')
                            break
                            
                        elif p.group(1)=='BLK':
                            log.info('Loop has been mitigated by STP for vlan '+str(vlan)+'.Port will not be blocked by SLD')
                            result.append(1)
                            
                    else:
                        log.info('STP state unknown. Port might be blocked by SLD.We will verify in the next section')
                        
                elif n.group(1)=='BLK':
                    log.info('Loop has been mitigated by STP for vlan '+str(vlan)+'.Port will not be blocked by SLD')
                    result.append(1)
            else:
                log.info('STP state unknown. Port might be blocked by SLD.We will verify in the next section')
                
        for i in result:
            if i==1:
                log.info('Skipping rest of th SLD sections')
                self.passed('Skipping rest of th SLD sections',goto=['cleanup'])
                break
            
    @aetest.test
    def Verify_loop_detection_status_STP(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po'][0])
        int2=str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po'][1])
        #int_1=int1.split('Ethernet')
        #int1=int_1[1]
        #int_2=int2.split('Ethernet')
        #int2=int_2[1]
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        
        for vlan in l2_vlans:
            leaf1_loop_detect=verify_loop_detection_for_PO_ints(testscript,LEAF_1,vlan,int1,int2)
            leaf2_loop_detect=verify_loop_detection_for_PO_ints(testscript,LEAF_2,vlan,int1,int2)
            if leaf1_loop_detect or leaf3_loop_detect:
                log.info('Loop detected for vlan '+str(vlan))
                continue
            else:
                log.info('Loop not detected for vlan '+str(vlan))
                self.failed('The loop has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
    
    @aetest.test
    def unconfigure_back_to_back_interfaces_STP(self, testscript):
        """configure_back_to_back_interfaces"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_1 = testscript.parameters['FAN-1']
        FAN_2 = testscript.parameters['FAN-2']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            for i in range (no_of_vlans):
                l2_vlans.append(l2_vlan_id)
                l2_vlan_id+=1
            vlan_end=l2_vlans[len(l2_vlans)-1]
            l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
            
            if leaf1_loop_detect:
                FAN_2.config('''
                              interface '''+testscript.parameters['intf_FAN_2_to_FAN_1_1']+'''
                              shut
                              ''')
            elif leaf2_loop_detect:
                FAN_1.config('''
                              interface '''+testscript.parameters['intf_FAN_1_to_FAN_2_1']+'''
                              shut
                              ''')
            time.sleep(5)
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while removing loop', goto=['cleanup'])
            
    @aetest.test
    def Verify_loop_detection_summary_STP(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            elif leaf2_loop_detect:
                output=LEAF_2.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_STP_2(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        int1=str(testscript.parameters['LEAF_1_dict']['VPC_data']['VPC_ACC_po'][0])
        int2=str(testscript.parameters['LEAF_2_dict']['VPC_data']['VPC_ACC_po'][1])
        #int_1=int1.split('Ethernet')
        #int1=int_1[1]
        #int_2=int2.split('Ethernet')
        #int2=int_2[1]
        
        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        for vlan in l2_vlans:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
            elif leaf2_loop_detect:
                output=LEAF_2.execute('''sh ngoam loop-detection status | i ''' + str(vlan))
            for line in output.split('\n'):
                m=re.search('^([0-9]+)\s+Eth([0-9]+\/[0-9]+)\s+RECOVERING',line)
                if m:
                    if m.group(1)==str(vlan):
                        if m.group(2)==int2:
                            log.info('The loop clearing has been detected and the port '+'ETH'+m.group(2)+ ' is in Recovery for vlan '+ str(vlan))
                        else:
                            log.info('The loop clear has NOT been detected')
                            self.failed('The loop clear has NOT been detected',goto=['cleanup'])
                    else:
                        log.info('The loop clear has NOT been detected for vlan '+str(vlan))
                        self.failed('The loop clear has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                else:
                    m=re.search('^([0-9]+)\s+Po([0-9]+)\s+RECOVERING',line)
                    if m:
                        if m.group(1)==str(vlan):
                            if m.group(2)==int1 or m.group(2)==int2:
                                log.info('The loop clearing has been detected and the portchannel '+m.group(2)+ ' is in Recovery for vlan '+ str(vlan))
                            else:
                                log.info('The loop clear has NOT been detected')
                                self.failed('The loop clear has NOT been detected',goto=['cleanup'])
                        else:
                            log.info('The loop clear has NOT been detected for vlan '+str(vlan))
                            self.failed('The loop clear has NOT been detected for vlan '+str(vlan),goto=['cleanup'])
                    else:
                        log.info('The loop clear has NOT been detected')
                        self.failed('The loop clear has NOT been detected',goto=['cleanup'])
        #except Exception as error:
        #    log.debug("Unable to configure - Encountered Exception " + str(error))
        #    self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_summary_for_recovery_STP(self, testscript):
        """Shut down the vpc leg on Leaf2 to force all traffic to Leaf1"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection summary''')
            elif leaf2_loop_detect:
                output=LEAF_2.execute('''sh ngoam loop-detection summary''')
            m=re.search('Next recovery window start:.*\(([0-9]+)\s+seconds\)',output)
            if m:
                recovery_window=int(m.group(1))
                log.info("Got the next recovery window time from loop-detection summary. Sleeing for that time window")
                time.sleep(recovery_window+2)
            else:
                log.info("Couldn't get the next recovery window time from loop-detection summary")
                self.failed("Couldn't get the next recovery window time from loop-detection summary", goto=['cleanup'])
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while getting the next probe window time from loop-detection summary', goto=['cleanup'])
    
    @aetest.test
    def Verify_loop_detection_status_after_loop_clear_STP(self, testscript):
        """Verify_loop_detection_status"""
        
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']
        
        try:
            if leaf1_loop_detect:
                output=LEAF_1.execute('''sh ngoam loop-detection status''')
            elif leaf2_loop_detect:
                output=LEAF_2.execute('''sh ngoam loop-detection status''')
            if 'BLOCKED' in output or 'RECOVERING' in output:
                log.info('Loop still present and detected in switch. ')
                self.failed('Loop still present and detected in switch.',goto=['cleanup'])
            else:
                log.info('No loop detected in switch. Continuing to next section')
        except Exception as error:
            log.debug("Unable to configure - Encountered Exception " + str(error))
            self.errored('Exception occurred while verifying loop-detection status', goto=['cleanup'])
            
    @aetest.cleanup
    def cleanup(self,testscript):
        """Unconfigure qos policies"""
        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']
        FAN_2 = testscript.parameters['FAN-2']
        FAN_1 = testscript.parameters['FAN-1']
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        l2_vlans=[]
        no_of_vlans=testscript.parameters['forwardingSysDict']['VLAN_PER_VRF_count']

        #try:
        for i in range (no_of_vlans):
            l2_vlans.append(l2_vlan_id)
            l2_vlan_id+=1
        vlan_end=l2_vlans[len(l2_vlans)-1]
        l2_vlan_id = testscript.parameters['LEAF_1_dict']['VNI_data']['l2_vlan_start']
        LEAF_1.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
        LEAF_2.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
        LEAF_3.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
        FAN_2.config('''spanning-tree vlan '''+ str(l2_vlan_id) +'''-''' + str(vlan_end))
        FAN_2.config('''
                              interface '''+testscript.parameters['intf_FAN_2_to_FAN_1_1']+'''
                              shut
                              ''')
        FAN_1.config('''
                              interface '''+testscript.parameters['intf_FAN_1_to_FAN_2_1']+'''
                              shut
                              ''')
        
        status = infraVerify.postTestVerification(post_test_process_dict)
        if status['status'] == 0:
            self.failed(reason=status['logs'])
        else:
            self.passed(reason=status['logs'])

#########################################################################
#####                       COMMON CLEANUP SECTION                    ###
#########################################################################
##
### Remove the BASE CONFIGURATION that was applied earlier in the 
### common cleanup section, clean the left over

class common_cleanup(aetest.CommonCleanup):
    pass
        
    # @aetest.subsection
    # def restore_terminal_width(self, testscript):
    #     """ Common Cleanup subsection """
    #     testscript.parameters['LEAF-1'].execute('rollback running checkpoint Leaf-1')
    
    # @aetest.subsection
    # def restore_terminal_width(self, testscript):
    #     """ Common Cleanup subsection """
    #     testscript.parameters['LEAF-2'].execute('rollback running checkpoint Leaf-2')
    
    # @aetest.subsection
    # def restore_terminal_width(self, testscript):
    #     """ Common Cleanup subsection """
    #     testscript.parameters['LEAF-3'].execute('rollback running checkpoint Leaf-3')
    
    # @aetest.subsection
    # def restore_terminal_width(self, testscript):
    #     """ Common Cleanup subsection """
    #     testscript.parameters['FAN-1'].execute('rollback running checkpoint FAN-1')
        
    # @aetest.subsection
    # def restore_terminal_width(self, testscript):
    #     """ Common Cleanup subsection """
    #     testscript.parameters['SPINE'].execute('rollback running checkpoint spine1')


if __name__ == '__main__':  # pragma: no cover
    aetest.main()
