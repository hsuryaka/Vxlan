#!/usr/bin/env python

###################################################################
###                  Importing Libraries                        ###
###################################################################
import logging
from socket import timeout
import time
from psutil import LINUX
import yaml
import re
import pprint
import json
from yaml import Loader
from pyats import aetest
from pyats.log.utils import banner
import unicon.statemachine.statemachine
from unicon.eal.dialogs import Statement, Dialog
import ipaddress as ip

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# ------------------------------------------------------
# Import and initialize Genie libraries
# ------------------------------------------------------
from genie.conf import Genie
from genie.harness.standalone import run_genie_sdk, GenieStandalone
from genie.conf import Genie

# ------------------------------------------------------
# Import and initialize EVPN specific libraries
# ------------------------------------------------------
import VxLAN_PYlib.vxlanEVPN_FNL_lib as vxlanEVPN_FNL_lib
evpnLib     = vxlanEVPN_FNL_lib.configure39KVxlanEvpn()
verifyEvpn  = vxlanEVPN_FNL_lib.verifyEVPNconfiguration()

# ------------------------------------------------------
# Import and initialize IXIA specific libraries
# ------------------------------------------------------
import VxLAN_PYlib.ixiaPyats_lib as ixiaPyats_lib
ixLib = ixiaPyats_lib.ixiaPyats_lib()

# ------------------------------------------------------
# Import and initialize INFRA specific libraries
# ------------------------------------------------------
import VxLAN_PYlib.infra_lib as infra_lib
infraTrig = infra_lib.infraTrigger()
infraConfig = infra_lib.infraConfigure()
infraVerify = infra_lib.infraVerify()

# ------------------------------------------------------
# Import and initialize PVNF specific libraries
# ------------------------------------------------------
import VxLAN_PYlib.vxlanEVPN_PVNF_lib as vxlanEVPN_PVNF_lib
pvnfConfig = vxlanEVPN_PVNF_lib.configureVxlanEvpnPVNF()
pvnfVerify = vxlanEVPN_PVNF_lib.verifyVxlanEvpnPVNF()

###################################################################
###                  GLOBAL VARIABLES                           ###
###################################################################
device_list             = []
BL_base_image_load      = 1
LEAF_base_image_load    = 1

###################################################################
###                  GLOBAL Methods                             ###
###################################################################
def PGW_route_work_around(PGW, BGP_AS):
    PGW.configure('''
        restart bgp '''+str(BGP_AS)+'''
        clear ip bgp vrf all *
        clear ip route vrf all *
        clear ipv6 route vrf all *
    ''', timeout=1200)
    time.sleep(120)

def PVNF_LEAF_route_work_around(testscript):
    for dut in device_list:
        dut.configure('''
            restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
            clear ip bgp vrf all *
            clear ip route vrf all *
            clear ipv6 route vrf all *
        ''', timeout=1200)

    time.sleep(120)

###################################################################
###                  COMMON SETUP SECTION                       ###
###################################################################
class COMMON_SETUP(aetest.CommonSetup):
    """ Common Setup """

    # *****************************************************************************************************************************#
    @aetest.subsection
    def topology_used_for_suite(self):
        """ Pictorial Topology to be used """

        # Set topology to be used
        topology = """

                                            +-------------+     
                                            |      BL     |----- IXIA
                                            +-------------+     
                                                   |
                                                   |
                                                   |
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
                                   \\              |                /
                                    \\             |               / 
                                     \\            |              /         <---- Two links each
                                      \\           |             /
                                    +------------------------------+
                                    |            PGW               |
                                    +------------------------------+
                                                   |    
                                                   |      
                                                  IXIA     
        """

        log.info("Topology to be used is")
        log.info(topology)

    # *****************************************************************************************************************************#
    @aetest.subsection
    def connecting_to_devices(self, testscript, testbed, uut_list, configurationFile, script_flags=None):
        """ Connecting to devices """

        Genie.init(testbed=testbed)
        testscript.parameters["testbed"] = Genie.testbed
        
        # =============================================================================================================================#
        # Grab the device object of the uut device with that name
        if script_flags is None:
            script_flags = {}

        SPINE   = testscript.parameters['SPINE']        = testscript.parameters['testbed'].devices[uut_list['SPINE']]
        LEAF_1  = testscript.parameters['LEAF-1']       = testscript.parameters['testbed'].devices[uut_list['LEAF-1']]
        LEAF_2  = testscript.parameters['LEAF-2']       = testscript.parameters['testbed'].devices[uut_list['LEAF-2']]
        LEAF_3  = testscript.parameters['LEAF-3']       = testscript.parameters['testbed'].devices[uut_list['LEAF-3']]
        BL      = testscript.parameters['BL']           = testscript.parameters['testbed'].devices[uut_list['BL']]
        PGW     = testscript.parameters['PGW']          = testscript.parameters['testbed'].devices[uut_list['PGW']]
        IXIA    = testscript.parameters['IXIA']         = testscript.parameters['testbed'].devices[uut_list['ixia']]
        LNX     = testscript.parameters['LNX']          = testscript.parameters['testbed'].devices[uut_list['lnx-server']]

        testscript.parameters['ixia_chassis_ip']        = str(IXIA.connections.a.ip)
        testscript.parameters['ixia_tcl_server']        = str(IXIA.connections.alt.ip)
        testscript.parameters['ixia_tcl_port']          = str(IXIA.connections.alt.port)

        # =============================================================================================================================#
        # Connect to the device
        SPINE.connect()
        LEAF_1.connect()
        LEAF_2.connect()
        LEAF_3.connect()
        BL.connect()
        PGW.connect()
        LNX.connect()

        device_list.append(SPINE)
        device_list.append(LEAF_1)
        device_list.append(LEAF_2)
        device_list.append(LEAF_3)
        device_list.append(BL)
        device_list.append(PGW)

        # =============================================================================================================================#
        # Make sure that the connection went fine

        for dut in device_list:
            if not hasattr(dut, 'execute'):
                self.failed()

            if dut.execute != dut.connectionmgr.default.execute:
                self.failed()
            
            dut.configure('logg cons 1')

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
        testscript.parameters['configurationFile'] = configurationFile

        with open(configurationFile) as cfgFile:
            configuration = yaml.load(cfgFile, Loader=Loader)

        #----- Get the Device Dict information from configuration file
        testscript.parameters['LEAF_1_dict']                    = configuration['LEAF_1_dict']
        testscript.parameters['LEAF_2_dict']                    = configuration['LEAF_2_dict']
        testscript.parameters['LEAF_3_dict']                    = configuration['LEAF_3_dict']
        testscript.parameters['BL_dict']                        = configuration['BL_dict']
        testscript.parameters['forwardingSysDict']              = configuration['FWD_SYS_dict']

        # ----- Get the TGEN Dict information from configuration file
        testscript.parameters['BL_TGEN_data']                   = configuration['BL_TGEN_data']
        testscript.parameters['PGW_TGEN_data']                  = configuration['PGW_TGEN_data']
        testscript.parameters['LEAF_1_TGEN_data']               = configuration['LEAF_1_TGEN_data']

        # ----- Declare few script needed variables
        testscript.parameters['leavesDictList']                 = [configuration['LEAF_1_dict'],
                                                                   configuration['LEAF_2_dict'],
                                                                   configuration['LEAF_3_dict'],
                                                                   configuration['BL_dict']]

        testscript.parameters['leavesDict']                     = {LEAF_1: configuration['LEAF_1_dict'],
                                                                   LEAF_2: configuration['LEAF_2_dict'],
                                                                   LEAF_3: configuration['LEAF_3_dict'],
                                                                   BL: configuration['BL_dict']}

        testscript.parameters['VTEP_List']                      = [testscript.parameters['LEAF_1_dict'],
                                                                   testscript.parameters['LEAF_2_dict'],
                                                                   testscript.parameters['LEAF_3_dict'],
                                                                   testscript.parameters['BL_dict']]

    # *****************************************************************************************************************************#
    @aetest.subsection
    def get_interfaces(self, testbed, testscript):
        """ Getting required Connections for Test """

        SPINE   = testscript.parameters['FX3-REG-TB2-TOR3']
        LEAF_1  = testscript.parameters['FX3-REG-TB2-TOR1']
        LEAF_2  = testscript.parameters['FX3-REG_TB2-TOR2']
        LEAF_3  = testscript.parameters['FX3-REG-TB1-TOR3']
        BL      = testscript.parameters['FX3-REG-TB1-TOR2']
        PGW     = testscript.parameters['FX3-REG-TB1-NODE4']
        IXIA    = testscript.parameters['IXIA']

        # =============================================================================================================================#
        log.info("================================================")
        log.info("All Available Interfaces from the YAML file are:")
        testbed_interfaces = {}
        for i in testbed.interfaces:
            testbed_interfaces[i.alias] = i.name
            log.info(str(i.alias) + " --> " + str(i.name))

        # =============================================================================================================================#
        # Fetching the specific interfaces
        
        testscript.parameters['intf_SPINE_to_LEAF_1']   = testbed_interfaces['SPINE_to_LEAF-1']
        testscript.parameters['intf_SPINE_to_LEAF_2']   = testbed_interfaces['SPINE_to_LEAF-2']
        testscript.parameters['intf_SPINE_to_LEAF_3']   = testbed_interfaces['SPINE_to_LEAF-3']
        testscript.parameters['intf_SPINE_to_BL']       = testbed_interfaces['SPINE_to_BL']

        testscript.parameters['intf_LEAF_1_to_SPINE']   = testbed_interfaces['LEAF-1_to_SPINE']
        testscript.parameters['intf_LEAF_1_to_PGW_1']   = testbed_interfaces['LEAF-1_to_PGW_1']
        testscript.parameters['intf_LEAF_1_to_PGW_2']   = testbed_interfaces['LEAF-1_to_PGW_2']
        testscript.parameters['intf_LEAF_1_to_IXIA']    = testbed_interfaces['LEAF-1_to_IXIA']

        testscript.parameters['intf_LEAF_2_to_SPINE']   = testbed_interfaces['LEAF-2_to_SPINE']
        testscript.parameters['intf_LEAF_2_to_PGW_1']   = testbed_interfaces['LEAF-2_to_PGW_1']
        testscript.parameters['intf_LEAF_2_to_PGW_2']   = testbed_interfaces['LEAF-2_to_PGW_2']

        testscript.parameters['intf_LEAF_3_to_SPINE']   = testbed_interfaces['LEAF-3_to_SPINE']
        testscript.parameters['intf_LEAF_3_to_PGW_1']   = testbed_interfaces['LEAF-3_to_PGW_1']
        testscript.parameters['intf_LEAF_3_to_PGW_2']   = testbed_interfaces['LEAF-3_to_PGW_2']

        testscript.parameters['intf_PGW_to_LEAF_1_1']   = testbed_interfaces['PGW_to_LEAF-1_1']
        testscript.parameters['intf_PGW_to_LEAF_1_2']   = testbed_interfaces['PGW_to_LEAF-1_2']
        testscript.parameters['intf_PGW_to_LEAF_2_1']   = testbed_interfaces['PGW_to_LEAF-2_1']
        testscript.parameters['intf_PGW_to_LEAF_2_2']   = testbed_interfaces['PGW_to_LEAF-2_2']
        testscript.parameters['intf_PGW_to_LEAF_3_1']   = testbed_interfaces['PGW_to_LEAF-3_1']
        testscript.parameters['intf_PGW_to_LEAF_3_2']   = testbed_interfaces['PGW_to_LEAF-3_2']
        testscript.parameters['intf_PGW_to_IXIA']       = testbed_interfaces['PGW_to_IXIA']

        testscript.parameters['intf_BL_to_SPINE']       = testbed_interfaces['BL_to_SPINE']
        testscript.parameters['intf_BL_to_IXIA']        = testbed_interfaces['BL_to_IXIA']

        testscript.parameters['intf_IXIA_to_BL']        = testbed_interfaces['IXIA_to_BL']
        testscript.parameters['intf_IXIA_to_PGW']       = testbed_interfaces['IXIA_to_PGW']
        testscript.parameters['intf_IXIA_to_LEAF_1']    = testbed_interfaces['IXIA_to_LEAF-1']

        testscript.parameters['ixia_int_list'] = str(testscript.parameters['intf_IXIA_to_BL']) + " " + str(testscript.parameters['intf_IXIA_to_PGW']) \
                                                 + " " + str(testscript.parameters['intf_IXIA_to_LEAF_1'])

        # =============================================================================================================================#

        log.info("\n\n================================================")
        log.info("Topology Specific Interfaces \n\n")
        for key in testscript.parameters.keys():
            if "intf_" in key:
                log.info("%-25s   ---> %-15s" % (key, testscript.parameters[key]))
        log.info("\n\n")

    # *****************************************************************************************************************************#
    @aetest.subsection
    def prepare_pvnf_script_var(self, testscript):
        """ Getting required Connections for Test """

        # =============================================================================================================================#
        # Import Configuration File and create required Structures
        configurationFile = testscript.parameters['configurationFile']
        with open(configurationFile) as cfgFile:
            configuration = yaml.load(cfgFile, Loader=Loader)

        LEAF_1 = testscript.parameters['LEAF-1']
        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        testscript.parameters['topo_1_vnf_leaves_dict'] = {}
        testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_1] = {}
        testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_2] = {}
        testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_3] = {}
        testscript.parameters['topo_2_vnf_leaves_dict'] = {}
        testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_1] = {}
        testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_2] = {}
        testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_3] = {}
        testscript.parameters['topo_3_vnf_leaves_dict'] = {}
        testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_1] = {}
        testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_2] = {}
        testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_3] = {}

        forwardingSysDict = testscript.parameters['forwardingSysDict']

        # ----- Declare few script needed variables for PVNF Topology
        testscript.parameters['PVNF_dict']                      = {LEAF_1: configuration['LEAF_1_dict']['PVNF_data'],
                                                                   LEAF_2: configuration['LEAF_2_dict']['PVNF_data'],
                                                                   LEAF_3: configuration['LEAF_3_dict']['PVNF_data']}

        testscript.parameters['SPINE_PVNF_rtmap_name']              = 'SPINE_passall'
        testscript.parameters['BL_PVNF_rtmap_name']                 = 'BL_passall'
        testscript.parameters['LEAF_stop_external_PVNF_rtmap_name'] = 'LEAF_STOP_EXTERNAL'
        testscript.parameters['LEAF_stop_external_PVNF_prfx_name']  = 'LEAF_STOP_EXTERNAL'

        # ===================================================
        # --- Check if topo_1 is present and add accordingly
        # ===================================================

        # ------- Adding topology type
        testscript.parameters['topo_1_vnf_leaves_dict']['type'] = 'topo_1'
        # ------- Adding VRF ID to be used
        testscript.parameters['topo_1_vnf_leaves_dict']['vrf'] = configuration['FWD_SYS_dict']['VRF_string'] + str(configuration['FWD_SYS_dict']['VRF_id_start'])
        # ------- Adding BGP Prefixes
        testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts'] = 200
        testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes'] = '150.1.1.5'
        testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes'] = '2001:150:1:1::5'

        # ------- If topo_1 is in LEAF_1
        if ("topo_1" in configuration['LEAF_1_dict']['PVNF_data'].keys()):

            # ------- Adding PVNF_data dict
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_1] = configuration['LEAF_1_dict']['PVNF_data']['topo_1']
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_1]['EW_LEAF_SRC'] = '1'
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_1]['leaf_as'] = forwardingSysDict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_1]['PGW_LEAF_int'] = testscript.parameters['intf_PGW_to_LEAF_1_1']
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_1]['LEAF_PGW_int'] = testscript.parameters['intf_LEAF_1_to_PGW_1']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_1]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_1]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_1]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_1]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_1]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_1]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        # ------- If topo_1 is in LEAF_2
        if ("topo_1" in configuration['LEAF_2_dict']['PVNF_data'].keys()):

            # ------- Adding PVNF_data dict
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_2] = configuration['LEAF_2_dict']['PVNF_data']['topo_1']
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_2]['leaf_as'] = forwardingSysDict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_2]['PGW_LEAF_int'] = testscript.parameters['intf_PGW_to_LEAF_2_1']
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_2]['LEAF_PGW_int'] = testscript.parameters['intf_LEAF_2_to_PGW_1']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_2]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_2]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_2]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_2]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_2]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_2]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        # ------- If topo_1 is in LEAF_3
        if ("topo_1" in configuration['LEAF_3_dict']['PVNF_data'].keys()):

            # ------- Adding PVNF_data dict
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_3] = configuration['LEAF_3_dict']['PVNF_data']['topo_1']
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_3]['leaf_as'] = forwardingSysDict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_3]['PGW_LEAF_int'] = testscript.parameters['intf_PGW_to_LEAF_3_1']
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_3]['LEAF_PGW_int'] = testscript.parameters['intf_LEAF_3_to_PGW_1']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_3]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_3]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_3]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_3]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_3]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_3]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        configuration['FWD_SYS_dict']['VRF_id_start'] += 1
        log.info(banner('TOPO-1 Dict'))
        log.info(pprint.pformat(testscript.parameters['topo_1_vnf_leaves_dict'], indent=2))

        # ===================================================
        # --- Check if topo_2 is present and add accordingly
        # ===================================================

        # ------- Adding topology type
        testscript.parameters['topo_2_vnf_leaves_dict']['type'] = 'topo_2'
        # ------- Adding VRF ID to be used
        testscript.parameters['topo_2_vnf_leaves_dict']['vrf'] = configuration['FWD_SYS_dict']['VRF_string'] + str(configuration['FWD_SYS_dict']['VRF_id_start'])
        # ------- Adding BGP Prefixes
        testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts'] = 200
        testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes'] = '160.1.1.5'
        testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes'] = '2001:160:1:1::5'

        # ------- If topo_2 is in LEAF_1
        if ("topo_2" in configuration['LEAF_1_dict']['PVNF_data'].keys()):

            # ------- Adding PVNF_data dict
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_1] = configuration['LEAF_1_dict']['PVNF_data']['topo_2']
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_1]['EW_LEAF_SRC'] = '1'
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_1]['leaf_as'] = forwardingSysDict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_1]['PGW_LEAF_int'] = testscript.parameters['intf_PGW_to_LEAF_1_1']
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_1]['LEAF_PGW_int'] = testscript.parameters['intf_LEAF_1_to_PGW_1']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_1]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_1]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_1]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_1]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_1]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_1]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        # ------- If topo_2 is in LEAF_2
        if ("topo_2" in configuration['LEAF_2_dict']['PVNF_data'].keys()):

            # ------- Adding PVNF_data dict
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_2] = configuration['LEAF_2_dict']['PVNF_data']['topo_2']
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_2]['leaf_as'] = forwardingSysDict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_2]['PGW_LEAF_int'] = testscript.parameters['intf_PGW_to_LEAF_2_1']
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_2]['LEAF_PGW_int'] = testscript.parameters['intf_LEAF_2_to_PGW_1']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_2]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_2]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_2]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_2]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_2]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_2]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        # ------- If topo_2 is in LEAF_3
        if ("topo_2" in configuration['LEAF_3_dict']['PVNF_data'].keys()):

            # ------- Adding PVNF_data dict
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_3] = configuration['LEAF_3_dict']['PVNF_data']['topo_2']
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_3]['leaf_as'] = forwardingSysDict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_3]['PGW_LEAF_int'] = testscript.parameters['intf_PGW_to_LEAF_3_1']
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_3]['LEAF_PGW_int'] = testscript.parameters['intf_LEAF_3_to_PGW_1']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_3]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_3]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_3]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_3]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_3]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_2_vnf_leaves_dict'][LEAF_3]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        configuration['FWD_SYS_dict']['VRF_id_start'] += 1
        log.info(banner('TOPO-2 Dict'))
        log.info(pprint.pformat(testscript.parameters['topo_2_vnf_leaves_dict'], indent=2))

        # ===================================================
        # --- Check if topo_3 is present and add accordingly
        # ===================================================

        # ------- Adding topology type
        testscript.parameters['topo_3_vnf_leaves_dict']['type'] = 'topo_3'
        # ------- Adding VRF ID to be used
        testscript.parameters['topo_3_vnf_leaves_dict']['vrf'] = configuration['FWD_SYS_dict']['VRF_string'] + str(configuration['FWD_SYS_dict']['VRF_id_start'])
        # ------- Adding BGP Prefixes
        testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts'] = 200
        testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes'] = '170.1.1.5'
        testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes'] = '2001:170:1:1::5'

        # ------- If topo_3 is in LEAF_1
        if ("topo_3" in configuration['LEAF_1_dict']['PVNF_data'].keys()):

            # ------- Adding PVNF_data dict
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_1] = configuration['LEAF_1_dict']['PVNF_data']['topo_3']
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_1]['EW_LEAF_SRC'] = '1'
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_1]['leaf_as'] = forwardingSysDict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_1]['PGW_LEAF_int'] = testscript.parameters['intf_PGW_to_LEAF_1_2']
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_1]['LEAF_PGW_int'] = testscript.parameters['intf_LEAF_1_to_PGW_2']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_1]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_1]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_1]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_1]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_1]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_1]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        # ------- If topo_3 is in LEAF_2
        if("topo_3" in configuration['LEAF_2_dict']['PVNF_data'].keys()):

            # ------- Adding PVNF_data dict
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_2] = configuration['LEAF_2_dict']['PVNF_data']['topo_3']
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_2]['leaf_as'] = forwardingSysDict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_2]['PGW_LEAF_int'] = testscript.parameters['intf_PGW_to_LEAF_2_2']
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_2]['LEAF_PGW_int'] = testscript.parameters['intf_LEAF_2_to_PGW_2']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_2]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_2]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_2]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_2]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_2]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_2]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        # ------- If topo_3 is in LEAF_3
        if("topo_3" in configuration['LEAF_3_dict']['PVNF_data'].keys()):

            # ------- Adding PVNF_data dict
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_3] = configuration['LEAF_3_dict']['PVNF_data']['topo_3']
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_3]['leaf_as'] = forwardingSysDict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_3]['PGW_LEAF_int'] = testscript.parameters['intf_PGW_to_LEAF_3_2']
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_3]['LEAF_PGW_int'] = testscript.parameters['intf_LEAF_3_to_PGW_2']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_3]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_3]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_3]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_3]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_3]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_3_vnf_leaves_dict'][LEAF_3]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        configuration['FWD_SYS_dict']['VRF_id_start']+=1
        log.info(banner('TOPO-3 Dict'))
        log.info(pprint.pformat(testscript.parameters['topo_3_vnf_leaves_dict'], indent=2))

    # *****************************************************************************************************************************#
    @aetest.subsection
    def verify_images_present_in_server(self, testscript, abs_base_image, abs_target_image):
        """ Verify images present in server """

        testscript.parameters['base_image_path'] = ''
        testscript.parameters['base_image']      = ''
        base_image_data = ''
        testscript.parameters['target_image_path'] = ''
        testscript.parameters['target_image']      = ''
        target_image_data = ''
        fail_flag = []
        fail_msgs = '\n'
        
        # Verify Base image present in the Server
        base_image_data = re.search('(.*/)(nxos.*)', abs_base_image)
        print(base_image_data)
        if base_image_data != '':
            testscript.parameters['base_image_path'] = base_image_data.group(1)
            testscript.parameters['base_image']      = base_image_data.group(2)
            log.info('Base Image path : '+str(testscript.parameters['base_image_path']))
            log.info('Base Image      : '+str(testscript.parameters['base_image']))
        else:
            fail_flag.append(0)
            fail_msgs+='Base Image path could not be parsed\n'

        if testscript.parameters['base_image'] != '' and testscript.parameters['base_image_path'] != '':
            testscript.parameters['LNX'].execute("cd "+str(testscript.parameters['base_image_path']), timeout=100)
            image_output = testscript.parameters['LNX'].execute("ls -l | grep "+str(testscript.parameters['base_image']), timeout=100)
        else:
            fail_flag.append(0)
            fail_msgs+='Base Image path could not be parsed\n'
        
        if testscript.parameters['base_image'] not in image_output:
            fail_flag.append(0)

        # Verify Target image present in the Server
        target_image_data = re.search('(.*/)(nxos.*)', abs_target_image)
        print(target_image_data)
        if target_image_data != '':
            testscript.parameters['target_image_path'] = target_image_data.group(1)
            testscript.parameters['target_image']      = target_image_data.group(2)
            log.info('Target Image path : '+str(testscript.parameters['target_image_path']))
            log.info('Target Image      : '+str(testscript.parameters['target_image']))
        else:
            fail_flag.append(0)
            fail_msgs+='Target Image path could not be parsed\n'

        if testscript.parameters['target_image'] != '' and testscript.parameters['target_image_path']!= '':
            testscript.parameters['LNX'].execute("cd "+str(testscript.parameters['target_image_path']), timeout=100)
            image_output = testscript.parameters['LNX'].execute("ls -l | grep "+str(testscript.parameters['target_image']), timeout=100)
        else:
            fail_flag.append(0)
            fail_msgs+='Target Image path could not be parsed\n'
        
        if testscript.parameters['target_image'] not in image_output:
            fail_flag.append(0)
        
        if 0 in fail_flag:
            self.failed(reason=fail_msgs, goto=['common_cleanup'])
        else:
            self.passed(reason="Required Images are present in the server to copy to devices")

    # *****************************************************************************************************************************#
    @aetest.subsection
    def copy_images_to_devices(self, testbed, testscript, abs_base_image, abs_target_image, delete_old_images):
        """ Copy Images from Server to devices """

        BL_base_img_verify_flag         = 0
        BL_target_img_verify_flag       = 0
        LEAF_base_img_verify_flag       = 0
        LEAF_target_img_verify_flag     = 0
        
        # Remove the boot variables
        testscript.parameters['BL'].configure("no boot nxos", timeout=1200)
        testscript.parameters['BL'].configure("copy r s", timeout=1200)
        testscript.parameters['LEAF-2'].configure("no boot nxos", timeout=1200)
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=1200)

        # If the flag is set, delete all images
        if delete_old_images:
            testscript.parameters['BL'].execute('delete bootflash:nxos* no')
            testscript.parameters['LEAF-2'].execute('delete bootflash:nxos* no')

        # Copy the Base Image
        try:
            testscript.parameters['BL'].shellexec(['rm -rf ~/.ssh/known_hosts'])
            testscript.parameters['BL'].api.copy_to_device(abs_base_image, 'bootflash:', testbed.servers.tftp.address, 'scp', timeout=1600, vrf='management')
            testscript.parameters['LEAF-2'].shellexec(['rm -rf ~/.ssh/known_hosts'])
            testscript.parameters['LEAF-2'].api.copy_to_device(abs_base_image, 'bootflash:', testbed.servers.tftp.address, 'scp', timeout=1600, vrf='management')
        except Exception as e:
            self.failed('Could not copy Base Images - Exception Seen ->'+str(e), goto=['common_cleanup'])

        # Copy the Target Image
        try:
            testscript.parameters['BL'].shellexec(['rm -rf ~/.ssh/known_hosts'])
            testscript.parameters['BL'].api.copy_to_device(abs_target_image, 'bootflash:', testbed.servers.tftp.address, 'scp', timeout=1600, vrf='management')
            testscript.parameters['LEAF-2'].shellexec(['rm -rf ~/.ssh/known_hosts'])
            testscript.parameters['LEAF-2'].api.copy_to_device(abs_target_image, 'bootflash:', testbed.servers.tftp.address, 'scp', timeout=1600, vrf='management')
        except Exception as e:
            self.failed('Could not copy Target Images - Exception Seen ->'+str(e), goto=['common_cleanup'])

        BL_base_img_verify_flag         = testscript.parameters['BL'].api.verify_file_exists(testscript.parameters['base_image'])
        BL_target_img_verify_flag       = testscript.parameters['BL'].api.verify_file_exists(testscript.parameters['target_image'])
        LEAF_base_img_verify_flag       = testscript.parameters['LEAF-2'].api.verify_file_exists(testscript.parameters['base_image'])
        LEAF_target_img_verify_flag     = testscript.parameters['LEAF-2'].api.verify_file_exists(testscript.parameters['target_image'])

        if BL_base_img_verify_flag == 0 or BL_target_img_verify_flag == 0 or LEAF_base_img_verify_flag == 0 or LEAF_target_img_verify_flag == 0:
            self.failed(reason='Image exists Verification failed', goto=['common_cleanup'])
        else:
            self.passed()

    # *****************************************************************************************************************************#
    @aetest.subsection
    def CHECK_BL_BASE_IMAGES(self, testscript):
        """ Check if devices are loaded with base image and skip base image load """

        # Set the reason for SKIP
        BL_base_image_load = 1
        resn = 'The BL device is already loaded with Base Image, Proceeding to configuration'

        # Get current booted Image details
        image_details = json.loads(testscript.parameters['BL'].execute('show ver | json'))

        # Check the current booted Image
        if re.search(str(testscript.parameters['base_image'])+'$',image_details['nxos_file_name']):
            log.info("Skipping the Base Image Load on BL, since it is already UP with it")
            BL_base_image_load = 0
            aetest.skip.affix(section=BL_LOAD_BASE_IMAGE, reason = resn)
        else:
            log.info("Need to Load Base Image on BL")

    # *****************************************************************************************************************************#
    @aetest.subsection
    def CHECK_LEAF_BASE_IMAGES(self, testscript):
        """ Check if devices are loaded with base image and skip base image load """

        # Set the reason for SKIP
        LEAF_base_image_load = 1
        resn = 'The LEAF device is already loaded with Base Image, Proceeding to configuration'

        # Get current booted Image details
        image_details = json.loads(testscript.parameters['LEAF-2'].execute('show ver | json'))

        # Check the current booted Image
        if re.search(str(testscript.parameters['base_image'])+'$',image_details['nxos_file_name']):
            log.info("Skipping the Base Image Load on LEAF, since it is already UP with it")
            LEAF_base_image_load = 0
            aetest.skip.affix(section=LEAF_LOAD_BASE_IMAGE, reason = resn)
        else:
            log.info("Need to Load Base Image on LEAF")

# *****************************************************************************************************************************#
class BL_LOAD_BASE_IMAGE(GenieStandalone):
    """ Load Base Image on BL """

    # Devices under test
    uut = 'BL'
    devices = ['BL']

    # Type of verifications and Triggers to performed
    verifications = ['Verify_InterfaceBrief']
    triggers = ['TriggerReloadTor', 'TriggerSleep']

    # Order of the Trigger and Verifications
    if BL_base_image_load:
        order = ['setup_boot_variables', 'copy_r_s', 'TriggerReloadTor', 'TriggerSleep']
    else:
        order = ['copy_r_s', 'TriggerSleep']
    
    # Mandatory Params
    timeout = {'interval':20, 'max_time':600}

    # Custom Params
    custom_arguments = {
        'TriggerReloadTor': {
            'timeout':{'interval':50, 'max_time':2000}
        }
    }

    # This is how to create a setup section
    @ aetest.test
    def setup_boot_variables(self, testscript):
        """ Setup Boot Variables """
        # Set boot variables
        testscript.parameters['BL'].configure("boot nxos "+str(testscript.parameters['base_image']), timeout=1200)

    # This is how to create a setup section
    @ aetest.test
    def copy_r_s(self, testscript):
        """ Perform Copy R S """
        log.info('Perform copy r s of the devices')
        testscript.parameters['BL'].configure("copy r s", timeout=1200)

# *****************************************************************************************************************************#
class LEAF_LOAD_BASE_IMAGE(GenieStandalone):
    """ Load Base Image on LEAF """

    # Devices under test
    uut = 'LEAF-2'
    devices = ['LEAF-2']

    # Type of verifications and Triggers to performed
    verifications = ['Verify_InterfaceBrief']
    triggers = ['TriggerReloadTor', 'TriggerSleep']

    # Order of the Trigger and Verifications
    if LEAF_base_image_load:
        order = ['setup_boot_variables', 'copy_r_s', 'TriggerReloadTor', 'TriggerSleep']
    else:
        order = ['copy_r_s', 'TriggerSleep']

    # Mandatory Params
    timeout = {'interval':20, 'max_time':600}

    # Custom Params
    custom_arguments = {
        'TriggerReloadTor': {
            'timeout':{'interval':20, 'max_time':600}
        }
    }

    # This is how to create a setup section
    @ aetest.test
    def setup_boot_variables(self, testscript):
        """ Setup boot variables """
        # Set boot variables
        testscript.parameters['LEAF-2'].configure("boot nxos "+str(testscript.parameters['base_image']), timeout=1200)

    # This is how to create a setup section
    @ aetest.test
    def copy_r_s(self, testscript):
        """ Perform Copy R S """
        log.info('Perform copy r s of the devices')
        testscript.parameters['LEAF-2'].configure("copy r s", timeout=1200)

# *****************************************************************************************************************************#
class BASE_EVPN_VxLAN_BRINGUP(aetest.Testcase):
    """BASE_EVPN_VxLAN_BRINGUP Test-Case"""

    # *****************************************************************************************************************************#
    @aetest.test
    def enable_feature_set(self, testscript):
        """ Configuring Features and Feature-sets """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            leafLst                 = [testscript.parameters['LEAF-1'], testscript.parameters['LEAF-2'], testscript.parameters['LEAF-3'], testscript.parameters['BL']]
            spineFeatureList        = ['ospf', 'bgp', 'pim', 'lacp', 'nv overlay']
            LeafFeatureList         = ['ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp', 'nv overlay']
            PGWFeatureList          = ['ospf', 'bgp', 'pim', 'interface-vlan', 'lacp', 'nv overlay']
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
            featureConfigureLeaf1_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-1'], LeafFeatureList)
            if featureConfigureLeaf1_status['result']:
                log.info("Passed Configuring features on LEAF-1")
            else:
                log.debug("Failed configuring features on LEAF-1")
                configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-2
            featureConfigureLeaf2_status = infraConfig.configureVerifyFeature(testscript.parameters['LEAF-2'], LeafFeatureList)
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
            # Configure Feature-set on BL
            featureConfigureBL_status = infraConfig.configureVerifyFeature(testscript.parameters['BL'], LeafFeatureList)
            if featureConfigureBL_status['result']:
                log.info("Passed Configuring features on BL")
            else:
                log.debug("Failed configuring features on BL")
                configFeatureSet_msgs += featureConfigureBL_status['log']
                configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on PGW
            featureSetConfigurePGW_status = infraConfig.configureVerifyFeatureSet(testscript.parameters['PGW'], ['mpls'])
            if featureSetConfigurePGW_status['result']:
                log.info("Passed Configuring feature-sets on PGW")
            else:
                log.debug("Failed configuring feature-sets on PGW")
                configFeatureSet_msgs += featureSetConfigurePGW_status['log']
                configFeatureSet_status.append(0)

            featureConfigurePGW_status = infraConfig.configureVerifyFeature(testscript.parameters['PGW'], PGWFeatureList)
            if featureConfigurePGW_status['result']:
                log.info("Passed Configuring features on PGW")
            else:
                log.debug("Failed configuring features on PGW")
                configFeatureSet_msgs += featureConfigurePGW_status['log']
                configFeatureSet_status.append(0)

            if 0 in configFeatureSet_status:
                self.failed(reason=configFeatureSet_msgs, goto=['common_cleanup'])

        else:
            self.passed(reason="Skipped Device Configuration as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_SPINE(self, testscript):
        """ Configuring SPINE """

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
                      
                    interface ''' + str(testscript.parameters['intf_SPINE_to_BL']) + '''
                      channel-group ''' + str(testscript.parameters['BL_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown
                      
                ''', timeout=1200)
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.failed('Exception occurred while configuring on SPINE', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_LEAF_1(self, testscript):
        """ Configuring LEAF-1 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNLeaf(testscript.parameters['LEAF-1'], testscript.parameters['forwardingSysDict'],testscript.parameters['LEAF_1_dict'])

            try:
                testscript.parameters['LEAF-1'].configure('''

                    interface ''' + str(testscript.parameters['intf_LEAF_1_to_SPINE']) + '''
                      channel-group ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_LEAF_1_to_PGW_1']) + '''
                      no shutdown
                      
                    interface ''' + str(testscript.parameters['intf_LEAF_1_to_PGW_2']) + '''
                      no shutdown
                      
                    interface ''' + str(testscript.parameters['intf_LEAF_1_to_IXIA']) + '''
                      no shutdown

              ''', timeout=1200)
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on LEAF-2', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_LEAF_2(self, testscript):
        """ Configuring LEAF-2 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNLeaf(testscript.parameters['LEAF-2'], testscript.parameters['forwardingSysDict'],testscript.parameters['LEAF_2_dict'])

            try:
                testscript.parameters['LEAF-2'].configure('''

                    interface ''' + str(testscript.parameters['intf_LEAF_2_to_SPINE']) + '''
                      channel-group ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_LEAF_2_to_PGW_1']) + '''
                      no shutdown
                      
                    interface ''' + str(testscript.parameters['intf_LEAF_2_to_PGW_2']) + '''
                      no shutdown

              ''', timeout=1200)
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on LEAF-2', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_LEAF_3(self, testscript):
        """ Configuring LEAF-3 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNLeaf(testscript.parameters['LEAF-3'], testscript.parameters['forwardingSysDict'],testscript.parameters['LEAF_3_dict'])

            try:
                testscript.parameters['LEAF-3'].configure('''

                    interface ''' + str(testscript.parameters['intf_LEAF_3_to_SPINE']) + '''
                      channel-group ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_LEAF_3_to_PGW_1']) + '''
                      no shutdown
                      
                    interface ''' + str(testscript.parameters['intf_LEAF_3_to_PGW_2']) + '''
                      no shutdown

              ''', timeout=1200)
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on LEAF-3', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_BL(self, testscript):
        """ Configuring BL """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNLeaf(testscript.parameters['BL'], testscript.parameters['forwardingSysDict'],testscript.parameters['BL_dict'])

            try:
                testscript.parameters['BL'].configure('''
                    interface ''' + str(testscript.parameters['intf_BL_to_SPINE']) + '''
                      channel-group ''' + str(testscript.parameters['BL_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown
                ''', timeout=1200)

            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on BL', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_PGW(self, testscript):
        """ Configuring PGW """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            try:
                testscript.parameters['PGW'].configure('''
                    interface ''' + str(testscript.parameters['intf_PGW_to_LEAF_1_1']) + '''
                      no shutdown
                      
                    interface ''' + str(testscript.parameters['intf_PGW_to_LEAF_1_2']) + '''
                      no shutdown
                      
                    interface ''' + str(testscript.parameters['intf_PGW_to_LEAF_2_1']) + '''
                      no shutdown
                      
                    interface ''' + str(testscript.parameters['intf_PGW_to_LEAF_2_2']) + '''
                      no shutdown
                      
                    interface ''' + str(testscript.parameters['intf_PGW_to_LEAF_3_1']) + '''
                      no shutdown
                      
                    interface ''' + str(testscript.parameters['intf_PGW_to_LEAF_3_2']) + '''
                      no shutdown
                      
                    interface ''' + str(testscript.parameters['intf_PGW_to_IXIA']) + '''
                      no shutdown
                ''', timeout=1200)

            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on PGW', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def configure_IXIA_facing_sub_ints_on_dut(self, testscript):
        """ Configure IXIA facing sub-interfaces """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            BL = testscript.parameters['BL']
            LEAF_1 = testscript.parameters['LEAF-1']
            PGW = testscript.parameters['PGW']

            BL_TGEN_data = testscript.parameters['BL_TGEN_data']
            PGW_TGEN_data = testscript.parameters['PGW_TGEN_data']
            LEAF_1_TGEN_data = testscript.parameters['LEAF_1_TGEN_data']

            topologies = [testscript.parameters['topo_1_vnf_leaves_dict'],
                        testscript.parameters['topo_2_vnf_leaves_dict'],
                        testscript.parameters['topo_3_vnf_leaves_dict']]

            # Configuring Sub-interfaces on DUT facing IXIA
            BL.configure('''
                        interface ''' + str(testscript.parameters['intf_BL_to_IXIA']) + '''
                            no shutdown
                        ''')

            LEAF_1.configure('''
                    interface ''' + str(testscript.parameters['intf_LEAF_1_to_IXIA']) + '''
                        no shutdown
            ''')

            PGW.configure('''
                    interface ''' + str(testscript.parameters['intf_PGW_to_IXIA']) + '''
                        no shutdown
            ''')

            BL_vlan = int(BL_TGEN_data['vlan_id'])
            BL_ipv4 = ip.IPv4Interface(str(BL_TGEN_data['v4_gateway'])+'/24')
            BL_ipv6 = ip.IPv6Interface(str(BL_TGEN_data['v6_gateway']) + '/64')
            sub_int = 1
            for topo in topologies:
                BL.configure('''
                        interface '''+str(testscript.parameters['intf_BL_to_IXIA'])+'''.'''+str(sub_int)+'''
                            encapsulation dot1q '''+str(BL_vlan)+'''
                            vrf member '''+str(topo['vrf'])+'''
                            ip address '''+str(BL_ipv4.ip)+'''/24
                            ipv6 address '''+str(BL_ipv6.ip)+'''/64
                            no shutdown
                ''')
                BL_vlan += 1
                BL_ipv4 += (256**3)
                BL_ipv6 += (65536**6)
                sub_int += 1

            LEAF_vlan = int(LEAF_1_TGEN_data['vlan_id'])
            LEAF_ipv4 = ip.IPv4Interface(str(LEAF_1_TGEN_data['v4_gateway'])+'/24')
            LEAF_ipv6 = ip.IPv6Interface(str(LEAF_1_TGEN_data['v6_gateway']) + '/64')
            sub_int = 1
            for topo in topologies:
                LEAF_1.configure('''
                        interface '''+str(testscript.parameters['intf_LEAF_1_to_IXIA'])+'''.'''+str(sub_int)+'''
                            encapsulation dot1q '''+str(LEAF_vlan)+'''
                            vrf member '''+str(topo['vrf'])+'''
                            ip address '''+str(LEAF_ipv4.ip)+'''/24
                            ipv6 address '''+str(LEAF_ipv6.ip)+'''/64
                            no shutdown
                ''')
                LEAF_vlan += 1
                LEAF_ipv4 += (256**3)
                LEAF_ipv6 += (65536**6)
                sub_int += 1

            PGW_vlan = int(PGW_TGEN_data['vlan_id'])
            PGW_ipv4 = ip.IPv4Interface(str(PGW_TGEN_data['v4_gateway'])+'/24')
            PGW_ipv6 = ip.IPv6Interface(str(PGW_TGEN_data['v6_gateway']) + '/64')
            PGW_bgp_ipv4 = ip.IPv4Interface(str(PGW_TGEN_data['v4_addr'])+'/24')
            PGW_bgp_ipv6 = ip.IPv6Interface(str(PGW_TGEN_data['v6_addr']) + '/64')
            sub_int = 1
            for topo in topologies:
                PGW.configure('''
                        interface '''+str(testscript.parameters['intf_PGW_to_IXIA'])+'''.'''+str(sub_int)+'''
                            encapsulation dot1q '''+str(PGW_vlan)+'''
                            vrf member '''+str(topo['vrf'])+'''
                            ip address '''+str(PGW_ipv4.ip)+'''/24
                            ipv6 address '''+str(PGW_ipv6.ip)+'''/64
                            no shutdown

                        router bgp '''+str(testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_1]['pgw_bgp_as'])+'''
                            vrf '''+str(topo['vrf'])+'''
                                neighbor '''+str(PGW_bgp_ipv4.ip)+''' remote-as 350
                                    address-family ipv4 unicast
                                        send-community
                                        send-community extended
                                neighbor '''+str(PGW_bgp_ipv6.ip)+''' remote-as 350
                                    address-family ipv6 unicast
                                        send-community
                                        send-community extended
                ''')
                PGW_vlan += 1
                PGW_ipv4 += (256**3)
                PGW_ipv6 += (65536**6)
                PGW_bgp_ipv4 += (256**3)
                PGW_bgp_ipv6 += (65536**6)
                sub_int += 1
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def perform_copy_r_s(self,testscript):
        """ Save all configurations (copy r s) """

        for device in device_list:
            device.configure("copy r s", timeout=300)

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
            time.sleep(300)
        else:
            time.sleep(60)

# *****************************************************************************************************************************#
class VERIFY_BASE_VxLAN_EVPN_NETWORK(aetest.Testcase):
    """ Verify Base EVPN """

    # =============================================================================================================================#
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if bgpSessionData['result'] == 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] == 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("WARNING : Failed to verify NVE Peering\n\n")
            self.passx(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_VNI(self, testscript):
        """ Verify VNI States """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if nveVniData['result'] == 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

# *****************************************************************************************************************************#
class VxLAN_PVNF_BRINGUP(aetest.Testcase):
    """VxLAN_PVNF_CONFIGURATION_BRINGUP"""

    # =============================================================================================================================#
    @aetest.test
    def configure_SPINE_for_BGP_l2vpn_advertisement(self, testscript):
        """Configure SPINE"""
        
        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
            spine_rt_map_name = testscript.parameters['SPINE_PVNF_rtmap_name']

            testscript.parameters["SPINE"].configure('''
                route-map '''+str(spine_rt_map_name)+''' permit
                    set path-selection all advertise

                router bgp '''+str(testscript.parameters['forwardingSysDict']['BGP_AS_num'])+'''
                    address-family l2vpn evpn
                        maximum-paths mixed 32
                        additional-paths send
                        additional-paths receive
                        additional-paths selection route-map '''+str(spine_rt_map_name)+'''
            ''', timeout=1200)
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def configure_BL_for_max_paths(self, testscript):
        """Configure BL for MAX Paths"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
            
            BL = testscript.parameters['BL']

            BL.configure('''
                            route-map BL_passall permit
                                set path-selection all advertise
                            
                            ip load-sharing address source-destination rotate 32 universal-id 1

                            router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                                address-family l2vpn evpn
                                    maximum-paths mixed 32
                                    additional-paths send
                                    additional-paths receive
                                    additional-paths selection route-map BL_passall
            ''', timeout=1200)

            BL.configure('''
                            router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                                vrf ''' + str(testscript.parameters['topo_1_vnf_leaves_dict']['vrf']) + '''
                                    address-family ipv4 unicast
                                        export-gateway-ip
                                        maximum-paths mixed 32
                                    address-family ipv6 unicast
                                        export-gateway-ip
                                        maximum-paths mixed 32
                        ''', timeout=1200)

            BL.configure('''
                            router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                                vrf ''' + str(testscript.parameters['topo_2_vnf_leaves_dict']['vrf']) + '''
                                    address-family ipv4 unicast
                                        export-gateway-ip
                                        maximum-paths mixed 32
                                    address-family ipv6 unicast
                                        export-gateway-ip
                                        maximum-paths mixed 32
                        ''', timeout=1200)

            BL.configure('''
                            router bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                                vrf ''' + str(testscript.parameters['topo_3_vnf_leaves_dict']['vrf']) + '''
                                    address-family ipv4 unicast
                                        export-gateway-ip
                                        maximum-paths mixed 32
                                    address-family ipv6 unicast
                                        export-gateway-ip
                                        maximum-paths mixed 32
                        ''', timeout=1200)
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def configure_PVNF_underlay_topo_1(self, testscript):
        """configure_PVNF_underlay_topo_1 - Common Loopback Solution"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
            pvnfConfig.configurePVNF_Underlay_PGW_to_LEAF(testscript.parameters['PGW'],testscript.parameters['topo_1_vnf_leaves_dict'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def configure_PVNF_underlay_topo_2(self, testscript):
        """configure_PVNF_underlay_topo_2 - Individual Loopback Solution"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
            pvnfConfig.configurePVNF_Underlay_PGW_to_LEAF(testscript.parameters['PGW'],testscript.parameters['topo_2_vnf_leaves_dict'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def configure_PVNF_underlay_topo_3(self, testscript):
        """configure_PVNF_underlay_topo_3 - Individual Links Solution"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
            pvnfConfig.configurePVNF_Underlay_PGW_to_LEAF(testscript.parameters['PGW'],testscript.parameters['topo_3_vnf_leaves_dict'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def configure_PVNF_pvnfBgp_topo_1(self, testscript):
        """configure_PVNF_pvnfBgp_topo_1 - PGW Common Loopback Solution"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
            pvnfConfig.configurePVNF_BGP_PGW_to_LEAF(testscript.parameters['PGW'],testscript.parameters['topo_1_vnf_leaves_dict'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def configure_PVNF_pvnfBgp_topo_2(self, testscript):
        """configure_PVNF_pvnfBgp_topo_2 - PGW Individual Loopback Solution"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
            pvnfConfig.configurePVNF_BGP_PGW_to_LEAF(testscript.parameters['PGW'],testscript.parameters['topo_2_vnf_leaves_dict'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def configure_PVNF_pvnfBgp_topo_3(self, testscript):
        """configure_PVNF_pvnfBgp_topo_3 - PGW Individual Links Solution"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
            pvnfConfig.configurePVNF_BGP_PGW_to_LEAF(testscript.parameters['PGW'],testscript.parameters['topo_3_vnf_leaves_dict'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def configure_PGW_PVNF_prefix_lists_for_redist(self, testscript):
        """configure_PVNF_prefix_lists_for_redist"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
        
            # Configure the Prefix lists
            pvnfConfig.generate_prefix_list_per_topo(testscript.parameters['PGW'],testscript.parameters['topo_1_vnf_leaves_dict'])
            pvnfConfig.generate_prefix_list_per_topo(testscript.parameters['PGW'],testscript.parameters['topo_2_vnf_leaves_dict'])
            pvnfConfig.generate_prefix_list_per_topo(testscript.parameters['PGW'],testscript.parameters['topo_3_vnf_leaves_dict'])

            LEAF_1 = testscript.parameters['LEAF-1']
            LEAF_2 = testscript.parameters['LEAF-2']
            LEAF_3 = testscript.parameters['LEAF-3']
            LEAF_1_TGEN_data = testscript.parameters['LEAF_1_TGEN_data']

            topologies = [testscript.parameters['topo_1_vnf_leaves_dict'],
                        testscript.parameters['topo_2_vnf_leaves_dict'],
                        testscript.parameters['topo_3_vnf_leaves_dict']]

            # Get the prefix names
            LEAF_1_prfx_name_v4 = testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_1]['LEAF_v4_prfx_lst_name']
            LEAF_1_prfx_name_v6 = testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_1]['LEAF_v6_prfx_lst_name']

            # Get the host network
            LEAF_1_v4_nw = ip.IPv4Interface(str(LEAF_1_TGEN_data['v4_addr']) + '/24')
            LEAF_1_v6_nw = ip.IPv6Interface(str(LEAF_1_TGEN_data['v6_addr']) + '/64')

            # Add PVNF EW LEAF-1 hosts to the prefix list for redistribution
            for _ in topologies:
                # Set the host network for broader subnet
                temp_v4_network = ip.IPv4Interface(str(LEAF_1_v4_nw.ip) + '/24')
                temp_v6_network = ip.IPv6Interface(str(LEAF_1_v6_nw.ip) + '/64')
                LEAF_1.configure('''
                    ip prefix-list ''' + str(LEAF_1_prfx_name_v4) + ''' permit ''' + str(temp_v4_network.network) + ''' le ''' + str(LEAF_1_v4_nw.max_prefixlen) + '''
                    ipv6 prefix-list ''' + str(LEAF_1_prfx_name_v6) + ''' permit ''' + str(temp_v6_network.network) + ''' le ''' + str(LEAF_1_v6_nw.max_prefixlen) + '''
                ''')
                LEAF_2.configure('''
                    ip prefix-list ''' + str(LEAF_1_prfx_name_v4) + ''' permit ''' + str(temp_v4_network.network) + ''' le ''' + str(LEAF_1_v4_nw.max_prefixlen) + '''
                    ipv6 prefix-list ''' + str(LEAF_1_prfx_name_v6) + ''' permit ''' + str(temp_v6_network.network) + ''' le ''' + str(LEAF_1_v6_nw.max_prefixlen) + '''
                ''')
                LEAF_3.configure('''
                    ip prefix-list ''' + str(LEAF_1_prfx_name_v4) + ''' permit ''' + str(temp_v4_network.network) + ''' le ''' + str(LEAF_1_v4_nw.max_prefixlen) + '''
                    ipv6 prefix-list ''' + str(LEAF_1_prfx_name_v6) + ''' permit ''' + str(temp_v6_network.network) + ''' le ''' + str(LEAF_1_v6_nw.max_prefixlen) + '''
                ''')
                LEAF_1_v4_nw += (256 ** 3)
                LEAF_1_v6_nw += (65536 ** 6)
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def configure_STOP_External_route_maps(self, testscript):
        """ configure stop external route-maps """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
        
            LEAF_1 = testscript.parameters['LEAF-1']
            LEAF_2 = testscript.parameters['LEAF-2']
            LEAF_3 = testscript.parameters['LEAF-3']

            topologies = [testscript.parameters['topo_1_vnf_leaves_dict'],
                        testscript.parameters['topo_2_vnf_leaves_dict'],
                        testscript.parameters['topo_3_vnf_leaves_dict']]

            # Get the prefix and route-map names
            LEAF_stop_prfx_name_v4 = testscript.parameters['LEAF_stop_external_PVNF_prfx_name'] + '_v4'
            LEAF_stop_prfx_name_v6 = testscript.parameters['LEAF_stop_external_PVNF_prfx_name'] + '_v6'
            LEAF_stop_rtmap_name = testscript.parameters['LEAF_stop_external_PVNF_rtmap_name']

            # Add PVNF EW LEAF-1 hosts to the prefix list
            for topology in topologies:
                if (topology['type'] == 'topo_1') or (topology['type'] == 'topo_2'):
                    for leaf in topology:
                        if type(topology[leaf]) == dict:
                            topo_nw_v4_prfx = ip.IPv4Interface(str(topology[leaf]['pgw_comn_loop_v4']) + '/8')
                            topo_nw_v6_prfx = ip.IPv6Interface(str(topology[leaf]['pgw_comn_loop_v6']) + '/32')
                            topo_bgp_v4_prfx = ip.IPv4Interface(str(topology['BGP_v4_prefixes']) + '/8')
                            topo_bgp_v6_prfx = ip.IPv6Interface(str(topology['BGP_v6_prefixes']) + '/32')
                            leaf.configure('''
                                ip prefix-list ''' + str(LEAF_stop_prfx_name_v4) + ''' permit ''' + str(
                                topo_nw_v4_prfx.network) + ''' le ''' + str(topo_nw_v4_prfx.max_prefixlen) + '''
                                ipv6 prefix-list ''' + str(LEAF_stop_prfx_name_v6) + ''' permit ''' + str(
                                topo_nw_v6_prfx.network) + ''' le ''' + str(topo_nw_v6_prfx.max_prefixlen) + '''
                                ip prefix-list ''' + str(LEAF_stop_prfx_name_v4) + ''' permit ''' + str(
                                topo_bgp_v4_prfx.network) + ''' le ''' + str(topo_nw_v4_prfx.max_prefixlen) + '''
                                ipv6 prefix-list ''' + str(LEAF_stop_prfx_name_v6) + ''' permit ''' + str(
                                topo_bgp_v6_prfx.network) + ''' le ''' + str(topo_nw_v6_prfx.max_prefixlen) + '''
                            ''', timeout=1200)
                if (topology['type'] == 'topo_3'):
                    for leaf in topology:
                        if type(topology[leaf]) == dict:
                            topo_nw_v4_prfx = ip.IPv4Interface(str(topology[leaf]['underlay_ipv4_start']) + '/8')
                            topo_nw_v6_prfx = ip.IPv6Interface(str(topology[leaf]['underlay_ipv6_start']) + '/32')
                            topo_bgp_v4_prfx = ip.IPv4Interface(str(topology['BGP_v4_prefixes']) + '/8')
                            topo_bgp_v6_prfx = ip.IPv6Interface(str(topology['BGP_v6_prefixes']) + '/32')
                            leaf.configure('''
                                ip prefix-list ''' + str(LEAF_stop_prfx_name_v4) + ''' permit ''' + str(
                                topo_nw_v4_prfx.network) + ''' le ''' + str(topo_nw_v4_prfx.max_prefixlen) + '''
                                ipv6 prefix-list ''' + str(LEAF_stop_prfx_name_v6) + ''' permit ''' + str(
                                topo_nw_v6_prfx.network) + ''' le ''' + str(topo_nw_v6_prfx.max_prefixlen) + '''
                                ip prefix-list ''' + str(LEAF_stop_prfx_name_v4) + ''' permit ''' + str(
                                topo_bgp_v4_prfx.network) + ''' le ''' + str(topo_nw_v4_prfx.max_prefixlen) + '''
                                ipv6 prefix-list ''' + str(LEAF_stop_prfx_name_v6) + ''' permit ''' + str(
                                topo_bgp_v6_prfx.network) + ''' le ''' + str(topo_nw_v6_prfx.max_prefixlen) + '''
                            ''', timeout=1200)

            # Create Deny route-map on LEAF-2 and LEAF-3 to deny any external routes learnt via SPINE
            LEAF_1.configure('''
                    ip load-sharing address source-destination rotate 32 universal-id 1
                    route-map ''' + str(LEAF_stop_rtmap_name) + ''' deny 5
                        match ip address prefix-list ''' + str(LEAF_stop_prfx_name_v4) + '''
                    route-map ''' + str(LEAF_stop_rtmap_name) + ''' deny 10
                        match ipv6 address prefix-list ''' + str(LEAF_stop_prfx_name_v6) + '''
                    route-map ''' + str(LEAF_stop_rtmap_name) + ''' permit 50
                    router bgp ''' + str(testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_1]['leaf_as']) + '''
                        neighbor ''' + str(testscript.parameters['LEAF_1_dict']['SPINE_1_UPLINK_PO']['spine_loop0_ip']) + '''
                            address-family l2vpn evpn
                            send-community
                            send-community extended
            ''', timeout=1200)

            LEAF_2.configure('''
                    ip load-sharing address source-destination rotate 32 universal-id 1
                    route-map ''' + str(LEAF_stop_rtmap_name) + ''' deny 5
                        match ip address prefix-list ''' + str(LEAF_stop_prfx_name_v4) + '''
                    route-map ''' + str(LEAF_stop_rtmap_name) + ''' deny 10
                        match ipv6 address prefix-list ''' + str(LEAF_stop_prfx_name_v6) + '''
                    route-map ''' + str(LEAF_stop_rtmap_name) + ''' permit 50

                    router bgp ''' + str(testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_2]['leaf_as']) + '''
                        neighbor ''' + str(testscript.parameters['LEAF_2_dict']['SPINE_1_UPLINK_PO']['spine_loop0_ip']) + '''
                            address-family l2vpn evpn
                            send-community
                            send-community extended
                            route-map ''' + str(LEAF_stop_rtmap_name) + ''' in
            ''', timeout=1200)

            LEAF_3.configure('''
                    ip load-sharing address source-destination rotate 32 universal-id 1
                    route-map ''' + str(LEAF_stop_rtmap_name) + ''' deny 5
                        match ip address prefix-list ''' + str(LEAF_stop_prfx_name_v4) + '''
                    route-map ''' + str(LEAF_stop_rtmap_name) + ''' deny 10
                        match ipv6 address prefix-list ''' + str(LEAF_stop_prfx_name_v6) + '''
                    route-map ''' + str(LEAF_stop_rtmap_name) + ''' permit 50

                    router bgp ''' + str(testscript.parameters['topo_1_vnf_leaves_dict'][LEAF_3]['leaf_as']) + '''
                        neighbor ''' + str(testscript.parameters['LEAF_3_dict']['SPINE_1_UPLINK_PO']['spine_loop0_ip']) + '''
                            address-family l2vpn evpn
                            send-community
                            send-community extended
                            route-map ''' + str(LEAF_stop_rtmap_name) + ''' in
            ''', timeout=1200)
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def restart_BGP_clear_routes(self, testscript):
        """cclear BGP"""
    
        for dut in device_list:
            dut.configure('''
                restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                clear ip bgp vrf all *
                clear ip route vrf all *
                clear ipv6 route vrf all *
            ''', timeout=1200)
    
        time.sleep(120)

    # =============================================================================================================================#
    @aetest.test
    def verify_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if bgpSessionData['result'] == 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify VNI States """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if nveVniData['result'] == 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

# *****************************************************************************************************************************#
class IXIA_CONFIGURATION(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    # =============================================================================================================================#
    @aetest.test
    def CONNECT_IXIA_CHASSIS(self, testscript):
        """ IXIA_CONFIGURATION subsection: Connect to IXIA """

        # testscript.parameters['ixia_int_list'] = str(testscript.parameters['intf_IXIA_to_BL']) + " " + str(testscript.parameters['intf_IXIA_to_PGW']) \
        #                                          + " " + str(testscript.parameters['intf_IXIA_to_LEAF_1'])

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            # Get IXIA paraameters
            ixia_chassis_ip = testscript.parameters['ixia_chassis_ip']
            ixia_tcl_server = testscript.parameters['ixia_tcl_server']
            ixia_tcl_port = testscript.parameters['ixia_tcl_port']
            ixia_int_list = testscript.parameters['ixia_int_list']

            ix_int_1 = testscript.parameters['intf_IXIA_to_BL']
            ix_int_2 = testscript.parameters['intf_IXIA_to_PGW']
            ix_int_3 = testscript.parameters['intf_IXIA_to_LEAF_1']

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

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def CREATE_IXIA_TOPOLOGIES(self, testscript):
        """ IXIA_CONFIGURATION subsection: Create IXIA Topologies """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            TOPO_1_dict = {'topology_name': 'BL',
                           'device_grp_name': 'BL',
                           'port_handle': testscript.parameters['port_handle_1']}

            TOPO_2_dict = {'topology_name': 'PGW-PVNF',
                           'device_grp_name': 'PGW-PVNF',
                           'port_handle': testscript.parameters['port_handle_2']}

            TOPO_3_dict = {'topology_name': 'LEAF-1-HOST',
                           'device_grp_name': 'LEAF-1-HOST',
                           'port_handle': testscript.parameters['port_handle_3']}

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

            testscript.parameters['IX_TP1']['port_handle'] = testscript.parameters['port_handle_1']
            testscript.parameters['IX_TP2']['port_handle'] = testscript.parameters['port_handle_2']
            testscript.parameters['IX_TP3']['port_handle'] = testscript.parameters['port_handle_3']
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

            # Retrieving TGEN Data from Config file
            CORE_TGEN_data              = testscript.parameters['BL_TGEN_data']
            PGW_TGEN_data               = testscript.parameters['PGW_TGEN_data']
            LEAF_1_TGEN_data            = testscript.parameters['LEAF_1_TGEN_data']

            CORE_int_dict = {'dev_grp_hndl'         : testscript.parameters['IX_TP1']['dev_grp_hndl'],
                             'port_hndl'            : P1,
                             'no_of_ints'           : str(CORE_TGEN_data['no_of_ints']),
                             'phy_mode'             : CORE_TGEN_data['phy_mode'],
                             'mac'                  : CORE_TGEN_data['mac'],
                             'mac_step'             : CORE_TGEN_data['mac_step'],
                             'protocol'             : CORE_TGEN_data['protocol'],
                             'v4_addr'              : CORE_TGEN_data['v4_addr'],
                             'v4_addr_step'         : CORE_TGEN_data['v4_addr_step'],
                             'v4_gateway'           : CORE_TGEN_data['v4_gateway'],
                             'v4_gateway_step'      : CORE_TGEN_data['v4_gateway_step'],
                             'v4_netmask'           : CORE_TGEN_data['v4_netmask'],
                             'v6_addr'              : CORE_TGEN_data['v6_addr'],
                             'v6_addr_step'         : CORE_TGEN_data['v6_addr_step'],
                             'v6_gateway'           : CORE_TGEN_data['v6_gateway'],
                             'v6_gateway_step'      : CORE_TGEN_data['v6_gateway_step'],
                             'v6_netmask'           : CORE_TGEN_data['v6_netmask'],
                             'vlan_id'              : str(CORE_TGEN_data['vlan_id']),
                             'vlan_id_step'         : CORE_TGEN_data['vlan_id_step']}

            PGW_int_dict = {'dev_grp_hndl'     : testscript.parameters['IX_TP2']['dev_grp_hndl'],
                             'port_hndl'            : P2,
                             'no_of_ints'           : str(PGW_TGEN_data['no_of_ints']),
                             'phy_mode'             : PGW_TGEN_data['phy_mode'],
                             'mac'                  : PGW_TGEN_data['mac'],
                             'mac_step'             : PGW_TGEN_data['mac_step'],
                             'protocol'             : PGW_TGEN_data['protocol'],
                             'v4_addr'              : PGW_TGEN_data['v4_addr'],
                             'v4_addr_step'         : PGW_TGEN_data['v4_addr_step'],
                             'v4_gateway'           : PGW_TGEN_data['v4_gateway'],
                             'v4_gateway_step'      : PGW_TGEN_data['v4_gateway_step'],
                             'v4_netmask'           : PGW_TGEN_data['v4_netmask'],
                             'v6_addr'              : PGW_TGEN_data['v6_addr'],
                             'v6_addr_step'         : PGW_TGEN_data['v6_addr_step'],
                             'v6_gateway'           : PGW_TGEN_data['v6_gateway'],
                             'v6_gateway_step'      : PGW_TGEN_data['v6_gateway_step'],
                             'v6_netmask'           : PGW_TGEN_data['v6_netmask'],
                             'vlan_id'              : str(PGW_TGEN_data['vlan_id']),
                             'vlan_id_step'         : PGW_TGEN_data['vlan_id_step']}

            LEAF_int_dict = {'dev_grp_hndl'         : testscript.parameters['IX_TP3']['dev_grp_hndl'],
                             'port_hndl'            : P3,
                             'no_of_ints'           : str(LEAF_1_TGEN_data['no_of_ints']),
                             'phy_mode'             : LEAF_1_TGEN_data['phy_mode'],
                             'mac'                  : LEAF_1_TGEN_data['mac'],
                             'mac_step'             : LEAF_1_TGEN_data['mac_step'],
                             'protocol'             : LEAF_1_TGEN_data['protocol'],
                             'v4_addr'              : LEAF_1_TGEN_data['v4_addr'],
                             'v4_addr_step'         : LEAF_1_TGEN_data['v4_addr_step'],
                             'v4_gateway'           : LEAF_1_TGEN_data['v4_gateway'],
                             'v4_gateway_step'      : LEAF_1_TGEN_data['v4_gateway_step'],
                             'v4_netmask'           : LEAF_1_TGEN_data['v4_netmask'],
                             'v6_addr'              : LEAF_1_TGEN_data['v6_addr'],
                             'v6_addr_step'         : LEAF_1_TGEN_data['v6_addr_step'],
                             'v6_gateway'           : LEAF_1_TGEN_data['v6_gateway'],
                             'v6_gateway_step'      : LEAF_1_TGEN_data['v6_gateway_step'],
                             'v6_netmask'           : LEAF_1_TGEN_data['v6_netmask'],
                             'vlan_id'              : str(LEAF_1_TGEN_data['vlan_id']),
                             'vlan_id_step'         : LEAF_1_TGEN_data['vlan_id_step']}

            CORE_int_data = ixLib.configure_multi_ixia_interface(CORE_int_dict)
            PGW_int_data = ixLib.configure_multi_ixia_interface(PGW_int_dict)
            LEAF_int_data = ixLib.configure_multi_ixia_interface(LEAF_int_dict)

            if CORE_int_data == 0 or PGW_int_data == 0 or LEAF_int_data == 0:
                log.debug("Configuring IXIA Interface failed")
                self.errored("Configuring IXIA Interface failed", goto=['next_tc'])
            else:
                log.info("Configured IXIA Interface Successfully")

            testscript.parameters['IX_TP1']['eth_handle'] = CORE_int_data['eth_handle']
            testscript.parameters['IX_TP1']['ipv4_handle'] = CORE_int_data['ipv4_handle']
            testscript.parameters['IX_TP1']['ipv6_handle'] = CORE_int_data['ipv6_handle']
            testscript.parameters['IX_TP1']['topo_int_handle'] = CORE_int_data['topo_int_handle'].split(" ")

            testscript.parameters['IX_TP2']['eth_handle'] = PGW_int_data['eth_handle']
            testscript.parameters['IX_TP2']['ipv4_handle'] = PGW_int_data['ipv4_handle']
            testscript.parameters['IX_TP2']['ipv6_handle'] = PGW_int_data['ipv6_handle']
            testscript.parameters['IX_TP2']['topo_int_handle'] = PGW_int_data['topo_int_handle'].split(" ")

            testscript.parameters['IX_TP3']['eth_handle'] = LEAF_int_data['eth_handle']
            testscript.parameters['IX_TP3']['ipv4_handle'] = LEAF_int_data['ipv4_handle']
            testscript.parameters['IX_TP3']['ipv6_handle'] = LEAF_int_data['ipv6_handle']
            testscript.parameters['IX_TP3']['topo_int_handle'] = LEAF_int_data['topo_int_handle'].split(" ")

            log.info("IXIA Port 1 Handles")
            log.info(testscript.parameters['IX_TP1'])
            log.info("IXIA Port 2 Handles")
            log.info(testscript.parameters['IX_TP2'])
            log.info("IXIA Port 3 Handles")
            log.info(testscript.parameters['IX_TP3'])

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def CONFIGURE_BGP_INTERFACES(self, testscript):
        """ IXIA_CONFIGURATION subsection: Configure IXIA Interfaces """

        v4_BGP_dict = {
            'topology'                  : testscript.parameters['IX_TP2'],
            'ip_hndl'                   : testscript.parameters['IX_TP2']['ipv4_handle'],
            'count'                     : '1',
            'ip_ver'                    : 4,
            'dut_ip'                    : testscript.parameters['PGW_TGEN_data']['v4_gateway'],
            'dut_ip_step'               : testscript.parameters['PGW_TGEN_data']['v4_gateway_step'],
            'neighbor_type'             : 'external',
            'ixia_as'                   : '350',
            'dut_as'                    : '50',
            'v4_route_start'            : '150.1.1.5',
            'v4_route_step'             : '0.1.0.0',
            'v4_route_prfx'             : '32',
            'route_range_multiplier'    : '4',
            'no_of_routes_per_rt_range' : '50',
            'nest_step'                 : '10.0.0.0,0.1.0.0',
            'nest_flag'                 : '1,1',
        }

        v6_BGP_dict = {
            'topology'                  : testscript.parameters['IX_TP2'],
            'ip_hndl'                   : testscript.parameters['IX_TP2']['ipv6_handle'],
            'count'                     : '1',
            'ip_ver'                    : 6,
            'dut_ip'                    : testscript.parameters['PGW_TGEN_data']['v6_gateway'],
            'dut_ip_step'               : testscript.parameters['PGW_TGEN_data']['v6_gateway_step'],
            'neighbor_type'             : 'external',
            'ixia_as'                   : '350',
            'dut_as'                    : '50',
            'v6_route_start'            : '2001:150:1:1::5',
            'v6_route_step'             : '0:0:1:0::0',
            'v6_route_prfx'             : '128',
            'route_range_multiplier'    : '4',
            'no_of_routes_per_rt_range' : '50',
            'nest_step'                 : '0:10:0:0::0,0:0:1:0::0',
            'nest_flag'                 : '1,1',
        }

        v4_BGP = ixLib.emulate_bgp(v4_BGP_dict)
        v6_BGP = ixLib.emulate_bgp(v6_BGP_dict)
        log.info(v4_BGP)
        log.info(v6_BGP)

        testscript.parameters['IX_TP2']['v4_network_group_handle'] = v4_BGP['network_group_handle']
        testscript.parameters['IX_TP2']['ipv4_prefix_pools_handle'] = v4_BGP['ipv4_prefix_pools_handle']
        testscript.parameters['IX_TP2']['v6_network_group_handle'] = v6_BGP['network_group_handle']
        testscript.parameters['IX_TP2']['ipv6_prefix_pools_handle'] = v6_BGP['ipv6_prefix_pools_handle']

        if v4_BGP != 0 and v6_BGP != 0:
            self.passed(reason='Emulating BGP with route ranges successful')
        else:
            self.failed(reason='Emulating BGP with route ranges failed')

    # =============================================================================================================================#
    @aetest.test
    def START_IXIA_PROTOCOLS(self):
        """ IXIA_CONFIGURATION subsection: Start Protocols """

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
        """ IXIA_CONFIGURATION subsection: Configure UCAST Traffic Item """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            IX_TP1 = testscript.parameters['IX_TP1']
            IX_TP2 = testscript.parameters['IX_TP2']
            IX_TP3 = testscript.parameters['IX_TP3']

            NS_v4_endpoint_set_dict = {
                'src_hndl'              : IX_TP1['ipv4_handle'],
                'dst_hndl'              : IX_TP2['ipv4_prefix_pools_handle'],
                'circuit'               : 'ipv4',
                'TI_name'               : "NS_V4",
                'rate_pps'              : "1000",
                'bi_dir'                : 1,
                'no_of_end_points'      : '3',
                'src_port_start'        : '1',
                'src_port_start_step'   : '0',
                'src_intf_count'        : '1',
                'dst_port_start'        : '1',
                'dst_port_start_step'   : '0',
                'dst_intf_count'        : '4',
            }

            NS_v6_endpoint_set_dict = {
                'src_hndl'              : IX_TP1['ipv6_handle'],
                'dst_hndl'              : IX_TP2['ipv6_prefix_pools_handle'],
                'circuit'               : 'ipv6',
                'TI_name'               : "NS_V6",
                'rate_pps'              : "1000",
                'bi_dir'                : 1,
                'no_of_end_points'      : '3',
                'src_port_start'        : '1',
                'src_port_start_step'   : '0',
                'src_intf_count'        : '1',
                'dst_port_start'        : '1',
                'dst_port_start_step'   : '0',
                'dst_intf_count'        : '4',
            }

            EW_v4_endpoint_set_dict = {
                'src_hndl'              : IX_TP3['ipv4_handle'],
                'dst_hndl'              : IX_TP2['ipv4_prefix_pools_handle'],
                'circuit'               : 'ipv4',
                'TI_name'               : "EW_V4",
                'rate_pps'              : "1000",
                'bi_dir'                : 1,
                'no_of_end_points'      : '3',
                'src_port_start'        : '1',
                'src_port_start_step'   : '0',
                'src_intf_count'        : '1',
                'dst_port_start'        : '1',
                'dst_port_start_step'   : '0',
                'dst_intf_count'        : '4',
            }

            EW_v6_endpoint_set_dict = {
                'src_hndl'              : IX_TP3['ipv6_handle'],
                'dst_hndl'              : IX_TP2['ipv6_prefix_pools_handle'],
                'circuit'               : 'ipv6',
                'TI_name'               : "EW_V6",
                'rate_pps'              : "1000",
                'bi_dir'                : 1,
                'no_of_end_points'      : '3',
                'src_port_start'        : '1',
                'src_port_start_step'   : '0',
                'src_intf_count'        : '1',
                'dst_port_start'        : '1',
                'dst_port_start_step'   : '0',
                'dst_intf_count'        : '4',
            }

            NS_UCAST_v4_TI = ixLib.configure_multi_endpoint_ixia_traffic_item(NS_v4_endpoint_set_dict)
            NS_UCAST_v6_TI = ixLib.configure_multi_endpoint_ixia_traffic_item(NS_v6_endpoint_set_dict)
            EW_UCAST_v4_TI = ixLib.configure_multi_endpoint_ixia_traffic_item(EW_v4_endpoint_set_dict)
            EW_UCAST_v6_TI = ixLib.configure_multi_endpoint_ixia_traffic_item(EW_v6_endpoint_set_dict)

            if NS_UCAST_v4_TI == 0 or NS_UCAST_v6_TI == 0 or EW_UCAST_v4_TI == 0 or EW_UCAST_v6_TI == 0:
                log.debug("Configuring UCast TI failed")
                self.errored("Configuring UCast TI failed", goto=['next_tc'])

        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class VERIFY_PVNF_TOPOLOGY_WITH_TRAFFIC(aetest.Testcase):
    """VERIFY_PVNF_TOPOLOGY_WITH_TRAFFIC"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_common_loopback_topology(BL, PGW, testscript.parameters['topo_1_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_loopback_topology(BL, PGW,testscript.parameters['topo_2_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_PHYSICAL_VM_TOPOLOGY(self, testscript):
        """ VERIFY_PHYSICAL_VM_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BL, PGW,testscript.parameters['topo_3_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Apply IXIA Traffic """

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

            if ixLib.verify_traffic(2,2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class BL_VERIFY_PERFORM_DEVICE_ISSU(aetest.Testcase):
    """VERIFY_PYATS_DEVICE_ISSU"""

    # =============================================================================================================================#
    @aetest.test
    def CHECK_ISSU_IMPACT(self, testscript):
        """ CHECK ISSU IMPACT """

        # Prepare the ISSU Impact Check command
        issu_impact_cmd = 'sh install all impact nxos bootflash:'+str(testscript.parameters['target_image'])+' non-disruptive'

        # Execute the ISSU Impact command
        impact_output = testscript.parameters['BL'].execute(issu_impact_cmd, timeout=1200)
        output_split = list(filter(None, impact_output.split('\n')))
        fail_flag = []
        fail_logs = '\n'

        # Process logs for any failure reasons
        for log_line in output_split:
            if re.search('CRASHED|fail|CPU Hog|malloc|core dump|mts_send|redzone|error', log_line, re.I):
                fail_flag.append(0)
                fail_logs += str(log_line) + '\n'
            if re.search('\\d+\\s+yes\\s+(\\S+)\\s+reset', log_line, re.I):
                if not re.search('\\d+\\s+yes\\s+(non-disruptive)\\s+reset', log_line, re.I):
                    fail_flag.append(0)
                    fail_logs += 'The ISSU Impact is reporting Disruptive, Please check\n'
        
        time.sleep(120)

        # Reporting
        if 0 in fail_flag:
            self.failed(reason=fail_logs, goto=['common_cleanup'])
        else:
            self.passed(reason="Upgrade successful")

    # =============================================================================================================================#
    @aetest.test
    def BL_VERIFY_ISSU(self, testscript):
        """ VERIFY_ISSU """
        
        # Establish dialogs for running ISSU command
        dialog = Dialog([
            Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True),
        ])
        
        # Create ISSU command
        issu_cmd = 'install all nxos bootflash:'+str(testscript.parameters['target_image'])+' non-disruptive' 

        # Perform ISSU
        result, output = testscript.parameters['BL'].reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
        output_split = list(filter(None, output.split('\n')))
        fail_flag = []
        fail_logs = '\n'
        
        # Process logs for any failure reasons
        for log_line in output_split:
            if re.search('CRASHED|fail|CPU Hog|malloc|core dump|mts_send|redzone|error', log_line, re.I):
                if 'Upgrade can no longer be aborted' in log_line:
                    continue
                else:
                    fail_flag.append(0)
                    fail_logs += str(log_line) + '\n'
        
        # Reporting
        if 0 in fail_flag:
            self.failed(reason=fail_logs)
        else:
            self.passed(reason="Upgrade successful")

# *****************************************************************************************************************************#
class LEAF_VERIFY_PERFORM_DEVICE_ISSU(aetest.Testcase):
    """VERIFY_PYATS_DEVICE_ISSU"""

    # =============================================================================================================================#
    @aetest.test
    def CHECK_ISSU_IMPACT(self, testscript):
        """ CHECK ISSU IMPACT """

        # Prepare the ISSU Impact Check command
        issu_impact_cmd = 'sh install all impact nxos bootflash:'+str(testscript.parameters['target_image'])+' non-disruptive'

        # Execute the ISSU Impact command
        impact_output = testscript.parameters['LEAF-2'].execute(issu_impact_cmd, timeout=1200)
        output_split = list(filter(None, impact_output.split('\n')))
        fail_flag = []
        fail_logs = '\n'

        # Process logs for any failure reasons
        for log_line in output_split:
            if re.search('CRASHED|fail|CPU Hog|malloc|core dump|mts_send|redzone|error', log_line, re.I):
                fail_flag.append(0)
                fail_logs += str(log_line) + '\n'
            if re.search('\\d+\\s+yes\\s+(\\S+)\\s+reset', log_line, re.I):
                if not re.search('\\d+\\s+yes\\s+(non-disruptive)\\s+reset', log_line, re.I):
                    fail_flag.append(0)
                    fail_logs += 'The ISSU Impact is reporting Disruptive, Please check\n'
        
        time.sleep(120)

        # Reporting
        if 0 in fail_flag:
            self.failed(reason=fail_logs, goto=['common_cleanup'])
        else:
            self.passed(reason="Upgrade successful")

    # =============================================================================================================================#
    @aetest.test
    def LEAF_VERIFY_ISSU(self, testscript):
        """ VERIFY_ISSU """
        
        # Establish dialogs for running ISSU command
        dialog = Dialog([
            Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True),
        ])
        
        # Create ISSU command
        issu_cmd = 'install all nxos bootflash:'+str(testscript.parameters['target_image'])+' non-disruptive' 

        # Perform ISSU
        result, output = testscript.parameters['LEAF-2'].reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
        output_split = list(filter(None, output.split('\n')))
        fail_flag = []
        fail_logs = '\n'
        
        # Process logs for any failure reasons
        for log_line in output_split:
            if re.search('CRASHED|fail|CPU Hog|malloc|core dump|mts_send|redzone|error', log_line, re.I):
                if 'Upgrade can no longer be aborted' in log_line:
                    continue
                else:
                    fail_flag.append(0)
                    fail_logs += str(log_line) + '\n'
        
        # Reporting
        if 0 in fail_flag:
            self.failed(reason=fail_logs)
        else:
            self.passed(reason="Upgrade successful")

# *****************************************************************************************************************************#
class POST_ISSU_VERIFY_PVNF_TOPOLOGY_WITH_TRAFFIC(aetest.Testcase):
    """POST_ISSU_VERIFY_PVNF_TOPOLOGY_WITH_TRAFFIC"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_common_loopback_topology(BL, PGW, testscript.parameters['topo_1_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_loopback_topology(BL, PGW,testscript.parameters['topo_2_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_PHYSICAL_VM_TOPOLOGY(self, testscript):
        """ VERIFY_PHYSICAL_VM_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BL, PGW,testscript.parameters['topo_3_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

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

            if ixLib.verify_traffic(2,2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class POST_ISSU_VERIFY_SINGLE_AND_DUAL_HOMED_PGW_LEAF_PATH_FLAP(aetest.Testcase):
    """VERIFY_DUAL_HOMED_PGW_LEAF_PATH_FLAP"""

    # =============================================================================================================================#
    @aetest.test
    def SHUT_PGW_LEAF_FIRST_PATH(self, testscript):
        """ Shut first paths to PGW """

        log.info("By Default all the paths are active - Dual Homed to all LEAF's")
        log.info("Now shut one path")

        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_2.configure('''
        interface '''+str(testscript.parameters['intf_LEAF_2_to_PGW_1'])+''','''+str(testscript.parameters['intf_LEAF_2_to_PGW_2'])+'''
            shut
        ''', timeout=1200)

        time.sleep(240)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_FIRST_PATH_SHUT(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2,2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed")
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def SHUT_PGW_LEAF_SECOND_PATH(self, testscript):
        """ Shut second paths PGW """

        log.info("Unshut previous path and shut new path")

        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        LEAF_2.configure('''
        interface ''' + str(testscript.parameters['intf_LEAF_2_to_PGW_1']) + ''',''' + str(testscript.parameters['intf_LEAF_2_to_PGW_2']) + '''
            no shut
        ''', timeout=1200)

        LEAF_3.configure('''
        interface ''' + str(testscript.parameters['intf_LEAF_3_to_PGW_1']) + ''',''' + str(testscript.parameters['intf_LEAF_3_to_PGW_2']) + '''
            shut
        ''', timeout=1200)

        time.sleep(240)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_AFTER_SECOND_PATH_SHUT(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2,2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed")
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def REVERT_PATHS(self, testscript):
        """ Rever the shut paths """

        LEAF_2 = testscript.parameters['LEAF-2']
        LEAF_3 = testscript.parameters['LEAF-3']

        LEAF_2.configure('''
        interface ''' + str(testscript.parameters['intf_LEAF_2_to_PGW_1']) + ''',''' + str(testscript.parameters['intf_LEAF_2_to_PGW_2']) + '''
            no shut
        ''', timeout=1200)

        LEAF_3.configure('''
        interface ''' + str(testscript.parameters['intf_LEAF_3_to_PGW_1']) + ''',''' + str(testscript.parameters['intf_LEAF_3_to_PGW_2']) + '''
            no shut
        ''', timeout=1200)

        # for dut in device_list:
        #     dut.configure('''
        #         restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
        #         clear ip route vrf all *
        #         clear ipv6 route vrf all *
        #     ''', timeout=1200)

        time.sleep(300)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_common_loopback_topology(BL, PGW, testscript.parameters['topo_1_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_loopback_topology(BL, PGW,testscript.parameters['topo_2_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_PHYSICAL_VM_TOPOLOGY(self, testscript):
        """ VERIFY_PHYSICAL_VM_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BL, PGW,testscript.parameters['topo_3_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Apply IXIA Traffic """

        # Apply IXIA Traffic
        if ixLib.apply_traffic() == 1:
            log.info("Applying IXIA TI Passed")
        else:
            self.errored("Applying IXIA TI failed", goto=['next_tc'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_IXIA_TRAFFIC_POST_REVERT(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            time.sleep(20)

            if ixLib.verify_traffic(2,2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class POST_ISSU_VERIFY_RESTART_BGP_AS(aetest.Testcase):
    """VERIFY_RESTART_BGP"""

    # =============================================================================================================================#
    @aetest.test
    def RESTART_BGP_AS(self, testscript):
        """ Restart BGP AS """

        for dut in device_list:
            dut.configure('''
                restart bgp ''' + str(testscript.parameters['forwardingSysDict']['BGP_AS_num']) + '''
                clear ip bgp vrf all *
                clear ip route vrf all *
                clear ipv6 route vrf all *
            ''', timeout=1200)

        time.sleep(240)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_common_loopback_topology(BL, PGW, testscript.parameters['topo_1_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_loopback_topology(BL, PGW,testscript.parameters['topo_2_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_PHYSICAL_VM_TOPOLOGY(self, testscript):
        """ VERIFY_PHYSICAL_VM_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BL, PGW,testscript.parameters['topo_3_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Apply IXIA Traffic """

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

            if ixLib.verify_traffic(2,2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class POST_ISSU_VERIFY_RESTART_BGP_PROCESS(aetest.Testcase):
    """VERIFY_RESTART_BGP_PROCESS"""

    # =============================================================================================================================#
    @aetest.test
    def RESTART_BGP_PROCESS(self, testscript):
        """ Restart BGP Process """

        LEAF_1 = testscript.parameters['LEAF-1']

        if infraTrig.verifyProcessRestart(LEAF_1, "bgp"):
            time.sleep(240)
            self.passed(reason='Restarting Process BGP Successful')
        else:
            time.sleep(240)
            self.failed(reason='Restart Process BGP failed')

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_common_loopback_topology(BL, PGW, testscript.parameters['topo_1_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_loopback_topology(BL, PGW,testscript.parameters['topo_2_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_PHYSICAL_VM_TOPOLOGY(self, testscript):
        """ VERIFY_PHYSICAL_VM_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BL, PGW,testscript.parameters['topo_3_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Apply IXIA Traffic """

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

            if ixLib.verify_traffic(2,2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class POST_ISSU_VERIFY_RESTART_NVE_PROCESS(aetest.Testcase):
    """VERIFY_RESTART_NVE_PROCESS"""

    # =============================================================================================================================#
    @aetest.test
    def RESTART_NVE_PROCESS(self, testscript):
        """ Restart NVE Process """

        LEAF_1 = testscript.parameters['LEAF-1']

        if infraTrig.verifyProcessRestart(LEAF_1, "nve"):
            time.sleep(240)
            self.passed(reason='Restarting Process NVE Successful')
        else:
            time.sleep(240)
            self.failed(reason='Restart Process NVE failed')

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_common_loopback_topology(BL, PGW, testscript.parameters['topo_1_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_loopback_topology(BL, PGW,testscript.parameters['topo_2_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_PHYSICAL_VM_TOPOLOGY(self, testscript):
        """ VERIFY_PHYSICAL_VM_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BL, PGW,testscript.parameters['topo_3_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Apply IXIA Traffic """

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

            if ixLib.verify_traffic(2,2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class POST_ISSU_VERIFY_FLAP_NVE_INTERFACE(aetest.Testcase):
    """VERIFY_FLAP_NVE_INTERFACE"""

    # =============================================================================================================================#
    @aetest.test
    def FLAP_NVE_INT(self, testscript):
        """ Flap NVE interface """

        LEAF_1 = testscript.parameters['LEAF-1']
        fail_flag = []
        fail_msgs = ''

        LEAF_1.configure('''
        interface nve1
            shut
            no shut
        ''', timeout=1200)

        time.sleep(240)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the state
        LEAF_1_nve_out = LEAF_1.execute("sh interf nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_1_nve_out:
            log.info("NVE INT is UP on LEAF-1 after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP on LEAF-1 after shut/no-shut"

        time.sleep(60)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] == 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("WARNING : Failed to verify NVE Peering\n\n")
            self.passx(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify VNI States """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if nveVniData['result'] == 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_common_loopback_topology(BL, PGW, testscript.parameters['topo_1_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_loopback_topology(BL, PGW,testscript.parameters['topo_2_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_PHYSICAL_VM_TOPOLOGY(self, testscript):
        """ VERIFY_PHYSICAL_VM_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BL, PGW,testscript.parameters['topo_3_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Apply IXIA Traffic """

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

            if ixLib.verify_traffic(2,2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class POST_ISSU_BL_RELOAD(GenieStandalone):
    ''' Perform BL Reload '''

    # Devices under test
    uut = 'LEAF-1'
    devices = ['LEAF-1']

    # Type of verifications and Triggers to performed
    verifications = ['Verify_InterfaceBrief']
    triggers = ['TriggerReloadTor', 'TriggerSleep']

    # Order of the Trigger and Verifications
    order = ['copy_r_s', 'TriggerReloadTor', 'TriggerSleep']
    
    # Mandatory Params
    timeout = {'interval':20, 'max_time':600}

    # Custom Params
    custom_arguments = {
        'TriggerReloadTor': {
            'timeout':{'interval':50, 'max_time':2000}
        }
    }

    # This is how to create a setup section
    @ aetest.test
    def copy_r_s(self, testscript):
        """ Perform Copy R S """
        log.info('Perform copy r s of the devices')
        testscript.parameters['LEAF-1'].configure("copy r s", timeout=1200)

# *****************************************************************************************************************************#
class POST_ISSU_POST_BL_RELOAD_VERIFY_PVNF(aetest.Testcase):
    """VERIFY_PVNF_TOR_RELOAD"""

    # =============================================================================================================================#
    @aetest.test
    def SLEEP_POST_TOR_RELOAD(self, testscript):
        """ Sleep post Device Reload """
        time.sleep(240)

    # =============================================================================================================================#
    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] == 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("WARNING : Failed to verify NVE Peering\n\n")
            self.passx(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify VNI States """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if nveVniData['result'] == 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_common_loopback_topology(BL, PGW, testscript.parameters['topo_1_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_loopback_topology(BL, PGW,testscript.parameters['topo_2_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_PHYSICAL_VM_TOPOLOGY(self, testscript):
        """ VERIFY_PHYSICAL_VM_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BL, PGW,testscript.parameters['topo_3_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Apply IXIA Traffic """

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

            if ixLib.verify_traffic(2,2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class POST_ISSU_VERIFY_TOR_RELOAD(GenieStandalone):
    ''' Perform LEAF Reload '''

    # Devices under test
    uut = 'BL'
    devices = ['BL']

    # Type of verifications and Triggers to performed
    verifications = ['Verify_InterfaceBrief']
    triggers = ['TriggerReloadTor', 'TriggerSleep']

    # Order of the Trigger and Verifications
    order = ['copy_r_s', 'TriggerReloadTor', 'TriggerSleep']
    
    # Mandatory Params
    timeout = {'interval':20, 'max_time':600}

    # Custom Params
    custom_arguments = {
        'TriggerReloadTor': {
            'timeout':{'interval':50, 'max_time':2000}
        }
    }

    # This is how to create a setup section
    @ aetest.test
    def copy_r_s(self, testscript):
        """ Perform Copy R S """
        log.info('Perform copy r s of the devices')
        testscript.parameters['BL'].configure("copy r s", timeout=1200)

# *****************************************************************************************************************************#
class POST_ISSU_POST_TOR_RELOAD_VERIFY_PVNF(aetest.Testcase):
    """VERIFY_PVNF_LEAF_RELOAD"""

    # =============================================================================================================================#
    @aetest.test
    def SLEEP_POST_BL_RELOAD(self, testscript):
        """ Sleep after device reload """
        time.sleep(240)

    # =============================================================================================================================#
    @aetest.test
    def verify_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['leavesDict'])

        if nvePeerData['result'] == 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("WARNING : Failed to verify NVE Peering\n\n")
            self.passx(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify VNI States """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['forwardingSysDict'],testscript.parameters['leavesDict'])

        if nveVniData['result'] == 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_common_loopback_topology(BL, PGW, testscript.parameters['topo_1_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY(self, testscript):
        """ VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_loopback_topology(BL, PGW,testscript.parameters['topo_2_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_PHYSICAL_VM_TOPOLOGY(self, testscript):
        """ VERIFY_PHYSICAL_VM_TOPOLOGY """

        BL = testscript.parameters['BL']
        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BL, PGW,testscript.parameters['topo_3_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def APPLY_TRAFFIC(self):
        """ IXIA_CONFIGURATION subsection: Apply IXIA Traffic """

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

            if ixLib.verify_traffic(2,2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

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
