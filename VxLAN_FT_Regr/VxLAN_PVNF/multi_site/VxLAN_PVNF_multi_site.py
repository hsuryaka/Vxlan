#!/usr/bin/env python

###################################################################
###                  Importing Libraries                        ###
###################################################################
import logging
import time

import texttable
import random
import re
import string
import yaml
import pprint
from yaml import Loader
from pyats import aetest
from pyats.log.utils import banner
import ipaddress as ip

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

# ------------------------------------------------------
# Import and initialize PVNF specific libraries
# ------------------------------------------------------
import vxlanEVPN_PVNF_lib

pvnfConfig = vxlanEVPN_PVNF_lib.configureVxlanEvpnPVNF()
pvnfVerify = vxlanEVPN_PVNF_lib.verifyVxlanEvpnPVNF()

###################################################################
###                  GLOBAL VARIABLES                           ###
###################################################################
device_list = []
dc1_device_list = []
dc1_leaf_list = []
dc2_device_list = []
dc2_leaf_list = []


###################################################################
###                  GLOBAL Methods                             ###
###################################################################

###################################################################
###                  COMMON SETUP SECTION                       ###
###################################################################
class COMMON_SETUP(aetest.CommonSetup):
    """ Common Setup """

    # *****************************************************************************************************************************#
    @aetest.subsection
    def topology_used_for_suite(self):
        """ common setup subsection: Represent Topology """

        # Set topology to be used
        topology = """
                                                DC-1                                                                            DC-2
                                                ----                                                                            ----

                                            +-------------+                                                               +-------------+
                                            |    BGW-1    |---------------------------------------------------------------|    BGW-2    |
                                            +-------------+                                                               +-------------+
                                                   |                                                                             |
                                                   |                                                                             |
                                                   |                                                                             |
                                            +-------------+                                                               +-------------+
                                            |    SPINE    |                                                               |    SPINE    |
                                            +-------------+                                                               +-------------+
                                            |             |                                                               |             |    
                                            |             |                                                               |             |
                                            |             |                                                               |             |
                                            |             |                                                               |             |
                                +-----------+             +-----------+                                       +-----------+             +-----------+
                         IXIA---|   LEAF-1  |             |   LEAF-2  |                                       |   LEAF-1  |             |   LEAF-2  |---IXIA
                                +-----------+             +-----------+                                       +-----------+             +-----------+
                                      |                         |                                                   |                         |
                                      |                         |                                                   |                         |
                                      |                         |                                                   |                         |
                                      |                         |                                                   |                         |
                                +-------------------------------------------------------------------------------------------------------------------+
                                |                                                       PGW                                                         |
                                +-------------------------------------------------------------------------------------------------------------------+
                                                                                         |
                                                                                         |
                                                                                        IXIA     
        """

        log.info("Topology to be used is")
        log.info(topology)

    # *****************************************************************************************************************************#
    @aetest.subsection
    def connecting_to_devices(self, testscript, testbed, uut_list, configurationFile, script_flags=None):
        """ common setup subsection: Connecting to devices """

        # =============================================================================================================================#
        # Grab the device object of the uut device with that name
        if script_flags is None:
            script_flags = {}

        DC_1_SPINE = testscript.parameters['DC_1_SPINE'] = testbed.devices[uut_list['DC_1_SPINE']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1'] = testbed.devices[uut_list['DC_1_LEAF-1']]
        DC_1_LEAF_2 = testscript.parameters['DC_1_LEAF-2'] = testbed.devices[uut_list['DC_1_LEAF-2']]
        DC_1_BGW = testscript.parameters['DC_1_BGW'] = testbed.devices[uut_list['DC_1_BGW']]

        DC_2_SPINE = testscript.parameters['DC_2_SPINE'] = testbed.devices[uut_list['DC_2_SPINE']]
        DC_2_LEAF_1 = testscript.parameters['DC_2_LEAF-1'] = testbed.devices[uut_list['DC_2_LEAF-1']]
        DC_2_LEAF_2 = testscript.parameters['DC_2_LEAF-2'] = testbed.devices[uut_list['DC_2_LEAF-2']]
        DC_2_BGW = testscript.parameters['DC_2_BGW'] = testbed.devices[uut_list['DC_2_BGW']]

        PGW = testscript.parameters['PGW'] = testbed.devices[uut_list['PGW']]
        IXIA = testscript.parameters['IXIA'] = testbed.devices[uut_list['ixia']]

        testscript.parameters['ixia_chassis_ip'] = str(IXIA.connections.a.ip)
        testscript.parameters['ixia_tcl_server'] = str(IXIA.connections.alt.ip)
        testscript.parameters['ixia_tcl_port'] = str(IXIA.connections.alt.port)

        # =============================================================================================================================#
        # Connect to the device
        DC_1_SPINE.connect()
        DC_1_LEAF_1.connect()
        DC_1_LEAF_2.connect()
        DC_1_BGW.connect()
        DC_2_SPINE.connect()
        DC_2_LEAF_1.connect()
        DC_2_LEAF_2.connect()
        DC_2_BGW.connect()

        PGW.connect()

        #device_list.append(DC_1_SPINE)
        device_list.append(DC_1_LEAF_1)
        device_list.append(DC_1_LEAF_2)
        device_list.append(DC_1_BGW)

        #dc1_device_list.append(DC_1_SPINE)
        dc1_device_list.append(DC_1_LEAF_1)
        dc1_device_list.append(DC_1_LEAF_2)
        dc1_device_list.append(DC_1_BGW)

        dc1_leaf_list.append(DC_1_LEAF_1)
        dc1_leaf_list.append(DC_1_LEAF_2)

        #device_list.append(DC_2_SPINE)
        device_list.append(DC_2_LEAF_1)
        device_list.append(DC_2_LEAF_2)
        device_list.append(DC_2_BGW)

        #dc2_device_list.append(DC_2_SPINE)
        dc2_device_list.append(DC_2_LEAF_1)
        dc2_device_list.append(DC_2_LEAF_2)
        dc2_device_list.append(DC_2_BGW)

        dc2_leaf_list.append(DC_2_LEAF_1)
        dc2_leaf_list.append(DC_2_LEAF_2)

        device_list.append(PGW)

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
        testscript.parameters['configurationFile'] = configurationFile

        with open(configurationFile) as cfgFile:
            configuration = yaml.load(cfgFile, Loader=Loader)

        # ----- Get the Device Dict information from configuration file
        testscript.parameters['DC_1_FWD_SYS_dict'] = configuration['DC_1_FWD_SYS_dict']
        testscript.parameters['DC_1_LEAF_1_dict'] = configuration['DC_1_LEAF_1_dict']
        testscript.parameters['DC_1_LEAF_2_dict'] = configuration['DC_1_LEAF_2_dict']
        testscript.parameters['DC_1_BGW_dict'] = configuration['DC_1_BGW_dict']

        testscript.parameters['DC_2_FWD_SYS_dict'] = configuration['DC_2_FWD_SYS_dict']
        testscript.parameters['DC_2_LEAF_1_dict'] = configuration['DC_2_LEAF_1_dict']
        testscript.parameters['DC_2_LEAF_2_dict'] = configuration['DC_2_LEAF_2_dict']
        testscript.parameters['DC_2_BGW_dict'] = configuration['DC_2_BGW_dict']

        # ----- Get the TGEN Dict information from configuration file
        testscript.parameters['PGW_TGEN_data'] = configuration['PGW_TGEN_data']
        testscript.parameters['DC_1_LEAF_1_TGEN_data'] = configuration['DC_1_LEAF_1_TGEN_data']
        testscript.parameters['DC_2_LEAF_2_TGEN_data'] = configuration['DC_2_LEAF_2_TGEN_data']

        # ----- Declare few script needed variables
        testscript.parameters['DC_1_leavesDictList'] = [configuration['DC_1_LEAF_1_dict'],
                                                        configuration['DC_1_LEAF_2_dict'],
                                                        configuration['DC_1_BGW_dict']]

        testscript.parameters['DC_2_leavesDictList'] = [configuration['DC_2_LEAF_1_dict'],
                                                        configuration['DC_2_LEAF_2_dict'],
                                                        configuration['DC_2_BGW_dict']]

        testscript.parameters['DC_1_leavesDict'] = {DC_1_LEAF_1: configuration['DC_1_LEAF_1_dict'],
                                                    DC_1_LEAF_2: configuration['DC_1_LEAF_2_dict'],
                                                    DC_1_BGW: configuration['DC_1_BGW_dict']}

        testscript.parameters['DC_2_leavesDict'] = {DC_2_LEAF_1: configuration['DC_2_LEAF_1_dict'],
                                                    DC_2_LEAF_2: configuration['DC_2_LEAF_2_dict'],
                                                    DC_2_BGW: configuration['DC_2_BGW_dict']}

        testscript.parameters['DC_1_VTEP_List'] = [testscript.parameters['DC_1_LEAF_1_dict'],
                                                   testscript.parameters['DC_1_LEAF_2_dict'],
                                                   testscript.parameters['DC_1_BGW_dict']]

        testscript.parameters['DC_2_VTEP_List'] = [testscript.parameters['DC_2_LEAF_1_dict'],
                                                   testscript.parameters['DC_2_LEAF_2_dict'],
                                                   testscript.parameters['DC_2_BGW_dict']]

    # *****************************************************************************************************************************#
    @aetest.subsection
    def get_interfaces(self, testscript):
        """ common setup subsection: Getting required Connections for Test """

        DC_1_SPINE = testscript.parameters['DC_1_SPINE']
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        DC_1_LEAF_2 = testscript.parameters['DC_1_LEAF-2']
        DC_1_BGW = testscript.parameters['DC_1_BGW']

        DC_2_SPINE = testscript.parameters['DC_2_SPINE']
        DC_2_LEAF_1 = testscript.parameters['DC_2_LEAF-1']
        DC_2_LEAF_2 = testscript.parameters['DC_2_LEAF-2']
        DC_2_BGW = testscript.parameters['DC_2_BGW']

        PGW = testscript.parameters['PGW']
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
        testscript.parameters['intf_DC1_SPINE_to_LEAF_1'] = DC_1_SPINE.interfaces['SPINE_to_LEAF-1'].intf
        testscript.parameters['intf_DC1_SPINE_to_LEAF_2'] = DC_1_SPINE.interfaces['SPINE_to_LEAF-2'].intf
        testscript.parameters['intf_DC1_SPINE_to_BGW'] = DC_1_SPINE.interfaces['SPINE_to_BGW'].intf

        testscript.parameters['intf_DC2_SPINE_to_LEAF_1'] = DC_2_SPINE.interfaces['SPINE_to_LEAF-1'].intf
        testscript.parameters['intf_DC2_SPINE_to_LEAF_2'] = DC_2_SPINE.interfaces['SPINE_to_LEAF-2'].intf
        testscript.parameters['intf_DC2_SPINE_to_BGW'] = DC_2_SPINE.interfaces['SPINE_to_BGW'].intf

        testscript.parameters['intf_DC1_LEAF_1_to_SPINE'] = DC_1_LEAF_1.interfaces['LEAF-1_to_SPINE'].intf
        testscript.parameters['intf_DC1_LEAF_1_to_PGW_1'] = DC_1_LEAF_1.interfaces['LEAF-1_to_PGW_1'].intf
        testscript.parameters['intf_DC1_LEAF_1_to_PGW_2'] = DC_1_LEAF_1.interfaces['LEAF-1_to_PGW_2'].intf
        testscript.parameters['intf_DC1_LEAF_1_to_IXIA'] = DC_1_LEAF_1.interfaces['LEAF-1_to_IXIA'].intf

        testscript.parameters['intf_DC2_LEAF_1_to_SPINE'] = DC_2_LEAF_1.interfaces['LEAF-1_to_SPINE'].intf
        testscript.parameters['intf_DC2_LEAF_1_to_PGW_1'] = DC_2_LEAF_1.interfaces['LEAF-1_to_PGW_1'].intf
        testscript.parameters['intf_DC2_LEAF_1_to_PGW_2'] = DC_2_LEAF_1.interfaces['LEAF-1_to_PGW_2'].intf

        testscript.parameters['intf_DC1_LEAF_2_to_SPINE'] = DC_1_LEAF_2.interfaces['LEAF-2_to_SPINE'].intf
        testscript.parameters['intf_DC1_LEAF_2_to_PGW_1'] = DC_1_LEAF_2.interfaces['LEAF-2_to_PGW_1'].intf
        testscript.parameters['intf_DC1_LEAF_2_to_PGW_2'] = DC_1_LEAF_2.interfaces['LEAF-2_to_PGW_2'].intf

        testscript.parameters['intf_DC2_LEAF_2_to_SPINE'] = DC_2_LEAF_2.interfaces['LEAF-2_to_SPINE'].intf
        testscript.parameters['intf_DC2_LEAF_2_to_PGW_1'] = DC_2_LEAF_2.interfaces['LEAF-2_to_PGW_1'].intf
        testscript.parameters['intf_DC2_LEAF_2_to_PGW_2'] = DC_2_LEAF_2.interfaces['LEAF-2_to_PGW_2'].intf
        testscript.parameters['intf_DC2_LEAF_2_to_IXIA'] = DC_2_LEAF_2.interfaces['LEAF-2_to_IXIA'].intf

        testscript.parameters['intf_DC1_BGW_to_SPINE'] = DC_1_BGW.interfaces['BGW_to_SPINE'].intf
        testscript.parameters['intf_DC1_BGW_1_to_BGW_2'] = DC_1_BGW.interfaces['BGW_1_to_BGW_2'].intf

        testscript.parameters['intf_DC2_BGW_to_SPINE'] = DC_2_BGW.interfaces['BGW_to_SPINE'].intf
        testscript.parameters['intf_DC2_BGW_2_to_BGW_1'] = DC_2_BGW.interfaces['BGW_2_to_BGW_1'].intf

        testscript.parameters['intf_PGW_to_DC1_LEAF_1_1'] = PGW.interfaces['PGW_to_DC_1_LEAF-1_1'].intf
        testscript.parameters['intf_PGW_to_DC1_LEAF_1_2'] = PGW.interfaces['PGW_to_DC_1_LEAF-1_2'].intf
        testscript.parameters['intf_PGW_to_DC1_LEAF_2_1'] = PGW.interfaces['PGW_to_DC_1_LEAF-2_1'].intf
        testscript.parameters['intf_PGW_to_DC1_LEAF_2_2'] = PGW.interfaces['PGW_to_DC_1_LEAF-2_2'].intf

        testscript.parameters['intf_PGW_to_DC2_LEAF_1_1'] = PGW.interfaces['PGW_to_DC_2_LEAF-1_1'].intf
        testscript.parameters['intf_PGW_to_DC2_LEAF_1_2'] = PGW.interfaces['PGW_to_DC_2_LEAF-1_2'].intf
        testscript.parameters['intf_PGW_to_DC2_LEAF_2_1'] = PGW.interfaces['PGW_to_DC_2_LEAF-2_1'].intf
        testscript.parameters['intf_PGW_to_DC2_LEAF_2_2'] = PGW.interfaces['PGW_to_DC_2_LEAF-2_2'].intf

        testscript.parameters['intf_PGW_to_IXIA'] = PGW.interfaces['PGW_to_IXIA'].intf

        testscript.parameters['intf_IXIA_to_PGW'] = IXIA.interfaces['IXIA_to_PGW'].intf
        testscript.parameters['intf_IXIA_to_DC1_LEAF_1'] = IXIA.interfaces['IXIA_to_DC_1_LEAF-1'].intf
        testscript.parameters['intf_IXIA_to_DC2_LEAF_2'] = IXIA.interfaces['IXIA_to_DC_2_LEAF-2'].intf

        testscript.parameters['ixia_int_list'] = str(testscript.parameters['intf_IXIA_to_PGW']) + " " + str(
            testscript.parameters['intf_IXIA_to_DC1_LEAF_1']) \
                                                 + " " + str(testscript.parameters['intf_IXIA_to_DC2_LEAF_2'])

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
        """ common setup subsection: Getting required Connections for Test """

        # =============================================================================================================================#
        # Import Configuration File and create required Structures
        configurationFile = testscript.parameters['configurationFile']
        with open(configurationFile) as cfgFile:
            configuration = yaml.load(cfgFile, Loader=Loader)

        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        DC_1_LEAF_2 = testscript.parameters['DC_1_LEAF-2']
        DC_2_LEAF_1 = testscript.parameters['DC_2_LEAF-1']
        DC_2_LEAF_2 = testscript.parameters['DC_2_LEAF-2']

        testscript.parameters['topo_1_vnf_leaves_dict'] = {}
        testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1] = {}
        testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_2] = {}
        testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_1] = {}
        testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_2] = {}
        testscript.parameters['topo_2_vnf_leaves_dict'] = {}
        testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_1] = {}
        testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_2] = {}
        testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_1] = {}
        testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_2] = {}
        testscript.parameters['topo_3_vnf_leaves_dict'] = {}
        testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_1] = {}
        testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_2] = {}
        testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_1] = {}
        testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_2] = {}

        DC_1_FWD_SYS_dict = testscript.parameters['DC_1_FWD_SYS_dict']
        DC_2_FWD_SYS_dict = testscript.parameters['DC_2_FWD_SYS_dict']

        # ----- Declare few script needed variables for PVNF Topology
        testscript.parameters['PVNF_dict'] = {DC_1_LEAF_1: configuration['DC_1_LEAF_1_dict']['PVNF_data'],
                                              DC_1_LEAF_2: configuration['DC_1_LEAF_2_dict']['PVNF_data'],
                                              DC_2_LEAF_1: configuration['DC_2_LEAF_1_dict']['PVNF_data'],
                                              DC_2_LEAF_2: configuration['DC_2_LEAF_2_dict']['PVNF_data'], }

        testscript.parameters['SPINE_PVNF_rtmap_name'] = 'SPINE_passall'
        testscript.parameters['BL_PVNF_rtmap_name'] = 'BL_passall'
        testscript.parameters['LEAF_stop_external_PVNF_rtmap_name'] = 'LEAF_STOP_EXTERNAL'
        testscript.parameters['LEAF_stop_external_PVNF_prfx_name'] = 'LEAF_STOP_EXTERNAL'

        # ===================================================
        # --- Check if topo_1 is present and add accordingly
        # ===================================================

        # ------- Adding topology type
        testscript.parameters['topo_1_vnf_leaves_dict']['type'] = 'topo_1'
        # ------- Adding VRF ID to be used
        testscript.parameters['topo_1_vnf_leaves_dict']['vrf'] = configuration['DC_1_FWD_SYS_dict']['VRF_string'] + str(
            configuration['DC_1_FWD_SYS_dict']['VRF_id_start'])
        # ------- Adding BGP Prefixes
        testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts'] = 200
        testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes'] = '150.1.1.5'
        testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes'] = '2001:150:1:1::5'

        # ------- If topo_1 is in DC-1 LEAF_1
        if "topo_1" in configuration['DC_1_LEAF_1_dict']['PVNF_data'].keys():
            # ------- Adding PVNF_data dict
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1] = \
                configuration['DC_1_LEAF_1_dict']['PVNF_data']['topo_1']
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['EW_LEAF_SRC'] = '1'
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['leaf_as'] = DC_1_FWD_SYS_dict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['PGW_LEAF_int'] = testscript.parameters[
                'intf_PGW_to_DC1_LEAF_1_1']
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['LEAF_PGW_int'] = testscript.parameters[
                'intf_DC1_LEAF_1_to_PGW_1']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        # ------- If topo_1 is in DC-1 LEAF_2
        if "topo_1" in configuration['DC_1_LEAF_2_dict']['PVNF_data'].keys():
            # ------- Adding PVNF_data dict
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_2] = \
                configuration['DC_1_LEAF_2_dict']['PVNF_data']['topo_1']
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_2]['leaf_as'] = DC_1_FWD_SYS_dict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_2]['PGW_LEAF_int'] = testscript.parameters[
                'intf_PGW_to_DC1_LEAF_2_1']
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_2]['LEAF_PGW_int'] = testscript.parameters[
                'intf_DC1_LEAF_2_to_PGW_1']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_2]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_2]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_2]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_2]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_2]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_2]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        # ------- If topo_1 is in DC-2 LEAF_1
        if "topo_1" in configuration['DC_2_LEAF_1_dict']['PVNF_data'].keys():
            # ------- Adding PVNF_data dict
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_1] = \
                configuration['DC_2_LEAF_1_dict']['PVNF_data']['topo_1']
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_1]['leaf_as'] = DC_2_FWD_SYS_dict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_1]['PGW_LEAF_int'] = testscript.parameters[
                'intf_PGW_to_DC2_LEAF_1_1']
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_1]['LEAF_PGW_int'] = testscript.parameters[
                'intf_DC2_LEAF_1_to_PGW_1']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_1]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_1]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_1]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_1]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_1]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_1]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        # ------- If topo_1 is in DC-2 LEAF_2
        if "topo_1" in configuration['DC_2_LEAF_2_dict']['PVNF_data'].keys():
            # ------- Adding PVNF_data dict
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_2] = \
                configuration['DC_2_LEAF_2_dict']['PVNF_data']['topo_1']
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_2]['EW_LEAF_SRC'] = '1'
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_2]['leaf_as'] = DC_2_FWD_SYS_dict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_2]['PGW_LEAF_int'] = testscript.parameters[
                'intf_PGW_to_DC2_LEAF_2_1']
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_2]['LEAF_PGW_int'] = testscript.parameters[
                'intf_DC2_LEAF_2_to_PGW_1']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_2]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_2]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_2]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_2]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_2]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_2]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        configuration['DC_1_FWD_SYS_dict']['VRF_id_start'] += 1
        log.info(banner('TOPO-1 Dict'))
        log.info(pprint.pformat(testscript.parameters['topo_1_vnf_leaves_dict'], indent=2))

        # ===================================================
        # --- Check if topo_2 is present and add accordingly
        # ===================================================

        # ------- Adding topology type
        testscript.parameters['topo_2_vnf_leaves_dict']['type'] = 'topo_2'
        # ------- Adding VRF ID to be used
        testscript.parameters['topo_2_vnf_leaves_dict']['vrf'] = configuration['DC_1_FWD_SYS_dict']['VRF_string'] + str(
            configuration['DC_1_FWD_SYS_dict']['VRF_id_start'])
        # ------- Adding BGP Prefixes
        testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts'] = 200
        testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes'] = '160.1.1.5'
        testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes'] = '2001:160:1:1::5'

        # ------- If topo_2 is in DC-1 LEAF_1
        if "topo_2" in configuration['DC_1_LEAF_1_dict']['PVNF_data'].keys():
            # ------- Adding PVNF_data dict
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_1] = \
                configuration['DC_1_LEAF_1_dict']['PVNF_data']['topo_2']
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_1]['EW_LEAF_SRC'] = '1'
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_1]['leaf_as'] = DC_1_FWD_SYS_dict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_1]['PGW_LEAF_int'] = testscript.parameters[
                'intf_PGW_to_DC1_LEAF_1_1']
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_1]['LEAF_PGW_int'] = testscript.parameters[
                'intf_DC1_LEAF_1_to_PGW_1']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_1]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_1]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_1]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_1]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_1]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_1]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        # ------- If topo_2 is in DC-1 LEAF_2
        if "topo_2" in configuration['DC_1_LEAF_2_dict']['PVNF_data'].keys():
            # ------- Adding PVNF_data dict
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_2] = \
                configuration['DC_1_LEAF_2_dict']['PVNF_data']['topo_2']
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_2]['leaf_as'] = DC_1_FWD_SYS_dict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_2]['PGW_LEAF_int'] = testscript.parameters[
                'intf_PGW_to_DC1_LEAF_2_1']
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_2]['LEAF_PGW_int'] = testscript.parameters[
                'intf_DC1_LEAF_2_to_PGW_1']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_2]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_2]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_2]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_2]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_2]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_1_LEAF_2]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        # ------- If topo_2 is in DC-2 LEAF_1
        if "topo_2" in configuration['DC_2_LEAF_1_dict']['PVNF_data'].keys():
            # ------- Adding PVNF_data dict
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_1] = \
                configuration['DC_2_LEAF_1_dict']['PVNF_data']['topo_2']
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_1]['leaf_as'] = DC_2_FWD_SYS_dict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_1]['PGW_LEAF_int'] = testscript.parameters[
                'intf_PGW_to_DC2_LEAF_1_1']
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_1]['LEAF_PGW_int'] = testscript.parameters[
                'intf_DC2_LEAF_1_to_PGW_1']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_1]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_1]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_1]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_1]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_1]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_1]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        # ------- If topo_2 is in DC-2 LEAF_2
        if "topo_2" in configuration['DC_2_LEAF_2_dict']['PVNF_data'].keys():
            # ------- Adding PVNF_data dict
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_2] = \
                configuration['DC_2_LEAF_2_dict']['PVNF_data']['topo_2']
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_2]['EW_LEAF_SRC'] = '1'
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_2]['leaf_as'] = DC_2_FWD_SYS_dict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_2]['PGW_LEAF_int'] = testscript.parameters[
                'intf_PGW_to_DC2_LEAF_2_1']
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_2]['LEAF_PGW_int'] = testscript.parameters[
                'intf_DC2_LEAF_2_to_PGW_1']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_2]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_2]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_2]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_2]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_2]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_2_vnf_leaves_dict'][DC_2_LEAF_2]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        configuration['DC_1_FWD_SYS_dict']['VRF_id_start'] += 1
        log.info(banner('TOPO-2 Dict'))
        log.info(pprint.pformat(testscript.parameters['topo_2_vnf_leaves_dict'], indent=2))

        # ===================================================
        # --- Check if topo_3 is present and add accordingly
        # ===================================================

        # ------- Adding topology type
        testscript.parameters['topo_3_vnf_leaves_dict']['type'] = 'topo_3'
        # ------- Adding VRF ID to be used
        testscript.parameters['topo_3_vnf_leaves_dict']['vrf'] = configuration['DC_1_FWD_SYS_dict']['VRF_string'] + str(
            configuration['DC_1_FWD_SYS_dict']['VRF_id_start'])
        # ------- Adding BGP Prefixes
        testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts'] = 200
        testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes'] = '170.1.1.5'
        testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes'] = '2001:170:1:1::5'

        # ------- If topo_3 is in DC-1 LEAF_1
        if "topo_3" in configuration['DC_1_LEAF_1_dict']['PVNF_data'].keys():
            # ------- Adding PVNF_data dict
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_1] = \
                configuration['DC_1_LEAF_1_dict']['PVNF_data']['topo_3']
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_1]['EW_LEAF_SRC'] = '1'
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_1]['leaf_as'] = DC_1_FWD_SYS_dict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_1]['PGW_LEAF_int'] = testscript.parameters[
                'intf_PGW_to_DC1_LEAF_1_2']
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_1]['LEAF_PGW_int'] = testscript.parameters[
                'intf_DC1_LEAF_1_to_PGW_2']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_1]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_1]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_1]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_1]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_1]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_1]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        # ------- If topo_3 is in DC-1 LEAF_2
        if "topo_3" in configuration['DC_1_LEAF_2_dict']['PVNF_data'].keys():
            # ------- Adding PVNF_data dict
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_2] = \
                configuration['DC_1_LEAF_2_dict']['PVNF_data']['topo_3']
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_2]['leaf_as'] = DC_1_FWD_SYS_dict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_2]['PGW_LEAF_int'] = testscript.parameters[
                'intf_PGW_to_DC1_LEAF_2_2']
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_2]['LEAF_PGW_int'] = testscript.parameters[
                'intf_DC1_LEAF_2_to_PGW_2']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_2]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_2]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_2]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_2]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_2]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_1_LEAF_2]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        # ------- If topo_3 is in DC-2 LEAF_1
        if "topo_3" in configuration['DC_2_LEAF_1_dict']['PVNF_data'].keys():
            # ------- Adding PVNF_data dict
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_1] = \
                configuration['DC_2_LEAF_1_dict']['PVNF_data']['topo_3']
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_1]['leaf_as'] = DC_2_FWD_SYS_dict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_1]['PGW_LEAF_int'] = testscript.parameters[
                'intf_PGW_to_DC2_LEAF_1_2']
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_1]['LEAF_PGW_int'] = testscript.parameters[
                'intf_DC2_LEAF_1_to_PGW_2']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_1]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_1]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_1]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_1]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_1]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_1]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        # ------- If topo_3 is in DC-2 LEAF_2
        if "topo_3" in configuration['DC_2_LEAF_2_dict']['PVNF_data'].keys():
            # ------- Adding PVNF_data dict
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_2] = \
                configuration['DC_2_LEAF_2_dict']['PVNF_data']['topo_3']
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_2]['EW_LEAF_SRC'] = '1'
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_2]['leaf_as'] = DC_2_FWD_SYS_dict['BGP_AS_num']

            # ------- Adding Interfaces for each leaf
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_2]['PGW_LEAF_int'] = testscript.parameters[
                'intf_PGW_to_DC2_LEAF_2_2']
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_2]['LEAF_PGW_int'] = testscript.parameters[
                'intf_DC2_LEAF_2_to_PGW_2']

            # ------- Adding Prefix List and route-map names
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_2]['PGW_v4_prfx_lst_name'] = "PGW_allow_v4"
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_2]['PGW_v6_prfx_lst_name'] = "PGW_allow_v6"
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_2]['PGW_route_map_name'] = "PGW_prefixes"

            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_2]['LEAF_v4_prfx_lst_name'] = "VNF_LEAF_allow_v4"
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_2]['LEAF_v6_prfx_lst_name'] = "VNF_LEAF_allow_v6"
            testscript.parameters['topo_3_vnf_leaves_dict'][DC_2_LEAF_2]['LEAF_route_map_name'] = "LEAF_PGW_prefixes"

        configuration['DC_1_FWD_SYS_dict']['VRF_id_start'] += 1
        log.info(banner('TOPO-3 Dict'))
        log.info(pprint.pformat(testscript.parameters['topo_3_vnf_leaves_dict'], indent=2))

# *****************************************************************************************************************************#
class DC1_BASIC_EVPN_VxLAN_BRINGUP(aetest.Testcase):
    """BASE_EVPN_VxLAN_BRINGUP Test-Case"""

    # *****************************************************************************************************************************#
    @aetest.test
    def DC_1_enable_feature_set(self, testscript):
        """ Device Bring-up subsection: Configuring Features and Feature-sets """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            DC_1_leafLst = [testscript.parameters['DC_1_LEAF-1'], testscript.parameters['DC_1_LEAF-2'],
                            testscript.parameters['DC_1_BGW']]
            DC_1_spineFeatureList = ['ospf', 'bgp', 'pim', 'lacp', 'nv overlay']
            DC_1_LeafFeatureList = ['ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp',
                                    'nv overlay']
            DC_1_configFeatureSet_status = []
            DC_1_configFeatureSet_msgs = ""

            # --------------------------------
            # Configure Feature Set on Leafs
            featureSetConfigureLeafs_status = infraConfig.configureVerifyFeatureSet(DC_1_leafLst, ['mpls'])
            if featureSetConfigureLeafs_status['result']:
                log.info("Passed Configuring feature Sets on all Leafs")
            else:
                log.debug("Failed Configuring feature Sets on all Leafs")
                DC_1_configFeatureSet_msgs += featureSetConfigureLeafs_status['log']
                DC_1_configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Features on SPINE
            featureConfigureSpine_status = infraConfig.configureVerifyFeature(testscript.parameters['DC_1_SPINE'],
                                                                              DC_1_spineFeatureList)
            if featureConfigureSpine_status['result']:
                log.info("Passed Configuring features on DC-1-SPINE")
            else:
                log.debug("Failed configuring features on DC-1-SPINE")
                DC_1_configFeatureSet_msgs += featureConfigureSpine_status['log']
                DC_1_configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-1
            featureConfigureLeaf1_status = infraConfig.configureVerifyFeature(testscript.parameters['DC_1_LEAF-1'],
                                                                              DC_1_LeafFeatureList)
            if featureConfigureLeaf1_status['result']:
                log.info("Passed Configuring features on DC-1-LEAF-1")
            else:
                log.debug("Failed configuring features on DC-1-LEAF-1")
                DC_1_configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                DC_1_configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-2
            featureConfigureLeaf2_status = infraConfig.configureVerifyFeature(testscript.parameters['DC_1_LEAF-2'],
                                                                              DC_1_LeafFeatureList)
            if featureConfigureLeaf2_status['result']:
                log.info("Passed Configuring features on DC-1-LEAF-2")
            else:
                log.debug("Failed configuring features on DC-1-LEAF-2")
                DC_1_configFeatureSet_msgs += featureConfigureLeaf2_status['log']
                DC_1_configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-3
            featureConfigureLeaf3_status = infraConfig.configureVerifyFeature(testscript.parameters['DC_1_BGW'],
                                                                              DC_1_LeafFeatureList)
            if featureConfigureLeaf3_status['result']:
                log.info("Passed Configuring features on DC-1-LEAF-3")
            else:
                log.debug("Failed configuring features on DC-1-LEAF-3")
                DC_1_configFeatureSet_msgs += featureConfigureLeaf3_status['log']
                DC_1_configFeatureSet_status.append(0)

            if 0 in DC_1_configFeatureSet_status:
                self.failed(reason=DC_1_configFeatureSet_msgs, goto=['common_cleanup'])

        else:
            self.passed(reason="Skipped Device Configuration as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_DC1_SPINE(self, testscript):
        """ Device Bring-up subsection: Configuring SPINE """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNSpines([testscript.parameters['DC_1_SPINE']],
                                        testscript.parameters['DC_1_FWD_SYS_dict'],
                                        testscript.parameters['DC_1_leavesDictList'])

            try:
                testscript.parameters['DC_1_SPINE'].configure('''

                    interface ''' + str(testscript.parameters['intf_DC1_SPINE_to_LEAF_1']) + '''
                      channel-group ''' + str(testscript.parameters['DC_1_LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_DC1_SPINE_to_LEAF_2']) + '''
                      channel-group ''' + str(testscript.parameters['DC_1_LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_DC1_SPINE_to_BGW']) + '''
                      channel-group ''' + str(testscript.parameters['DC_1_BGW_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown

                ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.failed('Exception occurred while configuring on DC-1-SPINE', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_DC1_LEAF_1(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNLeaf(testscript.parameters['DC_1_LEAF-1'], testscript.parameters['DC_1_FWD_SYS_dict'],
                                      testscript.parameters['DC_1_LEAF_1_dict'])

            try:
                testscript.parameters['DC_1_LEAF-1'].configure('''

                    interface ''' + str(testscript.parameters['intf_DC1_LEAF_1_to_SPINE']) + '''
                      channel-group ''' + str(testscript.parameters['DC_1_LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_DC1_LEAF_1_to_PGW_1']) + '''
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_DC1_LEAF_1_to_PGW_2']) + '''
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_DC1_LEAF_1_to_IXIA']) + '''
                      no shutdown

              ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on DC-1-LEAF-1', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_DC1_LEAF_2(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-2 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNLeaf(testscript.parameters['DC_1_LEAF-2'], testscript.parameters['DC_1_FWD_SYS_dict'],
                                      testscript.parameters['DC_1_LEAF_2_dict'])

            try:
                testscript.parameters['DC_1_LEAF-2'].configure('''

                    interface ''' + str(testscript.parameters['intf_DC1_LEAF_2_to_SPINE']) + '''
                      channel-group ''' + str(testscript.parameters['DC_1_LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_DC1_LEAF_2_to_PGW_1']) + '''
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_DC1_LEAF_2_to_PGW_2']) + '''
                      no shutdown

              ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on DC-1-LEAF-2', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_DC1_BGW(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-3 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNLeaf(testscript.parameters['DC_1_BGW'], testscript.parameters['DC_1_FWD_SYS_dict'],
                                      testscript.parameters['DC_1_BGW_dict'])

            try:
                testscript.parameters['DC_1_BGW'].configure('''

                    interface ''' + str(testscript.parameters['intf_DC1_BGW_to_SPINE']) + '''
                      channel-group ''' + str(testscript.parameters['DC_1_BGW_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown

              ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on DC-1-BGW', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

# *****************************************************************************************************************************#
class DC2_BASIC_EVPN_VxLAN_BRINGUP(aetest.Testcase):
    """BASE_EVPN_VxLAN_BRINGUP Test-Case"""

    # *****************************************************************************************************************************#
    @aetest.test
    def DC_2_enable_feature_set(self, testscript):
        """ Device Bring-up subsection: Configuring Features and Feature-sets """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            DC_2_leafLst = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2'],
                            testscript.parameters['DC_2_BGW']]
            DC_2_spineFeatureList = ['ospf', 'bgp', 'pim', 'lacp', 'nv overlay']
            DC_2_LeafFeatureList = ['ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'lacp',
                                    'nv overlay']
            DC_2_configFeatureSet_status = []
            DC_2_configFeatureSet_msgs = ""

            # --------------------------------
            # Configure Feature Set on Leafs
            featureSetConfigureLeafs_status = infraConfig.configureVerifyFeatureSet(DC_2_leafLst, ['mpls'])
            if featureSetConfigureLeafs_status['result']:
                log.info("Passed Configuring feature Sets on all Leafs")
            else:
                log.debug("Failed Configuring feature Sets on all Leafs")
                DC_2_configFeatureSet_msgs += featureSetConfigureLeafs_status['log']
                DC_2_configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Features on SPINE
            featureConfigureSpine_status = infraConfig.configureVerifyFeature(testscript.parameters['DC_2_SPINE'],
                                                                              DC_2_spineFeatureList)
            if featureConfigureSpine_status['result']:
                log.info("Passed Configuring features on DC-2-SPINE")
            else:
                log.debug("Failed configuring features on DC-2-SPINE")
                DC_2_configFeatureSet_msgs += featureConfigureSpine_status['log']
                DC_2_configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-1
            featureConfigureLeaf1_status = infraConfig.configureVerifyFeature(testscript.parameters['DC_2_LEAF-1'],
                                                                              DC_2_LeafFeatureList)
            if featureConfigureLeaf1_status['result']:
                log.info("Passed Configuring features on DC-2-LEAF-1")
            else:
                log.debug("Failed configuring features on DC-2-LEAF-1")
                DC_2_configFeatureSet_msgs += featureConfigureLeaf1_status['log']
                DC_2_configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-2
            featureConfigureLeaf2_status = infraConfig.configureVerifyFeature(testscript.parameters['DC_2_LEAF-2'],
                                                                              DC_2_LeafFeatureList)
            if featureConfigureLeaf2_status['result']:
                log.info("Passed Configuring features on DC-2-LEAF-2")
            else:
                log.debug("Failed configuring features on DC-2-LEAF-2")
                DC_2_configFeatureSet_msgs += featureConfigureLeaf2_status['log']
                DC_2_configFeatureSet_status.append(0)

            # --------------------------------
            # Configure Feature-set on LEAF-3
            featureConfigureLeaf3_status = infraConfig.configureVerifyFeature(testscript.parameters['DC_2_BGW'],
                                                                              DC_2_LeafFeatureList)
            if featureConfigureLeaf3_status['result']:
                log.info("Passed Configuring features on DC-2-BGW")
            else:
                log.debug("Failed configuring features on DC-2-BGW")
                DC_2_configFeatureSet_msgs += featureConfigureLeaf3_status['log']
                DC_2_configFeatureSet_status.append(0)

            if 0 in DC_2_configFeatureSet_status:
                self.failed(reason=DC_2_configFeatureSet_msgs, goto=['common_cleanup'])

        else:
            self.passed(reason="Skipped Device Configuration as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_DC2_SPINE(self, testscript):
        """ Device Bring-up subsection: Configuring SPINE """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNSpines([testscript.parameters['DC_2_SPINE']],
                                        testscript.parameters['DC_2_FWD_SYS_dict'],
                                        testscript.parameters['DC_2_leavesDictList'])

            try:
                testscript.parameters['DC_2_SPINE'].configure('''

                    interface ''' + str(testscript.parameters['intf_DC2_SPINE_to_LEAF_1']) + '''
                      channel-group ''' + str(testscript.parameters['DC_2_LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_DC2_SPINE_to_LEAF_2']) + '''
                      channel-group ''' + str(testscript.parameters['DC_2_LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_DC2_SPINE_to_BGW']) + '''
                      channel-group ''' + str(testscript.parameters['DC_2_BGW_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown

                ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.failed('Exception occurred while configuring on DC-2-SPINE', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_DC2_LEAF_1(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-1 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNLeaf(testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_FWD_SYS_dict'],
                                      testscript.parameters['DC_2_LEAF_1_dict'])

            try:
                testscript.parameters['DC_2_LEAF-1'].configure('''

                    interface ''' + str(testscript.parameters['intf_DC2_LEAF_1_to_SPINE']) + '''
                      channel-group ''' + str(testscript.parameters['DC_2_LEAF_1_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_DC2_LEAF_1_to_PGW_1']) + '''
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_DC2_LEAF_1_to_PGW_2']) + '''
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_DC2_LEAF_2_to_IXIA']) + '''
                      no shutdown

              ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on DC-2-LEAF-1', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_DC2_LEAF_2(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-2 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNLeaf(testscript.parameters['DC_2_LEAF-2'], testscript.parameters['DC_2_FWD_SYS_dict'],
                                      testscript.parameters['DC_2_LEAF_2_dict'])

            try:
                testscript.parameters['DC_2_LEAF-2'].configure('''

                    interface ''' + str(testscript.parameters['intf_DC2_LEAF_2_to_SPINE']) + '''
                      channel-group ''' + str(testscript.parameters['DC_2_LEAF_2_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_DC2_LEAF_2_to_PGW_1']) + '''
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_DC2_LEAF_2_to_PGW_2']) + '''
                      no shutdown

              ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on DC-2-LEAF-2', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_DC2_BGW(self, testscript):
        """ Device Bring-up subsection: Configuring LEAF-3 """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            evpnLib.configureEVPNLeaf(testscript.parameters['DC_2_BGW'], testscript.parameters['DC_2_FWD_SYS_dict'],
                                      testscript.parameters['DC_2_BGW_dict'])

            try:
                testscript.parameters['DC_2_BGW'].configure('''

                    interface ''' + str(testscript.parameters['intf_DC2_BGW_to_SPINE']) + '''
                      channel-group ''' + str(testscript.parameters['DC_2_BGW_dict']['SPINE_1_UPLINK_PO']['po_id']) + ''' force mode active
                      no shutdown

              ''')
            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on DC-2-BGW', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

# *****************************************************************************************************************************#
class Multi_Site_common_Devices_BRINGUP(aetest.Testcase):
    """BASE_EVPN_VxLAN_BRINGUP Test-Case"""

    # *****************************************************************************************************************************#
    @aetest.test
    def DC_common_devices_enable_feature_set(self, testscript):
        """ Device Bring-up subsection: Configuring Features and Feature-sets """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            DC_1_PGWFeatureList = ['ospf', 'bgp', 'pim', 'interface-vlan', 'lacp', 'nv overlay']
            DC_BGWFeatureList = ['ospf', 'bgp', 'pim', 'interface-vlan', 'vn-segment-vlan-based', 'fabric forwarding',
                                 'nv overlay']
            DC_1_configFeatureSet_status = []
            DC_1_configFeatureSet_msgs = ""

            # --------------------------------
            # Configure Feature-set on PGW
            featureSetConfigurePGW_status = infraConfig.configureVerifyFeatureSet(testscript.parameters['PGW'],
                                                                                  ['mpls'])
            if featureSetConfigurePGW_status['result']:
                log.info("Passed Configuring feature-sets on PGW")
            else:
                log.debug("Failed configuring feature-sets on PGW")
                DC_1_configFeatureSet_msgs += featureSetConfigurePGW_status['log']
                DC_1_configFeatureSet_status.append(0)

            featureConfigurePGW_status = infraConfig.configureVerifyFeature(testscript.parameters['PGW'],
                                                                            DC_1_PGWFeatureList)
            if featureConfigurePGW_status['result']:
                log.info("Passed Configuring features on PGW")
            else:
                log.debug("Failed configuring features on PGW")
                DC_1_configFeatureSet_msgs += featureConfigurePGW_status['log']
                DC_1_configFeatureSet_status.append(0)

            featureConfigureBGW_1_status = infraConfig.configureVerifyFeature(testscript.parameters['DC_1_BGW'],
                                                                              DC_BGWFeatureList)
            if featureConfigureBGW_1_status['result']:
                log.info("Passed Configuring features on PGW")
            else:
                log.debug("Failed configuring features on PGW")
                DC_1_configFeatureSet_msgs += featureConfigureBGW_1_status['log']
                DC_1_configFeatureSet_status.append(0)

            featureConfigureBGW_2_status = infraConfig.configureVerifyFeature(testscript.parameters['DC_2_BGW'],
                                                                              DC_BGWFeatureList)
            if featureConfigureBGW_2_status['result']:
                log.info("Passed Configuring features on PGW")
            else:
                log.debug("Failed configuring features on PGW")
                DC_1_configFeatureSet_msgs += featureConfigureBGW_2_status['log']
                DC_1_configFeatureSet_status.append(0)

            if 0 in DC_1_configFeatureSet_status:
                self.failed(reason=DC_1_configFeatureSet_msgs, goto=['common_cleanup'])

        else:
            self.passed(reason="Skipped Device Configuration as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_PGW(self, testscript):
        """ Device Bring-up subsection: Configuring PGW """

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:

            try:
                testscript.parameters['PGW'].configure('''
                    interface ''' + str(testscript.parameters['intf_PGW_to_DC1_LEAF_1_1']) + '''
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_PGW_to_DC1_LEAF_1_2']) + '''
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_PGW_to_DC1_LEAF_2_1']) + '''
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_PGW_to_DC1_LEAF_2_2']) + '''
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_PGW_to_DC2_LEAF_1_1']) + '''
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_PGW_to_DC2_LEAF_1_2']) + '''
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_PGW_to_DC2_LEAF_2_1']) + '''
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_PGW_to_DC2_LEAF_2_2']) + '''
                      no shutdown

                    interface ''' + str(testscript.parameters['intf_PGW_to_IXIA']) + '''
                      no shutdown
                ''')

            except Exception as error:
                log.debug("Unable to configure - Encountered Exception " + str(error))
                self.errored('Exception occurred while configuring on PGW', goto=['common_cleanup'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # *****************************************************************************************************************************#
    @aetest.test
    def configure_BGWs(self, testscript):
        """ Device Bring-up subsection: Configuring Features and Feature-sets """

        BGW_1 = testscript.parameters['DC_1_BGW']
        BGW_2 = testscript.parameters['DC_2_BGW']

        BGW_1_dict = testscript.parameters['DC_1_BGW_dict']
        BGW_2_dict = testscript.parameters['DC_2_BGW_dict']

        topologies = [testscript.parameters['topo_1_vnf_leaves_dict'],
                      testscript.parameters['topo_2_vnf_leaves_dict'],
                      testscript.parameters['topo_3_vnf_leaves_dict']]

        # --- Configure MSite BGW Loopbacks
        BGW_1.configure('''

            evpn multisite border-gateway 100
                delay-restore time 300

            interface ''' + str(BGW_1_dict['NVE_data']['msite_bgw_loop']) + '''
                ip address ''' + str(BGW_1_dict['NVE_data']['msite_bgw_loop_ip']) + '''/32 tag 54321
                ip router ospf ''' + str(testscript.parameters['DC_1_FWD_SYS_dict']['OSPF_AS']) + ''' are 0
                no shut

            interface loopback0
                no ip address
                ip address ''' + str(BGW_1_dict['loop0_ip']) + '''/32 tag 54321
                no shut

            interface ''' + str(BGW_1_dict['NVE_data']['src_loop']) + '''
                no ip address
                ip address ''' + str(BGW_1_dict['NVE_data']['VTEP_IP']) + '''/32 tag 54321
                no shut

            interface nve 1
                shut
                multisite border-gateway interface ''' + str(BGW_1_dict['NVE_data']['msite_bgw_loop']) + '''
                no shut

            interface ''' + str(testscript.parameters['intf_DC1_BGW_1_to_BGW_2']) + '''
                ip address 10.51.21.1/24 tag 54321
                evpn multisite dci-tracking
                no shutdown

            interface po ''' + str(BGW_1_dict['SPINE_1_UPLINK_PO']['po_id']) + '''
                evpn multisite fabric-tracking
                no shutdown

            route-map RMAP_REDIST_DIRECT permit 10
                match tag 54321
        ''')

        BGW_2.configure('''

            evpn multisite border-gateway 200
                delay-restore time 300

            interface ''' + str(BGW_2_dict['NVE_data']['msite_bgw_loop']) + '''
                ip address ''' + str(BGW_2_dict['NVE_data']['msite_bgw_loop_ip']) + '''/32 tag 54321
                ip router ospf ''' + str(testscript.parameters['DC_2_FWD_SYS_dict']['OSPF_AS']) + ''' are 0
                no shut

            interface loopback0
                no ip address
                ip address ''' + str(BGW_2_dict['loop0_ip']) + '''/32 tag 54321
                no shut

            interface ''' + str(BGW_2_dict['NVE_data']['src_loop']) + '''
                no ip address
                ip address ''' + str(BGW_2_dict['NVE_data']['VTEP_IP']) + '''/32 tag 54321
                no shut

            interface nve 1
                shut
                multisite border-gateway interface ''' + str(BGW_2_dict['NVE_data']['msite_bgw_loop']) + '''
                no shut

            interface ''' + str(testscript.parameters['intf_DC2_BGW_2_to_BGW_1']) + '''
                ip address 10.51.21.2/24 tag 54321
                evpn multisite dci-tracking
                no shutdown

            interface po ''' + str(BGW_2_dict['SPINE_1_UPLINK_PO']['po_id']) + '''
                evpn multisite fabric-tracking
                no shutdown

            route-map RMAP_REDIST_DIRECT permit 10
                match tag 54321
        ''')

        # --- Configure BGP on BGW
        BGW_1.configure('''
            router bgp ''' + str(testscript.parameters['DC_1_FWD_SYS_dict']['BGP_AS_num']) + '''
                router-id ''' + str(BGW_1_dict['loop0_ip']) + '''
                address-family ipv4 unicast
                    redistribute direct route-map RMAP_REDIST_DIRECT

                neighbor 10.51.21.2
                    remote-as ''' + str(testscript.parameters['DC_2_FWD_SYS_dict']['BGP_AS_num']) + '''
                    update-source ''' + str(testscript.parameters['intf_DC1_BGW_1_to_BGW_2']) + '''
                    address-family ipv4 unicast

                neighbor ''' + str(BGW_2_dict['loop0_ip']) + '''
                    remote-as ''' + str(testscript.parameters['DC_2_FWD_SYS_dict']['BGP_AS_num']) + '''
                    update-source loopback0
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family l2vpn evpn
                        send-community
                        send-community extended
                        rewrite-evpn-rt-asn
        ''')

        BGW_2.configure('''
            router bgp ''' + str(testscript.parameters['DC_2_FWD_SYS_dict']['BGP_AS_num']) + '''
                router-id ''' + str(BGW_2_dict['loop0_ip']) + '''
                address-family ipv4 unicast
                    redistribute direct route-map RMAP_REDIST_DIRECT

                neighbor 10.51.21.1
                    remote-as ''' + str(testscript.parameters['DC_1_FWD_SYS_dict']['BGP_AS_num']) + '''
                    update-source ''' + str(testscript.parameters['intf_DC2_BGW_2_to_BGW_1']) + '''
                    address-family ipv4 unicast

                neighbor ''' + str(BGW_1_dict['loop0_ip']) + '''
                    remote-as ''' + str(testscript.parameters['DC_1_FWD_SYS_dict']['BGP_AS_num']) + '''
                    update-source loopback0
                    ebgp-multihop 5
                    peer-type fabric-external
                    address-family l2vpn evpn
                        send-community
                        send-community extended
                        rewrite-evpn-rt-asn
        ''')

        for topo in topologies:
            BGW_1.configure('''
            router bgp ''' + str(testscript.parameters['DC_1_FWD_SYS_dict']['BGP_AS_num']) + '''
                vrf ''' + str(topo['vrf']) + '''
                    address-family ipv4 unicast
                        no export-gateway-ip
                        no maximum-paths mixed 32
                        maximum-paths 32
                        maximum-paths ibgp 32
                        maximum-paths local 32
                    address-family ipv6 unicast
                        no export-gateway-ip
                        no maximum-paths mixed 32
                        maximum-paths 32
                        maximum-paths ibgp 32
                        maximum-paths local 32
            ''')

            BGW_2.configure('''
            router bgp ''' + str(testscript.parameters['DC_2_FWD_SYS_dict']['BGP_AS_num']) + '''
                vrf ''' + str(topo['vrf']) + '''
                    address-family ipv4 unicast
                        no export-gateway-ip
                        no maximum-paths mixed 32
                        maximum-paths 32
                        maximum-paths ibgp 32
                        maximum-paths local 32
                    address-family ipv6 unicast
                        no export-gateway-ip
                        no maximum-paths mixed 32
                        maximum-paths 32
                        maximum-paths ibgp 32
                        maximum-paths local 32
            ''')

    # =============================================================================================================================#
    @aetest.test
    def configure_IXIA_facing_sub_ints_on_dut(self, testscript):
        """ IXIA_CONFIGURATION subsection: Connect to IXIA """

        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        DC_2_LEAF_2 = testscript.parameters['DC_2_LEAF-2']
        PGW = testscript.parameters['PGW']

        PGW_TGEN_data = testscript.parameters['PGW_TGEN_data']
        DC_1_LEAF_1_TGEN_data = testscript.parameters['DC_1_LEAF_1_TGEN_data']
        DC_2_LEAF_2_TGEN_data = testscript.parameters['DC_2_LEAF_2_TGEN_data']

        topologies = [testscript.parameters['topo_1_vnf_leaves_dict'],
                      testscript.parameters['topo_2_vnf_leaves_dict'],
                      testscript.parameters['topo_3_vnf_leaves_dict']]

        # Configuring Sub-interfaces on DUT facing IXIA
        DC_1_LEAF_1.configure('''
                interface ''' + str(testscript.parameters['intf_DC1_LEAF_1_to_IXIA']) + '''
                    switchport
                    switchport mode trunk
                    no shutdown
        ''')

        DC_2_LEAF_2.configure('''
                interface ''' + str(testscript.parameters['intf_DC2_LEAF_2_to_IXIA']) + '''
                    switchport
                    switchport mode trunk
                    no shutdown
        ''')

        PGW.configure('''
                interface ''' + str(testscript.parameters['intf_PGW_to_IXIA']) + '''
                    no shutdown
        ''')

        LEAF_vlan = int(DC_1_LEAF_1_TGEN_data['vlan_id'])
        LEAF_vlan_string = str(DC_1_LEAF_1_TGEN_data['vlan_id']) + '-'
        LEAF_ipv4 = ip.IPv4Interface(str(DC_1_LEAF_1_TGEN_data['v4_gateway']) + '/24')
        LEAF_ipv6 = ip.IPv6Interface(str(DC_1_LEAF_1_TGEN_data['v6_gateway']) + '/64')
        sub_int = 1
        for topo in topologies:
            DC_1_LEAF_1.configure('''

                vlan ''' + str(LEAF_vlan) + '''
                    state active
                    no shut

                interface vlan ''' + str(LEAF_vlan) + '''
                    vrf member ''' + str(topo['vrf']) + '''
                    ip address ''' + str(LEAF_ipv4.ip) + '''/24
                    ipv6 address ''' + str(LEAF_ipv6.ip) + '''/64
                    no shutdown
            ''')
            LEAF_vlan += 1
            LEAF_ipv4 += (256 ** 3)
            LEAF_ipv6 += (65536 ** 6)
            sub_int += 1
        LEAF_vlan_string += str(LEAF_vlan)
        DC_1_LEAF_1.configure('''
            interface ''' + str(testscript.parameters['intf_DC1_LEAF_1_to_IXIA']) + '''
                switchport
                switchport mode trunk
                switchport trunk allowed vlan ''' + str(LEAF_vlan_string) + '''
                no shutdown
        ''')

        LEAF_vlan = int(DC_2_LEAF_2_TGEN_data['vlan_id'])
        LEAF_vlan_string = str(DC_2_LEAF_2_TGEN_data['vlan_id']) + '-'
        LEAF_ipv4 = ip.IPv4Interface(str(DC_2_LEAF_2_TGEN_data['v4_gateway']) + '/24')
        LEAF_ipv6 = ip.IPv6Interface(str(DC_2_LEAF_2_TGEN_data['v6_gateway']) + '/64')
        sub_int = 1
        for topo in topologies:
            DC_2_LEAF_2.configure('''

                vlan ''' + str(LEAF_vlan) + '''
                    state active
                    no shut

                interface vlan ''' + str(LEAF_vlan) + '''
                    vrf member ''' + str(topo['vrf']) + '''
                    ip address ''' + str(LEAF_ipv4.ip) + '''/24
                    ipv6 address ''' + str(LEAF_ipv6.ip) + '''/64
                    no shutdown
            ''')
            LEAF_vlan += 1
            LEAF_ipv4 += (256 ** 3)
            LEAF_ipv6 += (65536 ** 6)
            sub_int += 1
        LEAF_vlan_string += str(LEAF_vlan)
        DC_2_LEAF_2.configure('''
            interface ''' + str(testscript.parameters['intf_DC2_LEAF_2_to_IXIA']) + '''
                switchport
                switchport mode trunk
                switchport trunk allowed vlan ''' + str(LEAF_vlan_string) + '''
                no shutdown
        ''')

        PGW_vlan = int(PGW_TGEN_data['vlan_id'])
        PGW_ipv4 = ip.IPv4Interface(str(PGW_TGEN_data['v4_gateway']) + '/24')
        PGW_ipv6 = ip.IPv6Interface(str(PGW_TGEN_data['v6_gateway']) + '/64')
        PGW_bgp_ipv4 = ip.IPv4Interface(str(PGW_TGEN_data['v4_addr']) + '/24')
        PGW_bgp_ipv6 = ip.IPv6Interface(str(PGW_TGEN_data['v6_addr']) + '/64')
        sub_int = 1
        for topo in topologies:
            PGW.configure('''
                    interface ''' + str(testscript.parameters['intf_PGW_to_IXIA']) + '''.''' + str(sub_int) + '''
                        encapsulation dot1q ''' + str(PGW_vlan) + '''
                        vrf member ''' + str(topo['vrf']) + '''
                        ip address ''' + str(PGW_ipv4.ip) + '''/24
                        ipv6 address ''' + str(PGW_ipv6.ip) + '''/64
                        no shutdown

                    router bgp ''' + str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_bgp_as']) + '''
                        vrf ''' + str(topo['vrf']) + '''
                            neighbor ''' + str(PGW_bgp_ipv4.ip) + ''' remote-as 350
                                address-family ipv4 unicast
                                    send-community
                                    send-community extended
                            neighbor ''' + str(PGW_bgp_ipv6.ip) + ''' remote-as 350
                                address-family ipv6 unicast
                                    send-community
                                    send-community extended
            ''')
            PGW_vlan += 1
            PGW_ipv4 += (256 ** 3)
            PGW_ipv6 += (65536 ** 6)
            PGW_bgp_ipv4 += (256 ** 3)
            PGW_bgp_ipv6 += (65536 ** 6)
            sub_int += 1

    # =============================================================================================================================#
    @aetest.test
    def perform_copy_r_s(self):
        """ ENABLE_L2_TRM_CONFIGURATION test subsection: Save all configurations (copy r s) """

        for device in device_list:
            device.configure("copy r s", timeout=300)

        time.sleep(300)

# *****************************************************************************************************************************#
class VERIFY_BASE_VxLAN_EVPN_NETWORK(aetest.Testcase):
    """This is description for my testcase one"""

    # =============================================================================================================================#
    @aetest.test
    def verify_DC1_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['DC_1_FWD_SYS_dict'],
                                                                testscript.parameters['DC_1_leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC2_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['DC_2_FWD_SYS_dict'],
                                                                testscript.parameters['DC_2_leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC1_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['DC_1_leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC2_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['DC_2_leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC1_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['DC_1_FWD_SYS_dict'],
                                                  testscript.parameters['DC_1_leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC2_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['DC_2_FWD_SYS_dict'],testscript.parameters['DC_2_leavesDict'])

        if nveVniData['result'] is 1:
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
    def configure_DC_1_SPINE_for_BGP_l2vpn_advertisement(self, testscript):
        """configure_PVNF_underlay_topo_1 - Common Loopback Solution"""

        spine_rt_map_name = testscript.parameters['SPINE_PVNF_rtmap_name']

        testscript.parameters["DC_1_SPINE"].configure('''
            route-map ''' + str(spine_rt_map_name) + ''' permit
                set path-selection all advertise

            router bgp ''' + str(testscript.parameters['DC_1_FWD_SYS_dict']['BGP_AS_num']) + '''
                address-family l2vpn evpn
                    maximum-paths mixed 32
                    additional-paths send
                    additional-paths receive
                    additional-paths selection route-map ''' + str(spine_rt_map_name) + '''
        ''')

    # =============================================================================================================================#
    @aetest.test
    def configure_DC_2_SPINE_for_BGP_l2vpn_advertisement(self, testscript):
        """configure_PVNF_underlay_topo_1 - Common Loopback Solution"""

        spine_rt_map_name = testscript.parameters['SPINE_PVNF_rtmap_name']

        testscript.parameters["DC_2_SPINE"].configure('''
            route-map ''' + str(spine_rt_map_name) + ''' permit
                set path-selection all advertise

            router bgp ''' + str(testscript.parameters['DC_2_FWD_SYS_dict']['BGP_AS_num']) + '''
                address-family l2vpn evpn
                    maximum-paths mixed 32
                    additional-paths send
                    additional-paths receive
                    additional-paths selection route-map ''' + str(spine_rt_map_name) + '''
        ''')

    # =============================================================================================================================#
    @aetest.test
    def configure_PVNF_underlay_topo_1(self, testscript):
        """configure_PVNF_underlay_topo_1 - Common Loopback Solution"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
            pvnfConfig.configurePVNF_Underlay_PGW_to_LEAF(testscript.parameters['PGW'],
                                                          testscript.parameters['topo_1_vnf_leaves_dict'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def configure_PVNF_underlay_topo_2(self, testscript):
        """configure_PVNF_underlay_topo_2 - Individual Loopback Solution"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
            pvnfConfig.configurePVNF_Underlay_PGW_to_LEAF(testscript.parameters['PGW'],
                                                          testscript.parameters['topo_2_vnf_leaves_dict'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def configure_PVNF_underlay_topo_3(self, testscript):
        """configure_PVNF_underlay_topo_3 - Individual Links Solution"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
            pvnfConfig.configurePVNF_Underlay_PGW_to_LEAF(testscript.parameters['PGW'],
                                                          testscript.parameters['topo_3_vnf_leaves_dict'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def configure_PVNF_pvnfBgp_topo_1(self, testscript):
        """configure_PVNF_pvnfBgp_topo_1 - Common Loopback Solution"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
            pvnfConfig.configurePVNF_BGP_PGW_to_LEAF(testscript.parameters['PGW'],
                                                     testscript.parameters['topo_1_vnf_leaves_dict'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def configure_PVNF_pvnfBgp_topo_2(self, testscript):
        """configure_PVNF_pvnfBgp_topo_2 - Individual Loopback Solution"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
            pvnfConfig.configurePVNF_BGP_PGW_to_LEAF(testscript.parameters['PGW'],
                                                     testscript.parameters['topo_2_vnf_leaves_dict'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def configure_PVNF_pvnfBgp_topo_3(self, testscript):
        """configure_PVNF_pvnfBgp_topo_3 - Individual Links Solution"""

        # Do not perform configurations if skip_device_config flag is set
        if not testscript.parameters['script_flags']['skip_device_config']:
            pvnfConfig.configurePVNF_BGP_PGW_to_LEAF(testscript.parameters['PGW'],
                                                     testscript.parameters['topo_3_vnf_leaves_dict'])
        else:
            self.passed(reason="Skipped Device Configurations as per request")

    # =============================================================================================================================#
    @aetest.test
    def configure_LEAF_ATTACH_prefix_lists_for_redist(self, testscript):
        """configure_PVNF_prefix_lists_for_redist"""

        # Configure the Prefix lists
        pvnfConfig.generate_prefix_list_per_topo(testscript.parameters['PGW'],testscript.parameters['topo_1_vnf_leaves_dict'])
        pvnfConfig.generate_prefix_list_per_topo(testscript.parameters['PGW'],testscript.parameters['topo_2_vnf_leaves_dict'])
        pvnfConfig.generate_prefix_list_per_topo(testscript.parameters['PGW'],testscript.parameters['topo_3_vnf_leaves_dict'])

        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        DC_1_LEAF_2 = testscript.parameters['DC_1_LEAF-2']
        DC_2_LEAF_1 = testscript.parameters['DC_2_LEAF-1']
        DC_2_LEAF_2 = testscript.parameters['DC_2_LEAF-2']

        DC_1_LEAF_1_TGEN_data = testscript.parameters['DC_1_LEAF_1_TGEN_data']
        DC_2_LEAF_2_TGEN_data = testscript.parameters['DC_1_LEAF_1_TGEN_data']

        topologies = [testscript.parameters['topo_1_vnf_leaves_dict'],
                      testscript.parameters['topo_2_vnf_leaves_dict'],
                      testscript.parameters['topo_3_vnf_leaves_dict']]

        # Get the prefix names
        LEAF_prfx_name_v4 = testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['LEAF_v4_prfx_lst_name']
        LEAF_prfx_name_v6 = testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['LEAF_v6_prfx_lst_name']

        # Get the host network
        LEAF_1_v4_nw = ip.IPv4Interface(str(DC_1_LEAF_1_TGEN_data['v4_addr']) + '/24')
        LEAF_1_v6_nw = ip.IPv6Interface(str(DC_1_LEAF_1_TGEN_data['v6_addr']) + '/64')

        # Add PVNF EW LEAF-1 hosts to the prefix list for redistribution testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']
        for topo in topologies:
            # Set the host network for broader subnet
            temp_v4_network = ip.IPv4Interface(str(LEAF_1_v4_nw.ip) + '/24')
            temp_v6_network = ip.IPv6Interface(str(LEAF_1_v6_nw.ip) + '/64')
            temp_host_v4 = ip.IPv4Interface(str(topo['BGP_v4_prefixes']) + '/8')
            temp_host_v6 = ip.IPv6Interface(str(topo['BGP_v6_prefixes']) + '/32')
            temp_host_v4_network = ip.IPv4Interface(str(temp_host_v4.ip) + '/8')
            temp_host_v6_network = ip.IPv6Interface(str(temp_host_v6.ip) + '/32')
            DC_1_LEAF_1.configure('''
                ip prefix-list ''' + str(LEAF_prfx_name_v4) + ''' permit ''' + str(temp_v4_network.network) + ''' le ''' + str(LEAF_1_v4_nw.max_prefixlen) + '''
                ip prefix-list ''' + str(LEAF_prfx_name_v4) + ''' permit ''' + str(temp_host_v4_network.network) + ''' le ''' + str(temp_host_v4_network.max_prefixlen) + '''
                ipv6 prefix-list ''' + str(LEAF_prfx_name_v6) + ''' permit ''' + str(temp_v6_network.network) + ''' le ''' + str(LEAF_1_v6_nw.max_prefixlen) + '''
                ipv6 prefix-list ''' + str(LEAF_prfx_name_v6) + ''' permit ''' + str(temp_host_v6_network.network) + ''' le ''' + str(temp_host_v6_network.max_prefixlen) + '''
            ''')
            DC_1_LEAF_2.configure('''
                ip prefix-list ''' + str(LEAF_prfx_name_v4) + ''' permit ''' + str(temp_v4_network.network) + ''' le ''' + str(LEAF_1_v4_nw.max_prefixlen) + '''
                ip prefix-list ''' + str(LEAF_prfx_name_v4) + ''' permit ''' + str(temp_host_v4_network.network) + ''' le ''' + str(temp_host_v4_network.max_prefixlen) + '''
                ipv6 prefix-list ''' + str(LEAF_prfx_name_v6) + ''' permit ''' + str(temp_v6_network.network) + ''' le ''' + str(LEAF_1_v6_nw.max_prefixlen) + '''
                ipv6 prefix-list ''' + str(LEAF_prfx_name_v6) + ''' permit ''' + str(temp_host_v6_network.network) + ''' le ''' + str(temp_host_v6_network.max_prefixlen) + '''
            ''')
            LEAF_1_v4_nw += (256 ** 3)
            LEAF_1_v6_nw += (65536 ** 6)

        # Get the host network
        LEAF_1_v4_nw = ip.IPv4Interface(str(DC_2_LEAF_2_TGEN_data['v4_addr']) + '/24')
        LEAF_1_v6_nw = ip.IPv6Interface(str(DC_2_LEAF_2_TGEN_data['v6_addr']) + '/64')

        # Add PVNF EW LEAF-1 hosts to the prefix list for redistribution
        for topo in topologies:
            # Set the host network for broader subnet
            temp_v4_network = ip.IPv4Interface(str(LEAF_1_v4_nw.ip) + '/24')
            temp_v6_network = ip.IPv6Interface(str(LEAF_1_v6_nw.ip) + '/64')
            temp_host_v4 = ip.IPv4Interface(str(topo['BGP_v4_prefixes']) + '/8')
            temp_host_v6 = ip.IPv6Interface(str(topo['BGP_v6_prefixes']) + '/32')
            temp_host_v4_network = ip.IPv4Interface(str(temp_host_v4.ip) + '/8')
            temp_host_v6_network = ip.IPv6Interface(str(temp_host_v6.ip) + '/32')
            DC_2_LEAF_1.configure('''
                ip prefix-list ''' + str(LEAF_prfx_name_v4) + ''' permit ''' + str(temp_v4_network.network) + ''' le ''' + str(LEAF_1_v4_nw.max_prefixlen) + '''
                ip prefix-list ''' + str(LEAF_prfx_name_v4) + ''' permit ''' + str(temp_host_v4_network.network) + ''' le ''' + str(temp_host_v4_network.max_prefixlen) + '''
                ipv6 prefix-list ''' + str(LEAF_prfx_name_v6) + ''' permit ''' + str(temp_v6_network.network) + ''' le ''' + str(LEAF_1_v6_nw.max_prefixlen) + '''
                ipv6 prefix-list ''' + str(LEAF_prfx_name_v6) + ''' permit ''' + str(temp_host_v6_network.network) + ''' le ''' + str(temp_host_v6_network.max_prefixlen) + '''
            ''')
            DC_2_LEAF_2.configure('''
                ip prefix-list ''' + str(LEAF_prfx_name_v4) + ''' permit ''' + str(temp_v4_network.network) + ''' le ''' + str(LEAF_1_v4_nw.max_prefixlen) + '''
                ip prefix-list ''' + str(LEAF_prfx_name_v4) + ''' permit ''' + str(temp_host_v4_network.network) + ''' le ''' + str(temp_host_v4_network.max_prefixlen) + '''
                ipv6 prefix-list ''' + str(LEAF_prfx_name_v6) + ''' permit ''' + str(temp_v6_network.network) + ''' le ''' + str(LEAF_1_v6_nw.max_prefixlen) + '''
                ipv6 prefix-list ''' + str(LEAF_prfx_name_v6) + ''' permit ''' + str(temp_host_v6_network.network) + ''' le ''' + str(temp_host_v6_network.max_prefixlen) + '''
            ''')
            LEAF_1_v4_nw += (256 ** 3)
            LEAF_1_v6_nw += (65536 ** 6)

    # =============================================================================================================================#
    @aetest.test
    def configure_STOP_External_route_maps(self, testscript):
        """ IXIA_CONFIGURATION subsection: Connect to IXIA """

        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        DC_1_LEAF_2 = testscript.parameters['DC_1_LEAF-2']
        DC_2_LEAF_1 = testscript.parameters['DC_2_LEAF-1']
        DC_2_LEAF_2 = testscript.parameters['DC_2_LEAF-2']

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
                        ''')
            if topology['type'] == 'topo_3':
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
                        ''')

        # Create Deny route-map on LEAF-2 and LEAF-3 to deny any external routes learnt via SPINE
        DC_1_LEAF_1.configure('''
                route-map ''' + str(LEAF_stop_rtmap_name) + ''' deny 5
                    match ip address prefix-list ''' + str(LEAF_stop_prfx_name_v4) + '''
                route-map ''' + str(LEAF_stop_rtmap_name) + ''' deny 10
                    match ipv6 address prefix-list ''' + str(LEAF_stop_prfx_name_v6) + '''
                route-map ''' + str(LEAF_stop_rtmap_name) + ''' permit 50
        ''')

        DC_1_LEAF_2.configure('''
                route-map ''' + str(LEAF_stop_rtmap_name) + ''' deny 5
                    match ip address prefix-list ''' + str(LEAF_stop_prfx_name_v4) + '''
                route-map ''' + str(LEAF_stop_rtmap_name) + ''' deny 10
                    match ipv6 address prefix-list ''' + str(LEAF_stop_prfx_name_v6) + '''
                route-map ''' + str(LEAF_stop_rtmap_name) + ''' permit 50

                router bgp ''' + str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_2]['leaf_as']) + '''
                    neighbor ''' + str(
            testscript.parameters['DC_1_LEAF_2_dict']['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + '''
                        address-family l2vpn evpn
                          send-community
                          send-community extended
                          route-map ''' + str(LEAF_stop_rtmap_name) + ''' in
        ''')

        DC_2_LEAF_1.configure('''
                route-map ''' + str(LEAF_stop_rtmap_name) + ''' deny 5
                    match ip address prefix-list ''' + str(LEAF_stop_prfx_name_v4) + '''
                route-map ''' + str(LEAF_stop_rtmap_name) + ''' deny 10
                    match ipv6 address prefix-list ''' + str(LEAF_stop_prfx_name_v6) + '''
                route-map ''' + str(LEAF_stop_rtmap_name) + ''' permit 50

                router bgp ''' + str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_2_LEAF_1]['leaf_as']) + '''
                    neighbor ''' + str(
            testscript.parameters['DC_2_LEAF_2_dict']['SPINE_1_UPLINK_PO']['spine_leaf_po_v4']) + '''
                        address-family l2vpn evpn
                          send-community
                          send-community extended
                          route-map ''' + str(LEAF_stop_rtmap_name) + ''' in
        ''')

        DC_2_LEAF_2.configure('''
                route-map ''' + str(LEAF_stop_rtmap_name) + ''' deny 5
                    match ip address prefix-list ''' + str(LEAF_stop_prfx_name_v4) + '''
                route-map ''' + str(LEAF_stop_rtmap_name) + ''' deny 10
                    match ipv6 address prefix-list ''' + str(LEAF_stop_prfx_name_v6) + '''
                route-map ''' + str(LEAF_stop_rtmap_name) + ''' permit 50
        ''')

    # =============================================================================================================================#
    @aetest.test
    def restart_BGP_clear_routes(self, testscript):
        """configure_PVNF_prefix_lists_for_redist"""

        for dut in dc1_device_list:
            dut.configure('''
                restart bgp ''' + str(testscript.parameters['DC_1_FWD_SYS_dict']['BGP_AS_num']) + '''
                clear ip bgp vrf all *
                clear ip route vrf all *
                clear ipv6 route vrf all *
            ''')

        for dut in dc2_device_list:
            dut.configure('''
                restart bgp ''' + str(testscript.parameters['DC_2_FWD_SYS_dict']['BGP_AS_num']) + '''
                clear ip bgp vrf all *
                clear ip route vrf all *
                clear ipv6 route vrf all *
            ''')

        time.sleep(120)

    # =============================================================================================================================#
    @aetest.test
    def verify_DC1_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['DC_1_FWD_SYS_dict'],
                                                                testscript.parameters['DC_1_leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC2_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['DC_2_FWD_SYS_dict'],
                                                                testscript.parameters['DC_2_leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC1_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['DC_1_FWD_SYS_dict'],
                                                  testscript.parameters['DC_1_leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC2_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['DC_2_FWD_SYS_dict'],
                                                  testscript.parameters['DC_2_leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

#*****************************************************************************************************************************#
class IXIA_CONFIGURATION(aetest.Testcase):
    """IXIA_CONFIGURATION"""

    # =============================================================================================================================#
    @aetest.test
    def CONNECT_IXIA_CHASSIS(self, testscript):
        """ IXIA_CONFIGURATION subsection: Connect to IXIA """

        # testscript.parameters['ixia_int_list'] = str(testscript.parameters['intf_IXIA_to_PGW']) + " " + str(testscript.parameters['intf_IXIA_to_DC1_LEAF_1'])\
        #                                          + " " + str(testscript.parameters['intf_IXIA_to_DC2_LEAF_2'])

        # Do not perform configurations if skip_tgen_config flag is set
        if not testscript.parameters['script_flags']['skip_tgen_config']:

            # Get IXIA paraameters
            ixia_chassis_ip = testscript.parameters['ixia_chassis_ip']
            ixia_tcl_server = testscript.parameters['ixia_tcl_server']
            ixia_tcl_port = testscript.parameters['ixia_tcl_port']
            ixia_int_list = testscript.parameters['ixia_int_list']

            ix_int_1 = testscript.parameters['intf_IXIA_to_DC1_LEAF_1']
            ix_int_2 = testscript.parameters['intf_IXIA_to_PGW']
            ix_int_3 = testscript.parameters['intf_IXIA_to_DC2_LEAF_2']

            ixiaArgDict = {
                'chassis_ip': ixia_chassis_ip,
                'port_list': ixia_int_list,
                'tcl_server': ixia_tcl_server,
                'tcl_port': ixia_tcl_port
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

            TOPO_1_dict = {'topology_name': 'DC-1-LEAF-1',
                           'device_grp_name': 'DC-1-LEAF-1',
                           'port_handle': testscript.parameters['port_handle_1']}

            TOPO_2_dict = {'topology_name': 'PGW-PVNF',
                           'device_grp_name': 'PGW-PVNF',
                           'port_handle': testscript.parameters['port_handle_2']}

            TOPO_3_dict = {'topology_name': 'DC-2-LEAF-2',
                           'device_grp_name': 'DC-2-LEAF-2',
                           'port_handle': testscript.parameters['port_handle_3']}

            testscript.parameters['IX_TP1'] = ixLib.create_topo_device_grp(TOPO_1_dict)
            if testscript.parameters['IX_TP1'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed", goto=['next_tc'])
            else:
                log.info("Created DC-1-LEAF-1 Topology Successfully")

            testscript.parameters['IX_TP2'] = ixLib.create_topo_device_grp(TOPO_2_dict)
            if testscript.parameters['IX_TP2'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating Topology failed", goto=['next_tc'])
            else:
                log.info("Created PGW-PVNF Topology Successfully")

            testscript.parameters['IX_TP3'] = ixLib.create_topo_device_grp(TOPO_3_dict)
            if testscript.parameters['IX_TP3'] == 0:
                log.debug("Creating Topology failed")
                self.errored("Creating DC-2-LEAF-2 Topology failed", goto=['next_tc'])
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
            DC_1_LEAF_1_TGEN_data = testscript.parameters['DC_1_LEAF_1_TGEN_data']
            PGW_TGEN_data = testscript.parameters['PGW_TGEN_data']
            DC_2_LEAF_2_TGEN_data = testscript.parameters['DC_2_LEAF_2_TGEN_data']

            DC1_int_dict = {'dev_grp_hndl': testscript.parameters['IX_TP1']['dev_grp_hndl'],
                            'port_hndl': P1,
                            'no_of_ints': str(DC_1_LEAF_1_TGEN_data['no_of_ints']),
                            'phy_mode': DC_1_LEAF_1_TGEN_data['phy_mode'],
                            'mac': DC_1_LEAF_1_TGEN_data['mac'],
                            'mac_step': DC_1_LEAF_1_TGEN_data['mac_step'],
                            'protocol': DC_1_LEAF_1_TGEN_data['protocol'],
                            'v4_addr': DC_1_LEAF_1_TGEN_data['v4_addr'],
                            'v4_addr_step': DC_1_LEAF_1_TGEN_data['v4_addr_step'],
                            'v4_gateway': DC_1_LEAF_1_TGEN_data['v4_gateway'],
                            'v4_gateway_step': DC_1_LEAF_1_TGEN_data['v4_gateway_step'],
                            'v4_netmask': DC_1_LEAF_1_TGEN_data['v4_netmask'],
                            'v6_addr': DC_1_LEAF_1_TGEN_data['v6_addr'],
                            'v6_addr_step': DC_1_LEAF_1_TGEN_data['v6_addr_step'],
                            'v6_gateway': DC_1_LEAF_1_TGEN_data['v6_gateway'],
                            'v6_gateway_step': DC_1_LEAF_1_TGEN_data['v6_gateway_step'],
                            'v6_netmask': DC_1_LEAF_1_TGEN_data['v6_netmask'],
                            'vlan_id': str(DC_1_LEAF_1_TGEN_data['vlan_id']),
                            'vlan_id_step': DC_1_LEAF_1_TGEN_data['vlan_id_step']}

            PGW_int_dict = {'dev_grp_hndl': testscript.parameters['IX_TP2']['dev_grp_hndl'],
                            'port_hndl': P2,
                            'no_of_ints': str(PGW_TGEN_data['no_of_ints']),
                            'phy_mode': PGW_TGEN_data['phy_mode'],
                            'mac': PGW_TGEN_data['mac'],
                            'mac_step': PGW_TGEN_data['mac_step'],
                            'protocol': PGW_TGEN_data['protocol'],
                            'v4_addr': PGW_TGEN_data['v4_addr'],
                            'v4_addr_step': PGW_TGEN_data['v4_addr_step'],
                            'v4_gateway': PGW_TGEN_data['v4_gateway'],
                            'v4_gateway_step': PGW_TGEN_data['v4_gateway_step'],
                            'v4_netmask': PGW_TGEN_data['v4_netmask'],
                            'v6_addr': PGW_TGEN_data['v6_addr'],
                            'v6_addr_step': PGW_TGEN_data['v6_addr_step'],
                            'v6_gateway': PGW_TGEN_data['v6_gateway'],
                            'v6_gateway_step': PGW_TGEN_data['v6_gateway_step'],
                            'v6_netmask': PGW_TGEN_data['v6_netmask'],
                            'vlan_id': str(PGW_TGEN_data['vlan_id']),
                            'vlan_id_step': PGW_TGEN_data['vlan_id_step']}

            DC2_int_dict = {'dev_grp_hndl': testscript.parameters['IX_TP3']['dev_grp_hndl'],
                            'port_hndl': P3,
                            'no_of_ints': str(DC_2_LEAF_2_TGEN_data['no_of_ints']),
                            'phy_mode': DC_2_LEAF_2_TGEN_data['phy_mode'],
                            'mac': DC_2_LEAF_2_TGEN_data['mac'],
                            'mac_step': DC_2_LEAF_2_TGEN_data['mac_step'],
                            'protocol': DC_2_LEAF_2_TGEN_data['protocol'],
                            'v4_addr': DC_2_LEAF_2_TGEN_data['v4_addr'],
                            'v4_addr_step': DC_2_LEAF_2_TGEN_data['v4_addr_step'],
                            'v4_gateway': DC_2_LEAF_2_TGEN_data['v4_gateway'],
                            'v4_gateway_step': DC_2_LEAF_2_TGEN_data['v4_gateway_step'],
                            'v4_netmask': DC_2_LEAF_2_TGEN_data['v4_netmask'],
                            'v6_addr': DC_2_LEAF_2_TGEN_data['v6_addr'],
                            'v6_addr_step': DC_2_LEAF_2_TGEN_data['v6_addr_step'],
                            'v6_gateway': DC_2_LEAF_2_TGEN_data['v6_gateway'],
                            'v6_gateway_step': DC_2_LEAF_2_TGEN_data['v6_gateway_step'],
                            'v6_netmask': DC_2_LEAF_2_TGEN_data['v6_netmask'],
                            'vlan_id': str(DC_2_LEAF_2_TGEN_data['vlan_id']),
                            'vlan_id_step': DC_2_LEAF_2_TGEN_data['vlan_id_step']}

            DC1_int_data = ixLib.configure_multi_ixia_interface(DC1_int_dict)
            PGW_int_data = ixLib.configure_multi_ixia_interface(PGW_int_dict)
            DC2_int_data = ixLib.configure_multi_ixia_interface(DC2_int_dict)

            if DC1_int_data == 0 or PGW_int_data == 0 or DC2_int_data == 0:
                log.debug("Configuring IXIA Interface failed")
                self.errored("Configuring IXIA Interface failed", goto=['next_tc'])
            else:
                log.info("Configured IXIA Interface Successfully")

            testscript.parameters['IX_TP1']['eth_handle'] = DC1_int_data['eth_handle']
            testscript.parameters['IX_TP1']['ipv4_handle'] = DC1_int_data['ipv4_handle']
            testscript.parameters['IX_TP1']['ipv6_handle'] = DC1_int_data['ipv6_handle']
            testscript.parameters['IX_TP1']['topo_int_handle'] = DC1_int_data['topo_int_handle'].split(" ")

            testscript.parameters['IX_TP2']['eth_handle'] = PGW_int_data['eth_handle']
            testscript.parameters['IX_TP2']['ipv4_handle'] = PGW_int_data['ipv4_handle']
            testscript.parameters['IX_TP2']['ipv6_handle'] = PGW_int_data['ipv6_handle']
            testscript.parameters['IX_TP2']['topo_int_handle'] = PGW_int_data['topo_int_handle'].split(" ")

            testscript.parameters['IX_TP3']['eth_handle'] = DC2_int_data['eth_handle']
            testscript.parameters['IX_TP3']['ipv4_handle'] = DC2_int_data['ipv4_handle']
            testscript.parameters['IX_TP3']['ipv6_handle'] = DC2_int_data['ipv6_handle']
            testscript.parameters['IX_TP3']['topo_int_handle'] = DC2_int_data['topo_int_handle'].split(" ")

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
            'topology': testscript.parameters['IX_TP2'],
            'ip_hndl': testscript.parameters['IX_TP2']['ipv4_handle'],
            'count': '1',
            'ip_ver': 4,
            'dut_ip': testscript.parameters['PGW_TGEN_data']['v4_gateway'],
            'dut_ip_step': testscript.parameters['PGW_TGEN_data']['v4_gateway_step'],
            'neighbor_type': 'external',
            'ixia_as': '350',
            'dut_as': '50',
            'v4_route_start': '150.1.1.5',
            'v4_route_step': '0.1.0.0',
            'v4_route_prfx': '32',
            'route_range_multiplier': '4',
            'no_of_routes_per_rt_range': '50',
            'nest_step': '10.0.0.0,0.1.0.0',
            'nest_flag': '1,1',
        }

        v6_BGP_dict = {
            'topology': testscript.parameters['IX_TP2'],
            'ip_hndl': testscript.parameters['IX_TP2']['ipv6_handle'],
            'count': '1',
            'ip_ver': 6,
            'dut_ip': testscript.parameters['PGW_TGEN_data']['v6_gateway'],
            'dut_ip_step': testscript.parameters['PGW_TGEN_data']['v6_gateway_step'],
            'neighbor_type': 'external',
            'ixia_as': '350',
            'dut_as': '50',
            'v6_route_start': '2001:150:1:1::5',
            'v6_route_step': '0:0:1:0::0',
            'v6_route_prfx': '128',
            'route_range_multiplier': '4',
            'no_of_routes_per_rt_range': '50',
            'nest_step': '0:10:0:0::0,0:0:1:0::0',
            'nest_flag': '1,1',
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

            DC1_PGW_v4_endpoint_set_dict = {
                'src_hndl': IX_TP1['ipv4_handle'],
                'dst_hndl': IX_TP2['ipv4_prefix_pools_handle'],
                'circuit': 'ipv4',
                'TI_name': "DC1_PGW_V4",
                'rate_pps': "1000",
                'bi_dir': 0,
                'no_of_end_points': '3',
                'src_port_start': '1',
                'src_port_start_step': '0',
                'src_intf_count': '1',
                'dst_port_start': '1',
                'dst_port_start_step': '0',
                'dst_intf_count': '4',
            }

            DC1_PGW_v6_endpoint_set_dict = {
                'src_hndl': IX_TP1['ipv6_handle'],
                'dst_hndl': IX_TP2['ipv6_prefix_pools_handle'],
                'circuit': 'ipv6',
                'TI_name': "DC1_PGW_V6",
                'rate_pps': "1000",
                'bi_dir': 0,
                'no_of_end_points': '3',
                'src_port_start': '1',
                'src_port_start_step': '0',
                'src_intf_count': '1',
                'dst_port_start': '1',
                'dst_port_start_step': '0',
                'dst_intf_count': '4',
            }

            DC2_PGW_v4_endpoint_set_dict = {
                'src_hndl': IX_TP3['ipv4_handle'],
                'dst_hndl': IX_TP2['ipv4_prefix_pools_handle'],
                'circuit': 'ipv4',
                'TI_name': "DC2_PGW_V4",
                'rate_pps': "1000",
                'bi_dir': 1,
                'no_of_end_points': '3',
                'src_port_start': '1',
                'src_port_start_step': '0',
                'src_intf_count': '1',
                'dst_port_start': '1',
                'dst_port_start_step': '0',
                'dst_intf_count': '4',
            }

            DC2_PGW_v6_endpoint_set_dict = {
                'src_hndl': IX_TP3['ipv6_handle'],
                'dst_hndl': IX_TP2['ipv6_prefix_pools_handle'],
                'circuit': 'ipv6',
                'TI_name': "DC2_PGW_V6",
                'rate_pps': "1000",
                'bi_dir': 1,
                'no_of_end_points': '3',
                'src_port_start': '1',
                'src_port_start_step': '0',
                'src_intf_count': '1',
                'dst_port_start': '1',
                'dst_port_start_step': '0',
                'dst_intf_count': '4',
            }

            DC1_DC2_v4_endpoint_set_dict = {
                'src_hndl': IX_TP1['ipv4_handle'],
                'dst_hndl': IX_TP3['ipv4_handle'],
                'circuit': 'ipv4',
                'TI_name': "DC1_DC2_V4",
                'rate_pps': "1000",
                'bi_dir': 1,
                'no_of_end_points': '3',
                'src_port_start': '1',
                'src_port_start_step': '0',
                'src_intf_count': '1',
                'dst_port_start': '1',
                'dst_port_start_step': '0',
                'dst_intf_count': '4',
            }

            DC1_DC2_v6_endpoint_set_dict = {
                'src_hndl': IX_TP1['ipv6_handle'],
                'dst_hndl': IX_TP3['ipv6_handle'],
                'circuit': 'ipv6',
                'TI_name': "DC1_DC2_V6",
                'rate_pps': "1000",
                'bi_dir': 1,
                'no_of_end_points': '3',
                'src_port_start': '1',
                'src_port_start_step': '0',
                'src_intf_count': '1',
                'dst_port_start': '1',
                'dst_port_start_step': '0',
                'dst_intf_count': '4',
            }

            DC1_PGW_UCAST_v4_TI = ixLib.configure_multi_endpoint_ixia_traffic_item(DC1_PGW_v4_endpoint_set_dict)
            DC1_PGW_UCAST_v6_TI = ixLib.configure_multi_endpoint_ixia_traffic_item(DC1_PGW_v6_endpoint_set_dict)
            DC2_PGW_UCAST_v4_TI = ixLib.configure_multi_endpoint_ixia_traffic_item(DC2_PGW_v4_endpoint_set_dict)
            DC2_PGW_UCAST_v6_TI = ixLib.configure_multi_endpoint_ixia_traffic_item(DC2_PGW_v6_endpoint_set_dict)
            DC1_DC2_UCAST_v4_TI = ixLib.configure_ixia_traffic_item(DC1_DC2_v4_endpoint_set_dict)
            DC1_DC2_UCAST_v6_TI = ixLib.configure_ixia_traffic_item(DC1_DC2_v6_endpoint_set_dict)

            if DC1_PGW_UCAST_v4_TI == 0 or DC1_PGW_UCAST_v6_TI == 0 or \
                    DC2_PGW_UCAST_v4_TI == 0 or DC2_PGW_UCAST_v6_TI == 0 or \
                    DC1_DC2_UCAST_v4_TI == 0 or DC1_DC2_UCAST_v6_TI == 0:
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

            if ixLib.verify_traffic(2, 2) == 0:
                log.debug("Traffic Verification failed")
                self.failed("Traffic Verification failed", goto=['next_tc'])
            else:
                log.info("Traffic Verification Passed")
        else:
            self.passed(reason="Skipped TGEN Configurations as per request")

# *****************************************************************************************************************************#
class VERIFY_RESTART_BGP_AS_POST_IXIA_CONFIG(aetest.Testcase):
    """VERIFY_RESTART_BGP"""

    # =============================================================================================================================#
    @aetest.test
    def RESTART_BGP_AS(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        for dut in dc1_device_list:
            dut.configure('''
                restart bgp ''' + str(testscript.parameters['DC_1_FWD_SYS_dict']['BGP_AS_num']) + '''
                clear ip bgp vrf all *
                clear ip route vrf all *
                clear ipv6 route vrf all *
            ''')

        time.sleep(240)

# *****************************************************************************************************************************#
class VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY(aetest.Testcase):
    """VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        DC1_leafList = [testscript.parameters['DC_1_LEAF-1'], testscript.parameters['DC_1_LEAF-2']]
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC1_status = pvnfVerify.verifyPVNF_common_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_1_vnf_leaves_dict'], DC1_leafList)
        DC2_status = pvnfVerify.verifyPVNF_common_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_1_vnf_leaves_dict'], DC2_leafList)

        if DC1_status['result'] and DC2_status['result']:
            self.passed(reason=str(DC1_status['status_msgs'])+str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC1_status['status_msgs'])+str(DC2_status['status_msgs']))

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_FROM_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_1_BGW'], testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4',testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4'],testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(v4_status);log.info(v6_status);log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 16 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(nxt_hops(v4_status)[1])
            fail_flag.append(nxt_hops(v6_status)[1])

            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'1,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '1,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4']),'16,16',str(v4_status['num_of_hops']),str(v4_status['fwd_num_of_hops']),str(nxt_hops(v4_status)[0]),str(v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6']), '16,16', str(v6_status['num_of_hops']), str(v6_status['fwd_num_of_hops']),str(nxt_hops(v6_status)[0]), str(v6_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

# *****************************************************************************************************************************#
class VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY(aetest.Testcase):
    """VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_loopback_topology_btw_LEAF_PGW(PGW,testscript.parameters['topo_2_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY_FROM_BGW(self, testscript):
        """ VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_1_BGW'], testscript.parameters['DC_2_BGW']]
        BGW_1 = testscript.parameters['DC_1_BGW']
        BGW_2 = testscript.parameters['DC_2_BGW']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        BGW_hst_nextHopTable = texttable.Texttable()
        BGW_hst_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_hst_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Individual Loop", 145)) + '''\n'''

        for leaf in dc1_leaf_list:
            dst_v4_ip = testscript.parameters['topo_2_vnf_leaves_dict'][leaf]['pgw_comn_loop_v4']
            dst_v6_ip = testscript.parameters['topo_2_vnf_leaves_dict'][leaf]['pgw_comn_loop_v6']
            leaf_to_pgw_link_count = testscript.parameters['topo_2_vnf_leaves_dict'][leaf]['leaf_to_pgw_link_count']

            # Get the next hop information
            v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1,'v4',dst_v4_ip,testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
            v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', dst_v6_ip, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(v4_status);log.info(v6_status);log.info('===>')

            # Set the pass criteria
            nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == leaf_to_pgw_link_count and int(X['fwd_num_of_hops']) == leaf_to_pgw_link_count) else ['FAIL', 0]
            fail_flag.append(nxt_hops(v4_status)[1])
            fail_flag.append(nxt_hops(v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW_1.alias, PGW.alias + '->' + leaf.alias + '\n' + str(dst_v4_ip), str(leaf_to_pgw_link_count)+','+str(leaf_to_pgw_link_count),str(v4_status['num_of_hops']), str(v4_status['fwd_num_of_hops']),str(nxt_hops(v4_status)[0]), str(v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW_1.alias, PGW.alias + '->' + leaf.alias + '\n' + str(dst_v6_ip), str(leaf_to_pgw_link_count)+','+str(leaf_to_pgw_link_count),str(v6_status['num_of_hops']), str(v6_status['fwd_num_of_hops']),str(nxt_hops(v6_status)[0]), str(v6_status['prfx_lst'])])

        for leaf in dc2_leaf_list:
            dst_v4_ip = testscript.parameters['topo_2_vnf_leaves_dict'][leaf]['pgw_comn_loop_v4']
            dst_v6_ip = testscript.parameters['topo_2_vnf_leaves_dict'][leaf]['pgw_comn_loop_v6']
            leaf_to_pgw_link_count = testscript.parameters['topo_2_vnf_leaves_dict'][leaf]['leaf_to_pgw_link_count']

            # Get the next hop information
            v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_2, 'v4', dst_v4_ip,testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
            v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_2, 'v6', dst_v6_ip,testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(v4_status);log.info(v6_status);log.info('===>')

            # Set the pass criteria
            nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == leaf_to_pgw_link_count and int(X['fwd_num_of_hops']) == leaf_to_pgw_link_count) else ['FAIL', 0]
            fail_flag.append(nxt_hops(v4_status)[1])
            fail_flag.append(nxt_hops(v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW_2.alias, PGW.alias + '->' + leaf.alias + '\n' + str(dst_v4_ip), str(leaf_to_pgw_link_count)+','+str(leaf_to_pgw_link_count),str(v4_status['num_of_hops']), str(v4_status['fwd_num_of_hops']), str(nxt_hops(v4_status)[0]),str(v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW_2.alias, PGW.alias + '->' + leaf.alias + '\n' + str(dst_v6_ip), str(leaf_to_pgw_link_count)+','+str(leaf_to_pgw_link_count),str(v6_status['num_of_hops']), str(v6_status['fwd_num_of_hops']), str(nxt_hops(v6_status)[0]),str(v6_status['prfx_lst'])])

        for BGW in BGW_list:
            # Get the next hop information
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 2 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_hst_nextHopTable.add_row([BGW.alias, PGW.alias + '\n' + str(random_host_ipv4), '2,16',str(hst_v4_status['num_of_hops']), str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_hst_nextHopTable.add_row([BGW.alias, PGW.alias + '\n' + str(random_host_ipv6), '2,16',str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw()) + '\n'
        status_msgs += str(BGW_hst_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

# *****************************************************************************************************************************#
class VERIFY_PVNF_PHYSICAL_VM_TOPOLOGY(aetest.Testcase):
    """VERIFY_PVNF_PHYSICAL_VM_TOPOLOGY"""

    #=============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_PHYSICAL_VM_TOPOLOGY_FROM_BGW(self, testscript):
        """ VERIFY_PHYSICAL_VM_TOPOLOGY """

        BGW_1 = testscript.parameters['DC_1_BGW']
        BGW_2 = testscript.parameters['DC_2_BGW']
        PGW = testscript.parameters['PGW']
        DC1_leafList = [testscript.parameters['DC_1_LEAF-1'], testscript.parameters['DC_1_LEAF-2']]
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC1_status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BGW_1, PGW, testscript.parameters['topo_3_vnf_leaves_dict'], DC1_leafList)
        DC2_status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BGW_2, PGW, testscript.parameters['topo_3_vnf_leaves_dict'], DC2_leafList)

        if DC1_status['result'] and DC2_status['result']:
            self.passed(reason=str(DC1_status['status_msgs'])+str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC1_status['status_msgs'])+str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_TRAFFIC_POST_PVNF_BRINGUP(aetest.Testcase):
    """VERIFY_TRAFFIC_POST_PVNF_BRINGUP"""

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
class SHUT_LOCAL_MODE_VTEP_PGW_LINKS(aetest.Testcase):
    """SHUT_LOCAL_MODE_VTEP_PGW_LINKS"""

    # =============================================================================================================================#
    @aetest.test
    def SHUT_LOCAL_MODE_VTEP_PGW_LINKS(self, testscript):

        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_LEAF2 = testscript.parameters['DC_1_LEAF-2']

        DC1_LEAF1.configure('''
            interface '''+str(testscript.parameters['intf_DC1_LEAF_1_to_PGW_1'])+'''
                shutdown

            interface '''+str(testscript.parameters['intf_DC1_LEAF_1_to_PGW_2'])+'''
                shutdown
        ''')

        DC1_LEAF2.configure('''
            interface ''' + str(testscript.parameters['intf_DC1_LEAF_2_to_PGW_1']) + '''
                shutdown

            interface ''' + str(testscript.parameters['intf_DC1_LEAF_2_to_PGW_2']) + '''
                shutdown
        ''')

        time.sleep(120)

# *****************************************************************************************************************************#
class VERIFY_RESTART_BGP_AS_POST_SHUT(aetest.Testcase):
    """VERIFY_RESTART_BGP"""

    # =============================================================================================================================#
    @aetest.test
    def RESTART_BGP_AS(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        for dut in dc1_device_list:
            dut.configure('''
                restart bgp ''' + str(testscript.parameters['DC_1_FWD_SYS_dict']['BGP_AS_num']) + '''
                clear ip bgp vrf all *
                clear ip route vrf all *
                clear ipv6 route vrf all *
            ''')

        time.sleep(240)

# *****************************************************************************************************************************#
class VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT(aetest.Testcase):
    """VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY_POST_LOCAL_MODE_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v4(DC1_LEAF1_v4_status)[1])
        nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v6(DC1_LEAF1_v6_status)[1])

        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4']), '1,>=1',
            str(DC1_LEAF1_v4_status['num_of_hops']), str(DC1_LEAF1_v4_status['fwd_num_of_hops']),
            str(nxt_hops_v4(DC1_LEAF1_v4_status)[0]), str(DC1_LEAF1_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6']), '1,>=1',
            str(DC1_LEAF1_v6_status['num_of_hops']), str(DC1_LEAF1_v6_status['fwd_num_of_hops']),
            str(nxt_hops_v6(DC1_LEAF1_v6_status)[0]), str(DC1_LEAF1_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v4(DC1_LEAF1_v4_status)[1])
        nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v6(DC1_LEAF1_v6_status)[1])

        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4']), '1,>=1',
            str(DC1_LEAF1_v4_status['num_of_hops']), str(DC1_LEAF1_v4_status['fwd_num_of_hops']),
            str(nxt_hops_v4(DC1_LEAF1_v4_status)[0]), str(DC1_LEAF1_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6']), '1,>=1',
            str(DC1_LEAF1_v6_status['num_of_hops']), str(DC1_LEAF1_v6_status['fwd_num_of_hops']),
            str(nxt_hops_v6(DC1_LEAF1_v6_status)[0]), str(DC1_LEAF1_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4',testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4'],testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(v4_status);log.info(v6_status);log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 16 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(nxt_hops(v4_status)[1])
            fail_flag.append(nxt_hops(v6_status)[1])

            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'1,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '1,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4']),'16,16',str(v4_status['num_of_hops']),str(v4_status['fwd_num_of_hops']),str(nxt_hops(v4_status)[0]),str(v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6']), '16,16', str(v6_status['num_of_hops']), str(v6_status['fwd_num_of_hops']),str(nxt_hops(v6_status)[0]), str(v6_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_common_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_1_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT(aetest.Testcase):
    """VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 2 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'2,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '2,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_individual_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_2_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_PVNF_PHYSICAL_VM_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT(aetest.Testcase):
    """VERIFY_PVNF_PHYSICAL_VM_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 16 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'16,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '16,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        BGW_2 = testscript.parameters['DC_2_BGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BGW_2, PGW, testscript.parameters['topo_3_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_TRAFFIC_POST_PVNF_PGW_SHUT(aetest.Testcase):
    """VERIFY_TRAFFIC_POST_PVNF_PGW_SHUT"""

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
class VERIFY_RESTART_BGP_AS(aetest.Testcase):
    """VERIFY_RESTART_BGP"""

    # =============================================================================================================================#
    @aetest.test
    def RESTART_BGP_AS(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        for dut in dc1_device_list:
            dut.configure('''
                restart bgp ''' + str(testscript.parameters['DC_1_FWD_SYS_dict']['BGP_AS_num']) + '''
                clear ip bgp vrf all *
                clear ip route vrf all *
                clear ipv6 route vrf all *
            ''')

        for dut in dc2_device_list:
            dut.configure('''
                restart bgp ''' + str(testscript.parameters['DC_2_FWD_SYS_dict']['BGP_AS_num']) + '''
                clear ip bgp vrf all *
                clear ip route vrf all *
                clear ipv6 route vrf all *
            ''')

        time.sleep(240)

# *****************************************************************************************************************************#
class VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY_POST_BGP_AS_RESTART(aetest.Testcase):
    """VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY_POST_LOCAL_MODE_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v4(DC1_LEAF1_v4_status)[1])
        nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v6(DC1_LEAF1_v6_status)[1])

        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4']), '1,>=1',
            str(DC1_LEAF1_v4_status['num_of_hops']), str(DC1_LEAF1_v4_status['fwd_num_of_hops']),
            str(nxt_hops_v4(DC1_LEAF1_v4_status)[0]), str(DC1_LEAF1_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6']), '1,>=1',
            str(DC1_LEAF1_v6_status['num_of_hops']), str(DC1_LEAF1_v6_status['fwd_num_of_hops']),
            str(nxt_hops_v6(DC1_LEAF1_v6_status)[0]), str(DC1_LEAF1_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v4(DC1_LEAF1_v4_status)[1])
        nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v6(DC1_LEAF1_v6_status)[1])

        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4']), '1,>=1',
            str(DC1_LEAF1_v4_status['num_of_hops']), str(DC1_LEAF1_v4_status['fwd_num_of_hops']),
            str(nxt_hops_v4(DC1_LEAF1_v4_status)[0]), str(DC1_LEAF1_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6']), '1,>=1',
            str(DC1_LEAF1_v6_status['num_of_hops']), str(DC1_LEAF1_v6_status['fwd_num_of_hops']),
            str(nxt_hops_v6(DC1_LEAF1_v6_status)[0]), str(DC1_LEAF1_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4',testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4'],testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(v4_status);log.info(v6_status);log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 16 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(nxt_hops(v4_status)[1])
            fail_flag.append(nxt_hops(v6_status)[1])

            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'1,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '1,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4']),'16,16',str(v4_status['num_of_hops']),str(v4_status['fwd_num_of_hops']),str(nxt_hops(v4_status)[0]),str(v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6']), '16,16', str(v6_status['num_of_hops']), str(v6_status['fwd_num_of_hops']),str(nxt_hops(v6_status)[0]), str(v6_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_common_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_1_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY_POST_BGP_AS_RESTART(aetest.Testcase):
    """VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 2 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'2,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '2,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_individual_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_2_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_PVNF_PHYSICAL_VM_LOOPBACK_TOPOLOGY_POST_BGP_AS_RESTART(aetest.Testcase):
    """VERIFY_PVNF_PHYSICAL_VM_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 16 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'16,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '16,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        BGW_2 = testscript.parameters['DC_2_BGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BGW_2, PGW, testscript.parameters['topo_3_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_TRAFFIC_POST_BGP_AS_RESTART(aetest.Testcase):
    """VERIFY_TRAFFIC_POST_PVNF_PGW_SHUT"""

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
class VERIFY_RESTART_BGP_PROCESS_ON_LEAF_BGW(aetest.Testcase):
    """VERIFY_RESTART_BGP_PROCESS"""

    # =============================================================================================================================#
    @aetest.test
    def RESTART_BGP_PROCESS_ON_LEAF(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        DC1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']

        if infraTrig.verifyProcessRestart(DC1_LEAF_1, "bgp"):
            self.passed(reason='Restarting Process BGP Successful')
        else:
            self.failed(reason='Restart Process BGP failed')

        DC1_LEAF_1.configure('''
            clear ip route vrf all *
            clear ipv6 route vrf all *
        ''')

        time.sleep(180)

    # =============================================================================================================================#
    @aetest.test
    def RESTART_BGP_PROCESS_ON_BGW(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        DC1_BGW = testscript.parameters['DC_1_BGW']

        if infraTrig.verifyProcessRestart(DC1_BGW, "bgp"):
            self.passed(reason='Restarting Process BGP Successful')
        else:
            self.failed(reason='Restart Process BGP failed')

        DC1_BGW.configure('''
            clear ip route vrf all *
            clear ipv6 route vrf all *
        ''')

        time.sleep(180)

# *****************************************************************************************************************************#
class VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY_POST_BGP_PROCESS_RESTART(aetest.Testcase):
    """VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY_POST_LOCAL_MODE_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v4(DC1_LEAF1_v4_status)[1])
        nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v6(DC1_LEAF1_v6_status)[1])

        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4']), '1,>=1',
            str(DC1_LEAF1_v4_status['num_of_hops']), str(DC1_LEAF1_v4_status['fwd_num_of_hops']),
            str(nxt_hops_v4(DC1_LEAF1_v4_status)[0]), str(DC1_LEAF1_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6']), '1,>=1',
            str(DC1_LEAF1_v6_status['num_of_hops']), str(DC1_LEAF1_v6_status['fwd_num_of_hops']),
            str(nxt_hops_v6(DC1_LEAF1_v6_status)[0]), str(DC1_LEAF1_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v4(DC1_LEAF1_v4_status)[1])
        nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v6(DC1_LEAF1_v6_status)[1])

        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4']), '1,>=1',
            str(DC1_LEAF1_v4_status['num_of_hops']), str(DC1_LEAF1_v4_status['fwd_num_of_hops']),
            str(nxt_hops_v4(DC1_LEAF1_v4_status)[0]), str(DC1_LEAF1_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6']), '1,>=1',
            str(DC1_LEAF1_v6_status['num_of_hops']), str(DC1_LEAF1_v6_status['fwd_num_of_hops']),
            str(nxt_hops_v6(DC1_LEAF1_v6_status)[0]), str(DC1_LEAF1_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4',testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4'],testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(v4_status);log.info(v6_status);log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 16 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(nxt_hops(v4_status)[1])
            fail_flag.append(nxt_hops(v6_status)[1])

            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'1,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '1,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4']),'16,16',str(v4_status['num_of_hops']),str(v4_status['fwd_num_of_hops']),str(nxt_hops(v4_status)[0]),str(v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6']), '16,16', str(v6_status['num_of_hops']), str(v6_status['fwd_num_of_hops']),str(nxt_hops(v6_status)[0]), str(v6_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_common_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_1_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY_POST_BGP_PROCESS_RESTART(aetest.Testcase):
    """VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 2 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'2,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '2,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_individual_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_2_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_PVNF_PHYSICAL_VM_LOOPBACK_TOPOLOGY_POST_BGP_PROCESS_RESTART(aetest.Testcase):
    """VERIFY_PVNF_PHYSICAL_VM_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 16 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'16,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '16,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        BGW_2 = testscript.parameters['DC_2_BGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BGW_2, PGW, testscript.parameters['topo_3_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_TRAFFIC_POST_BGP_PROCESS_RESTART(aetest.Testcase):
    """VERIFY_TRAFFIC_POST_PVNF_PGW_SHUT"""

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
class VERIFY_RESTART_NVE_PROCESS_ON_LEAF_BGW(aetest.Testcase):
    """VERIFY_RESTART_NVE_PROCESS_ON_LEAF_BGW"""

    # =============================================================================================================================#
    @aetest.test
    def RESTART_NVE_PROCESS_ON_LEAF(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        DC1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']

        if infraTrig.verifyProcessRestart(DC1_LEAF_1, "nve"):
            self.passed(reason='Restarting Process BGP Successful')
        else:
            self.failed(reason='Restart Process BGP failed')

        DC1_LEAF_1.configure('''
            clear ip route vrf all *
            clear ipv6 route vrf all *
        ''')

        time.sleep(180)

    # =============================================================================================================================#
    @aetest.test
    def RESTART_NVE_PROCESS_ON_BGW(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        DC1_BGW = testscript.parameters['DC_1_BGW']

        if infraTrig.verifyProcessRestart(DC1_BGW, "nve"):
            self.passed(reason='Restarting Process BGP Successful')
        else:
            self.failed(reason='Restart Process BGP failed')

        DC1_BGW.configure('''
            clear ip route vrf all *
            clear ipv6 route vrf all *
        ''')

        time.sleep(300)

# *****************************************************************************************************************************#
class VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY_POST_NVE_PROCESS_RESTART(aetest.Testcase):
    """VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY_POST_LOCAL_MODE_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v4(DC1_LEAF1_v4_status)[1])
        nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v6(DC1_LEAF1_v6_status)[1])

        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4']), '1,>=1',
            str(DC1_LEAF1_v4_status['num_of_hops']), str(DC1_LEAF1_v4_status['fwd_num_of_hops']),
            str(nxt_hops_v4(DC1_LEAF1_v4_status)[0]), str(DC1_LEAF1_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6']), '1,>=1',
            str(DC1_LEAF1_v6_status['num_of_hops']), str(DC1_LEAF1_v6_status['fwd_num_of_hops']),
            str(nxt_hops_v6(DC1_LEAF1_v6_status)[0]), str(DC1_LEAF1_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v4(DC1_LEAF1_v4_status)[1])
        nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v6(DC1_LEAF1_v6_status)[1])

        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4']), '1,>=1',
            str(DC1_LEAF1_v4_status['num_of_hops']), str(DC1_LEAF1_v4_status['fwd_num_of_hops']),
            str(nxt_hops_v4(DC1_LEAF1_v4_status)[0]), str(DC1_LEAF1_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6']), '1,>=1',
            str(DC1_LEAF1_v6_status['num_of_hops']), str(DC1_LEAF1_v6_status['fwd_num_of_hops']),
            str(nxt_hops_v6(DC1_LEAF1_v6_status)[0]), str(DC1_LEAF1_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4',testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4'],testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(v4_status);log.info(v6_status);log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 16 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(nxt_hops(v4_status)[1])
            fail_flag.append(nxt_hops(v6_status)[1])

            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'1,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '1,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4']),'16,16',str(v4_status['num_of_hops']),str(v4_status['fwd_num_of_hops']),str(nxt_hops(v4_status)[0]),str(v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6']), '16,16', str(v6_status['num_of_hops']), str(v6_status['fwd_num_of_hops']),str(nxt_hops(v6_status)[0]), str(v6_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_common_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_1_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY_POST_NVE_PROCESS_RESTART(aetest.Testcase):
    """VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 2 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'2,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '2,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_individual_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_2_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_PVNF_PHYSICAL_VM_LOOPBACK_TOPOLOGY_POST_NVE_PROCESS_RESTART(aetest.Testcase):
    """VERIFY_PVNF_PHYSICAL_VM_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 16 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'16,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '16,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        BGW_2 = testscript.parameters['DC_2_BGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BGW_2, PGW, testscript.parameters['topo_3_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_TRAFFIC_POST_NVE_PROCESS_RESTART(aetest.Testcase):
    """VERIFY_TRAFFIC_POST_PVNF_PGW_SHUT"""

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
class VERIFY_FLAP_NVE_INTERFACE(aetest.Testcase):
    """VERIFY_FLAP_NVE_INTERFACE"""

    # =============================================================================================================================#
    @aetest.test
    def FLAP_NVE_INT_ON_LEAF(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        DC1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        fail_flag = []
        fail_msgs = ''

        DC1_LEAF_1.configure('''
        interface nve1
            shut
            no shut
        ''')

        time.sleep(120)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the state
        LEAF_1_nve_out = DC1_LEAF_1.execute("sh int nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_1_nve_out:
            log.info("NVE INT is UP onDC1_LEAF_1 after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP on DC1_LEAF_1 after shut/no-shut"

        time.sleep(120)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

    # =============================================================================================================================#
    @aetest.test
    def FLAP_NVE_INT_ON_BGW(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        DC1_BGW = testscript.parameters['DC_1_BGW']
        fail_flag = []
        fail_msgs = ''

        DC1_BGW.configure('''
        interface nve1
            shut
            no shut
        ''')

        time.sleep(120)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
        # Get the state
        LEAF_1_nve_out = DC1_BGW.execute("sh int nve 1 brief | xml | i i state>")

        if ">up<" in LEAF_1_nve_out:
            log.info("NVE INT is UP onDC1_LEAF_1 after shut/no-shut")
        else:
            fail_flag.append(0)
            fail_msgs += "NVE INT is not UP on DC1_LEAF_1 after shut/no-shut"

        time.sleep(300)

        if 0 in fail_flag:
            self.failed(reason=fail_msgs)

# *****************************************************************************************************************************#
class VERIFY_BASE_VxLAN_EVPN_NETWORK_POST_NVE_FLAP(aetest.Testcase):
    """This is description for my testcase one"""

    # =============================================================================================================================#
    @aetest.test
    def verify_DC1_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['DC_1_FWD_SYS_dict'],
                                                                testscript.parameters['DC_1_leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC2_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['DC_2_FWD_SYS_dict'],
                                                                testscript.parameters['DC_2_leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC1_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['DC_1_leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC2_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['DC_2_leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC1_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['DC_1_FWD_SYS_dict'],
                                                  testscript.parameters['DC_1_leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC2_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['DC_2_FWD_SYS_dict'],testscript.parameters['DC_2_leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

# *****************************************************************************************************************************#
class VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY_POST_NVE_FLAP(aetest.Testcase):
    """VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY_POST_LOCAL_MODE_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v4(DC1_LEAF1_v4_status)[1])
        nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v6(DC1_LEAF1_v6_status)[1])

        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4']), '1,>=1',
            str(DC1_LEAF1_v4_status['num_of_hops']), str(DC1_LEAF1_v4_status['fwd_num_of_hops']),
            str(nxt_hops_v4(DC1_LEAF1_v4_status)[0]), str(DC1_LEAF1_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6']), '1,>=1',
            str(DC1_LEAF1_v6_status['num_of_hops']), str(DC1_LEAF1_v6_status['fwd_num_of_hops']),
            str(nxt_hops_v6(DC1_LEAF1_v6_status)[0]), str(DC1_LEAF1_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v4(DC1_LEAF1_v4_status)[1])
        nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v6(DC1_LEAF1_v6_status)[1])

        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4']), '1,>=1',
            str(DC1_LEAF1_v4_status['num_of_hops']), str(DC1_LEAF1_v4_status['fwd_num_of_hops']),
            str(nxt_hops_v4(DC1_LEAF1_v4_status)[0]), str(DC1_LEAF1_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6']), '1,>=1',
            str(DC1_LEAF1_v6_status['num_of_hops']), str(DC1_LEAF1_v6_status['fwd_num_of_hops']),
            str(nxt_hops_v6(DC1_LEAF1_v6_status)[0]), str(DC1_LEAF1_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4',testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4'],testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(v4_status);log.info(v6_status);log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 16 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(nxt_hops(v4_status)[1])
            fail_flag.append(nxt_hops(v6_status)[1])

            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'1,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '1,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4']),'16,16',str(v4_status['num_of_hops']),str(v4_status['fwd_num_of_hops']),str(nxt_hops(v4_status)[0]),str(v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6']), '16,16', str(v6_status['num_of_hops']), str(v6_status['fwd_num_of_hops']),str(nxt_hops(v6_status)[0]), str(v6_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_common_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_1_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY_POST_NVE_FLAP(aetest.Testcase):
    """VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 2 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'2,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '2,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_individual_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_2_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_PVNF_PHYSICAL_VM_LOOPBACK_TOPOLOGY_POST_NVE_FLAP(aetest.Testcase):
    """VERIFY_PVNF_PHYSICAL_VM_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 16 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'16,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '16,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        BGW_2 = testscript.parameters['DC_2_BGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BGW_2, PGW, testscript.parameters['topo_3_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_TRAFFIC_POST_NVE_FLAP(aetest.Testcase):
    """VERIFY_TRAFFIC_POST_PVNF_PGW_SHUT"""

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
class VERIFY_PVNF_TOR_RELOAD(aetest.Testcase):
    """VERIFY_PVNF_TOR_RELOAD"""

    # =============================================================================================================================#
    @aetest.test
    def PVNF_TOR_RELOAD(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']

        DC1_LEAF1.configure("copy r s")

        # Perform Device Reload
        result = infraTrig.switchASCIIreload(DC1_LEAF1)
        if result:
            log.info("ASCII Reload completed Successfully")
        else:
            log.debug("ASCII Reload Failed")
            self.failed("ASCII Reload Failed")

        log.info("Waiting for 300 sec for the topology to come UP")
        time.sleep(300)

        for dut in dc1_device_list:
            dut.configure('''
                restart bgp ''' + str(testscript.parameters['DC_1_FWD_SYS_dict']['BGP_AS_num']) + '''
                clear ip bgp vrf all *
                clear ip route vrf all *
                clear ipv6 route vrf all *
            ''')

        time.sleep(300)

# *****************************************************************************************************************************#
class VERIFY_BASE_VxLAN_EVPN_NETWORK_POST_TOR_RELOAD(aetest.Testcase):
    """This is description for my testcase one"""

    # =============================================================================================================================#
    @aetest.test
    def verify_DC1_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['DC_1_FWD_SYS_dict'],
                                                                testscript.parameters['DC_1_leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC2_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['DC_2_FWD_SYS_dict'],
                                                                testscript.parameters['DC_2_leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC1_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['DC_1_leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC2_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['DC_2_leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC1_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['DC_1_FWD_SYS_dict'],
                                                  testscript.parameters['DC_1_leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC2_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['DC_2_FWD_SYS_dict'],testscript.parameters['DC_2_leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

# *****************************************************************************************************************************#
class VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY_POST_TOR_RELOAD(aetest.Testcase):
    """VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY_POST_LOCAL_MODE_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v4(DC1_LEAF1_v4_status)[1])
        nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v6(DC1_LEAF1_v6_status)[1])

        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4']), '1,>=1',
            str(DC1_LEAF1_v4_status['num_of_hops']), str(DC1_LEAF1_v4_status['fwd_num_of_hops']),
            str(nxt_hops_v4(DC1_LEAF1_v4_status)[0]), str(DC1_LEAF1_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6']), '1,>=1',
            str(DC1_LEAF1_v6_status['num_of_hops']), str(DC1_LEAF1_v6_status['fwd_num_of_hops']),
            str(nxt_hops_v6(DC1_LEAF1_v6_status)[0]), str(DC1_LEAF1_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v4(DC1_LEAF1_v4_status)[1])
        nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v6(DC1_LEAF1_v6_status)[1])

        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4']), '1,>=1',
            str(DC1_LEAF1_v4_status['num_of_hops']), str(DC1_LEAF1_v4_status['fwd_num_of_hops']),
            str(nxt_hops_v4(DC1_LEAF1_v4_status)[0]), str(DC1_LEAF1_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6']), '1,>=1',
            str(DC1_LEAF1_v6_status['num_of_hops']), str(DC1_LEAF1_v6_status['fwd_num_of_hops']),
            str(nxt_hops_v6(DC1_LEAF1_v6_status)[0]), str(DC1_LEAF1_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4',testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4'],testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(v4_status);log.info(v6_status);log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 16 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(nxt_hops(v4_status)[1])
            fail_flag.append(nxt_hops(v6_status)[1])

            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'1,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '1,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4']),'16,16',str(v4_status['num_of_hops']),str(v4_status['fwd_num_of_hops']),str(nxt_hops(v4_status)[0]),str(v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6']), '16,16', str(v6_status['num_of_hops']), str(v6_status['fwd_num_of_hops']),str(nxt_hops(v6_status)[0]), str(v6_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_common_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_1_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY_POST_TOR_RELOAD(aetest.Testcase):
    """VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 2 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'2,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '2,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_individual_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_2_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_PVNF_PHYSICAL_VM_LOOPBACK_TOPOLOGY_POST_TOR_RELOAD(aetest.Testcase):
    """VERIFY_PVNF_PHYSICAL_VM_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 16 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'16,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '16,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        BGW_2 = testscript.parameters['DC_2_BGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BGW_2, PGW, testscript.parameters['topo_3_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_TRAFFIC_POST_TOR_RELOAD(aetest.Testcase):
    """VERIFY_TRAFFIC_POST_PVNF_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def RESTART_IXIA_PROTOCOLS(self):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        # Apply IXIA Traffic
        ixLib.start_protocols()
        if ixLib.stop_protocols() == 1:
            if ixLib.start_protocols() == 1:
                log.info("Restarting IXIA Protocols Passed")
            else:
                self.errored(reason="Starting back IXIA Protocols Failed", goto=['next_tc'])
        else:
            self.errored(reason="Stopping IXIA Protocols failed", goto=['next_tc'])

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

#*****************************************************************************************************************************#
class VERIFY_PVNF_BGW_RELOAD(aetest.Testcase):
    """VERIFY_PVNF_BGW_RELOAD"""

    # =============================================================================================================================#
    @aetest.test
    def PVNF_BGW_RELOAD(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        BGW_1 = testscript.parameters['DC_1_BGW']

        BGW_1.configure("copy r s")

        # Perform Device Reload
        result = infraTrig.switchASCIIreload(BGW_1)
        if result:
            log.info("ASCII Reload completed Successfully")
        else:
            log.debug("ASCII Reload Failed")
            self.failed("ASCII Reload Failed")

        log.info("Waiting for 300 sec for the topology to come UP")
        time.sleep(300)

        for dut in dc1_device_list:
            dut.configure('''
                restart bgp ''' + str(testscript.parameters['DC_1_FWD_SYS_dict']['BGP_AS_num']) + '''
                clear ip bgp vrf all *
                clear ip route vrf all *
                clear ipv6 route vrf all *
            ''')

        time.sleep(240)

# *****************************************************************************************************************************#
class VERIFY_BASE_VxLAN_EVPN_NETWORK_POST_BGW_RELOAD(aetest.Testcase):
    """This is description for my testcase one"""

    # =============================================================================================================================#
    @aetest.test
    def verify_DC1_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['DC_1_FWD_SYS_dict'],
                                                                testscript.parameters['DC_1_leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC2_bgp_neighborship(self, testscript):
        """ VERIFY_NETWORK subsection: Verify SPINE BGP Neighborship """

        bgpSessionData = verifyEvpn.verifyEvpnUpLinkBGPSessions(testscript.parameters['DC_2_FWD_SYS_dict'],
                                                                testscript.parameters['DC_2_leavesDict'])

        if bgpSessionData['result'] is 1:
            log.info("PASS : Successfully verified SPINE BGP Neighborship with Leaf's\n\n")
            self.passed(reason=bgpSessionData['log'])
        else:
            log.info("FAIL : Failed to verify SPINE BGP Neighborship with LEAF's\n\n")
            self.failed(reason=bgpSessionData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC1_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['DC_1_leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC2_NVE_peering(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nvePeerData = verifyEvpn.verifyEVPNNvePeers(testscript.parameters['DC_2_leavesDict'])

        if nvePeerData['result'] is 1:
            log.info("PASS : Successfully verified NVE Peering\n\n")
            self.passed(reason=nvePeerData['log'])
        else:
            log.info("FAIL : Failed to verify NVE Peering\n\n")
            self.failed(reason=nvePeerData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC1_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['DC_1_FWD_SYS_dict'],
                                                  testscript.parameters['DC_1_leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

    # =============================================================================================================================#
    @aetest.test
    def verify_DC2_VNI(self, testscript):
        """ VERIFY_NETWORK subsection: Verify NVE Peering """

        nveVniData = verifyEvpn.verifyEVPNVNIData(testscript.parameters['DC_2_FWD_SYS_dict'],testscript.parameters['DC_2_leavesDict'])

        if nveVniData['result'] is 1:
            log.info("PASS : Successfully verified NVE VNI Data\n\n")
            self.passed(reason=nveVniData['log'])
        else:
            log.info("FAIL : Failed to verify NVE VNI Data\n\n")
            self.failed(reason=nveVniData['log'])

# *****************************************************************************************************************************#
class VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY_POST_BGW_RELOAD(aetest.Testcase):
    """VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY_POST_LOCAL_MODE_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v4(DC1_LEAF1_v4_status)[1])
        nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v6(DC1_LEAF1_v6_status)[1])

        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4']), '1,>=1',
            str(DC1_LEAF1_v4_status['num_of_hops']), str(DC1_LEAF1_v4_status['fwd_num_of_hops']),
            str(nxt_hops_v4(DC1_LEAF1_v4_status)[0]), str(DC1_LEAF1_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6']), '1,>=1',
            str(DC1_LEAF1_v6_status['num_of_hops']), str(DC1_LEAF1_v6_status['fwd_num_of_hops']),
            str(nxt_hops_v6(DC1_LEAF1_v6_status)[0]), str(DC1_LEAF1_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v4(DC1_LEAF1_v4_status)[1])
        nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(nxt_hops_v6(DC1_LEAF1_v6_status)[1])

        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v4']), '1,>=1',
            str(DC1_LEAF1_v4_status['num_of_hops']), str(DC1_LEAF1_v4_status['fwd_num_of_hops']),
            str(nxt_hops_v4(DC1_LEAF1_v4_status)[0]), str(DC1_LEAF1_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(testscript.parameters['topo_1_vnf_leaves_dict'][DC1_LEAF1]['pgw_comn_loop_v6']), '1,>=1',
            str(DC1_LEAF1_v6_status['num_of_hops']), str(DC1_LEAF1_v6_status['fwd_num_of_hops']),
            str(nxt_hops_v6(DC1_LEAF1_v6_status)[0]), str(DC1_LEAF1_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4',testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4'],testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(v4_status);log.info(v6_status);log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 16 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(nxt_hops(v4_status)[1])
            fail_flag.append(nxt_hops(v6_status)[1])

            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'1,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '1,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4']),'16,16',str(v4_status['num_of_hops']),str(v4_status['fwd_num_of_hops']),str(nxt_hops(v4_status)[0]),str(v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6']), '16,16', str(v6_status['num_of_hops']), str(v6_status['fwd_num_of_hops']),str(nxt_hops(v6_status)[0]), str(v6_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_common_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_1_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY_POST_BGW_RELOAD(aetest.Testcase):
    """VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 2 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'2,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '2,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_individual_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_2_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_PVNF_PHYSICAL_VM_LOOPBACK_TOPOLOGY_POST_BGW_RELOAD(aetest.Testcase):
    """VERIFY_PVNF_PHYSICAL_VM_LOOPBACK_TOPOLOGY_POST_VTEP_PGW_SHUT"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF(self, testscript):
        """ VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_BGW_NVE_IP = testscript.parameters['DC_1_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Local BGW NVE PEER" + str(DC1_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v4', random_host_ipv4, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(DC1_LEAF1, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC1_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([DC1_LEAF1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_LOCAL_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY_ON_LEAF """

        fail_flag = []
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        BGW_1 = testscript.parameters['DC_1_BGW']
        DC2_BGW_NVE_IP = testscript.parameters['DC_2_BGW_dict']['NVE_data']['msite_bgw_loop_ip']
        status_msgs = '\n'+ str(banner("The routes should be pointing to Remote BGW NVE PEER" + str(DC2_BGW_NVE_IP), 145)) + '\n'

        # Generate Table handle
        LEAF_nextHopTable = texttable.Texttable()
        LEAF_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        LEAF_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        # Get the next hop information
        DC1_LEAF1_hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v4', random_host_ipv4, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
        DC1_LEAF1_hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

        # Set the pass criteria
        hst_nxt_hops_v4 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[1])
        hst_nxt_hops_v6 = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) >= 1 and '::ffff:'+str(DC2_BGW_NVE_IP) in X['prfx_lst']) else ['FAIL', 0]
        fail_flag.append(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[1])

        # Add the rows to the table
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv4), '1,>=1', str(DC1_LEAF1_hst_v4_status['num_of_hops']),
            str(DC1_LEAF1_hst_v4_status['fwd_num_of_hops']), str(hst_nxt_hops_v4(DC1_LEAF1_hst_v4_status)[0]),
            str(DC1_LEAF1_hst_v4_status['prfx_lst'])])
        LEAF_nextHopTable.add_row([BGW_1.alias, str(random_host_ipv6), '1,>=1', str(DC1_LEAF1_hst_v6_status['num_of_hops']),
            str(DC1_LEAF1_hst_v6_status['fwd_num_of_hops']), str(hst_nxt_hops_v6(DC1_LEAF1_hst_v6_status)[0]),
            str(DC1_LEAF1_hst_v6_status['prfx_lst'])])

        status_msgs += str(LEAF_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_PHYSICAL_VM_LOOPBACK_TOPOLOGY_ON_REMOTE_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_3_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_3_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_3_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 16 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'16,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '16,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_REMOTE_SITE_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        BGW_2 = testscript.parameters['DC_2_BGW']
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC2_status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BGW_2, PGW, testscript.parameters['topo_3_vnf_leaves_dict'], DC2_leafList)

        if DC2_status['result']:
            self.passed(reason=str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_TRAFFIC_POST_BGW_RELOAD(aetest.Testcase):
    """VERIFY_TRAFFIC_POST_PVNF_PGW_SHUT"""

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
class UNSHUT_LOCAL_MODE_VTEP_PGW_LINKS(aetest.Testcase):
    """UNSHUT_LOCAL_MODE_VTEP_PGW_LINKS"""

    # =============================================================================================================================#
    @aetest.test
    def UNSHUT_LOCAL_MODE_VTEP_PGW_LINKS(self, testscript):
        DC1_LEAF1 = testscript.parameters['DC_1_LEAF-1']
        DC1_LEAF2 = testscript.parameters['DC_1_LEAF-2']

        DC1_LEAF1.configure('''
            interface ''' + str(testscript.parameters['intf_DC1_LEAF_1_to_PGW_1']) + '''
                no shutdown

            interface ''' + str(testscript.parameters['intf_DC1_LEAF_1_to_PGW_2']) + '''
                no shutdown
        ''')

        DC1_LEAF2.configure('''
            interface ''' + str(testscript.parameters['intf_DC1_LEAF_2_to_PGW_1']) + '''
                no shutdown

            interface ''' + str(testscript.parameters['intf_DC1_LEAF_2_to_PGW_2']) + '''
                no shutdown
        ''')

        time.sleep(120)

# *****************************************************************************************************************************#
class VERIFY_RESTART_BGP_AS_POST_UNSHUT(aetest.Testcase):
    """VERIFY_RESTART_BGP"""

    # =============================================================================================================================#
    @aetest.test
    def RESTART_BGP_AS(self, testscript):
        """ IXIA_CONFIGURATION subsection: Verify IXIA Traffic """

        for dut in dc1_device_list:
            dut.configure('''
                restart bgp ''' + str(testscript.parameters['DC_1_FWD_SYS_dict']['BGP_AS_num']) + '''
                clear ip bgp vrf all *
                clear ip route vrf all *
                clear ipv6 route vrf all *
            ''')

        time.sleep(240)

# *****************************************************************************************************************************#
class VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY_POST_UNSHUT(aetest.Testcase):
    """VERIFY_PVNF_COMMON_LOOPBACK_TOPOLOGY"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']
        DC1_leafList = [testscript.parameters['DC_1_LEAF-1'], testscript.parameters['DC_1_LEAF-2']]
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC1_status = pvnfVerify.verifyPVNF_common_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_1_vnf_leaves_dict'], DC1_leafList)
        DC2_status = pvnfVerify.verifyPVNF_common_loopback_topology_btw_LEAF_PGW(PGW, testscript.parameters['topo_1_vnf_leaves_dict'], DC2_leafList)

        if DC1_status['result'] and DC2_status['result']:
            self.passed(reason=str(DC1_status['status_msgs'])+str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC1_status['status_msgs'])+str(DC2_status['status_msgs']))

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_COMMON_LOOPBACK_TOPOLOGY_FROM_BGW(self, testscript):
        """ VERIFY_COMMON_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_1_BGW'], testscript.parameters['DC_2_BGW']]
        DC_1_LEAF_1 = testscript.parameters['DC_1_LEAF-1']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_1_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_1_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Common Gateway", 145)) + '''\n'''

        for BGW in BGW_list:
            # Get the next hop information
            v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4',testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4'],testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6'], testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_1_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(v4_status);log.info(v6_status);log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 16 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(nxt_hops(v4_status)[1])
            fail_flag.append(nxt_hops(v6_status)[1])

            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 1 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv4),'1,16',str(hst_v4_status['num_of_hops']),str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(random_host_ipv6), '1,16', str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v6_status)[0]), str(hst_v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v4']),'16,16',str(v4_status['num_of_hops']),str(v4_status['fwd_num_of_hops']),str(nxt_hops(v4_status)[0]),str(v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW.alias, PGW.alias+'\n'+str(testscript.parameters['topo_1_vnf_leaves_dict'][DC_1_LEAF_1]['pgw_comn_loop_v6']), '16,16', str(v6_status['num_of_hops']), str(v6_status['fwd_num_of_hops']),str(nxt_hops(v6_status)[0]), str(v6_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

# *****************************************************************************************************************************#
class VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY_POST_UNSHUT(aetest.Testcase):
    """VERIFY_PVNF_INDIVIDUAL_LOOPBACK_TOPOLOGY"""

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY_BTW_LEAF_PGW(self, testscript):
        """ VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY """

        PGW = testscript.parameters['PGW']

        status = pvnfVerify.verifyPVNF_individual_loopback_topology_btw_LEAF_PGW(PGW,testscript.parameters['topo_2_vnf_leaves_dict'])

        if status['result']:
            self.passed(reason=status['status_msgs'])
        else:
            self.failed(reason=status['status_msgs'])

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY_FROM_BGW(self, testscript):
        """ VERIFY_INDIVIDUAL_LOOPBACK_TOPOLOGY """

        fail_flag = []
        status_msgs = ''
        BGW_list = [testscript.parameters['DC_1_BGW'], testscript.parameters['DC_2_BGW']]
        BGW_1 = testscript.parameters['DC_1_BGW']
        BGW_2 = testscript.parameters['DC_2_BGW']
        PGW = testscript.parameters['PGW']

        # Verify Gateway IP address next-hop Values
        BGW_nextHopTable = texttable.Texttable()
        BGW_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        BGW_hst_nextHopTable = texttable.Texttable()
        BGW_hst_nextHopTable.header(
            ['SRC NODE', 'Destination', 'Expected NH Count', 'Observed NH Count', 'Observed FWD NH Count', 'Status',
             'Next-hops'])
        BGW_hst_nextHopTable.set_cols_width([15, 25, 10, 10, 10, 10, 75])

        # --- Generate Random host IP
        host_ipv4 = ip.IPv4Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v4_prefixes']) + '/24')
        host_ipv6 = ip.IPv6Interface(str(testscript.parameters['topo_2_vnf_leaves_dict']['BGP_v6_prefixes']) + '/128')
        host_ipv4_routes_per_route_range = int(int(testscript.parameters['topo_2_vnf_leaves_dict']['no_of_hosts']) / 4) - 1
        random_octet = str(random.choice(string.hexdigits.lower()[6:]))
        random_host_ipv4 = host_ipv4 + (random.randint(2, host_ipv4_routes_per_route_range))
        random_host_ipv6 = re.sub('::\d+', '::' + str(random_octet), str(host_ipv6))

        status_msgs += '''
*** Legend
SRC NODE        == Source Node
DST NODE        == Destination Node
Destination     == Destination IP
NH Count        == Next-hops count
FWD NH Count    == Counts of Next-hops installed in hardware 'sh forwarding ipv4/v6 route'
Status          == Gives the tally of counts matching the expectations

====> Checking the Route DB from Individual LEAF's to PGW Common Gateway

''' + str(banner("Routes from BGW to Individual Loop", 145)) + '''\n'''

        for leaf in dc1_leaf_list:
            dst_v4_ip = testscript.parameters['topo_2_vnf_leaves_dict'][leaf]['pgw_comn_loop_v4']
            dst_v6_ip = testscript.parameters['topo_2_vnf_leaves_dict'][leaf]['pgw_comn_loop_v6']
            leaf_to_pgw_link_count = testscript.parameters['topo_2_vnf_leaves_dict'][leaf]['leaf_to_pgw_link_count']

            # Get the next hop information
            v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1,'v4',dst_v4_ip,testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
            v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_1, 'v6', dst_v6_ip, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(v4_status);log.info(v6_status);log.info('===>')

            # Set the pass criteria
            nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == leaf_to_pgw_link_count and int(X['fwd_num_of_hops']) == leaf_to_pgw_link_count) else ['FAIL', 0]
            fail_flag.append(nxt_hops(v4_status)[1])
            fail_flag.append(nxt_hops(v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW_1.alias, PGW.alias + '->' + leaf.alias + '\n' + str(dst_v4_ip), str(leaf_to_pgw_link_count)+','+str(leaf_to_pgw_link_count),str(v4_status['num_of_hops']), str(v4_status['fwd_num_of_hops']),str(nxt_hops(v4_status)[0]), str(v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW_1.alias, PGW.alias + '->' + leaf.alias + '\n' + str(dst_v6_ip), str(leaf_to_pgw_link_count)+','+str(leaf_to_pgw_link_count),str(v6_status['num_of_hops']), str(v6_status['fwd_num_of_hops']),str(nxt_hops(v6_status)[0]), str(v6_status['prfx_lst'])])

        for leaf in dc2_leaf_list:
            dst_v4_ip = testscript.parameters['topo_2_vnf_leaves_dict'][leaf]['pgw_comn_loop_v4']
            dst_v6_ip = testscript.parameters['topo_2_vnf_leaves_dict'][leaf]['pgw_comn_loop_v6']
            leaf_to_pgw_link_count = testscript.parameters['topo_2_vnf_leaves_dict'][leaf]['leaf_to_pgw_link_count']

            # Get the next hop information
            v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_2, 'v4', dst_v4_ip,testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
            v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW_2, 'v6', dst_v6_ip,testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(v4_status);log.info(v6_status);log.info('===>')

            # Set the pass criteria
            nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == leaf_to_pgw_link_count and int(X['fwd_num_of_hops']) == leaf_to_pgw_link_count) else ['FAIL', 0]
            fail_flag.append(nxt_hops(v4_status)[1])
            fail_flag.append(nxt_hops(v6_status)[1])

            # Add the rows to the table
            BGW_nextHopTable.add_row([BGW_2.alias, PGW.alias + '->' + leaf.alias + '\n' + str(dst_v4_ip), str(leaf_to_pgw_link_count)+','+str(leaf_to_pgw_link_count),str(v4_status['num_of_hops']), str(v4_status['fwd_num_of_hops']), str(nxt_hops(v4_status)[0]),str(v4_status['prfx_lst'])])
            BGW_nextHopTable.add_row([BGW_2.alias, PGW.alias + '->' + leaf.alias + '\n' + str(dst_v6_ip), str(leaf_to_pgw_link_count)+','+str(leaf_to_pgw_link_count),str(v6_status['num_of_hops']), str(v6_status['fwd_num_of_hops']), str(nxt_hops(v6_status)[0]),str(v6_status['prfx_lst'])])

        for BGW in BGW_list:
            # Get the next hop information
            hst_v4_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW,'v4', random_host_ipv4,testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])
            hst_v6_status = pvnfVerify.get_PGW_LEAF_nexthop_prefixes(BGW, 'v6', random_host_ipv6, testscript.parameters['topo_2_vnf_leaves_dict']['vrf'])

            log.info('===>');log.info(hst_v4_status);log.info(hst_v6_status);log.info('===>')

            # Set the pass criteria
            hst_nxt_hops = lambda X: ['PASS', 1] if (int(X['num_of_hops']) == 2 and int(X['fwd_num_of_hops']) == 16) else ['FAIL', 0]
            fail_flag.append(hst_nxt_hops(hst_v4_status)[1])
            fail_flag.append(hst_nxt_hops(hst_v6_status)[1])

            # Add the rows to the table
            BGW_hst_nextHopTable.add_row([BGW.alias, PGW.alias + '\n' + str(random_host_ipv4), '2,16',str(hst_v4_status['num_of_hops']), str(hst_v4_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])
            BGW_hst_nextHopTable.add_row([BGW.alias, PGW.alias + '\n' + str(random_host_ipv6), '2,16',str(hst_v6_status['num_of_hops']), str(hst_v6_status['fwd_num_of_hops']),str(hst_nxt_hops(hst_v4_status)[0]),str(hst_v4_status['prfx_lst'])])

        status_msgs += str(BGW_nextHopTable.draw()) + '\n'
        status_msgs += str(BGW_hst_nextHopTable.draw())

        if 0 in fail_flag:
            self.failed(reason=status_msgs)
        else:
            self.passed(reason=status_msgs)

# *****************************************************************************************************************************#
class VERIFY_PVNF_PHYSICAL_VM_TOPOLOGY_POST_UNSHUT(aetest.Testcase):
    """VERIFY_PVNF_PHYSICAL_VM_TOPOLOGY"""

    #=============================================================================================================================#
    @aetest.test
    def VERIFY_INDIVIDUAL_PHYSICAL_VM_TOPOLOGY_FROM_BGW(self, testscript):
        """ VERIFY_PHYSICAL_VM_TOPOLOGY """

        BGW_1 = testscript.parameters['DC_1_BGW']
        BGW_2 = testscript.parameters['DC_2_BGW']
        PGW = testscript.parameters['PGW']
        DC1_leafList = [testscript.parameters['DC_1_LEAF-1'], testscript.parameters['DC_1_LEAF-2']]
        DC2_leafList = [testscript.parameters['DC_2_LEAF-1'], testscript.parameters['DC_2_LEAF-2']]

        DC1_status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BGW_1, PGW, testscript.parameters['topo_3_vnf_leaves_dict'], DC1_leafList)
        DC2_status = pvnfVerify.verifyPVNF_individual_physical_vm_topology(BGW_2, PGW, testscript.parameters['topo_3_vnf_leaves_dict'], DC2_leafList)

        if DC1_status['result'] and DC2_status['result']:
            self.passed(reason=str(DC1_status['status_msgs'])+str(DC2_status['status_msgs']))
        else:
            self.failed(reason=str(DC1_status['status_msgs'])+str(DC2_status['status_msgs']))

# *****************************************************************************************************************************#
class VERIFY_TRAFFIC_POST_PVNF_BRINGUP_POST_UNSHUT(aetest.Testcase):
    """VERIFY_TRAFFIC_POST_PVNF_BRINGUP"""

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
