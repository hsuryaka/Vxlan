#!/usr/bin/env python

# Author information
__author__ = 'Nexus India VxLAN DevTest Group'
__copyright__ = 'Copyright (c) 2021, Cisco Systems Inc.'
__contact__ = ['group.jdasgupt@cisco.com']
__credits__ = ['pkanduri']
__version__ = 1.0

###################################################################
###                  Importing Libraries                        ###
###################################################################
# ------------------------------------------------------
# Import generic python libraries
# ------------------------------------------------------
from random import random
import yaml
import json
import time
from yaml import Loader
import chevron
import pdb
import sys
import re
import ipaddress as ip
import numpy as np
from operator import itemgetter
import texttable
import difflib

# ------------------------------------------------------
# Import pyats aetest libraries
# ------------------------------------------------------
import logging
from pyats import aetest
from pyats.datastructures.logic import Not
from pyats.log.utils import banner
from pyats.async_ import pcall
from pyats.aereport.utils.argsvalidator import ArgsValidator
from pyats.datastructures.logic import Or
ArgVal = ArgsValidator()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# ------------------------------------------------------
# Import pyats genie libraries
# ------------------------------------------------------
from genie.conf import Genie
from genie.conf.base import Device
from genie.libs.parser.nxos.show_platform import ShowCores
from genie.libs.parser.nxos.show_platform import ShowVersion
from genie.libs.parser.nxos.show_vrf import ShowVrf
from genie.libs.sdk.apis.execute import execute_copy_run_to_start
from genie.abstract import Lookup
from genie.libs import conf, ops, sdk, parser

# ------------------------------------------------------
# Import and initialize EVPN specific libraries
# ------------------------------------------------------
from VxLAN_PYlib import infra_lib

infraVerify = infra_lib.infraVerify()
infraEORTrigger = infra_lib.infraEORTrigger()

# ------------------------------------------------------
# Import and initialize IXIA specific libraries
# ------------------------------------------------------
# from VxLAN_PYlib.ixia_RestAPIlib import *

# Import the RestPy module
from ixnetwork_restpy import *

# ------------------------------------------------------
# Import and initialize INFRA specific libraries
# ------------------------------------------------------
from VxLAN_PYlib import infra_lib

infraTrig = infra_lib.infraTrigger()
infraEORTrig = infra_lib.infraEORTrigger()
infraConfig = infra_lib.infraConfigure()
infraVerify = infra_lib.infraVerify()

# ------------------------------------------------------
# Import nxtest / nexus-pyats-test libraries
# ------------------------------------------------------
from lib import nxtest
from lib.utils.find_path import get_full_with_script_path
from lib.config.interface.generate_interface_logical_map import generate_interface_logical_map
from lib.config.feature.feature_enabler import enable_features
from lib.config.feature.feature_disabler import disable_features
from lib.config.interface.interface_builder import BuildInterfaceConfig
from lib.config.mld.mld_builder import BuildMldConfig
from lib.config.ospf.ospf_builder import BuildOspfConfig
from lib.config.pim.pim_builder import BuildPimConfig
from lib.config.pim6.pim6_builder import BuildPim6Config
from lib.config.prefix_list.prefix_list_builder import BuildPrefixListConfig
from lib.config.routepolicy.route_policy_builder import BuildRoutePolicyConfig
from lib.config.static_route.static_route_builder import BuildStaticRouteConfig
from lib.config.bgp.bgp_builder import BuildBgpConfig
from lib.config.vlan.vlan_builder import BuildVlanConfig
from lib.config.vrf.vrf_builder import BuildVrfConfig
from lib.config.vxlan.vxlan_builder import BuildVxlanConfig
from src.forwarding.vxlan.vxlan_verify import common_verification
from lib.verify.verify_core import cores_check
from lib.triggers.config_trigger_lib import ConfigReplace, ConfigRollback
from lib.stimuli.stimuli_port_lib import StimuliInterfaceFlap

###################################################################
###                  GLOBAL VARIABLES                           ###
###################################################################

global_processors = {
    'pre': [],
    'post': [],
    'exception': [],
}
global copy_cores
copy_cores = False
MD_REGEX = '(^default|management|external)'

###################################################################
###                  User Library Methods                       ###
###################################################################
# Verify IXIA Traffic (Traffic Item Stats View)
def validateSteadystateTraffic(testscript):
    
    session     = testscript.parameters['session']
    ixNetwork   = testscript.parameters['ixNetwork']
    threshold   = testscript.parameters['traffic_threshold']

    TrafficItemTable = texttable.Texttable()
    TrafficItemTable.header(['Traffic Item', 'Loss % Observed\nThreshold - '+str(threshold)+' %', 'Status','Remarks'])
    TrafficItemTable.set_cols_width([40,20,20,50])
    fail_flag = []

    # Start all protocols and wait for 60sec
    ixNetwork.StartAllProtocols(Arg1='sync')
    time.sleep(60)
    
    # Apply traffic, start traffic and wait for 30min
    ixNetwork.Traffic.Apply()
    ixNetwork.Traffic.Start()
    log.info("==> Wait for 5min for the MSite Scale traffic to populate")
    time.sleep(300)
    
    # Loop wait buffer for 5 more min
    waitIteration = 1
    while waitIteration < 16:
        # Clear stats
        ixNetwork.ClearStats()
        time.sleep(20)
        fail_flag = []

        # Get Traffic Item Statistics
        trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
        for row in trafficItemStatistics.Rows:
            # Verify loss percentage for Traffic Items
            if row['Loss %'] != '':
                if int(float(row['Loss %'])) > threshold:
                    fail_flag.append(0)
            # Verify loss percentage for BUM Traffic Items
            else:
                if 'BUM' in str(row['Traffic Item']):
                    # Remote Site VTEPs
                    # Verify Tx Rate*256 = Rx Rate for Traffic Items
                    if 'DCI_BUM' in str(row['Traffic Item']):
                        if int(float(row['Tx Frame Rate']))*256 != int(float(row['Rx Frame Rate'])):
                            fail_flag.append(0)
                    # Remote Internal Site VTEPs
                    # Verify Tx Rate*116 = Rx Rate for Traffic Items
                    elif 'INT_BUM' in str(row['Traffic Item']):
                        if int(float(row['Tx Frame Rate']))*117 != int(float(row['Rx Frame Rate'])):
                            fail_flag.append(0)
                # Verify Traffic if Loss % is not available
                else:
                    if (int(float(row['Tx Frame Rate']))-int(float(row['Rx Frame Rate']))) not in range(0,1001):
                        fail_flag.append(0)

        if 0 in fail_flag:
            log.info("==> Iteration done , but traffic not converged , need to wait more")
            waitIteration+=1
            continue
        else:
            log.info("time ===>")
            log.info(time.gmtime())
            log.info("time ===>")
            break

    # Collect Data and tabulate it for reporting
    ixNetwork.ClearStats()
    time.sleep(20)
    fail_flag = []

    # Get Traffic Item Statistics
    trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
    for row in trafficItemStatistics.Rows:
        # Verify loss percentage for Traffic Items
        if row['Loss %'] != '':
            if int(float(row['Loss %'])) < threshold:
                TrafficItemTable.add_row([str(row['Traffic Item']), str(row['Loss %']), 'PASS', ''])
            else:
                TrafficItemTable.add_row([str(row['Traffic Item']), str(row['Loss %']), 'FAIL', ''])
                fail_flag.append(0)
        # Verify loss percentage for BUM Traffic Items
        else:
            if 'BUM' in str(row['Traffic Item']):
                # Remote Site VTEPs
                # Verify Tx Rate*256 = Rx Rate for Traffic Items
                if 'DCI_BUM' in str(row['Traffic Item']):
                    if int(float(row['Tx Frame Rate']))*256 == int(float(row['Rx Frame Rate'])):
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'PASS', 'Receiving 2560 for 256 Remote Site VTEPs'])
                    else:
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'FAIL', 'Not Receiving 2560 for 256 Remote Site VTEPs'])
                        fail_flag.append(0)
                # Remote Internal Site VTEPs
                # Verify Tx Rate*116 = Rx Rate for Traffic Items
                elif 'INT_BUM' in str(row['Traffic Item']):
                    if int(float(row['Tx Frame Rate']))*117 == int(float(row['Rx Frame Rate'])):
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'PASS', 'Receiving 1170 for 116 Internal Remote VTEPs + 1 BGW'])
                    else:
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'FAIL', 'Not Receiving 1170 for 116 Internal Remote VTEPs + 1 BGW'])
                        fail_flag.append(0)
            # Verify Traffic if Loss % is not available
            else:
                if (int(float(row['Tx Frame Rate']))-int(float(row['Rx Frame Rate']))) in range(0,1001):
                    TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'PASS', ''])
                else:
                    TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'FAIL', ''])
                    fail_flag.append(0)
    
    log.info(TrafficItemTable.draw())
    if 0 in fail_flag:
        return 0
    else:
        return 1

# Verify IXIA Traffic (Traffic Item Stats View)
def VerifyTraffic(section, testscript, **kwargs):
    
    session     = testscript.parameters['session']
    ixNetwork   = testscript.parameters['ixNetwork']
    threshold   = testscript.parameters['traffic_threshold']

    TrafficItemTable = texttable.Texttable()
    TrafficItemTable.header(['Traffic Item', 'Loss % Observed\nThreshold - '+str(threshold)+' %', 'Status','Remarks'])
    TrafficItemTable.set_cols_width([40,20,20,50])
    fail_flag = []

    # # Start all protocols and wait for 60sec
    # ixNetwork.StartAllProtocols(Arg1='sync')
    # time.sleep(60)
    
    # # Apply traffic, start traffic and wait for 60sec
    # ixNetwork.Traffic.Apply()
    # ixNetwork.Traffic.Start()
    time.sleep(240)

    # Clear stats
    ixNetwork.ClearStats()
    time.sleep(20)
    
    # Get Traffic Item Statistics
    trafficItemStatistics = session.StatViewAssistant('Traffic Item Statistics')
    for row in trafficItemStatistics.Rows:
        # Verify loss percentage for Traffic Items
        if row['Loss %'] != '':
            if int(float(row['Loss %'])) < threshold:
                TrafficItemTable.add_row([str(row['Traffic Item']), str(row['Loss %']), 'PASS', ''])
            else:
                TrafficItemTable.add_row([str(row['Traffic Item']), str(row['Loss %']), 'FAIL', ''])
                fail_flag.append(0)
        # Verify loss percentage for BUM Traffic Items
        else:
            if 'BUM' in str(row['Traffic Item']):
                # Remote Site VTEPs
                # Verify Tx Rate*256 = Rx Rate for Traffic Items
                if 'DCI_BUM' in str(row['Traffic Item']):
                    if int(float(row['Tx Frame Rate']))*256 == int(float(row['Rx Frame Rate'])):
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'PASS', 'Receiving 2560 for 256 Remote Site VTEPs'])
                    else:
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'FAIL', 'Not Receiving 2560 for 256 Remote Site VTEPs'])
                        fail_flag.append(0)
                # Remote Internal Site VTEPs
                # Verify Tx Rate*116 = Rx Rate for Traffic Items
                elif 'INT_BUM' in str(row['Traffic Item']):
                    if int(float(row['Tx Frame Rate']))*117 == int(float(row['Rx Frame Rate'])):
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'PASS', 'Receiving 1170 for 116 Internal Remote VTEPs + 1 BGW'])
                    else:
                        TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'FAIL', 'Not Receiving 1170 for 116 Internal Remote VTEPs + 1 BGW'])
                        fail_flag.append(0)
            # Verify Traffic if Loss % is not available
            else:
                if (int(float(row['Tx Frame Rate']))-int(float(row['Rx Frame Rate']))) in range(0,1001):
                    TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'PASS', ''])
                else:
                    TrafficItemTable.add_row([str(row['Traffic Item']), str(int(float(row['Tx Frame Rate'])))+'-'+str(int(float(row['Rx Frame Rate']))), 'FAIL', ''])
                    fail_flag.append(0)
    
    log.info(TrafficItemTable.draw())
    
    if 0 in fail_flag:
        section.failed("Traffic verification failed")
    else:
        section.passed("Traffic verification Passed")

# Increment a prefix of a network
def increment_prefix_network(pref, count):
    size = 1 << (pref.network.max_prefixlen - pref.network.prefixlen)
    pref_lst = []
    for i in range(count):
        pref_lst.append(str((pref.ip+size*i)) + "/" + str(pref.network.prefixlen))
    return pref_lst

# Perform copy r s
def doCopyRunToStart(section, **kwargs):
    for node in section.parameters['testbed'].find_devices(os=Or('NEXUS|NXOS|nxos')):
        execute_copy_run_to_start(node)


###################################################################
###                  Traffic Generator Configurations           ###
###################################################################

class ConfigureIxia(nxtest.Testcase):
    """ Configuring IXIA """

    @aetest.test
    def InitializeIxia(self, testscript, testbed, steps, tgen_cfg_file):
        """ Initializing IXIA Testbed """

        with steps.start("Get the IXIA details from testbed YAML file"):
            
            if "ixia" in testbed.devices:

                testscript.parameters['tgen_cfg_file'] = tgen_cfg_file
                testscript.parameters['traffic_threshold'] = 2
                ixia_chassis_ip = testbed.devices['ixia'].connections.tgn.ixia_chassis_ip
                ixia_tcl_server = testbed.devices['ixia'].connections.tgn.ixnetwork_api_server_ip
                ixia_tcl_port   = str(testbed.devices['ixia'].connections.tgn.ixnetwork_tcl_port)
                ixia_port_list  = testbed.devices['ixia'].connections.tgn.ixia_port_list
                ixia_int_list   = []
                for intPort in ixia_port_list:
                    intPort_split = intPort.split('/')
                    ixia_int_list.append([ixia_chassis_ip, intPort_split[0], intPort_split[1]])

            else:
                log.info("IXIA details not provided in testbed file")

        with steps.start("Connect to IXIA Chassis"):
            
            # Forcefully take port ownership if the portList are owned by other users.
            forceTakePortOwnership = True

            # LogLevel: none, info, warning, request, request_response, all
            # testscript.parameters['session'] = session = SessionAssistant(IpAddress=ixia_tcl_server, RestPort=None, UserName='admin', Password='admin', SessionName=None, SessionId=None, ApiKey=None, ClearConfig=True, LogLevel='all', LogFilename='restpy.log')
            testscript.parameters['session'] = session = SessionAssistant(IpAddress=ixia_tcl_server, UserName='admin', Password='admin', ClearConfig=True, LogLevel='all', LogFilename='restpy.log')
            testscript.parameters['ixNetwork'] = ixNetwork = testscript.parameters['session'].Ixnetwork

            #######Load a saved config file
            ixNetwork.info('Loading config file: {0}'.format(tgen_cfg_file))
            ixNetwork.LoadConfig(Files(tgen_cfg_file, local_file=True))

            # Assign ports. Map physical ports to the configured vports.
            portMap = testscript.parameters['session'].PortMapAssistant()
            vport = dict()
            for index,port in enumerate(ixia_int_list):
                # For the port name, get the loaded configuration's port name
                portName = ixNetwork.Vport.find()[index].Name
                portMap.Map(IpAddress=port[0], CardId=port[1], PortId=port[2], Name=portName)
            portMap.Connect(forceTakePortOwnership)

        with steps.start("Verify Steady State"):

            if validateSteadystateTraffic(testscript):
                self.passed()
            else:
                self.failed()

###################################################################
###                  Configuration Adjustments                  ###
###################################################################


###################################################################
###                  Trigger Verifications                      ###
###################################################################

class TriggerFlapNve(nxtest.Testcase):
    @aetest.test
    def shut_nosh_nve_interface(self, testbed, device_dut, cli_to_parse, wait_time):
        for node in device_dut:
            log.info('Calling StimuliInterfaceFlap to shutdown nve interface for %s', node)
            int_flap_flag = StimuliInterfaceFlap(node, testbed, converge_sec=int(wait_time))
            if int_flap_flag.nve_shutdown(cli_to_parse):
                log.info("NVE shutdown is-SUCCESS")
            else:
                log.error("NVE shutdown-FAILED")
                self.failed()
            log.info('Calling StimuliInterfaceFlap to no shutdown nve interface for %s', node)
            int_flap_flag = StimuliInterfaceFlap(node, testbed, converge_sec=int(wait_time))
            if int_flap_flag.nve_no_shutdown(cli_to_parse):
                log.info("NVE no shutdown is-SUCCESS")
            else:
                log.error("NVE no shutdown-FAILED")
                self.failed()
            log.info("Waiting "+str(wait_time)+"sec for nve peers to form...")
            time.sleep(int(wait_time))
        log.info("Waiting 2*"+str(wait_time)+"sec before checking traffic...")
        time.sleep(2 * int(wait_time))